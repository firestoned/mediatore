// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! `ClusterStaticEntry` through the Kubernetes API (ADR-0006).
//!
//! The SPIRE Controller Manager renders each resource into a server entry over its private
//! socket and reports `status.rendered`, `status.masked` and `status.set`. A declaration
//! here succeeds only once `set` is true; `masked` is a conflict and fails the claim.
//! Admission (`deploy/base/admission/clusterstaticentry-mediatore.yaml`) is the control
//! that holds even if this code is wrong; the validation here only refuses earlier.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, PostParams};
use kube::{Client, CustomResource};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    CLAIM_UID_LABEL, EntryKind, EntryManager, EntryRef, GUEST_AGENT_PATH, KIND_LABEL, MANAGED_BY,
    MANAGED_BY_LABEL, Naming, SpireError, claim_entry_name, node_entry_name, validate_ek_hash,
    validate_unix_user,
};

/// `spec` of `spire.spiffe.io/v1alpha1` `ClusterStaticEntry`, the fields mediatore uses.
/// The CRD's schema is the controller manager's; this type is a client view, not a source
/// for a schema (`schema = "disabled"`).
#[derive(CustomResource, Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[kube(
    group = "spire.spiffe.io",
    version = "v1alpha1",
    kind = "ClusterStaticEntry",
    status = "ClusterStaticEntryStatus",
    schema = "disabled"
)]
pub struct ClusterStaticEntrySpec {
    /// Full SPIFFE ID of the workload.
    #[serde(rename = "spiffeID")]
    pub spiffe_id: String,
    /// Full SPIFFE ID of the parent (here always a tpm agent).
    #[serde(rename = "parentID")]
    pub parent_id: String,
    /// Workload selectors, `type:value`.
    pub selectors: Vec<String>,
    /// Controller class; the hardened chart ignores classless resources.
    #[serde(rename = "className", skip_serializing_if = "Option::is_none")]
    pub class_name: Option<String>,
    /// Upper bound on X.509 SVID lifetime, e.g. `1h`.
    #[serde(rename = "x509SVIDTTL", skip_serializing_if = "Option::is_none")]
    pub x509_svid_ttl: Option<String>,
    /// Opaque hint delivered with the SVID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// `status` as the controller manager reports it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterStaticEntryStatus {
    /// The resource rendered into a valid entry.
    #[serde(default)]
    pub rendered: bool,
    /// Another entry with the same parent, selectors and ID shadows this one.
    #[serde(default)]
    pub masked: bool,
    /// The entry exists on the SPIRE server.
    #[serde(default)]
    pub set: bool,
}

/// Tunables for [`KubeEntryManager`] (`spire.entries` in `mediatore.yaml`).
#[derive(Debug, Clone)]
pub struct EntriesConfig {
    /// `spec.className` on every resource; must match the controller manager's class.
    pub class_name: String,
    /// How long a declaration may take to become `set` before the bind fails.
    pub ready_timeout: Duration,
    /// How often the status is re-read while waiting.
    pub poll_interval: Duration,
    /// `x509SVIDTTL` on claim entries; bounds an offline agent after release.
    pub claim_svid_ttl: String,
}

impl Default for EntriesConfig {
    fn default() -> Self {
        Self {
            class_name: "spire-server-spire".into(),
            ready_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_millis(500),
            claim_svid_ttl: "1h".into(),
        }
    }
}

/// Declares and retracts `ClusterStaticEntry` resources.
pub struct KubeEntryManager {
    api: Api<ClusterStaticEntry>,
    naming: Naming,
    cfg: EntriesConfig,
}

impl KubeEntryManager {
    /// Over a client for the cluster that hosts the downstream server's controller manager.
    #[must_use]
    pub fn new(client: Client, naming: Naming, cfg: EntriesConfig) -> Self {
        Self {
            api: Api::all(client),
            naming,
            cfg,
        }
    }

    fn labels(kind: EntryKind, claim_uid: Option<Uuid>) -> BTreeMap<String, String> {
        let mut l = BTreeMap::new();
        l.insert(MANAGED_BY_LABEL.into(), MANAGED_BY.into());
        l.insert(KIND_LABEL.into(), kind.label().into());
        if let Some(uid) = claim_uid {
            l.insert(CLAIM_UID_LABEL.into(), uid.to_string());
        }
        l
    }

    /// Create the resource (tolerating one that already exists), then wait for `set`.
    async fn declare(
        &self,
        name: &str,
        labels: BTreeMap<String, String>,
        spec: ClusterStaticEntrySpec,
    ) -> Result<String, SpireError> {
        let obj = ClusterStaticEntry {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                labels: Some(labels),
                ..ObjectMeta::default()
            },
            spec,
            status: None,
        };
        match self.api.create(&PostParams::default(), &obj).await {
            Ok(_) => tracing::info!(name, "entry declared"),
            Err(kube::Error::Api(e)) if e.code == 409 => {
                tracing::debug!(name, "entry already declared");
            }
            Err(kube::Error::Api(e)) if e.code == 403 => return Err(SpireError::Denied(e.message)),
            Err(e) => return Err(SpireError::Api(e.to_string())),
        }
        self.wait_set(name).await?;
        Ok(name.to_owned())
    }

    /// Poll the resource until the controller manager reports it set, masked, or the
    /// timeout passes. Bounded, and never assumes.
    async fn wait_set(&self, name: &str) -> Result<(), SpireError> {
        let deadline = Instant::now() + self.cfg.ready_timeout;
        loop {
            let obj = self
                .api
                .get(name)
                .await
                .map_err(|e| SpireError::Api(e.to_string()))?;
            if let Some(st) = &obj.status {
                if st.masked {
                    return Err(SpireError::Masked(name.to_owned()));
                }
                if st.set {
                    tracing::info!(name, "entry set on the SPIRE server");
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(SpireError::Timeout(name.to_owned()));
            }
            tokio::time::sleep(self.cfg.poll_interval).await;
        }
    }
}

#[async_trait]
impl EntryManager for KubeEntryManager {
    async fn ensure_node_entry(&self, ek_hash: &str) -> Result<String, SpireError> {
        validate_ek_hash(ek_hash)?;
        let name = node_entry_name(ek_hash);
        let spec = ClusterStaticEntrySpec {
            spiffe_id: self.naming.node_id(ek_hash),
            parent_id: self.naming.agent_id(ek_hash),
            selectors: vec!["unix:uid:0".into(), format!("unix:path:{GUEST_AGENT_PATH}")],
            class_name: Some(self.cfg.class_name.clone()),
            x509_svid_ttl: None,
            hint: Some("node".into()),
        };
        self.declare(&name, Self::labels(EntryKind::Node, None), spec)
            .await
    }

    async fn create_claim_entry(
        &self,
        ek_hash: &str,
        claim_uid: Uuid,
        unix_user: &str,
    ) -> Result<String, SpireError> {
        validate_ek_hash(ek_hash)?;
        validate_unix_user(unix_user)?;
        let name = claim_entry_name(claim_uid);
        let spec = ClusterStaticEntrySpec {
            spiffe_id: self.naming.claim_id(claim_uid),
            parent_id: self.naming.agent_id(ek_hash),
            selectors: vec![format!("unix:user:{unix_user}")],
            class_name: Some(self.cfg.class_name.clone()),
            x509_svid_ttl: Some(self.cfg.claim_svid_ttl.clone()),
            hint: Some("claim".into()),
        };
        self.declare(&name, Self::labels(EntryKind::Claim, Some(claim_uid)), spec)
            .await
    }

    async fn delete_entry(&self, name: &str) -> Result<(), SpireError> {
        match self.api.delete(name, &DeleteParams::default()).await {
            Ok(_) => tracing::info!(name, "entry retracted"),
            Err(kube::Error::Api(e)) if e.code == 404 => {
                tracing::debug!(name, "entry already gone");
            }
            Err(e) => return Err(SpireError::Api(e.to_string())),
        }
        Ok(())
    }

    async fn list_entries(&self) -> Result<Vec<EntryRef>, SpireError> {
        let lp = ListParams::default().labels(&format!("{MANAGED_BY_LABEL}={MANAGED_BY}"));
        let list = self
            .api
            .list(&lp)
            .await
            .map_err(|e| SpireError::Api(e.to_string()))?;
        Ok(list
            .items
            .into_iter()
            .filter_map(|o| {
                let name = o.metadata.name?;
                let labels = o.metadata.labels.unwrap_or_default();
                let kind = match labels.get(KIND_LABEL).map(String::as_str) {
                    Some("node") => EntryKind::Node,
                    Some("claim") => EntryKind::Claim,
                    _ => return None,
                };
                let claim_uid = labels
                    .get(CLAIM_UID_LABEL)
                    .and_then(|s| Uuid::parse_str(s).ok());
                Some(EntryRef {
                    name,
                    kind,
                    claim_uid,
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    //! A scripted fake API server: each step asserts the request it expects and answers
    //! with a canned response, so the manager's create / 409 / 403 / poll / 404 paths are
    //! exercised without a cluster.

    use http::{Request, Response};
    use http_body_util::BodyExt as _;
    use kube::client::Body;
    use serde_json::{Value, json};

    use super::*;

    const EK: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";
    const TD: &str = "sandbox.test";

    struct Step {
        method: &'static str,
        path_contains: String,
        status: u16,
        body: Value,
        check: Option<fn(&Value)>,
    }

    fn step(method: &'static str, path: &str, status: u16, body: Value) -> Step {
        Step {
            method,
            path_contains: path.to_owned(),
            status,
            body,
            check: None,
        }
    }

    fn entry_json(name: &str, status: Option<(bool, bool, bool)>, labels: &Value) -> Value {
        let mut v = json!({
            "apiVersion": "spire.spiffe.io/v1alpha1",
            "kind": "ClusterStaticEntry",
            "metadata": { "name": name, "labels": labels },
            "spec": { "spiffeID": "x", "parentID": "y", "selectors": ["unix:uid:0"] }
        });
        if let Some((rendered, masked, set)) = status {
            v["status"] = json!({ "rendered": rendered, "masked": masked, "set": set });
        }
        v
    }

    fn status_json(code: u16, reason: &str, message: &str) -> Value {
        json!({ "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "message": message, "reason": reason, "code": code })
    }

    fn manager(steps: Vec<Step>) -> (KubeEntryManager, tokio::task::JoinHandle<()>) {
        let (svc, mut handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        let client = Client::new(svc, "default");
        let task = tokio::spawn(async move {
            for s in steps {
                let (req, send) = handle.next_request().await.expect("a request");
                assert_eq!(
                    req.method().as_str(),
                    s.method,
                    "method for {}",
                    s.path_contains
                );
                assert!(
                    req.uri().path().contains(&s.path_contains),
                    "path {} should contain {}",
                    req.uri().path(),
                    s.path_contains
                );
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                if let Some(check) = s.check {
                    check(&serde_json::from_slice::<Value>(&bytes).unwrap());
                }
                send.send_response(
                    Response::builder()
                        .status(s.status)
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&s.body).unwrap()))
                        .unwrap(),
                );
            }
            // Anything beyond the script is a bug in the manager.
            assert!(
                handle.next_request().await.is_none(),
                "unexpected extra request"
            );
        });
        let cfg = EntriesConfig {
            class_name: "test-class".into(),
            ready_timeout: Duration::from_millis(400),
            poll_interval: Duration::from_millis(10),
            claim_svid_ttl: "1h".into(),
        };
        let m = KubeEntryManager::new(
            client,
            Naming {
                trust_domain: TD.into(),
            },
            cfg,
        );
        (m, task)
    }

    async fn finish(m: KubeEntryManager, task: tokio::task::JoinHandle<()>) {
        drop(m); // closes the mock service so the responder sees end-of-script
        task.await.unwrap();
    }

    #[tokio::test]
    async fn claim_entry_is_declared_with_the_admission_shape_and_waits_for_set() {
        let uid = Uuid::parse_str("8d7c6b5a-4f3e-4d2c-9b1a-0f9e8d7c6b5a").unwrap();
        let name = claim_entry_name(uid);
        let mut create = step(
            "POST",
            "/apis/spire.spiffe.io/v1alpha1/clusterstaticentries",
            201,
            entry_json(&name, None, &json!({})),
        );
        create.check = Some(|v: &Value| {
            assert_eq!(
                v["metadata"]["name"],
                "mediatore-claim-8d7c6b5a-4f3e-4d2c-9b1a-0f9e8d7c6b5a"
            );
            assert_eq!(
                v["metadata"]["labels"]["app.kubernetes.io/managed-by"],
                "mediatore"
            );
            assert_eq!(v["metadata"]["labels"]["mediatore.io/kind"], "claim");
            assert_eq!(
                v["metadata"]["labels"]["mediatore.io/claim-uid"],
                "8d7c6b5a-4f3e-4d2c-9b1a-0f9e8d7c6b5a"
            );
            assert_eq!(
                v["spec"]["spiffeID"],
                "spiffe://sandbox.test/banlieue/claim/8d7c6b5a-4f3e-4d2c-9b1a-0f9e8d7c6b5a"
            );
            assert_eq!(
                v["spec"]["parentID"],
                format!("spiffe://sandbox.test/spire/agent/tpm/{EK}")
            );
            assert_eq!(v["spec"]["selectors"], json!(["unix:user:sb-0123456789ab"]));
            assert_eq!(v["spec"]["className"], "test-class");
            assert_eq!(v["spec"]["x509SVIDTTL"], "1h");
            assert!(v["spec"].get("admin").is_none());
            assert!(v["spec"].get("downstream").is_none());
            assert!(v["spec"].get("storeSVID").is_none());
            assert!(v["spec"].get("federatesWith").is_none());
            assert!(v["spec"].get("dnsNames").is_none());
        });
        let (m, task) = manager(vec![
            create,
            step(
                "GET",
                &name,
                200,
                entry_json(&name, Some((true, false, false)), &json!({})),
            ),
            step(
                "GET",
                &name,
                200,
                entry_json(&name, Some((true, false, true)), &json!({})),
            ),
        ]);
        let got = m
            .create_claim_entry(EK, uid, "sb-0123456789ab")
            .await
            .unwrap();
        assert_eq!(got, name);
        finish(m, task).await;
    }

    #[tokio::test]
    async fn node_entry_pins_root_and_the_agent_binary() {
        let name = node_entry_name(EK);
        let mut create = step(
            "POST",
            "clusterstaticentries",
            201,
            entry_json(&name, None, &json!({})),
        );
        create.check = Some(|v: &Value| {
            assert_eq!(
                v["spec"]["spiffeID"],
                format!("spiffe://sandbox.test/banlieue/node/{EK}")
            );
            assert_eq!(
                v["spec"]["parentID"],
                format!("spiffe://sandbox.test/spire/agent/tpm/{EK}")
            );
            assert_eq!(
                v["spec"]["selectors"],
                json!(["unix:uid:0", "unix:path:/usr/local/bin/mediatore-guest"])
            );
            assert_eq!(v["metadata"]["labels"]["mediatore.io/kind"], "node");
            assert!(
                v["metadata"]["labels"]
                    .get("mediatore.io/claim-uid")
                    .is_none()
            );
            assert!(v["spec"].get("x509SVIDTTL").is_none());
        });
        let (m, task) = manager(vec![
            create,
            step(
                "GET",
                &name,
                200,
                entry_json(&name, Some((true, false, true)), &json!({})),
            ),
        ]);
        assert_eq!(m.ensure_node_entry(EK).await.unwrap(), name);
        finish(m, task).await;
    }

    #[tokio::test]
    async fn an_existing_entry_is_tolerated_and_still_waited_for() {
        let name = node_entry_name(EK);
        let (m, task) = manager(vec![
            step(
                "POST",
                "clusterstaticentries",
                409,
                status_json(409, "AlreadyExists", "exists"),
            ),
            step(
                "GET",
                &name,
                200,
                entry_json(&name, Some((true, false, true)), &json!({})),
            ),
        ]);
        assert_eq!(m.ensure_node_entry(EK).await.unwrap(), name);
        finish(m, task).await;
    }

    #[tokio::test]
    async fn a_masked_entry_fails_the_claim() {
        let uid = Uuid::new_v4();
        let name = claim_entry_name(uid);
        let (m, task) = manager(vec![
            step(
                "POST",
                "clusterstaticentries",
                201,
                entry_json(&name, None, &json!({})),
            ),
            step(
                "GET",
                &name,
                200,
                entry_json(&name, Some((true, true, false)), &json!({})),
            ),
        ]);
        let err = m
            .create_claim_entry(EK, uid, "sb-0123456789ab")
            .await
            .unwrap_err();
        assert!(matches!(err, SpireError::Masked(n) if n == name));
        finish(m, task).await;
    }

    #[tokio::test]
    async fn never_set_times_out_instead_of_assuming() {
        let name = node_entry_name(EK);
        let mut steps = vec![step(
            "POST",
            "clusterstaticentries",
            201,
            entry_json(&name, None, &json!({})),
        )];
        // 400 ms timeout at a 10 ms poll: well under 60 GETs; the responder answers as many
        // as the manager sends, then the manager gives up.
        for _ in 0..60 {
            steps.push(step(
                "GET",
                &name,
                200,
                entry_json(&name, Some((true, false, false)), &json!({})),
            ));
        }
        let (svc, mut handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        let client = Client::new(svc, "default");
        let task = tokio::spawn(async move {
            while let Some((_req, send)) = handle.next_request().await {
                let s = steps.remove(0);
                send.send_response(
                    Response::builder()
                        .status(s.status)
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&s.body).unwrap()))
                        .unwrap(),
                );
            }
        });
        let m = KubeEntryManager::new(
            client,
            Naming {
                trust_domain: TD.into(),
            },
            EntriesConfig {
                class_name: "c".into(),
                ready_timeout: Duration::from_millis(100),
                poll_interval: Duration::from_millis(10),
                claim_svid_ttl: "1h".into(),
            },
        );
        let err = m.ensure_node_entry(EK).await.unwrap_err();
        assert!(matches!(err, SpireError::Timeout(n) if n == name));
        drop(m);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn admission_refusal_is_reported_as_denied() {
        let uid = Uuid::new_v4();
        let (m, task) = manager(vec![step(
            "POST",
            "clusterstaticentries",
            403,
            status_json(403, "Forbidden", "mediatore entries are never admin"),
        )]);
        let err = m
            .create_claim_entry(EK, uid, "sb-0123456789ab")
            .await
            .unwrap_err();
        assert!(matches!(err, SpireError::Denied(msg) if msg.contains("never admin")));
        finish(m, task).await;
    }

    #[tokio::test]
    async fn invalid_input_never_reaches_the_api_server() {
        let (m, task) = manager(vec![]);
        assert!(matches!(
            m.ensure_node_entry("3f9a").await,
            Err(SpireError::Invalid(_))
        ));
        assert!(matches!(
            m.create_claim_entry(EK, Uuid::new_v4(), "root").await,
            Err(SpireError::Invalid(_))
        ));
        finish(m, task).await;
    }

    #[tokio::test]
    async fn delete_tolerates_a_missing_entry() {
        let name = claim_entry_name(Uuid::new_v4());
        let (m, task) = manager(vec![
            step("DELETE", &name, 200, status_json(200, "", "")),
            step(
                "DELETE",
                &name,
                404,
                status_json(404, "NotFound", "not found"),
            ),
        ]);
        m.delete_entry(&name).await.unwrap();
        m.delete_entry(&name).await.unwrap();
        finish(m, task).await;
    }

    #[tokio::test]
    async fn list_selects_on_the_managed_by_label_and_maps_kinds() {
        let uid = Uuid::new_v4();
        let mut list = step(
            "GET",
            "clusterstaticentries",
            200,
            json!({
                "apiVersion": "spire.spiffe.io/v1alpha1", "kind": "ClusterStaticEntryList",
                "metadata": {}, "items": [
                    entry_json(&node_entry_name(EK), Some((true,false,true)),
                        &json!({"app.kubernetes.io/managed-by":"mediatore","mediatore.io/kind":"node"})),
                    entry_json(&claim_entry_name(uid), Some((true,false,true)),
                        &json!({"app.kubernetes.io/managed-by":"mediatore","mediatore.io/kind":"claim",
                               "mediatore.io/claim-uid": uid.to_string()})),
                    entry_json("someone-elses", None, &json!({"mediatore.io/kind":"other"})),
                ]
            }),
        );
        list.check = None;
        let (svc, mut handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        let client = Client::new(svc, "default");
        let task = tokio::spawn(async move {
            let (req, send) = handle.next_request().await.unwrap();
            assert!(
                req.uri()
                    .query()
                    .unwrap_or("")
                    .contains("labelSelector=app.kubernetes.io%2Fmanaged-by%3Dmediatore"),
                "query was {:?}",
                req.uri().query()
            );
            send.send_response(
                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&list.body).unwrap()))
                    .unwrap(),
            );
        });
        let m = KubeEntryManager::new(
            client,
            Naming {
                trust_domain: TD.into(),
            },
            EntriesConfig::default(),
        );
        let entries = m.list_entries().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            EntryRef {
                name: node_entry_name(EK),
                kind: EntryKind::Node,
                claim_uid: None
            }
        );
        assert_eq!(
            entries[1],
            EntryRef {
                name: claim_entry_name(uid),
                kind: EntryKind::Claim,
                claim_uid: Some(uid)
            }
        );
        drop(m);
        task.await.unwrap();
    }
}
