// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! `ClusterStaticEntry` through the Kubernetes API (ADR-0006).
//!
//! The SPIRE Controller Manager renders each resource into a server entry over its private
//! socket and reports `status.rendered`, `status.masked` and `status.set`. `set` is written
//! true only by the reconcile pass that creates or updates the server entry; the next pass,
//! which that status write itself triggers, rewrites it to false. A declaration here
//! therefore watches the resource from before the create and succeeds on the `set`
//! transition; `masked` is a conflict and fails the claim.
//! Admission (`deploy/base/admission/clusterstaticentry-mediatore.yaml`) is the control
//! that holds even if this code is wrong; the validation here only refuses earlier.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::StreamExt as _;
use futures::stream::BoxStream;
use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, PostParams};
use kube::runtime::WatchStreamExt as _;
use kube::runtime::watcher::{self, Event, watcher};
use kube::{Client, CustomResource};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::x509pop::{NodeAttestation, node_entry_spec};
use crate::{
    CLAIM_UID_LABEL, ENTRIES_POLICY, ENTRIES_POLICY_SENDER_MESSAGE, EntryKind, EntryManager,
    EntryRef, KIND_LABEL, MANAGED_BY, MANAGED_BY_LABEL, Naming, SelfCheckError, SpireError,
    claim_entry_name, validate_ek_hash, validate_unix_user,
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
    /// `x509SVIDTTL` on claim entries, the most a claim SVID lives: bounds an agent that
    /// is offline when the entry disappears, and the identity a sandbox keeps when it can
    /// no longer renew (ADR-0027 decision 7: at most [`MAX_CLAIM_SVID_TTL`], and never
    /// more than the claim has left).
    pub claim_svid_ttl: Duration,
}

/// The most `claim_svid_ttl` may be (ADR-0027 decision 7): a released or cut-off claim's
/// identity ends within this.
pub const MAX_CLAIM_SVID_TTL: Duration = Duration::from_mins(15);

impl Default for EntriesConfig {
    fn default() -> Self {
        Self {
            class_name: "spire-server-spire".into(),
            ready_timeout: Duration::from_secs(30),
            claim_svid_ttl: MAX_CLAIM_SVID_TTL,
        }
    }
}

/// Name prefix of the entry the self-check sends: the broker's own prefix, so the policy
/// claims it by its name whoever the sender is.
const SELF_CHECK_NAME_PREFIX: &str = "mediatore-selfcheck-";
/// `spec.className` of that entry: the class of no controller manager, so the entry could
/// not be rendered into a server entry even on an API server that ignored the dry run.
const SELF_CHECK_CLASS: &str = "mediatore-selfcheck-never-rendered";

/// The entry [`KubeEntryManager`]'s self-check asks the API server to judge, as a dry run
/// (ADR-0056 decision 5). The policy claims it three times over (the name, the label, a
/// path under `/banlieue/`) and its validations refuse it twice: the SPIFFE ID is neither
/// a node's nor a claim's, and the parent is the SPIRE server, never a TPM agent. It is
/// well formed for the CRD's schema, so the schema is not what answers. It is never a
/// shape the policy admits; a test holds it to that.
fn self_check_probe(naming: &Naming) -> ClusterStaticEntry {
    let mut labels = BTreeMap::new();
    labels.insert(MANAGED_BY_LABEL.to_owned(), MANAGED_BY.to_owned());
    ClusterStaticEntry {
        metadata: ObjectMeta {
            name: Some(format!("{SELF_CHECK_NAME_PREFIX}{}", Uuid::new_v4())),
            labels: Some(labels),
            ..ObjectMeta::default()
        },
        spec: ClusterStaticEntrySpec {
            spiffe_id: format!(
                "spiffe://{}/banlieue/selfcheck/refused",
                naming.trust_domain
            ),
            parent_id: format!("spiffe://{}/spire/server", naming.trust_domain),
            selectors: vec!["unix:user:mediatore-selfcheck".to_owned()],
            class_name: Some(SELF_CHECK_CLASS.to_owned()),
            x509_svid_ttl: None,
            hint: Some("selfcheck".to_owned()),
        },
        status: None,
    }
}

/// What the API server says in a denial that names a policy it could not evaluate: the
/// binding's parameter was not found, or an expression failed (a key the parameter lacks).
const NOT_EVALUATED: [&str; 2] = ["failed to configure binding", "resulted in error"];

/// Read the API server's answer to the self-check's dry run. Only a refusal that names
/// the entries policy is proof, and only when it is not the policy's sender validation.
///
/// A denial by a `ValidatingAdmissionPolicy` is a `Status` whose code and reason are the
/// failed validation's (`Forbidden`, 403, for all but one of this policy's; `Invalid`,
/// 422, when a validation names none) and whose message names the policy. An RBAC
/// refusal is also a 403 `Forbidden`, and names no policy:
///
/// ```text
/// clusterstaticentries.spire.spiffe.io "NAME" is forbidden: ValidatingAdmissionPolicy 'POLICY' with binding 'BINDING' denied request: MESSAGE
/// clusterstaticentries.spire.spiffe.io is forbidden: User "USER" cannot create resource "clusterstaticentries" in API group "spire.spiffe.io" at the cluster scope
/// ```
///
/// The closing quote in the needle keeps `mediatore-clusterstaticentry-gateway`, the
/// gateway entries' policy, from standing in for this one.
///
/// The policy reads the broker's username from a parameter (ADR-0056 decision 4). When
/// the parameter is absent, or lacks the key, the API server still refuses and still
/// names the policy, but it judged nothing: it could not configure the binding, or an
/// expression failed. Both read as below (Kubernetes 1.30 and 1.36, the kind tiers), and
/// neither is proof: the refusal would be the same for a permitted entry.
///
/// ```text
/// ... ValidatingAdmissionPolicy 'POLICY' with binding 'BINDING' denied request: failed to configure binding: no params found for policy binding with `Deny` parameterNotFoundAction
/// ... ValidatingAdmissionPolicy 'POLICY' with binding 'BINDING' denied request: expression '...' resulted in error: no such key: broker
/// ```
fn judge_self_check(
    name: &str,
    answer: Result<ClusterStaticEntry, kube::Error>,
) -> Result<(), SelfCheckError> {
    let status = match answer {
        Ok(_) => return Err(SelfCheckError::Admitted(name.to_owned())),
        Err(kube::Error::Api(status)) => status,
        Err(e) => return Err(SelfCheckError::Unreachable(e.to_string())),
    };
    let by_the_policy = matches!(status.code, 403 | 422)
        && status
            .message
            .contains(&format!("ValidatingAdmissionPolicy '{ENTRIES_POLICY}'"));
    if by_the_policy {
        if status.message.contains(ENTRIES_POLICY_SENDER_MESSAGE) {
            return Err(SelfCheckError::NotTheBroker(status.message.clone()));
        }
        if NOT_EVALUATED.iter().any(|n| status.message.contains(n)) {
            return Err(SelfCheckError::Parameter(status.message.clone()));
        }
        return Ok(());
    }
    if status.code == 403 && status.message.contains("cannot create resource") {
        return Err(SelfCheckError::Rbac(status.message.clone()));
    }
    Err(SelfCheckError::Refused {
        code: status.code,
        message: status.message.clone(),
    })
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
        mediatore_proto::tls::ensure_provider();
        Self {
            api: Api::all(client),
            naming,
            cfg,
        }
    }

    /// The claim entry's `x509SVIDTTL`: the configured bound, or the time the claim has
    /// left when that is shorter, never below one second; in seconds, a form the controller
    /// manager and the admission policy's `duration()` both read.
    fn claim_svid_ttl(&self, claim_ttl: Duration) -> String {
        let ttl = self
            .cfg
            .claim_svid_ttl
            .min(claim_ttl)
            .max(Duration::from_secs(1));
        format!("{}s", ttl.as_secs())
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

    /// Create the resource (tolerating one that already exists) and wait until the
    /// controller manager has put the entry on the server.
    ///
    /// The watch is opened, and its initial list completed, before the create: the `set`
    /// transition lasts milliseconds (`spireentry/reconciler.go`, `IncrementEntrySuccess`
    /// on the creating pass, nothing on the steady-state pass), so only a watch holding a
    /// resource version from before the create sees it. Polling cannot.
    async fn declare(
        &self,
        name: &str,
        labels: BTreeMap<String, String>,
        spec: ClusterStaticEntrySpec,
    ) -> Result<String, SpireError> {
        let deadline = Instant::now() + self.cfg.ready_timeout;
        let wc = watcher::Config::default().fields(&format!("metadata.name={name}"));
        let mut stream = watcher(self.api.clone(), wc).default_backoff().boxed();
        let existing = Self::initial_state(&mut stream, name, deadline).await?;

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
                // Declared earlier. Its steady state is `rendered` without `set`; the
                // controller manager owns it from here and retries server failures itself.
                if let Some(st) = existing.as_ref().and_then(|o| o.status.as_ref()) {
                    Self::judge(name, st)?;
                    tracing::debug!(name, "entry already declared and rendered");
                    return Ok(name.to_owned());
                }
                tracing::debug!(name, "entry already declared, not yet reconciled");
            }
            Err(kube::Error::Api(e)) if e.code == 403 => return Err(SpireError::Denied(e.message)),
            Err(e) => return Err(SpireError::Api(e.to_string())),
        }
        Self::wait_for_set(&mut stream, name, deadline).await?;
        Ok(name.to_owned())
    }

    /// A status is only ever written by the controller manager: `masked` is a conflict,
    /// and not `rendered` means it refused the spec (its log says why).
    fn judge(name: &str, st: &ClusterStaticEntryStatus) -> Result<(), SpireError> {
        if st.masked {
            return Err(SpireError::Masked(name.to_owned()));
        }
        if !st.rendered {
            return Err(SpireError::Invalid(format!(
                "entry {name} did not render; see the controller manager log"
            )));
        }
        Ok(())
    }

    /// Drive the watcher through its initial list; the resource, if it already exists.
    async fn initial_state(
        stream: &mut EventStream,
        name: &str,
        deadline: Instant,
    ) -> Result<Option<ClusterStaticEntry>, SpireError> {
        let mut existing = None;
        loop {
            match Self::next_event(stream, name, deadline).await? {
                Event::InitApply(o) => existing = Some(o),
                Event::InitDone => return Ok(existing),
                Event::Init | Event::Apply(_) | Event::Delete(_) => {}
            }
        }
    }

    /// Succeed on the `set` transition. A relist (after a watch error) that finds the
    /// resource rendered is accepted too, by the same rule as a 409: the transition may
    /// have passed during the gap and the controller manager owns the entry from here.
    async fn wait_for_set(
        stream: &mut EventStream,
        name: &str,
        deadline: Instant,
    ) -> Result<(), SpireError> {
        loop {
            match Self::next_event(stream, name, deadline).await? {
                Event::Apply(o) => {
                    if let Some(st) = &o.status {
                        Self::judge(name, st)?;
                        if st.set {
                            tracing::info!(name, "entry set on the SPIRE server");
                            return Ok(());
                        }
                    }
                }
                Event::InitApply(o) => {
                    if let Some(st) = &o.status {
                        Self::judge(name, st)?;
                        tracing::info!(name, "entry rendered (seen on relist)");
                        return Ok(());
                    }
                }
                Event::Delete(_) => {
                    return Err(SpireError::Api(format!(
                        "entry {name} was deleted while waiting for it"
                    )));
                }
                Event::Init | Event::InitDone => {}
            }
        }
    }

    /// The next watch event before the deadline. Watch errors are logged and the stream
    /// goes on (the watcher relists with backoff); the deadline is what bounds the wait.
    async fn next_event(
        stream: &mut EventStream,
        name: &str,
        deadline: Instant,
    ) -> Result<Event<ClusterStaticEntry>, SpireError> {
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(SpireError::Timeout(name.to_owned()));
            }
            match tokio::time::timeout(left, stream.next()).await {
                Err(_) => return Err(SpireError::Timeout(name.to_owned())),
                Ok(None) => return Err(SpireError::Api(format!("watch on {name} ended"))),
                Ok(Some(Err(e))) => tracing::warn!(name, error = %e, "watch error, retrying"),
                Ok(Some(Ok(ev))) => return Ok(ev),
            }
        }
    }
}

type EventStream = BoxStream<'static, Result<Event<ClusterStaticEntry>, watcher::Error>>;

#[async_trait]
impl EntryManager for KubeEntryManager {
    async fn ensure_node_entry(&self, ek_hash: &str) -> Result<String, SpireError> {
        let attestation = NodeAttestation::Tpm {
            ek_hash: ek_hash.to_owned(),
        };
        let (name, spec) = node_entry_spec(&self.naming, &attestation, &self.cfg.class_name)?;
        self.declare(&name, Self::labels(EntryKind::Node, None), spec)
            .await
    }

    async fn create_claim_entry(
        &self,
        ek_hash: &str,
        claim_uid: Uuid,
        unix_user: &str,
        claim_ttl: Duration,
    ) -> Result<String, SpireError> {
        validate_ek_hash(ek_hash)?;
        validate_unix_user(unix_user)?;
        let name = claim_entry_name(claim_uid);
        let spec = ClusterStaticEntrySpec {
            spiffe_id: self.naming.claim_id(claim_uid),
            parent_id: self.naming.agent_id(ek_hash),
            selectors: vec![format!("unix:user:{unix_user}")],
            class_name: Some(self.cfg.class_name.clone()),
            x509_svid_ttl: Some(self.claim_svid_ttl(claim_ttl)),
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
                    parent_id: Some(o.spec.parent_id),
                    kind,
                    claim_uid,
                })
            })
            .collect())
    }

    /// A server-side dry-run create (`dryRun=All`: admission runs, nothing is stored) of
    /// the entry `self_check_probe` builds, which the policy must refuse. Needs no verb
    /// beyond the `create` a declaration already uses (`deploy/base/rbac.yaml`).
    async fn self_check(&self) -> Result<(), SelfCheckError> {
        let probe = self_check_probe(&self.naming);
        let name = probe.metadata.name.clone().unwrap_or_default();
        let dry_run = PostParams {
            dry_run: true,
            field_manager: None,
        };
        judge_self_check(&name, self.api.create(&dry_run, &probe).await)?;
        tracing::info!(
            name,
            policy = ENTRIES_POLICY,
            "entries: the admission policy refused a forbidden dry-run entry (self-check passed)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! A scripted fake API server: each step asserts the request it expects and answers
    //! with a canned response, so the manager's list / create / 409 / 403 / watch / 404
    //! paths are exercised without a cluster. A declaration is LIST (the watcher's initial
    //! list), POST, then WATCH; the watch body is newline-delimited events.

    use http::{Request, Response};
    use http_body_util::BodyExt as _;
    use kube::client::Body;
    use serde_json::{Value, json};

    use super::*;
    use crate::node_entry_name;

    const EK: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";
    const TD: &str = "sandbox.test";

    struct Step {
        method: &'static str,
        path_contains: String,
        /// `Some("watch=true")` for the watch request, `Some("")` for anything else.
        query_contains: &'static str,
        status: u16,
        body: Vec<u8>,
        check: Option<fn(&Value)>,
    }

    fn step(method: &'static str, path: &str, status: u16, body: &Value) -> Step {
        Step {
            method,
            path_contains: path.to_owned(),
            query_contains: "",
            status,
            body: serde_json::to_vec(body).unwrap(),
            check: None,
        }
    }

    fn entry_json(name: &str, status: Option<(bool, bool, bool)>, labels: &Value) -> Value {
        let mut v = json!({
            "apiVersion": "spire.spiffe.io/v1alpha1",
            "kind": "ClusterStaticEntry",
            "metadata": { "name": name, "labels": labels, "resourceVersion": "7" },
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

    /// The watcher's initial list, scoped to one name by field selector.
    fn list(items: &[Value]) -> Step {
        let mut s = step(
            "GET",
            "clusterstaticentries",
            200,
            &json!({
                "apiVersion": "spire.spiffe.io/v1alpha1", "kind": "ClusterStaticEntryList",
                "metadata": { "resourceVersion": "5" }, "items": items
            }),
        );
        s.query_contains = "fieldSelector=metadata.name%3D";
        s
    }

    /// The watch: a body of `{"type": ..., "object": ...}` lines, then end of stream.
    fn watch(events: &[(&str, Value)]) -> Step {
        let mut body = Vec::new();
        for (kind, obj) in events {
            body.extend(serde_json::to_vec(&json!({ "type": kind, "object": obj })).unwrap());
            body.push(b'\n');
        }
        Step {
            method: "GET",
            path_contains: "clusterstaticentries".into(),
            query_contains: "watch=true",
            status: 200,
            body,
            check: None,
        }
    }

    fn post(status: u16, body: &Value) -> Step {
        step("POST", "clusterstaticentries", status, body)
    }

    fn respond(send: tower_test::mock::SendResponse<Response<Body>>, status: u16, body: Vec<u8>) {
        send.send_response(
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        );
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
                let query = req.uri().query().unwrap_or("").to_owned();
                assert!(
                    query.contains(s.query_contains),
                    "query {query:?} should contain {:?}",
                    s.query_contains
                );
                if s.method != "GET" {
                    assert!(!query.contains("watch=true"));
                }
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                if let Some(check) = s.check {
                    check(&serde_json::from_slice::<Value>(&bytes).unwrap());
                }
                respond(send, s.status, s.body);
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
            claim_svid_ttl: Duration::from_mins(15),
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
        let mut create = post(201, &entry_json(&name, None, &json!({})));
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
            assert_eq!(
                v["spec"]["x509SVIDTTL"], "900s",
                "the configured bound, the claim having longer left"
            );
            assert!(v["spec"].get("admin").is_none());
            assert!(v["spec"].get("downstream").is_none());
            assert!(v["spec"].get("storeSVID").is_none());
            assert!(v["spec"].get("federatesWith").is_none());
            assert!(v["spec"].get("dnsNames").is_none());
        });
        // The controller manager's two writes, as observed live: set on the creating
        // pass, then back to the steady state. The first one is what we wait for.
        let (m, task) = manager(vec![
            list(&[]),
            create,
            watch(&[
                ("ADDED", entry_json(&name, None, &json!({}))),
                (
                    "MODIFIED",
                    entry_json(&name, Some((true, false, true)), &json!({})),
                ),
                (
                    "MODIFIED",
                    entry_json(&name, Some((true, false, false)), &json!({})),
                ),
            ]),
        ]);
        let got = m
            .create_claim_entry(EK, uid, "sb-0123456789ab", Duration::from_hours(1))
            .await
            .unwrap();
        assert_eq!(got, name);
        finish(m, task).await;
    }

    #[tokio::test]
    async fn node_entry_pins_root_and_the_agent_binary() {
        let name = node_entry_name(EK);
        let mut create = post(201, &entry_json(&name, None, &json!({})));
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
                json!(["unix:uid:0", "unix:path:/usr/bin/mediatore"])
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
            list(&[]),
            create,
            watch(&[(
                "MODIFIED",
                entry_json(&name, Some((true, false, true)), &json!({})),
            )]),
        ]);
        assert_eq!(m.ensure_node_entry(EK).await.unwrap(), name);
        finish(m, task).await;
    }

    #[tokio::test]
    async fn an_existing_rendered_entry_is_accepted_without_a_watch() {
        // Steady state: rendered, not set. The 409 confirms it is ours to keep.
        let name = node_entry_name(EK);
        let (m, task) = manager(vec![
            list(&[entry_json(&name, Some((true, false, false)), &json!({}))]),
            post(409, &status_json(409, "AlreadyExists", "exists")),
        ]);
        assert_eq!(m.ensure_node_entry(EK).await.unwrap(), name);
        finish(m, task).await;
    }

    #[tokio::test]
    async fn an_existing_unreconciled_entry_is_still_waited_for() {
        let name = node_entry_name(EK);
        let (m, task) = manager(vec![
            list(&[entry_json(&name, None, &json!({}))]),
            post(409, &status_json(409, "AlreadyExists", "exists")),
            watch(&[(
                "MODIFIED",
                entry_json(&name, Some((true, false, true)), &json!({})),
            )]),
        ]);
        assert_eq!(m.ensure_node_entry(EK).await.unwrap(), name);
        finish(m, task).await;
    }

    #[tokio::test]
    async fn an_existing_masked_entry_fails_without_a_watch() {
        let name = node_entry_name(EK);
        let (m, task) = manager(vec![
            list(&[entry_json(&name, Some((true, true, false)), &json!({}))]),
            post(409, &status_json(409, "AlreadyExists", "exists")),
        ]);
        let err = m.ensure_node_entry(EK).await.unwrap_err();
        assert!(matches!(err, SpireError::Masked(n) if n == name));
        finish(m, task).await;
    }

    #[tokio::test]
    async fn a_masked_entry_fails_the_claim() {
        let uid = Uuid::new_v4();
        let name = claim_entry_name(uid);
        let (m, task) = manager(vec![
            list(&[]),
            post(201, &entry_json(&name, None, &json!({}))),
            watch(&[(
                "MODIFIED",
                entry_json(&name, Some((true, true, false)), &json!({})),
            )]),
        ]);
        let err = m
            .create_claim_entry(EK, uid, "sb-0123456789ab", Duration::from_hours(1))
            .await
            .unwrap_err();
        assert!(matches!(err, SpireError::Masked(n) if n == name));
        finish(m, task).await;
    }

    #[tokio::test]
    async fn an_entry_the_controller_manager_refuses_to_render_fails_fast() {
        let uid = Uuid::new_v4();
        let name = claim_entry_name(uid);
        let (m, task) = manager(vec![
            list(&[]),
            post(201, &entry_json(&name, None, &json!({}))),
            watch(&[(
                "MODIFIED",
                entry_json(&name, Some((false, false, false)), &json!({})),
            )]),
        ]);
        let err = m
            .create_claim_entry(EK, uid, "sb-0123456789ab", Duration::from_hours(1))
            .await
            .unwrap_err();
        assert!(matches!(err, SpireError::Invalid(msg) if msg.contains("did not render")));
        finish(m, task).await;
    }

    #[tokio::test]
    async fn never_set_times_out_instead_of_assuming() {
        let name = node_entry_name(EK);
        let (svc, mut handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        let client = Client::new(svc, "default");
        let task = tokio::spawn(async move {
            let list_body = serde_json::to_vec(&json!({
                "apiVersion": "spire.spiffe.io/v1alpha1", "kind": "ClusterStaticEntryList",
                "metadata": { "resourceVersion": "5" }, "items": []
            }))
            .unwrap();
            let (_req, send) = handle.next_request().await.unwrap();
            respond(send, 200, list_body);
            let (_req, send) = handle.next_request().await.unwrap();
            respond(
                send,
                201,
                serde_json::to_vec(&entry_json(&name, None, &json!({}))).unwrap(),
            );
            // The watch is held open and never answered: the manager must give up on its
            // own deadline rather than assume.
            let mut held = Vec::new();
            while let Some((req, send)) = handle.next_request().await {
                assert!(req.uri().query().unwrap_or("").contains("watch=true"));
                held.push(send);
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
                claim_svid_ttl: Duration::from_mins(15),
            },
        );
        let err = m.ensure_node_entry(EK).await.unwrap_err();
        assert!(matches!(err, SpireError::Timeout(n) if n == node_entry_name(EK)));
        drop(m);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn admission_refusal_is_reported_as_denied() {
        let uid = Uuid::new_v4();
        let (m, task) = manager(vec![
            list(&[]),
            post(
                403,
                &status_json(403, "Forbidden", "mediatore entries are never admin"),
            ),
        ]);
        let err = m
            .create_claim_entry(EK, uid, "sb-0123456789ab", Duration::from_hours(1))
            .await
            .unwrap_err();
        assert!(matches!(err, SpireError::Denied(msg) if msg.contains("never admin")));
        finish(m, task).await;
    }

    /// What the API server answers when the entries policy denies: the validation's
    /// reason and code, the policy and its binding named in the message.
    fn policy_denial(code: u16, reason: &str, policy: &str, why: &str) -> Value {
        status_json(
            code,
            reason,
            &format!(
                "clusterstaticentries.spire.spiffe.io \"mediatore-selfcheck-0\" is forbidden: ValidatingAdmissionPolicy '{policy}' with binding '{policy}' denied request: {why}"
            ),
        )
    }

    /// The self-check's one request: a POST that must be a dry run, of the refused shape.
    fn dry_run_post(status: u16, body: &Value) -> Step {
        let mut s = post(status, body);
        s.query_contains = "dryRun=All";
        s.check = Some(|v: &Value| {
            let name = v["metadata"]["name"].as_str().unwrap();
            assert!(name.starts_with("mediatore-selfcheck-"), "{name}");
            assert_eq!(
                v["metadata"]["labels"]["app.kubernetes.io/managed-by"],
                "mediatore"
            );
            assert_eq!(
                v["spec"]["spiffeID"],
                "spiffe://sandbox.test/banlieue/selfcheck/refused"
            );
            assert_eq!(v["spec"]["parentID"], "spiffe://sandbox.test/spire/server");
            assert_eq!(
                v["spec"]["className"], "mediatore-selfcheck-never-rendered",
                "never the configured class: no controller manager would render it"
            );
            assert!(v["spec"].get("admin").is_none());
        });
        s
    }

    const SPIFFE_ID_RULE: &str = "spiffeID must be spiffe://<td>/banlieue/node/<ek-hash> or spiffe://<td>/banlieue/claim/<uuid>";

    #[tokio::test]
    async fn the_self_check_passes_on_the_policys_denial_of_a_dry_run() {
        // 403 Forbidden is what this policy's validations answer; 422 Invalid is what a
        // validation without a reason answers. Both name the policy.
        for (code, reason) in [(403, "Forbidden"), (422, "Invalid")] {
            let (m, task) = manager(vec![dry_run_post(
                code,
                &policy_denial(code, reason, ENTRIES_POLICY, SPIFFE_ID_RULE),
            )]);
            assert_eq!(m.self_check().await, Ok(()), "{code} {reason}");
            finish(m, task).await;
        }
    }

    #[tokio::test]
    async fn the_self_check_fails_when_the_forbidden_entry_is_admitted() {
        // The finding: a policy that matches nothing this identity sends admits it, and
        // nothing else would ever say so.
        let (m, task) = manager(vec![dry_run_post(
            201,
            &entry_json("mediatore-selfcheck-0", None, &json!({})),
        )]);
        let err = m.self_check().await.unwrap_err();
        assert!(
            matches!(&err, SelfCheckError::Admitted(n) if n.starts_with("mediatore-selfcheck-")),
            "{err:?}"
        );
        assert!(
            err.to_string().contains("not in force for this identity"),
            "{err}"
        );
        finish(m, task).await;
    }

    #[tokio::test]
    async fn an_rbac_403_is_not_proof_and_is_reported_as_rbac() {
        let (m, task) = manager(vec![dry_run_post(
            403,
            &status_json(
                403,
                "Forbidden",
                "clusterstaticentries.spire.spiffe.io is forbidden: User \"system:serviceaccount:elsewhere:broker\" cannot create resource \"clusterstaticentries\" in API group \"spire.spiffe.io\" at the cluster scope",
            ),
        )]);
        let err = m.self_check().await.unwrap_err();
        assert!(matches!(err, SelfCheckError::Rbac(_)), "{err:?}");
        finish(m, task).await;
    }

    #[tokio::test]
    async fn the_policys_sender_refusal_is_a_broker_the_policy_does_not_name() {
        // A renamed ServiceAccount with the policy left as shipped: in force, and it would
        // refuse every real entry. Said at start, not at the first bind.
        let (m, task) = manager(vec![dry_run_post(
            403,
            &policy_denial(
                403,
                "Forbidden",
                ENTRIES_POLICY,
                ENTRIES_POLICY_SENDER_MESSAGE,
            ),
        )]);
        let err = m.self_check().await.unwrap_err();
        assert!(matches!(err, SelfCheckError::NotTheBroker(_)), "{err:?}");
        finish(m, task).await;
    }

    #[tokio::test]
    async fn a_policy_that_could_not_read_its_parameter_is_not_proof() {
        // The two answers of an API server whose entries policy has no parameter to read:
        // the ConfigMap is gone, or it has no `broker` key. Both name the policy and both
        // would refuse a permitted entry too, so neither proves the policy judged anything.
        for why in [
            "failed to configure binding: no params found for policy binding with `Deny` parameterNotFoundAction",
            "expression 'request.userInfo.username == params.data.broker.trim() || (request.operation == 'UPDATE' && oldObject.spec == object.spec)' resulted in error: no such key: broker",
        ] {
            let (m, task) = manager(vec![dry_run_post(
                422,
                &policy_denial(422, "Invalid", ENTRIES_POLICY, why),
            )]);
            let err = m.self_check().await.unwrap_err();
            assert!(matches!(err, SelfCheckError::Parameter(_)), "{err:?}");
            assert!(err.to_string().contains("cannot be evaluated"), "{err}");
            finish(m, task).await;
        }
    }

    #[tokio::test]
    async fn a_refusal_that_is_not_the_entries_policys_is_not_proof() {
        // Another policy (the gateway entries', whose name only begins like this one's),
        // the CRD's schema, a missing CRD, a policy message under a code no denial has.
        let other = format!("{ENTRIES_POLICY}-gateway");
        for (code, body) in [
            (
                403,
                policy_denial(
                    403,
                    "Forbidden",
                    &other,
                    "nothing else lives under /gateway",
                ),
            ),
            (
                422,
                status_json(422, "Invalid", "spec.selectors: Required value"),
            ),
            (
                404,
                status_json(
                    404,
                    "NotFound",
                    "the server could not find the requested resource",
                ),
            ),
            (
                500,
                policy_denial(500, "InternalError", ENTRIES_POLICY, SPIFFE_ID_RULE),
            ),
        ] {
            let (m, task) = manager(vec![dry_run_post(code, &body)]);
            let err = m.self_check().await.unwrap_err();
            assert!(
                matches!(&err, SelfCheckError::Refused { code: c, .. } if *c == code),
                "{code}: {err:?}"
            );
            finish(m, task).await;
        }
    }

    #[tokio::test]
    async fn an_api_server_that_does_not_answer_fails_the_self_check_as_unreachable() {
        let (svc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        drop(handle); // nothing listens: every request fails before any answer
        let m = KubeEntryManager::new(
            Client::new(svc, "default"),
            Naming {
                trust_domain: TD.into(),
            },
            EntriesConfig::default(),
        );
        let err = m.self_check().await.unwrap_err();
        assert!(matches!(err, SelfCheckError::Unreachable(_)), "{err:?}");
    }

    #[test]
    fn the_self_check_probe_is_never_a_shape_the_policy_admits() {
        // The policy's two anchors, as its second and third validations spell them.
        let probe = self_check_probe(&Naming {
            trust_domain: TD.into(),
        });
        let name = probe.metadata.name.as_deref().unwrap();
        assert!(
            name.starts_with("mediatore-"),
            "claimed by its name: {name}"
        );
        assert!(name.len() <= 253, "a valid object name: {name}");
        let labels = probe.metadata.labels.as_ref().unwrap();
        assert_eq!(
            labels.get(MANAGED_BY_LABEL).map(String::as_str),
            Some(MANAGED_BY)
        );
        let id = &probe.spec.spiffe_id;
        assert!(
            id.starts_with("spiffe://sandbox.test/banlieue/"),
            "claimed by its path: {id}"
        );
        assert!(!id.contains("/banlieue/node/"), "not a node ID: {id}");
        assert!(!id.contains("/banlieue/claim/"), "not a claim ID: {id}");
        assert!(
            !id.contains("/gateway"),
            "never the gateway policy's to judge: {id}"
        );
        let parent = &probe.spec.parent_id;
        assert!(!parent.contains("/spire/agent/"), "not an agent: {parent}");
        assert_ne!(
            probe.spec.class_name.as_deref(),
            Some(EntriesConfig::default().class_name.as_str())
        );
        // Two probes never collide on a name, so a 409 is never the answer.
        let again = self_check_probe(&Naming {
            trust_domain: TD.into(),
        });
        assert_ne!(probe.metadata.name, again.metadata.name);
    }

    #[tokio::test]
    async fn invalid_input_never_reaches_the_api_server() {
        let (m, task) = manager(vec![]);
        assert!(matches!(
            m.ensure_node_entry("3f9a").await,
            Err(SpireError::Invalid(_))
        ));
        assert!(matches!(
            m.create_claim_entry(EK, Uuid::new_v4(), "root", Duration::from_hours(1))
                .await,
            Err(SpireError::Invalid(_))
        ));
        finish(m, task).await;
    }

    #[tokio::test]
    async fn the_claim_svid_ttl_is_the_bound_or_what_the_claim_has_left_whichever_is_shorter() {
        let (m, task) = manager(vec![]);
        assert_eq!(m.claim_svid_ttl(Duration::from_hours(1)), "900s");
        assert_eq!(m.claim_svid_ttl(Duration::from_mins(15)), "900s");
        assert_eq!(
            m.claim_svid_ttl(Duration::from_mins(5)),
            "300s",
            "ADR-0027 decision 7: never past the claim's deadline"
        );
        assert_eq!(m.claim_svid_ttl(Duration::ZERO), "1s");
        assert!(EntriesConfig::default().claim_svid_ttl <= MAX_CLAIM_SVID_TTL);
        finish(m, task).await;
    }

    #[tokio::test]
    async fn delete_tolerates_a_missing_entry() {
        let name = claim_entry_name(Uuid::new_v4());
        let (m, task) = manager(vec![
            step("DELETE", &name, 200, &status_json(200, "", "")),
            step(
                "DELETE",
                &name,
                404,
                &status_json(404, "NotFound", "not found"),
            ),
        ]);
        m.delete_entry(&name).await.unwrap();
        m.delete_entry(&name).await.unwrap();
        finish(m, task).await;
    }

    #[tokio::test]
    async fn list_selects_on_the_managed_by_label_and_maps_kinds() {
        let uid = Uuid::new_v4();
        let mut entries = step(
            "GET",
            "clusterstaticentries",
            200,
            &json!({
                "apiVersion": "spire.spiffe.io/v1alpha1", "kind": "ClusterStaticEntryList",
                "metadata": {}, "items": [
                    entry_json(&node_entry_name(EK), Some((true,false,false)),
                        &json!({"app.kubernetes.io/managed-by":"mediatore","mediatore.io/kind":"node"})),
                    entry_json(&claim_entry_name(uid), Some((true,false,false)),
                        &json!({"app.kubernetes.io/managed-by":"mediatore","mediatore.io/kind":"claim",
                               "mediatore.io/claim-uid": uid.to_string()})),
                    entry_json("someone-elses", None, &json!({"mediatore.io/kind":"other"})),
                ]
            }),
        );
        entries.query_contains = "labelSelector=app.kubernetes.io%2Fmanaged-by%3Dmediatore";
        let (m, task) = manager(vec![entries]);
        let got = m.list_entries().await.unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[0],
            EntryRef {
                name: node_entry_name(EK),
                kind: EntryKind::Node,
                claim_uid: None,
                parent_id: Some("y".into())
            }
        );
        assert_eq!(
            got[1],
            EntryRef {
                name: claim_entry_name(uid),
                kind: EntryKind::Claim,
                claim_uid: Some(uid),
                parent_id: Some("y".into())
            }
        );
        finish(m, task).await;
    }
}
