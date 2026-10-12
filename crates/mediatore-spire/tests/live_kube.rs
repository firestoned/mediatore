// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Live test of [`KubeEntryManager`] against a cluster that runs the SPIRE Controller
//! Manager with `deploy/base` applied (`ServiceAccount`, RBAC, admission policy).
//!
//! Every request runs as the broker's `ServiceAccount`, so what is exercised is what
//! production gets: the `ClusterRole` verbs and the `ValidatingAdmissionPolicy`. Either
//! the kubeconfig is an admin that impersonates it (the default), or it is the
//! `ServiceAccount` itself (`MEDIATORE_LIVE_IDENTITY=self`, for example a kubeconfig built
//! around `kubectl -n banlieue-system create token mediatore`). The test declares the two entry shapes, waits for
//! the controller manager to report `status.set` (a transient it catches with a watch
//! opened before the create), proves that admission refuses the shapes
//! ADR-0006 forbids and that RBAC refuses edits, then retracts everything it created.
//!
//! `make kind-e2e` runs it against SPIRE in a kind cluster; `docs/guides/testing.md` has
//! the tiers. Fixture (all required; a missing one fails, it never skips):
//!
//! ```sh
//! MEDIATORE_LIVE_KUBECONFIG=~/.kube/sandbox.yaml \
//! MEDIATORE_LIVE_TRUST_DOMAIN=sandbox.home.example \
//! MEDIATORE_LIVE_CLASS_NAME=spire-server-spire \
//! make live-admission-test
//! ```
//!
//! The parent agent (`spiffe://<td>/spire/agent/tpm/<ek>`) does not need to exist: the
//! server accepts an entry whose parent has not attested yet, which is exactly the order
//! in which a node entry is declared (ADR-0006 decision 3).

use std::panic::AssertUnwindSafe;

use futures::FutureExt as _;
use kube::api::{Api, DeleteParams, ObjectMeta, Patch, PatchParams, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};
use mediatore_spire::{
    ClusterStaticEntry, ClusterStaticEntrySpec, EntriesConfig, EntryKind, EntryManager,
    KubeEntryManager, Naming, claim_entry_name, node_entry_name,
};
use uuid::Uuid;

/// The RSA fixture's hash from `mediatore_proto::ek`; no real TPM has this key.
const EK: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";
const UNIX_USER: &str = "sb-0123456789ab";
const SERVICE_ACCOUNT: &str = "system:serviceaccount:banlieue-system:mediatore";
/// Name used by the admission negatives; must be `mediatore-*` so only the field under
/// test is what the policy refuses.
const BAD_NAME: &str = "mediatore-live-negative";

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is required: the live test fails without its fixture, it never skips")
    })
}

async fn as_service_account() -> Client {
    let kc = Kubeconfig::read_from(required("MEDIATORE_LIVE_KUBECONFIG"))
        .expect("read MEDIATORE_LIVE_KUBECONFIG");
    let mut cfg = Config::from_custom_kubeconfig(kc, &KubeConfigOptions::default())
        .await
        .expect("kubeconfig to client config");
    match std::env::var("MEDIATORE_LIVE_IDENTITY").as_deref() {
        Ok("self") => {}
        Ok("impersonate") | Err(_) => cfg.auth_info.impersonate = Some(SERVICE_ACCOUNT.into()),
        Ok(other) => panic!("MEDIATORE_LIVE_IDENTITY must be impersonate or self, not {other:?}"),
    }
    Client::try_from(cfg).expect("client")
}

fn fixture() -> (Naming, EntriesConfig) {
    let naming = Naming {
        trust_domain: required("MEDIATORE_LIVE_TRUST_DOMAIN"),
    };
    let cfg = EntriesConfig {
        class_name: required("MEDIATORE_LIVE_CLASS_NAME"),
        ..EntriesConfig::default()
    };
    (naming, cfg)
}

async fn delete_quietly(api: &Api<ClusterStaticEntry>, name: &str) {
    match api.delete(name, &DeleteParams::default()).await {
        Ok(_) => {}
        Err(kube::Error::Api(e)) if e.code == 404 => {}
        Err(e) => panic!("cleanup of {name} failed: {e}"),
    }
}

async fn cleanup(api: &Api<ClusterStaticEntry>, claim_uid: Uuid) {
    delete_quietly(api, &node_entry_name(EK)).await;
    delete_quietly(api, &claim_entry_name(claim_uid)).await;
    delete_quietly(api, BAD_NAME).await;
}

/// The admission policy must refuse this spec (403 for `reason: Forbidden`, 422 for
/// `reason: Invalid`) with a message containing `why`.
async fn expect_admission_denied(
    api: &Api<ClusterStaticEntry>,
    name: &str,
    spec: ClusterStaticEntrySpec,
    why: &str,
) {
    let obj = ClusterStaticEntry {
        metadata: ObjectMeta {
            name: Some(name.into()),
            ..ObjectMeta::default()
        },
        spec,
        status: None,
    };
    match api.create(&PostParams::default(), &obj).await {
        Err(kube::Error::Api(e)) if e.code == 403 || e.code == 422 => {
            assert!(
                e.message.contains(why),
                "denied for the wrong reason, wanted {why:?} in {:?}",
                e.message
            );
        }
        Err(e) => panic!("wanted admission 403 or 422 ({why}), got {e}"),
        Ok(_) => panic!("admission admitted a forbidden entry ({why}); it is now deleted"),
    }
}

#[tokio::test]
#[ignore = "needs a cluster with the SPIRE Controller Manager and deploy/base applied"]
async fn declares_waits_refuses_and_retracts() {
    let (naming, cfg) = fixture();
    let client = as_service_account().await;
    let api: Api<ClusterStaticEntry> = Api::all(client.clone());
    let claim_uid = Uuid::new_v4();

    cleanup(&api, claim_uid).await;
    // Cleanup runs whether the scenario returns an error or panics in an assertion.
    let outcome = AssertUnwindSafe(run(&api, client, naming, cfg, claim_uid))
        .catch_unwind()
        .await;
    cleanup(&api, claim_uid).await;
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("{e}"),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

// One sequential scenario on purpose: each step depends on cluster state the previous one made.
#[allow(clippy::too_many_lines)]
async fn run(
    api: &Api<ClusterStaticEntry>,
    client: Client,
    naming: Naming,
    cfg: EntriesConfig,
    claim_uid: Uuid,
) -> Result<(), String> {
    let class = cfg.class_name.clone();
    let mgr = KubeEntryManager::new(client, naming.clone(), cfg);

    // Node entry: declared, rendered and set by the controller manager.
    let node = match mgr.ensure_node_entry(EK).await {
        Ok(name) => name,
        Err(e) => {
            // Show what the controller manager actually wrote, so a timeout is diagnosable.
            let seen = api
                .get_opt(&node_entry_name(EK))
                .await
                .map_err(|e| e.to_string())?;
            return Err(format!(
                "ensure_node_entry: {e}; resource as seen: {seen:?}"
            ));
        }
    };
    assert_eq!(node, node_entry_name(EK));
    let got = api.get(&node).await.map_err(|e| e.to_string())?;
    let st = got.status.clone().unwrap_or_default();
    // Steady state: rendered, not masked; `set` was the transient the manager waited on.
    assert!(st.rendered && !st.masked, "node status {st:?}");
    assert_eq!(got.spec.spiffe_id, naming.node_id(EK));
    assert_eq!(got.spec.parent_id, naming.agent_id(EK));
    assert_eq!(got.spec.class_name.as_deref(), Some(class.as_str()));

    // Declaring it again is a no-op, not a 409 surfaced to the caller.
    let again = mgr
        .ensure_node_entry(EK)
        .await
        .map_err(|e| format!("second ensure_node_entry: {e}"))?;
    assert_eq!(again, node);

    // Claim entry.
    let claim = mgr
        .create_claim_entry(EK, claim_uid, UNIX_USER)
        .await
        .map_err(|e| format!("create_claim_entry: {e}"))?;
    assert_eq!(claim, claim_entry_name(claim_uid));
    let got = api.get(&claim).await.map_err(|e| e.to_string())?;
    let st = got.status.clone().unwrap_or_default();
    assert!(st.rendered && !st.masked, "claim status {st:?}");
    assert_eq!(got.spec.spiffe_id, naming.claim_id(claim_uid));
    assert_eq!(got.spec.selectors, vec![format!("unix:user:{UNIX_USER}")]);
    assert_eq!(got.spec.x509_svid_ttl.as_deref(), Some("1h"));

    // Both are listed under the managed-by label with their kinds.
    let listed = mgr.list_entries().await.map_err(|e| e.to_string())?;
    let node_ref = listed
        .iter()
        .find(|e| e.name == node)
        .ok_or("node entry not listed")?;
    assert_eq!(node_ref.kind, EntryKind::Node);
    assert_eq!(node_ref.claim_uid, None);
    let claim_ref = listed
        .iter()
        .find(|e| e.name == claim)
        .ok_or("claim entry not listed")?;
    assert_eq!(claim_ref.kind, EntryKind::Claim);
    assert_eq!(claim_ref.claim_uid, Some(claim_uid));

    // Admission refuses every shape ADR-0006 forbids, through this ServiceAccount.
    let td = &naming.trust_domain;
    let base = ClusterStaticEntrySpec {
        spiffe_id: naming.node_id(EK),
        parent_id: naming.agent_id(EK),
        selectors: vec!["unix:uid:0".into()],
        class_name: Some(class.clone()),
        x509_svid_ttl: None,
        hint: None,
    };
    expect_admission_denied(api, "not-mediatore", base.clone(), "named mediatore-*").await;
    expect_admission_denied(
        api,
        BAD_NAME,
        ClusterStaticEntrySpec {
            spiffe_id: format!("spiffe://{td}/mediatore"),
            ..base.clone()
        },
        "spiffeID must be",
    )
    .await;
    expect_admission_denied(
        api,
        BAD_NAME,
        ClusterStaticEntrySpec {
            parent_id: format!("spiffe://{td}/spire/agent/k8s_psat/x/y"),
            ..base.clone()
        },
        "parentID must be a tpm agent ID",
    )
    .await;
    let other_ek = "a".repeat(64);
    expect_admission_denied(
        api,
        BAD_NAME,
        ClusterStaticEntrySpec {
            parent_id: naming.agent_id(&other_ek),
            ..base.clone()
        },
        "must equal its parent agent's EK hash",
    )
    .await;
    expect_admission_denied(
        api,
        BAD_NAME,
        ClusterStaticEntrySpec {
            selectors: vec!["k8s:ns:kube-system".into()],
            ..base.clone()
        },
        "unix workload selectors",
    )
    .await;
    expect_admission_denied(
        api,
        BAD_NAME,
        ClusterStaticEntrySpec {
            spiffe_id: naming.claim_id(claim_uid),
            selectors: vec!["unix:uid:0".into()],
            ..base.clone()
        },
        "exactly one unix:user:sb-",
    )
    .await;
    expect_admission_denied(
        api,
        BAD_NAME,
        ClusterStaticEntrySpec {
            class_name: None,
            ..base.clone()
        },
        "className is required",
    )
    .await;
    expect_admission_denied(
        api,
        BAD_NAME,
        ClusterStaticEntrySpec {
            x509_svid_ttl: Some("24h".into()),
            ..base.clone()
        },
        "at most 4h",
    )
    .await;
    // Fields the client type does not even have: admin, downstream, storeSVID.
    for (field, why) in [
        ("admin", "never admin"),
        ("downstream", "never downstream"),
        ("storeSVID", "never use an SVIDStore"),
    ] {
        let mut raw = serde_json::to_value(&base).map_err(|e| e.to_string())?;
        raw[field] = serde_json::Value::Bool(true);
        let obj = serde_json::json!({
            "apiVersion": "spire.spiffe.io/v1alpha1",
            "kind": "ClusterStaticEntry",
            "metadata": { "name": BAD_NAME },
            "spec": raw,
        });
        let dyn_api: Api<kube::api::DynamicObject> = Api::all_with(
            api.clone().into_client(),
            &kube::api::ApiResource::erase::<ClusterStaticEntry>(&()),
        );
        let obj: kube::api::DynamicObject =
            serde_json::from_value(obj).map_err(|e| e.to_string())?;
        match dyn_api.create(&PostParams::default(), &obj).await {
            Err(kube::Error::Api(e)) if e.code == 403 || e.code == 422 => {
                assert!(e.message.contains(why), "{field}: {:?}", e.message);
            }
            Err(e) => return Err(format!("{field}: wanted admission 403 or 422, got {e}")),
            Ok(_) => return Err(format!("{field}: admission admitted a forbidden entry")),
        }
    }

    // RBAC refuses edits: entries are replaced, never updated or patched.
    let mut edited = api.get(&node).await.map_err(|e| e.to_string())?;
    edited.spec.hint = Some("edited".into());
    match api.replace(&node, &PostParams::default(), &edited).await {
        Err(kube::Error::Api(e)) if e.code == 403 => {}
        Err(e) => return Err(format!("replace: wanted RBAC 403, got {e}")),
        Ok(_) => return Err("RBAC allowed update on clusterstaticentries".into()),
    }
    let patch = serde_json::json!({ "spec": { "hint": "edited" } });
    match api
        .patch(&node, &PatchParams::default(), &Patch::Merge(&patch))
        .await
    {
        Err(kube::Error::Api(e)) if e.code == 403 => {}
        Err(e) => return Err(format!("patch: wanted RBAC 403, got {e}")),
        Ok(_) => return Err("RBAC allowed patch on clusterstaticentries".into()),
    }

    // Retraction, and retracting twice is fine.
    mgr.delete_entry(&claim)
        .await
        .map_err(|e| format!("delete claim: {e}"))?;
    mgr.delete_entry(&node)
        .await
        .map_err(|e| format!("delete node: {e}"))?;
    mgr.delete_entry(&node)
        .await
        .map_err(|e| format!("second delete node: {e}"))?;
    let listed = mgr.list_entries().await.map_err(|e| e.to_string())?;
    assert!(
        listed.iter().all(|e| e.name != node && e.name != claim),
        "retracted entries still listed: {listed:?}"
    );
    Ok(())
}
