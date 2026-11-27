// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The user API outside `dev_mode` (ADR-0008 decision 4): `POST /v1/claims` creates an
//! `AgentSandbox` with the token's subject, `GET` answers from its status, `DELETE` deletes
//! it. The Kubernetes API is `mediatore_testkit::MemorySandboxes`; everything else
//! (token validation, the audience check, the subject gate) is the production path.

use std::future::IntoFuture;
use std::sync::Arc;

use banlieue_api::common::LocalObjectReference;
use mediatore_api::{AppState, Limiter, Namespaces};
use mediatore_claims::sandbox::{AgentSandboxStatus, SandboxPhase};
use mediatore_entra::{Backend, IssuerConfig, Validator};
use mediatore_proto::{ClaimPhase, ClaimRequest, ClaimResponse, ErrorBody, PoolSelector, Workload};
use mediatore_spire::Naming;
use mediatore_store::MemoryStore;
use mediatore_testkit::{FakeIdp, MemorySandboxes};

const AUDIENCE: &str = "grafana.test";
const NAMESPACE: &str = "agents";

struct Harness {
    idp: FakeIdp,
    user_url: String,
    sandboxes: Arc<MemorySandboxes>,
    http: reqwest::Client,
}

/// The broker's state outside `dev_mode`: the production path over the in-memory Kubernetes
/// API, store and entries.
fn app_state(idp: &FakeIdp, sandboxes: &Arc<MemorySandboxes>, front_door: bool) -> AppState {
    AppState {
        tripwires: mediatore_api::Tripwires::default(),
        inject: std::collections::BTreeMap::new(),
        inject_port: None,
        audience_catalog: None,
        logs: None,
        log_limiter: Limiter::per_second(2),
        log_wakes: mediatore_api::LogWakes::default(),
        accept_plain_gateway_identity: false,
        scopes: std::collections::BTreeMap::new(),
        store: MemoryStore::shared(),
        spire: Arc::new(mediatore_spire::MemoryEntries::default()),
        naming: Naming {
            trust_domain: "sandbox.test".into(),
        },
        validator: Validator::new(vec![IssuerConfig {
            url: idp.issuer.clone(),
            backend: Backend::Sts,
            client_id: "mediatore".into(),
            subject_claim: "preferred_username".into(),
            required_group: None,
            required_groups: None,
            allow_any_authenticated: true,
            session: None,
            ca_file: None,
            entra: None,
            groups_claim: None,
            subject_prefix: None,
        }]),
        sts: None,
        audiences: vec![AUDIENCE.into()],
        obo_audiences: vec![],
        egress: std::collections::BTreeMap::new(),
        rules: std::collections::BTreeMap::new(),
        cas: std::collections::BTreeMap::new(),
        no_credential: std::collections::BTreeSet::new(),
        secrets: std::collections::BTreeMap::new(),
        delegated: std::collections::BTreeMap::new(),
        registries: std::collections::BTreeMap::new(),
        registry_audiences: None,
        policy_egress: None,
        sandboxes: front_door.then(|| sandboxes.clone() as _),
        namespaces: Namespaces::Single(NAMESPACE.into()),
        max_ttl_seconds: mediatore_proto::DEFAULT_MAX_TTL_SECONDS,
        sealer: None,
        limiter: Limiter::new(10),
        dev_mode: false,
        gateways: vec![],
    }
}

impl Harness {
    async fn start(front_door: bool) -> Self {
        let idp = FakeIdp::start().await;
        let sandboxes = Arc::new(MemorySandboxes::default());
        let state = Arc::new(app_state(&idp, &sandboxes, front_door));
        Self::serve(idp, sandboxes, state).await
    }

    /// Serve the user API of `state`.
    async fn serve(idp: FakeIdp, sandboxes: Arc<MemorySandboxes>, state: Arc<AppState>) -> Self {
        let user = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind user");
        let user_url = format!("http://{}", user.local_addr().expect("addr"));
        tokio::spawn(axum::serve(user, mediatore_api::user_router(state)).into_future());
        mediatore_proto::tls::ensure_provider();
        Self {
            idp,
            user_url,
            sandboxes,
            http: reqwest::Client::new(),
        }
    }

    fn login(&self, login: &str) -> String {
        self.idp.token(serde_json::json!({
            "aud": "mediatore",
            "preferred_username": login,
            "email": format!("{login}@example.com"),
        }))
    }

    async fn create(&self, token: &str, audiences: &[&str]) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(token)
            .json(&ClaimRequest {
                namespace: None,
                pool_ref: Some("pool-a".into()),
                pool_selector: None,
                selection: None,
                ttl_seconds: 3600,
                audiences: audiences.iter().map(|a| (*a).to_owned()).collect(),
                workload: Workload {
                    image: "registry.internal:5000/sandbox:latest".into(),
                    args: vec!["sh".into()],
                    restart: mediatore_proto::RestartPolicy::Always,
                    logs: false,
                },
                refresh_token: None,
                policy_ref: Some("agent".into()),
                delegations: vec![],
            })
            .send()
            .await
            .expect("create")
    }

    /// `POST /v1/claims` with the body as given, for the shapes `create` does not send.
    async fn create_raw(&self, token: &str, body: &serde_json::Value) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .expect("create")
    }

    async fn get(&self, token: &str, name: &str) -> reqwest::Response {
        self.http
            .get(format!("{}/v1/claims/{name}", self.user_url))
            .bearer_auth(token)
            .send()
            .await
            .expect("get")
    }
}

#[tokio::test]
async fn post_creates_an_agentsandbox_with_the_callers_subject() {
    let h = Harness::start(true).await;
    let resp = h.create(&h.login("octocat"), &[AUDIENCE]).await;
    assert_eq!(resp.status(), 201);
    let body: ClaimResponse = resp.json().await.expect("body");
    assert!(body.name.starts_with("sandbox-"), "{}", body.name);
    assert_eq!(body.phase, ClaimPhase::Pending);
    assert!(!body.ready);
    assert!(body.uid.is_none(), "no claim yet, no claim UID");

    let all = h.sandboxes.all();
    assert_eq!(all.len(), 1);
    let sb = &all[0];
    assert_eq!(sb.metadata.namespace.as_deref(), Some(NAMESPACE));
    assert_eq!(sb.metadata.name.as_deref(), Some(body.name.as_str()));
    assert_eq!(sb.spec.subject.issuer, h.idp.issuer, "the token's issuer");
    assert_eq!(
        sb.spec.subject.id, "octocat",
        "the token's subject, not a request field"
    );
    assert_eq!(
        sb.spec.pool_ref.as_ref().map(|p| p.name.as_str()),
        Some("pool-a")
    );
    assert!(sb.spec.pool_selector.is_none());
    assert_eq!(sb.spec.ttl_seconds, 3600);
    assert_eq!(sb.spec.audiences, vec![AUDIENCE.to_owned()]);
    assert_eq!(
        sb.spec.workload.image,
        "registry.internal:5000/sandbox:latest"
    );
    assert_eq!(sb.spec.workload.args, vec!["sh".to_owned()]);
    assert_eq!(
        sb.spec.policy_ref.as_ref().map(|p| p.name.as_str()),
        Some("agent"),
        "policy_ref lands on spec.policyRef (ADR-0026 decision 6)"
    );
    assert!(
        sb.status.is_none(),
        "the reconciler writes the status, not the API"
    );
}

#[tokio::test]
async fn get_mirrors_the_resources_status() {
    let h = Harness::start(true).await;
    let token = h.login("octocat");
    let created: ClaimResponse = h.create(&token, &[]).await.json().await.expect("body");
    let claim_uid = uuid::Uuid::new_v4();
    h.sandboxes.set_status(
        NAMESPACE,
        &created.name,
        AgentSandboxStatus {
            phase: SandboxPhase::Bound,
            claim_ref: Some(LocalObjectReference {
                name: created.name.clone(),
            }),
            claim_uid: Some(claim_uid.to_string()),
            pool_ref: Some(LocalObjectReference {
                name: "pool-b".into(),
            }),
            addresses: vec!["192.0.2.10".into()],
            expires_at: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::from_second(1_800_000_000).unwrap(),
            )),
            entry_set: true,
            ready: true,
            ..AgentSandboxStatus::default()
        },
    );
    let got: ClaimResponse = h
        .get(&token, &created.name)
        .await
        .json()
        .await
        .expect("body");
    assert_eq!(got.phase, ClaimPhase::Bound);
    assert!(got.ready);
    assert_eq!(got.uid, Some(claim_uid));
    assert_eq!(
        got.pool.as_deref(),
        Some("pool-b"),
        "the pool the member came from, from status (ADR-0044 decision 5)"
    );
    assert_eq!(got.addresses, vec!["192.0.2.10".to_owned()]);
    assert_eq!(
        got.expires_at.map(jiff::Timestamp::as_second),
        Some(1_800_000_000)
    );
}

#[tokio::test]
async fn another_subject_cannot_read_or_delete_and_an_unknown_name_is_not_found() {
    let h = Harness::start(true).await;
    let owner = h.login("octocat");
    let created: ClaimResponse = h.create(&owner, &[]).await.json().await.expect("body");
    let other = h.login("hexley");
    assert_eq!(h.get(&other, &created.name).await.status(), 403);
    let del = h
        .http
        .delete(format!("{}/v1/claims/{}", h.user_url, created.name))
        .bearer_auth(&other)
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status(), 403);
    assert_eq!(h.sandboxes.all().len(), 1, "still there");
    assert_eq!(h.get(&owner, "sandbox-nope").await.status(), 404);
    let no_token = h
        .http
        .get(format!("{}/v1/claims/{}", h.user_url, created.name))
        .send()
        .await
        .expect("get");
    assert_eq!(no_token.status(), 401);
}

#[tokio::test]
async fn delete_removes_the_resource_and_the_finalizer_does_the_rest() {
    let h = Harness::start(true).await;
    let token = h.login("octocat");
    let created: ClaimResponse = h.create(&token, &[]).await.json().await.expect("body");
    let del = h
        .http
        .delete(format!("{}/v1/claims/{}", h.user_url, created.name))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status(), 204);
    assert_eq!(h.sandboxes.all().len(), 0);
    assert_eq!(h.get(&token, &created.name).await.status(), 404);
}

// ----- ADR-0044: a sandbox selects its pool by label, or names it -----------------------------

fn body_with_pool(pool: serde_json::Value) -> serde_json::Value {
    let mut body = serde_json::json!({
        "ttl_seconds": 3600,
        "audiences": [],
        "workload": { "image": "registry.internal:5000/sandbox:latest", "args": ["sh"] }
    });
    if let serde_json::Value::Object(fields) = pool {
        for (k, v) in fields {
            body[k] = v;
        }
    }
    body
}

/// A selector lands on `spec.poolSelector` in banlieue's spelling, with no `poolRef`
/// beside it; the empty one is kept, since it means every pool in the namespace (ADR-0044
/// decisions 1, 2 and 4). `POST` answers with no pool: banlieue has not picked one yet.
#[tokio::test]
async fn post_with_a_selector_creates_a_sandbox_that_selects_and_names_no_pool() {
    let h = Harness::start(true).await;
    let token = h.login("octocat");
    let resp = h
        .create_raw(
            &token,
            &body_with_pool(serde_json::json!({ "pool_selector": {
                "match_labels": { "sandbox.example.com/image": "agent" },
                "match_expressions": [{ "key": "topology.kubernetes.io/zone", "operator": "NotIn", "values": ["c"] }]
            } })),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let body: ClaimResponse = resp.json().await.expect("body");
    assert!(body.pool.is_none(), "no pool until bound: {body:?}");
    let sb = &h.sandboxes.all()[0];
    assert!(sb.spec.pool_ref.is_none());
    let spec = serde_json::to_value(&sb.spec).unwrap();
    assert_eq!(
        spec["poolSelector"],
        serde_json::json!({
            "matchLabels": { "sandbox.example.com/image": "agent" },
            "matchExpressions": [{ "key": "topology.kubernetes.io/zone", "operator": "NotIn", "values": ["c"] }]
        }),
        "got {spec}"
    );
    assert!(spec.get("poolRef").is_none(), "got {spec}");

    let any = h
        .create_raw(
            &token,
            &body_with_pool(serde_json::json!({ "pool_selector": {} })),
        )
        .await;
    assert_eq!(any.status(), 201);
    let sb = h
        .sandboxes
        .all()
        .into_iter()
        .find(|s| s.spec.pool_selector == Some(banlieue_api::common::LabelSelector::default()))
        .expect("a sandbox with the empty selector");
    let spec = serde_json::to_value(&sb.spec).unwrap();
    assert_eq!(spec["poolSelector"], serde_json::json!({}), "kept: {spec}");
}

/// The typed request the CLI sends with neither flag: the empty selector (ADR-0044
/// decision 3), and it is what arrives.
#[tokio::test]
async fn the_typed_empty_selector_arrives_as_any_pool() {
    let h = Harness::start(true).await;
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(h.login("octocat"))
        .json(&ClaimRequest {
            namespace: None,
            pool_ref: None,
            pool_selector: Some(PoolSelector::default()),
            selection: None,
            ttl_seconds: 60,
            audiences: vec![],
            workload: Workload {
                image: "registry.internal:5000/sandbox:latest".into(),
                args: vec![],
                restart: mediatore_proto::RestartPolicy::Always,
                logs: false,
            },
            refresh_token: None,
            policy_ref: None,
            delegations: vec![],
        })
        .send()
        .await
        .expect("create");
    assert_eq!(resp.status(), 201);
    let sb = &h.sandboxes.all()[0];
    assert_eq!(
        sb.spec.pool_selector,
        Some(banlieue_api::common::LabelSelector::default())
    );
}

/// Neither is refused and never read as "any pool"; both is refused; an empty name is
/// refused. Nothing is created (ADR-0044 decision 2, fail closed).
#[tokio::test]
async fn a_request_with_neither_or_both_pool_fields_is_refused_before_anything_is_created() {
    let h = Harness::start(true).await;
    let token = h.login("octocat");
    for (what, pool) in [
        ("neither", serde_json::json!({})),
        (
            "both",
            serde_json::json!({ "pool_ref": "pool-a", "pool_selector": {} }),
        ),
        ("an empty name", serde_json::json!({ "pool_ref": "" })),
    ] {
        let resp = h.create_raw(&token, &body_with_pool(pool)).await;
        assert_eq!(resp.status(), 400, "{what}");
        let body: ErrorBody = resp.json().await.expect("error body");
        assert_eq!(body.error, "invalid_pool", "{what}");
    }
    assert_eq!(h.sandboxes.all().len(), 0);
}

// ----- ADR-0047: a sandbox chooses its member by strategy -------------------------------------

/// A strategy lands on `spec.selection` in banlieue's spelling (ADR-0047 decisions 1 and 3);
/// without one the spec has no `selection` at all (decision 2), so banlieue's default applies.
#[tokio::test]
async fn post_with_a_strategy_carries_it_to_the_sandbox_and_without_one_carries_none() {
    let h = Harness::start(true).await;
    let token = h.login("octocat");
    let mut body = body_with_pool(serde_json::json!({ "pool_selector": {} }));
    body["selection"] = serde_json::json!({ "strategy": "Spread" });
    let resp = h.create_raw(&token, &body).await;
    assert_eq!(resp.status(), 201);
    let sb = &h.sandboxes.all()[0];
    assert_eq!(
        sb.spec.selection,
        Some(banlieue_api::banlieue::ClaimSelection {
            strategy: banlieue_api::banlieue::SelectionStrategy::Spread,
        })
    );
    let spec = serde_json::to_value(&sb.spec).unwrap();
    assert_eq!(
        spec["selection"],
        serde_json::json!({ "strategy": "Spread" }),
        "got {spec}"
    );

    let plain = h
        .create_raw(
            &token,
            &body_with_pool(serde_json::json!({ "pool_ref": "pool-a" })),
        )
        .await;
    assert_eq!(plain.status(), 201);
    let sb = h
        .sandboxes
        .all()
        .into_iter()
        .find(|s| s.spec.pool_ref.is_some())
        .expect("the sandbox that named a pool");
    assert!(sb.spec.selection.is_none());
    let spec = serde_json::to_value(&sb.spec).unwrap();
    assert!(
        spec.get("selection").is_none(),
        "absent, not defaulted: {spec}"
    );
}

/// A strategy the broker does not know is refused before anything is created (ADR-0047
/// decision 3): a parse error, never a default.
#[tokio::test]
async fn a_request_with_an_unknown_strategy_is_refused_before_anything_is_created() {
    let h = Harness::start(true).await;
    let token = h.login("octocat");
    let mut body = body_with_pool(serde_json::json!({ "pool_ref": "pool-a" }));
    body["selection"] = serde_json::json!({ "strategy": "Pack" });
    let resp = h.create_raw(&token, &body).await;
    assert_eq!(
        resp.status(),
        422,
        "{}",
        resp.text().await.unwrap_or_default()
    );
    assert_eq!(h.sandboxes.all().len(), 0);
}

#[tokio::test]
async fn an_unknown_audience_is_refused_before_anything_is_created() {
    let h = Harness::start(true).await;
    let resp = h.create(&h.login("octocat"), &["api://elsewhere"]).await;
    assert_eq!(resp.status(), 400);
    let body: ErrorBody = resp.json().await.expect("error body");
    assert_eq!(body.error, "unknown_audience");
    assert_eq!(h.sandboxes.all().len(), 0);
}

#[tokio::test]
async fn without_a_front_door_the_claim_endpoints_fail_closed() {
    let h = Harness::start(false).await;
    let token = h.login("octocat");
    let resp = h.create(&token, &[]).await;
    assert_eq!(resp.status(), 501);
    let body: ErrorBody = resp.json().await.expect("error body");
    assert_eq!(body.error, "not_implemented");
    assert_eq!(h.get(&token, "sandbox-x").await.status(), 501);
}

// ----- ADR-0046 -----------------------------------------------------------------------------------------

#[tokio::test]
async fn create_sandbox_in_the_default_namespace_is_byte_identical_to_before() {
    let h = Harness::start(true).await;
    let resp = h.create(&h.login("octocat"), &[AUDIENCE]).await;
    assert_eq!(resp.status(), 201);
    let body: ClaimResponse = resp.json().await.expect("body");
    let all = h.sandboxes.all();
    let got = serde_json::to_value(&all[0]).expect("sandbox json");
    assert_eq!(got["metadata"]["name"], body.name.as_str());
    // The name is random, the rest of `metadata` is the fake API server's; what the broker
    // writes is the namespace and the whole `spec`, pinned here as the pre-ADR-0046 shape.
    let issuer = h.idp.issuer.clone();
    assert_eq!(got["metadata"]["namespace"], NAMESPACE);
    assert_eq!(
        got["spec"],
        serde_json::json!({
            "audiences": ["grafana.test"],
            "policyRef": { "name": "agent" },
            "poolRef": { "name": "pool-a" },
            "subject": { "display": "octocat@example.com", "id": "octocat", "issuer": issuer },
            "ttlSeconds": 3600,
            "workload": { "args": ["sh"], "image": "registry.internal:5000/sandbox:latest" },
        })
    );
    assert_eq!(got["apiVersion"], "mediatore.io/v1beta1");
    assert_eq!(got["kind"], "AgentSandbox");
    assert!(
        got.get("status").is_none(),
        "the reconciler writes the status"
    );
    // ADR-0072 decision 3, the one thing new in what the broker writes: its mark, and no
    // other annotation or label.
    assert_eq!(
        got["metadata"]["annotations"],
        serde_json::json!({ "mediatore.io/front-door": "api" })
    );
    assert!(got["metadata"].get("labels").is_none(), "no label");
}

/// ADR-0072 decision 3: a sandbox `POST /v1/claims` creates is the broker's by its mark, which
/// the reconciler reads through `created_through_the_api`; the same spec created by hand is not.
#[tokio::test]
async fn post_creates_an_agentsandbox_marked_as_created_through_the_api() {
    let h = Harness::start(true).await;
    let resp = h.create(&h.login("octocat"), &[AUDIENCE]).await;
    assert_eq!(resp.status(), 201);
    let all = h.sandboxes.all();
    assert_eq!(all.len(), 1);
    assert!(mediatore_claims::sandbox::created_through_the_api(&all[0]));
    let mut by_hand = all[0].clone();
    by_hand.metadata.annotations = None;
    assert!(!mediatore_claims::sandbox::created_through_the_api(
        &by_hand
    ));
}

#[tokio::test]
async fn create_without_the_front_is_501_with_a_namespace_set() {
    let h = Harness::start(false).await;
    let token = h.login("octocat");
    for namespace in [None, Some(NAMESPACE)] {
        let mut body = serde_json::json!({
            "pool_ref": "pool-a",
            "ttl_seconds": 3600,
            "audiences": [AUDIENCE],
            "workload": { "image": "registry.internal:5000/sandbox:latest" },
        });
        if let Some(ns) = namespace {
            body["namespace"] = ns.into();
        }
        let resp = h.create_raw(&token, &body).await;
        assert_eq!(resp.status(), 501, "namespace {namespace:?}");
        let err: ErrorBody = resp.json().await.expect("error body");
        assert_eq!(err.error, "not_implemented");
    }
    assert!(h.sandboxes.all().is_empty(), "nothing was created");
}

// ---------- ADR-0069 decision 9 (amended): a trip keeps the AgentSandbox ----------

mod tripped {
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use async_trait::async_trait;
    use banlieue_api::banlieue::{Provider, VirtualMachine, VirtualMachineClaim};
    use mediatore_claims::Reconciler;
    use mediatore_claims::sandbox::{AgentSandbox, FINALIZER, SandboxFrontDoor, TRIPPED};
    use mediatore_claims::watch::{ClaimsApi, WatchError, Watcher, WatcherConfig, claim_uid_of};
    use mediatore_proto::trip::{TrapsMode, TripEffect, TripKind, TripTarget};
    use mediatore_proto::{NodeRegistration, TokenRequest};
    use mediatore_tls::PeerSpiffeId;

    use super::*;

    const EK_HASH: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";

    type Key = (String, String);

    /// The Kubernetes API as the reconciler writes to it: the sandboxes are the front
    /// door's, the claims are kept here. No more permissive than the API server where the
    /// reconciler depends on it: a create on a taken name returns what is there, and a claim
    /// that was deleted is gone.
    #[derive(Default)]
    struct Cluster {
        sandboxes: Arc<MemorySandboxes>,
        claims: Mutex<HashMap<Key, VirtualMachineClaim>>,
        finalized: Mutex<HashSet<Key>>,
        created: Mutex<usize>,
        deleted: Mutex<Vec<Key>>,
    }

    impl Cluster {
        /// The sandbox as the API server holds it, with the finalizer the reconciler set.
        async fn sandbox(&self, name: &str) -> Option<AgentSandbox> {
            let mut sb = self.sandboxes.get(NAMESPACE, name).await.expect("get")?;
            let key = (NAMESPACE.to_owned(), name.to_owned());
            if self.finalized.lock().unwrap().contains(&key) {
                sb.metadata.finalizers = Some(vec![FINALIZER.into()]);
            }
            Some(sb)
        }

        fn claim(&self, name: &str) -> Option<VirtualMachineClaim> {
            self.claims
                .lock()
                .unwrap()
                .get(&(NAMESPACE.to_owned(), name.to_owned()))
                .cloned()
        }

        /// banlieue binds the claim to a member.
        fn bind(&self, name: &str) {
            let mut claims = self.claims.lock().unwrap();
            let claim = claims
                .get_mut(&(NAMESPACE.to_owned(), name.to_owned()))
                .expect("the claim exists");
            let mut v = serde_json::to_value(&*claim).expect("claim");
            v["status"] = serde_json::json!({
                "phase": "Bound",
                "virtualMachineRef": { "name": "member-1" },
            });
            *claim = serde_json::from_value(v).expect("claim with a status");
        }
    }

    #[async_trait]
    impl ClaimsApi for Cluster {
        async fn delete_claim(&self, namespace: &str, name: &str) -> Result<(), WatchError> {
            let key = (namespace.to_owned(), name.to_owned());
            self.claims.lock().unwrap().remove(&key);
            self.deleted.lock().unwrap().push(key);
            Ok(())
        }

        async fn list_claim_uids(&self) -> Result<HashSet<uuid::Uuid>, WatchError> {
            Ok(self
                .claims
                .lock()
                .unwrap()
                .values()
                .filter_map(claim_uid_of)
                .collect())
        }

        async fn list_machines(&self) -> Result<Vec<VirtualMachine>, WatchError> {
            Ok(vec![])
        }

        async fn get_machine(
            &self,
            _namespace: &str,
            _name: &str,
        ) -> Result<Option<VirtualMachine>, WatchError> {
            Ok(None)
        }

        async fn list_providers(&self) -> Result<Vec<Provider>, WatchError> {
            Ok(vec![])
        }

        async fn get_claim(
            &self,
            namespace: &str,
            name: &str,
        ) -> Result<Option<VirtualMachineClaim>, WatchError> {
            Ok(self
                .claims
                .lock()
                .unwrap()
                .get(&(namespace.to_owned(), name.to_owned()))
                .cloned())
        }

        async fn create_claim(
            &self,
            mut claim: VirtualMachineClaim,
        ) -> Result<VirtualMachineClaim, WatchError> {
            let key = (
                claim.metadata.namespace.clone().unwrap_or_default(),
                claim.metadata.name.clone().unwrap_or_default(),
            );
            let mut claims = self.claims.lock().unwrap();
            if let Some(existing) = claims.get(&key) {
                return Ok(existing.clone());
            }
            claim.metadata.uid = Some(uuid::Uuid::new_v4().to_string());
            claims.insert(key, claim.clone());
            *self.created.lock().unwrap() += 1;
            Ok(claim)
        }

        async fn patch_sandbox_status(
            &self,
            namespace: &str,
            name: &str,
            status: &AgentSandboxStatus,
        ) -> Result<(), WatchError> {
            self.sandboxes.set_status(namespace, name, status.clone());
            Ok(())
        }

        async fn set_sandbox_finalizer(
            &self,
            sandbox: &AgentSandbox,
            present: bool,
        ) -> Result<(), WatchError> {
            let key = (
                sandbox.metadata.namespace.clone().unwrap_or_default(),
                sandbox.metadata.name.clone().unwrap_or_default(),
            );
            let mut finalized = self.finalized.lock().unwrap();
            if present {
                finalized.insert(key);
            } else {
                finalized.remove(&key);
            }
            Ok(())
        }
    }

    /// The sandbox listener for one verified peer: what `mediatore_tls::serve` attaches to
    /// every request of a connection after it checked the client certificate. Outside
    /// `dev_mode` the broker reads the peer from nowhere else.
    async fn sandbox_api_as(state: &Arc<AppState>, peer: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sandbox");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let router =
            mediatore_api::sandbox_router(state.clone()).layer(axum::Extension(PeerSpiffeId(peer)));
        tokio::spawn(axum::serve(listener, router).into_future());
        url
    }

    /// Passes of the real reconciler over the sandbox until one changes nothing.
    async fn settle(watcher: &Watcher, cluster: &Cluster, name: &str) {
        for _ in 0..6 {
            let before = cluster.sandbox(name).await.expect("the sandbox exists");
            watcher.reconcile_sandbox(&before).await.expect("a pass");
            if cluster.sandbox(name).await.as_ref() == Some(&before) {
                break;
            }
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // one scripted scenario, front to back; splitting it would hide the order
    async fn a_trip_through_the_front_door_leaves_the_sandbox_with_tripped_and_its_events() {
        let idp = FakeIdp::start().await;
        let sandboxes = Arc::new(MemorySandboxes::default());
        let mut state = app_state(&idp, &sandboxes, true);
        state.tripwires.mode = TrapsMode::Enforce;
        let state = Arc::new(state);
        let naming = state.naming.clone();
        let cluster = Arc::new(Cluster {
            sandboxes: sandboxes.clone(),
            ..Cluster::default()
        });
        let reconciler = || Reconciler {
            store: state.store.clone(),
            spire: state.spire.clone(),
            naming: naming.clone(),
        };
        let watcher = Watcher::new(
            reconciler(),
            cluster.clone(),
            WatcherConfig {
                issuers: vec![idp.issuer.clone()],
                ..WatcherConfig::default()
            },
        );
        let h = Harness::serve(idp, sandboxes, state.clone()).await;

        // The front door creates the sandbox; the reconciler gives it its one claim and its
        // record; banlieue binds the claim, the node registers, the entry is set.
        let token = h.login("octocat");
        let created: ClaimResponse = h.create(&token, &[]).await.json().await.expect("body");
        let name = created.name.clone();
        settle(&watcher, &cluster, &name).await;
        let claim = cluster
            .claim(&name)
            .expect("the reconciler created the claim");
        let claim_uid = claim_uid_of(&claim).expect("a uid");
        let node_api = sandbox_api_as(&state, naming.node_id(EK_HASH)).await;
        let resp = h
            .http
            .post(format!("{node_api}/v1/nodes"))
            .json(&NodeRegistration {
                ek_hash: EK_HASH.into(),
                attestation: None,
                dmi_uuid: uuid::Uuid::new_v4(),
                hostname: "member-1".into(),
                provider: None,
            })
            .send()
            .await
            .expect("register");
        assert_eq!(resp.status(), 200);
        cluster.bind(&name);
        reconciler()
            .bind(
                claim_uid,
                &mediatore_spire::NodeIdentity::of(
                    &naming,
                    &mediatore_spire::NodeAttestation::Tpm {
                        ek_hash: EK_HASH.into(),
                    },
                )
                .expect("a TPM identity"),
            )
            .await
            .expect("the claim watcher binds the record");
        settle(&watcher, &cluster, &name).await;
        let bound: ClaimResponse = h.get(&token, &name).await.json().await.expect("body");
        assert_eq!(bound.phase, ClaimPhase::Bound);
        assert!(bound.ready && bound.tripped.is_none() && bound.tripwires.is_none());
        assert_eq!(bound.uid, Some(claim_uid));

        // The guest reports a trip over its node SVID.
        let id = uuid::Uuid::new_v4();
        let report = serde_json::json!({
            "mode": "enforce",
            "events": [{
                "id": id, "at": "2026-11-26T15:02:11.204Z",
                "kind": "credential", "trap": "aws",
                "target": { "host": "git.example" }, "source": "workload",
                "containment_ms": 41,
            }],
        });
        let resp = h
            .http
            .post(format!("{node_api}/v1/me/trip"))
            .json(&report)
            .send()
            .await
            .expect("trip");
        assert_eq!(resp.status(), 204);

        // The API ended the claim and deleted nothing: the AgentSandbox is still there (an
        // exit, outside dev_mode, deletes it), and so is its claim, until the reconciler's pass.
        assert!(
            cluster.sandbox(&name).await.is_some(),
            "a trip does not delete the AgentSandbox"
        );
        assert!(cluster.claim(&name).is_some(), "the API deletes no claim");
        let record = state.store.get_claim(claim_uid).await.expect("the record");
        assert!(record.tripped.is_some() && record.revoked_at.is_some());
        // Before the reconciler's pass the status still mirrors a bound claim; the owner is
        // shown the trip all the same, and a tripped claim is never ready.
        let between: ClaimResponse = h.get(&token, &name).await.json().await.expect("body");
        assert_eq!(
            between.phase,
            ClaimPhase::Bound,
            "the mirror has not caught up"
        );
        assert!(!between.ready && between.tripped.is_some());
        // The claim's identity gets no token, on the claim's own verified connection.
        let claim_api = sandbox_api_as(&state, naming.claim_id(claim_uid)).await;
        let resp = h
            .http
            .post(format!("{claim_api}/v1/token"))
            .json(&TokenRequest {
                audience: AUDIENCE.into(),
            })
            .send()
            .await
            .expect("token");
        assert_eq!(resp.status(), 403, "a tripped claim's token is refused");

        // The reconciler sees `tripped` on the record: the claim is deleted, once, and the
        // sandbox is Failed with the reason and the condition.
        settle(&watcher, &cluster, &name).await;
        assert!(
            cluster.claim(&name).is_none(),
            "the VirtualMachineClaim is deleted"
        );
        assert_eq!(cluster.deleted.lock().unwrap().len(), 1);
        let sb = cluster
            .sandbox(&name)
            .await
            .expect("the AgentSandbox survives its trip");
        assert!(sb.metadata.deletion_timestamp.is_none());
        let status = sb.status.expect("a status");
        assert_eq!(status.phase, SandboxPhase::Failed);
        assert_eq!(status.reason.as_deref(), Some("tripped: credential"));
        assert!(!status.ready && !status.entry_set);
        let conditions: Vec<_> = status
            .conditions
            .iter()
            .filter(|c| c.type_ == TRIPPED)
            .collect();
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0].status, "True");
        assert_eq!(conditions[0].reason, "credential");
        assert_eq!(conditions[0].message, "trap aws, target git.example");

        // Its owner reads all of it through the front door.
        let seen: ClaimResponse = h.get(&token, &name).await.json().await.expect("body");
        assert_eq!(seen.phase, ClaimPhase::Failed);
        assert!(!seen.ready);
        let tripped = seen.tripped.expect("tripped");
        assert_eq!(tripped.id, id);
        assert_eq!(tripped.kind, TripKind::Credential);
        assert_eq!(tripped.target, Some(TripTarget::Host("git.example".into())));
        let summary = seen.tripwires.expect("the folded events");
        assert_eq!(summary.entries.len(), 1);
        assert_eq!(summary.entries[0].effect, TripEffect::Tripped);
        assert_eq!(summary.entries[0].containment_ms, Some(41));

        // Never claimed again: pass after pass creates no second claim, and a second report
        // changes the summary alone.
        let second = serde_json::json!({
            "mode": "enforce",
            "events": [{
                "id": uuid::Uuid::new_v4(), "at": "2026-11-26T15:02:12Z",
                "kind": "port", "trap": "redis", "target": { "port": 6379 }, "source": "drawn",
            }],
        });
        let resp = h
            .http
            .post(format!("{node_api}/v1/me/trip"))
            .json(&second)
            .send()
            .await
            .expect("a second trip");
        assert_eq!(resp.status(), 204);
        for _ in 0..3 {
            settle(&watcher, &cluster, &name).await;
            assert!(
                cluster.claim(&name).is_none(),
                "a tripped sandbox gets no second claim"
            );
        }
        assert_eq!(*cluster.created.lock().unwrap(), 1, "one claim, ever");
        assert_eq!(cluster.deleted.lock().unwrap().len(), 1);
        let seen: ClaimResponse = h.get(&token, &name).await.json().await.expect("body");
        assert_eq!(
            seen.tripped.map(|t| t.id),
            Some(id),
            "the first trip is kept"
        );
        assert_eq!(seen.tripwires.expect("the folded events").entries.len(), 2);
        let status = cluster
            .sandbox(&name)
            .await
            .and_then(|sb| sb.status)
            .expect("a status");
        assert_eq!(status.reason.as_deref(), Some("tripped: credential"));
    }
}
