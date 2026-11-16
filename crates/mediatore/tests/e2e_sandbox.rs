// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The user API outside `dev_mode` (ADR-0008 decision 4): `POST /v1/claims` creates an
//! `AgentSandbox` with the token's subject, `GET` answers from its status, `DELETE` deletes
//! it. The Kubernetes API is `mediatore_testkit::MemorySandboxes`; everything else
//! (token validation, the audience check, the subject gate) is the production path.

use std::future::IntoFuture;
use std::sync::Arc;

use banlieue_api::common::LocalObjectReference;
use mediatore_api::{AppState, Limiter};
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

impl Harness {
    async fn start(front_door: bool) -> Self {
        let idp = FakeIdp::start().await;
        let sandboxes = Arc::new(MemorySandboxes::default());
        let state = Arc::new(AppState {
            inject: std::collections::BTreeMap::new(),
            inject_port: None,
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
                session: None,
                ca_file: None,
                entra: None,
                groups_claim: None,
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
            reachable_registries: None,
            policy_egress: None,
            sandboxes: front_door.then(|| sandboxes.clone() as _),
            sandbox_namespace: NAMESPACE.into(),
            sealer: None,
            limiter: Limiter::new(10),
            dev_mode: false,
            gateways: vec![],
        });
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
                pool_ref: Some("pool-a".into()),
                pool_selector: None,
                ttl_seconds: 3600,
                audiences: audiences.iter().map(|a| (*a).to_owned()).collect(),
                workload: Workload {
                    image: "registry.internal:5000/sandbox:latest".into(),
                    args: vec!["sh".into()],
                    restart: mediatore_proto::RestartPolicy::Always,
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
    assert_eq!(got.expires_at.map(|t| t.timestamp()), Some(1_800_000_000));
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
            pool_ref: None,
            pool_selector: Some(PoolSelector::default()),
            ttl_seconds: 60,
            audiences: vec![],
            workload: Workload {
                image: "registry.internal:5000/sandbox:latest".into(),
                args: vec![],
                restart: mediatore_proto::RestartPolicy::Always,
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
