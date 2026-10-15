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
use mediatore_proto::{ClaimPhase, ClaimRequest, ClaimResponse, ErrorBody, Workload};
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
            }]),
            sts: None,
            audiences: vec![AUDIENCE.into()],
            sandboxes: front_door.then(|| sandboxes.clone() as _),
            sandbox_namespace: NAMESPACE.into(),
            sealer: None,
            limiter: Limiter::new(10),
            dev_mode: false,
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
                pool_ref: "pool-a".into(),
                ttl_seconds: 3600,
                audiences: audiences.iter().map(|a| (*a).to_owned()).collect(),
                workload: Workload {
                    image: "registry.internal:5000/sandbox:latest".into(),
                    args: vec!["sh".into()],
                },
                refresh_token: None,
            })
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
    assert_eq!(sb.spec.pool_ref.name, "pool-a");
    assert_eq!(sb.spec.ttl_seconds, 3600);
    assert_eq!(sb.spec.audiences, vec![AUDIENCE.to_owned()]);
    assert_eq!(
        sb.spec.workload.image,
        "registry.internal:5000/sandbox:latest"
    );
    assert_eq!(sb.spec.workload.args, vec!["sh".to_owned()]);
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
