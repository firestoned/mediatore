// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The Dex path end to end (ADR-0013) over real HTTP listeners, `dev_mode` for the peer
//! identity and the binder: the caller delegates its refresh token with the claim, the
//! envelope lands sealed in the record, every `POST /v1/token` refreshes the session first
//! (rotation, fresh groups), an outage is a `503` that revokes nothing, a refusal upstream
//! or at the group gate releases the claim, and a looping workload hits the per-claim
//! limit before any upstream call.

use std::future::IntoFuture;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Duration;
use mediatore_api::{AppState, Limiter};
use mediatore_entra::{Backend, IssuerConfig, SessionConfig, Validator};
use mediatore_proto::{
    ClaimRequest, ClaimResponse, ErrorBody, NodeRegistration, Secret, TokenResponse, Workload,
};
use mediatore_spire::{MemoryEntries, Naming};
use mediatore_store::seal::LocalKeySealer;
use mediatore_store::{ClaimStore, MemoryStore};
use mediatore_sts::Sts;
use mediatore_testkit::FakeIdp;

/// Throwaway P-256 key for the e2e STS. Test material only; never reuse.
const STS_TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnjPFPJtOewKuQZS0
WTXasKCqUusD6hs+6AaBUWw5lOyhRANCAAQy0awwI1IJ/BKoy/Zj4KtfYOiJOaX2
bVIP4yKaVz1Zp2QNVZJ0t2NIXK0K55dfgdM/B4JF09EKDd/q/nHoAfis
-----END PRIVATE KEY-----
";

const TRUST_DOMAIN: &str = "sandbox.test";
const AUDIENCE: &str = "grafana.test";
const REQUIRED_GROUP: &str = "firestoned:sandbox-users";
const PEER_HEADER: &str = "x-mediatore-peer-spiffe-id";
const EK_HASH: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";

struct Harness {
    idp: FakeIdp,
    store: Arc<MemoryStore>,
    entries: Arc<MemoryEntries>,
    user_url: String,
    sandbox_url: String,
    http: reqwest::Client,
}

impl Harness {
    async fn start(rate_per_minute: u32) -> Self {
        let idp = FakeIdp::start().await;
        let sts = Sts::new(
            "https://mediatore.test",
            "e2e-1",
            STS_TEST_KEY.as_bytes(),
            Duration::minutes(15),
        )
        .expect("sts");
        let store = MemoryStore::shared();
        let entries = Arc::new(MemoryEntries::default());
        let state = Arc::new(AppState {
            store: store.clone(),
            spire: entries.clone(),
            naming: Naming {
                trust_domain: TRUST_DOMAIN.into(),
            },
            validator: Validator::new(vec![IssuerConfig {
                url: idp.issuer.clone(),
                backend: Backend::Sts,
                client_id: "mediatore".into(),
                subject_claim: "preferred_username".into(),
                required_group: Some(REQUIRED_GROUP.into()),
                session: Some(SessionConfig {
                    client_id: "mediatore".into(),
                }),
                ca_file: None,
            }]),
            sts: Some(sts),
            audiences: vec![AUDIENCE.into()],
            sandboxes: None,
            sandbox_namespace: "sandboxes".into(),
            sealer: Some(Arc::new(LocalKeySealer::new([3u8; 32]))),
            limiter: Limiter::new(rate_per_minute),
            dev_mode: true,
        });
        let user = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sandbox = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let user_url = format!("http://{}", user.local_addr().unwrap());
        let sandbox_url = format!("http://{}", sandbox.local_addr().unwrap());
        tokio::spawn(axum::serve(user, mediatore_api::user_router(state.clone())).into_future());
        tokio::spawn(axum::serve(sandbox, mediatore_api::sandbox_router(state)).into_future());
        mediatore_proto::tls::ensure_provider();
        Self {
            idp,
            store,
            entries,
            user_url,
            sandbox_url,
            http: reqwest::Client::new(),
        }
    }

    async fn register_node(&self) {
        let resp = self
            .http
            .post(format!("{}/v1/nodes", self.sandbox_url))
            .header(
                PEER_HEADER,
                format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{EK_HASH}"),
            )
            .json(&NodeRegistration {
                ek_hash: EK_HASH.into(),
                dmi_uuid: uuid::Uuid::new_v4(),
                hostname: "pool-a-7".into(),
                provider: None,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    async fn claim(&self, id_token: &str, refresh_token: Option<&str>) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(id_token)
            .json(&ClaimRequest {
                pool_ref: "pool-a".into(),
                ttl_seconds: 3600,
                audiences: vec![AUDIENCE.into()],
                workload: Workload {
                    image: "registry.internal:5000/sandbox:latest".into(),
                    args: vec![],
                },
                refresh_token: refresh_token.map(|t| Secret(t.to_owned())),
            })
            .send()
            .await
            .unwrap()
    }

    /// Log in, delegate, and get the claim bound to the registered node.
    async fn bound_claim(&self, login: &str) -> (ClaimResponse, String) {
        self.register_node().await;
        let (id_token, refresh_token) = self.idp.session(login, "mediatore");
        let resp = self.claim(&id_token, Some(&refresh_token)).await;
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
        let claim: ClaimResponse = resp.json().await.unwrap();
        assert!(claim.ready, "dev binder binds at once");
        (claim, refresh_token)
    }

    async fn token(&self, claim: &ClaimResponse) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/token", self.sandbox_url))
            .header(
                PEER_HEADER,
                format!(
                    "spiffe://{TRUST_DOMAIN}/banlieue/claim/{}",
                    claim.uid.unwrap()
                ),
            )
            .json(&mediatore_proto::TokenRequest {
                audience: AUDIENCE.into(),
            })
            .send()
            .await
            .unwrap()
    }
}

/// The payload of a JWT, unverified: what the e2e asserts on after the broker verified.
fn payload(token: &str) -> serde_json::Value {
    let part = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

async fn error_code(resp: reqwest::Response) -> (u16, String) {
    let status = resp.status().as_u16();
    let body: ErrorBody = resp.json().await.unwrap();
    (status, body.error)
}

#[tokio::test]
async fn a_session_issuer_requires_the_delegation() {
    let h = Harness::start(10).await;
    let (id_token, _) = h.idp.session("octocat", "mediatore");
    let resp = h.claim(&id_token, None).await;
    assert_eq!(error_code(resp).await, (400, "session_required".into()));
    assert_eq!(h.store.list_claims().await.unwrap().len(), 0);
}

#[tokio::test]
async fn the_envelope_lands_in_the_record_and_every_issue_refreshes_first() {
    let h = Harness::start(10).await;
    let (claim, refresh_token) = h.bound_claim("octocat").await;
    let rec = h.store.get_claim(claim.uid.unwrap()).await.unwrap();
    let before = rec.refresh.clone().expect("sealed envelope in the record");
    assert_ne!(before.ciphertext, refresh_token.as_bytes());

    let resp = h.token(&claim).await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let tok: TokenResponse = resp.json().await.unwrap();
    assert_eq!(tok.subject.id, "octocat");
    assert_eq!(h.idp.refreshes(), 1, "one refresh per issue");
    assert!(
        !h.idp.is_live(&refresh_token),
        "the delegated token was rotated away"
    );
    let rec = h.store.get_claim(claim.uid.unwrap()).await.unwrap();
    assert_ne!(
        rec.refresh.unwrap(),
        before,
        "the rotated token was re-sealed into the record"
    );

    // The groups in the minted token are the issuer's current ones, not the login's.
    h.idp
        .set_groups("octocat", &[REQUIRED_GROUP, "firestoned:dev"]);
    let tok: TokenResponse = h.token(&claim).await.json().await.unwrap();
    let groups = payload(&tok.access_token)["groups"].clone();
    assert_eq!(
        groups,
        serde_json::json!([REQUIRED_GROUP, "firestoned:dev"]),
        "fresh groups"
    );
    assert_eq!(h.idp.refreshes(), 2);
}

#[tokio::test]
async fn an_issuer_outage_is_503_and_revokes_nothing() {
    let h = Harness::start(10).await;
    let (claim, _) = h.bound_claim("octocat").await;
    h.idp.set_down(true);
    let resp = h.token(&claim).await;
    assert_eq!(error_code(resp).await, (503, "upstream_unavailable".into()));
    let rec = h.store.get_claim(claim.uid.unwrap()).await.unwrap();
    assert!(rec.revoked_at.is_none(), "an outage is not a revocation");
    assert_eq!(h.entries.names().len(), 1, "the entry stays");
    h.idp.set_down(false);
    assert_eq!(h.token(&claim).await.status(), 200);
}

#[tokio::test]
async fn a_session_revoked_upstream_releases_the_claim_at_once() {
    let h = Harness::start(10).await;
    let (claim, _) = h.bound_claim("octocat").await;
    assert_eq!(h.token(&claim).await.status(), 200);
    h.idp.revoke("octocat");
    let resp = h.token(&claim).await;
    assert_eq!(error_code(resp).await, (403, "session_revoked".into()));
    let rec = h.store.get_claim(claim.uid.unwrap()).await.unwrap();
    assert!(rec.revoked_at.is_some(), "record revoked");
    assert!(rec.refresh.is_none(), "envelope dropped");
    assert_eq!(h.entries.names().len(), 0, "entry retracted");
    // Even if the issuer relented, the claim is gone for good.
    let resp = h.token(&claim).await;
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn a_login_that_left_the_group_releases_the_claim_at_the_next_issue() {
    let h = Harness::start(10).await;
    let (claim, _) = h.bound_claim("octocat").await;
    h.idp.set_groups("octocat", &["firestoned:other"]);
    let resp = h.token(&claim).await;
    assert_eq!(error_code(resp).await, (403, "session_revoked".into()));
    assert!(
        h.store
            .get_claim(claim.uid.unwrap())
            .await
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert_eq!(h.entries.names().len(), 0);
}

#[tokio::test]
async fn a_delegated_token_the_issuer_never_issued_fails_the_first_issue() {
    let h = Harness::start(10).await;
    h.register_node().await;
    let (id_token, _) = h.idp.session("octocat", "mediatore");
    let resp = h.claim(&id_token, Some("rt-made-up")).await;
    assert_eq!(
        resp.status(),
        201,
        "delegation is checked at use, not at creation"
    );
    let claim: ClaimResponse = resp.json().await.unwrap();
    let resp = h.token(&claim).await;
    assert_eq!(error_code(resp).await, (403, "session_revoked".into()));
    assert_eq!(h.entries.names().len(), 0);
}

#[tokio::test]
async fn the_limit_is_per_claim_and_ahead_of_the_upstream_call() {
    let h = Harness::start(2).await;
    let (claim, _) = h.bound_claim("octocat").await;
    assert_eq!(h.token(&claim).await.status(), 200);
    assert_eq!(h.token(&claim).await.status(), 200);
    let resp = h.token(&claim).await;
    assert_eq!(error_code(resp).await, (429, "rate_limited".into()));
    assert_eq!(
        h.idp.refreshes(),
        2,
        "the third request never reached the issuer"
    );
    let rec = h.store.get_claim(claim.uid.unwrap()).await.unwrap();
    assert!(rec.revoked_at.is_none());
}

#[tokio::test]
async fn concurrent_issues_for_one_claim_refresh_one_at_a_time() {
    let h = Harness::start(10).await;
    let (claim, _) = h.bound_claim("octocat").await;
    let (a, b, c) = tokio::join!(h.token(&claim), h.token(&claim), h.token(&claim));
    for resp in [a, b, c] {
        assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    }
    assert_eq!(
        h.idp.refreshes(),
        3,
        "each issue refreshed, none reused a spent token"
    );
    let rec = h.store.get_claim(claim.uid.unwrap()).await.unwrap();
    assert!(rec.revoked_at.is_none());
}
