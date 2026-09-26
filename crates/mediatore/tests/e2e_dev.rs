//! Front-to-back exercise of the dev-mode loop over real HTTP listeners:
//!
//! fake `IdP` login → `POST /v1/claims` → dev bind to a registered node → `GET /v1/me` →
//! `POST /v1/token` → STS JWT verified against mediatore's own JWKS → release → cut-off.
//!
//! What stays faked here, on purpose: the peer identity is a header (`dev_mode`), the SPIRE
//! server is `Noop`, and banlieue's claim controller is the dev binder. Everything else --
//! upstream token validation, claim lifecycle, audience checks, token minting, revocation --
//! is the production code path.

use std::future::IntoFuture;
use std::sync::Arc;

use chrono::Duration;
use mediatore_api::AppState;
use mediatore_entra::{Backend, IssuerConfig, Validator};
use mediatore_proto::{
    ClaimRequest, ClaimResponse, Me, NodeRegistered, NodeRegistration, TokenResponse, Workload,
};
use mediatore_spire::Naming;
use mediatore_store::MemoryStore;
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
const EK_HASH: &str = "3f9a1c2b7e4d3f9a1c2b7e4d3f9a1c2b";

fn node_svid() -> String {
    format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{EK_HASH}")
}

fn claim_svid(uid: &uuid::Uuid) -> String {
    format!("spiffe://{TRUST_DOMAIN}/banlieue/claim/{uid}")
}

struct Harness {
    idp: FakeIdp,
    user_url: String,
    sandbox_url: String,
    http: reqwest::Client,
}

impl Harness {
    async fn start() -> Self {
        let idp = FakeIdp::start().await;
        let sts = Sts::new(
            "https://mediatore.test",
            "e2e-1",
            STS_TEST_KEY.as_bytes(),
            Duration::minutes(15),
        )
        .expect("sts");
        let state = Arc::new(AppState {
            store: MemoryStore::shared(),
            spire: Arc::new(mediatore_spire::Noop),
            naming: Naming {
                trust_domain: TRUST_DOMAIN.into(),
            },
            validator: Validator::new(vec![IssuerConfig {
                url: idp.issuer.clone(),
                backend: Backend::Sts,
                client_id: "mediatore".into(),
                subject_claim: "preferred_username".into(),
                required_group: Some(REQUIRED_GROUP.into()),
            }]),
            sts: Some(sts),
            audiences: vec![AUDIENCE.into()],
            dev_mode: true,
        });

        let user = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind user");
        let sandbox = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sandbox");
        let user_url = format!("http://{}", user.local_addr().expect("addr"));
        let sandbox_url = format!("http://{}", sandbox.local_addr().expect("addr"));
        tokio::spawn(axum::serve(user, mediatore_api::user_router(state.clone())).into_future());
        tokio::spawn(axum::serve(sandbox, mediatore_api::sandbox_router(state)).into_future());

        Self {
            idp,
            user_url,
            sandbox_url,
            http: reqwest::Client::new(),
        }
    }

    /// A valid login for `login`, shaped like a Dex ID token.
    fn login(&self, login: &str) -> String {
        self.idp.token(serde_json::json!({
            "aud": "mediatore",
            "preferred_username": login,
            "email": format!("{login}@example.com"),
            "groups": [REQUIRED_GROUP],
        }))
    }

    /// Register the standard test node; returns its SPIRE agent ID.
    async fn register_node(&self) -> String {
        let resp = self
            .http
            .post(format!("{}/v1/nodes", self.sandbox_url))
            .header(PEER_HEADER, node_svid())
            .json(&NodeRegistration {
                ek_hash: EK_HASH.into(),
                dmi_uuid: uuid::Uuid::new_v4(),
                hostname: "pool-a-7".into(),
                provider: Some(mediatore_proto::Provider::Libvirt),
            })
            .send()
            .await
            .expect("register");
        assert_eq!(
            resp.status(),
            200,
            "{}",
            resp.text().await.unwrap_or_default()
        );
        resp.json::<NodeRegistered>()
            .await
            .expect("node body")
            .node_id
    }

    async fn create_claim(&self, token: &str) -> (reqwest::StatusCode, ClaimResponse) {
        let resp = self
            .http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(token)
            .json(&ClaimRequest {
                pool_ref: "pool-a".into(),
                ttl_seconds: 3600,
                audiences: vec![AUDIENCE.into()],
                workload: Workload {
                    image: "registry.internal:5000/sandbox:latest".into(),
                    args: vec![],
                },
            })
            .send()
            .await
            .expect("create claim");
        let status = resp.status();
        let body = resp.json::<ClaimResponse>().await.expect("claim body");
        (status, body)
    }

    async fn token_for(&self, peer: &str, audience: &str) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/token", self.sandbox_url))
            .header(PEER_HEADER, peer)
            .json(&mediatore_proto::TokenRequest {
                audience: audience.into(),
            })
            .send()
            .await
            .expect("token request")
    }
}

#[tokio::test]
async fn full_loop_from_login_to_cutoff() {
    let h = Harness::start().await;

    // A pool member boots, attests (faked), and registers.
    let agent_id = h.register_node().await;
    assert_eq!(
        agent_id,
        format!("spiffe://{TRUST_DOMAIN}/spire/agent/tpm/{EK_HASH}")
    );

    // The user logs in at the front door and claims a sandbox.
    let user_token = h.login("octocat");
    let (status, claim) = h.create_claim(&user_token).await;
    assert_eq!(status, 201);
    assert_eq!(
        claim.phase,
        mediatore_proto::ClaimPhase::Bound,
        "dev binder should bind immediately"
    );
    let uid = claim.uid.expect("uid");
    assert!(claim.expires_at.is_some(), "bound claim has a deadline");

    // The claim mirrors back to its subject.
    let got: ClaimResponse = h
        .http
        .get(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&user_token)
        .send()
        .await
        .expect("get claim")
        .json()
        .await
        .expect("get body");
    assert_eq!(got.phase, mediatore_proto::ClaimPhase::Bound);

    // The in-guest agent asks who the sandbox is for.
    let me_resp = h
        .http
        .get(format!("{}/v1/me", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .send()
        .await
        .expect("me");
    assert_eq!(me_resp.status(), 200);
    let me: Me = me_resp.json().await.expect("me body");
    assert_eq!(me.claim_uid, uid);
    assert_eq!(me.subject.id, "octocat");
    assert_eq!(me.workload.image, "registry.internal:5000/sandbox:latest");
    let sandbox_user = me.subject.sandbox_username();
    assert!(sandbox_user.starts_with("sb-"));

    // The jailed workload trades its claim SVID for an audience-scoped token.
    let claim_svid = claim_svid(&uid);
    let tok_resp = h.token_for(&claim_svid, AUDIENCE).await;
    assert_eq!(tok_resp.status(), 200);
    let tok: TokenResponse = tok_resp.json().await.expect("token body");
    assert_eq!(tok.audience, AUDIENCE);
    assert_eq!(tok.subject.id, "octocat");

    // The token verifies against mediatore's own published JWKS, and carries the
    // RFC 8693 act claim naming the sandbox as the actor.
    let jwks: serde_json::Value = h
        .http
        .get(format!("{}/.well-known/jwks.json", h.user_url))
        .send()
        .await
        .expect("jwks")
        .json()
        .await
        .expect("jwks body");
    let jwk = &jwks["keys"][0];
    let key = jsonwebtoken::DecodingKey::from_ec_components(
        jwk["x"].as_str().expect("x"),
        jwk["y"].as_str().expect("y"),
    )
    .expect("jwk key");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_audience(&[AUDIENCE]);
    validation.set_issuer(&["https://mediatore.test"]);
    let decoded = jsonwebtoken::decode::<serde_json::Value>(&tok.access_token, &key, &validation)
        .expect("verify");
    assert_eq!(decoded.claims["sub"], "octocat");
    assert_eq!(decoded.claims["act"]["sub"], claim_svid);
    assert_eq!(decoded.claims["claim_uid"], uid.to_string());
    assert_eq!(decoded.claims["upstream_iss"], h.idp.issuer);

    // Release: the subject deletes the claim; every path cuts off.
    let del = h
        .http
        .delete(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&user_token)
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status(), 204);

    let after = h.token_for(&claim_svid, AUDIENCE).await;
    assert_eq!(after.status(), 403, "revoked claim must not issue");
    let me_after = h
        .http
        .get(format!("{}/v1/me", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .send()
        .await
        .expect("me after release");
    assert_eq!(
        me_after.status(),
        404,
        "released claim no longer answers /v1/me"
    );
}

#[tokio::test]
async fn wrong_audience_is_a_400_not_403() {
    let h = Harness::start().await;
    h.register_node().await;
    let (status, claim) = h.create_claim(&h.login("octocat")).await;
    assert_eq!(status, 201);
    let uid = claim.uid.expect("uid");
    let resp = h.token_for(&claim_svid(&uid), "api://something-else").await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn a_node_svid_gets_no_token() {
    let h = Harness::start().await;
    h.register_node().await;
    let (_, claim) = h.create_claim(&h.login("octocat")).await;
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Bound);
    // Root on the VM holds the node identity, not the claim's. 403, per the runbook.
    let resp = h.token_for(&node_svid(), AUDIENCE).await;
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn a_token_for_another_audience_client_is_unauthorized() {
    let h = Harness::start().await;
    // Shaped like a Dex token minted for the kubernetes client, not for mediatore.
    let token = h.idp.token(serde_json::json!({
        "aud": "kubernetes",
        "preferred_username": "octocat",
        "groups": [REQUIRED_GROUP],
    }));
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(&token)
        .json(&ClaimRequest {
            pool_ref: "pool-a".into(),
            ttl_seconds: 3600,
            audiences: vec![],
            workload: Workload::default(),
        })
        .send()
        .await
        .expect("create");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn a_login_outside_the_required_group_is_forbidden() {
    let h = Harness::start().await;
    let token = h.idp.token(serde_json::json!({
        "aud": "mediatore",
        "preferred_username": "octocat",
        "groups": ["firestoned:other"],
    }));
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(&token)
        .json(&ClaimRequest {
            pool_ref: "pool-a".into(),
            ttl_seconds: 3600,
            audiences: vec![],
            workload: Workload::default(),
        })
        .send()
        .await
        .expect("create");
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn another_subject_cannot_read_or_delete_the_claim() {
    let h = Harness::start().await;
    h.register_node().await;
    let (_, claim) = h.create_claim(&h.login("octocat")).await;
    let other = h.login("hexley");
    let read = h
        .http
        .get(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&other)
        .send()
        .await
        .expect("get");
    assert_eq!(read.status(), 403);
    let del = h
        .http
        .delete(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&other)
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status(), 403);
}

#[tokio::test]
async fn a_peer_cannot_register_someone_elses_ek() {
    let h = Harness::start().await;
    let resp = h
        .http
        .post(format!("{}/v1/nodes", h.sandbox_url))
        .header(
            PEER_HEADER,
            format!("spiffe://{TRUST_DOMAIN}/banlieue/node/other-ek"),
        )
        .json(&NodeRegistration {
            ek_hash: EK_HASH.into(),
            dmi_uuid: uuid::Uuid::new_v4(),
            hostname: "pool-a-7".into(),
            provider: None,
        })
        .send()
        .await
        .expect("register");
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn without_a_free_node_the_claim_stays_pending() {
    let h = Harness::start().await;
    let (status, claim) = h.create_claim(&h.login("octocat")).await;
    assert_eq!(status, 201);
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Pending);
    assert!(
        claim.expires_at.is_none(),
        "the TTL clock starts at bind, not at creation"
    );
    let me = h
        .http
        .get(format!("{}/v1/me", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .send()
        .await
        .expect("me");
    assert_eq!(
        me.status(),
        403,
        "an unregistered node has no identity here"
    );
}

#[tokio::test]
async fn a_pending_claim_binds_when_a_node_registers_later() {
    let h = Harness::start().await;
    let user_token = h.login("octocat");
    let (_, claim) = h.create_claim(&user_token).await;
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Pending);

    // The pool member arrives after the claim: the guest agent's boot registration
    // must still bind it.
    h.register_node().await;

    let got: ClaimResponse = h
        .http
        .get(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&user_token)
        .send()
        .await
        .expect("get claim")
        .json()
        .await
        .expect("get body");
    assert_eq!(got.phase, mediatore_proto::ClaimPhase::Bound);
    assert!(got.expires_at.is_some());
}

#[tokio::test]
async fn duplicate_ek_with_a_different_dmi_uuid_is_a_conflict() {
    let h = Harness::start().await;
    h.register_node().await;
    let resp = h
        .http
        .post(format!("{}/v1/nodes", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .json(&NodeRegistration {
            ek_hash: EK_HASH.into(),
            dmi_uuid: uuid::Uuid::new_v4(),
            hostname: "pool-a-8".into(),
            provider: None,
        })
        .send()
        .await
        .expect("register");
    assert_eq!(
        resp.status(),
        409,
        "cloned TPM state must be refused loudly"
    );
}
