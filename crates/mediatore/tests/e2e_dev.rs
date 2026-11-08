// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Front-to-back exercise of the dev-mode loop over real HTTP listeners:
//!
//! fake `IdP` login → `POST /v1/claims` → dev bind to a registered node → `GET /v1/me` →
//! `POST /v1/token` → STS JWT verified against mediatore's own JWKS → release → cut-off.
//!
//! What stays faked here, on purpose: the peer identity is a header (`dev_mode`), the SPIRE
//! entries live in memory (`MemoryEntries`), and banlieue's claim controller is the dev binder. Everything else --
//! upstream token validation, claim lifecycle, audience checks, token minting, revocation --
//! is the production code path.

use std::future::IntoFuture;
use std::sync::Arc;

use chrono::Duration;
use mediatore_api::{AppState, Limiter};
use mediatore_entra::{Backend, IssuerConfig, Validator};
use mediatore_proto::{
    ClaimEgress, ClaimRequest, ClaimResponse, Endpoint, ErrorBody, Me, NodeRegistered,
    NodeRegistration, TokenResponse, Workload,
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
const EK_HASH: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";
/// The environment's gateways, in the broker's order (ADR-0028 decision 6).
const GATEWAYS: [&str; 3] = [
    "198.51.100.2:3128",
    "198.51.100.3:3128",
    "198.51.100.4:3128",
];

fn node_svid() -> String {
    format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{EK_HASH}")
}

fn claim_svid(uid: &uuid::Uuid) -> String {
    format!("spiffe://{TRUST_DOMAIN}/banlieue/claim/{uid}")
}

fn gateway_svid() -> String {
    format!("spiffe://{TRUST_DOMAIN}/gateway")
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
            spire: Arc::new(mediatore_spire::MemoryEntries::default()),
            naming: Naming {
                trust_domain: TRUST_DOMAIN.into(),
            },
            validator: Validator::new(vec![IssuerConfig {
                url: idp.issuer.clone(),
                backend: Backend::Sts,
                client_id: "mediatore".into(),
                subject_claim: "preferred_username".into(),
                required_group: Some(REQUIRED_GROUP.into()),
                session: None,
                ca_file: None,
                entra: None,
                groups_claim: None,
            }]),
            sts: Some(sts),
            audiences: vec![AUDIENCE.into()],
            obo_audiences: vec![],
            egress: [(
                AUDIENCE.to_owned(),
                vec![
                    "api.home.example:443".parse().unwrap(),
                    "192.0.2.10:8443".parse().unwrap(),
                ],
            )]
            .into_iter()
            .collect(),
            rules: [(
                AUDIENCE.to_owned(),
                vec![
                    mediatore_proto::EndpointRule {
                        method: "GET".into(),
                        path: "/api/**".into(),
                    },
                    mediatore_proto::EndpointRule {
                        method: "POST".into(),
                        path: "/api/things/*/notes".into(),
                    },
                ],
            )]
            .into_iter()
            .collect(),
            cas: std::collections::BTreeMap::new(),
            no_credential: std::collections::BTreeSet::new(),
            registries: [(
                "registry.internal:5000".to_owned(),
                mediatore_proto::RegistryCredential {
                    host: "registry.internal:5000".into(),
                    username: "pool".into(),
                    password: mediatore_proto::Secret("pull-token".into()),
                },
            )]
            .into_iter()
            .collect(),
            reachable_registries: None,
            policy_egress: None,
            sandboxes: None,
            sandbox_namespace: "sandboxes".into(),
            sealer: None,
            limiter: Limiter::new(10),
            dev_mode: true,
            gateways: GATEWAYS.iter().map(|g| g.parse().unwrap()).collect(),
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
            http: {
                mediatore_proto::tls::ensure_provider();
                reqwest::Client::new()
            },
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

    async fn create_claim_with_image(&self, token: &str, image: &str) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(token)
            .json(&ClaimRequest {
                pool_ref: "pool-a".into(),
                ttl_seconds: 3600,
                audiences: vec![AUDIENCE.into()],
                workload: Workload {
                    image: image.into(),
                    args: vec![],
                },
                refresh_token: None,
                policy_ref: None,
            })
            .send()
            .await
            .expect("create claim")
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
                refresh_token: None,
                policy_ref: None,
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

/// The guest's report (ADR-0029 decision 5): the node identity reports for its claim, the
/// shapes are checked, the report is kept on the record and shown to the subject; a claim
/// identity cannot report and a malformed report is refused.
async fn report_round_trip(h: &Harness, claim: &ClaimResponse, uid: uuid::Uuid, user_token: &str) {
    let report = mediatore_proto::GuestReport {
        image_digest: format!("sha256:{}", "ab".repeat(32)),
        sandbox_ruleset_sha256: "cd".repeat(32),
        host_table: mediatore_proto::HostTable::Loaded {
            sha256: "ef".repeat(32),
        },
    };
    let before_report: ClaimResponse = h
        .http
        .get(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(user_token)
        .send()
        .await
        .expect("get claim")
        .json()
        .await
        .expect("get body");
    assert!(
        before_report.report.is_none(),
        "no report before the guest made one"
    );
    let resp = h
        .http
        .post(format!("{}/v1/me/report", h.sandbox_url))
        .header(PEER_HEADER, claim_svid(&uid))
        .json(&report)
        .send()
        .await
        .expect("report as the claim");
    assert_eq!(resp.status(), 403, "a claim identity is not the node");
    let mut bad = report.clone();
    bad.image_digest = "not-a-digest".into();
    let resp = h
        .http
        .post(format!("{}/v1/me/report", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .json(&bad)
        .send()
        .await
        .expect("bad report");
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["error"], "invalid_report", "{body}");
    let resp = h
        .http
        .post(format!("{}/v1/me/report", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .json(&report)
        .send()
        .await
        .expect("report as the node");
    assert_eq!(resp.status(), 204);
    let after_report: ClaimResponse = h
        .http
        .get(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(user_token)
        .send()
        .await
        .expect("get claim")
        .json()
        .await
        .expect("get body");
    let recorded = after_report.report.expect("the report is on the record");
    assert_eq!(recorded.report, report);
    assert!(recorded.reported_at <= chrono::Utc::now());
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one straight loop from login to cut-off, in the order the system runs it
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
    assert!(claim.ready, "bound with the entry set in memory: ready");
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
    // The jail admits the claim's audiences' egress for the sandbox uid, sorted (ADR-0020).
    let want: Vec<mediatore_proto::Endpoint> = ["192.0.2.10:8443", "api.home.example:443"]
        .iter()
        .map(|e| e.parse().unwrap())
        .collect();
    assert_eq!(me.egress, want);
    assert_registry_credential(me.registry_credential.as_ref());
    let sandbox_user = me.subject.sandbox_username();
    assert!(sandbox_user.starts_with("sb-"));

    report_round_trip(&h, &claim, uid, &user_token).await; // the guest's report, ADR-0029
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

/// The gateway-only route (ADR-0028 decision 4): the gateway identity reads what one claim
/// may reach, and the answer is the list the guest got; a node, the claim itself, or no
/// peer is refused; a pending, unknown or released claim is `404`.
#[tokio::test]
async fn the_gateway_reads_a_claims_egress_and_nobody_else_does() {
    let h = Harness::start().await;
    let user_token = h.login("octocat");
    let (status, claim) = h.create_claim(&user_token).await;
    assert_eq!(status, 201);
    assert_eq!(
        claim.phase,
        mediatore_proto::ClaimPhase::Pending,
        "no node yet"
    );
    let uid = claim.uid.expect("uid");
    let url = format!("{}/v1/gateway/claims/{uid}", h.sandbox_url);
    let as_gateway = || h.http.get(&url).header(PEER_HEADER, gateway_svid());

    // Pending: no deadline, no identity, nothing a gateway could admit.
    assert_eq!(as_gateway().send().await.expect("pending").status(), 404);

    // The node registers and the dev binder binds the claim: the gateway gets its answer.
    h.register_node().await;
    let resp = as_gateway().send().await.expect("bound");
    assert_eq!(resp.status(), 200);
    let answer: ClaimEgress = resp.json().await.expect("body");
    assert_eq!(answer.claim_uid, uid);
    let want: Vec<Endpoint> = ["192.0.2.10:8443", "api.home.example:443"]
        .iter()
        .map(|e| e.parse().unwrap())
        .collect();
    assert_eq!(
        answer.egress, want,
        "the same list the guest's ruleset admits"
    );
    let me: Me = h
        .http
        .get(format!("{}/v1/me", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .send()
        .await
        .expect("me")
        .json()
        .await
        .expect("me body");
    assert_eq!(answer.expires_at, me.expires_at, "the claim's own deadline");
    // And the guest got the gateways in the broker's order (ADR-0028 decision 6).
    assert_eq!(
        me.gateways,
        GATEWAYS.map(|g| g.parse::<Endpoint>().unwrap())
    );

    // Anyone but the gateway, the claim asked about included, is refused; no peer is 401.
    for peer in [
        node_svid(),
        claim_svid(&uid),
        format!("{}/x", gateway_svid()),
    ] {
        let resp = h
            .http
            .get(&url)
            .header(PEER_HEADER, &peer)
            .send()
            .await
            .expect("peer");
        assert_eq!(resp.status(), 403, "{peer}");
    }
    assert_eq!(h.http.get(&url).send().await.expect("anon").status(), 401);

    // Unknown, and malformed.
    let other = format!(
        "{}/v1/gateway/claims/{}",
        h.sandbox_url,
        uuid::Uuid::new_v4()
    );
    let resp = h
        .http
        .get(&other)
        .header(PEER_HEADER, gateway_svid())
        .send()
        .await
        .expect("unknown");
    assert_eq!(resp.status(), 404);
    let bad = format!("{}/v1/gateway/claims/not-a-uuid", h.sandbox_url);
    let resp = h
        .http
        .get(&bad)
        .header(PEER_HEADER, gateway_svid())
        .send()
        .await
        .expect("bad");
    assert_eq!(resp.status(), 400);

    // Released: the answer the gateway takes as "drop the cache, deny".
    let del = h
        .http
        .delete(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&user_token)
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status(), 204);
    assert_eq!(as_gateway().send().await.expect("released").status(), 404);
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

/// The operator's credential for the registry the image names travels with the subject,
/// over the same session, and prints redacted (ADR-0022).
fn assert_registry_credential(cred: Option<&mediatore_proto::RegistryCredential>) {
    let cred = cred.expect("the fixture configures registry.internal:5000");
    assert_eq!(cred.host, "registry.internal:5000");
    assert_eq!(cred.username, "pool");
    assert_eq!(cred.password.0, "pull-token");
    assert!(!format!("{cred:?}").contains("pull-token"), "{cred:?}");
}

#[tokio::test]
async fn a_malformed_workload_image_is_refused_at_creation() {
    let h = Harness::start().await;
    h.register_node().await;
    let resp = h
        .create_claim_with_image(&h.login("octocat"), "Not An Image")
        .await;
    assert_eq!(resp.status(), 400);
    let body: mediatore_proto::ErrorBody = resp.json().await.expect("error body");
    assert_eq!(body.error, "invalid_workload_image");
}

#[tokio::test]
async fn a_registry_without_a_configured_credential_gets_none() {
    let h = Harness::start().await;
    h.register_node().await;
    let resp = h
        .create_claim_with_image(&h.login("octocat"), "ghcr.io/octocat/agent:1")
        .await;
    assert_eq!(resp.status(), 201);
    let me: Me = h
        .http
        .get(format!("{}/v1/me", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .send()
        .await
        .expect("me")
        .json()
        .await
        .expect("me body");
    assert_eq!(me.workload.image, "ghcr.io/octocat/agent:1");
    assert_eq!(
        me.registry_credential, None,
        "no credential for ghcr.io is configured"
    );
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
            refresh_token: None,
            policy_ref: None,
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
            refresh_token: None,
            policy_ref: None,
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
async fn a_malformed_ek_hash_is_refused_at_registration() {
    // Not the attestor's shape: the admission policy and the entry manager would refuse
    // it later, so the front door refuses it now instead of a 500 at bind.
    let h = Harness::start().await;
    let bad = format!("demo{:060}", 7);
    let resp = h
        .http
        .post(format!("{}/v1/nodes", h.sandbox_url))
        .header(
            PEER_HEADER,
            format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{bad}"),
        )
        .json(&NodeRegistration {
            ek_hash: bad,
            dmi_uuid: uuid::Uuid::new_v4(),
            hostname: "pool-a-7".into(),
            provider: None,
        })
        .send()
        .await
        .expect("register");
    assert_eq!(resp.status(), 400);
    let body: ErrorBody = resp.json().await.expect("error body");
    assert_eq!(body.error, "invalid_ek_hash");
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

#[tokio::test]
async fn an_issuer_without_a_session_refuses_a_delegated_refresh_token() {
    let h = Harness::start().await;
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(h.login("octocat"))
        .json(&ClaimRequest {
            pool_ref: "pool-a".into(),
            ttl_seconds: 3600,
            audiences: vec![AUDIENCE.into()],
            workload: Workload {
                image: "registry.internal:5000/sandbox:latest".into(),
                args: vec![],
            },
            refresh_token: Some(mediatore_proto::Secret("rt-unwanted".into())),
            policy_ref: None,
        })
        .send()
        .await
        .expect("create claim");
    assert_eq!(resp.status(), 400);
    let body: ErrorBody = resp.json().await.expect("error body");
    assert_eq!(body.error, "session_unexpected");
}
