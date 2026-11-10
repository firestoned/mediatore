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
    ClaimEgress, ClaimRequest, ClaimResponse, Delegation, Endpoint, ErrorBody, Me, NodeRegistered,
    NodeRegistration, TokenResponse, Workload,
};
use mediatore_spire::Naming;
use mediatore_store::MemoryStore;
use mediatore_store::seal::LocalKeySealer;
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
/// An audience served from the caller's own credential (`via: delegated`, ADR-0035).
const DELEGATED: &str = "anthropic.test";
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

/// The two audiences' egress: the ordinary one with two endpoints, the delegated one with
/// Anthropic's.
fn egress_map() -> std::collections::BTreeMap<String, Vec<Endpoint>> {
    [
        (
            AUDIENCE.to_owned(),
            vec![
                "api.home.example:443".parse().unwrap(),
                "192.0.2.10:8443".parse().unwrap(),
            ],
        ),
        (
            DELEGATED.to_owned(),
            vec!["api.anthropic.test:443".parse().unwrap()],
        ),
    ]
    .into_iter()
    .collect()
}

fn rules_map() -> std::collections::BTreeMap<String, Vec<mediatore_proto::EndpointRule>> {
    [(
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
    .collect()
}

/// ADR-0035: the caller's own session, a bearer with Anthropic's beta header beside it.
fn delegated_map() -> std::collections::BTreeMap<String, mediatore_api::DelegatedAudience> {
    [(
        DELEGATED.to_owned(),
        mediatore_api::DelegatedAudience {
            header: "authorization".into(),
            extra_headers: vec![mediatore_proto::HeaderPair {
                name: "anthropic-beta".into(),
                value: "oauth-2025-04-20".into(),
            }],
            ttl: Duration::minutes(15),
        },
    )]
    .into_iter()
    .collect()
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
            audiences: vec![AUDIENCE.into(), DELEGATED.into()],
            obo_audiences: vec![],
            egress: egress_map(),
            rules: rules_map(),
            cas: std::collections::BTreeMap::new(),
            no_credential: std::collections::BTreeSet::new(),
            secrets: std::collections::BTreeMap::new(),
            delegated: delegated_map(),
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
            sealer: Some(Arc::new(LocalKeySealer::new([9u8; 32]))),
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
                    restart: mediatore_proto::RestartPolicy::Always,
                },
                refresh_token: None,
                policy_ref: None,
                delegations: vec![],
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
                    restart: mediatore_proto::RestartPolicy::Always,
                },
                refresh_token: None,
                policy_ref: None,
                delegations: vec![],
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
/// ADR-0033: a claim created `restart: never`; the node posts the workload's exit, the
/// broker records it and releases the claim as a delete does; a claim identity cannot
/// post it, and a late post after the release is `204` with nothing done.
#[tokio::test]
async fn a_one_shot_workload_ends_its_claim_at_the_broker() {
    let h = Harness::start().await;
    h.register_node().await;
    let user_token = h.login("octocat");
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(&user_token)
        .json(&ClaimRequest {
            pool_ref: "pool-a".into(),
            ttl_seconds: 3600,
            audiences: vec![AUDIENCE.into()],
            workload: Workload {
                image: "registry.internal:5000/sandbox:latest".into(),
                args: vec!["/usr/local/bin/agent".into(), "--once".into()],
                restart: mediatore_proto::RestartPolicy::Never,
            },
            refresh_token: None,
            policy_ref: None,
            delegations: vec![],
        })
        .send()
        .await
        .expect("create claim");
    assert_eq!(resp.status(), 201);
    let claim: ClaimResponse = resp.json().await.expect("claim body");
    let uid = claim.uid.expect("uid");
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Bound);

    // The guest reads the policy with the subject.
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
    assert_eq!(me.workload.restart, mediatore_proto::RestartPolicy::Never);

    let exit = mediatore_proto::GuestExit {
        code: Some(0),
        signal: None,
        restarts: 0,
    };
    // Not the node: refused, nothing ends.
    let resp = h
        .http
        .post(format!("{}/v1/me/exit", h.sandbox_url))
        .header(PEER_HEADER, claim_svid(&uid))
        .json(&exit)
        .send()
        .await
        .expect("exit as the claim");
    assert_eq!(resp.status(), 403, "a claim identity is not the node");
    let still: ClaimResponse = h
        .http
        .get(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&user_token)
        .send()
        .await
        .expect("get claim")
        .json()
        .await
        .expect("get body");
    assert_eq!(still.phase, mediatore_proto::ClaimPhase::Bound);
    assert!(still.exit.is_none());

    // The node: the exit on the record, the claim released, the tokens cut off.
    let resp = h
        .http
        .post(format!("{}/v1/me/exit", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .json(&exit)
        .send()
        .await
        .expect("exit as the node");
    assert_eq!(resp.status(), 204);
    let ended: ClaimResponse = h
        .http
        .get(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&user_token)
        .send()
        .await
        .expect("get claim")
        .json()
        .await
        .expect("get body");
    assert_ne!(ended.phase, mediatore_proto::ClaimPhase::Bound, "released");
    assert!(!ended.ready);
    let recorded = ended.exit.expect("the exit is on the record");
    assert_eq!(recorded.exit, exit);
    assert!(recorded.exited_at <= chrono::Utc::now());
    let resp = h.token_for(&claim_svid(&uid), AUDIENCE).await;
    assert_eq!(resp.status(), 403, "no token for a released claim");

    // Late: the node says it again; nothing to end, and no error for the guest.
    let resp = h
        .http
        .post(format!("{}/v1/me/exit", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .json(&exit)
        .send()
        .await
        .expect("late exit");
    assert_eq!(resp.status(), 204);
}

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
            delegations: vec![],
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
            delegations: vec![],
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
                restart: mediatore_proto::RestartPolicy::Always,
            },
            refresh_token: Some(mediatore_proto::Secret("rt-unwanted".into())),
            policy_ref: None,
            delegations: vec![],
        })
        .send()
        .await
        .expect("create claim");
    assert_eq!(resp.status(), 400);
    let body: ErrorBody = resp.json().await.expect("error body");
    assert_eq!(body.error, "session_unexpected");
}

/// A claim request naming the delegated audience beside the ordinary one.
fn delegated_request(delegations: Vec<Delegation>, ttl_seconds: u32) -> ClaimRequest {
    ClaimRequest {
        pool_ref: "pool-a".into(),
        ttl_seconds,
        audiences: vec![AUDIENCE.into(), DELEGATED.into()],
        workload: Workload {
            image: "registry.internal:5000/sandbox:latest".into(),
            args: vec![],
            restart: mediatore_proto::RestartPolicy::Always,
        },
        refresh_token: None,
        policy_ref: None,
        delegations,
    }
}

fn delegation(
    audience: &str,
    token: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Delegation {
    Delegation {
        audience: audience.into(),
        token: Some(mediatore_proto::Secret(token.into())),
        refresh_token: None,
        expires_at,
        pending: false,
    }
}

/// ADR-0035: the caller's own credential for a `via: delegated` audience is sealed with the
/// claim, handed to the proxy from `POST /v1/token` with the audience's headers and an
/// expiry bounded by the credential's own, and gone once the claim is released.
#[tokio::test]
async fn a_delegated_credential_is_sealed_at_the_claim_and_handed_to_the_proxy_with_its_headers() {
    let h = Harness::start().await;
    h.register_node().await;
    let user_token = h.login("octocat");
    let dies_at = chrono::Utc::now() + Duration::hours(2);
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(&user_token)
        .json(&delegated_request(
            vec![delegation(DELEGATED, "sess-octocat-abc", Some(dies_at))],
            3600,
        ))
        .send()
        .await
        .expect("create claim");
    assert_eq!(
        resp.status(),
        201,
        "{}",
        resp.text().await.unwrap_or_default()
    );
    let claim: ClaimResponse = resp.json().await.expect("claim body");
    let uid = claim.uid.expect("uid");
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Bound);

    // The route the proxy gets carries no special header: a bearer, the proxy's default.
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
    let route = me
        .routes
        .iter()
        .find(|r| r.audience.as_deref() == Some(DELEGATED))
        .expect("a route for the delegated audience");
    assert_eq!(route.credential, mediatore_proto::Credential::Token);
    assert!(route.credential_header.is_none());

    let before = chrono::Utc::now();
    let tok_resp = h.token_for(&claim_svid(&uid), DELEGATED).await;
    assert_eq!(
        tok_resp.status(),
        200,
        "{}",
        tok_resp.text().await.unwrap_or_default()
    );
    let tok: TokenResponse = tok_resp.json().await.expect("token body");
    assert_eq!(
        tok.access_token, "sess-octocat-abc",
        "the delegated bearer, as it was"
    );
    assert_eq!(tok.token_type, "Bearer");
    assert!(tok.header.is_none());
    assert_eq!(tok.extra_headers[0].name, "anthropic-beta");
    assert_eq!(tok.extra_headers[0].value, "oauth-2025-04-20");
    assert!(
        tok.expires_at <= before + Duration::minutes(15) + Duration::seconds(1),
        "the proxy asks again within max_ttl"
    );
    assert!(tok.expires_at <= dies_at);
    assert_eq!(tok.subject.id, "octocat");

    // The ordinary audience still mints an STS token beside it.
    assert_eq!(h.token_for(&claim_svid(&uid), AUDIENCE).await.status(), 200);

    // Released: the envelope is gone with the claim and nothing is handed out any more.
    let del = h
        .http
        .delete(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&user_token)
        .send()
        .await
        .expect("delete");
    assert!(del.status().is_success(), "{}", del.status());
    let after = h.token_for(&claim_svid(&uid), DELEGATED).await;
    assert_eq!(after.status(), 403);
}

/// The refusals of ADR-0035 decision 2, each a `400` before anything is created.
#[tokio::test]
async fn a_delegation_is_required_where_the_audience_wants_one_and_refused_anywhere_else() {
    let h = Harness::start().await;
    let user_token = h.login("octocat");
    let code = |resp: reqwest::Response| async move {
        let status = resp.status().as_u16();
        let body: ErrorBody = resp.json().await.expect("error body");
        (status, body.error)
    };
    // Named but not delegated.
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(&user_token)
        .json(&delegated_request(vec![], 3600))
        .send()
        .await
        .expect("create");
    assert_eq!(code(resp).await, (400, "delegation_required".to_owned()));
    // Delegated for an audience that is not served that way.
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(&user_token)
        .json(&delegated_request(
            vec![
                delegation(DELEGATED, "sess", None),
                delegation(AUDIENCE, "sess-too", None),
            ],
            3600,
        ))
        .send()
        .await
        .expect("create");
    assert_eq!(code(resp).await, (400, "delegation_refused".to_owned()));
    // A credential that dies before the claim would.
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(&user_token)
        .json(&delegated_request(
            vec![delegation(
                DELEGATED,
                "sess",
                Some(chrono::Utc::now() + Duration::seconds(30)),
            )],
            3600,
        ))
        .send()
        .await
        .expect("create");
    assert_eq!(
        code(resp).await,
        (400, "delegation_expires_first".to_owned())
    );
    // A pending one: the transit shape, not served yet.
    let mut pending = delegation(DELEGATED, "", None);
    pending.token = None;
    pending.pending = true;
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(&user_token)
        .json(&delegated_request(vec![pending], 3600))
        .send()
        .await
        .expect("create");
    assert_eq!(resp.status(), 501);
    // A delegation with no token at all.
    let mut empty = delegation(DELEGATED, "", None);
    empty.token = None;
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(&user_token)
        .json(&delegated_request(vec![empty], 3600))
        .send()
        .await
        .expect("create");
    assert_eq!(code(resp).await, (400, "delegation_required".to_owned()));
}
