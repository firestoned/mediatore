// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The Entra path end to end (ADR-0016) over real HTTP listeners against the fake issuer
//! playing Entra: the caller's access token is exchanged On-Behalf-Of at claim creation,
//! the session is refreshed for the audience's resource before every issue (a token for
//! mediatore itself validated like a login for an STS audience, Entra's token handed over
//! unread for an audience Entra serves), a refusal at Entra releases the claim, an outage
//! is a `503` that revokes nothing, a Dex login cannot reach an Entra audience, and the
//! broker authenticates with a client assertion in its three shapes.

use std::future::IntoFuture;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use mediatore_api::{AppState, Limiter};
use mediatore_entra::{Backend, ClientAssertion, EntraConfig, IssuerConfig, Validator};
use mediatore_proto::{
    ClaimRequest, ClaimResponse, ErrorBody, NodeRegistration, Secret, TokenResponse, Workload,
};
use mediatore_spire::{MemoryEntries, Naming};
use mediatore_store::seal::LocalKeySealer;
use mediatore_store::{ClaimStore, MemoryStore};
use mediatore_sts::Sts;
use mediatore_testkit::FakeIdp;
use mediatore_testkit::entra::write_client_credential;

const TRUST_DOMAIN: &str = "sandbox.test";
/// The broker's app id at Entra: `client_id`, and the `aud` of every token for it.
const CLIENT_ID: &str = "00001111-aaaa-2222-bbbb-3333cccc4444";
/// An audience Entra serves (a downstream app's id URI) and one the STS serves.
const OBO_AUDIENCE: &str = "api://trading-data";
const STS_AUDIENCE: &str = "grafana.test";
const REQUIRED_GROUP: &str = "firestoned:sandbox-users";
const PEER_HEADER: &str = "x-mediatore-peer-spiffe-id";
const EK_HASH: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";

/// How the broker authenticates at the fake Entra.
enum Credential {
    /// A key file and the registered certificate.
    KeyFile,
    /// A projected token from another fake issuer (the cluster), registered as federated.
    Federated,
}

struct Harness {
    idp: FakeIdp,
    /// A second issuer standing in for the cluster, when the credential is federated.
    _cluster: Option<FakeIdp>,
    /// A Dex-shaped issuer on the same broker, for the cross-issuer refusals.
    dex: FakeIdp,
    store: Arc<MemoryStore>,
    entries: Arc<MemoryEntries>,
    user_url: String,
    sandbox_url: String,
    http: reqwest::Client,
}

fn tempdir() -> std::path::PathBuf {
    let dir =
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The broker's credential in the shape asked for, registered at the fake Entra, and the
/// cluster issuer behind a federated one.
async fn credential(
    idp: &FakeIdp,
    dir: &std::path::Path,
    which: Credential,
) -> (EntraConfig, Option<FakeIdp>) {
    match which {
        Credential::KeyFile => {
            let (key, cert) = write_client_credential(dir);
            idp.register_client_certificate(
                CLIENT_ID,
                &mediatore_testkit::entra::client_credential().certificate_pem,
            );
            (
                EntraConfig {
                    certificate_file: Some(cert),
                    key_file: Some(key),
                    ..Default::default()
                },
                None,
            )
        }
        Credential::Federated => {
            let cluster = FakeIdp::start().await;
            let subject = "system:serviceaccount:banlieue-system:mediatore";
            idp.register_federated_credential(
                CLIENT_ID,
                &cluster.issuer,
                subject,
                "api://AzureADTokenExchange",
            );
            let token_file = dir.join("token");
            std::fs::write(
                &token_file,
                cluster.token(serde_json::json!({
                    "aud": "api://AzureADTokenExchange", "sub": subject
                })),
            )
            .unwrap();
            (
                EntraConfig {
                    token_file: Some(token_file),
                    ..Default::default()
                },
                Some(cluster),
            )
        }
    }
}

impl Harness {
    async fn start(which: Credential) -> Self {
        let idp = FakeIdp::start().await;
        let dex = FakeIdp::start().await;
        let dir = tempdir();
        let (entra_cfg, cluster) = credential(&idp, &dir, which).await;
        let entra_issuer = IssuerConfig {
            url: idp.issuer.clone(),
            backend: Backend::EntraObo,
            client_id: CLIENT_ID.into(),
            subject_claim: "oid".into(),
            required_group: Some(REQUIRED_GROUP.into()),
            session: None,
            ca_file: None,
            entra: Some(entra_cfg.clone()),
            groups_claim: None,
        };
        let dex_issuer = IssuerConfig {
            url: dex.issuer.clone(),
            backend: Backend::Sts,
            client_id: "mediatore".into(),
            subject_claim: "preferred_username".into(),
            required_group: Some(REQUIRED_GROUP.into()),
            session: None,
            ca_file: None,
            entra: None,
            groups_claim: None,
        };
        let assertion = ClientAssertion::build(&entra_cfg)
            .await
            .expect("the credential builds and probes");
        let validator = Validator::new(vec![entra_issuer, dex_issuer])
            .with_client_assertion(&idp.issuer, assertion);
        let sts = Sts::new(
            "https://mediatore.test",
            "e2e-1",
            mediatore_testkit::entra::fresh_p256_key_pem().as_bytes(),
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
            validator,
            sts: Some(sts),
            audiences: vec![OBO_AUDIENCE.into(), STS_AUDIENCE.into()],
            obo_audiences: vec![OBO_AUDIENCE.into()],
            egress: std::collections::BTreeMap::new(),
            rules: std::collections::BTreeMap::new(),
            registries: std::collections::BTreeMap::new(),
            sandboxes: None,
            sandbox_namespace: "sandboxes".into(),
            sealer: Some(Arc::new(LocalKeySealer::new([7u8; 32]))),
            limiter: Limiter::new(60),
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
            _cluster: cluster,
            dex,
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

    async fn claim(
        &self,
        bearer: &str,
        audiences: &[&str],
        refresh_token: Option<&str>,
    ) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(bearer)
            .json(&ClaimRequest {
                pool_ref: "pool-a".into(),
                ttl_seconds: 3600,
                audiences: audiences.iter().map(|a| (*a).to_owned()).collect(),
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

    /// An Entra login for `login` claiming `audiences`, bound to the registered node.
    async fn bound_claim(&self, login: &str, audiences: &[&str]) -> ClaimResponse {
        self.register_node().await;
        let bearer = self.idp.access_token(login, CLIENT_ID);
        let resp = self.claim(&bearer, audiences, None).await;
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
        let claim: ClaimResponse = resp.json().await.unwrap();
        assert!(claim.ready, "dev binder binds at once");
        claim
    }

    async fn token(&self, claim: &ClaimResponse, audience: &str) -> reqwest::Response {
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
                audience: audience.into(),
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
async fn the_bearer_is_exchanged_once_and_every_issue_refreshes_for_the_audience() {
    let h = Harness::start(Credential::KeyFile).await;
    let claim = h
        .bound_claim("octocat", &[OBO_AUDIENCE, STS_AUDIENCE])
        .await;
    assert_eq!(
        h.idp.exchanges(),
        1,
        "one On-Behalf-Of exchange at creation"
    );
    assert_eq!(h.idp.refreshes(), 0);
    let rec = h.store.get_claim(claim.uid.unwrap()).await.unwrap();
    assert!(
        rec.refresh.is_some(),
        "the session is sealed into the record"
    );

    // An audience Entra serves: Entra's token, with Entra's expiry, unread by the broker.
    let resp = h.token(&claim, OBO_AUDIENCE).await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let obo: TokenResponse = resp.json().await.unwrap();
    assert!(obo.access_token.starts_with("at-"), "{}", obo.access_token);
    assert_eq!(obo.token_type, "Bearer");
    assert_eq!(obo.audience, OBO_AUDIENCE);
    assert_eq!(obo.subject.id, "octocat");
    let life = obo.expires_at - Utc::now();
    assert!(
        life > Duration::minutes(50) && life <= Duration::minutes(60),
        "Entra's lifetime, not the STS's: {life}"
    );
    assert_eq!(
        h.idp.refresh_scopes(),
        vec![format!("offline_access {OBO_AUDIENCE}/.default")]
    );

    // An STS audience: a token for mediatore itself, validated, its groups minted.
    let resp = h.token(&claim, STS_AUDIENCE).await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let sts: TokenResponse = resp.json().await.unwrap();
    let claims = payload(&sts.access_token);
    assert_eq!(claims["iss"], "https://mediatore.test");
    assert_eq!(claims["aud"], STS_AUDIENCE);
    assert_eq!(claims["groups"], serde_json::json!([REQUIRED_GROUP]));
    assert_eq!(
        h.idp.refresh_scopes().last().unwrap(),
        &format!("offline_access {CLIENT_ID}/.default")
    );
    assert_eq!(h.idp.refreshes(), 2);
    assert_eq!(
        h.idp.exchanges(),
        1,
        "the bearer is exchanged once, never again"
    );

    // A fresh group lands in the next STS token.
    h.idp
        .set_groups("octocat", &[REQUIRED_GROUP, "firestoned:traders"]);
    let sts: TokenResponse = h.token(&claim, STS_AUDIENCE).await.json().await.unwrap();
    assert_eq!(
        payload(&sts.access_token)["groups"],
        serde_json::json!([REQUIRED_GROUP, "firestoned:traders"])
    );
}

#[tokio::test]
async fn an_entra_issuer_takes_no_delegated_token_and_a_dex_login_cannot_reach_an_entra_audience() {
    let h = Harness::start(Credential::KeyFile).await;
    h.register_node().await;
    let bearer = h.idp.access_token("octocat", CLIENT_ID);
    let resp = h.claim(&bearer, &[STS_AUDIENCE], Some("rt-smuggled")).await;
    assert_eq!(error_code(resp).await, (400, "session_unexpected".into()));
    assert_eq!(h.idp.exchanges(), 0, "refused before any exchange");

    // A Dex login asking for the Entra audience: refused before any claim exists.
    let login = h.dex.token(serde_json::json!({
        "aud": "mediatore", "preferred_username": "hexley", "groups": [REQUIRED_GROUP],
    }));
    let resp = h.claim(&login, &[OBO_AUDIENCE], None).await;
    assert_eq!(error_code(resp).await, (400, "audience_needs_entra".into()));
    // The same login with an STS audience works as before, with no session at all.
    let resp = h.claim(&login, &[STS_AUDIENCE], None).await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let claim: ClaimResponse = resp.json().await.unwrap();
    assert!(
        h.store
            .get_claim(claim.uid.unwrap())
            .await
            .unwrap()
            .refresh
            .is_none()
    );
    assert_eq!(h.token(&claim, STS_AUDIENCE).await.status(), 200);
    // And an Entra audience is refused at issue too, even if the record named it.
    let resp = h.token(&claim, OBO_AUDIENCE).await;
    assert_eq!(resp.status(), 400, "not among the claim's audiences");
}

#[tokio::test]
async fn an_entra_login_without_an_entra_audience_still_gets_a_session_for_mediatore_itself() {
    let h = Harness::start(Credential::KeyFile).await;
    let claim = h.bound_claim("octocat", &[STS_AUDIENCE]).await;
    assert_eq!(h.idp.exchanges(), 1);
    assert_eq!(h.token(&claim, STS_AUDIENCE).await.status(), 200);
    assert_eq!(
        h.idp.refresh_scopes(),
        vec![format!("offline_access {CLIENT_ID}/.default")],
        "the session serves mediatore's own resource"
    );
    // Revoked at Entra: the next issue releases the claim.
    h.idp.revoke("octocat");
    let resp = h.token(&claim, STS_AUDIENCE).await;
    assert_eq!(error_code(resp).await, (403, "session_revoked".into()));
    let rec = h.store.get_claim(claim.uid.unwrap()).await.unwrap();
    assert!(rec.revoked_at.is_some() && rec.refresh.is_none());
    assert_eq!(h.entries.names().len(), 0, "entry retracted");
    assert_eq!(h.token(&claim, STS_AUDIENCE).await.status(), 403);
}

#[tokio::test]
async fn a_refusal_at_entra_releases_the_claim_and_an_outage_revokes_nothing() {
    let h = Harness::start(Credential::KeyFile).await;
    let claim = h.bound_claim("octocat", &[OBO_AUDIENCE]).await;
    assert_eq!(h.token(&claim, OBO_AUDIENCE).await.status(), 200);

    h.idp.set_down(true);
    let resp = h.token(&claim, OBO_AUDIENCE).await;
    assert_eq!(error_code(resp).await, (503, "upstream_unavailable".into()));
    let rec = h.store.get_claim(claim.uid.unwrap()).await.unwrap();
    assert!(rec.revoked_at.is_none() && rec.refresh.is_some(), "kept");
    h.idp.set_down(false);
    assert_eq!(h.token(&claim, OBO_AUDIENCE).await.status(), 200);

    // A Conditional Access step the user must take: a refusal, as invalid_grant is.
    h.idp.set_interaction_required("octocat", true);
    let resp = h.token(&claim, OBO_AUDIENCE).await;
    assert_eq!(error_code(resp).await, (403, "session_revoked".into()));
    let rec = h.store.get_claim(claim.uid.unwrap()).await.unwrap();
    assert!(rec.revoked_at.is_some() && rec.refresh.is_none());
    assert_eq!(h.entries.names().len(), 0, "entry retracted");
}

#[tokio::test]
async fn a_refused_exchange_creates_no_claim_and_an_outage_at_creation_is_503() {
    let h = Harness::start(Credential::KeyFile).await;
    h.register_node().await;
    let bearer = h.idp.access_token("octocat", CLIENT_ID);
    h.idp.set_interaction_required("octocat", true);
    let resp = h.claim(&bearer, &[OBO_AUDIENCE], None).await;
    assert_eq!(error_code(resp).await, (403, "session_refused".into()));
    assert_eq!(h.store.list_claims().await.unwrap().len(), 0);
    h.idp.set_interaction_required("octocat", false);

    h.idp.set_down(true);
    // The login itself still validates (the JWKS is cached), the exchange does not.
    let resp = h.claim(&bearer, &[OBO_AUDIENCE], None).await;
    assert_eq!(error_code(resp).await, (503, "upstream_unavailable".into()));
    assert_eq!(h.store.list_claims().await.unwrap().len(), 0);
    h.idp.set_down(false);

    // A token for another app, or an expired one, is not exchanged: the login refuses it.
    let other = h
        .idp
        .token(serde_json::json!({ "aud": "another-app", "oid": "octocat" }));
    assert_eq!(h.claim(&other, &[OBO_AUDIENCE], None).await.status(), 401);
    assert_eq!(h.idp.exchanges(), 0);
}

#[tokio::test]
async fn a_login_that_left_the_group_releases_the_claim_at_the_next_sts_issue() {
    let h = Harness::start(Credential::KeyFile).await;
    let claim = h
        .bound_claim("octocat", &[STS_AUDIENCE, OBO_AUDIENCE])
        .await;
    h.idp.set_groups("octocat", &["firestoned:other"]);
    // The Entra audience's token carries whatever Entra puts in it; the broker's gate
    // runs where it reads a token of its own.
    assert_eq!(h.token(&claim, OBO_AUDIENCE).await.status(), 200);
    let resp = h.token(&claim, STS_AUDIENCE).await;
    assert_eq!(error_code(resp).await, (403, "session_revoked".into()));
    assert_eq!(
        h.token(&claim, OBO_AUDIENCE).await.status(),
        403,
        "released"
    );
}

#[tokio::test]
async fn a_federated_credential_authenticates_the_broker_without_a_key() {
    let h = Harness::start(Credential::Federated).await;
    let claim = h
        .bound_claim("octocat", &[OBO_AUDIENCE, STS_AUDIENCE])
        .await;
    assert_eq!(h.idp.exchanges(), 1);
    assert_eq!(h.token(&claim, OBO_AUDIENCE).await.status(), 200);
    assert_eq!(h.token(&claim, STS_AUDIENCE).await.status(), 200);
    assert_eq!(h.idp.refreshes(), 2);
}

#[tokio::test]
async fn the_fake_entra_refuses_an_unauthenticated_or_replayed_client() {
    // What the fake enforces, so the suite above means something: a confidential client
    // with no assertion, a reused assertion, and an ID token as the OBO assertion.
    mediatore_proto::tls::ensure_provider();
    let idp = FakeIdp::start().await;
    idp.register_client_certificate(
        CLIENT_ID,
        &mediatore_testkit::entra::client_credential().certificate_pem,
    );
    let http = reqwest::Client::new();
    let endpoint = format!("{}/token", idp.issuer);
    let bearer = idp.access_token("octocat", CLIENT_ID);
    let base = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("client_id", CLIENT_ID),
        ("assertion", bearer.as_str()),
        ("scope", "offline_access api://trading-data/.default"),
        ("requested_token_use", "on_behalf_of"),
    ];
    let resp = http.post(&endpoint).form(&base).send().await.unwrap();
    assert_eq!(resp.status(), 401, "no client assertion");

    let dir = tempdir();
    let (key, cert) = write_client_credential(&dir);
    let assertion = ClientAssertion::build(&EntraConfig {
        certificate_file: Some(cert),
        key_file: Some(key),
        ..Default::default()
    })
    .await
    .unwrap();
    let jwt = assertion.assert(CLIENT_ID, &endpoint).await.unwrap();
    let mut form = base.to_vec();
    form.push((
        "client_assertion_type",
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    ));
    form.push(("client_assertion", jwt.as_str()));
    let resp = http.post(&endpoint).form(&form).send().await.unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let resp = http.post(&endpoint).form(&form).send().await.unwrap();
    assert_eq!(resp.status(), 401, "the same jti twice");

    // A fresh assertion, but the OBO assertion is for another audience: invalid_grant.
    let jwt = assertion.assert(CLIENT_ID, &endpoint).await.unwrap();
    let foreign = idp.token(serde_json::json!({ "aud": "another-app", "oid": "octocat" }));
    let mut form = form.clone();
    form.retain(|(k, _)| *k != "client_assertion" && *k != "assertion");
    form.push(("client_assertion", jwt.as_str()));
    form.push(("assertion", foreign.as_str()));
    let resp = http.post(&endpoint).form(&form).send().await.unwrap();
    assert_eq!(error_code(resp).await, (400, "invalid_grant".into()));
}
