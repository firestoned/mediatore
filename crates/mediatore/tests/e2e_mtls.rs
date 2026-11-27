// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The sandbox API over SPIFFE mTLS, hermetically (ADR-0007 decision 8).
//!
//! The listener is the production one (`mediatore_tls::serve`, its verifiers and the
//! `sandbox_authorizer`), fed by the testkit CA instead of a SPIRE agent. Clients are
//! `reqwest` on the production client config. On an mTLS connection the peer identity is
//! the verified client certificate and nothing else; one test proves the dev header is
//! ignored there, another that a plain listener outside `dev_mode` refuses it. What stays
//! faked: the entries (`MemoryEntries`) and the claim lifecycle, which still needs
//! `dev_mode` for its in-memory create and bind until the claim watcher (roadmap 03).

use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;

use mediatore_api::{AppState, Limiter, Namespaces};
use mediatore_entra::{Backend, IssuerConfig, Validator};
use mediatore_proto::{
    ClaimRequest, ClaimResponse, Me, NodeRegistered, NodeRegistration, TokenRequest, TokenResponse,
    Workload,
};
use mediatore_spire::Naming;
use mediatore_store::MemoryStore;
use mediatore_sts::Sts;
use mediatore_testkit::{FakeIdp, MemoryMaterial, TestCa};
use mediatore_tls::{Material, SpiffeId, TlsConfigs, TrustDomain};
use rustls::ClientConfig;

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

fn broker_id() -> SpiffeId {
    SpiffeId::new(format!("spiffe://{TRUST_DOMAIN}/mediatore")).expect("broker id")
}

fn node_svid() -> String {
    format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{EK_HASH}")
}

fn claim_svid(uid: &uuid::Uuid) -> String {
    format!("spiffe://{TRUST_DOMAIN}/banlieue/claim/{uid}")
}

fn state(idp: &FakeIdp, dev_mode: bool) -> Arc<AppState> {
    let sts = Sts::new(
        "https://mediatore.test",
        "e2e-1",
        STS_TEST_KEY.as_bytes(),
        jiff::SignedDuration::from_mins(15),
    )
    .expect("sts");
    Arc::new(AppState {
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
            trust_domain: TRUST_DOMAIN.into(),
        },
        validator: Validator::new(vec![IssuerConfig {
            url: idp.issuer.clone(),
            backend: Backend::Sts,
            client_id: "mediatore".into(),
            subject_claim: "preferred_username".into(),
            required_group: Some(REQUIRED_GROUP.into()),
            required_groups: None,
            allow_any_authenticated: false,
            session: None,
            ca_file: None,
            entra: None,
            groups_claim: None,
            subject_prefix: None,
        }]),
        sts: Some(sts),
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
        sandboxes: None,
        namespaces: Namespaces::Single("sandboxes".into()),
        max_ttl_seconds: mediatore_proto::DEFAULT_MAX_TTL_SECONDS,
        sealer: None,
        limiter: Limiter::new(10),
        dev_mode,
        gateways: vec![],
    })
}

struct Harness {
    idp: FakeIdp,
    user_url: String,
    sandbox_url: String,
    ca: TestCa,
    broker: Arc<MemoryMaterial>,
    http: reqwest::Client,
}

impl Harness {
    /// The broker serving as `spiffe://sandbox.test/mediatore` under a fresh CA.
    async fn start() -> Self {
        let ca = TestCa::new(TRUST_DOMAIN);
        let broker = ca.svid(&broker_id().to_string());
        Self::start_with(ca, broker).await
    }

    /// The broker serving with `broker_material` (whatever identity that carries).
    async fn start_with(ca: TestCa, broker_material: Material) -> Self {
        Self::start_as(ca, broker_material, false).await
    }

    /// The broker with `accept_plain_gateway_identity` on (ADR-0053 decision 7), at the
    /// handshake and on the routes, as the one config key sets both.
    async fn start_accepting_the_plain_gateway_identity() -> Self {
        let ca = TestCa::new(TRUST_DOMAIN);
        let broker = ca.svid(&broker_id().to_string());
        Self::start_as(ca, broker, true).await
    }

    async fn start_as(ca: TestCa, broker_material: Material, accept_plain: bool) -> Self {
        mediatore_proto::tls::ensure_provider();
        let idp = FakeIdp::start().await;
        let mut st = state(&idp, true);
        Arc::get_mut(&mut st)
            .expect("the state has one owner until the routers take it")
            .accept_plain_gateway_identity = accept_plain;

        let user = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind user");
        let user_url = format!("http://{}", user.local_addr().expect("addr"));
        tokio::spawn(axum::serve(user, mediatore_api::user_router(st.clone())).into_future());

        let sandbox = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sandbox");
        let sandbox_url = format!("https://{}", sandbox.local_addr().expect("addr"));
        let broker = MemoryMaterial::new(broker_material);
        let configs = TlsConfigs::spawn(
            broker.clone(),
            mediatore_api::sandbox_authorizer(st.naming.clone(), accept_plain),
        )
        .expect("tls configs");
        tokio::spawn(mediatore_tls::serve(
            sandbox,
            configs,
            mediatore_api::sandbox_router(st),
            std::future::pending(),
        ));

        Self {
            idp,
            user_url,
            sandbox_url,
            ca,
            broker,
            http: reqwest::Client::new(),
        }
    }

    fn login(&self, login: &str) -> String {
        self.idp.token(serde_json::json!({
            "aud": "mediatore",
            "preferred_username": login,
            "email": format!("{login}@example.com"),
            "groups": [REQUIRED_GROUP],
        }))
    }

    /// A client presenting `material`, expecting the broker identity on the other side.
    fn mtls(material: &Material) -> reqwest::Client {
        let cfg = mediatore_tls::client_config(material, &broker_id()).expect("client config");
        reqwest::Client::builder()
            .tls_backend_preconfigured(cfg)
            .build()
            .expect("client")
    }

    /// A client presenting a fresh SVID for `spiffe_id` from this harness's CA.
    fn mtls_as(&self, spiffe_id: &str) -> reqwest::Client {
        Self::mtls(&self.ca.svid(spiffe_id))
    }

    /// A client with no identity at all, trusting this harness's CA.
    fn anonymous(&self) -> reqwest::Client {
        let verifier = mediatore_tls::server_verifier(
            self.ca.roots(),
            TrustDomain::new(TRUST_DOMAIN).expect("td"),
            broker_id(),
        );
        let cfg = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        reqwest::Client::builder()
            .tls_backend_preconfigured(cfg)
            .build()
            .expect("client")
    }

    async fn register_node(&self, client: &reqwest::Client) -> reqwest::Response {
        client
            .post(format!("{}/v1/nodes", self.sandbox_url))
            .json(&NodeRegistration {
                ek_hash: EK_HASH.into(),
                attestation: None,
                dmi_uuid: uuid::Uuid::new_v4(),
                hostname: "pool-a-7".into(),
                provider: Some(mediatore_proto::Provider::Libvirt),
            })
            .send()
            .await
            .expect("register")
    }

    async fn create_claim(&self, token: &str) -> ClaimResponse {
        let resp = self
            .http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(token)
            .json(&ClaimRequest {
                namespace: None,
                pool_ref: Some("pool-a".into()),
                pool_selector: None,
                selection: None,
                ttl_seconds: 3600,
                audiences: vec![AUDIENCE.into()],
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
            .expect("create claim");
        assert_eq!(resp.status(), 201);
        resp.json::<ClaimResponse>().await.expect("claim body")
    }

    async fn token(&self, client: &reqwest::Client) -> reqwest::Response {
        client
            .post(format!("{}/v1/token", self.sandbox_url))
            .json(&TokenRequest {
                audience: AUDIENCE.into(),
            })
            .send()
            .await
            .expect("token request")
    }

    async fn healthz(&self, client: &reqwest::Client) -> Result<u16, reqwest::Error> {
        client
            .get(format!("{}/healthz", self.sandbox_url))
            .send()
            .await
            .map(|r| r.status().as_u16())
    }
}

/// `Material` is `expected` identity-wise but trusts `roots` of another CA, to see which
/// side refuses.
fn with_roots(m: Material, roots: Arc<rustls::RootCertStore>) -> Material {
    Material {
        spiffe_id: m.spiffe_id,
        chain: m.chain,
        key: m.key,
        roots,
    }
}

#[tokio::test]
async fn full_loop_over_mtls() {
    let h = Harness::start().await;

    // The pool member registers with its node SVID; the peer identity is the certificate.
    let node = h.mtls_as(&node_svid());
    let resp = h.register_node(&node).await;
    assert_eq!(
        resp.status(),
        200,
        "{}",
        resp.text().await.unwrap_or_default()
    );
    let registered: NodeRegistered = resp.json().await.expect("node body");
    assert_eq!(
        registered.node_id,
        format!("spiffe://{TRUST_DOMAIN}/spire/agent/tpm/{EK_HASH}")
    );

    // A claim binds to it; the node learns its subject.
    let claim = h.create_claim(&h.login("octocat")).await;
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Bound);
    let uid = claim.uid.expect("uid");
    let me = node
        .get(format!("{}/v1/me", h.sandbox_url))
        .send()
        .await
        .expect("me");
    assert_eq!(me.status(), 200);
    let me: Me = me.json().await.expect("me body");
    assert_eq!(me.claim_uid, uid);
    assert_eq!(me.subject.id, "octocat");

    // The jailed workload presents the claim SVID and gets a token.
    let workload = h.mtls_as(&claim_svid(&uid));
    let resp = h.token(&workload).await;
    assert_eq!(
        resp.status(),
        200,
        "{}",
        resp.text().await.unwrap_or_default()
    );
    let tok: TokenResponse = resp.json().await.expect("token body");
    assert_ne!(tok.access_token, "");

    // Release cuts it off, same identity, same connection path.
    let del = h
        .http
        .delete(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(h.login("octocat"))
        .send()
        .await
        .expect("delete");
    assert!(del.status().is_success(), "{}", del.status());
    assert_eq!(h.token(&workload).await.status(), 403);
}

#[tokio::test]
async fn no_client_certificate_fails_the_handshake() {
    let h = Harness::start().await;
    assert_eq!(h.healthz(&h.mtls_as(&node_svid())).await.unwrap(), 200);
    assert!(h.healthz(&h.anonymous()).await.is_err());
}

#[tokio::test]
async fn a_foreign_trust_domain_fails_the_handshake() {
    let h = Harness::start().await;
    let other = TestCa::new("other.test");
    let foreign = with_roots(
        other.svid(&format!("spiffe://other.test/banlieue/node/{EK_HASH}")),
        h.ca.roots(),
    );
    assert!(h.healthz(&Harness::mtls(&foreign)).await.is_err());
}

#[tokio::test]
async fn the_broker_identity_is_not_a_sandbox_peer() {
    let h = Harness::start().await;
    assert!(
        h.healthz(&h.mtls_as(&broker_id().to_string()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn an_expired_svid_fails_the_handshake() {
    let h = Harness::start().await;
    let expired = h.ca.expired_svid(&node_svid());
    assert!(h.healthz(&Harness::mtls(&expired)).await.is_err());
}

#[tokio::test]
async fn a_ca_shaped_certificate_is_not_a_peer() {
    let h = Harness::start().await;
    // Chains to the bundle and carries a node SPIFFE ID, but is flagged as a CA with
    // keyCertSign: the leaf constraints refuse it before the chain is even checked.
    let ca_shaped = h.ca.ca_shaped_svid(&node_svid());
    assert!(h.healthz(&Harness::mtls(&ca_shaped)).await.is_err());
}

fn gateway_svid() -> String {
    format!("spiffe://{TRUST_DOMAIN}/gateway")
}

fn authorizer_svid() -> String {
    format!("spiffe://{TRUST_DOMAIN}/gateway/authorizer")
}

/// `POST /v1/gateway/claims/{uid}/credential` as `client`: the status and the error code.
async fn ask_credential(h: &Harness, client: &reqwest::Client, uid: uuid::Uuid) -> (u16, String) {
    let resp = client
        .post(format!(
            "{}/v1/gateway/claims/{uid}/credential",
            h.sandbox_url
        ))
        .json(&mediatore_proto::GatewayCredentialRequest {
            audience: AUDIENCE.into(),
        })
        .send()
        .await
        .expect("credential");
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    (
        status,
        body["error"].as_str().unwrap_or_default().to_owned(),
    )
}

/// The authorizer's identity completes the handshake (ADR-0053 decision 3, amending
/// ADR-0028 decision 4 and ADR-0007 decision 2) and reaches the two gateway routes and
/// nothing else; nothing under its path is a peer.
#[tokio::test]
async fn the_authorizer_identity_is_a_peer_for_the_gateway_routes_only() {
    let h = Harness::start().await;
    let authorizer = Harness::mtls(&h.ca.gateway_authorizer_svid());
    assert_eq!(h.healthz(&authorizer).await.unwrap(), 200);
    assert!(
        h.healthz(&h.mtls_as(&format!("{}/1", authorizer_svid())))
            .await
            .is_err(),
        "the authorizer's identity is one id, not a prefix"
    );

    let node = h.mtls_as(&node_svid());
    assert_eq!(h.register_node(&node).await.status(), 200);
    let claim = h.create_claim(&h.login("octocat")).await;
    let uid = claim.uid.expect("uid");
    let url = format!("{}/v1/gateway/claims/{uid}", h.sandbox_url);

    let resp = authorizer.get(&url).send().await.expect("authorizer");
    assert_eq!(resp.status(), 200);
    let answer: mediatore_proto::ClaimEgress = resp.json().await.expect("body");
    assert_eq!(answer.claim_uid, uid);
    // The credential route lets it past the guard: the refusal it gets is the audience's
    // (placed in the proxy in this broker), where any other peer gets `forbidden`.
    assert_eq!(
        ask_credential(&h, &authorizer, uid).await,
        (403, "not_placed_at_gateway".to_owned())
    );

    // The certificate is the identity: the node and the claim on the gateway's routes, the
    // authorizer on the node's and the claim's, each refused.
    assert_eq!(node.get(&url).send().await.expect("node").status(), 403);
    assert_eq!(
        ask_credential(&h, &node, uid).await,
        (403, "forbidden".to_owned())
    );
    let workload = h.mtls_as(&claim_svid(&uid));
    assert_eq!(
        workload.get(&url).send().await.expect("claim").status(),
        403
    );
    assert_eq!(
        ask_credential(&h, &workload, uid).await,
        (403, "forbidden".to_owned())
    );
    assert_eq!(
        authorizer
            .get(format!("{}/v1/me", h.sandbox_url))
            .send()
            .await
            .expect("me")
            .status(),
        403
    );
    assert_eq!(h.token(&authorizer).await.status(), 403);
}

/// The gateways' listener identity is a name the sandboxes verify and no peer of the broker
/// (ADR-0053 decision 3): it fails the handshake like any stranger, on every route.
#[tokio::test]
async fn the_plain_gateway_identity_does_not_complete_a_handshake_with_the_broker() {
    let h = Harness::start().await;
    // The listener is up and the CA is the right one: a node gets through.
    assert_eq!(h.healthz(&h.mtls_as(&node_svid())).await.unwrap(), 200);
    let listener = Harness::mtls(&h.ca.gateway_listener_svid());
    assert!(
        h.healthz(&listener).await.is_err(),
        "spiffe://<td>/gateway completed a handshake with the broker"
    );
    let any_claim = uuid::Uuid::new_v4();
    assert!(
        listener
            .get(format!("{}/v1/gateway/claims/{any_claim}", h.sandbox_url))
            .send()
            .await
            .is_err(),
        "no request of a listener's reaches a route"
    );
    assert!(
        h.healthz(&h.mtls_as(&format!("{}/1", gateway_svid())))
            .await
            .is_err(),
        "nor anything else under the gateway's path"
    );
}

/// The transition switch (ADR-0053 decision 7): with it on, the listeners' identity is a
/// peer of the two gateway routes again, as before the split, and of nothing else.
#[tokio::test]
async fn the_transition_switch_admits_the_plain_gateway_identity_to_the_gateway_routes_only() {
    let h = Harness::start_accepting_the_plain_gateway_identity().await;
    let listener = Harness::mtls(&h.ca.gateway_listener_svid());
    assert_eq!(h.healthz(&listener).await.unwrap(), 200);
    let node = h.mtls_as(&node_svid());
    assert_eq!(h.register_node(&node).await.status(), 200);
    let claim = h.create_claim(&h.login("octocat")).await;
    let uid = claim.uid.expect("uid");
    let url = format!("{}/v1/gateway/claims/{uid}", h.sandbox_url);
    assert_eq!(
        listener.get(&url).send().await.expect("plain").status(),
        200
    );
    assert_eq!(
        ask_credential(&h, &listener, uid).await,
        (403, "not_placed_at_gateway".to_owned())
    );
    assert_eq!(h.token(&listener).await.status(), 403);
    // The authorizer is a peer either way, and the switch widens nothing else.
    let authorizer = Harness::mtls(&h.ca.gateway_authorizer_svid());
    assert_eq!(
        authorizer
            .get(&url)
            .send()
            .await
            .expect("authorizer")
            .status(),
        200
    );
    assert!(
        h.healthz(&h.mtls_as(&format!("{}/1", gateway_svid())))
            .await
            .is_err()
    );
    assert!(
        h.healthz(&h.mtls_as(&broker_id().to_string()))
            .await
            .is_err()
    );
}

/// A connection is closed at the peer certificate's `notAfter` at the latest: the listener
/// verified that certificate once, at the handshake, and an identity must not outlive it by
/// keeping a connection open.
#[tokio::test]
async fn a_connection_does_not_outlive_the_peer_certificates_not_after() {
    let h = Harness::start().await;
    let lifetime = Duration::from_secs(3);
    let short = Harness::mtls(&h.ca.svid_valid_for(&node_svid(), lifetime));
    assert_eq!(
        h.healthz(&short).await.unwrap(),
        200,
        "the certificate is valid at the handshake"
    );
    // The client keeps the connection in its pool. Once the certificate has expired the
    // listener has closed it, so the next request needs a new handshake, and that one is
    // refused for the expired certificate. A listener that kept the connection would
    // answer 200 on it here.
    tokio::time::sleep(lifetime + Duration::from_millis(1500)).await;
    assert!(
        h.healthz(&short).await.is_err(),
        "a request was answered on a connection whose peer certificate had expired"
    );
    // The listener itself is fine: a peer with a valid certificate is served.
    assert_eq!(h.healthz(&h.mtls_as(&node_svid())).await.unwrap(), 200);
}

#[tokio::test]
async fn a_node_svid_gets_no_token() {
    let h = Harness::start().await;
    let resp = h.token(&h.mtls_as(&node_svid())).await;
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn the_dev_header_is_ignored_on_an_mtls_connection() {
    let h = Harness::start().await;
    let node = h.mtls_as(&node_svid());
    let resp = node
        .post(format!("{}/v1/token", h.sandbox_url))
        .header(PEER_HEADER, claim_svid(&uuid::Uuid::new_v4()))
        .json(&TokenRequest {
            audience: AUDIENCE.into(),
        })
        .send()
        .await
        .expect("token");
    assert_eq!(
        resp.status(),
        403,
        "the certificate is the peer, not the header"
    );
}

#[tokio::test]
async fn the_dev_header_is_refused_outside_dev_mode() {
    let idp = FakeIdp::start().await;
    let st = state(&idp, false);
    let plain = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", plain.local_addr().expect("addr"));
    tokio::spawn(axum::serve(plain, mediatore_api::sandbox_router(st)).into_future());
    let resp = reqwest::Client::new()
        .get(format!("{url}/v1/me"))
        .header(PEER_HEADER, node_svid())
        .send()
        .await
        .expect("me");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn a_server_with_another_identity_is_refused_by_the_client() {
    let ca = TestCa::new(TRUST_DOMAIN);
    let impostor = ca.svid(&format!("spiffe://{TRUST_DOMAIN}/not-mediatore"));
    let h = Harness::start_with(ca, impostor).await;
    assert!(h.healthz(&h.mtls_as(&node_svid())).await.is_err());
}

#[tokio::test]
async fn rotated_material_is_used_by_new_handshakes() {
    let h = Harness::start().await;
    let old_client = h.mtls_as(&node_svid());
    assert_eq!(h.healthz(&old_client).await.unwrap(), 200);

    // The trust domain re-keys: a new root, a new broker SVID under it.
    let new_ca = TestCa::new(TRUST_DOMAIN);
    h.broker.rotate(new_ca.svid(&broker_id().to_string()));
    let new_client = Harness::mtls(&new_ca.svid(&node_svid()));
    let mut ok = false;
    for _ in 0..50 {
        if h.healthz(&new_client).await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert!(ok, "new handshakes use the rotated material");
    // A fresh client (no pooled connection) under the old root: the broker's new SVID does
    // not chain to it, and the broker no longer trusts SVIDs it signed.
    let stale = Harness::mtls(&h.ca.svid(&node_svid()));
    assert!(
        h.healthz(&stale).await.is_err(),
        "the old root is gone on both sides"
    );
    drop(old_client);
}

/// ADR-0049 decision 8 over the real transport: the peer identity is the certificate, and an
/// x509pop node registers only the names whose key its SVID carries.
#[tokio::test]
async fn an_x509pop_node_registers_over_mtls_under_the_key_its_svid_names_and_no_other() {
    let h = Harness::start().await;
    let identity = |issuer: &str, subject: &str| {
        mediatore_spire::NodeIdentity::of(
            &Naming {
                trust_domain: TRUST_DOMAIN.into(),
            },
            &mediatore_spire::NodeAttestation::X509pop {
                issuer_cn: issuer.into(),
                subject_cn: subject.into(),
            },
        )
        .expect("an x509pop identity")
    };
    let svid_of = |id: &mediatore_spire::NodeIdentity| {
        format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{}", id.key)
    };
    let register = |client: reqwest::Client, issuer: &'static str, subject: &'static str| {
        let url = format!("{}/v1/nodes", h.sandbox_url);
        async move {
            client
                .post(url)
                .json(&NodeRegistration::x509pop(
                    issuer.into(),
                    subject.into(),
                    uuid::Uuid::new_v4(),
                    "pool-fc-1".into(),
                ))
                .send()
                .await
                .expect("register")
        }
    };
    let node = identity("hv-01", "vm-uid-1");

    // Another host's guest of the same subject, and a TPM node, each with a valid SVID of
    // this trust domain: neither may register the names.
    let other_host = h.mtls_as(&svid_of(&identity("hv-02", "vm-uid-1")));
    assert_eq!(
        register(other_host, "hv-01", "vm-uid-1").await.status(),
        403
    );
    let tpm_node = h.mtls_as(&node_svid());
    assert_eq!(register(tpm_node, "hv-01", "vm-uid-1").await.status(), 403);

    // The guest itself.
    let client = h.mtls_as(&svid_of(&node));
    let resp = register(client.clone(), "hv-01", "vm-uid-1").await;
    assert_eq!(resp.status(), 200, "the registration was refused");
    let registered: NodeRegistered = resp.json().await.expect("node body");
    assert_eq!(
        registered.node_id,
        format!("spiffe://{TRUST_DOMAIN}/spire/agent/x509pop/hv-01/vm-uid-1")
    );
    let claim = h.create_claim(&h.login("octocat")).await;
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Bound);
    let me = client
        .get(format!("{}/v1/me", h.sandbox_url))
        .send()
        .await
        .expect("me");
    assert_eq!(me.status(), 200);
    let me: Me = me.json().await.expect("me body");
    assert_eq!(me.claim_uid, claim.uid.expect("uid"));
}
