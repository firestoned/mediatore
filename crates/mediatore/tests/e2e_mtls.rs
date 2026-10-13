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

use mediatore_api::AppState;
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
        chrono::Duration::minutes(15),
    )
    .expect("sts");
    Arc::new(AppState {
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
        }]),
        sts: Some(sts),
        audiences: vec![AUDIENCE.into()],
        dev_mode,
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
        mediatore_proto::tls::ensure_provider();
        let idp = FakeIdp::start().await;
        let st = state(&idp, true);

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
            mediatore_api::sandbox_authorizer(st.naming.clone()),
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
            .use_preconfigured_tls(cfg)
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
            .use_preconfigured_tls(cfg)
            .build()
            .expect("client")
    }

    async fn register_node(&self, client: &reqwest::Client) -> reqwest::Response {
        client
            .post(format!("{}/v1/nodes", self.sandbox_url))
            .json(&NodeRegistration {
                ek_hash: EK_HASH.into(),
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
