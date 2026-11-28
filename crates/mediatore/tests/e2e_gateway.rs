// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The gateway's authorizer against the broker, end to end (ADR-0028 decision 4): the
//! broker's sandbox listener over SPIFFE mTLS under the testkit CA, `mediatore gateway`'s
//! authorizer asking it with the gateway SVID, and a stand-in for Envoy calling the check
//! listener on loopback with the three headers Envoy sets. What is proven: a claim reaches
//! its own allowlist and nothing else; a node, a foreign method, a malformed authority or a
//! check with no principal is refused; a released claim is cut off once its answer is
//! stale; a broker that is down is a deny once nothing stands in; a gateway the broker does
//! not recognise is a deny. The stand-in for Envoy speaks Envoy's own Check call over gRPC.

use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;

use envoy_types::ext_authz::v3::pb::CheckRequest;
use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
use envoy_types::pb::envoy::service::auth::v3::attribute_context::{
    HttpRequest, Peer, Request as HttpAttributes,
};
use envoy_types::pb::envoy::service::auth::v3::authorization_client::AuthorizationClient;
use envoy_types::pb::envoy::service::auth::v3::check_response::HttpResponse;
use mediatore_api::{AppState, Limiter, Namespaces};
use mediatore_entra::{Backend, IssuerConfig, Validator};
use mediatore_gateway::broker::Broker;
use mediatore_gateway::{Authorizer, CacheConfig};
use mediatore_proto::{ClaimRequest, ClaimResponse, NodeRegistration, Workload};
use mediatore_spire::Naming;
use mediatore_store::MemoryStore;
use mediatore_sts::Sts;
use mediatore_testkit::{FakeIdp, MemoryMaterial, TestCa};
use mediatore_tls::{SpiffeId, TlsConfigs};

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
const EK_HASH: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";
/// What the audience's egress declares: the claim's whole allowlist.
const ALLOWED: [&str; 2] = ["api.home.example:443", "192.0.2.10:8443"];

fn broker_id() -> SpiffeId {
    SpiffeId::new(format!("spiffe://{TRUST_DOMAIN}/mediatore")).expect("broker id")
}

fn node_svid() -> String {
    format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{EK_HASH}")
}

fn claim_svid(uid: &uuid::Uuid) -> String {
    format!("spiffe://{TRUST_DOMAIN}/banlieue/claim/{uid}")
}

/// The gateways' listener identity: what a sandbox's forwarder verifies, and since ADR-0053
/// no peer of the broker.
fn gateway_svid() -> String {
    format!("spiffe://{TRUST_DOMAIN}/gateway")
}

/// The authorizer's own identity (ADR-0053 decision 1): the one the broker answers.
fn authorizer_svid() -> String {
    format!("spiffe://{TRUST_DOMAIN}/gateway/authorizer")
}

fn state(idp: &FakeIdp, policy_egress: Option<mediatore_api::PolicyEgress>) -> Arc<AppState> {
    state_in(idp, "sandboxes", policy_egress)
}

/// [`state`] with the single namespace claims are created in (ADR-0054: the namespace a
/// record carries decides which policy namespaces it draws from).
fn state_in(
    idp: &FakeIdp,
    namespace: &str,
    policy_egress: Option<mediatore_api::PolicyEgress>,
) -> Arc<AppState> {
    let sts = Sts::new(
        "https://mediatore.test",
        "e2e-1",
        STS_TEST_KEY.as_bytes(),
        jiff::SignedDuration::from_mins(15),
    )
    .expect("sts");
    Arc::new(AppState {
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
        egress: [(
            AUDIENCE.to_owned(),
            ALLOWED.iter().map(|e| e.parse().unwrap()).collect(),
        )]
        .into_iter()
        .collect(),
        rules: std::collections::BTreeMap::new(),
        cas: std::collections::BTreeMap::new(),
        no_credential: std::collections::BTreeSet::new(),
        secrets: std::collections::BTreeMap::new(),
        delegated: std::collections::BTreeMap::new(),
        registries: std::collections::BTreeMap::new(),
        registry_audiences: None,
        policy_egress,
        sandboxes: None,
        namespaces: Namespaces::Single(namespace.into()),
        max_ttl_seconds: mediatore_proto::DEFAULT_MAX_TTL_SECONDS,
        sealer: None,
        limiter: Limiter::new(10),
        dev_mode: true,
        gateways: vec![],
    })
}

/// The broker under the testkit CA, and the authorizer's check listener beside it.
struct Harness {
    idp: FakeIdp,
    user_url: String,
    sandbox_url: String,
    ca: TestCa,
    http: reqwest::Client,
    /// The check listener a stand-in Envoy calls.
    check_url: String,
    /// The broker's store, to give a claim the policy uid a sandbox's record would carry.
    store: Arc<dyn mediatore_store::ClaimStore>,
    /// The broker's machine cache (ADR-0078), to list the members a probe's source is named from.
    machines: Arc<mediatore_claims::machines::MachineCache>,
}

impl Harness {
    /// The broker as `spiffe://sandbox.test/mediatore`; the authorizer as `identity`, with
    /// the cache bounds given, asking `broker_url` (the real listener unless overridden).
    async fn start(identity: &str, cfg: CacheConfig, broker_url: Option<&str>) -> Self {
        Self::start_with(identity, cfg, broker_url, None).await
    }

    /// [`start`](Self::start) with the broker serving direct egress from `policy_egress`
    /// (ADR-0030).
    async fn start_with(
        identity: &str,
        cfg: CacheConfig,
        broker_url: Option<&str>,
        policy_egress: Option<mediatore_api::PolicyEgress>,
    ) -> Self {
        Self::start_in("sandboxes", identity, cfg, broker_url, policy_egress).await
    }

    /// [`start_with`](Self::start_with) with claims created in `namespace`.
    async fn start_in(
        namespace: &str,
        identity: &str,
        cfg: CacheConfig,
        broker_url: Option<&str>,
        policy_egress: Option<mediatore_api::PolicyEgress>,
    ) -> Self {
        mediatore_proto::tls::ensure_provider();
        let ca = TestCa::new(TRUST_DOMAIN);
        let idp = FakeIdp::start().await;
        let st = state_in(&idp, namespace, policy_egress);
        let store = st.store.clone();
        let machines = st.tripwires.machines.clone();

        let user = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind user");
        let user_url = format!("http://{}", user.local_addr().expect("addr"));
        tokio::spawn(axum::serve(user, mediatore_api::user_router(st.clone())).into_future());

        let sandbox = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sandbox");
        let sandbox_url = format!("https://{}", sandbox.local_addr().expect("addr"));
        let broker = MemoryMaterial::new(ca.svid(&broker_id().to_string()));
        let configs = TlsConfigs::spawn(
            broker,
            mediatore_api::sandbox_authorizer(st.naming.clone(), false),
        )
        .expect("tls configs");
        tokio::spawn(mediatore_tls::serve(
            sandbox,
            configs,
            mediatore_api::sandbox_router(st),
            std::future::pending(),
        ));

        // The authorizer, with `identity`'s SVID from the same CA.
        let material = MemoryMaterial::new(ca.svid(identity));
        let source = Broker::with_material(broker_url.unwrap_or(&sandbox_url), material)
            .expect("broker client");
        let authorizer = Arc::new(Authorizer::new(TRUST_DOMAIN, Arc::new(source), cfg));
        let check = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind check");
        let check_url = format!("http://{}", check.local_addr().expect("addr"));
        tokio::spawn(mediatore_gateway::serve::serve(authorizer, check));

        Self {
            idp,
            user_url,
            sandbox_url,
            ca,
            http: reqwest::Client::new(),
            check_url,
            store,
            machines,
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

    /// A client presenting a fresh SVID for `spiffe_id` from this harness's CA.
    fn mtls_as(&self, spiffe_id: &str) -> reqwest::Client {
        let cfg = mediatore_tls::client_config(&self.ca.svid(spiffe_id), &broker_id())
            .expect("client config");
        reqwest::Client::builder()
            .tls_backend_preconfigured(cfg)
            .build()
            .expect("client")
    }

    /// What the guest fetches for the proxy, over the node SVID.
    async fn me(&self) -> mediatore_proto::Me {
        let resp = self
            .mtls_as(&node_svid())
            .get(format!("{}/v1/me", self.sandbox_url))
            .send()
            .await
            .expect("me");
        assert_eq!(resp.status(), 200);
        resp.json().await.expect("me body")
    }

    /// A bound claim: the node registers over mTLS, the user claims, the dev binder binds.
    async fn bound_claim(&self) -> (String, ClaimResponse) {
        let resp = self
            .mtls_as(&node_svid())
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
            .expect("register");
        assert_eq!(resp.status(), 200);
        let token = self.login("octocat");
        let resp = self
            .http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(&token)
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
        let claim: ClaimResponse = resp.json().await.expect("claim body");
        assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Bound);
        (token, claim)
    }

    /// What Envoy sends: its Check call with the peer's principal from the certificate,
    /// the method and the authority. Returns the HTTP status Envoy would answer the
    /// downstream with (`200`, or the denied response's) and the denied body.
    async fn check(&self, peer: &str, method: &str, authority: &str) -> (u16, String) {
        let mut client = AuthorizationClient::connect(self.check_url.clone())
            .await
            .expect("check client");
        let request = CheckRequest {
            attributes: Some(AttributeContext {
                source: Some(Peer {
                    principal: peer.to_owned(),
                    ..Default::default()
                }),
                request: Some(HttpAttributes {
                    http: Some(HttpRequest {
                        method: method.to_owned(),
                        host: authority.to_owned(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let response = client.check(request).await.expect("check").into_inner();
        let status = response.status.clone().unwrap_or_default();
        match response.http_response {
            None => {
                assert_eq!(status.code, 0, "an allow is OK with no HTTP response");
                (200, String::new())
            }
            Some(HttpResponse::OkResponse(_)) => (200, String::new()),
            Some(HttpResponse::DeniedResponse(d)) => {
                assert_ne!(status.code, 0, "a denial is not OK");
                let code = d
                    .status
                    .map_or(403, |s| u16::try_from(s.code).unwrap_or(403));
                (code, d.body.trim().to_owned())
            }
            Some(other) => panic!("not an answer the authorizer gives: {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_claim_reaches_its_allowlist_and_nothing_else_and_a_released_claim_is_cut_off() {
    let h = Harness::start(&authorizer_svid(), CacheConfig::default(), None).await;
    let (token, claim) = h.bound_claim().await;
    let uid = claim.uid.expect("uid");
    let peer = claim_svid(&uid);

    for authority in ALLOWED {
        assert_eq!(
            h.check(&peer, "CONNECT", authority).await,
            (200, String::new()),
            "{authority}"
        );
    }
    for (authority, code) in [
        ("other.home.example:443", "not_allowed"),
        ("api.home.example:8443", "not_allowed"),
        ("api.home.example", "bad_authority"),
    ] {
        assert_eq!(
            h.check(&peer, "CONNECT", authority).await,
            (403, code.into()),
            "{authority}"
        );
    }
    assert_eq!(
        h.check(&peer, "GET", ALLOWED[0]).await,
        (403, "not_connect".into())
    );
    assert_eq!(
        h.check(&node_svid(), "CONNECT", ALLOWED[0]).await,
        (403, "not_a_claim".into()),
        "the node holding the claim is not the claim"
    );
    assert_eq!(
        h.check(&claim_svid(&uuid::Uuid::new_v4()), "CONNECT", ALLOWED[0])
            .await,
        (403, "claim_gone".into()),
        "a claim the broker never saw"
    );
    // A check with no principal: whatever Envoy did not verify is nobody.
    assert_eq!(
        h.check("", "CONNECT", ALLOWED[0]).await,
        (403, "not_a_claim".into())
    );

    // Released: within the fresh bound the cached answer still serves (the ADR's bound on
    // revocation), after it the broker's 404 cuts the claim off.
    let del = h
        .http
        .delete(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status(), 204);
    assert_eq!(
        h.check(&peer, "CONNECT", ALLOWED[0]).await.0,
        200,
        "still fresh: the cache answers"
    );
    let h2 = Harness::start(
        &authorizer_svid(),
        CacheConfig {
            fresh_for: Duration::ZERO,
            ..CacheConfig::default()
        },
        None,
    )
    .await;
    let (token, claim) = h2.bound_claim().await;
    let peer = claim_svid(&claim.uid.expect("uid"));
    assert_eq!(h2.check(&peer, "CONNECT", ALLOWED[0]).await.0, 200);
    let del = h2
        .http
        .delete(format!("{}/v1/claims/{}", h2.user_url, claim.name))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status(), 204);
    assert_eq!(
        h2.check(&peer, "CONNECT", ALLOWED[0]).await,
        (403, "claim_gone".into())
    );
}

#[tokio::test]
async fn a_broker_that_is_down_is_a_deny_and_so_is_a_gateway_the_broker_does_not_know() {
    // Nothing listens there: every ask is an outage, and nothing was ever cached.
    let h = Harness::start(
        &authorizer_svid(),
        CacheConfig::default(),
        Some("https://127.0.0.1:9"),
    )
    .await;
    let (_, claim) = h.bound_claim().await;
    let peer = claim_svid(&claim.uid.expect("uid"));
    assert_eq!(
        h.check(&peer, "CONNECT", ALLOWED[0]).await,
        (403, "broker_unreachable".into())
    );

    // The authorizer presenting a node SVID: the handshake completes, the route refuses it.
    let h = Harness::start(&node_svid(), CacheConfig::default(), None).await;
    let (_, claim) = h.bound_claim().await;
    let peer = claim_svid(&claim.uid.expect("uid"));
    assert_eq!(
        h.check(&peer, "CONNECT", ALLOWED[0]).await,
        (403, "broker_refused".into())
    );

    // The authorizer presenting something under its own path, or under the gateway's: not
    // a peer at all.
    for stranger in [
        format!("{}/1", authorizer_svid()),
        format!("{}/1", gateway_svid()),
    ] {
        let h = Harness::start(&stranger, CacheConfig::default(), None).await;
        let (_, claim) = h.bound_claim().await;
        let peer = claim_svid(&claim.uid.expect("uid"));
        assert_eq!(
            h.check(&peer, "CONNECT", ALLOWED[0]).await,
            (403, "broker_unreachable".into()),
            "{stranger}"
        );
    }
}

/// ADR-0053 decisions 2 and 3: an authorizer that holds the listeners' identity (two
/// entries for its user, a mistaken entry, an image from before the split) gets nothing
/// from the broker, so no tunnel opens through it. `mediatore gateway` itself does not
/// start under that name (`Broker::connect`); this is the broker's side of the same
/// refusal, with a client built past that check. Over mutual TLS the refusal is the
/// handshake's, which the authorizer cannot tell from an outage: nothing was cached, so it
/// denies.
#[tokio::test]
async fn an_authorizer_holding_the_listeners_identity_is_refused_and_denies_every_tunnel() {
    let h = Harness::start(&gateway_svid(), CacheConfig::default(), None).await;
    let (_, claim) = h.bound_claim().await;
    let peer = claim_svid(&claim.uid.expect("uid"));
    for authority in ALLOWED {
        assert_eq!(
            h.check(&peer, "CONNECT", authority).await,
            (403, "broker_unreachable".into()),
            "{authority}"
        );
    }
    // The same broker answers the same question from the authorizer's own identity.
    let authorizer = h.mtls_as(&authorizer_svid());
    let url = format!(
        "{}/v1/gateway/claims/{}",
        h.sandbox_url,
        claim.uid.expect("uid")
    );
    assert_eq!(
        authorizer.get(&url).send().await.expect("ask").status(),
        200
    );
    assert!(
        h.mtls_as(&gateway_svid()).get(&url).send().await.is_err(),
        "the listeners' identity does not complete a handshake"
    );
}

/// ADR-0062 over the real listener: the authorizer's batch of decisions is taken (`204`),
/// the same batch from a claim or a node is `403`, the listeners' identity does not complete
/// a handshake, and a batch whose shape is off is refused whole (`400`), a line break in an
/// authority included.
#[tokio::test]
async fn decisions_are_taken_from_the_authorizer_alone_and_a_bad_batch_is_refused_whole() {
    let h = Harness::start(&authorizer_svid(), CacheConfig::default(), None).await;
    let (_, claim) = h.bound_claim().await;
    let uid = claim.uid.expect("uid");
    let url = format!("{}/v1/gateway/decisions", h.sandbox_url);
    let batch = |authority: &str| {
        serde_json::json!({
            "gateway": "gateway-02",
            "decisions": [
                { "at": "2026-11-22T14:41:58Z", "claim_uid": uid, "kind": "tunnel",
                  "authority": authority, "verdict": "allow", "served": "cache" },
                { "at": "2026-11-22T14:41:59Z", "claim_uid": uid, "kind": "inject",
                  "authority": "api.home.example", "audience": AUDIENCE,
                  "verdict": "deny", "reason": "not_allowed" }
            ]
        })
    };
    let post = |client: reqwest::Client, body: serde_json::Value| {
        let url = url.clone();
        async move { client.post(url).json(&body).send().await }
    };

    let authorizer = h.mtls_as(&authorizer_svid());
    let taken = post(authorizer.clone(), batch(ALLOWED[0]))
        .await
        .expect("report");
    assert_eq!(taken.status(), 204);

    for peer in [claim_svid(&uid), node_svid()] {
        let refused = post(h.mtls_as(&peer), batch(ALLOWED[0]))
            .await
            .expect("report");
        assert_eq!(refused.status(), 403, "{peer}");
    }
    assert!(
        post(h.mtls_as(&gateway_svid()), batch(ALLOWED[0]))
            .await
            .is_err(),
        "the listeners' identity does not complete a handshake"
    );

    let mut too_many = batch(ALLOWED[0]);
    let one = too_many["decisions"][0].clone();
    too_many["decisions"] = serde_json::Value::Array(vec![one; 257]);
    let mut bad_name = batch(ALLOWED[0]);
    bad_name["gateway"] = "Gateway 02".into();
    for (why, body) in [
        (
            "a line break in an authority",
            batch("pypi.org:443\nforged"),
        ),
        ("more than 256 decisions", too_many),
        ("a gateway name outside the grammar", bad_name),
    ] {
        let refused = post(authorizer.clone(), body).await.expect("report");
        assert_eq!(refused.status(), 400, "{why}");
        let body: serde_json::Value = refused.json().await.expect("error body");
        assert_eq!(body["error"], "invalid_decisions", "{why}: {body}");
    }
}

/// The authorizer's own reporter, sending to the real listener and keeping what it sent and
/// what the broker said.
struct Watched {
    broker: Broker,
    sent: std::sync::Mutex<Vec<(mediatore_proto::GatewayDecisions, bool)>>,
}

#[async_trait::async_trait]
impl mediatore_gateway::report::Reports for Watched {
    async fn report(
        &self,
        batch: &mediatore_proto::GatewayDecisions,
    ) -> Result<(), mediatore_gateway::broker::AskError> {
        let said = mediatore_gateway::report::Reports::report(&self.broker, batch).await;
        self.sent
            .lock()
            .expect("lock")
            .push((batch.clone(), said.is_ok()));
        said
    }
}

impl Watched {
    /// The batches sent so far, once `enough` says so.
    async fn wait(
        &self,
        enough: impl Fn(&[(mediatore_proto::GatewayDecisions, bool)]) -> bool,
    ) -> Vec<(mediatore_proto::GatewayDecisions, bool)> {
        for _ in 0..300 {
            let got = self.sent.lock().expect("lock").clone();
            if enough(&got) {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.sent.lock().expect("lock").clone()
    }
}

/// The authorizer's reporter as `mediatore gateway` runs it, with a probes directory: sending
/// to the real listener under the authorizer's SVID, every 20 ms.
fn probes_reporter(
    h: &Harness,
) -> (
    Arc<Watched>,
    mediatore_gateway::report::Reporter,
    std::path::PathBuf,
) {
    let broker = Broker::with_material(
        &h.sandbox_url,
        MemoryMaterial::new(h.ca.svid(&authorizer_svid())),
    )
    .expect("broker client");
    let watched = Arc::new(Watched {
        broker,
        sent: std::sync::Mutex::new(Vec::new()),
    });
    let dir = mediatore_testkit::tempdir();
    let (reporter, _task) = mediatore_gateway::report::Reporter::spawn(
        "gateway-02".into(),
        watched.clone(),
        Duration::from_millis(20),
        Some(mediatore_gateway::probes::Inbox::open(&dir)),
    );
    (watched, reporter, dir)
}

/// When the probes of these tests were read.
fn probed_at() -> jiff::Timestamp {
    "2026-11-27T10:00:00Z".parse().expect("timestamp")
}

fn probe(
    class: mediatore_proto::trip::TripClass,
    count: u64,
) -> mediatore_proto::trip::GatewayProbe {
    mediatore_proto::trip::GatewayProbe {
        at: probed_at(),
        class,
        count,
        port: None,
        source_address: None,
        user: None,
    }
}

/// Leave `probes` where the probes reader would.
fn leave_summary(dir: &std::path::Path, probes: &[mediatore_proto::trip::GatewayProbe]) {
    let summary = mediatore_gateway::probes::Summary {
        at: probed_at(),
        probes: probes.to_vec(),
    };
    mediatore_gateway::probes::write_summary(dir, &summary).expect("summary");
}

/// A deny the authorizer would report for `uid`.
fn denied(uid: uuid::Uuid) -> mediatore_proto::GatewayDecision {
    mediatore_proto::GatewayDecision {
        at: probed_at(),
        claim_uid: uid,
        kind: mediatore_proto::DecisionKind::Tunnel,
        authority: "elsewhere.example:443".into(),
        audience: None,
        verdict: mediatore_proto::DecisionVerdict::Deny,
        reason: Some("not_allowed".into()),
        served: Some("cache".into()),
    }
}

/// ADR-0070 decisions 4 and 8, the gateway's half over the real listener: the summary the
/// probes reader leaves is carried by the authorizer's next batch of decisions, once, under
/// the authorizer's own SVID, and the broker takes it (`204`). A batch of probes alone is
/// taken too. What the broker then does with a probe (one `warn` line each) is its own test,
/// in `mediatore-api`.
#[tokio::test]
async fn a_gateways_probes_reach_the_broker_in_its_batch() {
    use mediatore_proto::trip::{GatewayProbe, TripClass};

    let h = Harness::start(&authorizer_svid(), CacheConfig::default(), None).await;
    let (_, claim) = h.bound_claim().await;
    let uid = claim.uid.expect("uid");
    let (watched, reporter, dir) = probes_reporter(&h);
    let probes = vec![
        GatewayProbe {
            user: Some("envoy-relay".into()),
            ..probe(TripClass::GatewayOutput, 1)
        },
        GatewayProbe {
            port: Some(2375),
            source_address: Some("198.51.100.9".into()),
            ..probe(TripClass::GatewayPort, 2)
        },
        probe(TripClass::GatewayPort, 7),
    ];

    // A summary and a decision: one batch carries both, and the broker takes it.
    leave_summary(&dir, &probes);
    reporter.note(denied(uid));
    let got = watched
        .wait(|sent| sent.iter().any(|(b, _)| !b.probes.is_empty()))
        .await;
    let with: Vec<_> = got.iter().filter(|(b, _)| !b.probes.is_empty()).collect();
    assert_eq!(with.len(), 1, "one batch carries the summary");
    assert!(with[0].1, "the broker took the batch");
    assert_eq!(with[0].0.probes, probes);
    assert_eq!(
        serde_json::to_value(&with[0].0).expect("json")["probes"],
        serde_json::json!([
            { "at": "2026-11-27T10:00:00Z", "class": "gateway_output", "count": 1, "user": "envoy-relay" },
            { "at": "2026-11-27T10:00:00Z", "class": "gateway_port", "count": 2, "port": 2375,
              "source_address": "198.51.100.9" },
            { "at": "2026-11-27T10:00:00Z", "class": "gateway_port", "count": 7 }
        ]),
        "the probes on the wire"
    );
    // The same body by hand: the status is 204, as for decisions alone; and from anyone but
    // the authorizer it is refused, as decisions are.
    let url = format!("{}/v1/gateway/decisions", h.sandbox_url);
    let post = |peer: String| {
        let request = h.mtls_as(&peer).post(&url).json(&with[0].0);
        async move { request.send().await.expect("report").status() }
    };
    assert_eq!(post(authorizer_svid()).await, 204);
    for peer in [claim_svid(&uid), node_svid()] {
        assert_eq!(post(peer).await, 403, "a peer that is not the authorizer");
    }

    // Reported once: later batches carry no probe, with the file still in place.
    let before = got.len();
    reporter.note(denied(uid));
    let got = watched.wait(|sent| sent.len() > before).await;
    assert!(got.len() > before, "a later batch was sent");
    assert_eq!(
        got.iter().map(|(b, _)| b.probes.len()).sum::<usize>(),
        probes.len()
    );

    // Probes alone are still a batch, and still taken.
    let before = got.len();
    leave_summary(&dir, &probes[..1]);
    let got = watched.wait(|sent| sent.len() > before).await;
    assert_eq!(got.len(), before + 1);
    let (alone, took) = &got[before];
    assert!(alone.decisions.is_empty() && alone.probes.len() == 1 && *took);
}

/// The broker refuses a batch whole when one probe in it is off (`400`), so the authorizer
/// drops a summary that would fail that check before it can cost the decisions beside it: the
/// decision is still reported and taken, and nothing of the summary is.
#[tokio::test]
async fn a_summary_the_broker_would_refuse_costs_the_decisions_nothing() {
    use mediatore_proto::trip::{MAX_GATEWAY_PROBES, TripClass};

    let h = Harness::start(&authorizer_svid(), CacheConfig::default(), None).await;
    let (_, claim) = h.bound_claim().await;
    let uid = claim.uid.expect("uid");
    let (watched, reporter, dir) = probes_reporter(&h);

    // A class no gateway decides.
    leave_summary(&dir, &[probe(TripClass::PoolInbound, 1)]);
    reporter.note(denied(uid));
    let got = watched.wait(|sent| !sent.is_empty()).await;
    assert_eq!(got.len(), 1);
    let (kept, took) = &got[0];
    assert!(kept.decisions.len() == 1 && kept.probes.is_empty() && *took);

    // What the gateway's own check spared that batch: sent as it was, the broker refuses it.
    let mut off_class = serde_json::to_value(kept).expect("json");
    off_class["probes"] =
        serde_json::json!([{ "at": "2026-11-27T10:00:00Z", "class": "pool_inbound", "count": 1 }]);
    let mut too_many = serde_json::to_value(kept).expect("json");
    too_many["probes"] = serde_json::Value::Array(vec![
        serde_json::json!({ "at": "2026-11-27T10:00:00Z", "class": "gateway_port", "count": 1 });
        MAX_GATEWAY_PROBES + 1
    ]);
    let authorizer = h.mtls_as(&authorizer_svid());
    let url = format!("{}/v1/gateway/decisions", h.sandbox_url);
    for (why, body) in [
        ("a class no gateway decides", off_class),
        ("more than 64 probes", too_many),
    ] {
        let refused = authorizer
            .post(&url)
            .json(&body)
            .send()
            .await
            .expect("report");
        assert_eq!(refused.status(), 400, "{why}");
        let body: serde_json::Value = refused.json().await.expect("error body");
        assert_eq!(body["error"], "invalid_decisions", "{why}");
    }
}

/// The dev transport: the gateway identity as a header against a loopback `dev_mode`
/// broker, which is what the dev loop runs.
#[cfg(feature = "dev")]
#[tokio::test]
async fn the_dev_header_transport_reaches_a_dev_mode_broker() {
    mediatore_proto::tls::ensure_provider();
    let idp = FakeIdp::start().await;
    let st = state(&idp, None);
    let user = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let user_url = format!("http://{}", user.local_addr().unwrap());
    tokio::spawn(axum::serve(user, mediatore_api::user_router(st.clone())).into_future());
    let sandbox = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sandbox_url = format!("http://{}", sandbox.local_addr().unwrap());
    tokio::spawn(axum::serve(sandbox, mediatore_api::sandbox_router(st)).into_future());

    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{sandbox_url}/v1/nodes"))
        .header("x-mediatore-peer-spiffe-id", node_svid())
        .json(&NodeRegistration {
            ek_hash: EK_HASH.into(),
            attestation: None,
            dmi_uuid: uuid::Uuid::new_v4(),
            hostname: "pool-a-7".into(),
            provider: Some(mediatore_proto::Provider::Libvirt),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let token = idp.token(serde_json::json!({
        "aud": "mediatore",
        "preferred_username": "octocat",
        "email": "octocat@example.com",
        "groups": [REQUIRED_GROUP],
    }));
    let claim: ClaimResponse = http
        .post(format!("{user_url}/v1/claims"))
        .bearer_auth(&token)
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
        .unwrap()
        .json()
        .await
        .unwrap();
    let peer = claim_svid(&claim.uid.unwrap());

    let source = Broker::dev_header(&sandbox_url, &authorizer_svid());
    let authorizer = Authorizer::new(TRUST_DOMAIN, Arc::new(source), CacheConfig::default());
    let d = authorizer.authorize(&peer, "CONNECT", ALLOWED[0]).await;
    assert_eq!(d.verdict, Ok(()));
    let d = authorizer
        .authorize(&peer, "CONNECT", "other.home.example:443")
        .await;
    assert_eq!(d.verdict, Err(mediatore_gateway::Refusal::NotAllowed));
    // The route's own check, which is what holds where there is no handshake to refuse a
    // peer (ADR-0053 decision 3): a node, and the gateways' listener identity, are answered
    // 403 and the authorizer denies, cached or not.
    for other in [node_svid(), gateway_svid()] {
        let source = Broker::dev_header(&sandbox_url, &other);
        let authorizer = Authorizer::new(TRUST_DOMAIN, Arc::new(source), CacheConfig::default());
        let d = authorizer.authorize(&peer, "CONNECT", ALLOWED[0]).await;
        assert_eq!(
            d.verdict,
            Err(mediatore_gateway::Refusal::BrokerRefused),
            "{other}"
        );
    }
}

/// A reflector that admitted a bundle for the conformance policy whose direct `egress[]` is
/// `entries` (host:port, and whether the entry carries a rule), and the cache it filled.
async fn cache_with_direct_egress(
    entries: &[(&str, bool)],
    now: jiff::Timestamp,
) -> (Arc<mediatore_claims::policy::BundleCache>, String) {
    cache_with_direct_egress_in(None, entries, now).await
}

/// The namespace the testkit's conformance policy is signed for.
const POLICY_NS: &str = "conformance";

/// The mapping under which `sandbox_namespace` draws its policies from `policy_namespace`
/// (`policy.sources`, ADR-0054 decision 2).
fn drawing(
    sandbox_namespace: &str,
    policy_namespace: &str,
) -> mediatore_claims::policy::PolicySources {
    mediatore_claims::policy::PolicySources::new(std::collections::BTreeMap::from([(
        sandbox_namespace.to_owned(),
        vec![policy_namespace.to_owned()],
    )]))
}

/// [`cache_with_direct_egress`] with the policy signed for `namespace` instead of the
/// conformance one when given: the same name, a policy of that namespace's own.
async fn cache_with_direct_egress_in(
    namespace: Option<&str>,
    entries: &[(&str, bool)],
    now: jiff::Timestamp,
) -> (Arc<mediatore_claims::policy::BundleCache>, String) {
    let base = mediatore_testkit::policy::fresh_bundle(now, 1).payload;
    let mut content = base.content.clone();
    if let Some(namespace) = namespace {
        content.policy.namespace = namespace.to_owned();
        content.policy.uid = uuid::Uuid::new_v4().to_string();
    }
    content.egress = entries
        .iter()
        .map(|(endpoint, with_rules)| {
            mediatore_policy::types::EgressRule {
                endpoint: (*endpoint).into(),
                rules: if *with_rules {
                    vec![mediatore_policy::types::EndpointRule {
                        method: "GET".into(),
                        path: "/**".into(),
                    }]
                } else {
                    vec![]
                },
            }
            .into()
        })
        .collect();
    let signed = mediatore_testkit::policy::signed_bundle(now, 2, content);
    let uid = signed.payload.content.policy.uid.clone();
    let namespace = signed.payload.content.policy.namespace.clone();
    let reflector = mediatore_claims::policy::BundleReflector::new(
        MemoryStore::shared(),
        signed.keys,
        vec![namespace.clone()],
    );
    let cm =
        mediatore_testkit::policy::bundle_configmap(&namespace, "agent-bundle", &signed.envelope);
    let outcome = reflector.applied_at(&cm, now).await;
    assert!(
        matches!(outcome, mediatore_claims::policy::Outcome::Admitted { .. }),
        "{outcome:?}"
    );
    // The namespace's first list completed: a name asked of it is answered.
    reflector.resynced(
        &namespace,
        &std::collections::HashSet::from(["agent-bundle".to_owned()]),
    );
    (reflector.cache(), uid)
}

/// Give the claim the policy uid its record would carry under a sandbox naming a policy.
async fn name_policy(h: &Harness, uid: &uuid::Uuid, policy_uid: &str) {
    let mut rec = h.store.get_claim(*uid).await.expect("record");
    rec.policy_uid = Some(policy_uid.to_owned());
    h.store.update_claim(rec).await.expect("update");
}

const DIRECT: &str = "repo.home.example:443";

#[tokio::test]
async fn enforcing_serves_a_policys_direct_egress_and_shadow_serves_none_of_it() {
    for (mode, reaches) in [
        (mediatore_claims::policy::EgressMode::Enforce, true),
        (mediatore_claims::policy::EgressMode::Shadow, false),
    ] {
        let (bundles, policy_uid) = cache_with_direct_egress(
            &[
                (DIRECT, false),
                ("only-some.home.example:443", true),
                ("192.0.2.77:443", false),
                ("*.home.example:443", false),
                // An audience's own endpoint named again as direct egress.
                (ALLOWED[0], false),
            ],
            jiff::Timestamp::now(),
        )
        .await;
        let h = Harness::start_with(
            &authorizer_svid(),
            CacheConfig::default(),
            None,
            // The claims live in `sandboxes` and the policy in its own namespace: the
            // operator's `policy.sources` entry says the one draws from the other (ADR-0054).
            Some(mediatore_api::PolicyEgress {
                eligibility: mediatore_claims::eligibility::EligibilityMode::Off,
                follow: mediatore_claims::policy::EgressMode::Shadow,
                bundles,
                mode,
                sources: drawing("sandboxes", POLICY_NS),
                audiences: mediatore_claims::policy::EgressMode::Shadow,
            }),
        )
        .await;
        let (_, claim) = h.bound_claim().await;
        let uid = claim.uid.expect("uid");
        name_policy(&h, &uid, &policy_uid).await;
        let peer = claim_svid(&uid);

        let direct = h.check(&peer, "CONNECT", DIRECT).await;
        if reaches {
            assert_eq!(direct, (200, String::new()), "{mode:?}");
        } else {
            assert_eq!(direct, (403, "not_allowed".into()), "{mode:?}");
        }
        // Whatever the mode, the audience endpoints stand, and what the gateway cannot
        // enforce exactly (a rule, an IP literal, a wildcard) is never served.
        assert_eq!(
            h.check(&peer, "CONNECT", ALLOWED[0]).await,
            (200, String::new())
        );
        for refused in [
            "only-some.home.example:443",
            "192.0.2.77:443",
            "x.home.example:443",
        ] {
            assert_eq!(
                h.check(&peer, "CONNECT", refused).await,
                (403, "not_allowed".into()),
                "{refused} in {mode:?}"
            );
        }

        // The proxy's side (ADR-0025 decision 8): under enforce the served entry has a
        // route with no audience and no credential; under shadow it has none. The audience
        // routes are the same either way, and an endpoint that is both stays the
        // audience's, with its token.
        let me = h.me().await;
        let direct_routes: Vec<_> = me
            .routes
            .iter()
            .filter(|r| r.endpoint.to_string() == DIRECT)
            .collect();
        if reaches {
            assert_eq!(direct_routes.len(), 1, "{mode:?}: {:?}", me.routes);
            let r = direct_routes[0];
            assert_eq!(r.audience, None);
            assert_eq!(r.credential, mediatore_proto::Credential::None);
            assert!(r.rules.is_empty() && r.ca_pem.is_none());
            assert!(me.egress.contains(&DIRECT.parse().unwrap()));
        } else {
            assert!(direct_routes.is_empty(), "{mode:?}: {:?}", me.routes);
            assert!(!me.egress.contains(&DIRECT.parse().unwrap()));
        }
        let audience_routes: Vec<_> = me
            .routes
            .iter()
            .filter(|r| r.audience.as_deref() == Some(AUDIENCE))
            .collect();
        assert_eq!(
            audience_routes.len(),
            ALLOWED.len(),
            "{mode:?}: {:?}",
            me.routes
        );
        assert!(audience_routes.iter().all(|r| r.injects()));
        assert_eq!(
            me.routes
                .iter()
                .filter(|r| r.endpoint.to_string() == ALLOWED[0])
                .count(),
            1,
            "{mode:?}: one route per endpoint, the audience's"
        );
        for never in ["only-some.home.example:443", "192.0.2.77:443"] {
            assert!(
                !me.routes.iter().any(|r| r.endpoint.to_string() == never),
                "{mode:?}: {never} is not served, so it has no route"
            );
        }
    }
}

#[tokio::test]
async fn a_claim_with_no_policy_or_a_bundle_the_cache_does_not_hold_gets_the_audience_endpoints_only()
 {
    // Each case is its own broker and gateway: the authorizer's cache would otherwise
    // answer the second ask of a claim from the first.
    for named in [None, Some("a-policy-uid-nobody-published")] {
        let (bundles, _published) =
            cache_with_direct_egress(&[(DIRECT, false)], jiff::Timestamp::now()).await;
        let h = Harness::start_with(
            &authorizer_svid(),
            CacheConfig::default(),
            None,
            Some(mediatore_api::PolicyEgress {
                eligibility: mediatore_claims::eligibility::EligibilityMode::Off,
                follow: mediatore_claims::policy::EgressMode::Shadow,
                bundles,
                mode: mediatore_claims::policy::EgressMode::Enforce,
                sources: drawing("sandboxes", POLICY_NS),
                audiences: mediatore_claims::policy::EgressMode::Shadow,
            }),
        )
        .await;
        let (_, claim) = h.bound_claim().await;
        let uid = claim.uid.expect("uid");
        // None names no policy (P010); the other names one no verified bundle holds, as a
        // stale, tampered or never-read bundle leaves it.
        if let Some(policy_uid) = named {
            name_policy(&h, &uid, policy_uid).await;
        }
        let peer = claim_svid(&uid);
        assert_eq!(
            h.check(&peer, "CONNECT", DIRECT).await,
            (403, "not_allowed".into()),
            "{named:?}"
        );
        assert_eq!(
            h.check(&peer, "CONNECT", ALLOWED[0]).await,
            (200, String::new()),
            "{named:?}"
        );
    }
}

// ----- ADR-0054: which policies a namespace may name -----

/// A broker under `enforce` whose claims are created in `team-a` and whose one bundle is a
/// policy of `team-b` holding [`DIRECT`], with `sources`; a bound claim of it carrying that
/// policy's uid, as a record written through the fallback of ADR-0026 does.
async fn team_a_under_a_policy_of_team_b(
    sources: mediatore_claims::policy::PolicySources,
) -> (Harness, uuid::Uuid) {
    let (bundles, policy_uid) =
        cache_with_direct_egress_in(Some("team-b"), &[(DIRECT, false)], jiff::Timestamp::now())
            .await;
    let h = Harness::start_in(
        "team-a",
        &authorizer_svid(),
        CacheConfig::default(),
        None,
        Some(mediatore_api::PolicyEgress {
            eligibility: mediatore_claims::eligibility::EligibilityMode::Off,
            follow: mediatore_claims::policy::EgressMode::Shadow,
            bundles,
            mode: mediatore_claims::policy::EgressMode::Enforce,
            sources,
            audiences: mediatore_claims::policy::EgressMode::Shadow,
        }),
    )
    .await;
    let (_, claim) = h.bound_claim().await;
    let uid = claim.uid.expect("uid");
    let rec = h.store.get_claim(uid).await.expect("record");
    assert_eq!(rec.namespace, "team-a", "the record carries its namespace");
    name_policy(&h, &uid, &policy_uid).await;
    (h, uid)
}

#[tokio::test]
async fn a_claim_in_team_a_gets_nothing_from_a_policy_of_team_b() {
    let (h, uid) =
        team_a_under_a_policy_of_team_b(mediatore_claims::policy::PolicySources::default()).await;
    let peer = claim_svid(&uid);
    // The gateway's answer: the policy's host stays closed, the audience's stay open.
    assert_eq!(
        h.check(&peer, "CONNECT", DIRECT).await,
        (403, "not_allowed".into())
    );
    assert_eq!(
        h.check(&peer, "CONNECT", ALLOWED[0]).await,
        (200, String::new())
    );
    // The guest's side: no route and no egress entry for it either.
    let me = h.me().await;
    assert!(
        !me.egress.contains(&DIRECT.parse().unwrap()),
        "nothing of team-b's policy in the guest's ruleset"
    );
    assert!(
        !me.routes.iter().any(|r| r.endpoint.to_string() == DIRECT),
        "and no route for it"
    );
    assert_eq!(
        me.routes
            .iter()
            .filter(|r| r.audience.as_deref() == Some(AUDIENCE))
            .count(),
        ALLOWED.len(),
        "the audience routes stand"
    );
}

#[tokio::test]
async fn a_mapped_policy_namespace_serves_its_direct_egress_under_enforce() {
    let (h, uid) = team_a_under_a_policy_of_team_b(drawing("team-a", "team-b")).await;
    let peer = claim_svid(&uid);
    assert_eq!(
        h.check(&peer, "CONNECT", DIRECT).await,
        (200, String::new())
    );
    let me = h.me().await;
    assert!(me.egress.contains(&DIRECT.parse().unwrap()));
    assert_eq!(
        me.routes
            .iter()
            .filter(|r| r.endpoint.to_string() == DIRECT)
            .count(),
        1
    );
    // An entry for another namespace gives team-a nothing.
    let (h, uid) = team_a_under_a_policy_of_team_b(drawing("infra", "team-b")).await;
    assert_eq!(
        h.check(&claim_svid(&uid), "CONNECT", DIRECT).await,
        (403, "not_allowed".into())
    );
}

#[tokio::test]
async fn under_enforce_a_claim_naming_a_policy_outside_its_sources_is_400_and_parks_nothing() {
    // Over real HTTP: the conformance policy is verified and read, in a namespace the
    // claim's own (`sandboxes`) does not draw from.
    let (bundles, _) = cache_with_direct_egress(&[(DIRECT, false)], jiff::Timestamp::now()).await;
    let h = Harness::start_with(
        &authorizer_svid(),
        CacheConfig::default(),
        None,
        Some(mediatore_api::PolicyEgress {
            eligibility: mediatore_claims::eligibility::EligibilityMode::Off,
            follow: mediatore_claims::policy::EgressMode::Shadow,
            bundles,
            mode: mediatore_claims::policy::EgressMode::Enforce,
            sources: mediatore_claims::policy::PolicySources::default(),
            audiences: mediatore_claims::policy::EgressMode::Shadow,
        }),
    )
    .await;
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(h.login("octocat"))
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
            policy_ref: Some("agent".into()),
            delegations: vec![],
        })
        .send()
        .await
        .expect("create claim");
    assert_eq!(resp.status(), 400);
    let text = resp.text().await.expect("body");
    let body: serde_json::Value = serde_json::from_str(&text).expect("an error body");
    assert_eq!(body["error"], "policy_not_resolved");
    assert_eq!(
        body["detail"],
        "no verified bundle for policy agent in the namespaces sandboxes draws its policies from"
    );
    // The 400 names no other namespace.
    assert!(
        !text.contains(POLICY_NS),
        "the answer does not say where the policy is held"
    );
    assert!(
        h.store.list_claims().await.expect("list").is_empty(),
        "nothing was written for the refused request"
    );
}

// ---------- ADR-0070 at the broker: what it does with a probe, and with a handshake ----------

/// ADR-0070 decisions 5, 8 and 9, the broker's half over the real listener: each probe of a
/// batch the authorizer's reporter sent is one `warn` line with the class, the gateway, the
/// count, the port, and the source or the user, and with nothing else; no claim is touched.
#[tokio::test]
async fn the_broker_writes_one_line_a_probe_naming_only_what_a_probe_is() {
    use crate::e2e_dev::logs;
    use mediatore_proto::trip::{GatewayProbe, TripClass};

    logs::capture();
    let h = Harness::start(&authorizer_svid(), CacheConfig::default(), None).await;
    let (user, claim) = h.bound_claim().await;
    let (watched, _reporter, dir) = probes_reporter(&h);
    let probes = vec![
        GatewayProbe {
            port: Some(2375),
            source_address: Some("198.51.100.9".into()),
            ..probe(TripClass::GatewayPort, 2)
        },
        GatewayProbe {
            user: Some("envoy-relay".into()),
            ..probe(TripClass::GatewayOutput, 1)
        },
        // The remainder of a full set, and a chain with no user: a class and a count.
        probe(TripClass::GatewayPort, 7),
        probe(TripClass::GatewayOutput, 3),
    ];
    leave_summary(&dir, &probes);
    let got = watched
        .wait(|sent| sent.iter().any(|(b, _)| !b.probes.is_empty()))
        .await;
    assert!(got.iter().any(|(b, took)| !b.probes.is_empty() && *took));

    let lines = logs::captured();
    let written: Vec<&str> = lines
        .lines()
        .filter(|l| l.contains("gateway probe"))
        .collect();
    assert_eq!(written.len(), probes.len(), "one line a probe");
    for (line, want) in written.iter().zip([
        vec![
            "class=\"gateway_port\"",
            "count=2",
            "port=2375",
            "source_address=\"198.51.100.9\"",
            "user=\"\"",
        ],
        vec![
            "class=\"gateway_output\"",
            "count=1",
            "user=\"envoy-relay\"",
            "source_address=\"\"",
        ],
        vec!["class=\"gateway_port\"", "count=7", "source_address=\"\""],
        vec!["class=\"gateway_output\"", "count=3", "user=\"\""],
    ]) {
        assert!(line.contains(" WARN "), "a probe is said at warn");
        for part in want
            .into_iter()
            .chain(["kind=\"segment\"", "gateway=gateway-02"])
        {
            assert!(line.contains(part), "{part} in a probe's line");
        }
        // The fields of the line are these and no other: nothing else a peer chose has a
        // place in it.
        let fields = line.split("gateway probe").nth(1).expect("the fields");
        let mut keys: Vec<&str> = fields
            .split_whitespace()
            .filter_map(|pair| pair.split_once('=').map(|(key, _)| key))
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "at",
                "attribution",
                "class",
                "count",
                "gateway",
                "kind",
                "port",
                "source_address",
                "source_claim_uid",
                "source_host",
                "source_namespace",
                "source_node",
                "source_vm",
                "user"
            ]
        );
    }

    // A probe is on no claim: the owner reads no trip and no summary, and the claim lives.
    let held: ClaimResponse = h
        .http
        .get(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&user)
        .send()
        .await
        .expect("get claim")
        .json()
        .await
        .expect("claim body");
    assert!(held.tripped.is_none() && held.tripwires.is_none());
    assert_eq!(held.phase, mediatore_proto::ClaimPhase::Bound);
}

/// ADR-0078 over the real listener: a probe whose source address one live member holds names
/// that member, its node and its bound claim on its line; the claim is not touched.
#[tokio::test]
async fn a_probes_source_is_named_from_the_machine_cache_and_its_claim_is_untouched() {
    use crate::e2e_dev::{bound_vm_claim, logs, member_vm};
    use mediatore_proto::trip::{GatewayProbe, TripClass};

    logs::capture();
    let h = Harness::start(&authorizer_svid(), CacheConfig::default(), None).await;
    let (user, claim) = h.bound_claim().await;
    let uid = claim.uid.expect("uid");
    h.machines
        .replace_machines(&[member_vm("member-1", "198.51.100.9")]);
    h.machines
        .replace_claims(&[bound_vm_claim("member-1", uid)]);
    let (watched, _reporter, dir) = probes_reporter(&h);
    leave_summary(
        &dir,
        &[
            GatewayProbe {
                port: Some(2375),
                source_address: Some("198.51.100.9".into()),
                ..probe(TripClass::GatewayPort, 2)
            },
            GatewayProbe {
                port: Some(2376),
                source_address: Some("198.51.100.10".into()),
                ..probe(TripClass::GatewayPort, 1)
            },
        ],
    );
    let got = watched
        .wait(|sent| sent.iter().any(|(b, _)| !b.probes.is_empty()))
        .await;
    assert!(got.iter().any(|(b, took)| !b.probes.is_empty() && *took));
    let lines = logs::captured();
    let written: Vec<&str> = lines
        .lines()
        .filter(|l| l.contains("gateway probe"))
        .collect();
    assert_eq!(written.len(), 2, "one line a probe");
    for want in [
        "attribution=\"member\"".to_owned(),
        "source_vm=member-1".to_owned(),
        "source_namespace=sandboxes".to_owned(),
        format!("source_node=spiffe://{TRUST_DOMAIN}/spire/agent/tpm/{EK_HASH}"),
        format!("source_claim_uid={uid}"),
    ] {
        assert!(written[0].contains(&want), "{want} in {}", written[0]);
    }
    assert!(
        written[1].contains("attribution=\"unattributed\""),
        "{}",
        written[1]
    );
    let held: ClaimResponse = h
        .http
        .get(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&user)
        .send()
        .await
        .expect("get claim")
        .json()
        .await
        .expect("claim body");
    assert!(held.tripped.is_none() && held.tripwires.is_none());
    assert_eq!(held.phase, mediatore_proto::ClaimPhase::Bound);
}

/// ADR-0070 decision 9 for the probes: a probe with a field of its own, or a value outside its
/// grammar, is refused with the whole batch, and none of it reaches a line of the broker.
#[tokio::test]
async fn a_probe_that_is_off_is_refused_with_its_batch_and_none_of_it_is_logged() {
    use crate::e2e_dev::logs;
    use mediatore_proto::trip::{GatewayProbe, TripClass};

    let h = Harness::start(&authorizer_svid(), CacheConfig::default(), None).await;
    let probes = vec![
        GatewayProbe {
            port: Some(2375),
            source_address: Some("198.51.100.9".into()),
            ..probe(TripClass::GatewayPort, 2)
        },
        GatewayProbe {
            user: Some("envoy-relay".into()),
            ..probe(TripClass::GatewayOutput, 1)
        },
    ];
    let url = format!("{}/v1/gateway/decisions", h.sandbox_url);
    let good = serde_json::to_value(mediatore_proto::GatewayDecisions {
        gateway: "gateway-02".into(),
        decisions: vec![],
        probes: probes.clone(),
    })
    .expect("json");
    let mut with_a_path = good.clone();
    with_a_path["probes"][0]["path"] = "/canary-path-0c4e".into();
    let mut odd_user = good.clone();
    odd_user["probes"][1]["user"] = "canary user/0c4e".into();
    let mut odd_source = good.clone();
    odd_source["probes"][0]["source_address"] = "canary-host-0c4e.example".into();
    let mut odd_gateway = good.clone();
    odd_gateway["gateway"] = "Canary Gateway 0c4e".into();
    logs::capture();
    for body in [with_a_path, odd_user, odd_source, odd_gateway] {
        let resp = h
            .mtls_as(&authorizer_svid())
            .post(&url)
            .header("x-canary", "canary-header-0c4e")
            .json(&body)
            .send()
            .await
            .expect("report");
        assert!(resp.status().is_client_error());
    }
    let lines = logs::captured();
    assert!(!lines.contains("gateway probe"), "refused whole");
    assert!(
        !lines
            .lines()
            .filter(|l| !l.contains(" reqwest::") && !l.contains(" hyper_util::client::"))
            .any(|l| l.to_ascii_lowercase().contains("0c4e")),
        "nothing of a refused batch is in a line of the broker"
    );
    // The good batch is taken, so the refusals above were of what was off and nothing else.
    let resp = h
        .mtls_as(&authorizer_svid())
        .post(&url)
        .json(&good)
        .send()
        .await
        .expect("report");
    assert_eq!(resp.status(), 204);
    assert!(logs::captured().contains("gateway probe"));
}

/// ADR-0070 decision 3, `identity_shape`, over a real handshake: a valid SVID of the trust
/// domain that is none of the admitted shapes is refused as before and counted; one a
/// foreign authority signed never reaches the count; an admitted identity is not counted.
#[tokio::test]
async fn a_handshake_under_an_identity_of_no_admitted_shape_is_refused_and_counted() {
    use crate::e2e_dev::logs;
    use mediatore_proto::trip::TripClass;

    logs::capture();
    mediatore_proto::tls::ensure_provider();
    let ca = TestCa::new(TRUST_DOMAIN);
    let idp = FakeIdp::start().await;
    let st = state(&idp, None);
    let sandbox = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind sandbox");
    let url = format!("https://{}/healthz", sandbox.local_addr().expect("addr"));
    let configs = TlsConfigs::spawn(
        MemoryMaterial::new(ca.svid(&broker_id().to_string())),
        mediatore_api::sandbox_authorizer_classified(
            st.naming.clone(),
            false,
            st.tripwires.fold.clone(),
        ),
    )
    .expect("tls configs");
    tokio::spawn(mediatore_tls::serve(
        sandbox,
        configs,
        mediatore_api::sandbox_router(st.clone()),
        std::future::pending(),
    ));
    let ask = |material: mediatore_tls::Material| {
        let cfg = mediatore_tls::client_config(&material, &broker_id()).expect("client config");
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(cfg)
            .build()
            .expect("client");
        let url = url.clone();
        async move { client.get(url).send().await.map(|r| r.status().as_u16()) }
    };

    assert_eq!(ask(ca.svid(&authorizer_svid())).await.ok(), Some(200));
    assert_eq!(ask(ca.svid(&node_svid())).await.ok(), Some(200));
    let other_broker = format!("spiffe://{TRUST_DOMAIN}/mediatore-two");
    let strangers = [gateway_svid(), other_broker];
    for stranger in &strangers {
        assert!(
            ask(ca.svid(stranger)).await.is_err(),
            "refused at the handshake, as before"
        );
    }
    // The same name from another authority: the chain does not verify, so it is no
    // identity of this trust domain and no class.
    let forged = TestCa::new(TRUST_DOMAIN).svid(&format!("spiffe://{TRUST_DOMAIN}/forged"));
    let trusted_broker = mediatore_tls::Material {
        roots: ca.svid(&authorizer_svid()).roots,
        ..forged
    };
    assert!(ask(trusted_broker).await.is_err());

    mediatore_api::flush_classified(&st).await;
    let lines = logs::captured();
    let counted: Vec<&str> = lines
        .lines()
        .filter(|l| l.contains("a refusal no honest build earns"))
        .collect();
    assert_eq!(counted.len(), strangers.len(), "one line an identity");
    for stranger in &strangers {
        let line = counted
            .iter()
            .find(|l| l.contains(&format!("peer={stranger} ")))
            .expect("a line for the identity");
        for part in [
            format!("class=\"{}\"", TripClass::IdentityShape.as_str()),
            "scope=\"none\"".to_owned(),
            "action=\"report\"".to_owned(),
            "route=\"(handshake)\"".to_owned(),
        ] {
            assert!(line.contains(&part), "{part} in the line");
        }
    }
    assert!(!lines.contains("/forged"));
}
