// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The forwarder front to back (ADR-0028 decisions 3 and 7, ADR-0027 decision 8): the
//! egress proxy of ADR-0025 in an environment with gateways, driven as the jailed workload
//! drives it, reaching its upstream through a stand-in gateway as the claim. The broker is
//! the dev-mode one (the token source a client of the header path, as in `e2e_egress.rs`);
//! the gateways list travels on `GET /v1/me`; the sandbox leg is real: mutual TLS 1.3 on
//! the production configuration, the claim SVID from the testkit's CA presented to a
//! `mediatore_testkit::StandInGateway` holding `spiffe://<td>/gateway` from the same CA,
//! `CONNECT host:port` inside, the upstream's TLS inside that (a `TlsUpstream` on the
//! audience's own CA, which records what reached it).
//!
//! What is proven: the tunnel carries the workload's request and the STS token end to end,
//! keyed at the gateway by the claim's SPIFFE ID; a gateway that is down and one presenting
//! the wrong identity are skipped and the next carries it; a gateway's refusal is `502`
//! with `gateway_refused` and nothing reaches the upstream; no gateway reachable is `502`
//! with `gateway_unreachable`; a forwarder holding a node SVID gets no tunnel.

use std::future::IntoFuture;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::any;
use mediatore_api::{AppState, Limiter, Namespaces};
use mediatore_entra::{Backend, IssuerConfig, Validator};
use mediatore_guest::egress::{Phantom, Proxy, Routes, TokenSource};
use mediatore_guest::forward::{Dialer, Forwarder};
use mediatore_proto::{
    ClaimRequest, ClaimResponse, Endpoint, Me, NodeRegistration, TokenRequest, TokenResponse,
    Workload,
};
use mediatore_spire::Naming;
use mediatore_store::MemoryStore;
use mediatore_sts::Sts;
use mediatore_testkit::{FakeIdp, MemoryMaterial, StandInGateway, TestCa, TlsUpstream};

/// Throwaway P-256 key for the e2e STS. Test material only; never reuse.
const STS_TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnjPFPJtOewKuQZS0
WTXasKCqUusD6hs+6AaBUWw5lOyhRANCAAQy0awwI1IJ/BKoy/Zj4KtfYOiJOaX2
bVIP4yKaVz1Zp2QNVZJ0t2NIXK0K55dfgdM/B4JF09EKDd/q/nHoAfis
-----END PRIVATE KEY-----
";

const TRUST_DOMAIN: &str = "sandbox.test";
const AUDIENCE: &str = "internal-api";
const REQUIRED_GROUP: &str = "firestoned:sandbox-users";
const PEER_HEADER: &str = "x-mediatore-peer-spiffe-id";
const EK_HASH: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";

fn node_svid() -> String {
    format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{EK_HASH}")
}

fn claim_svid(uid: &uuid::Uuid) -> String {
    format!("spiffe://{TRUST_DOMAIN}/banlieue/claim/{uid}")
}

fn gateway_svid() -> String {
    format!("spiffe://{TRUST_DOMAIN}/gateway")
}

/// One request as the upstream saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    path_and_query: String,
    authorization: Option<String>,
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Seen>>>);

async fn record(
    State(rec): State<Recorder>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> &'static str {
    rec.0.lock().unwrap().push(Seen {
        path_and_query: uri
            .path_and_query()
            .map(ToString::to_string)
            .unwrap_or_default(),
        authorization: headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned),
    });
    "upstream answered through the tunnel"
}

/// The destination behind the gateways: a TLS upstream on its own CA, recording.
struct Upstream {
    tls: TlsUpstream,
    seen: Recorder,
}

impl Upstream {
    async fn start() -> Self {
        mediatore_proto::tls::ensure_provider();
        let seen = Recorder::default();
        let tls = TlsUpstream::start(
            axum::Router::new()
                .route("/{*rest}", any(record))
                .route("/", any(record))
                .with_state(seen.clone()),
        )
        .await;
        Self { tls, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.0.lock().unwrap().clone()
    }
}

/// The proxy's token source against the dev-mode broker, counting its calls.
struct DevTokens {
    sandbox_url: String,
    claim_svid: String,
    http: reqwest::Client,
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl TokenSource for DevTokens {
    async fn token(&self, audience: &str) -> anyhow::Result<TokenResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let resp = self
            .http
            .post(format!("{}/v1/token", self.sandbox_url))
            .header(PEER_HEADER, &self.claim_svid)
            .json(&TokenRequest {
                audience: audience.to_owned(),
            })
            .send()
            .await?;
        anyhow::ensure!(resp.status().is_success(), "{}", resp.status());
        Ok(resp.json().await?)
    }
}

/// The dev-mode broker with `gateways` in its config and `upstream` as the audience's one
/// endpoint, on its CA; every SVID of the test from `ca`.
struct Harness {
    #[allow(dead_code)] // dropped last: aborts the issuer
    idp: FakeIdp,
    user_url: String,
    sandbox_url: String,
    http: reqwest::Client,
    upstream: Upstream,
    ca: TestCa,
}

impl Harness {
    async fn start(
        ca: TestCa,
        upstream: Upstream,
        gateways: Vec<Endpoint>,
        registry_audiences: Option<
            std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
        >,
    ) -> Self {
        let idp = FakeIdp::start().await;
        let sts = Sts::new(
            "https://mediatore.test",
            "e2e-1",
            STS_TEST_KEY.as_bytes(),
            jiff::SignedDuration::from_mins(15),
        )
        .expect("sts");
        let state = Arc::new(AppState {
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
            }]),
            sts: Some(sts),
            audiences: vec![AUDIENCE.into()],
            obo_audiences: vec![],
            egress: [(AUDIENCE.to_owned(), vec![upstream.tls.endpoint()])]
                .into_iter()
                .collect(),
            rules: std::collections::BTreeMap::new(),
            cas: [(AUDIENCE.to_owned(), upstream.tls.ca_pem())]
                .into_iter()
                .collect(),
            no_credential: std::collections::BTreeSet::new(),
            secrets: std::collections::BTreeMap::new(),
            delegated: std::collections::BTreeMap::new(),
            registries: std::collections::BTreeMap::new(),
            registry_audiences,
            policy_egress: None,
            sandboxes: None,
            namespaces: Namespaces::Single("sandboxes".into()),
            sealer: None,
            limiter: Limiter::new(10),
            dev_mode: true,
            gateways,
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
            upstream,
            ca,
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

    /// A node registered and a claim bound to it (the dev binder); the claim's `Me`.
    async fn bound(&self) -> (ClaimResponse, Me) {
        let resp = self
            .http
            .post(format!("{}/v1/nodes", self.sandbox_url))
            .header(PEER_HEADER, node_svid())
            .json(&NodeRegistration {
                ek_hash: EK_HASH.into(),
                dmi_uuid: uuid::Uuid::new_v4(),
                hostname: "pool-a-7".into(),
                provider: None,
            })
            .send()
            .await
            .expect("register");
        assert_eq!(resp.status(), 200);
        let resp = self
            .http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(self.login("octocat"))
            .json(&ClaimRequest {
                namespace: None,
                pool_ref: Some("pool-a".into()),
                pool_selector: None,
                selection: None,
                ttl_seconds: 3600,
                audiences: vec![AUDIENCE.into()],
                workload: Workload {
                    image: "registry.internal:5000/sandbox:latest".into(),
                    args: vec!["/usr/bin/agent".into()],
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
        let me: Me = self
            .http
            .get(format!("{}/v1/me", self.sandbox_url))
            .header(PEER_HEADER, node_svid())
            .send()
            .await
            .expect("me")
            .json()
            .await
            .expect("me body");
        (claim, me)
    }

    /// The proxy as the guest would run it: the production constructor, the routes and
    /// the gateways from `me`, the forwarder presenting `identity` from this CA. Returns
    /// its base URL, the phantom and the token counter.
    async fn start_proxy(&self, me: &Me, identity: &str) -> (String, Phantom, Arc<DevTokens>) {
        let tokens = Arc::new(DevTokens {
            sandbox_url: self.sandbox_url.clone(),
            claim_svid: claim_svid(&me.claim_uid),
            http: reqwest::Client::new(),
            calls: AtomicUsize::new(0),
        });
        let phantom = Phantom::generate().expect("phantom");
        let material = MemoryMaterial::new(self.ca.svid(identity));
        let dialer = if me.gateways.is_empty() {
            Dialer::Direct
        } else {
            Dialer::Gateways(
                Forwarder::new(me.gateways.clone(), material)
                    .expect("a forwarder")
                    .with_attempt_timeout(Duration::from_secs(5)),
            )
        };
        let proxy = Arc::new(
            Proxy::with_webpki_roots(
                Routes::new(me.routes.clone()).expect("routes"),
                phantom.clone(),
                tokens.clone(),
                dialer,
            )
            .expect("a proxy from the claim's routes"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        tokio::spawn(proxy.serve(listener));
        (url, phantom, tokens)
    }

    /// The proxy with its pull listener for `host` as well (ADR-0043 decision 3, every pull under ADR-0063): the
    /// workload's URL, the puller's URL and the phantom.
    async fn start_proxy_with_pull(
        &self,
        me: &Me,
        identity: &str,
        host: &str,
    ) -> (String, String, Phantom) {
        let tokens = Arc::new(DevTokens {
            sandbox_url: self.sandbox_url.clone(),
            claim_svid: claim_svid(&me.claim_uid),
            http: reqwest::Client::new(),
            calls: AtomicUsize::new(0),
        });
        let phantom = Phantom::generate().expect("phantom");
        let material = MemoryMaterial::new(self.ca.svid(identity));
        let dialer = Dialer::Gateways(
            Forwarder::new(me.gateways.clone(), material)
                .expect("a forwarder")
                .with_attempt_timeout(Duration::from_secs(5)),
        );
        let proxy = Arc::new(
            Proxy::with_webpki_roots(
                Routes::new(me.routes.clone()).expect("routes"),
                phantom.clone(),
                tokens,
                dialer,
            )
            .expect("a proxy from the claim's routes"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy");
        let pull = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the pull listener");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let pull_url = format!("http://{}", pull.local_addr().expect("addr"));
        let host = host.to_owned();
        tokio::spawn(async move {
            let _ = tokio::join!(proxy.clone().serve(listener), proxy.serve_pull(pull, host));
        });
        (url, pull_url, phantom)
    }

    /// The workload's request: `GET /<host>/<path>` at the proxy with the phantom.
    async fn get(&self, proxy: &str, phantom: &Phantom, path: &str) -> reqwest::Response {
        self.http
            .get(format!("{proxy}/{}{path}", self.upstream.tls.endpoint()))
            .bearer_auth(phantom.expose())
            .send()
            .await
            .expect("through the proxy")
    }
}

fn error_of(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body).expect("json")["error"]
        .as_str()
        .expect("error code")
        .to_owned()
}

#[tokio::test]
async fn the_workload_reaches_its_upstream_through_a_gateway_as_the_claim() {
    let ca = TestCa::new(TRUST_DOMAIN);
    let upstream = Upstream::start().await;
    // Three gateways in the broker's order: one down, one presenting the wrong identity (a
    // valid SVID of the trust domain under the gateway's path, not the gateway's), one real.
    let dead = mediatore_testkit::dead_endpoint().await;
    let rogue = StandInGateway::start(&ca, &format!("{}/rogue", gateway_svid()), vec![]).await;
    // And one presenting the gateway's authorizer's identity (ADR-0053 decision 1): a real
    // name of the environment, and no listener's. The forwarder verifies exactly
    // `spiffe://<td>/gateway`, so a holder of the authorizer's SVID is no gateway to it.
    let authorizer_named =
        StandInGateway::start(&ca, &format!("{}/authorizer", gateway_svid()), vec![]).await;
    let live = StandInGateway::start(&ca, &gateway_svid(), vec![upstream.tls.endpoint()]).await;
    let listed = vec![
        dead.clone(),
        rogue.endpoint(),
        authorizer_named.endpoint(),
        live.endpoint(),
    ];
    let h = Harness::start(ca, upstream, listed.clone(), None).await;
    let (_claim, me) = h.bound().await;
    assert_eq!(
        me.gateways, listed,
        "the list reaches the guest on GET /v1/me, in the broker's order (decision 6)"
    );
    let (proxy, phantom, tokens) = h.start_proxy(&me, &claim_svid(&me.claim_uid)).await;

    // Several connections: whichever position each starts at, the dead and the rogue
    // gateway are skipped and the live one carries every tunnel.
    for i in 0..6 {
        let resp = h.get(&proxy, &phantom, &format!("/api/things/{i}")).await;
        assert_eq!(resp.status(), 200, "request {i}");
        assert_eq!(
            resp.text().await.unwrap(),
            "upstream answered through the tunnel"
        );
    }
    let seen = h.upstream.seen();
    assert_eq!(seen.len(), 6);
    assert_eq!(seen[0].path_and_query, "/api/things/0");
    let bearer = seen[0]
        .authorization
        .as_deref()
        .expect("a credential went upstream");
    assert!(bearer.starts_with("Bearer ") && !bearer.contains(phantom.expose()));
    assert_eq!(
        tokens.calls.load(Ordering::SeqCst),
        1,
        "the token is cached across tunnels"
    );

    // The gateway saw six tunnels, each from the claim's SPIFFE ID to the upstream's
    // host:port, each admitted; the rogue saw none (the handshake failed on its identity).
    let tunnels = live.tunnels();
    assert_eq!(tunnels.len(), 6, "{tunnels:?}");
    for t in &tunnels {
        assert_eq!(t.peer, claim_svid(&me.claim_uid));
        assert_eq!(t.authority, h.upstream.tls.endpoint().to_string());
        assert!(t.allowed);
    }
    assert_eq!(
        rogue.tunnels(),
        Vec::new(),
        "an identity that is not spiffe://<td>/gateway never gets a CONNECT"
    );
    assert_eq!(
        authorizer_named.tunnels(),
        Vec::new(),
        "a server presenting the authorizer's identity is not a gateway to the forwarder"
    );
}

/// ADR-0063 decisions 1, 3 and 5: a registry audience's route is pulled through the claim's proxy and a gateway's
/// tunnel, as the claim, decided by the gateway like any egress; the jail asking for the same route is refused before
/// anything leaves.
#[tokio::test]
async fn a_registry_route_is_pulled_through_a_gateway_tunnel_and_refused_to_the_workload() {
    let ca = TestCa::new(TRUST_DOMAIN);
    let upstream = Upstream::start().await;
    let live = StandInGateway::start(&ca, &gateway_svid(), vec![upstream.tls.endpoint()]).await;
    // The claim's one audience is the registry its image is on.
    let granted = [(
        AUDIENCE.to_owned(),
        ["registry.internal:5000".to_owned()].into_iter().collect(),
    )]
    .into_iter()
    .collect();
    let h = Harness::start(ca, upstream, vec![live.endpoint()], Some(granted)).await;
    let (_claim, me) = h.bound().await;
    let route = me
        .routes
        .iter()
        .find(|r| r.audience.as_deref() == Some(AUDIENCE))
        .expect("the registry route");
    assert!(
        route.pull_only,
        "a registry audience's route is the puller's"
    );
    assert_eq!(me.egress, vec![], "the jail reaches no registry");
    let host = h.upstream.tls.endpoint().to_string();
    let (proxy, pull, phantom) = h
        .start_proxy_with_pull(&me, &claim_svid(&me.claim_uid), &host)
        .await;

    // The jail, with the phantom: refused at the proxy, nothing tunnelled.
    let jail = h.get(&proxy, &phantom, "/v2/").await;
    assert_eq!(jail.status(), 404);
    assert!(
        live.tunnels().is_empty(),
        "no tunnel for the jail's request"
    );
    assert_eq!(h.upstream.seen().len(), 0, "nothing reached the registry");

    // The puller, with nothing: through the tunnel, as the claim.
    let pulled = h
        .http
        .get(format!("{pull}/{host}/v2/team/tool/manifests/v1"))
        .send()
        .await
        .expect("through the pull listener");
    assert_eq!(pulled.status(), 200);
    assert_eq!(
        pulled.text().await.unwrap(),
        "upstream answered through the tunnel"
    );
    let tunnels = live.tunnels();
    assert_eq!(tunnels.len(), 1, "{tunnels:?}");
    assert_eq!(tunnels[0].peer, claim_svid(&me.claim_uid));
    assert_eq!(tunnels[0].authority, host);
    assert!(tunnels[0].allowed);
    assert_eq!(
        h.upstream.seen()[0].path_and_query,
        "/v2/team/tool/manifests/v1"
    );
}

#[tokio::test]
async fn a_gateway_that_refuses_the_tunnel_is_502_and_nothing_reaches_the_upstream() {
    let ca = TestCa::new(TRUST_DOMAIN);
    let upstream = Upstream::start().await;
    // The gateway's allowlist (the broker's answer, at a real one) does not hold the
    // upstream: the authorizer's no.
    let gateway = StandInGateway::start(&ca, &gateway_svid(), vec![]).await;
    let h = Harness::start(ca, upstream, vec![gateway.endpoint()], None).await;
    let (_claim, me) = h.bound().await;
    let (proxy, phantom, tokens) = h.start_proxy(&me, &claim_svid(&me.claim_uid)).await;

    let resp = h.get(&proxy, &phantom, "/api/things").await;
    assert_eq!(resp.status(), 502);
    assert_eq!(error_of(&resp.text().await.unwrap()), "gateway_refused");
    assert_eq!(h.upstream.seen(), Vec::new());
    let tunnels = gateway.tunnels();
    assert_eq!(
        tunnels.len(),
        1,
        "one ask, no second gateway to ask: {tunnels:?}"
    );
    assert!(!tunnels[0].allowed);
    assert_eq!(tunnels[0].peer, claim_svid(&me.claim_uid));
    assert_eq!(
        tokens.calls.load(Ordering::SeqCst),
        1,
        "the request was admitted by the proxy's own rules; the gateway said no"
    );
}

#[tokio::test]
async fn no_gateway_reachable_is_502_and_a_node_identity_gets_no_tunnel() {
    let ca = TestCa::new(TRUST_DOMAIN);
    let upstream = Upstream::start().await;
    let (dead_1, dead_2) = (
        mediatore_testkit::dead_endpoint().await,
        mediatore_testkit::dead_endpoint().await,
    );
    let h = Harness::start(ca, upstream, vec![dead_1, dead_2], None).await;
    let (_claim, me) = h.bound().await;
    let (proxy, phantom, _tokens) = h.start_proxy(&me, &claim_svid(&me.claim_uid)).await;
    let resp = h.get(&proxy, &phantom, "/api/things").await;
    assert_eq!(resp.status(), 502);
    assert_eq!(error_of(&resp.text().await.unwrap()), "gateway_unreachable");
    assert_eq!(h.upstream.seen(), Vec::new());

    // A live gateway, and a forwarder presenting the node's SVID instead of the claim's:
    // the gateway's validator refuses the handshake, so no gateway carried the tunnel.
    let gateway =
        StandInGateway::start(&h.ca, &gateway_svid(), vec![h.upstream.tls.endpoint()]).await;
    let me_via_live = Me {
        gateways: vec![gateway.endpoint()],
        ..me.clone()
    };
    let (proxy, phantom, _tokens) = h.start_proxy(&me_via_live, &node_svid()).await;
    let resp = h.get(&proxy, &phantom, "/api/things").await;
    assert_eq!(resp.status(), 502);
    assert_eq!(error_of(&resp.text().await.unwrap()), "gateway_unreachable");
    assert_eq!(
        gateway.tunnels(),
        Vec::new(),
        "the node never reached a CONNECT"
    );
    assert_eq!(h.upstream.seen(), Vec::new());

    // The same gateway, the claim's SVID: the tunnel opens. The difference is the identity.
    let (proxy, phantom, _tokens) = h
        .start_proxy(&me_via_live, &claim_svid(&me.claim_uid))
        .await;
    let resp = h.get(&proxy, &phantom, "/api/things").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(h.upstream.seen().len(), 1);
    assert_eq!(gateway.tunnels().len(), 1);
}

/// ADR-0028 decision 7 as amended 2026-11-09: a gateway's own `5xx` (Envoy's resolver
/// failing, no verdict given) moves the forwarder to the next gateway; every gateway in
/// trouble is `502 gateway_unreachable` after one pass, each asked once. The authorizer's
/// `403` stays final (the test above).
#[tokio::test]
async fn a_gateway_in_trouble_is_skipped_and_every_gateway_in_trouble_is_unreachable() {
    let ca = TestCa::new(TRUST_DOMAIN);
    let upstream = Upstream::start().await;
    let unwell_1 = StandInGateway::start_unwell(&ca, &gateway_svid()).await;
    let unwell_2 = StandInGateway::start_unwell(&ca, &gateway_svid()).await;
    let h = Harness::start(
        ca,
        upstream,
        vec![unwell_1.endpoint(), unwell_2.endpoint()],
        None,
    )
    .await;
    let (_claim, me) = h.bound().await;
    let (proxy, phantom, _tokens) = h.start_proxy(&me, &claim_svid(&me.claim_uid)).await;

    let resp = h.get(&proxy, &phantom, "/api/things").await;
    assert_eq!(resp.status(), 502);
    assert_eq!(
        error_of(&resp.text().await.unwrap()),
        "gateway_unreachable",
        "a 503 is the gateway's condition, not the request's verdict"
    );
    assert_eq!(h.upstream.seen(), Vec::new());
    assert_eq!(
        (unwell_1.tunnels().len(), unwell_2.tunnels().len()),
        (1, 1),
        "both asked once, the second after the first's 503"
    );

    // A healthy gateway beside them: every request reaches the upstream, whatever the
    // random start; the unwell ones only ever see asks they answer 503 to.
    let healthy =
        StandInGateway::start(&h.ca, &gateway_svid(), vec![h.upstream.tls.endpoint()]).await;
    let me_mixed = Me {
        gateways: vec![unwell_1.endpoint(), healthy.endpoint(), unwell_2.endpoint()],
        ..me.clone()
    };
    let (proxy, phantom, _tokens) = h.start_proxy(&me_mixed, &claim_svid(&me.claim_uid)).await;
    for i in 0..6 {
        let resp = h.get(&proxy, &phantom, "/api/things").await;
        assert_eq!(resp.status(), 200, "request {i}");
    }
    assert_eq!(h.upstream.seen().len(), 6);
    assert_eq!(
        healthy.tunnels().len(),
        6,
        "each request ended at the healthy gateway"
    );
    assert!(
        unwell_1
            .tunnels()
            .iter()
            .chain(unwell_2.tunnels().iter())
            .all(|t| !t.allowed),
        "an unwell gateway never carried one"
    );
}

/// ADR-0063 decision 2: in an environment with gateways the broker refuses a claim whose image is on a registry none
/// of its audiences of `role: registry` serves, naming none of the registries that exist, and admits one its audience
/// serves; without gateways nothing is refused by registry (every other suite).
#[tokio::test]
async fn a_claim_whose_registry_is_not_granted_is_refused_and_a_granted_one_is_not() {
    let ca = TestCa::new(TRUST_DOMAIN);
    let upstream = Upstream::start().await;
    let dead = mediatore_testkit::dead_endpoint().await;
    // The claim's one audience serves the mirror; nothing serves ghcr.io.
    let granted = [(
        AUDIENCE.to_owned(),
        ["registry.internal:5000".to_owned()].into_iter().collect(),
    )]
    .into_iter()
    .collect();
    let h = Harness::start(ca, upstream, vec![dead], Some(granted)).await;
    let claim = |image: &str| ClaimRequest {
        namespace: None,
        pool_ref: Some("pool-a".into()),
        pool_selector: None,
        selection: None,
        ttl_seconds: 3600,
        audiences: vec![AUDIENCE.into()],
        workload: Workload {
            image: image.into(),
            args: vec!["/usr/bin/agent".into()],
            restart: mediatore_proto::RestartPolicy::Always,
            logs: false,
        },
        refresh_token: None,
        policy_ref: None,
        delegations: vec![],
    };
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(h.login("octocat"))
        .json(&claim("ghcr.io/firestoned/agent:1"))
        .send()
        .await
        .expect("create claim");
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["error"], "registry_not_granted", "{body}");
    let detail = body["detail"].as_str().unwrap_or_default().to_owned();
    assert!(
        detail.contains("ghcr.io") && detail.contains("ADR-0063"),
        "{body}"
    );
    assert!(
        !detail.contains("registry.internal:5000"),
        "a refusal names no registry the broker serves: {body}"
    );
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(h.login("octocat"))
        .json(&claim("registry.internal:5000/team/agent:1"))
        .send()
        .await
        .expect("create claim");
    assert_eq!(resp.status(), 201, "the mirror is granted");
}
