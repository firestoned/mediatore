// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The egress proxy front to back (ADR-0025): the fake issuer, the dev-mode broker, a TLS
//! upstream that records what reached it, and the proxy in between, driven as the jailed
//! workload would drive it: plain HTTP on loopback, the host as the first path segment, the
//! phantom token in `Authorization`.
//!
//! What stays faked: the peer identity is a header (`dev_mode`) and the proxy's token
//! source is a client of that header path, since no Workload API exists here. Everything
//! else (the routes from `GET /v1/me`, the rules, the swap, the upstream TLS through the
//! production constructor with the audience's own CA on the route, the token minted by the
//! STS and verified against the broker's JWKS) is the production code path.

use std::future::IntoFuture;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::any;
use jiff::SignedDuration;
use mediatore_api::{AppState, Limiter, Namespaces};
use mediatore_entra::{Backend, IssuerConfig, Validator};
use mediatore_guest::egress::{Phantom, Proxy, Routes, TokenSource};
use mediatore_guest::forward::Dialer;
use mediatore_proto::{
    ClaimRequest, ClaimResponse, EndpointRule, Me, NodeRegistration, TokenRequest, TokenResponse,
    Workload,
};
use mediatore_spire::Naming;
use mediatore_store::MemoryStore;
use mediatore_sts::Sts;
use mediatore_testkit::{FakeIdp, TlsUpstream};

/// Throwaway P-256 key for the e2e STS. Test material only; never reuse.
const STS_TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnjPFPJtOewKuQZS0
WTXasKCqUusD6hs+6AaBUWw5lOyhRANCAAQy0awwI1IJ/BKoy/Zj4KtfYOiJOaX2
bVIP4yKaVz1Zp2QNVZJ0t2NIXK0K55dfgdM/B4JF09EKDd/q/nHoAfis
-----END PRIVATE KEY-----
";

const TRUST_DOMAIN: &str = "sandbox.test";
const AUDIENCE: &str = "internal-api";
/// An audience reached without a credential (`via: none`, ADR-0025 decision 8).
const PUBLIC: &str = "api.example.com";
/// An audience served from an operator-held credential in `x-api-key` (`via: secret`,
/// ADR-0032), the shape Anthropic's API takes.
const KEYED: &str = "anthropic";
const KEYED_SECRET: &str = "sk-test-operator-key-0001";
const REQUIRED_GROUP: &str = "firestoned:sandbox-users";
const PEER_HEADER: &str = "x-mediatore-peer-spiffe-id";
const EK_HASH: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";

/// One request as the upstream saw it.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path_and_query: String,
    authorization: Option<String>,
    host: Option<String>,
    /// `x-api-key`, where a `via: secret` audience's credential goes (ADR-0032).
    api_key: Option<String>,
    /// `anthropic-beta`, an extra header the audience names.
    beta: Option<String>,
    /// Every header, lower-case names, in the order received.
    headers: Vec<(String, String)>,
    /// The body's bytes as far as they arrived.
    body: Vec<u8>,
    /// Whether the body arrived whole. False for a request cut before its end.
    complete: bool,
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Seen>>>);

async fn record(
    State(rec): State<Recorder>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    mut body: axum::body::Body,
) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    use axum::body::HttpBody as _;
    let seen = Seen {
        headers: headers
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: Vec::new(),
        complete: false,
        method: method.to_string(),
        path_and_query: uri
            .path_and_query()
            .map(ToString::to_string)
            .unwrap_or_default(),
        authorization: headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned),
        host: headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned),
        api_key: headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned),
        beta: headers
            .get("anthropic-beta")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned),
    };
    // Recorded as soon as the head is in, then the body as it comes: a request cut before its
    // end is still seen, with what arrived of it.
    let index = {
        let mut all = rec.0.lock().unwrap();
        all.push(seen);
        all.len() - 1
    };
    loop {
        let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
        match frame {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    rec.0.lock().unwrap()[index].body.extend_from_slice(data);
                }
            }
            Some(Err(_)) => break,
            None => {
                rec.0.lock().unwrap()[index].complete = true;
                break;
            }
        }
    }
    (
        [(axum::http::HeaderName::from_static("x-upstream"), "seen")],
        "upstream answered".to_owned(),
    )
}

/// The proxy's token source against the dev-mode broker: the claim identity as a header,
/// counting the calls so the cache is observable.
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

/// The broker's state for the proxy's proof: three audiences on one trust domain, the
/// first on a private PKI with rules, the second `via: none`, the third `via: secret` with
/// the operator's key in `x-api-key` (ADR-0032).
/// The harness's STS: the test key, fifteen minutes at most.
fn test_sts() -> Sts {
    Sts::new(
        "https://mediatore.test",
        "e2e-1",
        STS_TEST_KEY.as_bytes(),
        SignedDuration::from_mins(15),
    )
    .expect("sts")
}

fn state(
    idp: &FakeIdp,
    upstream: &TlsUpstream,
    keyed_upstream: &TlsUpstream,
    tripwires: mediatore_api::Tripwires,
) -> Arc<AppState> {
    let sts = test_sts();
    Arc::new(AppState {
        tripwires,
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
        audiences: vec![AUDIENCE.into(), PUBLIC.into(), KEYED.into()],
        obo_audiences: vec![],
        egress: [
            (AUDIENCE.to_owned(), vec![upstream.endpoint()]),
            (
                PUBLIC.to_owned(),
                vec!["api.example.com:443".parse().unwrap()],
            ),
            (KEYED.to_owned(), vec![keyed_upstream.endpoint()]),
        ]
        .into_iter()
        .collect(),
        rules: [
            (
                AUDIENCE.to_owned(),
                vec![
                    EndpointRule {
                        method: "GET".into(),
                        path: "/api/**".into(),
                    },
                    EndpointRule {
                        method: "POST".into(),
                        path: "/api/things/*/notes".into(),
                    },
                ],
            ),
            (
                KEYED.to_owned(),
                vec![EndpointRule {
                    method: "POST".into(),
                    path: "/v1/messages".into(),
                }],
            ),
        ]
        .into_iter()
        .collect(),
        // The upstream is on a private PKI, as the homelab's are: its CA is the
        // audience's `ca_file`, carried to the proxy on the route (ADR-0025 amended).
        cas: [
            (AUDIENCE.to_owned(), upstream.ca_pem()),
            (KEYED.to_owned(), keyed_upstream.ca_pem()),
        ]
        .into_iter()
        .collect(),
        no_credential: [PUBLIC.to_owned()].into_iter().collect(),
        // The operator's credential for the keyed audience (ADR-0032): in the broker's
        // memory alone, placed by the proxy in x-api-key with the beta header beside it.
        secrets: [(
            KEYED.to_owned(),
            mediatore_api::AudienceSecret {
                value: mediatore_proto::Secret(KEYED_SECRET.into()),
                header: "x-api-key".into(),
                extra_headers: vec![mediatore_proto::HeaderPair {
                    name: "anthropic-beta".into(),
                    value: "oauth-2025-04-20".into(),
                }],
                ttl: SignedDuration::from_mins(15),
            },
        )]
        .into_iter()
        .collect(),
        delegated: std::collections::BTreeMap::new(),
        registries: std::collections::BTreeMap::new(),
        registry_audiences: None,
        policy_egress: None,
        sandboxes: None,
        namespaces: Namespaces::Single("sandboxes".into()),
        max_ttl_seconds: mediatore_proto::DEFAULT_MAX_TTL_SECONDS,
        sealer: None,
        limiter: Limiter::new(10),
        dev_mode: true,
        gateways: vec![],
    })
}

struct Harness {
    #[allow(dead_code)] // dropped last: aborts the issuer
    idp: FakeIdp,
    user_url: String,
    sandbox_url: String,
    http: reqwest::Client,
    upstream: TlsUpstream,
    /// The upstream behind the `via: secret` audience, on its own CA, the same recorder.
    keyed_upstream: TlsUpstream,
    seen: Recorder,
}

impl Harness {
    async fn start() -> Self {
        Self::start_with(mediatore_api::Tripwires::default()).await
    }

    /// The harness with the broker's tripwires as given (ADR-0069): `off` by default.
    async fn start_with(tripwires: mediatore_api::Tripwires) -> Self {
        mediatore_proto::tls::ensure_provider();
        let seen = Recorder::default();
        let upstream = TlsUpstream::start(
            axum::Router::new()
                .route("/{*rest}", any(record))
                .route("/", any(record))
                .with_state(seen.clone()),
        )
        .await;
        let keyed_upstream = TlsUpstream::start(
            axum::Router::new()
                .route("/{*rest}", any(record))
                .route("/", any(record))
                .with_state(seen.clone()),
        )
        .await;
        let idp = FakeIdp::start().await;
        let state = state(&idp, &upstream, &keyed_upstream, tripwires);
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
            keyed_upstream,
            seen,
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
                attestation: None,
                dmi_uuid: uuid::Uuid::new_v4(),
                hostname: "pool-a-7".into(),
                provider: None,
            })
            .send()
            .await
            .expect("register");
        assert_eq!(resp.status(), 200);
    }

    async fn claim(&self) -> ClaimResponse {
        self.claim_with(&[AUDIENCE]).await
    }

    async fn claim_with(&self, audiences: &[&str]) -> ClaimResponse {
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
                audiences: audiences.iter().map(|a| (*a).to_owned()).collect(),
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
        resp.json().await.expect("claim body")
    }

    async fn me(&self) -> Me {
        self.http
            .get(format!("{}/v1/me", self.sandbox_url))
            .header(
                PEER_HEADER,
                format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{EK_HASH}"),
            )
            .send()
            .await
            .expect("me")
            .json()
            .await
            .expect("me body")
    }

    /// The proxy as the guest would run it, through the production constructor (the
    /// Mozilla roots for routes without a CA), from `routes`, on an ephemeral loopback
    /// port; returns its base URL, the phantom and the token counter.
    async fn start_proxy(
        &self,
        routes: Vec<mediatore_proto::Route>,
        claim_uid: &uuid::Uuid,
    ) -> (String, Phantom, Arc<DevTokens>) {
        let tokens = Arc::new(DevTokens {
            sandbox_url: self.sandbox_url.clone(),
            claim_svid: format!("spiffe://{TRUST_DOMAIN}/banlieue/claim/{claim_uid}"),
            http: reqwest::Client::new(),
            calls: AtomicUsize::new(0),
        });
        let phantom = Phantom::generate().expect("phantom");
        let proxy = Arc::new(
            Proxy::with_webpki_roots(
                Routes::new(routes).expect("routes"),
                phantom.clone(),
                tokens.clone(),
                Dialer::Direct,
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

    fn seen(&self) -> Vec<Seen> {
        self.seen.0.lock().unwrap().clone()
    }

    async fn jwks_key(&self) -> jsonwebtoken::DecodingKey {
        let jwks: serde_json::Value = self
            .http
            .get(format!("{}/.well-known/jwks.json", self.user_url))
            .send()
            .await
            .expect("jwks")
            .json()
            .await
            .expect("jwks body");
        let jwk = &jwks["keys"][0];
        jsonwebtoken::DecodingKey::from_ec_components(
            jwk["x"].as_str().expect("x"),
            jwk["y"].as_str().expect("y"),
        )
        .expect("jwk key")
    }
}

#[tokio::test]
async fn the_phantom_is_swapped_for_a_real_token_the_workload_never_sees() {
    let h = Harness::start().await;
    h.register_node().await;
    let claim = h.claim().await;
    let uid = claim.uid.expect("uid");

    // The guest learns the routes with the subject: one per audience and endpoint, with
    // the audience's rules (ADR-0025 decision 4).
    let me = h.me().await;
    assert_eq!(me.routes.len(), 1);
    assert_eq!(me.routes[0].audience.as_deref(), Some(AUDIENCE));
    assert!(me.routes[0].injects());
    assert_eq!(me.routes[0].endpoint, h.upstream.endpoint());
    assert_eq!(me.routes[0].rules.len(), 2);
    assert_eq!(
        me.egress,
        vec![h.upstream.endpoint()],
        "the ruleset's destinations are the routes' endpoints"
    );

    assert_eq!(
        me.routes[0].ca_pem.as_deref(),
        Some(h.upstream.ca_pem().as_str()),
        "the audience's CA travels on the route (ADR-0025 amended)"
    );
    let (proxy, phantom, tokens) = h.start_proxy(me.routes.clone(), &uid).await;
    let host = h.upstream.endpoint().to_string();

    // The workload: a GET within the rules, the phantom in Authorization.
    let resp = h
        .http
        .get(format!("{proxy}/{host}/api/things?x=1"))
        .bearer_auth(phantom.expose())
        .send()
        .await
        .expect("through the proxy");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["x-upstream"], "seen");
    assert_eq!(resp.text().await.unwrap(), "upstream answered");
    let seen = h.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].path_and_query, "/api/things?x=1");
    assert_eq!(seen[0].host.as_deref(), Some(host.as_str()));
    let authorization = seen[0]
        .authorization
        .clone()
        .expect("a credential went upstream");
    let token = authorization.strip_prefix("Bearer ").expect("a bearer");
    assert_ne!(
        token,
        phantom.expose(),
        "the phantom never leaves the proxy"
    );

    // The upstream got an STS token for its audience, acting for the subject, naming the
    // claim as the actor: the same token the workload used to fetch itself.
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_audience(&[AUDIENCE]);
    validation.set_issuer(&["https://mediatore.test"]);
    let decoded =
        jsonwebtoken::decode::<serde_json::Value>(token, &h.jwks_key().await, &validation)
            .expect("the upstream verifies the token");
    assert_eq!(decoded.claims["sub"], "octocat");
    assert_eq!(
        decoded.claims["act"]["sub"],
        format!("spiffe://{TRUST_DOMAIN}/banlieue/claim/{uid}")
    );

    // A second request within the rules reuses the cached token: one fetch for two calls.
    let resp = h
        .http
        .post(format!("{proxy}/{host}/api/things/7/notes"))
        .bearer_auth(phantom.expose())
        .body("a note")
        .send()
        .await
        .expect("second request");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        tokens.calls.load(Ordering::SeqCst),
        1,
        "the token is cached"
    );
    let seen = h.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].method, "POST");
    assert_eq!(
        seen[1].authorization.as_deref(),
        Some(authorization.as_str())
    );

    // No Authorization: forwarded bare (a public endpoint behind the same host).
    let resp = h
        .http
        .get(format!("{proxy}/{host}/api/public"))
        .send()
        .await
        .expect("bare request");
    assert_eq!(resp.status(), 200);
    let seen = h.seen();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        seen[2].authorization, None,
        "nothing injected without the phantom"
    );
    assert_eq!(tokens.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_route_without_a_credential_forwards_bare_and_the_phantom_never_leaves() {
    let h = Harness::start().await;
    h.register_node().await;
    let claim = h.claim_with(&[AUDIENCE, PUBLIC]).await;
    let uid = claim.uid.expect("uid");

    // The `via: none` audience's route says so (ADR-0025 decision 8), beside the other's.
    let me = h.me().await;
    assert_eq!(me.routes.len(), 2);
    let public = me
        .routes
        .iter()
        .find(|r| r.audience.as_deref() == Some(PUBLIC))
        .expect("the public audience's route");
    assert_eq!(public.credential, mediatore_proto::Credential::None);
    assert!(!public.injects());
    assert!(
        me.routes
            .iter()
            .find(|r| r.audience.as_deref() == Some(AUDIENCE))
            .expect("the other route")
            .injects()
    );
    // And the broker mints nothing for it, whoever holds the claim SVID.
    let resp = h
        .http
        .post(format!("{}/v1/token", h.sandbox_url))
        .header(
            PEER_HEADER,
            format!("spiffe://{TRUST_DOMAIN}/banlieue/claim/{uid}"),
        )
        .json(&TokenRequest {
            audience: PUBLIC.into(),
        })
        .send()
        .await
        .expect("token request");
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"], "no_credential");

    // The proxy against the real upstream, its route turned credential-less: the shape a
    // bundle's direct egress entry arrives in (no audience, no rules, ADR-0030), the CA
    // kept so the fixture upstream is reachable.
    let routes: Vec<mediatore_proto::Route> = me
        .routes
        .into_iter()
        .filter(|r| r.audience.as_deref() == Some(AUDIENCE))
        .map(|r| mediatore_proto::Route {
            audience: None,
            rules: vec![],
            credential: mediatore_proto::Credential::None,
            ..r
        })
        .collect();
    let (proxy, phantom, tokens) = h.start_proxy(routes, &uid).await;
    let host = h.upstream.endpoint().to_string();

    // The phantom presented, as every tool does: dropped, the request leaves bare.
    let resp = h
        .http
        .get(format!("{proxy}/{host}/api/things"))
        .bearer_auth(phantom.expose())
        .send()
        .await
        .expect("through the proxy");
    assert_eq!(resp.status(), 200);
    let seen = h.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].authorization, None,
        "the phantom never leaves the proxy and nothing replaces it"
    );
    assert_eq!(
        tokens.calls.load(Ordering::SeqCst),
        0,
        "no token is fetched"
    );

    // No header: bare, as on every route.
    let resp = h
        .http
        .get(format!("{proxy}/{host}/api/public"))
        .send()
        .await
        .expect("bare request");
    assert_eq!(resp.status(), 200);
    assert_eq!(h.seen().len(), 2);

    // A credential the image brought: refused on this route as on any other.
    let resp = h
        .http
        .get(format!("{proxy}/{host}/api/things"))
        .bearer_auth("baked-into-the-image")
        .send()
        .await
        .expect("foreign bearer");
    assert_eq!(resp.status(), 401);
    assert_eq!(h.seen().len(), 2, "nothing reached the upstream");
    assert_eq!(tokens.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_operator_held_credential_is_placed_by_the_proxy_and_never_enters_the_jail() {
    let h = Harness::start().await;
    h.register_node().await;
    let claim = h.claim_with(&[AUDIENCE, KEYED]).await;
    let uid = claim.uid.expect("uid");

    // The route says where the credential goes (ADR-0032 decision 2); not what it is.
    let me = h.me().await;
    let keyed = me
        .routes
        .iter()
        .find(|r| r.audience.as_deref() == Some(KEYED))
        .expect("the keyed audience's route");
    assert!(keyed.injects());
    assert_eq!(keyed.credential_header.as_deref(), Some("x-api-key"));
    assert!(
        !serde_json::to_string(&me).unwrap().contains(KEYED_SECRET),
        "the credential is not in the subject the guest fetches"
    );
    // The broker hands it with the header, for max_ttl, to the claim SVID.
    let resp = h
        .http
        .post(format!("{}/v1/token", h.sandbox_url))
        .header(
            PEER_HEADER,
            format!("spiffe://{TRUST_DOMAIN}/banlieue/claim/{uid}"),
        )
        .json(&TokenRequest {
            audience: KEYED.into(),
        })
        .send()
        .await
        .expect("token request");
    assert_eq!(resp.status(), 200);
    let token: TokenResponse = resp.json().await.expect("token body");
    assert_eq!(token.access_token, KEYED_SECRET);
    assert_eq!(token.token_type, "Header");
    assert_eq!(token.header.as_deref(), Some("x-api-key"));
    assert_eq!(token.extra_headers[0].name, "anthropic-beta");
    let left = token.expires_at.duration_since(jiff::Timestamp::now());
    assert!(
        left > SignedDuration::from_mins(14) && left <= SignedDuration::from_mins(15),
        "expires_at is now plus max_ttl: {left}"
    );

    let (proxy, phantom, tokens) = h.start_proxy(me.routes.clone(), &uid).await;
    let host = h.keyed_upstream.endpoint().to_string();
    let other = h.upstream.endpoint().to_string();

    // The SDK's shape: the phantom in x-api-key. The upstream sees the operator's key
    // there, the beta header beside it, and no Authorization at all.
    let resp = h
        .http
        .post(format!("{proxy}/{host}/v1/messages"))
        .header("x-api-key", phantom.expose())
        .body("{}")
        .send()
        .await
        .expect("through the proxy");
    assert_eq!(resp.status(), 200);
    let seen = h.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].api_key.as_deref(), Some(KEYED_SECRET));
    assert_eq!(seen[0].beta.as_deref(), Some("oauth-2025-04-20"));
    assert_eq!(seen[0].authorization, None, "nothing in Authorization");

    // The phantom as a bearer works the same on this route.
    let resp = h
        .http
        .post(format!("{proxy}/{host}/v1/messages"))
        .bearer_auth(phantom.expose())
        .body("{}")
        .send()
        .await
        .expect("as a bearer");
    assert_eq!(resp.status(), 200);
    let seen = h.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].api_key.as_deref(), Some(KEYED_SECRET));
    assert_eq!(seen[1].authorization, None);
    assert_eq!(
        tokens.calls.load(Ordering::SeqCst),
        1,
        "one fetch for two requests: the credential is cached for max_ttl"
    );

    // A key the image brought, in the header the proxy owns: refused on this route and on
    // every other (decision 3), nothing forwarded.
    // (Each request is within its route's rules, so the refusal is the credential's.)
    for (method, target) in [
        (reqwest::Method::POST, format!("{proxy}/{host}/v1/messages")),
        (reqwest::Method::GET, format!("{proxy}/{other}/api/public")),
    ] {
        let resp = h
            .http
            .request(method, &target)
            .header("x-api-key", "sk-baked-into-the-image")
            .send()
            .await
            .expect("foreign key");
        assert_eq!(resp.status(), 401, "{target}");
    }
    assert_eq!(h.seen().len(), 2, "nothing reached either upstream");

    // The rules still bound the audience: only POST /v1/messages.
    let resp = h
        .http
        .get(format!("{proxy}/{host}/v1/messages"))
        .header("x-api-key", phantom.expose())
        .send()
        .await
        .expect("outside the rules");
    assert_eq!(resp.status(), 403);
    assert_eq!(tokens.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn refusals_never_reach_the_upstream() {
    let h = Harness::start().await;
    h.register_node().await;
    let claim = h.claim().await;
    let me = h.me().await;
    let (proxy, phantom, tokens) = h.start_proxy(me.routes, &claim.uid.expect("uid")).await;
    let host = h.upstream.endpoint().to_string();
    let error_of = |body: String| -> String {
        serde_json::from_str::<serde_json::Value>(&body).expect("json")["error"]
            .as_str()
            .expect("error code")
            .to_owned()
    };

    // A foreign bearer: the workload has no credential of its own this layer carries.
    let resp = h
        .http
        .get(format!("{proxy}/{host}/api/things"))
        .bearer_auth("ghp_somethingTheImageShipped")
        .send()
        .await
        .expect("foreign bearer");
    assert_eq!(resp.status(), 401);
    assert_eq!(error_of(resp.text().await.unwrap()), "unknown_credential");

    // Outside the audience's rules: DELETE is not admitted, nor is a path off /api.
    let resp = h
        .http
        .delete(format!("{proxy}/{host}/api/things/7"))
        .bearer_auth(phantom.expose())
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), 403);
    assert_eq!(error_of(resp.text().await.unwrap()), "outside_rules");
    let resp = h
        .http
        .get(format!("{proxy}/{host}/admin"))
        .bearer_auth(phantom.expose())
        .send()
        .await
        .expect("off path");
    assert_eq!(resp.status(), 403);

    // A host the claim has no route to, with the phantom.
    let resp = h
        .http
        .get(format!("{proxy}/evil.example/api/things"))
        .bearer_auth(phantom.expose())
        .send()
        .await
        .expect("unknown host");
    assert_eq!(resp.status(), 404);
    assert_eq!(error_of(resp.text().await.unwrap()), "no_route");

    // Nothing was forwarded and no token was fetched for any of it.
    assert_eq!(h.seen().len(), 0, "{:?}", h.seen());
    assert_eq!(tokens.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_released_claim_gets_no_token_and_the_request_fails_closed() {
    let h = Harness::start().await;
    h.register_node().await;
    let claim = h.claim().await;
    let me = h.me().await;
    let (proxy, phantom, _tokens) = h.start_proxy(me.routes, &claim.uid.expect("uid")).await;
    let host = h.upstream.endpoint().to_string();

    let del = h
        .http
        .delete(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(h.login("octocat"))
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status(), 204);

    // The proxy cannot get a token for a revoked claim: the request is refused, not
    // forwarded bare.
    let resp = h
        .http
        .get(format!("{proxy}/{host}/api/things"))
        .bearer_auth(phantom.expose())
        .send()
        .await
        .expect("after release");
    assert_eq!(resp.status(), 502);
    assert_eq!(h.seen().len(), 0);
}

#[tokio::test]
async fn without_the_audiences_ca_a_private_upstream_is_refused_not_trusted() {
    let h = Harness::start().await;
    h.register_node().await;
    let claim = h.claim().await;
    let me = h.me().await;
    // The same routes with the CA stripped: what an audience without `ca_file` gets, the
    // Mozilla roots, which did not sign this upstream.
    let routes: Vec<mediatore_proto::Route> = me
        .routes
        .into_iter()
        .map(|r| mediatore_proto::Route { ca_pem: None, ..r })
        .collect();
    let (proxy, phantom, tokens) = h.start_proxy(routes, &claim.uid.expect("uid")).await;
    let host = h.upstream.endpoint().to_string();

    let resp = h
        .http
        .get(format!("{proxy}/{host}/api/things"))
        .bearer_auth(phantom.expose())
        .send()
        .await
        .expect("through the proxy");
    assert_eq!(resp.status(), 502);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"], "upstream_unreachable");
    assert_eq!(h.seen().len(), 0, "the handshake failed before any request");
    assert_eq!(
        tokens.calls.load(Ordering::SeqCst),
        1,
        "the token was fetched (the request was admitted) and went nowhere"
    );
}

// ---- Tripwires on the VM (ADR-0069): the proxy armed over the real trap socket, the guest's own tripwire behind
// it (`trip::start_with`, `trip::serve_socket`), its reports posted to the broker's real `POST /v1/me/trip`. What
// stays faked: `nft` (a recorder: nothing is cut on the machine running the tests) and the peer identity header.

mod tripwires {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use base64::Engine as _;
    use mediatore_guest::egress::{Phantom, Proxy, Routes, TrapLink, TrapPlan};
    use mediatore_guest::forward::Dialer;
    use mediatore_guest::net::{NftOutput, NftRunner};
    use mediatore_guest::trip::{self, PostOutcome, SocketGuard, Timing, TripSink, Tripwire};
    use mediatore_proto::trip::{
        ClassAction, DeniedSwitches, ProxyBait, ProxyDecoyRoute, ProxyTraps, TrapsBody, TrapsMode,
        TripClass, TripEffect, TripEntry, TripKind, TripMode, TripReport, TripSource, TripTarget,
    };
    use mediatore_proto::{ClaimResponse, Secret, TokenRequest};

    use super::{AUDIENCE, DevTokens, EK_HASH, Harness, KEYED, PEER_HEADER, Seen, TRUST_DOMAIN};

    /// A bait value in the shape a provider issues, planted nowhere but in these tests.
    const BAIT: &str = "AKIAQ7TRIPWIREBAIT42";
    /// A decoy route's host: a route that is no audience.
    const DECOY: &str = "vault.corp.internal";
    /// What the workload posts with the bait in it.
    const BAIT_BODY: &str = r#"{"description":"notes","files":{"creds":{"content":"aws_access_key_id = AKIAQ7TRIPWIREBAIT42"}}}"#;
    /// [`BAIT_BODY`] as gzip (level 9, no name, no time), base64.
    const BAIT_BODY_GZIP: &str = "H4sIAAAAAAAC/6tWSkktTi7KLCjJzM9TslLKyy9JLVbSUUrLzAHSVtVKyUWpKRBGfl5Jal4JUE1ieXF8YnJyanFxfHZqZXxmioKtgqO3p2OgeUiQZ0C4Z5Crk6NniImRUm1tLQD5rzQQYAAAAA==";
    /// 1280 KiB of zero bytes as gzip, base64: 1305 bytes that expand past the matcher's bound (a megabyte, then 64
    /// times the compressed size).
    const BOMB_GZIP: &str = "\
     H4sIAAAAAAAC/+3BMQEAAADCoPVPbQlPoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC+\
     BjSgPFAAABQA";

    /// An honest compressed upload: a JSON document of two hundred lines as gzip, base64.
    const HONEST_GZIP: &str = "\
     H4sIAAAAAAAC/3XYvWrcQBiG0VsRqlPo1YxGGt9KSGFiBRvs1bK7rkLuPSGkCjqd+KY66O+Z+Tlejsc+Po3Pl+H1uOz3x/D9\
     +Lje9vt9fxk+r+/H88v4ZXx/+7M0Pn39ezFMw/FjeLzuw22/HrfHv/Uh5+P5fFzOx/V8vJyP2/l4PR9v5+MOjphwBtBAGlAD\
     a4ANtAE38M7wzrqv8M7wzvDO8M7wzvDO8M7wFngLvEUPMrwF3gJvgbfAW+At8FZ4K7wV3qo3F94Kb4W3wlvhrfAu8C7wLvAu\
     8C76VMG7wLvAu8C7wNvgbfA2eBu8Dd6mbzO8Dd4Gb4N3hXeFd4V3hXeFd4V31c8I3hXeFd4N3g3eDd4N3g3eDd4N3k1/X3g3\
     eDu8Hd4Ob4e3w9vh7fB2eLtyg72h4JhUHJOSY1JzTIqOSdUxKTsmdcek8Jgkd2pJzthibTG32FsMLhYXk0vNFUVXZlam5Oqu\
     KLyi8orSK2qvKL6i+oryK+qvFAa25EqwqMGiCIsqLMqwqMOiEItKLEqxVO4tJFeNRTkW9VgUZFGRRUkWNVkUZVGVZeG2SnKF\
     WVRmUZpFbRbFWVRnUZ5FfRYFWhp3lJKr0aJIiyotyrSo06JQi0otSrWo1bJyMy25ci3qtSjYomKLki1qtijaomqLsi0bzxEk\
     V7lF6Ra1WxRvUb1F+Rb1WxRwUcGl8wjlf/m3X78BbvoJ0UoTAAA=";

    fn unbase64(text: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .expect("a fixture")
    }

    /// The broker's tripwires for a harness: the mode, the `denied` switches, and the keyed audience (the shape of a
    /// model API) marked `traps_body: skip`.
    fn broker(mode: TrapsMode, denied: DeniedSwitches) -> mediatore_api::Tripwires {
        mediatore_api::Tripwires {
            mode,
            denied,
            body_skip: [KEYED.to_owned()].into_iter().collect(),
            ..mediatore_api::Tripwires::default()
        }
    }

    fn hand_drawn(mode: TripMode, unknown_host: ClassAction) -> ProxyTraps {
        ProxyTraps {
            mode,
            unknown_host,
            routes: vec![ProxyDecoyRoute {
                name: "vault".into(),
                host: DECOY.into(),
            }],
            bait: vec![ProxyBait {
                name: "aws".into(),
                values: vec![Secret(BAIT.into())],
            }],
        }
    }

    /// An `nft` that cuts nothing and records every script it was handed.
    #[derive(Default)]
    struct RecordingNft(Mutex<Vec<String>>);

    #[async_trait::async_trait]
    impl NftRunner for RecordingNft {
        async fn run(&self, _args: &[&str], stdin: Option<&str>) -> std::io::Result<NftOutput> {
            self.0
                .lock()
                .unwrap()
                .push(stdin.unwrap_or_default().to_owned());
            Ok(NftOutput {
                success: true,
                stdout: Vec::new(),
                stderr: String::new(),
            })
        }
    }

    /// The guest's reports to the dev-mode broker, as the node, each kept as the JSON that was sent.
    struct DevTripSink {
        sandbox_url: String,
        http: reqwest::Client,
        sent: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl TripSink for DevTripSink {
        async fn post(&self, report: &TripReport) -> anyhow::Result<PostOutcome> {
            let body = serde_json::to_string(report)?;
            self.sent.lock().unwrap().push(body.clone());
            let resp = self
                .http
                .post(format!("{}/v1/me/trip", self.sandbox_url))
                .header(
                    PEER_HEADER,
                    format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{EK_HASH}"),
                )
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await?;
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned);
            Ok(mediatore_guest::report::trip_outcome(
                resp.status().as_u16(),
                retry_after.as_deref(),
            ))
        }
    }

    /// The proxy armed over the socket, and the guest's end of everything.
    struct Armed {
        proxy: String,
        phantom: Phantom,
        wire: Tripwire,
        nft: Arc<RecordingNft>,
        sink: Arc<DevTripSink>,
        uid: u32,
        _socket: SocketGuard,
        _dir: tempfile::TempDir,
    }

    impl Armed {
        /// Every script `nft` was handed: the cut, when there was one.
        fn cuts(&self) -> Vec<String> {
            self.nft.0.lock().unwrap().clone()
        }

        /// Every report the guest sent the broker, as JSON.
        fn sent(&self) -> Vec<String> {
            self.sink.sent.lock().unwrap().clone()
        }
    }

    impl Harness {
        /// The proxy for `routes`, armed with `traps` as the guest arms it: the tripwire's tasks, the trap socket (its
        /// peer admitted by the test's own uid), the proxy connecting, reading the draw and answering `armed`.
        async fn start_armed(
            &self,
            routes: Vec<mediatore_proto::Route>,
            claim_uid: &uuid::Uuid,
            traps: ProxyTraps,
            denied: DeniedSwitches,
        ) -> Armed {
            use std::os::unix::fs::MetadataExt as _;
            let dir = tempfile::tempdir().expect("a short directory for the socket");
            let uid = std::fs::metadata(dir.path()).expect("stat").uid();
            let nft = Arc::new(RecordingNft::default());
            let sink = Arc::new(DevTripSink {
                sandbox_url: self.sandbox_url.clone(),
                http: reqwest::Client::new(),
                sent: Mutex::new(Vec::new()),
            });
            let wire = trip::start_with(
                traps.mode,
                denied,
                uid,
                sink.clone(),
                nft.clone(),
                Timing {
                    fold: Duration::from_millis(50),
                    ..Timing::default()
                },
            );
            let mut socket =
                trip::serve_socket(&dir.path().join("trap"), uid, traps, wire.trips.clone())
                    .await
                    .expect("the trap socket");
            let (handed, pending) = TrapLink::connect(socket.path())
                .await
                .expect("the proxy is handed the draw");
            let routes = Routes::new(routes).expect("routes");
            let plan = TrapPlan::new(&handed, &routes).expect("a plan");
            let link = pending.armed(plan.patterns()).await.expect("armed");
            socket
                .armed(Duration::from_secs(5))
                .await
                .expect("the guest heard `armed`");
            let tokens = Arc::new(DevTokens {
                sandbox_url: self.sandbox_url.clone(),
                claim_svid: format!("spiffe://{TRUST_DOMAIN}/banlieue/claim/{claim_uid}"),
                http: reqwest::Client::new(),
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            let phantom = Phantom::generate().expect("phantom");
            let proxy = Arc::new(
                Proxy::with_webpki_roots(routes, phantom.clone(), tokens, Dialer::Direct)
                    .expect("a proxy from the claim's routes")
                    .with_traps(plan, link),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind proxy");
            let url = format!("http://{}", listener.local_addr().expect("addr"));
            tokio::spawn(proxy.serve(listener));
            Armed {
                proxy: url,
                phantom,
                wire,
                nft,
                sink,
                uid,
                _socket: socket,
                _dir: dir,
            }
        }

        async fn claim_now(&self, name: &str) -> ClaimResponse {
            self.http
                .get(format!("{}/v1/claims/{name}", self.user_url))
                .bearer_auth(self.login("octocat"))
                .send()
                .await
                .expect("get claim")
                .json()
                .await
                .expect("claim body")
        }

        /// The claim once `ready` holds of it, at most ten seconds on.
        async fn claim_when(
            &self,
            name: &str,
            ready: impl Fn(&ClaimResponse) -> bool,
        ) -> ClaimResponse {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let claim = self.claim_now(name).await;
                if ready(&claim) {
                    return claim;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the broker did not record the trip in time"
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }

        /// The folded entries of the claim, latest first.
        fn entries(claim: &ClaimResponse) -> Vec<TripEntry> {
            claim
                .tripwires
                .as_ref()
                .map(|t| t.entries.clone())
                .unwrap_or_default()
        }
    }

    /// A harness, a claim for both audiences and its routes, under the broker's `mode`.
    async fn claimed(
        mode: TrapsMode,
        denied: DeniedSwitches,
    ) -> (Harness, ClaimResponse, Vec<mediatore_proto::Route>) {
        let h = Harness::start_with(broker(mode, denied)).await;
        h.register_node().await;
        let claim = h.claim_with(&[AUDIENCE, KEYED]).await;
        let me = h.me().await;
        (h, claim, me.routes)
    }

    fn trip_mode(mode: TrapsMode) -> TripMode {
        mode.trip_mode().expect("shadow or enforce")
    }

    /// Where the workload puts the bait.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Position {
        Header,
        Query,
        Body,
        GzipBody,
    }

    /// The request that carries the bait in `position`, on the token route, within its rules.
    async fn send_bait(h: &Harness, armed: &Armed, position: Position) -> reqwest::Response {
        let host = h.upstream.endpoint().to_string();
        let request = match position {
            Position::Header => h
                .http
                .get(format!("{}/{host}/api/things", armed.proxy))
                .header("x-notes", BAIT),
            Position::Query => h.http.get(format!(
                "{}/{host}/api/things?access_key={BAIT}",
                armed.proxy
            )),
            Position::Body => h
                .http
                .post(format!("{}/{host}/api/things/7/notes", armed.proxy))
                .body(BAIT_BODY),
            Position::GzipBody => h
                .http
                .post(format!("{}/{host}/api/things/7/notes", armed.proxy))
                .header("content-encoding", "gzip")
                .body(unbase64(BAIT_BODY_GZIP)),
        };
        request
            .bearer_auth(armed.phantom.expose())
            .send()
            .await
            .expect("through the proxy")
    }

    async fn error_code(resp: reqwest::Response) -> (u16, String) {
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        (
            status,
            body["error"].as_str().unwrap_or_default().to_owned(),
        )
    }

    fn carries_bait(seen: &Seen) -> bool {
        seen.path_and_query.contains(BAIT)
            || seen.headers.iter().any(|(_, v)| v.contains(BAIT))
            || String::from_utf8_lossy(&seen.body).contains(BAIT)
            || seen.body == unbase64(BAIT_BODY_GZIP)
    }

    /// Under `enforce`: the request is `403 trap`, the bait reaches no upstream, the sandbox uid is cut, the claim is
    /// ended at the broker with the trap named, its token is refused, and nothing more is forwarded.
    async fn bait_trips_under_enforce(position: Position) {
        let (h, claim, routes) = claimed(TrapsMode::Enforce, DeniedSwitches::default()).await;
        let uid = claim.uid.expect("uid");
        let armed = h
            .start_armed(
                routes,
                &uid,
                hand_drawn(TripMode::Enforce, ClassAction::Report),
                DeniedSwitches::default(),
            )
            .await;
        let resp = send_bait(&h, &armed, position).await;
        assert_eq!(error_code(resp).await, (403, "trap".to_owned()));
        let seen = h.seen();
        assert!(
            !seen.iter().any(carries_bait),
            "the bait reached the upstream"
        );
        match position {
            Position::Header | Position::Query => {
                assert!(seen.is_empty(), "bait in the head opens no upstream");
            }
            Position::Body | Position::GzipBody => assert!(
                seen.iter().all(|s| !s.complete),
                "the upstream saw a whole request"
            ),
        }
        // The guest: cut first, then the report; the broker: the claim ended, the trap on the record.
        let ended = h.claim_when(&claim.name, |c| c.tripped.is_some()).await;
        let tripped = ended.tripped.clone().expect("tripped");
        assert_eq!(
            (tripped.kind, tripped.trap.as_deref(), tripped.source),
            (TripKind::Credential, Some("aws"), TripSource::Workload)
        );
        assert_eq!(
            tripped.target,
            Some(TripTarget::Host(h.upstream.endpoint().host)),
            "the host of the route the bait was sent to"
        );
        assert!(!ended.ready);
        assert_eq!(
            armed.cuts(),
            [trip::drop_all_ruleset(armed.uid)],
            "one nft transaction: the drop of everything the sandbox uid sends"
        );
        assert!(armed.wire.trips.is_tripped());
        let entries = Harness::entries(&ended);
        assert!(
            entries
                .iter()
                .any(|e| e.effect == TripEffect::Tripped && e.kind == TripKind::Credential),
            "the folded event that ended the claim is shown"
        );
        // The tripped claim's token is refused.
        let token = h
            .http
            .post(format!("{}/v1/token", h.sandbox_url))
            .header(
                PEER_HEADER,
                format!("spiffe://{TRUST_DOMAIN}/banlieue/claim/{uid}"),
            )
            .json(&TokenRequest {
                audience: AUDIENCE.to_owned(),
            })
            .send()
            .await
            .expect("token");
        assert!(
            !token.status().is_success(),
            "a tripped claim was served a token"
        );
        // And the proxy forwards nothing more, whatever is asked.
        let before = h.seen().len();
        let host = h.upstream.endpoint().to_string();
        let clean = h
            .http
            .get(format!("{}/{host}/api/things", armed.proxy))
            .bearer_auth(armed.phantom.expose())
            .send()
            .await
            .expect("after the trip");
        assert_eq!(error_code(clean).await, (403, "trap".to_owned()));
        assert_eq!(
            h.seen().len(),
            before,
            "a request was forwarded after the trip"
        );
    }

    /// Under `shadow`: the request is forwarded exactly as it came, nothing is cut or ended, and the use is on the
    /// claim as `would_trip`.
    async fn bait_would_trip_under_shadow(position: Position) {
        let (h, claim, routes) = claimed(TrapsMode::Shadow, DeniedSwitches::default()).await;
        let uid = claim.uid.expect("uid");
        let armed = h
            .start_armed(
                routes,
                &uid,
                hand_drawn(TripMode::Shadow, ClassAction::Report),
                DeniedSwitches::default(),
            )
            .await;
        let resp = send_bait(&h, &armed, position).await;
        assert_eq!(resp.status(), 200, "shadow forwards");
        assert_eq!(resp.text().await.unwrap(), "upstream answered");
        let seen = h.seen();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].complete);
        match position {
            Position::Header => assert!(
                seen[0]
                    .headers
                    .iter()
                    .any(|(n, v)| n == "x-notes" && v == BAIT),
                "the header crossed as sent"
            ),
            Position::Query => assert_eq!(
                seen[0].path_and_query,
                format!("/api/things?access_key={BAIT}")
            ),
            Position::Body => assert_eq!(seen[0].body, BAIT_BODY.as_bytes()),
            Position::GzipBody => assert_eq!(seen[0].body, unbase64(BAIT_BODY_GZIP)),
        }
        let shown = h
            .claim_when(&claim.name, |c| !Harness::entries(c).is_empty())
            .await;
        let entries = Harness::entries(&shown);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            (
                entries[0].effect,
                entries[0].kind,
                entries[0].trap.as_deref(),
                entries[0].count
            ),
            (TripEffect::WouldTrip, TripKind::Credential, Some("aws"), 1)
        );
        assert!(shown.tripped.is_none(), "nothing is ended under shadow");
        assert!(armed.cuts().is_empty(), "nothing is cut under shadow");
        assert!(!armed.wire.trips.is_tripped());
        // The next request is forwarded as ever.
        let host = h.upstream.endpoint().to_string();
        let clean = h
            .http
            .get(format!("{}/{host}/api/things", armed.proxy))
            .bearer_auth(armed.phantom.expose())
            .send()
            .await
            .expect("after the use");
        assert_eq!(clean.status(), 200);
    }

    #[tokio::test]
    async fn bait_in_a_header_trips_and_never_reaches_the_upstream() {
        bait_trips_under_enforce(Position::Header).await;
        bait_would_trip_under_shadow(Position::Header).await;
    }

    #[tokio::test]
    async fn bait_in_the_query_trips() {
        bait_trips_under_enforce(Position::Query).await;
        bait_would_trip_under_shadow(Position::Query).await;
    }

    #[tokio::test]
    async fn bait_in_a_body_trips_and_the_upstream_sees_an_incomplete_request_without_the_value() {
        bait_trips_under_enforce(Position::Body).await;
        bait_would_trip_under_shadow(Position::Body).await;
    }

    #[tokio::test]
    async fn bait_in_a_gzip_body_trips() {
        bait_trips_under_enforce(Position::GzipBody).await;
        bait_would_trip_under_shadow(Position::GzipBody).await;
    }

    #[tokio::test]
    async fn a_long_body_is_forwarded_up_to_the_bait_and_never_the_bait() {
        // The body streamed through the matcher: what precedes the value may leave, the value does not, and the
        // upstream is left with a request that never ends.
        let (h, claim, routes) = claimed(TrapsMode::Enforce, DeniedSwitches::default()).await;
        let armed = h
            .start_armed(
                routes,
                &claim.uid.expect("uid"),
                hand_drawn(TripMode::Enforce, ClassAction::Report),
                DeniedSwitches::default(),
            )
            .await;
        let host = h.upstream.endpoint().to_string();
        let mut body = "an honest line of a long upload\n".repeat(16 * 1024);
        body.push_str(BAIT);
        body.push_str(&"and more after it\n".repeat(1024));
        let resp = h
            .http
            .post(format!("{}/{host}/api/things/7/notes", armed.proxy))
            .bearer_auth(armed.phantom.expose())
            .body(body)
            .send()
            .await
            .expect("through the proxy");
        assert_eq!(error_code(resp).await, (403, "trap".to_owned()));
        let seen = h.seen();
        assert!(!seen.iter().any(carries_bait), "the bait left the VM");
        assert!(
            seen.iter().all(|s| !s.complete),
            "the request ended upstream"
        );
        assert!(
            seen.iter()
                .all(|s| !String::from_utf8_lossy(&s.body).contains("and more after it")),
            "something after the bait was forwarded"
        );
        h.claim_when(&claim.name, |c| c.tripped.is_some()).await;
    }

    #[tokio::test]
    async fn bait_in_a_model_api_body_trips_nothing_and_in_its_authorization_trips() {
        let (h, claim, routes) = claimed(TrapsMode::Enforce, DeniedSwitches::default()).await;
        let model = routes
            .iter()
            .find(|r| r.audience.as_deref() == Some(KEYED))
            .expect("the keyed audience's route");
        assert_eq!(
            model.traps_body,
            TrapsBody::Skip,
            "the broker's mark reaches the route in GET /v1/me"
        );
        assert!(
            routes
                .iter()
                .filter(|r| r.audience.as_deref() == Some(AUDIENCE))
                .all(|r| r.traps_body == TrapsBody::Match),
            "every other route's body is matched"
        );
        let armed = h
            .start_armed(
                routes.clone(),
                &claim.uid.expect("uid"),
                hand_drawn(TripMode::Enforce, ClassAction::Report),
                DeniedSwitches::default(),
            )
            .await;
        let host = h.keyed_upstream.endpoint().to_string();
        // The agent telling its model what it read: discovery, not use.
        let conversation = format!(
            r#"{{"messages":[{{"role":"user","content":"~/.aws/credentials holds {BAIT}"}}]}}"#
        );
        let resp = h
            .http
            .post(format!("{}/{host}/v1/messages", armed.proxy))
            .bearer_auth(armed.phantom.expose())
            .body(conversation.clone())
            .send()
            .await
            .expect("the conversation");
        assert_eq!(resp.status(), 200);
        let seen = h.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].body,
            conversation.as_bytes(),
            "forwarded as it came"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(armed.sent().is_empty(), "nothing was reported");
        assert!(armed.cuts().is_empty(), "something was cut");
        assert!(h.claim_now(&claim.name).await.tripped.is_none());
        // The head of that same route still counts.
        let resp = h
            .http
            .post(format!("{}/{host}/v1/messages", armed.proxy))
            .header("authorization", format!("Bearer {BAIT}"))
            .body("{}")
            .send()
            .await
            .expect("bait in Authorization");
        assert_eq!(error_code(resp).await, (403, "trap".to_owned()));
        assert_eq!(h.seen().len(), 1, "it went nowhere");
        let ended = h.claim_when(&claim.name, |c| c.tripped.is_some()).await;
        assert_eq!(
            ended.tripped.map(|t| (t.kind, t.trap)),
            Some((TripKind::Credential, Some("aws".to_owned())))
        );
    }

    #[tokio::test]
    async fn a_decoy_route_trips_and_is_never_tunnelled() {
        for mode in [TrapsMode::Enforce, TrapsMode::Shadow] {
            let (h, claim, routes) = claimed(mode, DeniedSwitches::default()).await;
            let armed = h
                .start_armed(
                    routes,
                    &claim.uid.expect("uid"),
                    hand_drawn(trip_mode(mode), ClassAction::Report),
                    DeniedSwitches::default(),
                )
                .await;
            let resp = h
                .http
                .get(format!("{}/{DECOY}/v1/secret/data/prod", armed.proxy))
                .bearer_auth(armed.phantom.expose())
                .send()
                .await
                .expect("the decoy");
            let answer = error_code(resp).await;
            assert!(h.seen().is_empty(), "no upstream saw a connection");
            if mode == TrapsMode::Enforce {
                assert_eq!(answer, (403, "trap".to_owned()));
                let ended = h.claim_when(&claim.name, |c| c.tripped.is_some()).await;
                let tripped = ended.tripped.expect("tripped");
                assert_eq!(
                    (tripped.kind, tripped.trap.as_deref(), tripped.source),
                    (TripKind::Route, Some("vault"), TripSource::Drawn)
                );
                assert_eq!(tripped.target, Some(TripTarget::Host(DECOY.to_owned())));
                assert_eq!(armed.cuts().len(), 1);
            } else {
                assert_eq!(
                    answer,
                    (404, "no_route".to_owned()),
                    "what any unknown host gets"
                );
                let shown = h
                    .claim_when(&claim.name, |c| !Harness::entries(c).is_empty())
                    .await;
                let entries = Harness::entries(&shown);
                assert_eq!(
                    (
                        entries[0].effect,
                        entries[0].kind,
                        entries[0].trap.as_deref()
                    ),
                    (TripEffect::WouldTrip, TripKind::Route, Some("vault"))
                );
                assert!(shown.tripped.is_none());
                assert!(armed.cuts().is_empty(), "something was cut");
            }
        }
    }

    #[tokio::test]
    async fn an_unknown_host_is_the_same_404_as_before_and_a_denied_event() {
        // With no tripwire: the answer to compare with.
        let (plain, plain_claim, plain_routes) =
            claimed(TrapsMode::Off, DeniedSwitches::default()).await;
        let (unarmed, phantom, _) = plain
            .start_proxy(plain_routes, &plain_claim.uid.expect("uid"))
            .await;
        let before = plain
            .http
            .get(format!("{unarmed}/Mirror.Example:8443/simple/pkg?q=1"))
            .bearer_auth(phantom.expose())
            .send()
            .await
            .expect("unknown host, unarmed");
        let before = (
            before.status(),
            before.headers().get("content-type").cloned(),
            before.bytes().await.unwrap(),
        );
        for mode in [TrapsMode::Shadow, TrapsMode::Enforce] {
            let (h, claim, routes) = claimed(mode, DeniedSwitches::default()).await;
            let armed = h
                .start_armed(
                    routes,
                    &claim.uid.expect("uid"),
                    hand_drawn(trip_mode(mode), ClassAction::Report),
                    DeniedSwitches::default(),
                )
                .await;
            for _ in 0..3 {
                let after = h
                    .http
                    .get(format!(
                        "{}/Mirror.Example:8443/simple/pkg?q=1",
                        armed.proxy
                    ))
                    .bearer_auth(armed.phantom.expose())
                    .send()
                    .await
                    .expect("unknown host, armed");
                let after = (
                    after.status(),
                    after.headers().get("content-type").cloned(),
                    after.bytes().await.unwrap(),
                );
                assert_eq!(after, before, "the answer changed");
            }
            assert_eq!(before.0, 404);
            let shown = h
                .claim_when(&claim.name, |c| {
                    Harness::entries(c).iter().map(|e| e.count).sum::<u64>() == 3
                })
                .await;
            let entries = Harness::entries(&shown);
            assert_eq!(entries.len(), 1, "repeats fold into one entry");
            assert_eq!(
                (
                    entries[0].effect,
                    entries[0].kind,
                    entries[0].class,
                    entries[0].trap.as_deref()
                ),
                (
                    TripEffect::Reported,
                    TripKind::Denied,
                    Some(TripClass::UnknownHost),
                    None
                ),
                "at its default switch the class is reported and ends nothing, under either mode"
            );
            assert_eq!(
                entries[0].target,
                Some(TripTarget::Host("mirror.example".to_owned())),
                "the host alone: no port, no path, no query"
            );
            assert!(shown.tripped.is_none());
            assert!(armed.cuts().is_empty(), "something was cut");
            assert!(h.seen().is_empty());
        }
    }

    #[tokio::test]
    async fn an_unknown_host_ends_the_claim_once_its_class_is_switched_to_trip() {
        let denied = DeniedSwitches {
            unknown_host: ClassAction::Trip,
            ..DeniedSwitches::default()
        };
        let (h, claim, routes) = claimed(TrapsMode::Enforce, denied).await;
        let armed = h
            .start_armed(
                routes,
                &claim.uid.expect("uid"),
                hand_drawn(TripMode::Enforce, ClassAction::Trip),
                denied,
            )
            .await;
        let resp = h
            .http
            .get(format!("{}/mirror.example/simple/pkg", armed.proxy))
            .send()
            .await
            .expect("unknown host");
        assert_eq!(error_code(resp).await, (404, "no_route".to_owned()));
        let ended = h.claim_when(&claim.name, |c| c.tripped.is_some()).await;
        assert_eq!(
            ended.tripped.map(|t| (t.kind, t.class)),
            Some((TripKind::Denied, Some(TripClass::UnknownHost)))
        );
        assert_eq!(armed.cuts().len(), 1);
        let host = h.upstream.endpoint().to_string();
        let after = h
            .http
            .get(format!("{}/{host}/api/things", armed.proxy))
            .bearer_auth(armed.phantom.expose())
            .send()
            .await
            .expect("after the trip");
        assert_eq!(error_code(after).await, (403, "trap".to_owned()));
        assert!(h.seen().is_empty());
    }

    /// One request as the upstream received it: the method, the path and query, the headers, the body, and whether
    /// the body ended.
    type Received = (String, String, Vec<(String, String)>, Vec<u8>, bool);

    /// What the upstream received of the legitimate requests, without what differs from one harness to the next (the
    /// minted token and the upstream's own port).
    fn comparable(seen: &[Seen]) -> Vec<Received> {
        seen.iter()
            .map(|s| {
                let headers = s
                    .headers
                    .iter()
                    .filter(|(name, _)| name != "authorization" && name != "host")
                    .cloned()
                    .collect();
                (
                    s.method.clone(),
                    s.path_and_query.clone(),
                    headers,
                    s.body.clone(),
                    s.complete,
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn a_legitimate_route_is_unchanged_with_traps_armed() {
        // The same honest requests under off, shadow and enforce: what the upstream receives and what the workload
        // gets back are the same, byte for byte.
        let upload: Vec<u8> = (0..300_000u32)
            .map(|i| u8::try_from(i.wrapping_mul(2_654_435_761) >> 24).unwrap_or(0))
            .collect();
        let mut received = Vec::new();
        for mode in [TrapsMode::Off, TrapsMode::Shadow, TrapsMode::Enforce] {
            let (h, claim, routes) = claimed(mode, DeniedSwitches::default()).await;
            let uid = claim.uid.expect("uid");
            let (proxy, phantom, armed) = match mode.trip_mode() {
                None => {
                    let (proxy, phantom, _) = h.start_proxy(routes, &uid).await;
                    (proxy, phantom, None)
                }
                Some(mode) => {
                    let armed = h
                        .start_armed(
                            routes,
                            &uid,
                            hand_drawn(mode, ClassAction::Report),
                            DeniedSwitches::default(),
                        )
                        .await;
                    (armed.proxy.clone(), armed.phantom.clone(), Some(armed))
                }
            };
            let host = h.upstream.endpoint().to_string();
            let keyed = h.keyed_upstream.endpoint().to_string();
            let mut answers = Vec::new();
            let get = h
                .http
                .get(format!("{proxy}/{host}/api/things?page=2&filter=a%20b"))
                .bearer_auth(phantom.expose())
                .header("accept", "application/json")
                .header("x-request-note", "an honest header")
                .send()
                .await
                .expect("get");
            answers.push((get.status().as_u16(), get.bytes().await.unwrap()));
            let post = h
                .http
                .post(format!("{proxy}/{host}/api/things/7/notes"))
                .bearer_auth(phantom.expose())
                .header("content-type", "application/octet-stream")
                .body(upload.clone())
                .send()
                .await
                .expect("post");
            answers.push((post.status().as_u16(), post.bytes().await.unwrap()));
            let gz = h
                .http
                .post(format!("{proxy}/{host}/api/things/8/notes"))
                .bearer_auth(phantom.expose())
                .header("content-encoding", "gzip")
                .body(unbase64(HONEST_GZIP))
                .send()
                .await
                .expect("an honest compressed upload");
            answers.push((gz.status().as_u16(), gz.bytes().await.unwrap()));
            let model = h
                .http
                .post(format!("{proxy}/{keyed}/v1/messages"))
                .bearer_auth(phantom.expose())
                .header("content-type", "application/json")
                .body(r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#)
                .send()
                .await
                .expect("model");
            answers.push((model.status().as_u16(), model.bytes().await.unwrap()));
            assert!(answers.iter().all(|(status, _)| *status == 200));
            let seen = h.seen();
            assert_eq!(seen.len(), 4);
            assert!(seen.iter().all(|s| s.complete));
            assert_eq!(seen[1].body, upload, "the upload crossed whole");
            assert_eq!(
                seen[2].body,
                unbase64(HONEST_GZIP),
                "compressed, as it came"
            );
            received.push((comparable(&seen), answers));
            if let Some(armed) = armed {
                tokio::time::sleep(Duration::from_millis(200)).await;
                assert!(armed.cuts().is_empty(), "an honest run cut nothing");
                assert!(h.claim_now(&claim.name).await.tripped.is_none());
            }
        }
        assert_eq!(received[0], received[1], "shadow changed an honest request");
        assert_eq!(
            received[0], received[2],
            "enforce changed an honest request"
        );
    }

    #[tokio::test]
    async fn a_body_the_matcher_cannot_finish_is_refused_under_enforce_and_ends_nothing() {
        // The maintainer's decision 4 of 2026-11-27: a compressed body past the expansion bound is 413 and one that
        // does not decode is 400; neither is a trip, under either mode; nothing unscanned is forwarded under enforce.
        let cases = [
            (unbase64(BOMB_GZIP), 413, "body_expansion"),
            (
                b"not gzip, whatever the header says: an honest client's bug".to_vec(),
                400,
                "body_undecodable",
            ),
        ];
        for (wire, status, code) in cases {
            for mode in [TrapsMode::Enforce, TrapsMode::Shadow] {
                let (h, claim, routes) = claimed(mode, DeniedSwitches::default()).await;
                let armed = h
                    .start_armed(
                        routes,
                        &claim.uid.expect("uid"),
                        hand_drawn(trip_mode(mode), ClassAction::Report),
                        DeniedSwitches::default(),
                    )
                    .await;
                let host = h.upstream.endpoint().to_string();
                let resp = h
                    .http
                    .post(format!("{}/{host}/api/things/7/notes", armed.proxy))
                    .bearer_auth(armed.phantom.expose())
                    .header("content-encoding", "gzip")
                    .body(wire.clone())
                    .send()
                    .await
                    .expect("through the proxy");
                if mode == TrapsMode::Enforce {
                    assert_eq!(error_code(resp).await, (status, code.to_owned()));
                    assert!(
                        h.seen().iter().all(|s| !s.complete && s.body != wire),
                        "the body the matcher could not finish reached the upstream whole"
                    );
                } else {
                    assert_eq!(resp.status(), 200, "shadow forwards what came");
                    let seen = h.seen();
                    assert_eq!(seen.len(), 1);
                    assert_eq!(seen[0].body, wire);
                }
                // The guest was told, and decided: nothing cut, nothing ended, nothing sent to the broker.
                assert!(armed.wire.trips.flush(Duration::from_secs(5)).await);
                assert!(armed.cuts().is_empty(), "something was cut");
                assert!(!armed.wire.trips.is_tripped());
                assert!(armed.sent().is_empty(), "it was reported to the broker");
                let shown = h.claim_now(&claim.name).await;
                assert!(shown.tripped.is_none() && Harness::entries(&shown).is_empty());
                // And the claim goes on.
                let before = h.seen().len();
                let clean = h
                    .http
                    .get(format!("{}/{host}/api/things", armed.proxy))
                    .bearer_auth(armed.phantom.expose())
                    .send()
                    .await
                    .expect("the next request");
                assert_eq!(clean.status(), 200);
                assert_eq!(h.seen().len(), before + 1);
            }
        }
    }

    #[tokio::test]
    async fn a_trip_at_the_proxy_ends_the_claim_at_the_broker() {
        // The whole chain once more, looked at from the broker: proxy, socket, guest, `POST /v1/me/trip`, record.
        let (h, claim, routes) = claimed(TrapsMode::Enforce, DeniedSwitches::default()).await;
        let before = h.claim_now(&claim.name).await;
        assert!(before.tripped.is_none() && before.tripwires.is_none());
        let armed = h
            .start_armed(
                routes,
                &claim.uid.expect("uid"),
                hand_drawn(TripMode::Enforce, ClassAction::Report),
                DeniedSwitches::default(),
            )
            .await;
        let _ = send_bait(&h, &armed, Position::Header).await;
        tokio::time::timeout(Duration::from_secs(10), armed.wire.trips.reported())
            .await
            .expect("the broker acknowledged the report");
        let ended = h.claim_now(&claim.name).await;
        assert!(ended.tripped.is_some());
        let sent = armed.sent();
        assert!(!sent.is_empty(), "nothing was reported");
        let report: TripReport = serde_json::from_str(&sent[0]).expect("a report");
        assert_eq!(report.mode, TripMode::Enforce);
        assert_eq!(report.validate(), Ok(()));
        assert!(
            report.events[0].containment_ms.is_some(),
            "the time from the proxy's verdict to the end of the cut is in the report"
        );
        // The node no longer has a claim.
        let me = h
            .http
            .get(format!("{}/v1/me", h.sandbox_url))
            .header(
                PEER_HEADER,
                format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{EK_HASH}"),
            )
            .send()
            .await
            .expect("me");
        assert_eq!(me.status(), 404);
    }

    #[tokio::test]
    async fn the_tripped_claims_token_is_refused() {
        // A token fetched before the trip does not make the next fetch succeed: the proxy's own source is refused.
        let (h, claim, routes) = claimed(TrapsMode::Enforce, DeniedSwitches::default()).await;
        let uid = claim.uid.expect("uid");
        let fetch = || async {
            h.http
                .post(format!("{}/v1/token", h.sandbox_url))
                .header(
                    PEER_HEADER,
                    format!("spiffe://{TRUST_DOMAIN}/banlieue/claim/{uid}"),
                )
                .json(&TokenRequest {
                    audience: AUDIENCE.to_owned(),
                })
                .send()
                .await
                .expect("token")
                .status()
        };
        assert_eq!(fetch().await, 200, "before the trip the claim is served");
        let armed = h
            .start_armed(
                routes,
                &uid,
                hand_drawn(TripMode::Enforce, ClassAction::Report),
                DeniedSwitches::default(),
            )
            .await;
        let _ = send_bait(&h, &armed, Position::Query).await;
        h.claim_when(&claim.name, |c| c.tripped.is_some()).await;
        assert!(
            !fetch().await.is_success(),
            "a tripped claim was served a token"
        );
    }

    fn percent(value: &str) -> String {
        use std::fmt::Write as _;
        value.bytes().fold(String::new(), |mut out, b| {
            if b.is_ascii_alphanumeric() {
                out.push(char::from(b));
            } else {
                let _ = write!(out, "%{b:02X}");
            }
            out
        })
    }

    /// `data` as a gzip member of stored (uncompressed) deflate blocks: a body the proxy must decode to scan, built
    /// without a compressor.
    fn gzip_stored(data: &[u8]) -> Vec<u8> {
        let mut crc = !0u32;
        for byte in data {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
        let mut chunks: Vec<&[u8]> = data.chunks(0xffff).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        for (i, chunk) in chunks.iter().enumerate() {
            let len = u16::try_from(chunk.len()).expect("a stored block's length");
            out.push(u8::from(i + 1 == chunks.len()));
            out.extend(len.to_le_bytes());
            out.extend((!len).to_le_bytes());
            out.extend_from_slice(chunk);
        }
        out.extend((!crc).to_le_bytes());
        out.extend(u32::try_from(data.len()).expect("small").to_le_bytes());
        out
    }

    #[test]
    fn the_stored_gzip_of_the_canary_is_a_gzip_member() {
        // The empty member, as RFC 1952 and RFC 1951 lay it out: header, one final stored block of length 0, CRC, size.
        assert_eq!(
            gzip_stored(b""),
            [
                0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 1, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        // CRC-32 of "123456789" is the standard check value.
        let member = gzip_stored(b"123456789");
        assert_eq!(
            member[member.len() - 8..member.len() - 4],
            0xCBF4_3926u32.to_le_bytes()
        );
    }

    /// One request for each position the proxy checks, with `value` in it: the path, the query, a Basic pair, any
    /// header, a credential header, a bearer, a body and a gzip body on the matched route, a body on the model's; and
    /// the refusals that have a log line of their own (outside the rules, an unknown host, the decoy route `decoy`).
    fn plants(
        h: &Harness,
        armed: &Armed,
        decoy: &str,
        value: &str,
    ) -> Vec<reqwest::RequestBuilder> {
        let host = h.upstream.endpoint().to_string();
        let keyed = h.keyed_upstream.endpoint().to_string();
        let base = &armed.proxy;
        let encoded = percent(value);
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("git:{value}"));
        // First, the positions S4 and S3 of the review found (under enforce only the first request of a run reaches
        // the traps: every later one is `403 trap` at once): the value as the first path segment, which names no
        // route, then as the method and as a header name where it can be one.
        let mut requests = vec![h.http.get(format!("{base}/{encoded}/x?k=1"))];
        if value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            requests.push(h.http.get(format!("{base}/{value}/x")));
        }
        if let Ok(method) = reqwest::Method::from_bytes(value.as_bytes()) {
            requests.push(
                h.http
                    .request(method, format!("{base}/{host}/api/things"))
                    .bearer_auth(armed.phantom.expose()),
            );
        }
        if let Ok(name) = reqwest::header::HeaderName::from_bytes(value.as_bytes()) {
            requests.push(
                h.http
                    .get(format!("{base}/{host}/api/things"))
                    .bearer_auth(armed.phantom.expose())
                    .header(name, "1"),
            );
        }
        requests.extend([
            h.http.get(format!("{base}/{host}/api/{encoded}/x")),
            h.http.get(format!("{base}/{host}/api/things?k={encoded}")),
            h.http
                .get(format!("{base}/{host}/admin/{encoded}?k={encoded}")),
            h.http
                .get(format!("{base}/nowhere.example/{encoded}?k={encoded}")),
            h.http.get(format!("{base}/{decoy}/{encoded}?k={encoded}")),
            h.http
                .get(format!("{base}/{host}/api/things"))
                .header("authorization", format!("Basic {basic}")),
            h.http
                .post(format!("{base}/{host}/api/things/7/notes"))
                .bearer_auth(armed.phantom.expose())
                .body(format!("token = {value}\n")),
            h.http
                .post(format!("{base}/{host}/api/things/8/notes"))
                .bearer_auth(armed.phantom.expose())
                .header("content-encoding", "gzip")
                .body(gzip_stored(format!("secret: {value}\n").as_bytes())),
            h.http
                .post(format!("{base}/{keyed}/v1/messages"))
                .bearer_auth(armed.phantom.expose())
                .body(format!("{{\"content\":{}}}", serde_json::json!(value))),
        ]);
        // Headers, where the value can be one.
        if reqwest::header::HeaderValue::from_str(value).is_ok() {
            for (name, sent) in [
                ("x-notes", value.to_owned()),
                ("x-api-key", value.to_owned()),
                ("authorization", format!("Bearer {value}")),
            ] {
                requests.push(
                    h.http
                        .get(format!("{base}/{host}/api/things"))
                        .header(name, sent),
                );
            }
        }
        requests
    }

    #[tokio::test]
    async fn the_bait_canary_scan() {
        // ADR-0069 decision 12: a real draw's bait planted in every position the proxy checks, under shadow (every
        // request runs its whole course through the proxy's log lines) and then under enforce. Nothing the proxy,
        // the guest's tripwire or the broker logs at any level, no report to the broker and nothing the claim shows
        // carries a value.
        crate::e2e_dev::logs::capture();
        for mode in [TrapsMode::Shadow, TrapsMode::Enforce] {
            let (h, claim, routes) = claimed(mode, DeniedSwitches::default()).await;
            let drawn = mediatore_guest::draw::draw(
                &mut mediatore_guest::draw::OsEntropy,
                &mediatore_guest::draw::DrawInputs {
                    routes: &routes,
                    proxy_port: 3128,
                    pull_port: 18129,
                    reserved_ports: &[3128],
                    reserved_env: &["HOME", "MEDIATORE_TOKEN", "MEDIATORE_EGRESS_PROXY"],
                    catalogue: None,
                    metadata: false,
                },
            )
            .expect("a draw");
            let values = drawn.secret_values();
            assert!(
                values.len() >= 3,
                "a draw has at least three bait credentials"
            );
            let armed = h
                .start_armed(
                    routes,
                    &claim.uid.expect("uid"),
                    drawn.proxy_traps(trip_mode(mode), ClassAction::Report),
                    DeniedSwitches::default(),
                )
                .await;
            for value in &values {
                for request in plants(&h, &armed, &drawn.routes[0].host, value) {
                    let _ = request.send().await.expect("the proxy answers");
                }
            }
            assert!(
                armed.wire.trips.flush(Duration::from_secs(10)).await
                    || armed.wire.trips.is_tripped()
            );
            if mode == TrapsMode::Enforce {
                h.claim_when(&claim.name, |c| c.tripped.is_some()).await;
            } else {
                h.claim_when(&claim.name, |c| !Harness::entries(c).is_empty())
                    .await;
            }
            let lines = crate::e2e_dev::logs::captured();
            assert!(
                lines.contains("a trap was used") || lines.contains("trip reported"),
                "the lines of this run were not captured"
            );
            let shown = serde_json::to_string(&h.claim_now(&claim.name).await).expect("json");
            let sent = armed.sent();
            assert!(!sent.is_empty(), "something was reported");
            for value in &values {
                let forms = [
                    value.clone(),
                    // What hyper makes of a header name, and of the segment a host is read from.
                    value.to_ascii_lowercase(),
                    percent(value),
                    base64::engine::general_purpose::STANDARD.encode(value),
                    base64::engine::general_purpose::STANDARD.encode(format!("git:{value}")),
                ];
                for form in &forms {
                    assert!(
                        !lines.contains(form.as_str()),
                        "a bait value is in a log line"
                    );
                    assert!(
                        !sent.iter().any(|report| report.contains(form.as_str())),
                        "a bait value is in a report to the broker"
                    );
                    assert!(
                        !shown.contains(form.as_str()),
                        "a bait value is on the claim"
                    );
                }
            }
            assert!(
                !lines.contains(armed.phantom.expose()),
                "the phantom is in a log line"
            );
            assert!(!lines.contains("?k="), "a query is in a log line");
        }
    }
}
