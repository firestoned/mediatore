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
use chrono::Duration;
use mediatore_api::{AppState, Limiter};
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
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Seen>>>);

async fn record(
    State(rec): State<Recorder>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    let seen = Seen {
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
    rec.0.lock().unwrap().push(seen);
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
fn state(idp: &FakeIdp, upstream: &TlsUpstream, keyed_upstream: &TlsUpstream) -> Arc<AppState> {
    let sts = Sts::new(
        "https://mediatore.test",
        "e2e-1",
        STS_TEST_KEY.as_bytes(),
        Duration::minutes(15),
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
            session: None,
            ca_file: None,
            entra: None,
            groups_claim: None,
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
                ttl: Duration::minutes(15),
            },
        )]
        .into_iter()
        .collect(),
        delegated: std::collections::BTreeMap::new(),
        registries: std::collections::BTreeMap::new(),
        reachable_registries: None,
        policy_egress: None,
        sandboxes: None,
        sandbox_namespace: "sandboxes".into(),
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
        let state = state(&idp, &upstream, &keyed_upstream);
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
                pool_ref: "pool-a".into(),
                ttl_seconds: 3600,
                audiences: audiences.iter().map(|a| (*a).to_owned()).collect(),
                workload: Workload {
                    image: "registry.internal:5000/sandbox:latest".into(),
                    args: vec!["/usr/bin/agent".into()],
                    restart: mediatore_proto::RestartPolicy::Always,
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
    let left = token.expires_at - chrono::Utc::now();
    assert!(
        left > Duration::minutes(14) && left <= Duration::minutes(15),
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
