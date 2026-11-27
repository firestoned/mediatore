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

use jiff::SignedDuration;
use mediatore_api::{AppState, Limiter, Namespaces};
use mediatore_entra::{Backend, IssuerConfig, Validator};
use mediatore_proto::{
    ClaimEgress, ClaimRequest, ClaimResponse, Delegation, Endpoint, ErrorBody, LogBatch, LogEnd,
    LogLine, LogRecord, LogStream, Me, NodeRegistered, NodeRegistration, TokenResponse, Workload,
};
use mediatore_spire::Naming;
use mediatore_store::LogLimits;
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

/// The authorizer's own identity (ADR-0053 decision 1): the one the broker's gateway routes
/// answer. The listeners' identity above is a stranger to them.
fn authorizer_svid() -> String {
    format!("spiffe://{TRUST_DOMAIN}/gateway/authorizer")
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
            ttl: SignedDuration::from_mins(15),
            basic: false,
        },
    )]
    .into_iter()
    .collect()
}

struct Harness {
    idp: FakeIdp,
    user_url: String,
    sandbox_url: String,
    /// The entries the broker declared, to see what a claim's entry is parented to.
    entries: Arc<mediatore_spire::MemoryEntries>,
    http: reqwest::Client,
}

/// How often the harness's broker writes its classified refusals (ADR-0070 decision 8): a
/// minute on a real broker, short here so a test can wait for the line and the status.
const FLUSH_EVERY: std::time::Duration = std::time::Duration::from_millis(25);

impl Harness {
    async fn start() -> Self {
        Self::start_with(Namespaces::Single("sandboxes".into())).await
    }

    async fn start_with(namespaces: Namespaces) -> Self {
        Self::start_opts(namespaces, None).await
    }

    /// A broker that stores a workload's output (ADR-0045 decision 11, `logs.enabled`).
    async fn start_with_logs() -> Self {
        Self::start_opts(
            Namespaces::Single("sandboxes".into()),
            Some(LogLimits {
                max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
            }),
        )
        .await
    }

    async fn start_opts(namespaces: Namespaces, logs: Option<LogLimits>) -> Self {
        Self::start_full(namespaces, logs, std::collections::BTreeMap::new(), None).await
    }

    /// `scopes`: the audiences scoped to namespaces, with their rules per namespace (ADR-0053).
    async fn start_full(
        namespaces: Namespaces,
        logs: Option<LogLimits>,
        scopes: std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<String, Vec<mediatore_proto::EndpointRule>>,
        >,
        policy: Option<mediatore_api::PolicyEgress>,
    ) -> Self {
        Self::start_all(namespaces, logs, scopes, policy, None).await
    }

    /// The broker under `policy.audience_definitions.mode: bundles` (ADR-0055): the catalog
    /// serves and the file's audience maps are empty, as the configuration requires.
    async fn start_catalog(
        namespaces: Namespaces,
        catalog: mediatore_api::AudienceCatalogSource,
    ) -> Self {
        Self::start_all(
            namespaces,
            None,
            std::collections::BTreeMap::new(),
            None,
            Some(catalog),
        )
        .await
    }

    async fn start_all(
        namespaces: Namespaces,
        logs: Option<LogLimits>,
        scopes: std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<String, Vec<mediatore_proto::EndpointRule>>,
        >,
        policy: Option<mediatore_api::PolicyEgress>,
        catalog: Option<mediatore_api::AudienceCatalogSource>,
    ) -> Self {
        Self::start_tripwires(
            namespaces,
            logs,
            scopes,
            policy,
            catalog,
            mediatore_api::Tripwires::default(),
        )
        .await
    }

    /// The broker under `policy.traps: mode` (ADR-0069 decision 5), every `denied` class at
    /// `report` unless `denied` says otherwise.
    async fn start_traps(
        mode: mediatore_proto::trip::TrapsMode,
        denied: mediatore_proto::trip::DeniedSwitches,
    ) -> Self {
        let tripwires = mediatore_api::Tripwires {
            mode,
            denied,
            ..mediatore_api::Tripwires::default()
        };
        Self::start_tripwires(
            Namespaces::Single("sandboxes".into()),
            None,
            std::collections::BTreeMap::new(),
            None,
            None,
            tripwires,
        )
        .await
    }

    #[allow(clippy::too_many_lines)] // every AppState field, listed in full
    async fn start_tripwires(
        namespaces: Namespaces,
        logs: Option<LogLimits>,
        scopes: std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<String, Vec<mediatore_proto::EndpointRule>>,
        >,
        policy: Option<mediatore_api::PolicyEgress>,
        catalog: Option<mediatore_api::AudienceCatalogSource>,
        tripwires: mediatore_api::Tripwires,
    ) -> Self {
        let file = catalog.is_none();
        let idp = FakeIdp::start().await;
        let sts = Sts::new(
            "https://mediatore.test",
            "e2e-1",
            STS_TEST_KEY.as_bytes(),
            SignedDuration::from_mins(15),
        )
        .expect("sts");
        // Held to the trust domain, as the Kubernetes entry manager holds its entries.
        let entries = Arc::new(mediatore_spire::MemoryEntries::in_trust_domain(
            TRUST_DOMAIN,
        ));
        let state = Arc::new(AppState {
            tripwires,
            inject: std::collections::BTreeMap::new(),
            inject_port: None,
            audience_catalog: catalog,
            logs,
            log_limiter: Limiter::per_second(2),
            log_wakes: mediatore_api::LogWakes::default(),
            accept_plain_gateway_identity: false,
            scopes,
            store: MemoryStore::shared(),
            spire: entries.clone(),
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
            audiences: if file {
                vec![AUDIENCE.into(), DELEGATED.into()]
            } else {
                vec![]
            },
            obo_audiences: vec![],
            egress: if file {
                egress_map()
            } else {
                std::collections::BTreeMap::new()
            },
            rules: if file {
                rules_map()
            } else {
                std::collections::BTreeMap::new()
            },
            cas: std::collections::BTreeMap::new(),
            no_credential: std::collections::BTreeSet::new(),
            secrets: std::collections::BTreeMap::new(),
            delegated: if file {
                delegated_map()
            } else {
                std::collections::BTreeMap::new()
            },
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
            registry_audiences: None,
            policy_egress: policy,
            sandboxes: None,
            namespaces: with_fixture_issuer(namespaces, &idp.issuer),
            max_ttl_seconds: mediatore_proto::DEFAULT_MAX_TTL_SECONDS,
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
        // The fold's flush, as `mediatore serve` starts it.
        mediatore_api::spawn_flush(state.clone(), FLUSH_EVERY);
        tokio::spawn(axum::serve(sandbox, mediatore_api::sandbox_router(state)).into_future());

        Self {
            idp,
            user_url,
            sandbox_url,
            entries,
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
                attestation: None,
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
                namespace: None,
                pool_ref: Some("pool-a".into()),
                pool_selector: None,
                selection: None,
                ttl_seconds: 3600,
                audiences: vec![AUDIENCE.into()],
                workload: Workload {
                    image: image.into(),
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
            .expect("create claim")
    }

    async fn create_claim(&self, token: &str) -> (reqwest::StatusCode, ClaimResponse) {
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
        let status = resp.status();
        let body = resp.json::<ClaimResponse>().await.expect("claim body");
        (status, body)
    }

    /// `POST /v1/claims` with `workload.logs` as given and `restart: never` (ADR-0045 decision 1).
    async fn create_claim_logs(&self, token: &str, logs: bool) -> reqwest::Response {
        self.http
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
                    args: vec!["/usr/local/bin/agent".into(), "--once".into()],
                    restart: mediatore_proto::RestartPolicy::Never,
                    logs,
                },
                refresh_token: None,
                policy_ref: None,
                delegations: vec![],
            })
            .send()
            .await
            .expect("create claim")
    }

    /// `POST /v1/me/logs` as `peer`.
    async fn post_logs(&self, peer: &str, batch: &LogBatch) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/me/logs", self.sandbox_url))
            .header(PEER_HEADER, peer)
            .json(batch)
            .send()
            .await
            .expect("post logs")
    }

    /// `GET /v1/claims/{name}/logs{query}` with `token`, the body parsed line by line (empty
    /// keepalive lines skipped).
    async fn read_logs(&self, token: &str, name: &str, query: &str) -> (u16, Vec<LogLine>) {
        let resp = self
            .http
            .get(format!("{}/v1/claims/{name}/logs{query}", self.user_url))
            .bearer_auth(token)
            .send()
            .await
            .expect("read logs");
        let status = resp.status().as_u16();
        if status != 200 {
            return (status, vec![]);
        }
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/x-ndjson")
        );
        let text = resp.text().await.expect("ndjson body");
        (status, parse_lines(&text))
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

fn parse_lines(text: &str) -> Vec<LogLine> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<LogLine>(l).unwrap_or_else(|e| panic!("{l}: {e}")))
        .collect()
}

fn record(seq: u64, stream: LogStream, text: &str) -> LogRecord {
    LogRecord {
        seq,
        stream,
        ts: jiff::Timestamp::now(),
        text: text.into(),
        partial: false,
    }
}

fn batch(records: Vec<LogRecord>) -> LogBatch {
    LogBatch {
        records,
        ..LogBatch::default()
    }
}

/// The `seq` of every record among `lines`, in order.
fn seqs(lines: &[LogLine]) -> Vec<u64> {
    lines
        .iter()
        .filter_map(|l| match l {
            LogLine::Record(r) => Some(r.seq),
            _ => None,
        })
        .collect()
}

fn end_reason(lines: &[LogLine]) -> Option<LogEnd> {
    match lines.last() {
        Some(LogLine::End(e)) => Some(e.reason),
        _ => None,
    }
}

/// ADR-0045 decisions 4, 5, 7, 8 and 9 over real listeners: the claim's node ships the
/// workload's output in batches, the owner and nobody else reads it back in order, a retried
/// batch changes nothing, the size, shape and rate limits refuse what they must, and the output
/// of a released claim is still the owner's to read inside the retention window.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one scripted scenario, front to back; splitting it would hide the order
async fn a_workloads_output_is_shipped_by_its_node_and_read_by_its_owner_alone() {
    let h = Harness::start_with_logs().await;
    h.register_node().await;
    let user_token = h.login("octocat");
    let resp = h.create_claim_logs(&user_token, true).await;
    assert_eq!(resp.status(), 201);
    let claim: ClaimResponse = resp.json().await.expect("claim body");
    let uid = claim.uid.expect("uid");
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
    assert!(
        me.workload.logs,
        "the guest learns the opt-in from GET /v1/me"
    );

    // Nothing yet: a header, no record, and the stream ends by the client's choice.
    let (status, lines) = h.read_logs(&user_token, &claim.name, "").await;
    assert_eq!(status, 200);
    assert!(
        matches!(&lines[0], LogLine::Header(hd) if hd.truncated_before == 0 && hd.claim_phase == "Bound"),
        "{lines:?}"
    );
    assert_eq!(seqs(&lines), Vec::<u64>::new());
    assert_eq!(end_reason(&lines), Some(LogEnd::Client));

    // Two batches are taken (ADR-0045 decision 4, amended 2026-11-20); the third within the
    // second is told to wait.
    let first = batch(vec![
        record(1, LogStream::Stdout, "hello"),
        record(2, LogStream::Stderr, "warning: something"),
    ]);
    let second = batch(vec![
        record(3, LogStream::Stdout, "world"),
        record(4, LogStream::Stdout, "done"),
    ]);
    assert_eq!(h.post_logs(&node_svid(), &first).await.status(), 204);
    assert_eq!(h.post_logs(&node_svid(), &second).await.status(), 204);
    let resp = h.post_logs(&node_svid(), &second).await;
    assert_eq!(resp.status(), 429, "two batches per second per claim");
    assert_eq!(
        resp.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
    let body: ErrorBody = resp.json().await.expect("429 body");
    assert_eq!(body.error, "too_many_batches");
    assert_eq!(
        body.detail.as_deref(),
        Some("two batches per second per claim")
    );

    // After the wait the same batch is taken, and a retried batch is a no-op (decision 8):
    // the same output, once.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(h.post_logs(&node_svid(), &second).await.status(), 204);
    let (status, lines) = h.read_logs(&user_token, &claim.name, "").await;
    assert_eq!(status, 200);
    assert_eq!(seqs(&lines), vec![1, 2, 3, 4]);
    assert!(
        matches!(&lines[2], LogLine::Record(r) if r.stream == LogStream::Stderr && r.text == "warning: something")
    );
    assert_eq!(end_reason(&lines), Some(LogEnd::Client));
    // `tail` and `since` (decision 9).
    let (_, lines) = h.read_logs(&user_token, &claim.name, "?tail=1").await;
    assert_eq!(seqs(&lines), vec![4]);
    let (_, lines) = h.read_logs(&user_token, &claim.name, "?since=2").await;
    assert_eq!(seqs(&lines), vec![3, 4]);

    // Only the owner reads (decision 5).
    let (status, _) = h.read_logs(&h.login("hexley"), &claim.name, "").await;
    assert_eq!(status, 403, "another subject");
    let resp = h
        .http
        .get(format!("{}/v1/claims/{}/logs", h.user_url, claim.name))
        .send()
        .await
        .expect("no token");
    assert_eq!(resp.status(), 401, "no token");
    let resp = h
        .http
        .get(format!("{}/v1/claims/{}/logs", h.user_url, claim.name))
        .header(PEER_HEADER, node_svid())
        .send()
        .await
        .expect("node on the user route");
    assert_eq!(resp.status(), 401, "a node identity is no bearer");
    // Only the claim's node writes (decision 9).
    let resp = h
        .http
        .post(format!("{}/v1/me/logs", h.sandbox_url))
        .bearer_auth(&user_token)
        .json(&first)
        .send()
        .await
        .expect("user on the node route");
    assert_eq!(resp.status(), 401, "a user token is no peer identity");
    let resp = h.post_logs(&claim_svid(&uid), &first).await;
    assert_eq!(resp.status(), 403, "a claim identity is not the node");

    // The size and the shape (decisions 4 and 9).
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let big = batch(vec![
        record(5, LogStream::Stdout, &"x".repeat(60 * 1024)),
        record(6, LogStream::Stdout, &"x".repeat(60 * 1024)),
        record(7, LogStream::Stdout, &"x".repeat(60 * 1024)),
        record(8, LogStream::Stdout, &"x".repeat(60 * 1024)),
        record(9, LogStream::Stdout, &"x".repeat(60 * 1024)),
    ]);
    let resp = h.post_logs(&node_svid(), &big).await;
    assert_eq!(resp.status(), 413);
    let body: ErrorBody = resp.json().await.expect("413 body");
    assert_eq!(body.error, "batch_too_large");
    let malformed = batch(vec![
        record(6, LogStream::Stdout, "b"),
        record(5, LogStream::Stdout, "a"),
    ]);
    let resp = h.post_logs(&node_svid(), &malformed).await;
    assert_eq!(resp.status(), 400);
    let body: ErrorBody = resp.json().await.expect("400 body");
    assert_eq!(body.error, "invalid_log_batch");
    let (_, lines) = h.read_logs(&user_token, &claim.name, "").await;
    assert_eq!(seqs(&lines), vec![1, 2, 3, 4], "nothing refused was stored");

    // The workload exits: the claim is released (ADR-0033) and the output stays readable.
    let exit = mediatore_proto::GuestExit {
        code: Some(0),
        signal: None,
        restarts: 0,
    };
    let resp = h
        .http
        .post(format!("{}/v1/me/exit", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .json(&exit)
        .send()
        .await
        .expect("exit");
    assert_eq!(resp.status(), 204);
    // A late batch, the guest flushing after the release: taken as 204 and dropped (decision 7).
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let late = batch(vec![record(5, LogStream::Stdout, "late")]);
    assert_eq!(h.post_logs(&node_svid(), &late).await.status(), 204);
    let (status, lines) = h.read_logs(&user_token, &claim.name, "").await;
    assert_eq!(status, 200);
    assert!(
        matches!(&lines[0], LogLine::Header(hd) if hd.claim_phase == "Releasing"),
        "{lines:?}"
    );
    assert_eq!(seqs(&lines), vec![1, 2, 3, 4], "the late batch was dropped");
    assert_eq!(end_reason(&lines), Some(LogEnd::ClaimEnded));
    let (status, _) = h.read_logs(&h.login("hexley"), &claim.name, "").await;
    assert_eq!(
        status, 403,
        "a released claim's output is still the owner's alone"
    );
    // `follow` on an ended claim: the stored output, then the end.
    let (status, lines) = h.read_logs(&user_token, &claim.name, "?follow=true").await;
    assert_eq!(status, 200);
    assert_eq!(seqs(&lines), vec![1, 2, 3, 4]);
    assert_eq!(end_reason(&lines), Some(LogEnd::ClaimEnded));
}

/// The guest's side of the output path, posting to the harness as the claim's node: what
/// `BrokerSink` does over the node SVID, here over the dev header.
struct NodeSink {
    http: reqwest::Client,
    url: String,
}

#[async_trait::async_trait]
impl mediatore_guest::logs::LogSink for NodeSink {
    async fn post(&self, batch: &LogBatch) -> anyhow::Result<mediatore_guest::logs::PostOutcome> {
        let resp = self
            .http
            .post(&self.url)
            .header(PEER_HEADER, node_svid())
            .json(batch)
            .send()
            .await?;
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        Ok(mediatore_guest::logs::classify(
            resp.status().as_u16(),
            retry_after,
        ))
    }
}

/// The next record of a followed stream, read as it arrives: the header and the keepalives
/// are skipped. `buf` keeps what a chunk held beyond the line returned.
async fn next_record(resp: &mut reqwest::Response, buf: &mut Vec<u8>) -> LogRecord {
    loop {
        while let Some(nl) = buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).collect();
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            match serde_json::from_slice::<LogLine>(&line).expect("a log line") {
                LogLine::Record(r) => return r,
                LogLine::Header(_) | LogLine::Gap(_) => {}
                LogLine::End(e) => panic!("the stream ended: {:?}", e.reason),
            }
        }
        let chunk = resp
            .chunk()
            .await
            .expect("the follow stream")
            .expect("the stream stays open while the claim lives");
        buf.extend_from_slice(&chunk);
    }
}

/// ADR-0045 decisions 1 and 9, amended 2026-11-20, front to back over real listeners: bytes
/// the workload writes to its pipe are read by the guest's reader, posted on the leading edge
/// by its batcher, stored by the broker, and sent to a follower the ingest woke, well inside
/// the two seconds the follower's poll alone would have taken. A line that does not end is
/// seen too, as a partial record, and the record that ends it is whole.
#[tokio::test]
async fn output_written_in_the_guest_reaches_a_follower_well_inside_the_poll() {
    use mediatore_guest::logs::{Capture, Queue, ShipperConfig, Shipping};
    use tokio::io::AsyncWriteExt as _;

    /// Well inside the follower's two-second poll, with room for a busy test host.
    const PROMPT: std::time::Duration = std::time::Duration::from_millis(1000);

    let h = Harness::start_with_logs().await;
    h.register_node().await;
    let user_token = h.login("octocat");
    let resp = h.create_claim_logs(&user_token, true).await;
    assert_eq!(resp.status(), 201);
    let claim: ClaimResponse = resp.json().await.expect("claim body");

    // The owner follows first: the stream opens on an empty ring.
    let mut follow = h
        .http
        .get(format!(
            "{}/v1/claims/{}/logs?follow=true",
            h.user_url, claim.name
        ))
        .bearer_auth(&user_token)
        .send()
        .await
        .expect("follow");
    assert_eq!(follow.status(), 200);
    let mut buf = Vec::new();
    // Past the follower's first read, so only a wake or the poll can bring what follows.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // The guest's side: a pipe for the workload's stdout, the reader, the queue, the batcher.
    let queue = Arc::new(Queue::default());
    let capture = Arc::new(Capture::new(Vec::new(), queue.clone()).without_console());
    let sink = Arc::new(NodeSink {
        http: h.http.clone(),
        url: format!("{}/v1/me/logs", h.sandbox_url),
    });
    let shipping = Shipping::start(queue, sink, ShipperConfig::default());
    let (mut pipe, read_end) = tokio::io::duplex(64 * 1024);
    let reader = tokio::spawn(async move {
        capture.read_stream(read_end, LogStream::Stdout).await;
    });

    // A whole line.
    let written = std::time::Instant::now();
    pipe.write_all(b"first line\n").await.expect("write");
    let got = next_record(&mut follow, &mut buf).await;
    let took = written.elapsed();
    assert_eq!(got.text, "first line");
    assert!(!got.partial, "a whole line");
    assert!(took < PROMPT, "a line took {took:?} to reach its follower");

    // A line that does not end: its start arrives as a partial, less the end the redactor
    // holds back, and its end as a record that is not one.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let start = "s".repeat(1000);
    let written = std::time::Instant::now();
    pipe.write_all(start.as_bytes()).await.expect("write");
    let head = next_record(&mut follow, &mut buf).await;
    let took = written.elapsed();
    assert!(head.partial, "the line has not ended");
    assert!(
        !head.text.is_empty() && start.starts_with(&head.text),
        "the start of the line, {} bytes of it",
        head.text.len()
    );
    assert!(
        took < PROMPT,
        "a partial took {took:?} to reach its follower"
    );
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    pipe.write_all(b" and its end\n").await.expect("write");
    let tail = next_record(&mut follow, &mut buf).await;
    assert!(!tail.partial, "the record that ends the line");
    assert_eq!(
        format!("{}{}", head.text, tail.text),
        format!("{start} and its end")
    );
    assert_eq!(
        (head.stream, tail.stream),
        (LogStream::Stdout, LogStream::Stdout)
    );

    drop(pipe);
    reader.await.expect("the reader ends with its pipe");
    assert!(
        shipping.flush(std::time::Duration::from_secs(5)).await,
        "nothing left to post"
    );
}

/// ADR-0045 decision 1: capture is the requester's opt-in. A claim without it takes no output
/// from its node, and the owner reads a header and an end line.
#[tokio::test]
async fn a_claim_that_did_not_opt_in_takes_no_output() {
    let h = Harness::start_with_logs().await;
    h.register_node().await;
    let user_token = h.login("octocat");
    let resp = h.create_claim_logs(&user_token, false).await;
    assert_eq!(resp.status(), 201);
    let claim: ClaimResponse = resp.json().await.expect("claim body");
    let resp = h
        .post_logs(
            &node_svid(),
            &batch(vec![record(1, LogStream::Stdout, "hello")]),
        )
        .await;
    assert_eq!(resp.status(), 400);
    let body: ErrorBody = resp.json().await.expect("400 body");
    assert_eq!(body.error, "logs_not_requested");
    let (status, lines) = h.read_logs(&user_token, &claim.name, "").await;
    assert_eq!(status, 200);
    assert_eq!(seqs(&lines), Vec::<u64>::new());
    assert_eq!(end_reason(&lines), Some(LogEnd::Client));
}

/// ADR-0045 decision 11: with `logs.enabled` off, both routes are `501 not_implemented`, and a
/// claim that opts in is refused with nothing created.
#[tokio::test]
async fn with_output_storage_off_everything_about_it_is_501() {
    let h = Harness::start().await;
    h.register_node().await;
    let user_token = h.login("octocat");
    let resp = h.create_claim_logs(&user_token, true).await;
    assert_eq!(resp.status(), 501);
    let body: ErrorBody = resp.json().await.expect("501 body");
    assert_eq!(body.error, "not_implemented");
    assert!(
        body.detail.as_deref().unwrap_or_default().contains("logs"),
        "{body:?}"
    );
    // Nothing was created: the node is still free, and the next claim binds to it.
    let (status, claim) = h.create_claim(&user_token).await;
    assert_eq!(status, 201);
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Bound);
    let resp = h
        .post_logs(
            &node_svid(),
            &batch(vec![record(1, LogStream::Stdout, "hello")]),
        )
        .await;
    assert_eq!(resp.status(), 501);
    let (status, _) = h.read_logs(&user_token, &claim.name, "").await;
    assert_eq!(status, 501);
}

/// ADR-0047 decision 7: `dev_mode` has no pools and no hosts; a strategy is accepted, and the
/// claim binds to the registered node as before.
#[tokio::test]
async fn dev_mode_accepts_a_strategy_and_binds_as_before() {
    let h = Harness::start().await;
    h.register_node().await;
    let user_token = h.login("octocat");
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(&user_token)
        .json(&ClaimRequest {
            namespace: None,
            pool_ref: None,
            pool_selector: Some(mediatore_proto::PoolSelector::default()),
            selection: Some(mediatore_proto::Selection {
                strategy: mediatore_proto::SelectionStrategy::Spread,
            }),
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
}

/// ADR-0045 decision 9: `follow` streams what arrives after the read started and ends when the
/// claim does.
#[tokio::test]
async fn follow_streams_output_as_it_arrives_and_ends_with_the_claim() {
    let h = Harness::start_with_logs().await;
    h.register_node().await;
    let user_token = h.login("octocat");
    let resp = h.create_claim_logs(&user_token, true).await;
    assert_eq!(resp.status(), 201);
    let claim: ClaimResponse = resp.json().await.expect("claim body");
    assert_eq!(
        h.post_logs(
            &node_svid(),
            &batch(vec![record(1, LogStream::Stdout, "before the read")])
        )
        .await
        .status(),
        204
    );
    let http = h.http.clone();
    let url = format!("{}/v1/claims/{}/logs?follow=true", h.user_url, claim.name);
    let token = user_token.clone();
    let follower = tokio::spawn(async move {
        let resp = http
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .expect("follow");
        assert_eq!(resp.status(), 200);
        parse_lines(&resp.text().await.expect("stream to the end"))
    });
    // The read is under way; the node ships more, then the workload exits.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert_eq!(
        h.post_logs(
            &node_svid(),
            &batch(vec![record(2, LogStream::Stderr, "during the read")])
        )
        .await
        .status(),
        204
    );
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    let resp = h
        .http
        .post(format!("{}/v1/me/exit", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .json(&mediatore_proto::GuestExit {
            code: Some(0),
            signal: None,
            restarts: 0,
        })
        .send()
        .await
        .expect("exit");
    assert_eq!(resp.status(), 204);
    let lines = tokio::time::timeout(std::time::Duration::from_secs(20), follower)
        .await
        .expect("the follow ends with the claim")
        .expect("follower task");
    assert!(matches!(&lines[0], LogLine::Header(_)), "{lines:?}");
    assert_eq!(seqs(&lines), vec![1, 2]);
    assert_eq!(end_reason(&lines), Some(LogEnd::ClaimEnded));
}

/// The guest's report (ADR-0029 decision 5): the node identity reports for its claim, the
/// shapes are checked, the report is kept on the record and shown to the subject; a claim
/// identity cannot report and a malformed report is refused.
/// ADR-0033: a claim created `restart: never`; the node posts the workload's exit, the
/// broker records it and releases the claim as a delete does; a claim identity cannot
/// post it, and a late post after the release is `204` with nothing done.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one scripted scenario, front to back; splitting it would hide the order
async fn a_one_shot_workload_ends_its_claim_at_the_broker() {
    let h = Harness::start().await;
    h.register_node().await;
    let user_token = h.login("octocat");
    let resp = h
        .http
        .post(format!("{}/v1/claims", h.user_url))
        .bearer_auth(&user_token)
        .json(&ClaimRequest {
            namespace: None,
            pool_ref: Some("pool-a".into()),
            pool_selector: None,
            selection: None,
            ttl_seconds: 3600,
            audiences: vec![AUDIENCE.into()],
            workload: Workload {
                image: "registry.internal:5000/sandbox:latest".into(),
                args: vec!["/usr/local/bin/agent".into(), "--once".into()],
                restart: mediatore_proto::RestartPolicy::Never,
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
    assert!(recorded.exited_at <= jiff::Timestamp::now());
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
    assert!(recorded.reported_at <= jiff::Timestamp::now());
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
    let as_gateway = || h.http.get(&url).header(PEER_HEADER, authorizer_svid());

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
        gateway_svid(),
        format!("{}/x", gateway_svid()),
        format!("{}/x", authorizer_svid()),
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
        .header(PEER_HEADER, authorizer_svid())
        .send()
        .await
        .expect("unknown");
    assert_eq!(resp.status(), 404);
    let bad = format!("{}/v1/gateway/claims/not-a-uuid", h.sandbox_url);
    let resp = h
        .http
        .get(&bad)
        .header(PEER_HEADER, authorizer_svid())
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
            namespace: None,
            pool_ref: Some("pool-a".into()),
            pool_selector: None,
            selection: None,
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
            namespace: None,
            pool_ref: Some("pool-a".into()),
            pool_selector: None,
            selection: None,
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
            attestation: None,
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
            attestation: None,
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
            attestation: None,
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
        namespace: None,
        pool_ref: Some("pool-a".into()),
        pool_selector: None,
        selection: None,
        ttl_seconds,
        audiences: vec![AUDIENCE.into(), DELEGATED.into()],
        workload: Workload {
            image: "registry.internal:5000/sandbox:latest".into(),
            args: vec![],
            restart: mediatore_proto::RestartPolicy::Always,
            logs: false,
        },
        refresh_token: None,
        policy_ref: None,
        delegations,
    }
}

fn delegation(audience: &str, token: &str, expires_at: Option<jiff::Timestamp>) -> Delegation {
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
    let dies_at = jiff::Timestamp::now() + SignedDuration::from_hours(2);
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

    let before = jiff::Timestamp::now();
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
        tok.expires_at <= before + SignedDuration::from_mins(15) + SignedDuration::from_secs(1),
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
                Some(jiff::Timestamp::now() + SignedDuration::from_secs(30)),
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

// ----- ADR-0046: who may claim where, over real listeners --------------------------------------------------

const ADMIN_GROUP: &str = "example-org:APP_EXAMPLE_ADMIN";
const TEAM_A_GROUP: &str = "APP_EXAMPLE_TEAM_A_USER";

/// Stands for the fake issuer's URL in a map written before it listens; the harness puts in
/// the URL it took (ADR-0074: every entry names the issuers its groups are read from).
const FIXTURE_ISSUER: &str = "https://fixture-issuer.test";

fn tenant_map() -> Namespaces {
    let grant = |group: &str| mediatore_api::NamespaceGrant {
        groups: vec![group.to_owned()],
        issuers: vec![FIXTURE_ISSUER.to_owned()],
    };
    Namespaces::Map(std::collections::BTreeMap::from([
        ("infra".to_owned(), grant(ADMIN_GROUP)),
        ("team-a".to_owned(), grant(TEAM_A_GROUP)),
    ]))
}

/// `namespaces` with [`FIXTURE_ISSUER`] replaced by `issuer`.
fn with_fixture_issuer(namespaces: Namespaces, issuer: &str) -> Namespaces {
    match namespaces {
        Namespaces::Map(map) => Namespaces::Map(
            map.into_iter()
                .map(|(ns, mut grant)| {
                    for i in &mut grant.issuers {
                        if i == FIXTURE_ISSUER {
                            issuer.clone_into(i);
                        }
                    }
                    (ns, grant)
                })
                .collect(),
        ),
        single @ Namespaces::Single(_) => single,
    }
}

impl Harness {
    /// A login that passes the issuer gate and holds `groups` besides.
    fn login_in(&self, login: &str, groups: &[&str]) -> String {
        let mut all = vec![REQUIRED_GROUP];
        all.extend_from_slice(groups);
        self.idp.token(serde_json::json!({
            "aud": "mediatore",
            "preferred_username": login,
            "groups": all,
        }))
    }

    async fn create_in(&self, token: &str, namespace: Option<&str>) -> reqwest::Response {
        let mut body = serde_json::json!({
            "pool_ref": "pool-a",
            "ttl_seconds": 3600,
            "audiences": [AUDIENCE],
            "workload": { "image": "registry.internal:5000/sandbox:latest" },
        });
        if let Some(ns) = namespace {
            body["namespace"] = ns.into();
        }
        self.http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .expect("create")
    }

    async fn claim_at(
        &self,
        method: reqwest::Method,
        token: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> reqwest::Response {
        let query = namespace.map_or_else(String::new, |ns| format!("?namespace={ns}"));
        self.http
            .request(method, format!("{}/v1/claims/{name}{query}", self.user_url))
            .bearer_auth(token)
            .send()
            .await
            .expect("claim request")
    }
}

/// The error code and detail of a refusal.
async fn refusal(resp: reqwest::Response) -> (u16, ErrorBody) {
    (
        resp.status().as_u16(),
        resp.json().await.expect("error body"),
    )
}

#[tokio::test]
async fn a_tenant_claims_in_its_namespace_and_not_in_the_admin_namespace() {
    let h = Harness::start_with(tenant_map()).await;
    let tenant = h.login_in("octocat", &[TEAM_A_GROUP]);

    let resp = h.create_in(&tenant, Some("team-a")).await;
    assert_eq!(resp.status(), 201);
    let claim: ClaimResponse = resp.json().await.expect("claim");
    assert_eq!(claim.namespace.as_deref(), Some("team-a"));

    // The admin namespace: 403, one code, one message naming only what the caller sent.
    let (status, body) = refusal(h.create_in(&tenant, Some("infra")).await).await;
    assert_eq!(status, 403);
    assert_eq!(body.error, "forbidden");
    assert_eq!(
        body.detail.as_deref(),
        Some("not permitted to create sandboxes in namespace infra")
    );
    // A namespace the map does not list answers the same way: no oracle for what exists.
    let (status, unlisted) = refusal(h.create_in(&tenant, Some("nowhere")).await).await;
    assert_eq!(status, 403);
    assert_eq!(unlisted.error, body.error);
    assert_eq!(
        unlisted.detail.as_deref(),
        Some("not permitted to create sandboxes in namespace nowhere")
    );
    for text in [body.detail.unwrap(), unlisted.detail.unwrap()] {
        for leaked in [ADMIN_GROUP, TEAM_A_GROUP, REQUIRED_GROUP, "team-a"] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
    }

    // With a map and no namespace there is no default: 400, naming no namespace.
    let (status, body) = refusal(h.create_in(&tenant, None).await).await;
    assert_eq!(status, 400);
    assert_eq!(body.error, "namespace_required");
    let detail = body.detail.unwrap_or_default();
    assert!(
        !detail.contains("team-a") && !detail.contains("infra"),
        "{detail}"
    );
    let (status, body) = refusal(h.create_in(&tenant, Some("Team_A")).await).await;
    assert_eq!((status, body.error.as_str()), (400, "invalid_namespace"));

    // The claim is read and deleted in its namespace, by name, by its owner.
    let name = &claim.name;
    let get = h
        .claim_at(reqwest::Method::GET, &tenant, name, Some("team-a"))
        .await;
    assert_eq!(get.status(), 200);
    let got: ClaimResponse = get.json().await.expect("claim");
    assert_eq!(got.namespace.as_deref(), Some("team-a"));
    // Unqualified for the namespace, an unlisted one, and a listed one with no such claim are one
    // answer; and with the map a get with no namespace is 400.
    let (status, body) = refusal(
        h.claim_at(reqwest::Method::GET, &tenant, name, Some("infra"))
            .await,
    )
    .await;
    assert_eq!((status, body.error.as_str()), (404, "not_found"));
    let (status, _) = refusal(
        h.claim_at(reqwest::Method::GET, &tenant, name, Some("nowhere"))
            .await,
    )
    .await;
    assert_eq!(status, 404);
    let (status, body) = refusal(h.claim_at(reqwest::Method::GET, &tenant, name, None).await).await;
    assert_eq!((status, body.error.as_str()), (400, "namespace_required"));
    let (status, body) = refusal(
        h.claim_at(reqwest::Method::DELETE, &tenant, name, None)
            .await,
    )
    .await;
    assert_eq!((status, body.error.as_str()), (400, "namespace_required"));

    // An admin does not see the tenant's claim, and cannot delete it: 404, and it is still there.
    let admin = h.login_in("hexley", &[ADMIN_GROUP]);
    for ns in ["team-a", "infra"] {
        let get = h
            .claim_at(reqwest::Method::GET, &admin, name, Some(ns))
            .await;
        assert_eq!(get.status(), 404, "admin GET in {ns}");
        let del = h
            .claim_at(reqwest::Method::DELETE, &admin, name, Some(ns))
            .await;
        assert_eq!(del.status(), 404, "admin DELETE in {ns}");
    }
    assert_eq!(
        h.claim_at(reqwest::Method::GET, &tenant, name, Some("team-a"))
            .await
            .status(),
        200,
        "the admin's refused delete left the claim"
    );

    let del = h
        .claim_at(reqwest::Method::DELETE, &tenant, name, Some("team-a"))
        .await;
    assert!(del.status().is_success(), "{}", del.status());
}

#[tokio::test]
async fn an_admin_claims_in_the_admin_namespace_and_not_in_a_tenants() {
    let h = Harness::start_with(tenant_map()).await;
    let admin = h.login_in("hexley", &[ADMIN_GROUP]);
    let tenant = h.login_in("octocat", &[TEAM_A_GROUP]);

    let resp = h.create_in(&admin, Some("infra")).await;
    assert_eq!(resp.status(), 201);
    let claim: ClaimResponse = resp.json().await.expect("claim");
    assert_eq!(claim.namespace.as_deref(), Some("infra"));

    let (status, body) = refusal(h.create_in(&admin, Some("team-a")).await).await;
    assert_eq!((status, body.error.as_str()), (403, "forbidden"));
    // The tenant cannot claim in infra, nor see the admin's claim there.
    let (status, _) = refusal(h.create_in(&tenant, Some("infra")).await).await;
    assert_eq!(status, 403);
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let resp = h
            .claim_at(method.clone(), &tenant, &claim.name, Some("infra"))
            .await;
        assert_eq!(resp.status(), 404, "tenant {method} in infra");
    }
    assert_eq!(
        h.claim_at(reqwest::Method::GET, &admin, &claim.name, Some("infra"))
            .await
            .status(),
        200
    );
    // A person in both namespaces' groups still names one.
    let both = h.login_in("mona", &[ADMIN_GROUP, TEAM_A_GROUP]);
    let (status, body) = refusal(h.create_in(&both, None).await).await;
    assert_eq!((status, body.error.as_str()), (400, "namespace_required"));
    assert_eq!(h.create_in(&both, Some("team-a")).await.status(), 201);
}

#[tokio::test]
async fn without_a_map_the_single_namespace_is_open_and_any_other_is_403() {
    let h = Harness::start().await;
    let token = h.login("octocat");
    let resp = h.create_in(&token, None).await;
    assert_eq!(resp.status(), 201);
    let claim: ClaimResponse = resp.json().await.expect("claim");
    assert_eq!(claim.namespace.as_deref(), Some("sandboxes"));
    assert_eq!(h.create_in(&token, Some("sandboxes")).await.status(), 201);
    let (status, body) = refusal(h.create_in(&token, Some("team-a")).await).await;
    assert_eq!((status, body.error.as_str()), (403, "forbidden"));
    // A get with no namespace means the one namespace, as before.
    assert_eq!(
        h.claim_at(reqwest::Method::GET, &token, &claim.name, None)
            .await
            .status(),
        200
    );
}

// ----- ADR-0053: an audience scoped to namespaces, over real listeners ---------------------------------------

impl Harness {
    async fn create_naming(
        &self,
        token: &str,
        namespace: &str,
        audience: &str,
    ) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "pool_ref": "pool-a",
                "ttl_seconds": 3600,
                "audiences": [audience],
                "namespace": namespace,
                "workload": { "image": "registry.internal:5000/sandbox:latest" },
            }))
            .send()
            .await
            .expect("create")
    }
}

#[tokio::test]
async fn a_scoped_audience_is_usable_in_its_namespace_and_unknown_in_another() {
    // `grafana.test` is scoped to team-a. A person who may claim in infra (the admin) names it there and is told
    // exactly what they are told for an audience that does not exist: the response is no oracle for which
    // audiences exist in another namespace.
    let grants = std::collections::BTreeMap::from([(
        AUDIENCE.to_owned(),
        std::collections::BTreeMap::from([(
            "team-a".to_owned(),
            vec![mediatore_proto::EndpointRule {
                method: "GET".into(),
                path: "/api/**".into(),
            }],
        )]),
    )]);
    let h = Harness::start_full(tenant_map(), None, grants, None).await;
    let tenant = h.login_in("octocat", &[TEAM_A_GROUP]);
    let admin = h.login_in("hexley", &[ADMIN_GROUP]);

    let ok = h.create_naming(&tenant, "team-a", AUDIENCE).await;
    assert_eq!(ok.status(), 201, "the listed namespace");

    let (status, hidden) = refusal(h.create_naming(&admin, "infra", AUDIENCE).await).await;
    let (status_missing, missing) =
        refusal(h.create_naming(&admin, "infra", "nonexistent.test").await).await;
    assert_eq!((status, status_missing), (400, 400));
    assert_eq!(hidden.error, "unknown_audience");
    assert_eq!(hidden.error, missing.error, "one code for both");
    assert_eq!(
        hidden.detail.as_deref(),
        Some(AUDIENCE),
        "it echoes the caller's own value and nothing else"
    );
    assert_eq!(missing.detail.as_deref(), Some("nonexistent.test"));

    // The namespace check of ADR-0046 comes first: a tenant outside infra's groups is refused there, not told
    // anything about the audience.
    let (status, body) = refusal(h.create_naming(&tenant, "infra", AUDIENCE).await).await;
    assert_eq!((status, body.error.as_str()), (403, "forbidden"));

    // An unscoped audience is unchanged: usable from either namespace.
    let ok = h.create_naming(&admin, "infra", DELEGATED).await;
    assert_ne!(
        ok.status(),
        403,
        "an unscoped audience is not refused for its namespace"
    );
}

// ----- ADR-0053 phase 2: the verified bundle as the source of the grants, over real listeners ----------------

/// A reflector holding one bundle whose only grant is `grafana.test` (both endpoints, `GET /api/**`,
/// no `ttlSeconds`), and the policy's name. `synced` says whether the namespace's first list is done.
async fn bundle_policy(
    audiences: mediatore_claims::policy::EgressMode,
    synced: bool,
) -> (mediatore_api::PolicyEgress, String) {
    let now = jiff::Timestamp::now();
    let mut content = mediatore_testkit::policy::fresh_bundle(now, 1)
        .payload
        .content;
    let mut grant = content.audiences[0].clone();
    grant.name = AUDIENCE.into();
    grant.endpoints = vec!["api.home.example:443".into(), "192.0.2.10:8443".into()];
    grant.rules = vec![mediatore_policy::types::EndpointRule {
        method: "GET".into(),
        path: "/api/**".into(),
    }];
    grant.ttl_seconds = None;
    content.audiences = vec![grant];
    let signed = mediatore_testkit::policy::signed_bundle(now, 2, content);
    let policy = signed.payload.content.policy.clone();
    let reflector = mediatore_claims::policy::BundleReflector::new(
        MemoryStore::shared(),
        signed.keys,
        vec![policy.namespace.clone()],
    );
    if synced {
        reflector.resynced(&policy.namespace, &std::collections::HashSet::new());
    }
    let cm = mediatore_testkit::policy::bundle_configmap(
        &policy.namespace,
        "agent-bundle",
        &signed.envelope,
    );
    reflector.applied_at(&cm, now).await;
    (
        mediatore_api::PolicyEgress {
            follow: mediatore_claims::policy::EgressMode::Shadow,
            bundles: reflector.cache(),
            mode: mediatore_claims::policy::EgressMode::Shadow,
            audiences,
            // The claims live in `sandboxes` and the bundle is signed for its own namespace:
            // the operator's `policy.sources` entry says the one draws from the other (ADR-0054).
            sources: mediatore_claims::policy::PolicySources::new(
                std::collections::BTreeMap::from([(
                    "sandboxes".to_owned(),
                    vec![policy.namespace.clone()],
                )]),
            ),
        },
        policy.name,
    )
}

impl Harness {
    async fn create_body(&self, token: &str, body: serde_json::Value) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .expect("create")
    }
}

fn claim_body(audience: &str, policy: Option<&str>, ttl: u32) -> serde_json::Value {
    let mut body = serde_json::json!({
        "pool_ref": "pool-a",
        "ttl_seconds": ttl,
        "audiences": [audience],
        "workload": { "image": "registry.internal:5000/sandbox:latest" },
    });
    if let Some(p) = policy {
        body["policy_ref"] = p.into();
    }
    body
}

#[tokio::test]
async fn under_enforce_a_claim_needs_a_known_policy_that_grants_what_it_asks_for() {
    use mediatore_claims::policy::EgressMode::Enforce;
    let (pe, policy) = bundle_policy(Enforce, true).await;
    let h = Harness::start_full(
        Namespaces::Single("sandboxes".into()),
        None,
        std::collections::BTreeMap::new(),
        Some(pe),
    )
    .await;
    let token = h.login("octocat");

    let (status, body) = refusal(
        h.create_body(&token, claim_body(AUDIENCE, None, 3600))
            .await,
    )
    .await;
    assert_eq!((status, body.error.as_str()), (400, "policy_required"));

    let (status, body) = refusal(
        h.create_body(&token, claim_body(AUDIENCE, Some("no-such-policy"), 3600))
            .await,
    )
    .await;
    assert_eq!((status, body.error.as_str()), (400, "unknown_policy"));

    // An audience the bundle does not grant is told exactly what a missing audience is told.
    let (status, ungranted) = refusal(
        h.create_body(&token, claim_body(DELEGATED, Some(&policy), 3600))
            .await,
    )
    .await;
    let (_, missing) = refusal(
        h.create_body(&token, claim_body("nonexistent.test", Some(&policy), 3600))
            .await,
    )
    .await;
    assert_eq!(
        (status, ungranted.error.as_str()),
        (400, "unknown_audience")
    );
    assert_eq!(ungranted.error, missing.error, "one code for both");
    assert_eq!(
        ungranted.detail.as_deref(),
        Some(DELEGATED),
        "the caller's own value only"
    );

    // A lifetime above the bundle's lease.
    let (status, body) = refusal(
        h.create_body(&token, claim_body(AUDIENCE, Some(&policy), 10_000_000))
            .await,
    )
    .await;
    assert_eq!((status, body.error.as_str()), (400, "ttl_exceeds_policy"));

    // And the one that fits.
    let ok = h
        .create_body(&token, claim_body(AUDIENCE, Some(&policy), 3600))
        .await;
    assert_eq!(
        ok.status(),
        201,
        "a named policy that grants it, inside its lease"
    );
}

#[tokio::test]
async fn under_enforce_before_the_bundles_are_read_nothing_is_created() {
    use mediatore_claims::policy::EgressMode::Enforce;
    // "No bundle yet" is never read as "no policy": 503 and nothing is created.
    let (pe, policy) = bundle_policy(Enforce, false).await;
    let h = Harness::start_full(
        Namespaces::Single("sandboxes".into()),
        None,
        std::collections::BTreeMap::new(),
        Some(pe),
    )
    .await;
    let token = h.login("octocat");
    let (status, body) = refusal(
        h.create_body(&token, claim_body(AUDIENCE, Some(&policy), 3600))
            .await,
    )
    .await;
    assert_eq!((status, body.error.as_str()), (503, "policy_not_synced"));
}

#[tokio::test]
async fn in_shadow_a_claim_with_no_policy_is_created_as_before() {
    use mediatore_claims::policy::EgressMode::Shadow;
    let (pe, _) = bundle_policy(Shadow, true).await;
    let h = Harness::start_full(
        Namespaces::Single("sandboxes".into()),
        None,
        std::collections::BTreeMap::new(),
        Some(pe),
    )
    .await;
    let token = h.login("octocat");
    let ok = h
        .create_body(&token, claim_body(AUDIENCE, None, 3600))
        .await;
    assert_eq!(ok.status(), 201, "shadow refuses nothing");
}

// ----- ADR-0055: audiences from signed SandboxAudience bundles, over real listeners ----------------

const PLATFORM: &str = "sandbox-platform";

fn audience_definition(endpoint: &str) -> mediatore_policy::types::AudienceDefinition {
    use mediatore_policy::types::{
        AudienceCredential, AudienceDefinition, Backend as B, CredentialFormat, Placement,
    };
    AudienceDefinition {
        credential: AudienceCredential {
            // `none`: a team audience may not mint with the platform's keys (L022).
            backend: B::None,
            placement: Placement::Proxy,
            format: CredentialFormat::Bearer,
            source: None,
            header: None,
            extra_headers: Vec::new(),
            refresh: None,
        },
        endpoints: vec![endpoint.into()],
        rules: Vec::new(),
        max_ttl_seconds: 300,
        ca_ref: None,
    }
}

/// A catalog listed in every namespace, holding `team.test` in team-a and `shared.test` in the
/// platform namespace, both reached without a credential.
async fn two_namespace_catalog() -> mediatore_api::AudienceCatalogSource {
    let now = jiff::Timestamp::now();
    let team = mediatore_testkit::policy::signed_audience(
        now,
        1,
        "team-a",
        "team.test",
        audience_definition("team.home.example:443"),
    );
    let shared = mediatore_testkit::policy::signed_audience(
        now,
        1,
        PLATFORM,
        "shared.test",
        audience_definition("shared.home.example:443"),
    );
    // The testkit signs every bundle under one key; a third signing hands over its keys.
    let keys = mediatore_testkit::policy::signed_audience(
        now,
        1,
        PLATFORM,
        "keys.test",
        audience_definition("keys.home.example:443"),
    )
    .keys;
    let reflector = mediatore_claims::audience::AudienceReflector::new(
        MemoryStore::shared(),
        keys,
        PLATFORM.into(),
        vec![PLATFORM.into(), "infra".into(), "team-a".into()],
    );
    for ns in [PLATFORM, "infra", "team-a"] {
        reflector.resynced(ns, &std::collections::HashSet::new());
    }
    for (ns, name, a) in [
        ("team-a", "team.test", &team),
        (PLATFORM, "shared.test", &shared),
    ] {
        let cm = mediatore_testkit::policy::audience_configmap(ns, name, &a.envelope);
        assert!(matches!(
            reflector.applied(&cm).await,
            mediatore_claims::audience::AudienceOutcome::Admitted { .. }
        ));
    }
    mediatore_api::AudienceCatalogSource {
        live: reflector.live(),
        credentials: Arc::new(mediatore_claims::credential::CredentialCache::new(
            SignedDuration::from_secs(60),
        )),
    }
}

#[tokio::test]
async fn a_team_audience_is_claimed_in_its_namespace_and_unknown_from_another() {
    let h = Harness::start_catalog(tenant_map(), two_namespace_catalog().await).await;
    let tenant = h.login_in("octocat", &[TEAM_A_GROUP]);
    let admin = h.login_in("hexley", &[ADMIN_GROUP]);

    let ok = h.create_naming(&tenant, "team-a", "team.test").await;
    assert_eq!(ok.status(), 201, "a team audience in its own namespace");

    // From infra, the team audience reads exactly as one that exists nowhere.
    let (status, hidden) = refusal(h.create_naming(&admin, "infra", "team.test").await).await;
    let (missing_status, missing) =
        refusal(h.create_naming(&admin, "infra", "nonexistent.test").await).await;
    assert_eq!((status, missing_status), (400, 400));
    assert_eq!(hidden.error, "unknown_audience");
    assert_eq!(hidden.error, missing.error);

    // The platform audience serves both namespaces.
    for (token, ns) in [(&tenant, "team-a"), (&admin, "infra")] {
        let created = h.create_naming(token, ns, "shared.test").await;
        assert_eq!(created.status(), 201, "{ns}");
    }
    // The file's audiences are gone under bundles.
    let (status, body) = refusal(h.create_naming(&admin, "infra", AUDIENCE).await).await;
    assert_eq!((status, body.error.as_str()), (400, "unknown_audience"));
}

// ---------- ADR-0069 decisions 8 and 9: a trip at the broker ----------

use mediatore_proto::trip::{
    ClassAction, DeniedSwitches, TrapsMode, TripEffect, TripKind, TripSource, TripTarget,
};

/// A second pool VM's EK hash, for a second node.
const OTHER_EK_HASH: &str = "5d0e7c1a9b2f4e6d8c3a1b0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a291807";

fn node_svid_of(ek_hash: &str) -> String {
    format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{ek_hash}")
}

/// One event of a trip report: `fields` over an id and a time.
fn trip_event(id: uuid::Uuid, fields: &serde_json::Value) -> serde_json::Value {
    let mut event = serde_json::json!({ "id": id, "at": "2026-11-26T15:02:11.204Z" });
    for (k, v) in fields.as_object().expect("an object") {
        event[k] = v.clone();
    }
    event
}

/// A drawn credential seen in a request towards a routed host.
fn credential_trip(id: uuid::Uuid) -> serde_json::Value {
    trip_event(
        id,
        &serde_json::json!({ "kind": "credential", "trap": "aws", "target": { "host": "git.example" }, "source": "workload" }),
    )
}

/// A drawn decoy port the workload connected to.
fn port_trip(id: uuid::Uuid) -> serde_json::Value {
    trip_event(
        id,
        &serde_json::json!({ "kind": "port", "trap": "redis", "target": { "port": 6379 }, "source": "drawn" }),
    )
}

impl Harness {
    /// Register a node under `ek_hash`, as its own identity.
    async fn register_node_as(&self, ek_hash: &str) {
        let resp = self
            .http
            .post(format!("{}/v1/nodes", self.sandbox_url))
            .header(PEER_HEADER, node_svid_of(ek_hash))
            .json(&NodeRegistration {
                ek_hash: ek_hash.into(),
                attestation: None,
                dmi_uuid: uuid::Uuid::new_v4(),
                hostname: "pool-a-8".into(),
                provider: Some(mediatore_proto::Provider::Libvirt),
            })
            .send()
            .await
            .expect("register");
        assert_eq!(resp.status(), 200);
    }

    /// `POST /v1/me/trip` as `peer`: a report under `mode` with `events`.
    async fn trip(
        &self,
        peer: &str,
        mode: &str,
        events: &[serde_json::Value],
    ) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/me/trip", self.sandbox_url))
            .header(PEER_HEADER, peer)
            .json(&serde_json::json!({ "mode": mode, "events": events }))
            .send()
            .await
            .expect("trip")
    }

    /// `GET /v1/claims/{name}` as its owner.
    async fn claim_named(&self, token: &str, name: &str) -> ClaimResponse {
        self.http
            .get(format!("{}/v1/claims/{name}", self.user_url))
            .bearer_auth(token)
            .send()
            .await
            .expect("get claim")
            .json()
            .await
            .expect("claim body")
    }
}

#[tokio::test]
async fn a_trip_ends_the_claim_and_the_owner_sees_it() {
    let h = Harness::start_traps(TrapsMode::Enforce, DeniedSwitches::default()).await;
    h.register_node().await;
    let user = h.login("octocat");
    let (status, claim) = h.create_claim(&user).await;
    assert_eq!(status, 201);
    let uid = claim.uid.expect("uid");
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Bound);
    assert!(claim.tripped.is_none() && claim.tripwires.is_none());

    // The guest is told the mode with its claim, and the claim's identity gets a token.
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
    let traps = me.traps.expect("traps under enforce");
    assert_eq!(traps.mode, TrapsMode::Enforce);
    assert_eq!(traps.denied, DeniedSwitches::default());
    assert!(traps.catalogue.is_none(), "no bundle carries a catalogue");
    assert_eq!(h.token_for(&claim_svid(&uid), AUDIENCE).await.status(), 200);

    // The guest has cut the network and killed the jail; it reports over its node SVID.
    let id = uuid::Uuid::new_v4();
    let mut bait = credential_trip(id);
    bait["containment_ms"] = 41.into();
    let resp = h.trip(&node_svid(), "enforce", &[bait]).await;
    assert_eq!(resp.status(), 204);

    // The owner sees what ended the claim, and the folded events.
    let ended = h.claim_named(&user, &claim.name).await;
    assert_ne!(ended.phase, mediatore_proto::ClaimPhase::Bound, "released");
    assert!(!ended.ready);
    let tripped = ended.tripped.expect("tripped is shown to the owner");
    assert_eq!(tripped.id, id);
    assert_eq!(tripped.kind, TripKind::Credential);
    assert_eq!(tripped.trap.as_deref(), Some("aws"));
    assert_eq!(tripped.target, Some(TripTarget::Host("git.example".into())));
    assert_eq!(tripped.source, TripSource::Workload);
    assert!(tripped.recorded_at <= jiff::Timestamp::now());
    let summary = ended.tripwires.expect("the folded events");
    assert_eq!(summary.entries.len(), 1);
    assert_eq!(summary.entries[0].effect, TripEffect::Tripped);
    assert_eq!(summary.entries[0].kind, TripKind::Credential);
    assert_eq!(summary.entries[0].count, 1);
    assert_eq!(summary.entries[0].containment_ms, Some(41));
    assert!(ended.exit.is_none(), "a trip is not an exit");

    // The tripped claim's token is refused, the gateway is told the claim is gone, and the
    // guest is handed no claim to start the workload again.
    let resp = h.token_for(&claim_svid(&uid), AUDIENCE).await;
    assert_eq!(resp.status(), 403, "no token for a tripped claim");
    let resp = h
        .http
        .get(format!("{}/v1/gateway/claims/{uid}", h.sandbox_url))
        .header(PEER_HEADER, authorizer_svid())
        .send()
        .await
        .expect("gateway claim");
    assert_eq!(resp.status(), 404, "the gateway drops what it cached");
    assert_eq!(
        h.me_status(&node_svid()).await,
        404,
        "a tripped claim is not restarted: its node has no claim to run"
    );
    // And the record is never live again: a later exit ends nothing and changes nothing.
    let resp = h
        .http
        .post(format!("{}/v1/me/exit", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .json(&mediatore_proto::GuestExit {
            code: Some(137),
            signal: None,
            restarts: 0,
        })
        .send()
        .await
        .expect("exit");
    assert_eq!(resp.status(), 204);
    let after = h.claim_named(&user, &claim.name).await;
    assert!(after.exit.is_none());
    assert_eq!(after.tripped.map(|t| t.id), Some(id));
}

/// ADR-0069 decision 7 step 4 (amended 2026-11-27): the trip report lands first and ends the
/// claim at once; the guest's final line naming the trap, and what the workload wrote last,
/// are shipped after it and still reach the owner.
#[tokio::test]
async fn a_tripped_claims_last_output_reaches_its_owner_after_the_report() {
    let tripwires = mediatore_api::Tripwires {
        mode: TrapsMode::Enforce,
        ..mediatore_api::Tripwires::default()
    };
    let h = Harness::start_tripwires(
        Namespaces::Single("sandboxes".into()),
        Some(LogLimits {
            max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
        }),
        std::collections::BTreeMap::new(),
        None,
        None,
        tripwires,
    )
    .await;
    h.register_node().await;
    let user = h.login("octocat");
    let resp = h.create_claim_logs(&user, true).await;
    assert_eq!(resp.status(), 201);
    let claim: ClaimResponse = resp.json().await.expect("claim body");
    assert_eq!(h.me_status(&node_svid()).await, 200);

    let resp = h
        .trip(&node_svid(), "enforce", &[port_trip(uuid::Uuid::new_v4())])
        .await;
    assert_eq!(resp.status(), 204);
    let ended = h.claim_named(&user, &claim.name).await;
    assert!(ended.tripped.is_some());
    assert_eq!(h.me_status(&node_svid()).await, 404, "no claim to run");

    let last = batch(vec![
        record(1, LogStream::Stdout, "the workload's last line"),
        record(2, LogStream::Stderr, "mediatore: a trap ended this run"),
    ]);
    assert_eq!(h.post_logs(&node_svid(), &last).await.status(), 204);
    let (status, lines) = h.read_logs(&user, &claim.name, "").await;
    assert_eq!(status, 200);
    assert_eq!(seqs(&lines), vec![1, 2], "the owner reads the last output");
    // Another node's output is never taken for it.
    h.register_node_as(OTHER_EK_HASH).await;
    let other = batch(vec![record(3, LogStream::Stdout, "not this claim's")]);
    assert_eq!(
        h.post_logs(&node_svid_of(OTHER_EK_HASH), &other)
            .await
            .status(),
        204
    );
    let (_, lines) = h.read_logs(&user, &claim.name, "").await;
    assert_eq!(seqs(&lines), vec![1, 2]);
}

#[tokio::test]
async fn a_trip_from_a_non_node_peer_or_another_claims_node_ends_nothing() {
    let h = Harness::start_traps(TrapsMode::Enforce, DeniedSwitches::default()).await;
    h.register_node().await;
    let user = h.login("octocat");
    let (_, first) = h.create_claim(&user).await;
    let first_uid = first.uid.expect("uid");
    // A second node, bound to a second claim.
    h.register_node_as(OTHER_EK_HASH).await;
    let (_, second) = h.create_claim(&user).await;
    assert_eq!(second.phase, mediatore_proto::ClaimPhase::Bound);
    let other_node = node_svid_of(OTHER_EK_HASH);

    // The claim's own identity, the gateway's authorizer, the gateway's listeners, a node
    // that never registered, and no identity at all: refused, and nothing ends.
    let events = [port_trip(uuid::Uuid::new_v4())];
    for (peer, expected) in [
        (claim_svid(&first_uid), 403),
        (authorizer_svid(), 403),
        (gateway_svid(), 403),
        (node_svid_of(&"e".repeat(64)), 403),
    ] {
        let resp = h.trip(&peer, "enforce", &events).await;
        assert_eq!(resp.status(), expected);
    }
    let resp = h
        .http
        .post(format!("{}/v1/me/trip", h.sandbox_url))
        .json(&serde_json::json!({ "mode": "enforce", "events": events }))
        .send()
        .await
        .expect("trip with no identity");
    assert_eq!(resp.status(), 401);
    for name in [&first.name, &second.name] {
        let held = h.claim_named(&user, name).await;
        assert_eq!(held.phase, mediatore_proto::ClaimPhase::Bound);
        assert!(held.tripped.is_none() && held.tripwires.is_none());
    }

    // The other claim's node reports a trip: its own claim ends, and this one does not. A
    // report names no claim, so a node can end none but the one bound to it.
    let resp = h.trip(&other_node, "enforce", &events).await;
    assert_eq!(resp.status(), 204);
    let untouched = h.claim_named(&user, &first.name).await;
    assert_eq!(untouched.phase, mediatore_proto::ClaimPhase::Bound);
    assert!(untouched.tripped.is_none() && untouched.tripwires.is_none());
    assert_eq!(
        h.token_for(&claim_svid(&first_uid), AUDIENCE)
            .await
            .status(),
        200,
        "the first claim still gets its token"
    );
    let ended = h.claim_named(&user, &second.name).await;
    assert!(
        ended.tripped.is_some(),
        "the reporting node's own claim ended"
    );
}

#[tokio::test]
async fn a_repeated_trip_id_is_idempotent() {
    let h = Harness::start_traps(TrapsMode::Enforce, DeniedSwitches::default()).await;
    h.register_node().await;
    let user = h.login("octocat");
    let (_, claim) = h.create_claim(&user).await;
    let id = uuid::Uuid::new_v4();
    let events = [port_trip(id)];
    // The guest retries until it reads 204: the same report, twice.
    for _ in 0..2 {
        let resp = h.trip(&node_svid(), "enforce", &events).await;
        assert_eq!(resp.status(), 204);
    }
    let ended = h.claim_named(&user, &claim.name).await;
    assert_eq!(ended.tripped.map(|t| t.id), Some(id));
    let summary = ended.tripwires.expect("the folded events");
    assert_eq!(summary.entries.len(), 1);
    assert_eq!(
        summary.entries[0].count, 1,
        "the retry is not counted again"
    );
}

#[tokio::test]
async fn a_trip_for_a_released_claim_is_a_no_op() {
    let h = Harness::start_traps(TrapsMode::Enforce, DeniedSwitches::default()).await;
    h.register_node().await;
    let user = h.login("octocat");
    let (_, claim) = h.create_claim(&user).await;
    // Its owner releases it; the guest's report arrives after.
    let resp = h
        .http
        .delete(format!("{}/v1/claims/{}", h.user_url, claim.name))
        .bearer_auth(&user)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), 204);
    let resp = h
        .trip(&node_svid(), "enforce", &[port_trip(uuid::Uuid::new_v4())])
        .await;
    assert_eq!(resp.status(), 204, "no error for the guest");
    let after = h.claim_named(&user, &claim.name).await;
    assert!(
        after.tripped.is_none(),
        "a claim that ended for another reason is not tripped after the fact"
    );
    // What the guest saw is still recorded, as reported: the event ended nothing.
    let summary = after.tripwires.expect("the folded events");
    assert_eq!(summary.entries[0].effect, TripEffect::Reported);
}

#[tokio::test]
async fn under_shadow_a_trip_is_recorded_and_the_claim_lives() {
    let h = Harness::start_traps(TrapsMode::Shadow, DeniedSwitches::default()).await;
    h.register_node().await;
    let user = h.login("octocat");
    let (_, claim) = h.create_claim(&user).await;
    let uid = claim.uid.expect("uid");
    let mut probed = port_trip(uuid::Uuid::new_v4());
    probed["count"] = 4.into();
    let denied = trip_event(
        uuid::Uuid::new_v4(),
        &serde_json::json!({ "kind": "denied", "class": "unknown_host", "target": { "host": "mirror.example" }, "source": "workload" }),
    );
    let resp = h.trip(&node_svid(), "shadow", &[probed, denied]).await;
    assert_eq!(resp.status(), 204);
    let held = h.claim_named(&user, &claim.name).await;
    assert_eq!(
        held.phase,
        mediatore_proto::ClaimPhase::Bound,
        "nothing ended"
    );
    assert!(held.ready && held.tripped.is_none());
    let summary = held.tripwires.expect("the folded events");
    assert_eq!(summary.entries.len(), 2);
    let port = summary
        .entries
        .iter()
        .find(|e| e.kind == TripKind::Port)
        .expect("the port entry");
    assert_eq!((port.effect, port.count), (TripEffect::WouldTrip, 4));
    assert_eq!(port.target, Some(TripTarget::Port(6379)));
    let host = summary
        .entries
        .iter()
        .find(|e| e.kind == TripKind::Denied)
        .expect("the denied entry");
    assert_eq!(host.effect, TripEffect::Reported, "a class at report");
    assert_eq!(h.token_for(&claim_svid(&uid), AUDIENCE).await.status(), 200);
    assert_eq!(h.me_status(&node_svid()).await, 200);
}

#[tokio::test]
async fn a_denied_class_moved_to_trip_ends_the_claim_under_enforce() {
    let h = Harness::start_traps(
        TrapsMode::Enforce,
        DeniedSwitches {
            unknown_host: ClassAction::Trip,
            ..DeniedSwitches::default()
        },
    )
    .await;
    h.register_node().await;
    let user = h.login("octocat");
    let (_, claim) = h.create_claim(&user).await;
    let id = uuid::Uuid::new_v4();
    let denied = trip_event(
        id,
        &serde_json::json!({ "kind": "denied", "class": "unknown_host", "target": { "host": "mirror.example" }, "source": "workload" }),
    );
    let resp = h.trip(&node_svid(), "enforce", &[denied]).await;
    assert_eq!(resp.status(), 204);
    let ended = h.claim_named(&user, &claim.name).await;
    let tripped = ended.tripped.expect("a class at trip ends the claim");
    assert_eq!(tripped.id, id);
    assert_eq!(tripped.kind, TripKind::Denied);
    assert_eq!(
        tripped.class,
        Some(mediatore_proto::trip::TripClass::UnknownHost)
    );
}

#[tokio::test]
async fn with_traps_off_the_route_is_501_and_me_carries_no_traps() {
    // The harness every other test here uses: `policy.traps` is off unless set.
    let h = Harness::start().await;
    h.register_node().await;
    let user = h.login("octocat");
    let (_, claim) = h.create_claim(&user).await;
    let resp = h
        .trip(&node_svid(), "enforce", &[port_trip(uuid::Uuid::new_v4())])
        .await;
    assert_eq!(resp.status(), 501);
    let body: ErrorBody = resp.json().await.expect("error body");
    assert_eq!(body.error, "not_implemented");
    let text = h
        .http
        .get(format!("{}/v1/me", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .send()
        .await
        .expect("me")
        .text()
        .await
        .expect("me body");
    assert!(
        !text.contains("traps"),
        "an off broker says nothing of traps"
    );
    let me: Me = serde_json::from_str(&text).expect("me");
    assert!(me.traps.is_none());
    let held = h.claim_named(&user, &claim.name).await;
    assert_eq!(held.phase, mediatore_proto::ClaimPhase::Bound);
    assert!(held.tripped.is_none() && held.tripwires.is_none());
}

// ---------- ADR-0070: a request no honest build makes, classified at the broker ----------

use mediatore_proto::trip::TripClass;

/// The log lines of the tests that ask for them, one buffer a test thread. One process-wide
/// subscriber, installed by the first test that captures, and a filter that lets an event
/// through only on a thread that is capturing: every other test of this binary logs nothing,
/// as before. A `#[tokio::test]` runs its broker on its own thread, so the buffer holds what
/// that test's broker logged and nothing of another's.
pub(crate) mod logs {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::{Layer as _, Registry};

    thread_local! {
        static CAPTURING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static LINES: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    struct ThreadLines;

    impl std::io::Write for ThreadLines {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            LINES.with(|l| l.borrow_mut().extend_from_slice(buf));
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Capture this thread's log lines, at every level, from nothing.
    pub(crate) fn capture() {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            let lines = tracing_subscriber::fmt::layer()
                .with_writer(|| ThreadLines)
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::dynamic_filter_fn(|_, _| {
                    CAPTURING.with(std::cell::Cell::get)
                }));
            tracing::subscriber::set_global_default(Registry::default().with(lines))
                .expect("the one subscriber of this test binary");
        });
        CAPTURING.with(|c| c.set(true));
        LINES.with(|l| l.borrow_mut().clear());
    }

    /// What this thread has logged since [`capture`].
    pub(crate) fn captured() -> String {
        LINES.with(|l| String::from_utf8_lossy(&l.borrow()).into_owned())
    }
}

/// The message of the audit line of a classified refusal.
const CLASSIFIED: &str = "a refusal no honest build earns";

impl Harness {
    /// A broker with each of `tripping` at `trip` and every other class at `report`, under
    /// `policy`: with one, what a guest is handed is recorded (`rendered`), which two of the
    /// classes are judged against.
    async fn start_classes(
        tripping: &[TripClass],
        policy: Option<mediatore_api::PolicyEgress>,
    ) -> Self {
        let mut tripwires = mediatore_api::Tripwires::default();
        for class in tripping {
            tripwires
                .classes
                .set(*class, ClassAction::Trip)
                .expect("a class that may trip");
        }
        Self::start_tripwires(
            Namespaces::Single("sandboxes".into()),
            None,
            std::collections::BTreeMap::new(),
            policy,
            None,
            tripwires,
        )
        .await
    }

    /// A claim bound to the standard node. Under a policy the claim names it, and the guest
    /// has fetched `GET /v1/me` once, so what it was handed is on the record.
    async fn bound(&self, user: &str, policy: Option<&str>) -> ClaimResponse {
        self.register_node().await;
        let resp = self
            .create_body(user, claim_body(AUDIENCE, policy, 3600))
            .await;
        assert_eq!(resp.status(), 201);
        let claim: ClaimResponse = resp.json().await.expect("claim body");
        assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Bound);
        assert_eq!(self.me_status(&node_svid()).await, 200);
        claim
    }

    /// One request on the sandbox listener as `peer`: the status and the body.
    async fn sandbox(
        &self,
        method: reqwest::Method,
        path: &str,
        peer: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, String) {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.sandbox_url))
            .header(PEER_HEADER, peer);
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = req.send().await.expect("sandbox request");
        let status = resp.status().as_u16();
        (status, resp.text().await.expect("body"))
    }

    /// A gateway's report of one denied tunnel for `uid` towards `authority`.
    async fn report_deny(&self, uid: uuid::Uuid, authority: &str, reason: &str) -> u16 {
        let batch = serde_json::json!({
            "gateway": "gateway-02",
            "decisions": [{
                "at": "2026-11-27T10:00:00Z", "claim_uid": uid, "kind": "tunnel",
                "authority": authority, "verdict": "deny", "reason": reason,
            }],
        });
        self.sandbox(
            reqwest::Method::POST,
            "/v1/gateway/decisions",
            &authorizer_svid(),
            Some(batch),
        )
        .await
        .0
    }

    /// The claim as its owner reads it, once `settled` says so, or as it is after two seconds.
    async fn claim_when(
        &self,
        user: &str,
        name: &str,
        settled: impl Fn(&ClaimResponse) -> bool,
    ) -> ClaimResponse {
        for _ in 0..200 {
            let claim = self.claim_named(user, name).await;
            if settled(&claim) {
                return claim;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        self.claim_named(user, name).await
    }

    /// The claim after the broker has flushed several times with nothing more to say.
    async fn claim_after_flushes(&self, user: &str, name: &str) -> ClaimResponse {
        tokio::time::sleep(FLUSH_EVERY * 8).await;
        self.claim_named(user, name).await
    }
}

/// The one `protocol` entry a claim's summary is expected to hold: its effect and its target.
fn protocol_entry(claim: &ClaimResponse, class: TripClass) -> (TripEffect, Option<TripTarget>) {
    let summary = claim.tripwires.as_ref().expect("a summary");
    assert_eq!(summary.entries.len(), 1, "one entry");
    let entry = &summary.entries[0];
    assert_eq!(entry.kind, TripKind::Protocol);
    assert_eq!(entry.class, Some(class));
    assert_eq!(entry.source, TripSource::Peer);
    assert_eq!(entry.trap, None, "the class is its own field");
    (entry.effect, entry.target.clone())
}

/// What every claim-scoped class is proven to do under both values (ADR-0070 decision 6):
/// `offend` makes the request that no honest build makes and returns its answer. At `report`
/// the claim lives and its summary gains a `reported` entry; at `trip` the same answer comes
/// back, and the claim is ended as ADR-0069 decision 9 ends one, with `tripped` saying why.
async fn ends_under_trip_and_only_records_under_report<F>(
    class: TripClass,
    with_policy: bool,
    target: Option<TripTarget>,
    offend: F,
) where
    F: AsyncFn(&Harness, uuid::Uuid) -> (u16, String),
{
    let mut answers = Vec::new();
    for tripping in [false, true] {
        let (policy, name) = if with_policy {
            let (pe, name) =
                bundle_policy(mediatore_claims::policy::EgressMode::Enforce, true).await;
            (Some(pe), Some(name))
        } else {
            (None, None)
        };
        let classes = if tripping { vec![class] } else { vec![] };
        let h = Harness::start_classes(&classes, policy).await;
        let user = h.login("octocat");
        let claim = h.bound(&user, name.as_deref()).await;
        let uid = claim.uid.expect("uid");
        assert_eq!(h.token_for(&claim_svid(&uid), AUDIENCE).await.status(), 200);

        answers.push(offend(&h, uid).await);

        if tripping {
            let ended = h
                .claim_when(&user, &claim.name, |c| {
                    c.tripped.is_some() && c.tripwires.is_some()
                })
                .await;
            let tripped = ended.tripped.clone().expect("the claim is tripped");
            assert_eq!(tripped.kind, TripKind::Protocol);
            assert_eq!(tripped.class, Some(class));
            assert_eq!(tripped.source, TripSource::Peer);
            assert_eq!(tripped.trap, None);
            assert_eq!(tripped.target, target);
            assert!(!ended.ready);
            assert_ne!(ended.phase, mediatore_proto::ClaimPhase::Bound, "released");
            assert_eq!(
                protocol_entry(&ended, class),
                (TripEffect::Tripped, target.clone())
            );
            // Ended as a trap on the VM ends one: no token, nothing for a gateway, no claim
            // for the guest to run.
            assert_eq!(h.token_for(&claim_svid(&uid), AUDIENCE).await.status(), 403);
            let (status, _) = h
                .sandbox(
                    reqwest::Method::GET,
                    &format!("/v1/gateway/claims/{uid}"),
                    &authorizer_svid(),
                    None,
                )
                .await;
            assert_eq!(status, 404);
            assert_eq!(h.me_status(&node_svid()).await, 404);
        } else {
            let held = h
                .claim_when(&user, &claim.name, |c| c.tripwires.is_some())
                .await;
            assert_eq!(
                protocol_entry(&held, class),
                (TripEffect::Reported, target.clone())
            );
            assert!(held.tripped.is_none(), "at report nothing is ended");
            assert_eq!(held.phase, mediatore_proto::ClaimPhase::Bound);
            assert_eq!(h.token_for(&claim_svid(&uid), AUDIENCE).await.status(), 200);
            assert_eq!(h.me_status(&node_svid()).await, 200);
        }
    }
    assert_eq!(
        answers[0], answers[1],
        "the request is answered the same at report and at trip"
    );
}

#[tokio::test]
async fn a_claim_identity_on_a_node_route_ends_the_claim_under_trip_and_only_records_under_report()
{
    ends_under_trip_and_only_records_under_report(
        TripClass::ForeignRoute,
        false,
        None,
        async |h: &Harness, uid| {
            let answer = h
                .sandbox(reqwest::Method::GET, "/v1/me", &claim_svid(&uid), None)
                .await;
            assert_eq!(answer.0, 403);
            answer
        },
    )
    .await;
}

#[tokio::test]
async fn a_path_the_broker_does_not_serve_ends_the_claim_under_trip_and_only_records_under_report()
{
    ends_under_trip_and_only_records_under_report(
        TripClass::UnknownRoute,
        false,
        None,
        async |h: &Harness, uid| {
            let answer = h
                .sandbox(
                    reqwest::Method::GET,
                    "/v1/me/routes",
                    &claim_svid(&uid),
                    None,
                )
                .await;
            assert_eq!(answer, (404, String::new()), "the router's own empty 404");
            answer
        },
    )
    .await;
}

#[tokio::test]
async fn an_audience_outside_rendered_ends_the_claim_under_trip_and_only_records_under_report() {
    ends_under_trip_and_only_records_under_report(
        TripClass::AudienceOutsideRendered,
        true,
        None,
        async |h: &Harness, uid| {
            let resp = h.token_for(&claim_svid(&uid), "nonexistent.test").await;
            let status = resp.status().as_u16();
            assert_eq!(status, 400);
            let text = resp.text().await.expect("body");
            assert!(text.contains("unknown_audience"));
            (status, text)
        },
    )
    .await;
}

#[tokio::test]
async fn a_reported_deny_outside_rendered_only_records_and_trip_is_refused() {
    // ADR-0070 decision 6 (amended 2026-11-27): the claim a deny names is the word of whoever
    // holds the authorizer's shared identity, so `trip` is refused for the class and a deny
    // for an authority never handed only records, with every class that may trip at trip.
    let mut refused = mediatore_api::Tripwires::default();
    assert!(
        refused
            .classes
            .set(TripClass::DenyOutsideRendered, ClassAction::Trip)
            .is_err()
    );
    let tripping: Vec<TripClass> = TripClass::PROTOCOL
        .into_iter()
        .filter(|c| c.may_trip())
        .collect();
    assert!(!tripping.contains(&TripClass::DenyOutsideRendered));
    let (pe, policy) = bundle_policy(mediatore_claims::policy::EgressMode::Enforce, true).await;
    let h = Harness::start_classes(&tripping, Some(pe)).await;
    let user = h.login("octocat");
    let claim = h.bound(&user, Some(&policy)).await;
    let uid = claim.uid.expect("uid");
    assert_eq!(
        h.report_deny(uid, "elsewhere.example:443", "not_allowed")
            .await,
        204
    );
    let held = h
        .claim_when(&user, &claim.name, |c| c.tripwires.is_some())
        .await;
    assert_eq!(
        protocol_entry(&held, TripClass::DenyOutsideRendered),
        (
            TripEffect::Reported,
            Some(TripTarget::Host("elsewhere.example".into()))
        )
    );
    assert!(held.tripped.is_none(), "a reported deny ends nothing");
    assert_eq!(held.phase, mediatore_proto::ClaimPhase::Bound);
    assert_eq!(h.token_for(&claim_svid(&uid), AUDIENCE).await.status(), 200);
    assert_eq!(h.me_status(&node_svid()).await, 200);
}

#[tokio::test]
async fn the_same_deny_for_a_route_rendered_and_since_narrowed_ends_nothing() {
    // The two classes judged against `rendered`, `audience_outside_rendered` at trip and
    // `deny_outside_rendered` at report (it records only, ADR-0070 decision 6 amended), where
    // a judged deny would still put an entry on the summary. A deny for an authority the
    // guest was handed is what a newer, narrower bundle produces at a gateway for an honest
    // proxy: the broker compares with what it recorded at the first `GET /v1/me`, so the
    // deny is inside it whatever the bundle says now.
    let classes = [TripClass::AudienceOutsideRendered];
    let (pe, policy) = bundle_policy(mediatore_claims::policy::EgressMode::Enforce, true).await;
    let h = Harness::start_classes(&classes, Some(pe)).await;
    let user = h.login("octocat");
    let claim = h.bound(&user, Some(&policy)).await;
    let uid = claim.uid.expect("uid");
    for authority in [
        "api.home.example:443",
        "192.0.2.10:8443",
        "API.home.example",
    ] {
        assert_eq!(h.report_deny(uid, authority, "not_allowed").await, 204);
    }
    // A release racing a request: the gateway's own word for it, whatever the authority.
    assert_eq!(
        h.report_deny(uid, "elsewhere.example:443", "claim_gone")
            .await,
        204
    );
    let held = h.claim_after_flushes(&user, &claim.name).await;
    assert_eq!(held.phase, mediatore_proto::ClaimPhase::Bound);
    assert!(held.tripped.is_none() && held.tripwires.is_none());
    assert_eq!(h.token_for(&claim_svid(&uid), AUDIENCE).await.status(), 200);

    // And a claim under no policy has nothing rendered: neither class judges it, at trip.
    let h = Harness::start_classes(&classes, None).await;
    let user = h.login("octocat");
    let claim = h.bound(&user, None).await;
    let uid = claim.uid.expect("uid");
    assert_eq!(
        h.report_deny(uid, "elsewhere.example:443", "not_allowed")
            .await,
        204
    );
    let resp = h.token_for(&claim_svid(&uid), "nonexistent.test").await;
    assert_eq!(resp.status(), 400);
    let held = h.claim_after_flushes(&user, &claim.name).await;
    assert_eq!(held.phase, mediatore_proto::ClaimPhase::Bound);
    assert!(held.tripped.is_none() && held.tripwires.is_none());
}

#[tokio::test]
async fn the_authorizers_classes_never_end_a_claim() {
    logs::capture();
    // Every class that may be set to trip is at trip; the authorizer's two cannot be.
    let tripping: Vec<TripClass> = TripClass::PROTOCOL
        .into_iter()
        .filter(|c| c.may_trip())
        .collect();
    let mut refused = mediatore_api::Tripwires::default();
    for class in [
        TripClass::ClaimNeverIssued,
        TripClass::CredentialOutsideInject,
        TripClass::DenyOutsideRendered,
        TripClass::NoRecord,
        TripClass::IdentityShape,
    ] {
        assert!(refused.classes.set(class, ClassAction::Trip).is_err());
    }
    let (pe, policy) = bundle_policy(mediatore_claims::policy::EgressMode::Enforce, true).await;
    let h = Harness::start_classes(&tripping, Some(pe)).await;
    let user = h.login("octocat");
    let claim = h.bound(&user, Some(&policy)).await;
    let uid = claim.uid.expect("uid");
    let ghost = uuid::Uuid::new_v4();
    let audience = |a: &str| Some(serde_json::json!({ "audience": a }));
    let get = reqwest::Method::GET;
    let post = reqwest::Method::POST;
    for (method, path, body, status) in [
        // `claim_never_issued`: a uid the store holds no record of.
        (
            get.clone(),
            format!("/v1/gateway/claims/{ghost}"),
            None,
            404,
        ),
        (
            post.clone(),
            format!("/v1/gateway/claims/{ghost}/credential"),
            audience(AUDIENCE),
            404,
        ),
        // `credential_outside_inject`: an audience placed in the proxy, and one that is not
        // the claim's.
        (
            post.clone(),
            format!("/v1/gateway/claims/{uid}/credential"),
            audience(AUDIENCE),
            403,
        ),
        (
            post.clone(),
            format!("/v1/gateway/claims/{uid}/credential"),
            audience("nonexistent.test"),
            400,
        ),
        // `foreign_route` and `unknown_route` under the authorizer's identity: classes that
        // end a claim when a claim makes them, and nothing when the authorizer does.
        (get.clone(), "/v1/me".to_owned(), None, 403),
        (
            post.clone(),
            "/v1/token".to_owned(),
            audience(AUDIENCE),
            403,
        ),
        (get, "/v1/gateway/routes".to_owned(), None, 404),
    ] {
        let (got, _) = h
            .sandbox(method.clone(), &path, &authorizer_svid(), body)
            .await;
        assert_eq!(got, status, "{method} {path}");
    }
    let held = h.claim_after_flushes(&user, &claim.name).await;
    assert_eq!(held.phase, mediatore_proto::ClaimPhase::Bound);
    assert!(held.tripped.is_none() && held.tripwires.is_none());
    assert_eq!(h.token_for(&claim_svid(&uid), AUDIENCE).await.status(), 200);
    // Each was recorded all the same: one line a class, naming the authorizer.
    let lines = logs::captured();
    for class in [
        "claim_never_issued",
        "credential_outside_inject",
        "foreign_route",
        "unknown_route",
    ] {
        let line = lines
            .lines()
            .find(|l| l.contains(CLASSIFIED) && l.contains(&format!("class=\"{class}\"")))
            .unwrap_or_else(|| panic!("a line for {class}"));
        assert!(line.contains("scope=\"authorizer\""), "{class}");
        assert!(line.contains(&authorizer_svid()), "{class}");
    }
    assert!(!lines.contains("claim ended by a trip"));
}

const CANARY_PATH: &str = "canary-path-3e71";
const CANARY_QUERY: &str = "canary-query-a6c2";
const CANARY_HEADER: &str = "canary-header-d94b";
const CANARY_TOKEN: &str = "canary-token-58f0";

/// A request of each class of ADR-0070 about claim `uid`, each with a canary where a peer
/// can put one: the method, the path, the peer and the body.
fn canary_requests(uid: uuid::Uuid) -> Vec<(reqwest::Method, String, String, serde_json::Value)> {
    let ghost = uuid::Uuid::new_v4();
    let odd_audience = format!("aud/{CANARY_TOKEN}?");
    let deny = serde_json::json!({
        "gateway": "gateway-02",
        "decisions": [{
            "at": "2026-11-27T10:00:00Z", "claim_uid": uid, "kind": "inject",
            "authority": "elsewhere.example", "verdict": "deny", "reason": "not_allowed",
        }],
    });
    vec![
        // The authorizer's classes, and a deny outside what the claim was handed.
        (
            reqwest::Method::GET,
            format!("/v1/gateway/claims/{ghost}"),
            authorizer_svid(),
            serde_json::Value::Null,
        ),
        (
            reqwest::Method::GET,
            format!("/v1/gateway/claims/{CANARY_PATH}"),
            authorizer_svid(),
            serde_json::Value::Null,
        ),
        (
            reqwest::Method::POST,
            format!("/v1/gateway/claims/{uid}/credential"),
            authorizer_svid(),
            serde_json::json!({ "audience": odd_audience }),
        ),
        (
            reqwest::Method::POST,
            format!("/v1/gateway/claims/{uid}/credential"),
            authorizer_svid(),
            serde_json::json!({ "audience": AUDIENCE }),
        ),
        (
            reqwest::Method::POST,
            "/v1/gateway/decisions".into(),
            authorizer_svid(),
            deny,
        ),
        // A claim and a node with no record.
        (
            reqwest::Method::POST,
            "/v1/token".into(),
            claim_svid(&ghost),
            serde_json::json!({ "audience": odd_audience }),
        ),
        (
            reqwest::Method::GET,
            "/v1/me".into(),
            node_svid_of(OTHER_EK_HASH),
            serde_json::Value::Null,
        ),
        // The claim's own: an audience it was never handed, a node route, a gateway
        // route, paths the broker does not serve.
        (
            reqwest::Method::POST,
            "/v1/token".into(),
            claim_svid(&uid),
            serde_json::json!({ "audience": odd_audience }),
        ),
        (
            reqwest::Method::GET,
            "/v1/me".into(),
            claim_svid(&uid),
            serde_json::Value::Null,
        ),
        (
            reqwest::Method::POST,
            "/v1/me/exit".into(),
            claim_svid(&uid),
            serde_json::json!({ "restarts": 0 }),
        ),
        (
            reqwest::Method::GET,
            format!("/v1/gateway/claims/{CANARY_PATH}"),
            claim_svid(&uid),
            serde_json::Value::Null,
        ),
        (
            reqwest::Method::GET,
            format!("/v1/{CANARY_PATH}"),
            claim_svid(&uid),
            serde_json::Value::Null,
        ),
        (
            reqwest::Method::POST,
            format!("/{CANARY_PATH}/v1/token"),
            node_svid(),
            serde_json::json!({ "audience": CANARY_TOKEN }),
        ),
        (
            reqwest::Method::POST,
            "/v1/token".into(),
            node_svid(),
            serde_json::json!({ "audience": CANARY_TOKEN }),
        ),
    ]
}

#[tokio::test]
async fn the_canary_scan_finds_nothing_the_peer_sent() {
    // ADR-0070 decision 9, over the real listener: a token, a path, a query and headers
    // planted on every classified route, and every line the broker wrote, at every level.
    logs::capture();
    let tripping: Vec<TripClass> = TripClass::PROTOCOL
        .into_iter()
        .filter(|c| c.may_trip())
        .collect();
    let mut kept = String::new();
    for tripping in [vec![], tripping] {
        let (pe, policy) = bundle_policy(mediatore_claims::policy::EgressMode::Enforce, true).await;
        let h = Harness::start_classes(&tripping, Some(pe)).await;
        let user = h.login("octocat");
        let claim = h.bound(&user, Some(&policy)).await;
        let uid = claim.uid.expect("uid");
        let query = format!("?token={CANARY_TOKEN}&q={CANARY_QUERY}");
        let requests = canary_requests(uid);
        for (method, path, peer, body) in requests {
            let mut req = h
                .http
                .request(method, format!("{}{path}{query}", h.sandbox_url))
                .header(PEER_HEADER, peer)
                .header("authorization", format!("Bearer {CANARY_TOKEN}"))
                .header("x-api-key", CANARY_TOKEN)
                .header("cookie", format!("session={CANARY_HEADER}"))
                .header("x-canary", CANARY_HEADER);
            if !body.is_null() {
                req = req.json(&body);
            }
            req.send().await.expect("planted request");
        }
        let held = h.claim_after_flushes(&user, &claim.name).await;
        assert_eq!(held.tripped.is_some(), !tripping.is_empty());
        kept.push_str(&serde_json::to_string(&held).expect("json"));
    }
    let lines = logs::captured();
    // The capture is live down to the request span, and every class fired in it.
    assert!(lines.contains("request{method=\"POST\" route=\"/v1/token\"}"));
    for class in [
        "foreign_route",
        "unknown_route",
        "no_record",
        "audience_outside_rendered",
        "claim_never_issued",
        "credential_outside_inject",
        "deny_outside_rendered",
    ] {
        let fired = lines
            .lines()
            .any(|l| l.contains(CLASSIFIED) && l.contains(&format!("class=\"{class}\"")));
        assert!(fired, "{class} fired in this run");
    }
    assert!(lines.contains("claim ended by a trip"));
    // What the broker wrote: every line but the test's own HTTP client's, which runs in this
    // process and names the URLs it was told to ask for.
    let broker: Vec<&str> = lines
        .lines()
        .filter(|l| !CLIENT_TARGETS.iter().any(|t| l.contains(t)))
        .collect();
    assert!(broker.len() > 50, "the broker's lines are in the capture");
    for canary in [CANARY_PATH, CANARY_QUERY, CANARY_HEADER, CANARY_TOKEN] {
        assert!(
            !broker.iter().any(|l| l.contains(canary)),
            "a value the peer planted is in a line of the broker"
        );
        assert!(
            !kept.contains(canary),
            "a value the peer planted is shown to the owner"
        );
    }
}

/// The log targets of the HTTP client these tests send with.
const CLIENT_TARGETS: [&str; 3] = [" reqwest::", " hyper_util::client::", " hyper::client::"];

// ----- an x509pop node's registration (ADR-0049 decision 8) -------------------------------

/// The common name of the host CA and the subject its signer gave the guest.
const HOST_CA_CN: &str = "hv-01";
const GUEST_SUBJECT_CN: &str = "3f0c2a1e-7b1d-4e0a-9c55-0a1b2c3d4e5f";
const DMI: &str = "6b0a3e9c-1f4d-4c2e-9a7b-0d1e2f3a4b5c";

/// The identity an x509pop guest attested under: the node key and the agent ID the watcher
/// declared its node entry with, from the same functions the broker uses.
fn x509pop_identity(issuer_cn: &str, subject_cn: &str) -> mediatore_spire::NodeIdentity {
    mediatore_spire::NodeIdentity::of(
        &Naming {
            trust_domain: TRUST_DOMAIN.into(),
        },
        &mediatore_spire::NodeAttestation::X509pop {
            issuer_cn: issuer_cn.into(),
            subject_cn: subject_cn.into(),
        },
    )
    .expect("an x509pop identity")
}

/// The node SVID SPIRE issues under that node entry.
fn x509pop_node_svid(issuer_cn: &str, subject_cn: &str) -> String {
    format!(
        "spiffe://{TRUST_DOMAIN}/banlieue/node/{}",
        x509pop_identity(issuer_cn, subject_cn).key
    )
}

fn x509pop_attestation(issuer_cn: &str, subject_cn: &str) -> serde_json::Value {
    serde_json::json!({ "kind": "x509pop", "issuer_cn": issuer_cn, "subject_cn": subject_cn })
}

/// A registration body around `extra` (the `ek_hash`, the `attestation`, or both).
fn registration_body(extra: &serde_json::Value) -> serde_json::Value {
    let mut body = serde_json::json!({ "dmi_uuid": DMI, "hostname": "pool-fc-1" });
    for (k, v) in extra.as_object().expect("an object") {
        body[k] = v.clone();
    }
    body
}

impl Harness {
    /// `POST /v1/nodes` as `peer`, with a raw JSON body: what a guest of any version sends.
    async fn post_node(&self, peer: &str, body: &serde_json::Value) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/nodes", self.sandbox_url))
            .header(PEER_HEADER, peer)
            .json(body)
            .send()
            .await
            .expect("register")
    }

    /// The status `GET /v1/me` answers `peer` with.
    async fn me_status(&self, peer: &str) -> reqwest::StatusCode {
        self.http
            .get(format!("{}/v1/me", self.sandbox_url))
            .header(PEER_HEADER, peer)
            .send()
            .await
            .expect("me")
            .status()
    }
}

#[tokio::test]
async fn an_x509pop_node_registers_is_bound_and_its_claims_entry_is_parented_to_its_x509pop_agent()
{
    let h = Harness::start().await;
    let node = x509pop_identity(HOST_CA_CN, GUEST_SUBJECT_CN);
    let svid = x509pop_node_svid(HOST_CA_CN, GUEST_SUBJECT_CN);
    let agent =
        format!("spiffe://{TRUST_DOMAIN}/spire/agent/x509pop/{HOST_CA_CN}/{GUEST_SUBJECT_CN}");
    assert_eq!(node.agent_id, agent);

    // The guest sends the names of its leaf, exactly as the typed client serializes them.
    let reg = NodeRegistration::x509pop(
        HOST_CA_CN.into(),
        GUEST_SUBJECT_CN.into(),
        DMI.parse().expect("dmi"),
        "pool-fc-1".into(),
    );
    let resp = h
        .post_node(&svid, &serde_json::to_value(&reg).expect("body"))
        .await;
    assert_eq!(resp.status(), 200, "the registration was refused");
    let registered: NodeRegistered = resp.json().await.expect("node body");
    assert_eq!(
        registered.node_id, agent,
        "the stored agent ID is the x509pop one, not spire/agent/tpm/<key>"
    );

    // A claim binds to it, and the node learns its subject over its own identity.
    let (status, claim) = h.create_claim(&h.login("octocat")).await;
    assert_eq!(status, 201);
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Bound);
    let uid = claim.uid.expect("uid");
    let me = h
        .http
        .get(format!("{}/v1/me", h.sandbox_url))
        .header(PEER_HEADER, &svid)
        .send()
        .await
        .expect("me");
    assert_eq!(me.status(), 200);
    let me: mediatore_proto::Me = me.json().await.expect("me body");
    assert_eq!(me.claim_uid, uid);

    // The claim's entry hangs off the x509pop agent: the workload's SVID is issued there.
    assert_eq!(
        h.entries.parent_of(&mediatore_spire::claim_entry_name(uid)),
        Some(agent)
    );
    // Registering again (a reboot, the same machine) is the same node.
    let again = h
        .post_node(&svid, &serde_json::to_value(&reg).expect("body"))
        .await;
    assert_eq!(again.status(), 200);
}

#[tokio::test]
async fn a_pending_claim_binds_when_an_x509pop_node_registers_later() {
    let h = Harness::start().await;
    let (_, claim) = h.create_claim(&h.login("octocat")).await;
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Pending);
    let svid = x509pop_node_svid(HOST_CA_CN, GUEST_SUBJECT_CN);
    let body = registration_body(&serde_json::json!({
        "attestation": x509pop_attestation(HOST_CA_CN, GUEST_SUBJECT_CN)
    }));
    assert_eq!(h.post_node(&svid, &body).await.status(), 200);
    assert_eq!(h.me_status(&svid).await, 200, "bound on registration");
}

#[tokio::test]
async fn x509pop_names_that_do_not_hash_to_the_peers_node_id_are_forbidden() {
    // The peer's SVID is the node entry's, declared for exactly one pair of names. A guest
    // that sends other names, or a TPM node that sends x509pop names, registers nothing.
    let h = Harness::start().await;
    let attested = x509pop_node_svid(HOST_CA_CN, GUEST_SUBJECT_CN);
    for (peer, issuer, subject) in [
        // Another guest of the same host, and the same subject under another host.
        (attested.clone(), HOST_CA_CN, "another-guest"),
        (attested.clone(), "hv-02", GUEST_SUBJECT_CN),
        // The names swapped.
        (attested.clone(), GUEST_SUBJECT_CN, HOST_CA_CN),
        // A TPM node's identity claiming x509pop names.
        (node_svid(), HOST_CA_CN, GUEST_SUBJECT_CN),
    ] {
        let body = registration_body(&serde_json::json!({
            "attestation": x509pop_attestation(issuer, subject)
        }));
        let (status, code) = refusal(h.post_node(&peer, &body).await).await;
        assert_eq!(
            (status, code.error.as_str()),
            (403, "forbidden"),
            "{issuer}/{subject}"
        );
    }
    // And an x509pop node's identity claiming an EK.
    let body = registration_body(&serde_json::json!({ "ek_hash": EK_HASH }));
    let (status, code) = refusal(h.post_node(&attested, &body).await).await;
    assert_eq!((status, code.error.as_str()), (403, "forbidden"));
    // Nothing was registered under either identity.
    assert_eq!(h.me_status(&attested).await, 403);
    assert_eq!(h.me_status(&node_svid()).await, 403);
}

#[tokio::test]
async fn an_x509pop_attestation_beside_an_ek_hash_is_a_bad_request() {
    let h = Harness::start().await;
    let svid = x509pop_node_svid(HOST_CA_CN, GUEST_SUBJECT_CN);
    let body = registration_body(&serde_json::json!({
        "ek_hash": EK_HASH,
        "attestation": x509pop_attestation(HOST_CA_CN, GUEST_SUBJECT_CN)
    }));
    // Refused whichever of the two identities sends it.
    for peer in [svid.clone(), node_svid()] {
        let (status, code) = refusal(h.post_node(&peer, &body).await).await;
        assert_eq!((status, code.error.as_str()), (400, "invalid_attestation"));
    }
    assert_eq!(h.me_status(&svid).await, 403, "nothing was registered");
}

#[tokio::test]
async fn an_unknown_attestation_kind_or_field_is_a_bad_request() {
    let h = Harness::start().await;
    let svid = x509pop_node_svid(HOST_CA_CN, GUEST_SUBJECT_CN);
    for attestation in [
        serde_json::json!({ "kind": "join_token", "token": "abc" }),
        serde_json::json!({ "kind": "X509POP", "issuer_cn": HOST_CA_CN, "subject_cn": GUEST_SUBJECT_CN }),
        serde_json::json!({ "kind": "x509pop", "issuer_cn": HOST_CA_CN, "subject_cn": GUEST_SUBJECT_CN, "fingerprint": "00" }),
        serde_json::json!({ "kind": "x509pop", "issuer_cn": HOST_CA_CN }),
        serde_json::json!({ "kind": "tpm", "ek_hash": EK_HASH, "subject_cn": GUEST_SUBJECT_CN }),
        serde_json::json!({ "issuer_cn": HOST_CA_CN, "subject_cn": GUEST_SUBJECT_CN }),
        serde_json::json!("x509pop"),
    ] {
        // With and without a valid top-level ek_hash beside it: an attestation that cannot
        // be read is never skipped in favour of the EK.
        for with_ek in [false, true] {
            let mut extra = serde_json::json!({ "attestation": attestation });
            if with_ek {
                extra["ek_hash"] = serde_json::json!(EK_HASH);
            }
            let peer = if with_ek { node_svid() } else { svid.clone() };
            let (status, code) =
                refusal(h.post_node(&peer, &registration_body(&extra)).await).await;
            assert_eq!(
                (status, code.error.as_str()),
                (400, "invalid_attestation"),
                "an unreadable attestation was not refused as one (with_ek={with_ek})"
            );
        }
    }
    assert_eq!(h.me_status(&svid).await, 403);
    assert_eq!(h.me_status(&node_svid()).await, 403);
}

#[tokio::test]
async fn a_registration_naming_no_attestation_a_disagreeing_one_or_a_bad_name_is_a_bad_request() {
    let h = Harness::start().await;
    let svid = x509pop_node_svid(HOST_CA_CN, GUEST_SUBJECT_CN);
    // Neither an attestation nor an ek_hash: the bad EK hash it always was.
    for extra in [serde_json::json!({}), serde_json::json!({ "ek_hash": "" })] {
        let (status, code) =
            refusal(h.post_node(&node_svid(), &registration_body(&extra)).await).await;
        assert_eq!((status, code.error.as_str()), (400, "invalid_ek_hash"));
    }
    // A tpm attestation that is not the top-level hash, and one whose hash is no hash.
    let other = "ab".repeat(32);
    let disagreeing = registration_body(&serde_json::json!({
        "ek_hash": EK_HASH, "attestation": { "kind": "tpm", "ek_hash": other }
    }));
    let (status, code) = refusal(h.post_node(&node_svid(), &disagreeing).await).await;
    assert_eq!((status, code.error.as_str()), (400, "invalid_attestation"));
    let malformed = registration_body(&serde_json::json!({
        "attestation": { "kind": "tpm", "ek_hash": "3f9a" }
    }));
    let (status, code) = refusal(h.post_node(&node_svid(), &malformed).await).await;
    assert_eq!((status, code.error.as_str()), (400, "invalid_ek_hash"));
    // A common name that cannot be a path segment of the agent ID.
    for (issuer, subject) in [
        (HOST_CA_CN, "../hv-02/other"),
        ("hv 01", GUEST_SUBJECT_CN),
        ("", GUEST_SUBJECT_CN),
        (HOST_CA_CN, ".."),
    ] {
        let body = registration_body(&serde_json::json!({
            "attestation": x509pop_attestation(issuer, subject)
        }));
        let (status, code) = refusal(h.post_node(&svid, &body).await).await;
        assert_eq!(
            (status, code.error.as_str()),
            (400, "invalid_attestation"),
            "a name outside the alphabet was not refused as a bad attestation"
        );
    }
    // A body that is not a registration at all stays unprocessable, as before.
    let no_dmi = serde_json::json!({ "ek_hash": EK_HASH, "hostname": "pool-a-7" });
    assert_eq!(h.post_node(&node_svid(), &no_dmi).await.status(), 422);
    assert_eq!(h.me_status(&node_svid()).await, 403, "nothing registered");
}

#[tokio::test]
async fn a_v0_4_0_registration_body_still_registers_and_binds() {
    // Byte for byte what a v0.4.0 guest sends: the top-level ek_hash and no attestation.
    let h = Harness::start().await;
    let body = format!(
        r#"{{"ek_hash":"{EK_HASH}","dmi_uuid":"{DMI}","hostname":"pool-a-7","provider":"libvirt"}}"#
    );
    let resp = h
        .http
        .post(format!("{}/v1/nodes", h.sandbox_url))
        .header(PEER_HEADER, node_svid())
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("register");
    assert_eq!(resp.status(), 200, "the registration was refused");
    let registered: NodeRegistered = resp.json().await.expect("node body");
    let agent = format!("spiffe://{TRUST_DOMAIN}/spire/agent/tpm/{EK_HASH}");
    assert_eq!(registered.node_id, agent);
    let (_, claim) = h.create_claim(&h.login("octocat")).await;
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Bound);
    assert_eq!(
        h.entries
            .parent_of(&mediatore_spire::claim_entry_name(claim.uid.expect("uid"))),
        Some(agent)
    );
    assert_eq!(h.me_status(&node_svid()).await, 200);
}

#[tokio::test]
async fn a_tpm_attestation_that_agrees_with_the_top_level_ek_hash_registers_the_same_node() {
    let h = Harness::start().await;
    let tpm = serde_json::json!({ "kind": "tpm", "ek_hash": EK_HASH });
    for extra in [
        serde_json::json!({ "attestation": tpm }),
        serde_json::json!({ "attestation": tpm, "ek_hash": EK_HASH }),
    ] {
        let resp = h.post_node(&node_svid(), &registration_body(&extra)).await;
        assert_eq!(resp.status(), 200);
        let registered: NodeRegistered = resp.json().await.expect("node body");
        assert_eq!(
            registered.node_id,
            format!("spiffe://{TRUST_DOMAIN}/spire/agent/tpm/{EK_HASH}")
        );
    }
}

#[tokio::test]
async fn a_key_first_registered_as_an_ek_is_a_conflict_for_its_honest_x509pop_registration() {
    // The node SVID of an x509pop guest carries a 64 hex key, which is also the shape of an
    // EK hash: the guest can register it as one, and the broker cannot tell (it is what a
    // TPM node of that hash would send). What must not follow is a later, honest
    // registration answered 200 with an agent ID the record does not hold.
    let h = Harness::start().await;
    let node = x509pop_identity(HOST_CA_CN, GUEST_SUBJECT_CN);
    let svid = x509pop_node_svid(HOST_CA_CN, GUEST_SUBJECT_CN);
    let as_ek = registration_body(&serde_json::json!({ "ek_hash": node.key }));
    let honest = registration_body(&serde_json::json!({
        "attestation": x509pop_attestation(HOST_CA_CN, GUEST_SUBJECT_CN)
    }));

    // Under its own key, as an EK: taken, and stored under the tpm agent ID of that key.
    let resp = h.post_node(&svid, &as_ek).await;
    assert_eq!(resp.status(), 200);
    let registered: NodeRegistered = resp.json().await.expect("node body");
    let tpm_agent = format!("spiffe://{TRUST_DOMAIN}/spire/agent/tpm/{}", node.key);
    assert_eq!(registered.node_id, tpm_agent);

    // Honestly, afterwards: refused as a conflict of its own kind, the same machine or
    // another one, and the record is not rewritten.
    let (status, body) = refusal(h.post_node(&svid, &honest).await).await;
    assert_eq!(
        (status, body.error.as_str()),
        (409, "node_identity_conflict")
    );
    let mut other_machine = honest.clone();
    other_machine["dmi_uuid"] = serde_json::json!(uuid::Uuid::new_v4().to_string());
    let (status, body) = refusal(h.post_node(&svid, &other_machine).await).await;
    assert_eq!(
        (status, body.error.as_str()),
        (409, "node_identity_conflict")
    );
    // What it registered first still answers as it did.
    let resp = h.post_node(&svid, &as_ek).await;
    assert_eq!(resp.status(), 200);
    let again: NodeRegistered = resp.json().await.expect("node body");
    assert_eq!(again.node_id, tpm_agent, "the stored agent ID, unchanged");

    // A claim bound to that record hangs off an agent no attestor can produce for this
    // guest: its entry is parented to the stored tpm ID, never to the x509pop agent.
    let (_, claim) = h.create_claim(&h.login("octocat")).await;
    assert_eq!(claim.phase, mediatore_proto::ClaimPhase::Bound);
    assert_eq!(
        h.entries
            .parent_of(&mediatore_spire::claim_entry_name(claim.uid.expect("uid"))),
        Some(tpm_agent)
    );
}

#[tokio::test]
async fn the_reverse_conflict_a_key_registered_as_x509pop_refuses_a_later_ek_registration() {
    let h = Harness::start().await;
    let node = x509pop_identity(HOST_CA_CN, GUEST_SUBJECT_CN);
    let svid = x509pop_node_svid(HOST_CA_CN, GUEST_SUBJECT_CN);
    let honest = registration_body(&serde_json::json!({
        "attestation": x509pop_attestation(HOST_CA_CN, GUEST_SUBJECT_CN)
    }));
    assert_eq!(h.post_node(&svid, &honest).await.status(), 200);
    let as_ek = registration_body(&serde_json::json!({ "ek_hash": node.key }));
    let (status, body) = refusal(h.post_node(&svid, &as_ek).await).await;
    assert_eq!(
        (status, body.error.as_str()),
        (409, "node_identity_conflict")
    );
    let resp = h.post_node(&svid, &honest).await;
    assert_eq!(resp.status(), 200);
    let again: NodeRegistered = resp.json().await.expect("node body");
    assert_eq!(again.node_id, node.agent_id);
}
