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
    http: reqwest::Client,
}

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
        let idp = FakeIdp::start().await;
        let sts = Sts::new(
            "https://mediatore.test",
            "e2e-1",
            STS_TEST_KEY.as_bytes(),
            SignedDuration::from_mins(15),
        )
        .expect("sts");
        let state = Arc::new(AppState {
            inject: std::collections::BTreeMap::new(),
            inject_port: None,
            logs,
            log_limiter: Limiter::per_second(2),
            log_wakes: mediatore_api::LogWakes::default(),
            accept_plain_gateway_identity: false,
            scopes,
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
            policy_egress: policy,
            sandboxes: None,
            namespaces,
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

fn tenant_map() -> Namespaces {
    Namespaces::Map(std::collections::BTreeMap::from([
        ("infra".to_owned(), vec![ADMIN_GROUP.to_owned()]),
        ("team-a".to_owned(), vec![TEAM_A_GROUP.to_owned()]),
    ]))
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
