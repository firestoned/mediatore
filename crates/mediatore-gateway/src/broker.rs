// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Where a claim's allowlist comes from: the broker's gateway-only route (ADR-0028
//! decision 4), `GET /v1/gateway/claims/{uid}`, asked over SPIFFE mTLS with the authorizer's
//! own SVID, `spiffe://<td>/gateway/authorizer`, from the local Workload API (ADR-0053
//! decisions 1 and 2). The gateway's listeners hold `spiffe://<td>/gateway`; the authorizer
//! never asks under that name and does not start when its own is not to be had.

use std::sync::Arc;
use std::time::Duration;

use mediatore_proto::{ClaimEgress, GatewayCredential, GatewayCredentialRequest, GatewayDecisions};
use mediatore_spire::Naming;
use mediatore_tls::{MaterialSource, SpiffeId, WorkloadApiSource};
use uuid::Uuid;

/// Header carrying the peer SPIFFE ID against a `dev_mode` broker.
#[cfg(feature = "dev")]
const DEV_PEER_HEADER: &str = "x-mediatore-peer-spiffe-id";

/// The path of the authorizer's SPIFFE ID, `spiffe://<td>/gateway/authorizer` (ADR-0053
/// decision 1; `Naming::gateway_authorizer_id`, which a test holds this to). The SVID asked
/// of the Workload API is the one with exactly this path, never the agent's default.
pub const AUTHORIZER_PATH: &str = "/gateway/authorizer";

/// Refuse any identity but the authorizer's own (ADR-0053 decision 2): exactly
/// `spiffe://<td>/gateway/authorizer` in `own`'s trust domain. The listeners'
/// `spiffe://<td>/gateway` is refused like any other name.
pub fn ensure_authorizer(own: &SpiffeId) -> anyhow::Result<()> {
    let naming = Naming {
        trust_domain: own.trust_domain().to_string(),
    };
    anyhow::ensure!(
        naming.is_gateway_authorizer(&own.to_string()),
        "the authorizer's identity must be {}, got {own}: it does not start under another name",
        naming.gateway_authorizer_id()
    );
    Ok(())
}

/// How long the authorizer waits for its first SVID before it fails closed. The gateway's
/// entry is static (ADR-0028 decision 2), so the agent has it as soon as it attested;
/// bounded all the same, so an absent agent is an error that names the cause.
pub const WORKLOAD_API_WAIT: Duration = Duration::from_secs(90);

/// One ask of the broker, bounded: an answer slower than this is an outage for the
/// decision at hand, which falls back to the cache or denies.
pub const ASK_TIMEOUT: Duration = Duration::from_secs(5);

/// What the broker said about a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The claim is bound and live: its allowlist and its deadline.
    Found(ClaimEgress),
    /// `404`: pending, released, expired or unknown. The gateway forgets the claim.
    Gone,
}

/// Why the broker gave no answer.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AskError {
    /// No connection, no SVID, a timeout, a `5xx`: the broker is unreachable for this ask.
    /// A cached answer may stand in, within its bound.
    #[error("broker unreachable: {0}")]
    Unreachable(String),
    /// The broker answered and refused us (`401`, `403`): our identity is not the gateway's
    /// in its eyes. Nothing cached stands in for that.
    #[error("broker refused the gateway: {0}")]
    Refused(u16),
}

/// A source of allowlists, by claim UID.
#[async_trait::async_trait]
pub trait Allowlists: Send + Sync {
    /// Ask once; no retry, the cache decides what an outage means.
    async fn ask(&self, claim_uid: Uuid) -> Result<Answer, AskError>;
}

/// What the broker said about a claim's credential for one audience (ADR-0040 decision 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialAnswer {
    /// The credential and when it stops being good. The value prints as `[redacted]`.
    Found(GatewayCredential),
    /// `404`: the claim is pending, released, expired or unknown. The gateway forgets it.
    Gone,
}

/// A source of gateway-placed credentials, by claim UID and audience.
#[async_trait::async_trait]
pub trait Credentials: Send + Sync {
    /// Ask once; no retry. `401` and `403` are [`AskError::Refused`]: the caller tells the
    /// gateway's own identity being refused (`401`) from the credential being refused (`403`).
    async fn credential(
        &self,
        claim_uid: Uuid,
        audience: &str,
    ) -> Result<CredentialAnswer, AskError>;
}

/// `POST /v1/gateway/claims/{uid}/credential`'s URL.
#[must_use]
pub fn credential_url(base: &str, claim_uid: Uuid) -> String {
    format!(
        "{}/v1/gateway/claims/{claim_uid}/credential",
        base.trim_end_matches('/')
    )
}

/// What a status and a body from the credential route mean. The body of a refusal is never
/// read, and a body that does not parse is reported without its content: a serde error can
/// quote the value it choked on, and this one may be a credential.
pub fn interpret_credential(status: u16, body: &[u8]) -> Result<CredentialAnswer, AskError> {
    match status {
        200 => serde_json::from_slice::<GatewayCredential>(body)
            .map(CredentialAnswer::Found)
            .map_err(|_| AskError::Unreachable("unreadable credential answer".into())),
        404 => Ok(CredentialAnswer::Gone),
        s @ (401 | 403) => Err(AskError::Refused(s)),
        s => Err(AskError::Unreachable(format!("status {s}"))),
    }
}

/// The broker over HTTP, with this process's identity as the client.
pub struct Broker {
    base: String,
    transport: Transport,
}

enum Transport {
    /// The authorizer's SVID as the client certificate; the broker accepted only as
    /// `spiffe://<td>/mediatore`.
    Mtls {
        source: Arc<dyn MaterialSource>,
        server: SpiffeId,
    },
    /// The identity as a header, for a loopback `dev_mode` broker.
    #[cfg(feature = "dev")]
    DevHeader(String),
}

impl Broker {
    /// Obtain the transport identity from the Workload API at `workload_api_socket`,
    /// within [`WORKLOAD_API_WAIT`]: the SVID of the authorizer's own ID, selected by ID
    /// among whatever the agent hands this user, never the default one (ADR-0053
    /// decision 2). Fails closed: no Workload API or no such SVID, no authorizer.
    pub async fn connect(mediatore_url: &str, workload_api_socket: &str) -> anyhow::Result<Self> {
        let endpoint = mediatore_tls::endpoint(workload_api_socket);
        let source = WorkloadApiSource::connect_as(&endpoint, AUTHORIZER_PATH, WORKLOAD_API_WAIT)
            .await
            .map_err(|e| anyhow::anyhow!("Workload API at {endpoint}: {e}"))?;
        let own = source.current()?;
        ensure_authorizer(&own.spiffe_id)?;
        tracing::info!(spiffe_id = %own.spiffe_id, "the authorizer's SVID from the Workload API");
        Self::with_material(mediatore_url, Arc::new(source))
    }

    /// The broker over mTLS with whatever `source` supplies; the server is expected to be
    /// the broker of the material's trust domain. No check of the identity here: this is the
    /// seam the end-to-end suite uses to show what the broker does with a wrong one.
    /// [`Self::connect`], the only caller outside tests, has made that check.
    pub fn with_material(
        mediatore_url: &str,
        source: Arc<dyn MaterialSource>,
    ) -> anyhow::Result<Self> {
        let own = source.current()?;
        let server = SpiffeId::new(format!("spiffe://{}/mediatore", own.trust_domain()))?;
        Ok(Self {
            base: base_of(mediatore_url),
            transport: Transport::Mtls { source, server },
        })
    }

    /// The identity as a header, which only a loopback `dev_mode` broker accepts.
    #[cfg(feature = "dev")]
    pub fn dev_header(mediatore_url: &str, spiffe_id: &str) -> Self {
        tracing::warn!(
            "dev: gateway identity sent as a header; only a loopback dev_mode broker accepts this"
        );
        Self {
            base: base_of(mediatore_url),
            transport: Transport::DevHeader(spiffe_id.to_owned()),
        }
    }

    /// The trust domain this client speaks for.
    pub fn trust_domain(&self) -> anyhow::Result<String> {
        match &self.transport {
            Transport::Mtls { source, .. } => Ok(source.current()?.trust_domain().to_string()),
            #[cfg(feature = "dev")]
            Transport::DevHeader(id) => Ok(SpiffeId::new(id)?.trust_domain().to_string()),
        }
    }

    fn client(&self) -> Result<reqwest::Client, AskError> {
        let builder = reqwest::Client::builder().timeout(ASK_TIMEOUT);
        let builder = match &self.transport {
            Transport::Mtls { source, server } => {
                // Built per ask from the current material, so a rotated SVID is used next.
                let material = source
                    .current()
                    .map_err(|e| AskError::Unreachable(format!("no gateway SVID: {e}")))?;
                let cfg = mediatore_tls::client_config(&material, server)
                    .map_err(|e| AskError::Unreachable(format!("client config: {e}")))?;
                builder.tls_backend_preconfigured(cfg)
            }
            #[cfg(feature = "dev")]
            Transport::DevHeader(_) => builder,
        };
        builder
            .build()
            .map_err(|e| AskError::Unreachable(e.to_string()))
    }
}

fn base_of(mediatore_url: &str) -> String {
    mediatore_url.trim_end_matches('/').to_owned()
}

#[async_trait::async_trait]
impl Allowlists for Broker {
    async fn ask(&self, claim_uid: Uuid) -> Result<Answer, AskError> {
        let url = format!("{}/v1/gateway/claims/{claim_uid}", self.base);
        let req = self.client()?.get(url);
        #[cfg(feature = "dev")]
        let req = match &self.transport {
            Transport::DevHeader(id) => req.header(DEV_PEER_HEADER, id),
            Transport::Mtls { .. } => req,
        };
        let resp = req
            .send()
            .await
            .map_err(|e| AskError::Unreachable(e.to_string()))?;
        match resp.status().as_u16() {
            200 => resp
                .json::<ClaimEgress>()
                .await
                .map(Answer::Found)
                .map_err(|e| AskError::Unreachable(format!("unreadable answer: {e}"))),
            404 => Ok(Answer::Gone),
            s @ (401 | 403) => Err(AskError::Refused(s)),
            s => Err(AskError::Unreachable(format!("status {s}"))),
        }
    }
}

#[async_trait::async_trait]
impl crate::report::Reports for Broker {
    async fn report(&self, batch: &GatewayDecisions) -> Result<(), AskError> {
        let req = self
            .client()?
            .post(format!("{}/v1/gateway/decisions", self.base))
            .json(batch);
        #[cfg(feature = "dev")]
        let req = match &self.transport {
            Transport::DevHeader(id) => req.header(DEV_PEER_HEADER, id),
            Transport::Mtls { .. } => req,
        };
        let resp = req
            .send()
            .await
            .map_err(|e| AskError::Unreachable(e.to_string()))?;
        match resp.status().as_u16() {
            200 | 204 => Ok(()),
            s @ (401 | 403) => Err(AskError::Refused(s)),
            s => Err(AskError::Unreachable(format!("status {s}"))),
        }
    }
}

#[async_trait::async_trait]
impl Credentials for Broker {
    async fn credential(
        &self,
        claim_uid: Uuid,
        audience: &str,
    ) -> Result<CredentialAnswer, AskError> {
        let req = self
            .client()?
            .post(credential_url(&self.base, claim_uid))
            .json(&GatewayCredentialRequest {
                audience: audience.to_owned(),
            });
        #[cfg(feature = "dev")]
        let req = match &self.transport {
            Transport::DevHeader(id) => req.header(DEV_PEER_HEADER, id),
            Transport::Mtls { .. } => req,
        };
        let resp = req
            .send()
            .await
            .map_err(|e| AskError::Unreachable(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = if status == 200 {
            resp.bytes()
                .await
                .map_err(|_| AskError::Unreachable("unreadable credential answer".into()))?
                .to_vec()
        } else {
            Vec::new()
        };
        interpret_credential(status, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-ant-oat01-NEVER-LOG-THIS";
    /// The authorizer's own identity in the tests' trust domain.
    const AUTHORIZER: &str = "spiffe://sandbox.test/gateway/authorizer";

    #[test]
    fn the_authorizer_asks_as_the_authorizer_identity_and_does_not_start_on_the_listeners() {
        // ADR-0053 decisions 1 and 2. The path asked of the Workload API is the one `Naming`
        // gives the authorizer, so the two cannot drift apart.
        let naming = Naming {
            trust_domain: "sandbox.test".into(),
        };
        assert_eq!(naming.gateway_authorizer_id(), AUTHORIZER);
        assert_eq!(
            format!("spiffe://sandbox.test{AUTHORIZER_PATH}"),
            naming.gateway_authorizer_id()
        );
        let id = |s: &str| SpiffeId::new(s).expect("a SPIFFE ID");
        ensure_authorizer(&id(AUTHORIZER)).expect("its own identity");
        ensure_authorizer(&id("spiffe://other.test/gateway/authorizer"))
            .expect("its own identity, whatever trust domain the agent serves");
        // The listeners' name first of all, then everything near either name.
        for other in [
            naming.gateway_id(),
            "spiffe://sandbox.test/gateway/authorizer/extra".to_owned(),
            "spiffe://sandbox.test/gateway/authorizerx".to_owned(),
            "spiffe://sandbox.test/gateway/1".to_owned(),
            "spiffe://sandbox.test/authorizer".to_owned(),
            naming.broker_id(),
            naming.node_id("ekhash"),
        ] {
            let err = ensure_authorizer(&id(&other)).expect_err(&other);
            assert!(
                err.to_string().contains(AUTHORIZER) && err.to_string().contains(&other),
                "the refusal names both identities: {err}"
            );
        }
    }

    fn body(audience: &str, value: &str) -> String {
        serde_json::json!({
            "audience": audience,
            "subject": { "issuer": "https://login.example.test", "id": "octocat" },
            "header": "x-api-key",
            "value": value,
            "extra_headers": [ { "name": "anthropic-version", "value": "2023-06-01" } ],
            "expires_at": (jiff::Timestamp::now() + jiff::SignedDuration::from_secs(200)).to_string(),
        })
        .to_string()
    }

    #[test]
    fn the_credential_route_is_the_claims_own_and_a_trailing_slash_is_ignored() {
        let uid = Uuid::nil();
        assert_eq!(
            credential_url("https://mediatore.example.test", uid),
            "https://mediatore.example.test/v1/gateway/claims/00000000-0000-0000-0000-000000000000/credential"
        );
        assert_eq!(
            credential_url("https://mediatore.example.test/", uid),
            credential_url("https://mediatore.example.test", uid)
        );
    }

    #[test]
    fn a_200_is_the_credential_and_it_prints_as_redacted() {
        let Ok(CredentialAnswer::Found(c)) =
            interpret_credential(200, body("anthropic", SECRET).as_bytes())
        else {
            panic!("not a credential")
        };
        assert_eq!(c.audience, "anthropic");
        assert_eq!(c.header, "x-api-key");
        assert_eq!(c.value.0, SECRET);
        assert_eq!(c.extra_headers.len(), 1);
        let printed = format!("{c:?}");
        assert!(
            !printed.contains(SECRET) && printed.contains("[redacted]"),
            "{printed}"
        );
    }

    #[test]
    fn the_other_statuses_map_to_gone_refused_or_unreachable_and_never_read_a_body() {
        assert!(matches!(
            interpret_credential(404, SECRET.as_bytes()),
            Ok(CredentialAnswer::Gone)
        ));
        assert!(matches!(
            interpret_credential(401, SECRET.as_bytes()),
            Err(AskError::Refused(401))
        ));
        assert!(matches!(
            interpret_credential(403, SECRET.as_bytes()),
            Err(AskError::Refused(403))
        ));
        for status in [400, 429, 500, 502, 503] {
            match interpret_credential(status, SECRET.as_bytes()) {
                Err(AskError::Unreachable(why)) => {
                    assert_eq!(why, format!("status {status}"));
                    assert!(!why.contains(SECRET));
                }
                other => panic!("{status}: {other:?}"),
            }
        }
    }

    #[test]
    fn an_unreadable_200_is_reported_without_a_word_of_its_body() {
        // A serde error can quote the value it choked on; this one may be a credential.
        for bad in [
            format!("{{\"audience\": 5, \"value\": \"{SECRET}\"}}"),
            format!("not json {SECRET}"),
            body("anthropic", SECRET).replace("\"expires_at\"", "\"expires\""),
            String::new(),
        ] {
            match interpret_credential(200, bad.as_bytes()) {
                Err(AskError::Unreachable(why)) => {
                    assert_eq!(why, "unreadable credential answer");
                    assert!(!why.contains(SECRET));
                }
                other => panic!("{bad:?}: {other:?}"),
            }
        }
    }

    #[cfg(feature = "dev")]
    mod over_a_socket {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        /// One HTTP/1.1 exchange: the request is handed to `check` and `reply` is sent back.
        async fn serve_once(
            reply: String,
            check: impl FnOnce(&str) + Send + 'static,
        ) -> (String, tokio::task::JoinHandle<()>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let handle = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = sock.read(&mut buf).await.unwrap();
                    raw.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&raw).to_string();
                    if let Some(i) = text.find("\r\n\r\n") {
                        let len = text[..i]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if raw.len() >= i + 4 + len {
                            break;
                        }
                    }
                    assert!(n > 0, "closed before the request was complete");
                }
                check(&String::from_utf8_lossy(&raw));
                sock.write_all(reply.as_bytes()).await.unwrap();
            });
            (base, handle)
        }

        /// This reqwest needs a rustls crypto provider installed before any client is built; the
        /// mTLS path installs one, the plain-HTTP dev path does not.
        fn provider() {
            let _ = mediatore_proto::tls::https_client_config();
        }

        fn http(status: &str, body: &str) -> String {
            format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
        }

        #[tokio::test]
        async fn the_broker_is_asked_with_a_post_of_the_audience_and_answers_a_credential() {
            provider();
            let uid = Uuid::new_v4();
            let (base, server) =
                serve_once(http("200 OK", &body("anthropic", SECRET)), move |req| {
                    let first = req.lines().next().unwrap();
                    assert_eq!(
                        first,
                        format!("POST /v1/gateway/claims/{uid}/credential HTTP/1.1")
                    );
                    assert!(
                        req.to_ascii_lowercase()
                            .contains(&format!("x-mediatore-peer-spiffe-id: {AUTHORIZER}\r\n")),
                        "the ask goes out under the authorizer's identity, whole"
                    );
                    let json: serde_json::Value =
                        serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap()).unwrap();
                    assert_eq!(json, serde_json::json!({ "audience": "anthropic" }));
                })
                .await;
            let broker = Broker::dev_header(&base, AUTHORIZER);
            let got = broker.credential(uid, "anthropic").await;
            server.await.unwrap();
            let Ok(CredentialAnswer::Found(c)) = got else {
                panic!("{got:?}")
            };
            assert_eq!(c.value.0, SECRET);
        }

        #[tokio::test]
        async fn a_403_a_404_and_a_dead_broker_are_refused_gone_and_unreachable() {
            provider();
            for (status, want) in [("403 Forbidden", 403u16), ("401 Unauthorized", 401)] {
                let (base, server) =
                    serve_once(http(status, "{\"error\":\"forbidden\"}"), |_| {}).await;
                let broker = Broker::dev_header(&base, AUTHORIZER);
                assert!(matches!(
                    broker.credential(Uuid::new_v4(), "anthropic").await,
                    Err(AskError::Refused(s)) if s == want
                ));
                server.await.unwrap();
            }
            let (base, server) = serve_once(http("404 Not Found", "{}"), |_| {}).await;
            let broker = Broker::dev_header(&base, AUTHORIZER);
            assert!(matches!(
                broker.credential(Uuid::new_v4(), "anthropic").await,
                Ok(CredentialAnswer::Gone)
            ));
            server.await.unwrap();
            let dead = Broker::dev_header("http://127.0.0.1:1", AUTHORIZER);
            assert!(matches!(
                dead.credential(Uuid::new_v4(), "anthropic").await,
                Err(AskError::Unreachable(_))
            ));
        }
    }
}
