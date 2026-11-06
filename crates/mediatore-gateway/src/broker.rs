// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Where a claim's allowlist comes from: the broker's gateway-only route (ADR-0028
//! decision 4), `GET /v1/gateway/claims/{uid}`, asked over SPIFFE mTLS with the gateway
//! SVID from the local Workload API.

use std::sync::Arc;
use std::time::Duration;

use mediatore_proto::ClaimEgress;
use mediatore_tls::{MaterialSource, SpiffeId, WorkloadApiSource};
use uuid::Uuid;

/// Header carrying the peer SPIFFE ID against a `dev_mode` broker.
#[cfg(feature = "dev")]
const DEV_PEER_HEADER: &str = "x-mediatore-peer-spiffe-id";

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

/// The broker over HTTP, with this process's identity as the client.
pub struct Broker {
    base: String,
    transport: Transport,
}

enum Transport {
    /// The gateway SVID as the client certificate; the broker accepted only as
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
    /// within [`WORKLOAD_API_WAIT`]. Fails closed: no Workload API, no authorizer.
    pub async fn connect(mediatore_url: &str, workload_api_socket: &str) -> anyhow::Result<Self> {
        let endpoint = mediatore_tls::endpoint(workload_api_socket);
        let source = WorkloadApiSource::connect(&endpoint, WORKLOAD_API_WAIT)
            .await
            .map_err(|e| anyhow::anyhow!("Workload API at {endpoint}: {e}"))?;
        let own = source.current()?;
        tracing::info!(spiffe_id = %own.spiffe_id, "gateway SVID from the Workload API");
        Self::with_material(mediatore_url, Arc::new(source))
    }

    /// The broker over mTLS with whatever `source` supplies; the server is expected to be
    /// the broker of the material's trust domain.
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
