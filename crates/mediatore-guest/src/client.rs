// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The HTTP client both VM-side roles use against the sandbox listener.

use mediatore_tls::{MaterialSource, SpiffeId, WorkloadApiSource};
use reqwest::Method;
use serde::Serialize;

/// Header carrying the peer SPIFFE ID against a `dev_mode` server.
#[cfg(feature = "dev")]
const DEV_PEER_HEADER: &str = "x-mediatore-peer-spiffe-id";

/// HTTP client for the sandbox listener, with this process's identity as the client.
pub struct SandboxClient {
    base: String,
    transport: Transport,
}

enum Transport {
    /// The SVID from the Workload API as the client certificate; the broker accepted only
    /// as `spiffe://<td>/mediatore`.
    Mtls {
        source: WorkloadApiSource,
        server: SpiffeId,
    },
    /// The peer identity as a header, for a loopback `dev_mode` server.
    #[cfg(feature = "dev")]
    DevHeader(String),
}

impl SandboxClient {
    /// Obtain the transport identity from the Workload API at `workload_api_socket`.
    /// Fails closed: no Workload API, no client.
    pub async fn connect(mediatore_url: &str, workload_api_socket: &str) -> anyhow::Result<Self> {
        let endpoint = mediatore_tls::endpoint(workload_api_socket);
        let source = WorkloadApiSource::connect(&endpoint)
            .await
            .map_err(|e| anyhow::anyhow!("Workload API at {endpoint}: {e}"))?;
        let own = source.current()?;
        let server = SpiffeId::new(format!("spiffe://{}/mediatore", own.trust_domain()))?;
        tracing::info!(spiffe_id = %own.spiffe_id, broker = %server, "SVID from the Workload API");
        Ok(Self {
            base: Self::base_of(mediatore_url),
            transport: Transport::Mtls { source, server },
        })
    }

    /// The identity as a header, which only a loopback `dev_mode` server accepts.
    #[cfg(feature = "dev")]
    pub fn dev_header(mediatore_url: &str, spiffe_id: &str) -> Self {
        tracing::warn!(
            "dev: peer identity sent as a header; only a loopback dev_mode server accepts this"
        );
        Self {
            base: Self::base_of(mediatore_url),
            transport: Transport::DevHeader(spiffe_id.to_owned()),
        }
    }

    fn base_of(mediatore_url: &str) -> String {
        mediatore_url.trim_end_matches('/').to_owned()
    }

    /// Send one request with this process's identity. The mTLS client is built per
    /// request from the current material, so a rotated SVID is used by the next call.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> anyhow::Result<reqwest::Response> {
        let url = format!("{}{path}", self.base);
        let req = match &self.transport {
            Transport::Mtls { source, server } => {
                let cfg = mediatore_tls::client_config(source.current()?.as_ref(), server)?;
                reqwest::Client::builder()
                    .use_preconfigured_tls(cfg)
                    .build()?
                    .request(method, url)
            }
            #[cfg(feature = "dev")]
            Transport::DevHeader(id) => reqwest::Client::new()
                .request(method, url)
                .header(DEV_PEER_HEADER, id),
        };
        let req = match body {
            Some(b) => req.json(b),
            None => req,
        };
        Ok(req.send().await?)
    }
}
