// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The check service Envoy calls, and the `mediatore gateway` role around it.
//!
//! Envoy's external authorization filter asks this service once per downstream request
//! with its own `Check` call, over gRPC on loopback (`ext_authz` with `grpc_service`). The
//! request carries what Envoy knows of the downstream connection and request, and nothing
//! the client could set: the peer's identity from its verified certificate (the URI SAN, as
//! `source.principal`), the request's method and its authority (`request.http.method`,
//! `request.http.host`). Why gRPC, when the rest of mediatore speaks none: Envoy's HTTP
//! mode copies the downstream request's method and target into the check, so for a tunnel
//! the check is itself a `CONNECT`, and Envoy's own client then resets any `2xx` to it and
//! strips a refusal's body (verified on Envoy 1.40.2). The gRPC mode has no such shape.
//!
//! An allow is an `OK` status; a refusal is `PERMISSION_DENIED` with the refusal's code as
//! the message and as the `403` body Envoy returns to the client. An unreachable service is
//! a refusal too, by Envoy's `failure_mode_allow: false`.

use std::net::SocketAddr;
use std::sync::Arc;

use envoy_types::ext_authz::v3::pb::{
    Authorization, AuthorizationServer, CheckRequest, CheckResponse,
};
use envoy_types::ext_authz::v3::{CheckResponseExt, DeniedHttpResponseBuilder};
use envoy_types::pb::envoy::r#type::v3::StatusCode as HttpStatusCode;
use tokio::net::TcpListener;
use tonic::{Request, Response, Status};

use crate::broker::Broker;
use crate::{Authorizer, CacheConfig, Served};

/// The default loopback port Envoy's authorization cluster points at.
pub const DEFAULT_PORT: u16 = 9001;

/// `mediatore gateway`'s arguments.
#[derive(Debug, clap::Args)]
pub struct GatewayArgs {
    /// Loopback address and port Envoy's authorization cluster calls
    #[arg(long, default_value_t = SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT)))]
    pub listen: SocketAddr,
    /// mediatore sandbox-facing base URL
    #[arg(long, env = "MEDIATORE_URL")]
    pub mediatore_url: String,
    /// SPIRE Workload API socket
    #[arg(
        long,
        env = "SPIFFE_ENDPOINT_SOCKET",
        default_value = "/run/spire/sockets/agent.sock"
    )]
    pub workload_api_socket: String,
    /// Seconds an allowlist is used without asking the broker again
    #[arg(long, default_value_t = 30)]
    pub fresh_secs: u64,
    /// Seconds past that an allowlist still stands in while the broker is unreachable
    #[arg(long, default_value_t = 300)]
    pub stale_secs: u64,
    /// Claims the cache holds; past it, the least recently used goes
    #[arg(long, default_value_t = 4096)]
    pub max_claims: usize,
    /// Dev only: send this SPIFFE ID as a header instead of mTLS (loopback `dev_mode` broker)
    #[cfg(feature = "dev")]
    #[arg(long)]
    pub dev_spiffe_id: Option<String>,
}

/// The `Check` service over one [`Authorizer`].
pub struct Checks {
    authorizer: Arc<Authorizer>,
}

impl Checks {
    /// A service answering from `authorizer`.
    #[must_use]
    pub fn new(authorizer: Arc<Authorizer>) -> Self {
        Self { authorizer }
    }

    /// What one check says, as Envoy filled it: the peer's principal, the method and the
    /// authority. Anything absent is empty, which the authorizer refuses.
    fn fields(request: CheckRequest) -> (String, String, String) {
        let attributes = request.attributes.unwrap_or_default();
        let peer = attributes.source.map(|s| s.principal).unwrap_or_default();
        let http = attributes.request.and_then(|r| r.http).unwrap_or_default();
        (peer, http.method, http.host)
    }

    /// Answer one check: `OK` to allow, `PERMISSION_DENIED` with the code otherwise, the
    /// same code as the `403` body the client gets.
    pub async fn answer(&self, request: CheckRequest) -> CheckResponse {
        let (peer, method, authority) = Self::fields(request);
        let d = self.authorizer.authorize(&peer, &method, &authority).await;
        let claim_uid = d.claim_uid.map(|u| u.to_string()).unwrap_or_default();
        let served = match d.served {
            Served::Cache => "cache",
            Served::Broker => "broker",
            Served::Stale => "stale",
            Served::None => "none",
        };
        match d.verdict {
            Ok(()) => {
                tracing::info!(
                    claim_uid,
                    peer,
                    authority,
                    served,
                    verdict = "allow",
                    "tunnel"
                );
                CheckResponse::with_status(Status::ok(""))
            }
            Err(why) => {
                tracing::info!(
                    claim_uid,
                    peer,
                    authority,
                    served,
                    verdict = "deny",
                    reason = why.code(),
                    "tunnel"
                );
                let mut denied = DeniedHttpResponseBuilder::new();
                denied
                    .set_http_status(HttpStatusCode::Forbidden)
                    .set_body(format!("{}\n", why.code()));
                let mut response =
                    CheckResponse::with_status(Status::permission_denied(why.code()));
                response.set_http_response(denied);
                response
            }
        }
    }
}

#[tonic::async_trait]
impl Authorization for Checks {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        Ok(Response::new(self.answer(request.into_inner()).await))
    }
}

/// Serve checks on `listener` until it fails.
pub async fn serve(authorizer: Arc<Authorizer>, listener: TcpListener) -> anyhow::Result<()> {
    let incoming = tonic::transport::server::TcpIncoming::from(listener).with_nodelay(Some(true));
    tonic::transport::Server::builder()
        .add_service(AuthorizationServer::new(Checks::new(authorizer)))
        .serve_with_incoming(incoming)
        .await?;
    anyhow::bail!("the authorizer's listener ended")
}

/// `mediatore gateway`: the authorizer on loopback, its identity from the Workload API.
pub async fn run(args: GatewayArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.listen.ip().is_loopback(),
        "the authorizer listens on loopback only, for Envoy; got {}",
        args.listen
    );
    #[cfg(feature = "dev")]
    let broker = match &args.dev_spiffe_id {
        Some(id) => Broker::dev_header(&args.mediatore_url, id),
        None => Broker::connect(&args.mediatore_url, &args.workload_api_socket).await?,
    };
    #[cfg(not(feature = "dev"))]
    let broker = Broker::connect(&args.mediatore_url, &args.workload_api_socket).await?;
    let trust_domain = broker.trust_domain()?;
    let cfg = CacheConfig {
        fresh_for: std::time::Duration::from_secs(args.fresh_secs),
        stale_for: std::time::Duration::from_secs(args.stale_secs),
        max_claims: args.max_claims,
    };
    let authorizer = Arc::new(Authorizer::new(&trust_domain, Arc::new(broker), cfg));
    let listener = TcpListener::bind(args.listen).await?;
    tracing::info!(
        addr = %listener.local_addr()?,
        trust_domain,
        fresh_secs = args.fresh_secs,
        stale_secs = args.stale_secs,
        max_claims = args.max_claims,
        "gateway authorizer listening"
    );
    serve(authorizer, listener).await
}

#[cfg(test)]
mod tests {
    use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
    use envoy_types::pb::envoy::service::auth::v3::attribute_context::{
        HttpRequest, Peer, Request as HttpAttributes,
    };

    use super::*;

    #[test]
    fn a_check_is_read_from_the_principal_the_method_and_the_host_and_absent_parts_are_empty() {
        let full = CheckRequest {
            attributes: Some(AttributeContext {
                source: Some(Peer {
                    principal: "spiffe://sandbox.test/banlieue/claim/x".into(),
                    ..Default::default()
                }),
                request: Some(HttpAttributes {
                    http: Some(HttpRequest {
                        method: "CONNECT".into(),
                        host: "api.home.example:443".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        assert_eq!(
            Checks::fields(full),
            (
                "spiffe://sandbox.test/banlieue/claim/x".into(),
                "CONNECT".into(),
                "api.home.example:443".into()
            )
        );
        assert_eq!(
            Checks::fields(CheckRequest { attributes: None }),
            (String::new(), String::new(), String::new())
        );
    }
}
