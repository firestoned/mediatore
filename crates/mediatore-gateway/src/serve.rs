// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The check server Envoy calls, and the `mediatore gateway` role around it.
//!
//! Envoy's external authorization filter in HTTP mode sends one request per downstream
//! request to this listener and allows the downstream on `200`, refuses it on anything
//! else. What this server reads is three headers Envoy sets from the downstream connection
//! (`authorization_request.headers_to_add`, which overrides anything the client sent):
//!
//! | Header | Envoy formatter | What |
//! | --- | --- | --- |
//! | `x-mediatore-peer` | `%DOWNSTREAM_PEER_URI_SAN%` | the verified client certificate's SPIFFE ID |
//! | `x-mediatore-method` | `%REQ(:method)%` | the downstream request's method, `CONNECT` |
//! | `x-mediatore-authority` | `%REQ(:authority)%` | the `host:port` the tunnel asks for |
//!
//! A check missing any of them is refused: the listener is for Envoy, on loopback, and
//! nothing else forms a check. `GET /healthz` answers `200` with no check, for Envoy's
//! health checking of its authorization cluster.

use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::broker::Broker;
use crate::{Authorizer, CacheConfig, Served};

/// The default loopback port Envoy's authorization cluster points at.
pub const DEFAULT_PORT: u16 = 9001;

/// Header carrying the downstream peer's SPIFFE ID, set by Envoy.
pub const PEER_HEADER: &str = "x-mediatore-peer";
/// Header carrying the downstream request's method, set by Envoy.
pub const METHOD_HEADER: &str = "x-mediatore-method";
/// Header carrying the downstream request's authority, set by Envoy.
pub const AUTHORITY_HEADER: &str = "x-mediatore-authority";

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

/// The one check Envoy's request forms, or why it forms none.
fn check_of(req: &Request<Incoming>) -> Result<(String, String, String), &'static str> {
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
    };
    Ok((
        header(PEER_HEADER).ok_or("no peer")?,
        header(METHOD_HEADER).ok_or("no method")?,
        header(AUTHORITY_HEADER).ok_or("no authority")?,
    ))
}

fn reply(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(body.to_owned())))
        .expect("static response")
}

/// Answer one check: `200` to allow, `403` with the refusal's code otherwise.
async fn handle(authorizer: Arc<Authorizer>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    if req.uri().path() == "/healthz" {
        return reply(StatusCode::OK, "ok\n");
    }
    let (peer, method, authority) = match check_of(&req) {
        Ok(c) => c,
        Err(why) => {
            tracing::warn!(why, "check refused: not a check Envoy forms");
            return reply(StatusCode::FORBIDDEN, "malformed_check\n");
        }
    };
    let d = authorizer.authorize(&peer, &method, &authority).await;
    let claim_uid = d.claim_uid.map(|u| u.to_string()).unwrap_or_default();
    let served = match d.served {
        Served::Cache => "cache",
        Served::Broker => "broker",
        Served::Stale => "stale",
        Served::None => "none",
    };
    match d.verdict {
        Ok(()) => {
            tracing::info!(claim_uid, peer, %authority, served, verdict = "allow", "tunnel");
            reply(StatusCode::OK, "")
        }
        Err(why) => {
            tracing::info!(claim_uid, peer, %authority, served, verdict = "deny", reason = why.code(), "tunnel");
            reply(StatusCode::FORBIDDEN, &format!("{}\n", why.code()))
        }
    }
}

/// Serve checks on `listener` until it fails.
pub async fn serve(authorizer: Arc<Authorizer>, listener: TcpListener) -> anyhow::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let authorizer = authorizer.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let authorizer = authorizer.clone();
                async move { Ok::<_, std::convert::Infallible>(handle(authorizer, req).await) }
            });
            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(error = %e, "check connection ended");
            }
        });
    }
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
