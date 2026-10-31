// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! `mediatore egress-proxy`: the jail's only way out (ADR-0025).
//!
//! One process per claim, started by the guest as the sandbox user outside the jail. A
//! reverse proxy on loopback: the workload calls `http://127.0.0.1:<port>/<host>[:<port>]/<path>`
//! with the phantom token in `Authorization`, the proxy finds the route the host names (one
//! of the claim's audiences and its `egress` endpoint, from `GET /v1/me`), checks the method
//! and path against that audience's rules, swaps the phantom for a token for that audience
//! (fetched over the claim SVID at `POST /v1/token`, cached until shortly before its expiry)
//! and forwards over TLS 1.3 to the Mozilla roots, or to the CA the route carries for an
//! upstream on a private PKI (`audiences[].ca_file`). The token is in this process's memory
//! and nowhere else; the workload holds a phantom that is useless anywhere but here.
//!
//! Refusals: `404` for a host outside the routes, `403` for a request outside the audience's
//! rules, `401` for an `Authorization` that is not the phantom (the workload has no credential
//! of its own this layer carries), `502` when the token or the upstream cannot be had. A
//! request with no `Authorization` is forwarded bare. Nothing but the audience, the host,
//! the method, the path and the status is logged.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use http::header::{self, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;
use mediatore_proto::{Endpoint, Route, TokenRequest, TokenResponse};
use rustls::pki_types::ServerName;
use tokio::io::AsyncBufReadExt as _;
use tokio::net::{TcpListener, TcpStream};

use crate::client::SandboxClient;

/// The proxy's loopback port unless the guest is told otherwise.
pub const DEFAULT_PORT: u16 = 3128;
/// The jail's environment variable naming the proxy's base URL.
pub const PROXY_URL_ENV: &str = "MEDIATORE_EGRESS_PROXY";
/// The jail's environment variable carrying the phantom token (decision 3).
pub const PHANTOM_ENV: &str = "MEDIATORE_TOKEN";
/// The one line the proxy prints on standard output once it listens; the guest waits for it.
pub const READY_LINE: &str = "ready";
/// A cached token is replaced this long before its `expires_at`.
const REFRESH_MARGIN_SECS: i64 = 30;
/// File names under the sandbox's `egress/` directory.
const ROUTES_FILE: &str = "routes.json";
const PHANTOM_FILE: &str = "phantom";

/// Arguments of the `egress-proxy` role.
#[derive(Debug, clap::Args)]
pub struct EgressArgs {
    /// Loopback address and port to listen on
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
    /// The claim's routes, JSON as `GET /v1/me` returned them
    #[arg(long)]
    pub routes: PathBuf,
    /// The file holding the phantom token the jail was given
    #[arg(long)]
    pub phantom_file: PathBuf,
}

/// The phantom token (decision 3): 256 random bits as hex, handed to the jail, swapped by
/// the proxy. Prints redacted; useless anywhere but at this proxy during this claim.
#[derive(Clone, PartialEq, Eq)]
pub struct Phantom(String);

impl Phantom {
    /// A fresh phantom from the provider's random source.
    ///
    /// # Errors
    /// When the random source fails, which the guest treats as fatal for the claim.
    pub fn generate() -> anyhow::Result<Self> {
        let mut bytes = [0u8; 32];
        aws_lc_rs::rand::fill(&mut bytes)
            .map_err(|_| anyhow::anyhow!("the random source failed"))?;
        Ok(Self(hex::encode(bytes)))
    }

    /// From its stored text (the file the guest wrote), trimmed; refuses an empty one.
    ///
    /// # Errors
    /// When `text` is empty after trimming.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let t = text.trim();
        anyhow::ensure!(!t.is_empty(), "the phantom token is empty");
        Ok(Self(t.to_owned()))
    }

    /// The value, for the jail's environment and the file.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether `authorization` is exactly `Bearer <this phantom>`, compared in constant time.
    fn is_bearer(&self, authorization: &[u8]) -> bool {
        let Some(token) = authorization.strip_prefix(b"Bearer ") else {
            return false;
        };
        aws_lc_rs::constant_time::verify_slices_are_equal(token, self.0.as_bytes()).is_ok()
    }
}

impl std::fmt::Debug for Phantom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Phantom([redacted])")
    }
}

/// The claim's routes, indexed by the endpoint a request names.
#[derive(Debug, Clone)]
pub struct Routes {
    by_endpoint: BTreeMap<Endpoint, Route>,
    by_host: BTreeMap<String, Vec<Endpoint>>,
}

impl Routes {
    /// Index `routes`; an endpoint on two routes is refused (the host must choose one
    /// token, decision 4; the broker checks the same at its config).
    ///
    /// # Errors
    /// On a duplicate endpoint.
    pub fn new(routes: Vec<Route>) -> anyhow::Result<Self> {
        let mut by_endpoint = BTreeMap::new();
        let mut by_host: BTreeMap<String, Vec<Endpoint>> = BTreeMap::new();
        for r in routes {
            let e = r.endpoint.clone();
            if let Some(other) = by_endpoint.insert(e.clone(), r) {
                anyhow::bail!(
                    "endpoint {e} is on two routes ({} and {}); the proxy cannot choose a token",
                    other.audience,
                    by_endpoint[&e].audience
                );
            }
            by_host.entry(e.host.clone()).or_default().push(e);
        }
        Ok(Self {
            by_endpoint,
            by_host,
        })
    }

    /// How many routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_endpoint.len()
    }

    /// No routes: the proxy forwards nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_endpoint.is_empty()
    }

    /// The route for the first path segment of a request: `host:port` exactly, or `host`
    /// alone when that host is on one route only (decision 2).
    fn resolve(&self, segment: &str) -> Option<&Route> {
        if let Ok(e) = segment.parse::<Endpoint>()
            && let Some(r) = self.by_endpoint.get(&e)
        {
            return Some(r);
        }
        let host = segment
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(segment);
        match self.by_host.get(host).map(Vec::as_slice) {
            Some([one]) => self.by_endpoint.get(one),
            _ => None,
        }
    }
}

/// Why a request is not forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The status the workload gets.
    pub status: StatusCode,
    /// The stable code in the JSON body.
    pub code: &'static str,
}

impl Refusal {
    const fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
    }
}

/// What goes upstream when a request is admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward<'a> {
    /// The route the host segment named.
    pub route: &'a Route,
    /// The path and query the upstream gets: everything after the host segment.
    pub path_and_query: String,
    /// Whether the phantom was presented and a token for the route's audience goes in.
    pub inject: bool,
}

/// Decide a request from its method, its path and query, and its `Authorization` header
/// (decisions 2 to 4). Pure, so the whole policy is unit-tested without a socket.
///
/// # Errors
/// The refusal the workload gets.
pub fn judge<'a>(
    routes: &'a Routes,
    phantom: &Phantom,
    method: &Method,
    path_and_query: &str,
    authorization: Option<&[u8]>,
) -> Result<Forward<'a>, Refusal> {
    let rest = path_and_query
        .strip_prefix('/')
        .ok_or(Refusal::new(StatusCode::BAD_REQUEST, "bad_request"))?;
    let (segment, tail) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if segment.is_empty() {
        return Err(Refusal::new(StatusCode::NOT_FOUND, "no_route"));
    }
    let route = routes
        .resolve(segment)
        .ok_or(Refusal::new(StatusCode::NOT_FOUND, "no_route"))?;
    let path_and_query = if tail.starts_with('/') {
        tail.to_owned()
    } else {
        format!("/{tail}")
    };
    let path = path_and_query.split('?').next().unwrap_or("/");
    if !route.admits(method.as_str(), path) {
        return Err(Refusal::new(StatusCode::FORBIDDEN, "outside_rules"));
    }
    let inject = match authorization {
        None => false,
        Some(v) if phantom.is_bearer(v) => true,
        Some(_) => return Err(Refusal::new(StatusCode::UNAUTHORIZED, "unknown_credential")),
    };
    Ok(Forward {
        route,
        path_and_query,
        inject,
    })
}

/// Headers that belong to one hop and never cross the proxy, either way.
const HOP_BY_HOP: [HeaderName; 8] = [
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

/// Where tokens come from: the broker over the claim SVID in production, a fake in tests.
#[async_trait::async_trait]
pub trait TokenSource: Send + Sync {
    /// One token for `audience`.
    async fn token(&self, audience: &str) -> anyhow::Result<TokenResponse>;
}

/// The broker, over the claim SVID: `POST /v1/token`.
pub struct BrokerTokens {
    client: SandboxClient,
}

#[async_trait::async_trait]
impl TokenSource for BrokerTokens {
    async fn token(&self, audience: &str) -> anyhow::Result<TokenResponse> {
        let resp = self
            .client
            .send(
                reqwest::Method::POST,
                "/v1/token",
                Some(&TokenRequest {
                    audience: audience.to_owned(),
                }),
            )
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "mediatore refused a token for {audience}: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(resp.json().await?)
    }
}

/// Tokens by audience, replaced [`REFRESH_MARGIN_SECS`] before they expire. One fetch at a
/// time: two requests arriving together do not both spend the claim's rate limit.
#[derive(Default)]
struct TokenCache {
    tokens: tokio::sync::Mutex<HashMap<String, (String, DateTime<Utc>)>>,
}

impl TokenCache {
    async fn bearer(&self, source: &dyn TokenSource, audience: &str) -> anyhow::Result<String> {
        let mut tokens = self.tokens.lock().await;
        if let Some((token, expires_at)) = tokens.get(audience)
            && *expires_at - Utc::now() > Duration::seconds(REFRESH_MARGIN_SECS)
        {
            return Ok(token.clone());
        }
        let fresh = source.token(audience).await?;
        tracing::info!(audience, expires_at = %fresh.expires_at, "token fetched for the proxy");
        tokens.insert(
            audience.to_owned(),
            (fresh.access_token.clone(), fresh.expires_at),
        );
        Ok(fresh.access_token)
    }
}

/// The proxy: the claim's routes, its phantom, where tokens come from and how the upstream
/// is trusted, per route.
pub struct Proxy {
    routes: Routes,
    phantom: Phantom,
    tokens: Arc<dyn TokenSource>,
    cache: TokenCache,
    /// The trust for a route without a CA of its own.
    tls: Arc<rustls::ClientConfig>,
    /// Per audience, the trust for routes that carry a CA (`Route::ca_pem`): exactly that
    /// CA, never the default roots as well.
    tls_by_audience: HashMap<String, Arc<rustls::ClientConfig>>,
}

type Body = BoxBody<Bytes, hyper::Error>;

/// `tls` with HTTP/1.1 as the one application protocol.
fn http1_only(mut tls: rustls::ClientConfig) -> Arc<rustls::ClientConfig> {
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(tls)
}

impl Proxy {
    /// A proxy over `tls` for the routes that carry no CA (the Mozilla roots in production,
    /// [`Self::with_webpki_roots`]); a route with a `ca_pem` gets a config trusting that CA
    /// alone, built here.
    ///
    /// # Errors
    /// A `ca_pem` that holds no certificate: the claim must not start with a route whose
    /// trust cannot be built (fail closed, never the default roots in its place).
    pub fn new(
        routes: Routes,
        phantom: Phantom,
        tokens: Arc<dyn TokenSource>,
        tls: rustls::ClientConfig,
    ) -> anyhow::Result<Self> {
        let mut tls_by_audience = HashMap::new();
        for r in routes.by_endpoint.values() {
            if let Some(pem) = &r.ca_pem
                && !tls_by_audience.contains_key(&r.audience)
            {
                let cfg = mediatore_proto::tls::https_client_config_with_ca(pem.as_bytes())
                    .map_err(|e| {
                        anyhow::anyhow!("route {} (audience {}): {e}", r.endpoint, r.audience)
                    })?;
                tls_by_audience.insert(r.audience.clone(), http1_only(cfg));
            }
        }
        Ok(Self {
            routes,
            phantom,
            tokens,
            cache: TokenCache::default(),
            tls: http1_only(tls),
            tls_by_audience,
        })
    }

    /// The production trust for routes without a CA: TLS 1.3 to the Mozilla roots, like
    /// the broker's identity provider client.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn with_webpki_roots(
        routes: Routes,
        phantom: Phantom,
        tokens: Arc<dyn TokenSource>,
    ) -> anyhow::Result<Self> {
        Self::new(
            routes,
            phantom,
            tokens,
            mediatore_proto::tls::https_client_config(),
        )
    }

    /// The trust for `route`: its audience's CA when it carries one, the default otherwise.
    fn tls_for(&self, route: &Route) -> Arc<rustls::ClientConfig> {
        route
            .ca_pem
            .as_ref()
            .and_then(|_| self.tls_by_audience.get(&route.audience))
            .unwrap_or(&self.tls)
            .clone()
    }

    /// Serve connections from `listener` forever (until the task is dropped).
    ///
    /// # Errors
    /// When `accept` fails, which ends the proxy and so the claim.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let proxy = self.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    let proxy = proxy.clone();
                    async move { Ok::<_, std::convert::Infallible>(proxy.handle(req).await) }
                });
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    tracing::debug!(error = %e, "connection from the jail ended with an error");
                }
            });
        }
    }

    /// One request from the jail: judged, rewritten, forwarded, relayed.
    pub async fn handle(&self, req: Request<Incoming>) -> Response<Body> {
        let method = req.method().clone();
        let Some(path_and_query) = req.uri().path_and_query().map(ToString::to_string) else {
            return refuse(&Refusal::new(StatusCode::BAD_REQUEST, "bad_request"));
        };
        let authorization = req
            .headers()
            .get(header::AUTHORIZATION)
            .map(HeaderValue::as_bytes);
        let forward = match judge(
            &self.routes,
            &self.phantom,
            &method,
            &path_and_query,
            authorization,
        ) {
            Ok(f) => f,
            Err(r) => {
                tracing::warn!(%method, path = %path_and_query, status = %r.status, code = r.code, "request refused");
                return refuse(&r);
            }
        };
        let route = forward.route.clone();
        let path_log = forward.path_and_query.clone();
        let bearer = if forward.inject {
            match self.cache.bearer(&*self.tokens, &route.audience).await {
                Ok(b) => Some(b),
                Err(e) => {
                    tracing::error!(audience = %route.audience, error = %e, "no token for the proxy");
                    return refuse(&Refusal::new(StatusCode::BAD_GATEWAY, "token_unavailable"));
                }
            }
        } else {
            None
        };
        let upstream = rewrite(req, &forward, bearer.as_deref());
        match connect_and_send(&route.endpoint, self.tls_for(&route), upstream).await {
            Ok(resp) => {
                tracing::info!(
                    audience = %route.audience,
                    host = %route.endpoint,
                    %method,
                    path = %path_log,
                    status = %resp.status(),
                    credential = forward.inject,
                    "forwarded"
                );
                let mut resp = resp.map(BodyExt::boxed);
                for h in HOP_BY_HOP {
                    resp.headers_mut().remove(&h);
                }
                resp
            }
            Err(e) => {
                tracing::error!(audience = %route.audience, host = %route.endpoint, error = %e, "upstream unreachable");
                refuse(&Refusal::new(
                    StatusCode::BAD_GATEWAY,
                    "upstream_unreachable",
                ))
            }
        }
    }
}

/// The request as the upstream gets it: origin-form path, `Host` set to the endpoint,
/// hop-by-hop headers dropped, the phantom replaced by the real bearer when one goes in.
fn rewrite(
    req: Request<Incoming>,
    forward: &Forward<'_>,
    bearer: Option<&str>,
) -> Request<Incoming> {
    let (mut parts, body) = req.into_parts();
    parts.uri = forward
        .path_and_query
        .parse()
        .unwrap_or_else(|_| http::Uri::from_static("/"));
    parts.version = http::Version::HTTP_11;
    for h in HOP_BY_HOP {
        parts.headers.remove(&h);
    }
    if let Ok(v) = HeaderValue::from_str(&host_header(&forward.route.endpoint)) {
        parts.headers.insert(header::HOST, v);
    }
    match bearer {
        Some(b) => {
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {b}")) {
                parts.headers.insert(header::AUTHORIZATION, v);
            }
        }
        None => {
            parts.headers.remove(header::AUTHORIZATION);
        }
    }
    Request::from_parts(parts, body)
}

/// The `Host` the upstream sees: the endpoint, with the port left out at 443 and an IPv6
/// address in brackets either way.
fn host_header(e: &Endpoint) -> String {
    match (e.port, e.host.contains(':')) {
        (443, true) => format!("[{}]", e.host),
        (443, false) => e.host.clone(),
        _ => e.to_string(),
    }
}

/// TLS to `endpoint`, one HTTP/1.1 connection, one request.
async fn connect_and_send(
    endpoint: &Endpoint,
    tls: Arc<rustls::ClientConfig>,
    req: Request<Incoming>,
) -> anyhow::Result<Response<Incoming>> {
    let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port)).await?;
    let name = ServerName::try_from(endpoint.host.clone())
        .map_err(|e| anyhow::anyhow!("{} is not a server name: {e}", endpoint.host))?;
    let stream = tokio_rustls::TlsConnector::from(tls)
        .connect(name, tcp)
        .await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "upstream connection ended with an error");
        }
    });
    Ok(sender.send_request(req).await?)
}

/// A refusal as the workload sees it: the status and a JSON body with the code.
fn refuse(r: &Refusal) -> Response<Body> {
    let body = serde_json::json!({ "error": r.code }).to_string();
    Response::builder()
        .status(r.status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap_or_else(|_| {
            Response::new(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
        })
}

/// The files the guest writes for the proxy, under the sandbox's `egress/` directory.
#[derive(Debug, Clone)]
pub struct EgressFiles {
    /// The routes, JSON.
    pub routes: PathBuf,
    /// The phantom.
    pub phantom: PathBuf,
}

/// Write the routes and the phantom into `dir` for the sandbox user: mode 0400, owned by
/// `uid:gid`, outside the jail's mounts.
///
/// # Errors
/// On any filesystem failure.
pub fn write_files(
    dir: &Path,
    routes: &[Route],
    phantom: &Phantom,
    uid: u32,
    gid: u32,
) -> anyhow::Result<EgressFiles> {
    use std::os::unix::fs::PermissionsExt as _;
    let files = EgressFiles {
        routes: dir.join(ROUTES_FILE),
        phantom: dir.join(PHANTOM_FILE),
    };
    std::fs::write(&files.routes, serde_json::to_vec(routes)?)?;
    std::fs::write(&files.phantom, phantom.expose().as_bytes())?;
    for p in [&files.routes, &files.phantom] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o400))?;
        std::os::unix::fs::chown(p, Some(uid), Some(gid))?;
    }
    Ok(files)
}

/// The command line the guest starts the proxy with (decision 1): the pinned binary's
/// `egress-proxy` role, as the sandbox user. Kept as data so it is testable.
#[must_use]
pub fn command_args(
    listen: SocketAddr,
    mediatore_url: &str,
    workload_api_socket: &str,
    files: &EgressFiles,
) -> Vec<String> {
    vec![
        "egress-proxy".into(),
        "--listen".into(),
        listen.to_string(),
        "--mediatore-url".into(),
        mediatore_url.to_owned(),
        "--workload-api-socket".into(),
        workload_api_socket.to_owned(),
        "--routes".into(),
        files.routes.display().to_string(),
        "--phantom-file".into(),
        files.phantom.display().to_string(),
    ]
}

/// Start the proxy as `uid:gid` and wait for its ready line, at most `timeout`.
///
/// # Errors
/// A spawn failure, an exit before ready, or the timeout: the claim must not start.
pub async fn spawn(
    binary: &Path,
    args: &[String],
    uid: u32,
    gid: u32,
    timeout: std::time::Duration,
) -> anyhow::Result<tokio::process::Child> {
    let mut child = tokio::process::Command::new(binary)
        .args(args)
        .uid(uid)
        .gid(gid)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawning the egress proxy {}: {e}", binary.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("the egress proxy's stdout was not captured"))?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let ready = tokio::time::timeout(timeout, lines.next_line()).await;
    match ready {
        Ok(Ok(Some(line))) if line.starts_with(READY_LINE) => Ok(child),
        Ok(Ok(other)) => {
            let _ = child.start_kill();
            anyhow::bail!("the egress proxy did not report ready (got {other:?})")
        }
        Ok(Err(e)) => {
            let _ = child.start_kill();
            anyhow::bail!("reading the egress proxy's ready line: {e}")
        }
        Err(_) => {
            let _ = child.start_kill();
            anyhow::bail!("the egress proxy did not report ready within {timeout:?}")
        }
    }
}

/// Run the role: read the routes and the phantom, obtain the claim SVID, listen, say so.
///
/// # Errors
/// Anything missing: no routes file, no phantom, no Workload API, the port taken.
pub async fn run(args: EgressArgs) -> anyhow::Result<()> {
    let routes: Vec<Route> = serde_json::from_slice(&std::fs::read(&args.routes)?)?;
    let routes = Routes::new(routes)?;
    let phantom = Phantom::parse(&std::fs::read_to_string(&args.phantom_file)?)?;
    anyhow::ensure!(
        args.listen.ip().is_loopback(),
        "the egress proxy listens on loopback only; got {}",
        args.listen
    );
    let client = SandboxClient::connect(&args.mediatore_url, &args.workload_api_socket).await?;
    let listener = TcpListener::bind(args.listen).await?;
    let addr = listener.local_addr()?;
    let proxy = Arc::new(Proxy::with_webpki_roots(
        routes,
        phantom,
        Arc::new(BrokerTokens { client }),
    )?);
    tracing::info!(%addr, routes = proxy.routes.len(), "egress proxy listening");
    // The one line on standard output: the guest starts the jail when it reads it.
    println!("{READY_LINE} {addr}");
    proxy.serve(listener).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use mediatore_proto::EndpointRule;

    fn route(audience: &str, endpoint: &str, rules: &[(&str, &str)]) -> Route {
        Route {
            audience: audience.into(),
            endpoint: endpoint.parse().unwrap(),
            rules: rules
                .iter()
                .map(|(m, p)| EndpointRule {
                    method: (*m).into(),
                    path: (*p).into(),
                })
                .collect(),
            ca_pem: None,
        }
    }

    struct NoTokens;

    #[async_trait::async_trait]
    impl TokenSource for NoTokens {
        async fn token(&self, _: &str) -> anyhow::Result<TokenResponse> {
            anyhow::bail!("no tokens in this test")
        }
    }

    #[test]
    fn a_route_with_a_ca_is_trusted_through_that_ca_alone_and_a_bad_one_refuses_the_proxy() {
        let private = Route {
            ca_pem: Some(mediatore_testkit::fixture_ca_pem()),
            ..route("internal-git", "git.home.example:443", &[])
        };
        let public = route("public", "api.example.com:443", &[]);
        let proxy = Proxy::with_webpki_roots(
            Routes::new(vec![private.clone(), public.clone()]).unwrap(),
            phantom(),
            Arc::new(NoTokens),
        )
        .unwrap();
        let for_private = proxy.tls_for(&private);
        let for_public = proxy.tls_for(&public);
        assert!(
            Arc::ptr_eq(&for_public, &proxy.tls),
            "no ca_pem: the default roots"
        );
        assert!(
            !Arc::ptr_eq(&for_private, &proxy.tls),
            "a ca_pem: a config of its own, never the default roots as well"
        );
        assert_eq!(for_private.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert_eq!(for_public.alpn_protocols, vec![b"http/1.1".to_vec()]);

        let broken = Route {
            ca_pem: Some("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n".into()),
            ..route("internal-git", "git.home.example:443", &[])
        };
        let err = Proxy::with_webpki_roots(
            Routes::new(vec![broken]).unwrap(),
            phantom(),
            Arc::new(NoTokens),
        )
        .err()
        .expect("a CA that is not a certificate refuses the proxy")
        .to_string();
        assert!(err.contains("git.home.example:443"), "{err}");
        let empty = Route {
            ca_pem: Some(String::new()),
            ..route("internal-git", "git.home.example:443", &[])
        };
        assert!(
            Proxy::with_webpki_roots(
                Routes::new(vec![empty]).unwrap(),
                phantom(),
                Arc::new(NoTokens)
            )
            .is_err(),
            "an empty ca_pem is not the Mozilla roots; it is a refusal"
        );
    }

    fn routes() -> Routes {
        Routes::new(vec![
            route(
                "internal-git",
                "git.home.example:443",
                &[
                    ("GET", "/platform/**"),
                    ("POST", "/platform/*/git-receive-pack"),
                ],
            ),
            route("grafana", "grafana.home.example:443", &[]),
            route("grafana", "grafana.home.example:8443", &[]),
            route("data", "192.0.2.10:8443", &[]),
            route("data6", "[2001:db8::1]:8443", &[]),
        ])
        .unwrap()
    }

    fn phantom() -> Phantom {
        Phantom::parse("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap()
    }

    #[test]
    fn the_phantom_is_256_random_bits_as_hex_and_prints_redacted() {
        let a = Phantom::generate().unwrap();
        let b = Phantom::generate().unwrap();
        assert_eq!(a.expose().len(), 64);
        assert!(a.expose().chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        assert_eq!(format!("{a:?}"), "Phantom([redacted])");
        assert!(Phantom::parse("  \n").is_err());
        assert_eq!(Phantom::parse(" abc \n").unwrap().expose(), "abc");
    }

    #[test]
    fn the_host_segment_names_the_route_by_endpoint_or_by_a_host_on_one_route() {
        let r = routes();
        assert_eq!(
            r.resolve("git.home.example").unwrap().audience,
            "internal-git"
        );
        assert_eq!(
            r.resolve("git.home.example:443").unwrap().audience,
            "internal-git"
        );
        assert!(
            r.resolve("git.home.example:8443").is_none(),
            "that port is not declared"
        );
        assert!(
            r.resolve("grafana.home.example").is_none(),
            "two ports for the host: the request must name one"
        );
        assert_eq!(
            r.resolve("grafana.home.example:8443")
                .unwrap()
                .endpoint
                .port,
            8443
        );
        assert_eq!(r.resolve("192.0.2.10").unwrap().audience, "data");
        assert_eq!(r.resolve("[2001:db8::1]:8443").unwrap().audience, "data6");
        assert_eq!(r.resolve("[2001:db8::1]").unwrap().audience, "data6");
        assert!(r.resolve("evil.example").is_none());
        assert!(r.resolve("").is_none());
        assert_eq!(r.len(), 5);
        assert!(!r.is_empty());
    }

    #[test]
    fn an_endpoint_on_two_routes_is_refused() {
        let err = Routes::new(vec![
            route("a", "api.home.example:443", &[]),
            route("b", "api.home.example:443", &[]),
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("two routes"), "{err}");
    }

    #[test]
    fn the_phantom_is_swapped_a_bare_request_is_forwarded_and_a_foreign_bearer_is_refused() {
        let r = routes();
        let p = phantom();
        let with_phantom = format!("Bearer {}", p.expose());
        let f = judge(
            &r,
            &p,
            &Method::GET,
            "/git.home.example/platform/services.git/info/refs?service=git-upload-pack",
            Some(with_phantom.as_bytes()),
        )
        .unwrap();
        assert_eq!(f.route.audience, "internal-git");
        assert_eq!(
            f.path_and_query,
            "/platform/services.git/info/refs?service=git-upload-pack"
        );
        assert!(f.inject, "the phantom is replaced by the audience's token");

        let bare = judge(&r, &p, &Method::GET, "/git.home.example/platform/x", None).unwrap();
        assert!(!bare.inject, "no header: forwarded without a credential");

        let foreign = judge(
            &r,
            &p,
            &Method::GET,
            "/git.home.example/platform/x",
            Some(b"Bearer someone-elses"),
        )
        .unwrap_err();
        assert_eq!(
            foreign,
            Refusal::new(StatusCode::UNAUTHORIZED, "unknown_credential")
        );
        let basic = judge(
            &r,
            &p,
            &Method::GET,
            "/git.home.example/platform/x",
            Some(b"Basic abc"),
        )
        .unwrap_err();
        assert_eq!(basic.status, StatusCode::UNAUTHORIZED);
        // A prefix or a suffix of the phantom is not the phantom.
        let partial = format!("Bearer {}x", p.expose());
        assert_eq!(
            judge(
                &r,
                &p,
                &Method::GET,
                "/git.home.example/platform/x",
                Some(partial.as_bytes())
            )
            .unwrap_err()
            .status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn a_request_outside_the_rules_is_403_and_the_rules_see_the_path_without_the_query() {
        let r = routes();
        let p = phantom();
        let err = judge(
            &r,
            &p,
            &Method::DELETE,
            "/git.home.example/platform/services.git",
            None,
        )
        .unwrap_err();
        assert_eq!(err, Refusal::new(StatusCode::FORBIDDEN, "outside_rules"));
        let err = judge(&r, &p, &Method::GET, "/git.home.example/other/x", None).unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert!(
            judge(
                &r,
                &p,
                &Method::POST,
                "/git.home.example/platform/services.git/git-receive-pack",
                None
            )
            .is_ok()
        );
        // The query is not part of the path the glob sees.
        assert!(
            judge(
                &r,
                &p,
                &Method::GET,
                "/git.home.example/platform/a?x=/evil",
                None
            )
            .is_ok()
        );
        // An audience with no rules admits any method and path.
        assert!(judge(&r, &p, &Method::DELETE, "/192.0.2.10/anything/at/all", None).is_ok());
        // The rules are checked before the credential: a foreign bearer outside the rules is 403.
        let err = judge(
            &r,
            &p,
            &Method::DELETE,
            "/git.home.example/x",
            Some(b"Bearer other"),
        )
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn a_host_outside_the_routes_and_an_empty_path_are_404() {
        let r = routes();
        let p = phantom();
        assert_eq!(
            judge(&r, &p, &Method::GET, "/evil.example/x", None)
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            judge(&r, &p, &Method::GET, "/", None).unwrap_err().status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            judge(&r, &p, &Method::GET, "//x", None).unwrap_err().status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            judge(&r, &p, &Method::GET, "x", None).unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
        // The host alone, no trailing slash: the upstream path is `/`.
        let f = judge(&r, &p, &Method::GET, "/192.0.2.10", None).unwrap();
        assert_eq!(f.path_and_query, "/");
        let f = judge(&r, &p, &Method::GET, "/192.0.2.10?x=1", None).unwrap();
        assert_eq!(f.path_and_query, "/?x=1");
    }

    #[test]
    fn the_host_header_is_the_endpoint_without_a_default_port_and_with_ipv6_in_brackets() {
        let ep = |s: &str| s.parse::<Endpoint>().unwrap();
        assert_eq!(host_header(&ep("git.home.example:443")), "git.home.example");
        assert_eq!(
            host_header(&ep("git.home.example:8443")),
            "git.home.example:8443"
        );
        assert_eq!(host_header(&ep("[2001:db8::1]:443")), "[2001:db8::1]");
        assert_eq!(host_header(&ep("[2001:db8::1]:8443")), "[2001:db8::1]:8443");
        assert_eq!(host_header(&ep("192.0.2.10:443")), "192.0.2.10");
    }

    #[test]
    fn the_command_line_is_the_pinned_binarys_role_with_the_files() {
        let files = EgressFiles {
            routes: "/mnt/sandbox/egress/routes.json".into(),
            phantom: "/mnt/sandbox/egress/phantom".into(),
        };
        let a = command_args(
            SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT)),
            "https://mediatore.test:8443",
            "/run/spire/sockets/agent.sock",
            &files,
        );
        assert_eq!(
            a,
            [
                "egress-proxy",
                "--listen",
                "127.0.0.1:3128",
                "--mediatore-url",
                "https://mediatore.test:8443",
                "--workload-api-socket",
                "/run/spire/sockets/agent.sock",
                "--routes",
                "/mnt/sandbox/egress/routes.json",
                "--phantom-file",
                "/mnt/sandbox/egress/phantom",
            ]
        );
    }

    #[test]
    fn the_files_are_the_sandbox_users_read_only_and_the_phantom_is_not_in_the_routes() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = mediatore_testkit::tempdir();
        let me = std::fs::metadata(&dir).unwrap();
        let p = phantom();
        let files = write_files(
            &dir,
            &[route("a", "api.home.example:443", &[("GET", "/**")])],
            &p,
            me.uid(),
            me.gid(),
        )
        .unwrap();
        for f in [&files.routes, &files.phantom] {
            let m = std::fs::metadata(f).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o400, "{}", f.display());
            assert_eq!((m.uid(), m.gid()), (me.uid(), me.gid()));
        }
        let routes = std::fs::read_to_string(&files.routes).unwrap();
        assert!(routes.contains("api.home.example"));
        assert!(!routes.contains(p.expose()));
        assert_eq!(std::fs::read_to_string(&files.phantom).unwrap(), p.expose());
        let back: Vec<Route> = serde_json::from_str(&routes).unwrap();
        assert_eq!(back.len(), 1);
    }
}
