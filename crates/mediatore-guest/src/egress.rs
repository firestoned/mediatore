// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! `mediatore egress-proxy`: the jail's only way out (ADR-0025).
//!
//! One process per claim, started by the guest as the sandbox user outside the jail. A
//! reverse proxy on loopback: the workload calls `http://127.0.0.1:<port>/<host>[:<port>]/<path>`
//! with the phantom token in `Authorization`, the proxy finds the route the host names (one
//! of the claim's audiences and its `egress` endpoint, or a direct egress entry of its
//! policy bundle, from `GET /v1/me`), checks the method and path against the route's
//! rules, swaps the phantom for a token for the route's audience (fetched over the claim
//! SVID at `POST /v1/token`, cached until shortly before its expiry), or drops it on a route
//! that carries no credential (ADR-0025 decision 8), and forwards over TLS 1.3 to the
//! Mozilla roots, or to the CA the route carries for an upstream on a private PKI
//! (`audiences[].ca_file`). The token is in this process's memory and nowhere else; the
//! workload holds a phantom that is useless anywhere but here. In an
//! environment with egress gateways (ADR-0028) the upstream is not dialled directly: the
//! proxy opens a tunnel through one of them as the claim, `CONNECT host:port` over mutual
//! TLS with the claim SVID, and the upstream TLS runs inside it ([`crate::forward`], the
//! forwarder of ADR-0028 decision 3, a dialer in this process by ADR-0027 decision 8).
//!
//! A route the gateway places the credential for (`credential: gateway`, ADR-0040 decision 7) takes
//! a different path: the proxy never asks for a token and holds none. After the same checks (the
//! rules, a foreign credential is `401`) it strips the phantom and sends the request in origin
//! form, `Host` the audience's authority, over the claim's mutual TLS to a gateway's inject port,
//! where the gateway terminates the audience's TLS and places the credential; the body and the
//! response are streamed. A gateway's own refusal ([`GATEWAY_REFUSAL_HEADER`]) is `502
//! gateway_refused`, none reachable `502 gateway_unreachable`; a route with nowhere to be sent
//! refuses the proxy at start, so it is never tunnelled or given a token instead.
//!
//! Refusals: `405` for a `TRACE` or a `CONNECT`, `404` for a host outside the routes, `400` for
//! a path that is not canonical (a `.` or `..` segment, an empty one, a backslash, an encoded
//! dot, slash or backslash: the rules match the path as sent), `403` for a request outside the
//! audience's rules, `401` for an `Authorization` that is not the phantom (the workload has no credential
//! of its own this layer carries) and for any header of [`CREDENTIAL_HEADERS`] that no route
//! owns, `502` when the token or the upstream cannot be had. A
//! request with no `Authorization` is forwarded bare; `502` with `gateway_refused` when the
//! gateway answered the tunnel with the environment's no (the authorizer's code is logged),
//! `gateway_unreachable` when no gateway carried it. Nothing but the audience, the host,
//! the method, the path, the gateway and the status is logged.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http::header::{self, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;
use jiff::{SignedDuration, Timestamp};
use mediatore_proto::tls::UpstreamTls;
use mediatore_proto::{Endpoint, Route, TokenRequest, TokenResponse};
use rustls::pki_types::ServerName;
use tokio::io::AsyncBufReadExt as _;
use tokio::net::TcpListener;

use crate::client::SandboxClient;
use crate::forward::{DialError, Dialer, Forwarder};

/// The proxy's loopback port unless the guest is told otherwise.
pub const DEFAULT_PORT: u16 = 3128;
/// The jail's environment variable naming the proxy's base URL.
pub const PROXY_URL_ENV: &str = "MEDIATORE_EGRESS_PROXY";
/// The jail's environment variable carrying the phantom token (decision 3).
pub const PHANTOM_ENV: &str = "MEDIATORE_TOKEN";
/// The one line the proxy prints on standard output once it listens; the guest waits for it.
pub const READY_LINE: &str = "ready";
/// The response header with which a gateway marks its own refusal of a gateway-placed request
/// (the authorizer's `403`, ADR-0028 decision 4 and ADR-0040 decision 4) as opposed to the
/// upstream's answer, which crosses unchanged: the value is the authorizer's code. A response
/// that carries it is `502 gateway_refused` to the workload; anything else is relayed as it came.
pub const GATEWAY_REFUSAL_HEADER: &str = "x-mediatore-refusal";
/// A cached token is replaced this long before its `expires_at`.
const REFRESH_MARGIN_SECS: i64 = 30;
/// File names under the sandbox's `egress/` directory.
const ROUTES_FILE: &str = "routes.json";
const GATEWAYS_FILE: &str = "gateways.json";
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
    /// The environment's egress gateways, JSON as `GET /v1/me` returned them (ADR-0028);
    /// an empty list dials the upstreams directly
    #[arg(long)]
    pub gateways: PathBuf,
    /// The file holding the phantom token the jail was given
    #[arg(long)]
    pub phantom_file: PathBuf,
    /// A PEM of CA certificates trusted beside the Mozilla roots for an upstream that has
    /// no CA of its own: a policy bundle's direct egress, on the operator's private PKI
    /// (`MEDIATORE_EGRESS_CA` on the guest)
    #[arg(long, value_name = "PEM")]
    pub upstream_ca: Option<PathBuf>,
    /// The lowest TLS version offered to such an upstream: `1.3` (the default) or `1.2`, for
    /// an upstream that has no 1.3 (`MEDIATORE_EGRESS_MIN_TLS` on the guest)
    #[arg(long, default_value_t = UpstreamTls::Tls13)]
    pub upstream_min_tls: UpstreamTls,
    /// A second loopback listener for the guest's image pull (ADR-0043 decision 3): root's puller reaches the one
    /// registry named by `--pull-host` through it, as a gateway-placed route and nothing else. A port no jail rule
    /// lists, so the sandbox cannot reach it.
    #[arg(long, requires = "pull_host")]
    pub pull_listen: Option<SocketAddr>,
    /// The registry the pull listener serves, as an image reference names it (`host`, or `host:port` when the port is
    /// not 443).
    #[arg(long, requires = "pull_listen")]
    pub pull_host: Option<String>,
}

/// The trust the guest hands the proxy for upstreams that carry no CA of their own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamArgs {
    /// A PEM of CA certificates trusted beside the Mozilla roots.
    pub ca: Option<PathBuf>,
    /// The lowest TLS version offered.
    pub min_tls: UpstreamTls,
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

    /// Whether `value`, found in `header`, presents this phantom: `Bearer <phantom>` in
    /// `Authorization`, the bare phantom in a header a route names for its credential
    /// (ADR-0032 decision 3). Constant time either way.
    fn presented_in(&self, header: &HeaderName, value: &[u8]) -> bool {
        if *header == header::AUTHORIZATION {
            self.is_bearer(value)
        } else {
            aws_lc_rs::constant_time::verify_slices_are_equal(value, self.0.as_bytes()).is_ok()
        }
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
    /// The request headers the proxy owns on every route (ADR-0032 decision 3):
    /// `Authorization`, and every header a route names for its credential. A value in one
    /// of them is the phantom or a refusal, and none of them crosses the proxy as sent.
    owned: Vec<HeaderName>,
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
        let mut owned = vec![header::AUTHORIZATION];
        for r in routes {
            let e = r.endpoint.clone();
            anyhow::ensure!(
                !r.injects() || r.audience.is_some(),
                "route {e} injects a token but names no audience; the proxy cannot choose one"
            );
            if r.placed_at_gateway() {
                // The gateway places the credential, so the proxy must know where to send the
                // request and for whom; a route that cannot be sent anywhere refuses the
                // proxy (the claim does not start) rather than falling back to a tunnel or
                // to asking for a token, which would put the credential where this
                // placement exists to keep it from.
                anyhow::ensure!(
                    r.audience.is_some(),
                    "route {e} is placed at the gateway but names no audience; the gateway cannot choose a credential (ADR-0040 decision 7)"
                );
                anyhow::ensure!(
                    r.inject_port.is_some_and(|p| p != 0),
                    "route {e} is placed at the gateway but carries no inject_port: there is nowhere to send it, and it is never tunnelled or given a token in its place (ADR-0040 decision 7)"
                );
            }
            if let Some(h) = &r.credential_header {
                let name = HeaderName::from_bytes(h.as_bytes()).map_err(|_| {
                    anyhow::anyhow!("route {e}: credential_header {h:?} is not a header name")
                })?;
                if !owned.contains(&name) {
                    owned.push(name);
                }
            }
            if let Some(other) = by_endpoint.insert(e.clone(), r) {
                anyhow::bail!(
                    "endpoint {e} is on two routes ({} and {}); the proxy cannot choose a credential",
                    other.audience_label(),
                    by_endpoint[&e].audience_label()
                );
            }
            by_host.entry(e.host.clone()).or_default().push(e);
        }
        Ok(Self {
            by_endpoint,
            by_host,
            owned,
        })
    }

    /// The headers the proxy owns on every route (ADR-0032 decision 3).
    #[must_use]
    pub fn owned_headers(&self) -> &[HeaderName] {
        &self.owned
    }

    /// The first route the gateway places the credential for, if any (ADR-0040).
    #[must_use]
    pub fn first_gateway_placed(&self) -> Option<&Route> {
        self.by_endpoint.values().find(|r| r.placed_at_gateway())
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

/// The inject ports of the claim's gateway-placed routes (ADR-0040 decision 7), sorted and
/// without repeats: what the sandbox uid's table must name at each gateway, and nothing
/// when the claim has no such route.
#[must_use]
pub fn inject_ports(routes: &[Route]) -> std::collections::BTreeSet<u16> {
    routes
        .iter()
        .filter(|r| r.placed_at_gateway())
        .filter_map(|r| r.inject_port)
        .collect()
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
    /// Whether the phantom was presented and the route injects (decision 8): a token for
    /// the route's audience goes in. On a route without a credential the phantom is
    /// dropped and the request leaves bare.
    pub inject: bool,
}

/// Decide a request from its method, its path and query, and its `Authorization` header
/// (decisions 2 to 4 and 8). Pure, so the whole policy is unit-tested without a socket.
/// The shape every caller had before ADR-0032; [`judge_headers`] reads the whole header
/// map, so a phantom in a route's named header counts too.
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
    let mut headers = http::HeaderMap::new();
    if let Some(v) = authorization {
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(v)
                .map_err(|_| Refusal::new(StatusCode::UNAUTHORIZED, "unknown_credential"))?,
        );
    }
    judge_headers(routes, phantom, method, path_and_query, &headers)
}

/// [`judge`] over the request's headers: every header the proxy owns (`Authorization` and
/// each route's `credential_header`, ADR-0032 decision 3) is read on every route; a value
/// that is not the phantom is `401`, the phantom in any of them is the phantom presented.
/// A header of [`CREDENTIAL_HEADERS`] that no route owns is `401` as well, whatever its
/// value, on every kind of route.
///
/// Two refusals come before any route is consulted and hold on every kind of route: a
/// `TRACE` or a `CONNECT` is `405` (this proxy forwards requests, it opens no tunnel for the
/// workload, and an upstream that echoes a request would hand the placed credential back),
/// and a path that is not in its one canonical spelling
/// ([`mediatore_proto::path_is_canonical`]) is `400`, since the rules are globs over the
/// path as sent and the path is forwarded as sent. The query is not part of that check.
///
/// # Errors
/// The refusal the workload gets.
pub fn judge_headers<'a>(
    routes: &'a Routes,
    phantom: &Phantom,
    method: &Method,
    path_and_query: &str,
    headers: &http::HeaderMap,
) -> Result<Forward<'a>, Refusal> {
    if method == Method::TRACE || method == Method::CONNECT {
        return Err(Refusal::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
        ));
    }
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
    if !mediatore_proto::path_is_canonical(path) {
        return Err(Refusal::new(StatusCode::BAD_REQUEST, "bad_request"));
    }
    if !route.admits(method.as_str(), path) {
        return Err(Refusal::new(StatusCode::FORBIDDEN, "outside_rules"));
    }
    let mut presented = false;
    for owned in routes.owned_headers() {
        for v in headers.get_all(owned) {
            if phantom.presented_in(owned, v.as_bytes()) {
                presented = true;
            } else {
                return Err(Refusal::new(StatusCode::UNAUTHORIZED, "unknown_credential"));
            }
        }
    }
    if carries_unowned_credential(headers, routes.owned_headers(), phantom) {
        return Err(Refusal::new(StatusCode::UNAUTHORIZED, "unknown_credential"));
    }
    let inject = presented && route.injects();
    Ok(Forward {
        route,
        path_and_query,
        inject,
    })
}

/// Request headers that carry a credential on widely used APIs, beside the ones the proxy
/// owns (`Authorization` and each route's `credential_header`, [`Routes::owned_headers`]).
/// The workload has no credential of its own this layer carries (ADR-0025 decision 3): with
/// one of these it could act on an allowed host as some other account, which is a way to
/// move data to an account the policy never named. A request that carries any of them is
/// `401 unknown_credential` on every kind of route (token, `credential: none`, gateway-placed)
/// and nothing is forwarded.
///
/// Refused, not stripped: that is what an `Authorization` that is not the phantom gets, and
/// a refusal tells the workload's author that the credential was not used, where a silent
/// strip would send the request bare and leave an upstream `401` or an anonymous answer to
/// be explained.
///
/// A header a route names as its `credential_header` is not judged here: the proxy owns it
/// on every route, so [`judge_headers`] has already accepted the phantom in it and refused
/// anything else (ADR-0032 decision 3).
///
/// This list is a floor, not a claim of completeness: an upstream may read a credential
/// from a header of any name, and from the query string or the body, which this proxy does
/// not parse (a credential in the query is out of scope here; a route's rules and the
/// upstream's own authorization are what bound it). Names are lower-case, as
/// [`HeaderName`] holds every name it parses, so the match is case-insensitive on the wire;
/// [`HeaderName::from_static`] refuses an upper-case name at compile time.
pub const CREDENTIAL_HEADERS: [HeaderName; 14] = [
    header::COOKIE,
    header::PROXY_AUTHORIZATION,
    HeaderName::from_static("x-api-key"),
    HeaderName::from_static("api-key"),
    HeaderName::from_static("apikey"),
    HeaderName::from_static("x-auth-token"),
    HeaderName::from_static("x-access-token"),
    HeaderName::from_static("x-goog-api-key"),
    HeaderName::from_static("private-token"),
    HeaderName::from_static("job-token"),
    HeaderName::from_static("deploy-token"),
    HeaderName::from_static("x-amz-security-token"),
    HeaderName::from_static("x-vault-token"),
    HeaderName::from_static("ocp-apim-subscription-key"),
];

/// Whether `headers` carry a credential of the workload's own in one of
/// [`CREDENTIAL_HEADERS`] that is not among `owned`, the headers the proxy owns and has
/// judged by their value. The phantom there is not the workload's own: a client that sends
/// its one key in two headers (an SDK given `MEDIATORE_TOKEN` as its API key) is let through,
/// and [`rewrite`] drops the header, so the phantom never leaves the VM.
fn carries_unowned_credential(
    headers: &http::HeaderMap,
    owned: &[HeaderName],
    phantom: &Phantom,
) -> bool {
    CREDENTIAL_HEADERS
        .iter()
        .filter(|denied| !owned.contains(denied))
        .any(|denied| {
            headers
                .get_all(denied)
                .iter()
                .any(|v| !phantom.presented_in(denied, v.as_bytes()))
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

/// Drop from a request's `headers` what belongs to the hop from the workload: the fixed
/// [`HOP_BY_HOP`] list, and every header the request's own `Connection` names (RFC 9110
/// section 7.6.1). Without the second part a workload could mark a header as hop-by-hop
/// that this proxy forwards and the upstream, or something in front of it, drops or keeps
/// by a different reading. `close` and `keep-alive` in `Connection` name no header that
/// outlives this: `Connection` itself goes either way, and the connection to the upstream
/// is this proxy's own.
fn strip_hop_by_hop(headers: &mut http::HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|v| v.as_bytes().split(|b| *b == b','))
        .filter_map(|option| HeaderName::from_bytes(option.trim_ascii()).ok())
        .collect();
    for h in &named {
        headers.remove(h);
    }
    for h in HOP_BY_HOP {
        headers.remove(&h);
    }
}

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

/// A credential as the proxy places it (ADR-0032 decision 2): the header, its value, and
/// the headers that travel beside it. For a minted token, `Authorization: Bearer <token>`.
#[derive(Clone)]
struct Placement {
    header: HeaderName,
    value: HeaderValue,
    extra: Vec<(HeaderName, HeaderValue)>,
}

impl Placement {
    /// From the broker's answer; a header name or value the wire cannot carry is an error,
    /// and the request is refused rather than forwarded without the credential.
    fn from_response(resp: &TokenResponse) -> anyhow::Result<Self> {
        let (header, value) = match resp.header.as_deref() {
            None | Some("authorization") => (
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", resp.access_token)),
            ),
            Some(name) => (
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                    anyhow::anyhow!("credential header {name:?} is not a header name")
                })?,
                HeaderValue::from_str(&resp.access_token),
            ),
        };
        let value = value.map_err(|_| anyhow::anyhow!("the credential is not a header value"))?;
        let mut extra = Vec::with_capacity(resp.extra_headers.len());
        for h in &resp.extra_headers {
            extra.push((
                HeaderName::from_bytes(h.name.as_bytes()).map_err(|_| {
                    anyhow::anyhow!("extra header {:?} is not a header name", h.name)
                })?,
                HeaderValue::from_str(&h.value).map_err(|_| {
                    anyhow::anyhow!(
                        "extra header {:?} has a value the wire cannot carry",
                        h.name
                    )
                })?,
            ));
        }
        Ok(Self {
            header,
            value,
            extra,
        })
    }
}

/// One audience's credential and its expiry, behind the lock that makes its fetch single flight.
type TokenSlot = Arc<tokio::sync::Mutex<Option<(Placement, Timestamp)>>>;

/// Credentials by audience, replaced [`REFRESH_MARGIN_SECS`] before they expire. One
/// fetch at a time per audience: two requests arriving together for the same audience do not
/// both spend the claim's rate limit, and a request for an audience whose credential is fresh
/// does not wait behind another audience's fetch. The audiences are the ones the claim's
/// routes name ([`Proxy::handle`] takes the audience from the route, never from the request),
/// so there are no more slots than routes.
#[derive(Default)]
struct TokenCache {
    slots: std::sync::Mutex<HashMap<String, TokenSlot>>,
}

impl TokenCache {
    /// The slot for `audience`, made on first use. The map's lock is held for the lookup and
    /// nothing else, never across an await.
    fn slot(&self, audience: &str) -> TokenSlot {
        // A panic under this lock leaves the map as it was: a slot is inserted whole or not at all.
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(slot) = slots.get(audience) {
            return slot.clone();
        }
        slots.entry(audience.to_owned()).or_default().clone()
    }

    async fn placement(
        &self,
        source: &dyn TokenSource,
        audience: &str,
    ) -> anyhow::Result<Placement> {
        let slot = self.slot(audience);
        let mut held = slot.lock().await;
        if let Some((placed, expires_at)) = held.as_ref()
            && expires_at.duration_since(Timestamp::now())
                > SignedDuration::from_secs(REFRESH_MARGIN_SECS)
        {
            return Ok(placed.clone());
        }
        let fresh = source.token(audience).await?;
        tracing::info!(audience, expires_at = %fresh.expires_at, header = fresh.header.as_deref().unwrap_or("authorization"), "token fetched for the proxy");
        let placed = Placement::from_response(&fresh)?;
        *held = Some((placed.clone(), fresh.expires_at));
        Ok(placed)
    }
}

/// The proxy: the claim's routes, its phantom, where tokens come from, how an upstream is
/// reached (directly, or through the environment's gateways as the claim) and how it is
/// trusted, per route.
pub struct Proxy {
    routes: Routes,
    phantom: Phantom,
    tokens: Arc<dyn TokenSource>,
    cache: TokenCache,
    dialer: Dialer,
    /// The trust for a route without a CA of its own.
    tls: Arc<rustls::ClientConfig>,
    /// Per endpoint, the trust for a route that carries a CA (`Route::ca_pem`): exactly that
    /// CA and nothing else (decision 7); keyed by the endpoint since a route without a
    /// credential may carry one too and names no audience (decision 8).
    tls_by_endpoint: HashMap<Endpoint, Arc<rustls::ClientConfig>>,
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
    /// alone, built here. Upstreams are reached through `dialer`: directly, or as a tunnel
    /// through one of the environment's gateways (ADR-0028).
    ///
    /// # Errors
    /// A `ca_pem` that holds no certificate: the claim must not start with a route whose
    /// trust cannot be built (fail closed, never the default roots in its place).
    pub fn new(
        routes: Routes,
        phantom: Phantom,
        tokens: Arc<dyn TokenSource>,
        tls: rustls::ClientConfig,
        dialer: Dialer,
    ) -> anyhow::Result<Self> {
        if dialer.is_direct()
            && let Some(r) = routes.first_gateway_placed()
        {
            anyhow::bail!(
                "route {} (audience {}) is placed at the gateway but the claim lists no egress gateway: the credential cannot be placed anywhere, and it is never fetched here in its place (ADR-0040 decisions 1 and 7)",
                r.endpoint,
                r.audience_label()
            );
        }
        let mut tls_by_endpoint = HashMap::new();
        for r in routes.by_endpoint.values() {
            if let Some(pem) = &r.ca_pem {
                let cfg = mediatore_proto::tls::https_client_config_with_ca(pem.as_bytes())
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "route {} (audience {}): {e}",
                            r.endpoint,
                            r.audience_label()
                        )
                    })?;
                tls_by_endpoint.insert(r.endpoint.clone(), http1_only(cfg));
            }
        }
        Ok(Self {
            routes,
            phantom,
            tokens,
            cache: TokenCache::default(),
            dialer,
            tls: http1_only(tls),
            tls_by_endpoint,
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
        dialer: Dialer,
    ) -> anyhow::Result<Self> {
        Self::new(
            routes,
            phantom,
            tokens,
            mediatore_proto::tls::https_client_config(),
            dialer,
        )
    }

    /// As [`Self::with_webpki_roots`], with the operator's own trust for the routes that carry
    /// no CA (a policy bundle's direct egress): `extra_roots_pem` beside the Mozilla roots,
    /// and TLS 1.2 accepted below 1.3 when `min` says so. A route with a CA of its own keeps
    /// exactly that CA at TLS 1.3, whatever this is.
    ///
    /// # Errors
    /// `extra_roots_pem` holds no certificate, or as [`Self::new`].
    pub fn with_upstream_trust(
        routes: Routes,
        phantom: Phantom,
        tokens: Arc<dyn TokenSource>,
        dialer: Dialer,
        extra_roots_pem: Option<&[u8]>,
        min: UpstreamTls,
    ) -> anyhow::Result<Self> {
        let tls = mediatore_proto::tls::egress_upstream_config(extra_roots_pem, min)
            .map_err(|e| anyhow::anyhow!("the egress proxy's upstream trust: {e}"))?;
        Self::new(routes, phantom, tokens, tls, dialer)
    }

    /// How upstreams are reached.
    #[must_use]
    pub fn dialer(&self) -> &Dialer {
        &self.dialer
    }

    /// The trust for `route`: the CA it carries when it does, the default otherwise.
    fn tls_for(&self, route: &Route) -> Arc<rustls::ClientConfig> {
        route
            .ca_pem
            .as_ref()
            .and_then(|_| self.tls_by_endpoint.get(&route.endpoint))
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
            // A failure only costs latency (Nagle against delayed ACKs on a streamed answer).
            let _ = stream.set_nodelay(true);
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
        let forward = match judge_headers(
            &self.routes,
            &self.phantom,
            &method,
            &path_and_query,
            req.headers(),
        ) {
            Ok(f) => f,
            Err(r) => {
                tracing::warn!(%method, path = %path_and_query, status = %r.status, code = r.code, "request refused");
                return refuse(&r);
            }
        };
        if forward.route.pull_only {
            // A registry audience's route (ADR-0063 decision 5): the puller's, through the pull listener, never the
            // workload's. The workload cannot fetch further images.
            tracing::warn!(audience = forward.route.audience_label(), host = %forward.route.endpoint, %method, "a pull-only route asked from the jail; refused");
            return refuse(&Refusal::new(StatusCode::NOT_FOUND, "pull_only"));
        }
        if forward.route.placed_at_gateway() {
            return self.handle_at_gateway(req, &forward).await;
        }
        self.handle_tunnelled(req, forward).await
    }

    /// A request on a route the proxy places itself (or sends bare), through a gateway's tunnel or, without gateways,
    /// directly (ADR-0025, ADR-0028). It has been judged.
    async fn handle_tunnelled(
        &self,
        req: Request<Incoming>,
        forward: Forward<'_>,
    ) -> Response<Body> {
        let method = req.method().clone();
        let route = forward.route.clone();
        let path_log = forward.path_and_query.clone();
        let placed = match (forward.inject, route.audience.as_deref()) {
            (true, Some(audience)) => match self.cache.placement(&*self.tokens, audience).await {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::error!(audience, error = %e, "no token for the proxy");
                    return refuse(&Refusal::new(StatusCode::BAD_GATEWAY, "token_unavailable"));
                }
            },
            // `Routes::new` refused a route that injects with no audience; nothing goes in.
            _ => None,
        };
        let upstream = rewrite(req, &forward, placed.as_ref(), self.routes.owned_headers());
        match connect_and_send(
            &self.dialer,
            &route.endpoint,
            self.tls_for(&route),
            upstream,
        )
        .await
        {
            Ok((resp, via)) => {
                tracing::info!(
                    audience = route.audience_label(),
                    host = %route.endpoint,
                    %method,
                    path = %path_log,
                    status = %resp.status(),
                    credential = forward.inject,
                    via = %via.as_ref().map_or_else(|| "direct".to_owned(), ToString::to_string),
                    "forwarded"
                );
                let mut resp = resp.map(BodyExt::boxed);
                for h in HOP_BY_HOP {
                    resp.headers_mut().remove(&h);
                }
                resp
            }
            Err(SendError::Dial(e @ DialError::Refused { .. })) => {
                // The environment's verdict on this tunnel, with the authorizer's code.
                tracing::warn!(audience = route.audience_label(), host = %route.endpoint, error = %e, "the gateway refused the tunnel");
                refuse(&Refusal::new(StatusCode::BAD_GATEWAY, e.code()))
            }
            Err(SendError::Dial(e)) => {
                tracing::error!(audience = route.audience_label(), host = %route.endpoint, error = %e, "upstream unreachable");
                refuse(&Refusal::new(StatusCode::BAD_GATEWAY, e.code()))
            }
            Err(SendError::Upstream(e)) => {
                tracing::error!(audience = route.audience_label(), host = %route.endpoint, error = %e, "upstream unreachable");
                refuse(&Refusal::new(
                    StatusCode::BAD_GATEWAY,
                    "upstream_unreachable",
                ))
            }
        }
    }
}

impl Proxy {
    /// Serve the pull listener (ADR-0043 decision 3) until the task is dropped: the guest's puller, as root, asks for
    /// the one registry `host` here, as `/<host>/v2/...` with no credential, and each request goes to a gateway as a
    /// placed route. Nothing else is served on this port.
    ///
    /// # Errors
    /// When `accept` fails, which ends the proxy and so the claim.
    pub async fn serve_pull(
        self: Arc<Self>,
        listener: TcpListener,
        host: String,
    ) -> anyhow::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            // A failure only costs latency (Nagle against delayed ACKs on a streamed answer).
            let _ = stream.set_nodelay(true);
            let proxy = self.clone();
            let host = host.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    let proxy = proxy.clone();
                    let host = host.clone();
                    async move { Ok::<_, std::convert::Infallible>(proxy.handle_pull(req, &host).await) }
                });
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    tracing::debug!(error = %e, "connection from the puller ended with an error");
                }
            });
        }
    }

    /// One request from the puller: for `host` only, judged by the route's rules as any request is, and sent through a
    /// gateway (ADR-0063 decision 3): to its inject port for a gateway-placed route, in a tunnel for any other. Only a
    /// registry audience's route (pull-only) or a gateway-placed one is served here; any other route is refused, so this
    /// port never serves the workload's APIs.
    async fn handle_pull(&self, req: Request<Incoming>, host: &str) -> Response<Body> {
        let method = req.method().clone();
        let Some(path_and_query) = req.uri().path_and_query().map(ToString::to_string) else {
            return refuse(&Refusal::new(StatusCode::BAD_REQUEST, "bad_request"));
        };
        let segment = path_and_query
            .trim_start_matches('/')
            .split(['/', '?'])
            .next()
            .unwrap_or_default();
        if !segment.eq_ignore_ascii_case(host) {
            tracing::warn!(%method, "pull request for a host that is not the pull host refused");
            return refuse(&Refusal::new(StatusCode::NOT_FOUND, "not_the_pull_host"));
        }
        let forward = match judge_headers(
            &self.routes,
            &self.phantom,
            &method,
            &path_and_query,
            req.headers(),
        ) {
            Ok(f) => f,
            Err(r) => {
                tracing::warn!(%method, path = %path_and_query, status = %r.status, code = r.code, "pull request refused");
                return refuse(&r);
            }
        };
        if forward.route.placed_at_gateway() {
            return self.handle_at_gateway(req, &forward).await;
        }
        if !forward.route.pull_only {
            tracing::warn!(host, "the pull host's route is not a registry's; refused");
            return refuse(&Refusal::new(StatusCode::FORBIDDEN, "not_a_pull_route"));
        }
        // The puller presents no phantom (it is root's, outside the jail): the route's own credential goes in when it
        // has one, as the workload's would.
        let forward = Forward {
            inject: forward.route.injects(),
            ..forward
        };
        self.handle_tunnelled(req, forward).await
    }
}

impl Proxy {
    /// A request on a gateway-placed route (ADR-0040 decision 7). It has been judged: the rules
    /// held, and any credential header it carried was the phantom (a foreign one is `401`, as
    /// is any header of [`CREDENTIAL_HEADERS`] no route owns).
    /// It is sent in origin form, with `Host` the audience's authority and no credential, over
    /// the claim's mutual TLS to a gateway's inject port; the gateway terminates the
    /// audience's TLS and places the credential, so this process never asks for a token and
    /// never holds one for the route. The response comes back as it was, streamed, unless the
    /// gateway marked it as its own refusal ([`GATEWAY_REFUSAL_HEADER`]).
    async fn handle_at_gateway(
        &self,
        req: Request<Incoming>,
        forward: &Forward<'_>,
    ) -> Response<Body> {
        let route = forward.route;
        let method = req.method().clone();
        // The path alone is logged (the query can carry what the workload put in it).
        let path_log = forward
            .path_and_query
            .split('?')
            .next()
            .unwrap_or("/")
            .to_owned();
        let Some(port) = route.inject_port.filter(|p| *p != 0) else {
            // `Routes::new` refuses this route at start; failing closed here too costs nothing.
            tracing::error!(audience = route.audience_label(), host = %route.endpoint, "a gateway-placed route has no inject port; nothing is sent");
            return refuse(&Refusal::new(StatusCode::BAD_GATEWAY, "inject_unavailable"));
        };
        let upstream = rewrite_for_gateway(req, forward, self.routes.owned_headers());
        match send_to_gateway(&self.dialer, port, upstream).await {
            Ok((resp, via)) => {
                if let Some(code) = resp.headers().get(GATEWAY_REFUSAL_HEADER) {
                    // The environment's verdict (the authorizer's code), not the upstream's answer.
                    tracing::warn!(
                        audience = route.audience_label(),
                        host = %route.endpoint,
                        %method,
                        path = %path_log,
                        code = %log_safe(code.as_bytes()),
                        "the gateway refused the request"
                    );
                    return refuse(&Refusal::new(StatusCode::BAD_GATEWAY, "gateway_refused"));
                }
                tracing::info!(
                    audience = route.audience_label(),
                    host = %route.endpoint,
                    %method,
                    path = %path_log,
                    status = %resp.status(),
                    credential = "gateway",
                    via = %via.as_ref().map_or_else(|| "-".to_owned(), ToString::to_string),
                    "forwarded"
                );
                let mut resp = resp.map(BodyExt::boxed);
                for h in HOP_BY_HOP {
                    resp.headers_mut().remove(&h);
                }
                resp
            }
            Err(SendError::Dial(e)) => {
                tracing::error!(audience = route.audience_label(), host = %route.endpoint, error = %e, "no gateway took the request");
                refuse(&Refusal::new(StatusCode::BAD_GATEWAY, e.code()))
            }
            Err(SendError::Upstream(e)) => {
                tracing::error!(audience = route.audience_label(), host = %route.endpoint, error = %e, "the gateway's connection failed");
                refuse(&Refusal::new(
                    StatusCode::BAD_GATEWAY,
                    "gateway_unreachable",
                ))
            }
        }
    }
}

/// A header value as a log field: the characters of a code, a bounded few.
fn log_safe(v: &[u8]) -> String {
    String::from_utf8_lossy(v)
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .take(64)
        .collect()
}

/// The request as a gateway's inject port gets it (ADR-0040 decision 7): what [`rewrite`] makes
/// with no credential placed (origin-form path, `Host` the audience's authority, hop-by-hop and
/// every owned header dropped, so the phantom never leaves), and `x-api-key` dropped as well
/// wherever no route owns it. Since [`CREDENTIAL_HEADERS`] a request with an `x-api-key` no
/// route owns is refused before it gets here, so that drop is a second line and not the
/// control. The gateway's authorizer strips the client credential headers too; this layer does
/// not wait for it.
fn rewrite_for_gateway(
    req: Request<Incoming>,
    forward: &Forward<'_>,
    owned: &[HeaderName],
) -> Request<Incoming> {
    let mut req = rewrite(req, forward, None, owned);
    req.headers_mut()
        .remove(HeaderName::from_static("x-api-key"));
    req
}

/// To a gateway's inject port through `dialer`, one HTTP/1.1 connection over the claim's mutual
/// TLS, one request, the body streamed. No second gateway is tried once one holds the
/// connection: the body cannot be replayed, and whatever answers is the answer.
async fn send_to_gateway(
    dialer: &Dialer,
    port: u16,
    req: Request<Incoming>,
) -> Result<(Response<Incoming>, Option<Endpoint>), SendError> {
    let opened = dialer.inject(port).await.map_err(SendError::Dial)?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(opened.conn))
        .await
        .map_err(|e| SendError::Upstream(e.into()))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "gateway connection ended with an error");
        }
    });
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| SendError::Upstream(e.into()))?;
    Ok((resp, opened.via))
}

/// The request as the upstream gets it: origin-form path, `Host` set to the endpoint,
/// hop-by-hop headers dropped, the ones the request's `Connection` names among them
/// ([`strip_hop_by_hop`]), every header the proxy owns dropped (the phantom never
/// leaves, ADR-0032 decision 3), and the credential placed where the broker said when one
/// goes in, with the headers that travel beside it.
fn rewrite(
    req: Request<Incoming>,
    forward: &Forward<'_>,
    placed: Option<&Placement>,
    owned: &[HeaderName],
) -> Request<Incoming> {
    let (mut parts, body) = req.into_parts();
    parts.uri = forward
        .path_and_query
        .parse()
        .unwrap_or_else(|_| http::Uri::from_static("/"));
    parts.version = http::Version::HTTP_11;
    strip_hop_by_hop(&mut parts.headers);
    if let Ok(v) = HeaderValue::from_str(&host_header(&forward.route.endpoint)) {
        parts.headers.insert(header::HOST, v);
    }
    for h in owned {
        parts.headers.remove(h);
    }
    // What was let through in a credential header no route owns was the phantom: it stays here.
    for h in CREDENTIAL_HEADERS {
        parts.headers.remove(h);
    }
    if let Some(p) = placed {
        parts.headers.insert(p.header.clone(), p.value.clone());
        for (name, value) in &p.extra {
            parts.headers.insert(name.clone(), value.clone());
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

/// Why a request did not come back from the upstream.
enum SendError {
    /// The dial: no connection, no gateway carried the tunnel, or a gateway refused it.
    Dial(DialError),
    /// Connected, then the upstream's TLS or HTTP failed.
    Upstream(anyhow::Error),
}

/// To `endpoint` through `dialer`, the upstream's TLS over whatever it opened (a tunnel's
/// bytes are relayed untouched by the gateway, so the upstream sees this handshake and
/// nothing in between does), one HTTP/1.1 connection, one request. Returns the response
/// and the gateway that carried it, if one did.
async fn connect_and_send(
    dialer: &Dialer,
    endpoint: &Endpoint,
    tls: Arc<rustls::ClientConfig>,
    req: Request<Incoming>,
) -> Result<(Response<Incoming>, Option<Endpoint>), SendError> {
    let opened = dialer.dial(endpoint).await.map_err(SendError::Dial)?;
    let name = ServerName::try_from(endpoint.host.clone()).map_err(|e| {
        SendError::Upstream(anyhow::anyhow!(
            "{} is not a server name: {e}",
            endpoint.host
        ))
    })?;
    let stream = tokio_rustls::TlsConnector::from(tls)
        .connect(name, opened.conn)
        .await
        .map_err(|e| SendError::Upstream(e.into()))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| SendError::Upstream(e.into()))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "upstream connection ended with an error");
        }
    });
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| SendError::Upstream(e.into()))?;
    Ok((resp, opened.via))
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
    /// The environment's gateways, JSON (ADR-0028).
    pub gateways: PathBuf,
    /// The phantom.
    pub phantom: PathBuf,
}

/// Write the routes, the gateways and the phantom into `dir` for the sandbox user: mode
/// 0400, owned by `uid:gid`, outside the jail's mounts.
///
/// # Errors
/// On any filesystem failure.
pub fn write_files(
    dir: &Path,
    routes: &[Route],
    gateways: &[Endpoint],
    phantom: &Phantom,
    uid: u32,
    gid: u32,
) -> anyhow::Result<EgressFiles> {
    use std::os::unix::fs::PermissionsExt as _;
    let files = EgressFiles {
        routes: dir.join(ROUTES_FILE),
        gateways: dir.join(GATEWAYS_FILE),
        phantom: dir.join(PHANTOM_FILE),
    };
    std::fs::write(&files.routes, serde_json::to_vec(routes)?)?;
    std::fs::write(&files.gateways, serde_json::to_vec(gateways)?)?;
    std::fs::write(&files.phantom, phantom.expose().as_bytes())?;
    for p in [&files.routes, &files.gateways, &files.phantom] {
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
    upstream: &UpstreamArgs,
) -> Vec<String> {
    let mut args = vec![
        "egress-proxy".into(),
        "--listen".into(),
        listen.to_string(),
        "--mediatore-url".into(),
        mediatore_url.to_owned(),
        "--workload-api-socket".into(),
        workload_api_socket.to_owned(),
        "--routes".into(),
        files.routes.display().to_string(),
        "--gateways".into(),
        files.gateways.display().to_string(),
        "--phantom-file".into(),
        files.phantom.display().to_string(),
    ];
    // Only when set: the default argv is the one the proxy has always had.
    if let Some(ca) = &upstream.ca {
        args.push("--upstream-ca".into());
        args.push(ca.display().to_string());
    }
    if upstream.min_tls != UpstreamTls::Tls13 {
        args.push("--upstream-min-tls".into());
        args.push(upstream.min_tls.to_string());
    }
    args
}

/// The pull listener's loopback port unless the guest is told otherwise (`MEDIATORE_EGRESS_PULL_PORT`): not the
/// proxy's, and listed by no jail rule.
pub const DEFAULT_PULL_PORT: u16 = 18129;

/// The registry of an image, by the name its reference carries (the host, with the port only when it is not 443),
/// when a route of the claim serves the pull: a registry audience's (pull-only, ADR-0063 decision 5) or a
/// gateway-placed one (ADR-0043 decision 2). The pull then goes through the proxy. `None` for every other registry.
#[must_use]
pub fn pull_registry(routes: &[Route], registry: &str) -> Option<String> {
    routes
        .iter()
        .filter(|r| r.pull_only || r.placed_at_gateway())
        .map(|r| {
            if r.endpoint.port == 443 {
                r.endpoint.host.clone()
            } else {
                format!("{}:{}", r.endpoint.host, r.endpoint.port)
            }
        })
        .find(|name| name.eq_ignore_ascii_case(registry))
}

/// The two options that add the pull listener (ADR-0043 decision 3), appended to [`command_args`] only for a claim
/// whose image is on a registry the gateway places a credential for.
#[must_use]
pub fn pull_args(listen: SocketAddr, host: &str) -> Vec<String> {
    vec![
        "--pull-listen".into(),
        listen.to_string(),
        "--pull-host".into(),
        host.to_owned(),
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

/// Run the role: read the routes, the gateways and the phantom, obtain the claim SVID (one
/// source for the broker's client and the gateways' tunnels), listen, say so.
///
/// # Errors
/// Anything missing: no routes, gateways or phantom file, no Workload API, the port taken.
pub async fn run(args: EgressArgs) -> anyhow::Result<()> {
    // First, before anything is read or bound: this process runs beside the jail as the
    // sandbox user and parses what the workload sends, and no packet filter sees a socket
    // that is not inet. It opens unix and inet sockets and no other kind, so every other
    // family is closed to it for good, as to the workload (ADR-0051). No filter, no proxy.
    crate::seccomp::restrict_families()
        .map_err(|e| anyhow::anyhow!("the egress proxy does not start: {e:#}"))?;
    tracing::info!("address families restricted to unix and inet (seccomp, all threads)");
    let routes: Vec<Route> = serde_json::from_slice(&std::fs::read(&args.routes)?)?;
    let routes = Routes::new(routes)?;
    let gateways: Vec<Endpoint> = serde_json::from_slice(&std::fs::read(&args.gateways)?)?;
    let phantom = Phantom::parse(&std::fs::read_to_string(&args.phantom_file)?)?;
    anyhow::ensure!(
        args.listen.ip().is_loopback(),
        "the egress proxy listens on loopback only; got {}",
        args.listen
    );
    let source = crate::client::workload_api_source(&args.workload_api_socket).await?;
    let client = SandboxClient::with_material(&args.mediatore_url, source.clone())?;
    let dialer = if gateways.is_empty() {
        tracing::warn!(
            "no egress gateway listed: upstreams are dialled directly (ADR-0028 decision 3 applies once the environment has gateways)"
        );
        Dialer::Direct
    } else {
        let forwarder = Forwarder::new(gateways, source)?;
        tracing::info!(
            gateways = ?forwarder.gateways().iter().map(ToString::to_string).collect::<Vec<_>>(),
            gateway_id = %forwarder.gateway_id(),
            "upstreams are tunnelled through the egress gateways as the claim"
        );
        Dialer::Gateways(forwarder)
    };
    let listener = TcpListener::bind(args.listen).await?;
    let addr = listener.local_addr()?;
    // The CA is read here, by the proxy as the sandbox user: a file it cannot read, or one
    // with no certificate, ends the claim before the jail starts (fail closed).
    let upstream_ca = match &args.upstream_ca {
        Some(path) => Some(
            std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("reading --upstream-ca {}: {e}", path.display()))?,
        ),
        None => None,
    };
    let proxy = Arc::new(Proxy::with_upstream_trust(
        routes,
        phantom,
        Arc::new(BrokerTokens { client }),
        dialer,
        upstream_ca.as_deref(),
        args.upstream_min_tls,
    )?);
    tracing::info!(%addr, routes = proxy.routes.len(), dial = %proxy.dialer, "egress proxy listening");
    // The one line on standard output: the guest starts the jail when it reads it.
    // The pull listener is bound before the ready line, so the guest's puller never meets a closed port.
    let pull = match (args.pull_listen, args.pull_host.clone()) {
        (Some(pull_addr), Some(pull_host)) => {
            anyhow::ensure!(
                pull_addr.ip().is_loopback() && pull_addr != args.listen,
                "the pull listener is on loopback and is not the proxy's own port; got {pull_addr}"
            );
            let pull = TcpListener::bind(pull_addr).await?;
            tracing::info!(addr = %pull.local_addr()?, host = %pull_host, "pull listener (a placed registry, for the guest's image pull)");
            Some((pull, pull_host))
        }
        _ => None,
    };
    println!("{READY_LINE} {addr}");
    let Some((pull, pull_host)) = pull else {
        return proxy.serve(listener).await;
    };
    // Either listener ending ends the proxy, and so the claim.
    tokio::select! {
        r = proxy.clone().serve(listener) => r,
        r = proxy.serve_pull(pull, pull_host) => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mediatore_proto::{Credential, EndpointRule};

    fn route(audience: &str, endpoint: &str, rules: &[(&str, &str)]) -> Route {
        Route {
            audience: Some(audience.into()),
            endpoint: endpoint.parse().unwrap(),
            rules: rules
                .iter()
                .map(|(m, p)| EndpointRule {
                    method: (*m).into(),
                    path: (*p).into(),
                })
                .collect(),
            ca_pem: None,
            credential: Credential::Token,
            credential_header: None,
            inject_port: None,
            pull_only: false,
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
            Dialer::Direct,
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
            Dialer::Direct,
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
                Arc::new(NoTokens),
                Dialer::Direct,
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
            r.resolve("git.home.example").unwrap().audience_label(),
            "internal-git"
        );
        assert_eq!(
            r.resolve("git.home.example:443").unwrap().audience_label(),
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
        assert_eq!(r.resolve("192.0.2.10").unwrap().audience_label(), "data");
        assert_eq!(
            r.resolve("[2001:db8::1]:8443").unwrap().audience_label(),
            "data6"
        );
        assert_eq!(
            r.resolve("[2001:db8::1]").unwrap().audience_label(),
            "data6"
        );
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
        assert_eq!(f.route.audience_label(), "internal-git");
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
    fn on_a_route_without_a_credential_the_phantom_is_dropped_and_a_foreign_bearer_still_refused() {
        // A bundle's direct egress entry (no audience) and a `via: none` audience, both
        // `credential: none` (ADR-0025 decision 8).
        let r = Routes::new(vec![
            Route {
                audience: None,
                credential: Credential::None,
                ..route("-", "repo.home.example:443", &[])
            },
            Route {
                credential: Credential::None,
                ..route("public", "api.example.com:443", &[("GET", "/repos/**")])
            },
            route("internal-git", "git.home.example:443", &[]),
        ])
        .unwrap();
        let p = phantom();
        let with_phantom = format!("Bearer {}", p.expose());
        for host in ["repo.home.example", "api.example.com"] {
            let f = judge(
                &r,
                &p,
                &Method::GET,
                &format!("/{host}/repos/x"),
                Some(with_phantom.as_bytes()),
            )
            .unwrap();
            assert!(
                !f.inject,
                "{host}: the phantom is dropped, nothing goes in its place"
            );
            let bare = judge(&r, &p, &Method::GET, &format!("/{host}/repos/x"), None).unwrap();
            assert!(!bare.inject);
            let foreign = judge(
                &r,
                &p,
                &Method::GET,
                &format!("/{host}/repos/x"),
                Some(b"Bearer baked-into-the-image"),
            )
            .unwrap_err();
            assert_eq!(
                foreign,
                Refusal::new(StatusCode::UNAUTHORIZED, "unknown_credential"),
                "{host}: an image's own credential is refused on every route"
            );
        }
        // The rules on a `via: none` audience still apply.
        assert_eq!(
            judge(&r, &p, &Method::DELETE, "/api.example.com/repos/x", None).unwrap_err(),
            Refusal::new(StatusCode::FORBIDDEN, "outside_rules")
        );
        // A route with a token keeps injecting beside them.
        let f = judge(
            &r,
            &p,
            &Method::GET,
            "/git.home.example/x",
            Some(with_phantom.as_bytes()),
        )
        .unwrap();
        assert!(f.inject);
        assert_eq!(f.route.audience_label(), "internal-git");
    }

    #[test]
    fn a_route_that_injects_without_an_audience_is_refused() {
        let err = Routes::new(vec![Route {
            audience: None,
            ..route("-", "repo.home.example:443", &[])
        }])
        .unwrap_err()
        .to_string();
        assert!(err.contains("names no audience"), "{err}");
        assert!(
            Routes::new(vec![Route {
                audience: None,
                credential: Credential::None,
                ..route("-", "repo.home.example:443", &[])
            }])
            .is_ok(),
            "no credential: no audience needed"
        );
    }

    #[test]
    fn the_phantom_in_a_routes_named_header_is_recognised_and_that_header_is_owned_everywhere() {
        // An audience `via: secret` with `x-api-key` (ADR-0032 decisions 2 and 3).
        let r = Routes::new(vec![
            Route {
                credential_header: Some("x-api-key".into()),
                ..route(
                    "anthropic",
                    "api.anthropic.com:443",
                    &[("POST", "/v1/messages")],
                )
            },
            route("internal-git", "git.home.example:443", &[]),
        ])
        .unwrap();
        assert_eq!(
            r.owned_headers(),
            &[header::AUTHORIZATION, HeaderName::from_static("x-api-key")]
        );
        let p = phantom();
        let key = HeaderName::from_static("x-api-key");
        let mut in_key = http::HeaderMap::new();
        in_key.insert(key.clone(), HeaderValue::from_str(p.expose()).unwrap());
        let f = judge_headers(
            &r,
            &p,
            &Method::POST,
            "/api.anthropic.com/v1/messages",
            &in_key,
        )
        .unwrap();
        assert!(
            f.inject,
            "the phantom in x-api-key is the phantom presented"
        );
        let mut as_bearer = http::HeaderMap::new();
        as_bearer.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", p.expose())).unwrap(),
        );
        assert!(
            judge_headers(
                &r,
                &p,
                &Method::POST,
                "/api.anthropic.com/v1/messages",
                &as_bearer
            )
            .unwrap()
            .inject,
            "and in Authorization, as before"
        );
        // A key of the image's own, in the named header, is refused on this route and on
        // every other: the header is the proxy's wherever a request goes.
        let mut foreign = http::HeaderMap::new();
        foreign.insert(
            key.clone(),
            HeaderValue::from_static("sk-baked-into-the-image"),
        );
        for path in ["/api.anthropic.com/v1/messages", "/git.home.example/x"] {
            assert_eq!(
                judge_headers(&r, &p, &Method::POST, path, &foreign).unwrap_err(),
                Refusal::new(StatusCode::UNAUTHORIZED, "unknown_credential"),
                "{path}"
            );
        }
        // The phantom in one owned header and a foreign value in another: refused.
        let mut mixed = as_bearer.clone();
        mixed.insert(key, HeaderValue::from_static("sk-other"));
        assert_eq!(
            judge_headers(
                &r,
                &p,
                &Method::POST,
                "/api.anthropic.com/v1/messages",
                &mixed
            )
            .unwrap_err()
            .status,
            StatusCode::UNAUTHORIZED
        );
        // A header no route names passes through judgement untouched.
        let mut other = http::HeaderMap::new();
        other.insert(
            HeaderName::from_static("x-trace"),
            HeaderValue::from_static("t"),
        );
        assert!(
            !judge_headers(&r, &p, &Method::GET, "/git.home.example/x", &other)
                .unwrap()
                .inject
        );
        // A route naming something that is not a header name refuses the proxy.
        assert!(
            Routes::new(vec![Route {
                credential_header: Some("not a header".into()),
                ..route("a", "a.example.com:443", &[])
            }])
            .is_err()
        );
    }

    #[test]
    fn a_placement_puts_the_credential_where_the_broker_said_with_its_extra_headers() {
        let subject = mediatore_proto::Subject {
            issuer: "https://idp.example".into(),
            id: "octocat".into(),
            display: None,
        };
        let keyed = TokenResponse {
            access_token: "sk-real".into(),
            token_type: "Header".into(),
            expires_at: Timestamp::now() + SignedDuration::from_mins(10),
            audience: "anthropic".into(),
            subject: subject.clone(),
            header: Some("x-api-key".into()),
            extra_headers: vec![mediatore_proto::HeaderPair {
                name: "anthropic-beta".into(),
                value: "oauth-2025-04-20".into(),
            }],
        };
        let p = Placement::from_response(&keyed).unwrap();
        assert_eq!(p.header, HeaderName::from_static("x-api-key"));
        assert_eq!(p.value, HeaderValue::from_static("sk-real"));
        assert_eq!(p.extra[0].0, HeaderName::from_static("anthropic-beta"));
        let bearer = TokenResponse {
            header: None,
            token_type: "Bearer".into(),
            extra_headers: vec![],
            ..keyed.clone()
        };
        let b = Placement::from_response(&bearer).unwrap();
        assert_eq!(b.header, header::AUTHORIZATION);
        assert_eq!(b.value, HeaderValue::from_static("Bearer sk-real"));
        assert!(
            Placement::from_response(&TokenResponse {
                access_token: "line\nbreak".into(),
                ..keyed
            })
            .is_err(),
            "a value the wire cannot carry is an error, never forwarded bare"
        );
    }

    /// A token source that counts its fetches per audience. Each fetch gives way once, so
    /// requests that arrive together do overlap; a fetch for `held` waits inside the source
    /// until `release`, having said so on `entered`.
    struct Fetches {
        by_audience: Mutex<HashMap<String, usize>>,
        /// How long a token it hands out is good for.
        ttl: SignedDuration,
        /// How many fetches fail before one answers.
        failures: AtomicUsize,
        held: Option<&'static str>,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    impl Fetches {
        fn new() -> Self {
            Self {
                by_audience: Mutex::new(HashMap::new()),
                ttl: SignedDuration::from_mins(10),
                failures: AtomicUsize::new(0),
                held: None,
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
            }
        }

        fn fetched(&self, audience: &str) -> usize {
            self.by_audience
                .lock()
                .unwrap()
                .get(audience)
                .copied()
                .unwrap_or(0)
        }
    }

    #[async_trait::async_trait]
    impl TokenSource for Fetches {
        async fn token(&self, audience: &str) -> anyhow::Result<TokenResponse> {
            *self
                .by_audience
                .lock()
                .unwrap()
                .entry(audience.to_owned())
                .or_default() += 1;
            if self.held == Some(audience) {
                self.entered.notify_one();
                self.release.notified().await;
            } else {
                tokio::task::yield_now().await;
            }
            // One test task drives the source: load then subtract cannot race.
            if self.failures.load(Ordering::SeqCst) > 0 {
                self.failures.fetch_sub(1, Ordering::SeqCst);
                anyhow::bail!("the broker is away");
            }
            Ok(TokenResponse {
                access_token: format!("token-for-{audience}"),
                token_type: "Bearer".into(),
                expires_at: Timestamp::now() + self.ttl,
                audience: audience.into(),
                subject: mediatore_proto::Subject {
                    issuer: "https://idp.example".into(),
                    id: "octocat".into(),
                    display: None,
                },
                header: None,
                extra_headers: vec![],
            })
        }
    }

    #[tokio::test]
    async fn requests_arriving_together_for_one_audience_fetch_its_token_once() {
        // The claim's rate limit: single flight per audience.
        let cache = TokenCache::default();
        let src = Fetches::new();
        let (a, b, c, d) = tokio::join!(
            cache.placement(&src, "github"),
            cache.placement(&src, "github"),
            cache.placement(&src, "github"),
            cache.placement(&src, "github"),
        );
        for placed in [a, b, c, d] {
            assert!(
                placed.is_ok_and(|p| p.value.as_bytes() == b"Bearer token-for-github"),
                "every request is given the one token"
            );
        }
        assert_eq!(src.fetched("github"), 1, "four requests, one fetch");
        assert!(cache.placement(&src, "github").await.is_ok());
        assert_eq!(
            src.fetched("github"),
            1,
            "and it is served again while fresh"
        );
    }

    #[tokio::test]
    async fn a_fresh_token_is_served_while_another_audiences_fetch_is_still_out() {
        let cache = TokenCache::default();
        let src = Fetches {
            held: Some("slow"),
            ..Fetches::new()
        };
        assert!(cache.placement(&src, "fresh").await.is_ok());
        assert_eq!(src.fetched("fresh"), 1);

        // The fetch for `slow` is driven until it is inside the source, and left there.
        let slow = cache.placement(&src, "slow");
        tokio::pin!(slow);
        tokio::select! {
            biased;
            _ = &mut slow => panic!("the held fetch must not finish before it is released"),
            () = src.entered.notified() => {}
        }

        // One poll is all a fresh token needs: nothing it waits for is held by the other audience.
        let served = tokio::select! {
            biased;
            placed = cache.placement(&src, "fresh") => placed,
            () = std::future::ready(()) => {
                panic!("a fresh token waited behind another audience's fetch")
            }
        };
        assert!(
            served.is_ok_and(|p| p.value.as_bytes() == b"Bearer token-for-fresh"),
            "the cached token is the one served"
        );
        assert_eq!(src.fetched("fresh"), 1, "and it was not fetched again");

        src.release.notify_one();
        assert!(slow.await.is_ok(), "the held fetch ends once released");
        assert_eq!(src.fetched("slow"), 1);
    }

    #[tokio::test]
    async fn a_failed_fetch_caches_nothing_and_fails_the_request() {
        let cache = TokenCache::default();
        let src = Fetches {
            failures: AtomicUsize::new(1),
            ..Fetches::new()
        };
        assert!(
            cache.placement(&src, "github").await.is_err(),
            "no token, no placement: the request fails closed"
        );
        assert!(
            cache.placement(&src, "github").await.is_ok(),
            "the next request asks again"
        );
        assert_eq!(src.fetched("github"), 2, "the failure was not cached");
        assert!(cache.placement(&src, "github").await.is_ok());
        assert_eq!(src.fetched("github"), 2);
    }

    #[tokio::test]
    async fn a_token_inside_the_refresh_margin_is_fetched_again() {
        let cache = TokenCache::default();
        let src = Fetches {
            ttl: SignedDuration::from_secs(REFRESH_MARGIN_SECS - 1),
            ..Fetches::new()
        };
        assert!(cache.placement(&src, "github").await.is_ok());
        assert!(cache.placement(&src, "github").await.is_ok());
        assert_eq!(
            src.fetched("github"),
            2,
            "a token about to expire is not served from the cache"
        );
    }

    #[test]
    fn a_route_without_a_credential_may_carry_a_ca_of_its_own() {
        // A `via: none` audience on a private PKI: its CA is trusted for its endpoint alone,
        // keyed by the endpoint since the route may name no audience.
        let private = Route {
            audience: None,
            credential: Credential::None,
            ca_pem: Some(mediatore_testkit::fixture_ca_pem()),
            ..route("-", "repo.home.example:443", &[])
        };
        let public = Route {
            credential: Credential::None,
            ..route("public", "api.example.com:443", &[])
        };
        let proxy = Proxy::with_webpki_roots(
            Routes::new(vec![private.clone(), public.clone()]).unwrap(),
            phantom(),
            Arc::new(NoTokens),
            Dialer::Direct,
        )
        .unwrap();
        assert!(!Arc::ptr_eq(&proxy.tls_for(&private), &proxy.tls));
        assert!(Arc::ptr_eq(&proxy.tls_for(&public), &proxy.tls));
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
    fn a_path_that_is_not_canonical_is_400_on_every_route_whatever_its_rules_admit() {
        let wide = |credential: Credential| Route {
            credential,
            inject_port: (credential == Credential::Gateway).then_some(8444),
            ..route("wide", "host.home.example:443", &[("*", "/**")])
        };
        let p = phantom();
        for credential in [Credential::Token, Credential::None, Credential::Gateway] {
            let r = Routes::new(vec![
                wide(credential),
                route(
                    "narrow",
                    "narrow.home.example:443",
                    &[("GET", "/allowed/**")],
                ),
                route("open", "open.home.example:443", &[]),
            ])
            .unwrap();
            for path in [
                "/host.home.example/allowed/../other",
                "/host.home.example/allowed/%2e%2e/other",
                "/host.home.example/allowed/%2E%2e/other",
                "/host.home.example/allowed/./other",
                "/host.home.example/a%2fb",
                "/host.home.example/a%2Fb",
                "/host.home.example/a%5cb",
                "/host.home.example/a\\b",
                "/host.home.example/a//b",
                "/host.home.example//a",
                "/host.home.example/a%zz",
                "/host.home.example/allowed/../other?x=1",
                "/narrow.home.example/allowed/../../user/emails",
                "/narrow.home.example/allowed/%2e%2e/%2e%2e/user/emails",
                "/open.home.example/a/../b",
            ] {
                assert_eq!(
                    judge(&r, &p, &Method::GET, path, None).unwrap_err(),
                    Refusal::new(StatusCode::BAD_REQUEST, "bad_request"),
                    "{path:?} on a {credential:?} route"
                );
            }
            // The same rule admits the canonical spellings.
            for path in [
                "/host.home.example/allowed/other",
                "/host.home.example/allowed/other/",
                "/host.home.example/a%20b/c%2Bd",
                "/host.home.example",
                "/host.home.example/",
            ] {
                assert!(
                    judge(&r, &p, &Method::GET, path, None).is_ok(),
                    "{path:?} on a {credential:?} route"
                );
            }
        }
    }

    #[test]
    fn the_canonical_path_check_does_not_read_the_query() {
        let r = Routes::new(vec![route(
            "wide",
            "host.home.example:443",
            &[("*", "/**")],
        )])
        .unwrap();
        let p = phantom();
        for path_and_query in [
            "/host.home.example/allowed?next=../other",
            "/host.home.example/allowed?next=%2e%2e%2fother&x=a\\b",
            "/host.home.example/allowed/?a=//b&c=%zz",
            "/host.home.example?next=/../x",
        ] {
            let f = judge(&r, &p, &Method::GET, path_and_query, None)
                .unwrap_or_else(|e| panic!("{path_and_query:?} refused: {}", e.code));
            assert!(
                path_and_query.ends_with(f.path_and_query.trim_start_matches('/')),
                "the query goes upstream as it came: {path_and_query:?}"
            );
        }
    }

    #[test]
    fn trace_and_connect_are_405_on_every_route_before_anything_else_is_read() {
        let r = routes();
        let p = phantom();
        for method in [Method::TRACE, Method::CONNECT] {
            for path in [
                // a route without rules, which admits every other method
                "/192.0.2.10/anything",
                // a route with rules
                "/git.home.example/platform/x",
                // no route at all, and not even a path
                "/evil.example/x",
                "x",
            ] {
                assert_eq!(
                    judge(&r, &p, &method, path, None).unwrap_err(),
                    Refusal::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
                    "{method} {path:?}"
                );
            }
        }
        let wide = Routes::new(vec![route(
            "wide",
            "host.home.example:443",
            &[("*", "/**")],
        )])
        .unwrap();
        let with_phantom = format!("Bearer {}", p.expose());
        assert_eq!(
            judge(
                &wide,
                &p,
                &Method::TRACE,
                "/host.home.example/x",
                Some(with_phantom.as_bytes())
            )
            .unwrap_err()
            .status,
            StatusCode::METHOD_NOT_ALLOWED,
            "a rule naming every method does not name TRACE"
        );
        assert!(judge(&wide, &p, &Method::OPTIONS, "/host.home.example/x", None).is_ok());
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
            gateways: "/mnt/sandbox/egress/gateways.json".into(),
            phantom: "/mnt/sandbox/egress/phantom".into(),
        };
        let a = command_args(
            SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT)),
            "https://mediatore.test:8443",
            "/run/spire/sockets/agent.sock",
            &files,
            &UpstreamArgs::default(),
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
                "--gateways",
                "/mnt/sandbox/egress/gateways.json",
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
            &["198.51.100.7:8443".parse().unwrap()],
            &p,
            me.uid(),
            me.gid(),
        )
        .unwrap();
        for f in [&files.routes, &files.gateways, &files.phantom] {
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
        let gateways: Vec<Endpoint> =
            serde_json::from_slice(&std::fs::read(&files.gateways).unwrap()).unwrap();
        assert_eq!(gateways, ["198.51.100.7:8443".parse().unwrap()]);
    }

    // ----- gateway-placed routes (ADR-0040 decision 7) ---------------------------------------------------------------
    //
    // The proxy under test is the real one on a loopback port, driven the way the jailed workload drives it; the
    // gateway is a fake inject listener on the production sandbox-leg TLS configuration (mutual TLS 1.3, claim
    // identities only) that records what it received and answers from a script.

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use mediatore_testkit::{MemoryMaterial, TestCa};
    use mediatore_tls::{Authorizer, SpiffeId, TlsConfigs};
    use tokio::sync::mpsc;

    const TD: &str = "sandbox.test";
    const CLAIM_ID: &str =
        "spiffe://sandbox.test/banlieue/claim/00000000-0000-0000-0000-000000000042";
    const GATEWAY_ID: &str = "spiffe://sandbox.test/gateway";
    const UPSTREAM: &str = "api.anthropic.example:443";

    fn gw(s: &str) -> Endpoint {
        s.parse().unwrap()
    }

    /// What the fake gateway saw of one request.
    #[derive(Debug, Clone)]
    struct Seen {
        peer: String,
        method: String,
        target: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Seen {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    /// How the fake gateway answers.
    enum Script {
        /// `200` with the request's own body back.
        Echo,
        /// A fixed answer.
        Fixed {
            status: u16,
            headers: Vec<(&'static str, &'static str)>,
            body: &'static str,
        },
        /// `200 text/event-stream`, the body being what the test sends on the channel.
        Stream(Mutex<Option<mpsc::Receiver<Bytes>>>),
    }

    struct ChannelBody(mpsc::Receiver<Bytes>);

    impl hyper::body::Body for ChannelBody {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, std::convert::Infallible>>>
        {
            self.0
                .poll_recv(cx)
                .map(|o| o.map(|b| Ok(hyper::body::Frame::data(b))))
        }
    }

    type FakeBody = BoxBody<Bytes, std::convert::Infallible>;

    fn answer(script: &Script, echo: Bytes) -> Response<FakeBody> {
        match script {
            Script::Echo => Response::new(Full::new(echo).boxed()),
            Script::Fixed {
                status,
                headers,
                body,
            } => {
                let mut b = Response::builder().status(*status);
                for (k, v) in headers {
                    b = b.header(*k, *v);
                }
                b.body(Full::new(Bytes::from_static(body.as_bytes())).boxed())
                    .unwrap()
            }
            Script::Stream(rx) => {
                let rx = rx.lock().unwrap().take().expect("one stream per fake");
                Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(ChannelBody(rx).boxed())
                    .unwrap()
            }
        }
    }

    struct FakeGateway {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<Seen>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for FakeGateway {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl FakeGateway {
        async fn start(ca: &TestCa, script: Script) -> Self {
            mediatore_proto::tls::ensure_provider();
            let material = ca.svid(GATEWAY_ID);
            let authorizer: Authorizer = Arc::new(|peer: &SpiffeId| {
                peer.to_string()
                    .starts_with("spiffe://sandbox.test/banlieue/claim/")
            });
            let config = TlsConfigs::build(&material, &authorizer).expect("gateway config");
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
            let script = Arc::new(script);
            let recorder = seen.clone();
            let task = tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        return;
                    };
                    let (acceptor, script, seen) =
                        (acceptor.clone(), script.clone(), recorder.clone());
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let peer = tls
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|c| c.first())
                            .and_then(|leaf| mediatore_tls::leaf_spiffe_id(leaf).ok())
                            .map(|id| id.to_string())
                            .unwrap_or_default();
                        let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                            let (script, seen, peer) = (script.clone(), seen.clone(), peer.clone());
                            async move {
                                let (parts, body) = req.into_parts();
                                let body = body
                                    .collect()
                                    .await
                                    .map(http_body_util::Collected::to_bytes)
                                    .unwrap_or_default();
                                seen.lock().unwrap().push(Seen {
                                    peer,
                                    method: parts.method.to_string(),
                                    target: parts.uri.to_string(),
                                    headers: parts
                                        .headers
                                        .iter()
                                        .map(|(k, v)| {
                                            (
                                                k.to_string(),
                                                String::from_utf8_lossy(v.as_bytes()).into_owned(),
                                            )
                                        })
                                        .collect(),
                                    body: body.to_vec(),
                                });
                                Ok::<_, std::convert::Infallible>(answer(&script, body))
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(tls), service)
                            .await;
                    });
                }
            });
            Self { addr, seen, task }
        }

        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }

    /// A token source that must never be asked: it counts the asks and refuses them.
    struct CountingTokens(AtomicUsize);

    #[async_trait::async_trait]
    impl TokenSource for CountingTokens {
        async fn token(&self, _audience: &str) -> anyhow::Result<TokenResponse> {
            self.0.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("a gateway-placed route never asks for a token")
        }
    }

    fn placed(endpoint: &str, inject_port: Option<u16>, rules: &[(&str, &str)]) -> Route {
        Route {
            credential: Credential::Gateway,
            inject_port,
            ..route("anthropic", endpoint, rules)
        }
    }

    struct Harness {
        base: String,
        phantom: Phantom,
        tokens: Arc<CountingTokens>,
        _task: tokio::task::JoinHandle<()>,
    }

    async fn harness(ca: &TestCa, routes: Vec<Route>, gateways: Vec<Endpoint>) -> Harness {
        let material = MemoryMaterial::new(ca.svid(CLAIM_ID));
        let forwarder = Forwarder::new(gateways, material).unwrap();
        let phantom = Phantom::generate().unwrap();
        let tokens = Arc::new(CountingTokens(AtomicUsize::new(0)));
        let proxy = Proxy::with_webpki_roots(
            Routes::new(routes).unwrap(),
            phantom.clone(),
            tokens.clone(),
            Dialer::Gateways(forwarder),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let _ = Arc::new(proxy).serve(listener).await;
        });
        Harness {
            base,
            phantom,
            tokens,
            _task: task,
        }
    }

    /// The proxy with a second, pull-only listener for `host` (ADR-0043 decision 3); returns the harness and the pull URL.
    async fn harness_with_pull(
        ca: &TestCa,
        routes: Vec<Route>,
        gateways: Vec<Endpoint>,
        host: &str,
    ) -> (Harness, String) {
        let material = MemoryMaterial::new(ca.svid(CLAIM_ID));
        let forwarder = Forwarder::new(gateways, material).unwrap();
        let phantom = Phantom::generate().unwrap();
        let tokens = Arc::new(CountingTokens(AtomicUsize::new(0)));
        let proxy = Arc::new(
            Proxy::with_webpki_roots(
                Routes::new(routes).unwrap(),
                phantom.clone(),
                tokens.clone(),
                Dialer::Gateways(forwarder),
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pull = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let pull_base = format!("http://{}", pull.local_addr().unwrap());
        let host = host.to_owned();
        let task = tokio::spawn(async move {
            let _ = tokio::join!(proxy.clone().serve(listener), proxy.serve_pull(pull, host));
        });
        (
            Harness {
                base,
                phantom,
                tokens,
                _task: task,
            },
            pull_base,
        )
    }

    /// The jailed workload: plain HTTP to the loopback proxy, never through an ambient proxy.
    fn workload() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    #[tokio::test]
    async fn a_gateway_placed_route_goes_to_the_inject_port_in_origin_form_with_no_credential() {
        let ca = TestCa::new(TD);
        let fake = FakeGateway::start(&ca, Script::Echo).await;
        let h = harness(
            &ca,
            vec![placed(
                UPSTREAM,
                Some(fake.addr.port()),
                &[("POST", "/v1/messages")],
            )],
            vec![gw("127.0.0.1:1")],
        )
        .await;
        let body =
            serde_json::json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]})
                .to_string();
        let resp = workload()
            .post(format!("{}/{UPSTREAM}/v1/messages?beta=1", h.base))
            .bearer_auth(h.phantom.expose())
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.text().await.unwrap(),
            body,
            "the response comes back unchanged"
        );
        let seen = fake.seen();
        assert_eq!(seen.len(), 1, "one request, to the inject port");
        let s = &seen[0];
        assert_eq!(s.peer, CLAIM_ID, "as the claim, over mutual TLS");
        assert_eq!(
            (s.method.as_str(), s.target.as_str()),
            ("POST", "/v1/messages?beta=1"),
            "origin form, not a CONNECT and not an absolute URI"
        );
        assert_eq!(
            s.header("host"),
            Some("api.anthropic.example"),
            "Host without a port"
        );
        assert_eq!(s.body, body.as_bytes(), "the body crossed intact");
        for (k, v) in &s.headers {
            assert!(!v.contains(h.phantom.expose()), "{k} carries the phantom");
        }
        for name in ["authorization", "x-api-key", "proxy-authorization"] {
            assert!(s.header(name).is_none(), "{name} must not leave the guest");
        }
        assert_eq!(
            h.tokens.0.load(Ordering::SeqCst),
            0,
            "POST /v1/token is never called for a gateway-placed route"
        );
    }

    #[tokio::test]
    async fn the_pull_listener_serves_its_registry_host_only_and_only_as_a_placed_route() {
        // ADR-0043 decision 3: root's puller reaches the registry through this proxy on a port the jail never lists. It
        // sends no credential; the request goes to the gateway as a placed route; any other host is refused there.
        let ca = TestCa::new(TD);
        let fake = FakeGateway::start(&ca, Script::Echo).await;
        let routes = vec![
            placed(
                "registry.home.example:443",
                Some(fake.addr.port()),
                &[("GET", "/v2/**")],
            ),
            placed(
                UPSTREAM,
                Some(fake.addr.port()),
                &[("POST", "/v1/messages")],
            ),
        ];
        let (h, pull) = harness_with_pull(
            &ca,
            routes,
            vec![gw("127.0.0.1:1")],
            "registry.home.example",
        )
        .await;
        let ok = workload()
            .get(format!(
                "{pull}/registry.home.example/v2/team/tool/manifests/v1"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), 200);
        let seen = fake.seen();
        assert_eq!(seen.len(), 1, "one request, to the inject port");
        assert_eq!(seen[0].peer, CLAIM_ID, "as the claim");
        assert_eq!(seen[0].target, "/v2/team/tool/manifests/v1", "origin form");
        assert_eq!(seen[0].header("host"), Some("registry.home.example"));
        assert!(
            seen[0].header("authorization").is_none(),
            "no credential leaves the guest"
        );
        // Another host, though it is a placed route of the claim, is not served on the pull port.
        let other = workload()
            .post(format!("{pull}/{UPSTREAM}/v1/messages"))
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(other.status(), 404);
        assert_eq!(fake.seen().len(), 1, "nothing more reached the gateway");
        assert_eq!(h.tokens.0.load(Ordering::SeqCst), 0, "no token was asked");
    }

    #[tokio::test]
    async fn the_pull_listener_refuses_a_route_that_is_neither_a_registrys_nor_placed() {
        // An API route (a misconfiguration, or the image named on an API's host) must not be served from here: the pull
        // listener serves a registry audience's route or a placed one (ADR-0063 decision 3), and asks for no token else.
        let ca = TestCa::new(TD);
        let fake = FakeGateway::start(&ca, Script::Echo).await;
        let routes = vec![route("api", "registry.home.example:443", &[])];
        let (h, pull) = harness_with_pull(
            &ca,
            routes,
            vec![gw(&format!("127.0.0.1:{}", fake.addr.port()))],
            "registry.home.example",
        )
        .await;
        let resp = workload()
            .get(format!("{pull}/registry.home.example/v2/"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        assert!(fake.seen().is_empty());
        assert_eq!(h.tokens.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_workload_is_refused_a_pull_only_route_and_the_puller_is_served_it() {
        // ADR-0063 decision 5: the registry audience's route is the puller's. The jail asking for it, with the phantom,
        // is 404 pull_only and nothing leaves; the pull listener serves the same route.
        let ca = TestCa::new(TD);
        let fake = FakeGateway::start(&ca, Script::Echo).await;
        let registry = Route {
            pull_only: true,
            ..placed(
                "registry.home.example:443",
                Some(fake.addr.port()),
                &[("GET", "/v2/**")],
            )
        };
        let (h, pull) = harness_with_pull(
            &ca,
            vec![registry],
            vec![gw("127.0.0.1:1")],
            "registry.home.example",
        )
        .await;
        let jail = workload()
            .get(format!(
                "{}/registry.home.example/v2/team/tool/manifests/v1",
                h.base
            ))
            .bearer_auth(h.phantom.expose())
            .send()
            .await
            .unwrap();
        assert_eq!(jail.status(), 404);
        assert!(
            jail.text().await.unwrap().contains("pull_only"),
            "the refusal names why"
        );
        assert!(
            fake.seen().is_empty(),
            "nothing left for the jail's request"
        );
        let puller = workload()
            .get(format!(
                "{pull}/registry.home.example/v2/team/tool/manifests/v1"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(puller.status(), 200);
        assert_eq!(
            fake.seen().len(),
            1,
            "the puller's request went to the gateway"
        );
    }

    #[test]
    fn a_registry_is_pulled_through_the_proxy_when_a_pull_only_or_placed_route_names_it() {
        // ADR-0043: the guest pulls through the proxy when the image's registry is a gateway-placed route of the claim, by
        // the name an image reference carries (the host, with the port only when it is not 443).
        let routes = vec![
            placed(
                "registry.home.example:443",
                Some(3133),
                &[("GET", "/v2/**")],
            ),
            placed("odd.home.example:5443", Some(3133), &[]),
            route("direct", "plain.example:443", &[]),
            Route {
                pull_only: true,
                ..route("mirror", "mirror.home.example:443", &[("GET", "/v2/**")])
            },
        ];
        assert_eq!(
            pull_registry(&routes, "mirror.home.example").as_deref(),
            Some("mirror.home.example"),
            "a registry audience's tunnelled route (ADR-0063)"
        );
        assert_eq!(
            pull_registry(&routes, "registry.home.example").as_deref(),
            Some("registry.home.example"),
            "443 is the bare host"
        );
        assert_eq!(
            pull_registry(&routes, "odd.home.example:5443").as_deref(),
            Some("odd.home.example:5443"),
            "another port is part of the name"
        );
        assert_eq!(
            pull_registry(&routes, "plain.example"),
            None,
            "an API route is no registry's"
        );
        assert_eq!(pull_registry(&routes, "other.example"), None);
    }

    #[test]
    fn the_pull_listener_is_on_the_command_line_only_for_a_placed_registry() {
        let listen = SocketAddr::from(([127, 0, 0, 1], 18129));
        assert_eq!(
            pull_args(listen, "registry.home.example"),
            [
                "--pull-listen",
                "127.0.0.1:18129",
                "--pull-host",
                "registry.home.example"
            ]
        );
    }

    #[tokio::test]
    async fn an_upstream_on_another_port_keeps_it_in_host_because_a_rule_names_that_authority() {
        let ca = TestCa::new(TD);
        let fake = FakeGateway::start(&ca, Script::Echo).await;
        let h = harness(
            &ca,
            vec![placed(
                "api.anthropic.example:8443",
                Some(fake.addr.port()),
                &[("GET", "/v1/**")],
            )],
            vec![gw("127.0.0.1:1")],
        )
        .await;
        let resp = workload()
            .get(format!("{}/api.anthropic.example:8443/v1/models", h.base))
            .bearer_auth(h.phantom.expose())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            fake.seen()[0].header("host"),
            Some("api.anthropic.example:8443"),
            "an absent port means 443 at the gateway, so any other port is explicit"
        );
    }

    #[tokio::test]
    async fn a_request_outside_the_rules_or_with_a_foreign_credential_never_leaves_the_guest() {
        let ca = TestCa::new(TD);
        let fake = FakeGateway::start(&ca, Script::Echo).await;
        let h = harness(
            &ca,
            vec![placed(
                UPSTREAM,
                Some(fake.addr.port()),
                &[("POST", "/v1/messages")],
            )],
            vec![gw("127.0.0.1:1")],
        )
        .await;
        let url = |p: &str| format!("{}/{UPSTREAM}{p}", h.base);
        let c = workload();
        let wrong_method = c
            .get(url("/v1/messages"))
            .bearer_auth(h.phantom.expose())
            .send()
            .await
            .unwrap();
        assert_eq!(wrong_method.status(), 403, "a method no rule names");
        let wrong_path = c
            .post(url("/v1/organizations"))
            .bearer_auth(h.phantom.expose())
            .send()
            .await
            .unwrap();
        assert_eq!(wrong_path.status(), 403, "a path no rule names");
        let foreign = c
            .post(url("/v1/messages"))
            .bearer_auth("not-the-phantom")
            .send()
            .await
            .unwrap();
        assert_eq!(
            foreign.status(),
            401,
            "the workload has no credential of its own to send"
        );
        assert!(
            fake.seen().is_empty(),
            "none of the three reached the gateway"
        );
        assert_eq!(h.tokens.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_api_key_header_is_never_sent_to_the_gateway_even_where_no_route_owns_it() {
        // The authorizer strips client credential headers too; the guest does not rely on that.
        // Since `CREDENTIAL_HEADERS` the request is refused here, not sent without the header.
        let ca = TestCa::new(TD);
        let fake = FakeGateway::start(&ca, Script::Echo).await;
        let h = harness(
            &ca,
            vec![placed(
                UPSTREAM,
                Some(fake.addr.port()),
                &[("POST", "/v1/messages")],
            )],
            vec![gw("127.0.0.1:1")],
        )
        .await;
        let resp = workload()
            .post(format!("{}/{UPSTREAM}/v1/messages", h.base))
            .bearer_auth(h.phantom.expose())
            .header("x-api-key", "the-workloads-own")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            401,
            "refused beside the phantom, not stripped"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "unknown_credential");
        assert!(
            fake.seen().is_empty(),
            "nothing reached the gateway, so the header and its value did not either"
        );
        assert_eq!(h.tokens.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_header_the_workload_names_in_connection_is_not_sent_to_the_gateway() {
        let ca = TestCa::new(TD);
        let fake = FakeGateway::start(&ca, Script::Echo).await;
        let h = harness(
            &ca,
            vec![placed(
                UPSTREAM,
                Some(fake.addr.port()),
                &[("POST", "/v1/messages")],
            )],
            vec![gw("127.0.0.1:1")],
        )
        .await;
        let resp = workload()
            .post(format!("{}/{UPSTREAM}/v1/messages", h.base))
            .bearer_auth(h.phantom.expose())
            .header("connection", "close, x-foo")
            .header("x-foo", "one-hop")
            .header("x-request-id", "r-1")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let seen = fake.seen();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].header("x-foo").is_none(),
            "a header the request's Connection names stays on the workload's hop"
        );
        assert_eq!(
            seen[0].header("x-request-id"),
            Some("r-1"),
            "a header it does not name crosses"
        );
        assert!(
            seen[0].header("connection").is_none(),
            "the workload's Connection is not the gateway's"
        );
    }

    /// One route of each kind (a token, no credential, placed at the gateway), every rule
    /// open, and a path on each.
    fn one_route_of_each_kind() -> (Routes, [&'static str; 3]) {
        let routes = Routes::new(vec![
            route("internal-git", "git.home.example:443", &[]),
            Route {
                audience: None,
                credential: Credential::None,
                ..route("-", "repo.home.example:443", &[])
            },
            placed(UPSTREAM, Some(3133), &[]),
        ])
        .unwrap();
        (
            routes,
            [
                "/git.home.example/x",
                "/repo.home.example/x",
                "/api.anthropic.example/x",
            ],
        )
    }

    #[test]
    fn a_credential_header_no_route_owns_is_refused_on_every_kind_of_route() {
        let (routes, targets) = one_route_of_each_kind();
        let p = phantom();
        let bearer = HeaderValue::from_str(&format!("Bearer {}", p.expose())).unwrap();
        for denied in CREDENTIAL_HEADERS {
            for path in targets {
                // Alone, and beside the phantom: the phantom does not vouch for it.
                let mut alone = http::HeaderMap::new();
                alone.insert(denied.clone(), HeaderValue::from_static("not-the-phantom"));
                let mut beside = alone.clone();
                beside.insert(header::AUTHORIZATION, bearer.clone());
                // The phantom itself there is not a credential of the workload's own: it is
                // let through, and `rewrite` drops the header.
                let mut as_phantom = http::HeaderMap::new();
                as_phantom.insert(denied.clone(), HeaderValue::from_str(p.expose()).unwrap());
                let let_through =
                    judge_headers(&routes, &p, &Method::GET, path, &as_phantom).is_ok();
                assert!(let_through, "the phantom in {denied} on {path}");
                for headers in [&alone, &beside] {
                    assert_eq!(
                        judge_headers(&routes, &p, &Method::GET, path, headers).unwrap_err(),
                        Refusal::new(StatusCode::UNAUTHORIZED, "unknown_credential"),
                        "{denied} on {path}"
                    );
                }
            }
        }
        // The headers the item was written for are all on the list.
        for name in [
            "cookie",
            "x-api-key",
            "private-token",
            "x-auth-token",
            "x-goog-api-key",
            "proxy-authorization",
        ] {
            assert!(
                CREDENTIAL_HEADERS.iter().any(|h| h.as_str() == name),
                "{name} is on the deny-list"
            );
        }
        // The rules are read first, as for a foreign bearer: outside them is 403.
        let ruled = Routes::new(vec![route(
            "internal-git",
            "git.home.example:443",
            &[("GET", "/platform/**")],
        )])
        .unwrap();
        let mut cookie = http::HeaderMap::new();
        cookie.insert(header::COOKIE, HeaderValue::from_static("session=x"));
        assert_eq!(
            judge_headers(&ruled, &p, &Method::GET, "/git.home.example/other", &cookie)
                .unwrap_err(),
            Refusal::new(StatusCode::FORBIDDEN, "outside_rules")
        );
    }

    #[test]
    fn credential_header_names_are_matched_whatever_their_case() {
        // `HeaderName` holds every parsed name in lower case, which is how hyper hands the
        // request's headers over: `PRIVATE-TOKEN` on the wire is `private-token` here.
        let (routes, targets) = one_route_of_each_kind();
        let p = phantom();
        for sent in ["PRIVATE-TOKEN", "Cookie", "X-Api-Key", "X-Goog-Api-Key"] {
            let name = HeaderName::from_bytes(sent.as_bytes()).unwrap();
            assert_eq!(name.as_str(), sent.to_ascii_lowercase());
            let mut headers = http::HeaderMap::new();
            headers.insert(name, HeaderValue::from_static("not-the-phantom"));
            for path in targets {
                assert_eq!(
                    judge_headers(&routes, &p, &Method::GET, path, &headers)
                        .unwrap_err()
                        .status,
                    StatusCode::UNAUTHORIZED,
                    "{sent} on {path}"
                );
            }
        }
        for listed in CREDENTIAL_HEADERS {
            assert_eq!(
                listed.as_str(),
                listed.as_str().to_ascii_lowercase(),
                "the list is lower-case"
            );
        }
    }

    #[test]
    fn a_route_that_owns_a_listed_header_takes_the_phantom_there_and_refuses_anything_else() {
        let key = HeaderName::from_static("x-api-key");
        let p = phantom();
        // Owned by a token route (ADR-0032) and, in a second set, by a gateway-placed one.
        let keyed = Routes::new(vec![
            Route {
                credential_header: Some("x-api-key".into()),
                ..route("keyed", "keyed.example.com:443", &[])
            },
            route("internal-git", "git.home.example:443", &[]),
        ])
        .unwrap();
        let at_gateway = Routes::new(vec![Route {
            credential_header: Some("x-api-key".into()),
            ..placed(UPSTREAM, Some(3133), &[])
        }])
        .unwrap();
        let mut with_phantom = http::HeaderMap::new();
        with_phantom.insert(key.clone(), HeaderValue::from_str(p.expose()).unwrap());
        let mut with_another = http::HeaderMap::new();
        with_another.insert(key, HeaderValue::from_static("not-the-phantom"));
        // The phantom there, and a listed header no route owns beside it.
        let mut with_cookie = with_phantom.clone();
        with_cookie.insert(header::COOKIE, HeaderValue::from_static("session=x"));

        let f = judge_headers(
            &keyed,
            &p,
            &Method::POST,
            "/keyed.example.com/v1/x",
            &with_phantom,
        )
        .unwrap();
        assert!(f.inject, "the phantom where the route's credential goes");
        let g = judge_headers(
            &at_gateway,
            &p,
            &Method::POST,
            "/api.anthropic.example/v1/x",
            &with_phantom,
        )
        .unwrap();
        assert!(
            g.route.placed_at_gateway() && !g.inject,
            "accepted on a gateway-placed route that owns the header; the gateway places"
        );
        for (set, path) in [
            (&keyed, "/keyed.example.com/v1/x"),
            (&keyed, "/git.home.example/x"),
            (&at_gateway, "/api.anthropic.example/v1/x"),
        ] {
            for headers in [&with_another, &with_cookie] {
                assert_eq!(
                    judge_headers(set, &p, &Method::POST, path, headers).unwrap_err(),
                    Refusal::new(StatusCode::UNAUTHORIZED, "unknown_credential"),
                    "{path}"
                );
            }
        }
    }

    #[test]
    fn ordinary_headers_pass_on_every_kind_of_route() {
        let (routes, targets) = one_route_of_each_kind();
        let p = phantom();
        let mut headers = http::HeaderMap::new();
        for (name, value) in [
            ("accept", "application/json"),
            ("content-type", "application/json"),
            ("user-agent", "agent/1"),
            ("x-request-id", "r-1"),
        ] {
            headers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        for path in targets {
            assert!(
                judge_headers(&routes, &p, &Method::GET, path, &headers).is_ok(),
                "{path}: bare"
            );
        }
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", p.expose())).unwrap(),
        );
        for path in targets {
            assert!(
                judge_headers(&routes, &p, &Method::GET, path, &headers).is_ok(),
                "{path}: with the phantom"
            );
        }
    }

    #[test]
    fn headers_named_in_connection_are_dropped_with_the_fixed_hop_by_hop_list() {
        let kept = |h: &http::HeaderMap| -> Vec<String> {
            let mut sorted: Vec<String> = h.keys().map(ToString::to_string).collect();
            sorted.sort();
            sorted
        };
        let build = |pairs: &[(&'static str, &'static str)]| -> http::HeaderMap {
            let mut h = http::HeaderMap::new();
            for (name, value) in pairs {
                h.append(
                    HeaderName::from_static(name),
                    HeaderValue::from_static(value),
                );
            }
            h
        };
        // A named header goes, in whatever case and spacing the option was written, from
        // every `Connection` line; one it does not name stays.
        let mut marked = build(&[
            ("connection", "close, X-Foo"),
            ("connection", " x-bar ,, "),
            ("x-foo", "1"),
            ("x-bar", "2"),
            ("x-request-id", "r-1"),
            ("accept", "*/*"),
        ]);
        strip_hop_by_hop(&mut marked);
        assert_eq!(kept(&marked), ["accept", "x-request-id"]);
        // `keep-alive` and `close` are as before: `Connection` and `Keep-Alive` go, the
        // rest of the fixed list with them, and nothing else does.
        for option in ["keep-alive", "close", "Keep-Alive, close"] {
            let mut plain = build(&[
                ("connection", option),
                ("keep-alive", "timeout=5"),
                ("te", "trailers"),
                ("upgrade", "h2c"),
                ("content-type", "application/json"),
                ("user-agent", "agent/1"),
            ]);
            strip_hop_by_hop(&mut plain);
            assert_eq!(kept(&plain), ["content-type", "user-agent"], "{option}");
        }
        // No `Connection`: the fixed list alone.
        let mut bare = build(&[("te", "trailers"), ("accept", "*/*")]);
        strip_hop_by_hop(&mut bare);
        assert_eq!(kept(&bare), ["accept"]);
        // A value that is not a header name names nothing and breaks nothing.
        let mut odd = build(&[("connection", "not a name, @"), ("accept", "*/*")]);
        strip_hop_by_hop(&mut odd);
        assert_eq!(kept(&odd), ["accept"]);
    }

    #[tokio::test]
    async fn a_streamed_response_is_relayed_as_it_arrives() {
        let ca = TestCa::new(TD);
        let (tx, rx) = mpsc::channel::<Bytes>(4);
        let fake = FakeGateway::start(&ca, Script::Stream(Mutex::new(Some(rx)))).await;
        let h = harness(
            &ca,
            vec![placed(
                UPSTREAM,
                Some(fake.addr.port()),
                &[("POST", "/v1/messages")],
            )],
            vec![gw("127.0.0.1:1")],
        )
        .await;
        tx.send(Bytes::from_static(b"event: one\n\n"))
            .await
            .unwrap();
        let mut resp = workload()
            .post(format!("{}/{UPSTREAM}/v1/messages", h.base))
            .bearer_auth(h.phantom.expose())
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()["content-type"], "text/event-stream");
        // The stream is still open (the sender is alive): this chunk arriving proves the body is
        // relayed as it comes, not buffered to its end.
        let first = tokio::time::timeout(std::time::Duration::from_secs(5), resp.chunk())
            .await
            .expect("the first event arrives while the stream is open")
            .unwrap()
            .unwrap();
        assert_eq!(&first[..], b"event: one\n\n");
        tx.send(Bytes::from_static(b"event: two\n\n"))
            .await
            .unwrap();
        drop(tx);
        let mut tail = Vec::new();
        while let Some(c) = resp.chunk().await.unwrap() {
            tail.extend_from_slice(&c);
        }
        assert_eq!(tail, b"event: two\n\n");
    }

    #[tokio::test]
    async fn a_gateway_that_is_down_is_skipped_and_the_next_carries_the_request() {
        // Same inject port on every gateway, as in production; the hosts differ. Nothing listens on
        // [::1] at that port (the fake is on 127.0.0.1), so that dial is refused at once on any
        // machine, and the next gateway is tried.
        let ca = TestCa::new(TD);
        let fake = FakeGateway::start(&ca, Script::Echo).await;
        let h = harness(
            &ca,
            vec![placed(
                UPSTREAM,
                Some(fake.addr.port()),
                &[("POST", "/v1/messages")],
            )],
            vec![gw("[::1]:1"), gw("127.0.0.1:1")],
        )
        .await;
        for _ in 0..8 {
            let resp = workload()
                .post(format!("{}/{UPSTREAM}/v1/messages", h.base))
                .bearer_auth(h.phantom.expose())
                .body("{}")
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "whichever gateway the walk starts at");
        }
        assert_eq!(fake.seen().len(), 8);
    }

    #[tokio::test]
    async fn no_gateway_reachable_is_502_gateway_unreachable() {
        let ca = TestCa::new(TD);
        let closed = mediatore_testkit::dead_endpoint().await.port;
        let h = harness(
            &ca,
            vec![placed(UPSTREAM, Some(closed), &[("POST", "/v1/messages")])],
            vec![gw("[::1]:1")],
        )
        .await;
        let resp = workload()
            .post(format!("{}/{UPSTREAM}/v1/messages", h.base))
            .bearer_auth(h.phantom.expose())
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 502);
        assert_eq!(
            resp.text().await.unwrap(),
            r#"{"error":"gateway_unreachable"}"#
        );
        assert_eq!(
            h.tokens.0.load(Ordering::SeqCst),
            0,
            "no fallback to fetching a credential"
        );
    }

    #[tokio::test]
    async fn the_gateways_own_refusal_is_502_gateway_refused_and_an_upstreams_answer_is_passed_on()
    {
        let ca = TestCa::new(TD);
        let call = |base: &str, phantom: &Phantom| {
            workload()
                .post(format!("{base}/{UPSTREAM}/v1/messages"))
                .bearer_auth(phantom.expose())
                .body("{}")
                .send()
        };
        // The authorizer's verdict, marked as the gateway's own.
        let refusing = FakeGateway::start(
            &ca,
            Script::Fixed {
                status: 403,
                headers: vec![(GATEWAY_REFUSAL_HEADER, "not_allowed")],
                body: "not_allowed",
            },
        )
        .await;
        let h = harness(
            &ca,
            vec![placed(
                UPSTREAM,
                Some(refusing.addr.port()),
                &[("POST", "/v1/messages")],
            )],
            vec![gw("127.0.0.1:1")],
        )
        .await;
        let resp = call(&h.base, &h.phantom).await.unwrap();
        assert_eq!(resp.status(), 502);
        assert_eq!(resp.text().await.unwrap(), r#"{"error":"gateway_refused"}"#);
        // The upstream's own 403 and 503 are its answers, relayed unchanged.
        for (status, body) in [
            (403u16, r#"{"type":"permission_error"}"#),
            (503, r#"{"type":"overloaded"}"#),
        ] {
            let upstream = FakeGateway::start(
                &ca,
                Script::Fixed {
                    status,
                    headers: vec![("content-type", "application/json")],
                    body: body_static(body),
                },
            )
            .await;
            let h = harness(
                &ca,
                vec![placed(
                    UPSTREAM,
                    Some(upstream.addr.port()),
                    &[("POST", "/v1/messages")],
                )],
                vec![gw("127.0.0.1:1")],
            )
            .await;
            let resp = call(&h.base, &h.phantom).await.unwrap();
            assert_eq!(
                resp.status(),
                status,
                "the upstream's status, not a gateway refusal"
            );
            assert_eq!(resp.text().await.unwrap(), body);
        }
    }

    fn body_static(s: &str) -> &'static str {
        Box::leak(s.to_owned().into_boxed_str())
    }

    #[test]
    fn a_gateway_placed_route_that_cannot_be_sent_anywhere_refuses_the_proxy_at_start() {
        let missing = Routes::new(vec![placed(UPSTREAM, None, &[("POST", "/v1/messages")])])
            .unwrap_err()
            .to_string();
        assert!(
            missing.contains("inject_port")
                && missing.contains(UPSTREAM)
                && missing.contains("ADR-0040"),
            "{missing}"
        );
        let zero = Routes::new(vec![placed(UPSTREAM, Some(0), &[("POST", "/v1/messages")])])
            .unwrap_err()
            .to_string();
        assert!(zero.contains("inject_port"), "{zero}");
        let nameless = Routes::new(vec![Route {
            audience: None,
            ..placed(UPSTREAM, Some(3133), &[("POST", "/v1/messages")])
        }])
        .unwrap_err()
        .to_string();
        assert!(nameless.contains("audience"), "{nameless}");
        assert!(
            Routes::new(vec![placed(
                UPSTREAM,
                Some(3133),
                &[("POST", "/v1/messages")]
            )])
            .is_ok()
        );
    }

    #[test]
    fn a_gateway_placed_route_without_a_gateway_in_the_environment_refuses_the_proxy_at_start() {
        let routes = || {
            Routes::new(vec![placed(
                UPSTREAM,
                Some(3133),
                &[("POST", "/v1/messages")],
            )])
            .unwrap()
        };
        let err = Proxy::with_webpki_roots(routes(), phantom(), Arc::new(NoTokens), Dialer::Direct)
            .err()
            .expect("direct dial and a gateway-placed route")
            .to_string();
        assert!(
            err.contains("gateway") && err.contains(UPSTREAM) && err.contains("ADR-0040"),
            "{err}"
        );
        // A claim with no gateway-placed route is not affected by the dialer.
        assert!(
            Proxy::with_webpki_roots(
                Routes::new(vec![route("a", "a.example:443", &[])]).unwrap(),
                phantom(),
                Arc::new(NoTokens),
                Dialer::Direct
            )
            .is_ok()
        );
    }

    #[test]
    fn token_and_no_credential_routes_are_unchanged_beside_a_gateway_placed_one() {
        let none = Route {
            audience: None,
            credential: Credential::None,
            ..route("x", "bundle.example:443", &[])
        };
        let all = vec![
            route("grafana", "grafana.example:443", &[]),
            none,
            placed(UPSTREAM, Some(3133), &[("POST", "/v1/messages")]),
        ];
        assert_eq!(inject_ports(&all), std::collections::BTreeSet::from([3133]));
        assert!(
            inject_ports(&all[..2]).is_empty(),
            "no gateway-placed route, no inject port"
        );
        let routes = Routes::new(all).unwrap();
        let p = phantom();
        let bearer = format!("Bearer {}", p.expose());
        let token = judge(
            &routes,
            &p,
            &Method::GET,
            "/grafana.example/x",
            Some(bearer.as_bytes()),
        )
        .unwrap();
        assert!(
            token.inject && !token.route.placed_at_gateway(),
            "a token route still gets a token"
        );
        let bare = judge(
            &routes,
            &p,
            &Method::GET,
            "/bundle.example/x",
            Some(bearer.as_bytes()),
        )
        .unwrap();
        assert!(
            !bare.inject && !bare.route.placed_at_gateway(),
            "a route without a credential still gets none"
        );
        let at_gateway = judge(
            &routes,
            &p,
            &Method::POST,
            "/api.anthropic.example/v1/messages",
            Some(bearer.as_bytes()),
        )
        .unwrap();
        assert!(
            at_gateway.route.placed_at_gateway() && !at_gateway.inject,
            "the proxy places no credential here: the gateway does"
        );
    }
}
