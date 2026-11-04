// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The forwarder: how the egress proxy reaches an upstream in an environment with egress
//! gateways (ADR-0028 decisions 3 and 7, ADR-0027 decision 8).
//!
//! ADR-0028 named it `mediatore forward`, the sandbox leg of the gateway: mutual TLS to a
//! gateway with the claim SVID, the gateway verified as exactly `spiffe://<td>/gateway`,
//! `CONNECT host:port` inside, the workload's own TLS to its destination inside that. ADR-0027
//! decision 8 then made it a dialer inside `egress-proxy` rather than a second listener: the
//! proxy is already the one process holding the claim SVID outside the jail, and the jail
//! keeps one loopback port. So there is no `forward` subcommand; this module is what the
//! proxy's upstream dial becomes when `GET /v1/me` lists gateways.
//!
//! The list is taken in the broker's order. Each connection starts at a random position and
//! tries the next gateway on a connect, handshake or transport failure (decision 7). A
//! gateway that answers the `CONNECT` with anything but `200` has given the environment's
//! verdict (the authorizer's code is the body), and that is not a reason to ask another:
//! the attempt ends there and the workload gets `502` with the code. Every gateway failing
//! is `502` too. Nothing is retried on the workload's behalf beyond that one pass.
//!
//! Without a gateway (an old broker, an environment with none yet) the dial is direct, as
//! before ADR-0028, and the proxy says so once at start.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use mediatore_proto::Endpoint;
use mediatore_tls::{MaterialSource, SpiffeId};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// What a connection must be for the upstream TLS to run on it.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// A connection to an upstream, direct or through a tunnel; what the upstream TLS runs on.
pub type Conn = Box<dyn Stream>;

/// One attempt at one gateway (connect, handshake, `CONNECT`, the answer) is bounded by
/// this; a gateway that is black-holed counts as unreachable and the next is tried.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// The most a `CONNECT` answer's head and body are allowed: anything longer is not a
/// gateway answering.
const MAX_ANSWER: usize = 8 * 1024;

/// Why an upstream could not be reached.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    /// A direct dial failed (no gateways in this environment).
    #[error("connect: {0}")]
    Connect(#[from] std::io::Error),
    /// Every gateway was tried and none carried the tunnel: no connection, a refused
    /// handshake, a transport failure or a timeout at each.
    #[error("no gateway reachable ({tried} tried; last: {last})")]
    Unreachable {
        /// How many were tried: the whole list.
        tried: usize,
        /// The last failure, with the gateway it came from.
        last: String,
    },
    /// A gateway answered the `CONNECT` with a refusal: the environment's verdict, with the
    /// authorizer's code (`not_allowed`, `claim_gone`, `broker_unreachable`, ...).
    #[error("gateway {gateway} refused the tunnel: {status} {code}")]
    Refused {
        /// Which gateway answered.
        gateway: Endpoint,
        /// The HTTP status of the answer.
        status: u16,
        /// The code in its body, or the reason phrase when there was none.
        code: String,
    },
}

impl DialError {
    /// The stable code the workload gets in the proxy's `502` body.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Connect(_) => "upstream_unreachable",
            Self::Unreachable { .. } => "gateway_unreachable",
            Self::Refused { .. } => "gateway_refused",
        }
    }
}

/// A connection the dialer opened, and how.
pub struct Dialed {
    /// The connection; the upstream TLS runs on it.
    pub conn: Conn,
    /// The gateway that carries it, or `None` for a direct dial.
    pub via: Option<Endpoint>,
}

/// How the proxy reaches an upstream.
pub enum Dialer {
    /// TCP to the endpoint itself: an environment with no gateway yet (ADR-0020's shape).
    Direct,
    /// A tunnel through one of the environment's gateways, as the claim.
    Gateways(Forwarder),
}

impl Dialer {
    /// Open a connection to `authority`.
    ///
    /// # Errors
    /// [`DialError`], which the proxy turns into a `502` with the error's code.
    pub async fn dial(&self, authority: &Endpoint) -> Result<Dialed, DialError> {
        match self {
            Self::Direct => {
                let tcp = TcpStream::connect((authority.host.as_str(), authority.port)).await?;
                Ok(Dialed {
                    conn: Box::new(tcp),
                    via: None,
                })
            }
            Self::Gateways(f) => f.tunnel(authority).await,
        }
    }
}

impl fmt::Display for Dialer {
    /// For the proxy's start line: `direct`, or how many gateways.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => f.write_str("direct"),
            Self::Gateways(fw) => write!(f, "{} gateway(s)", fw.gateways.len()),
        }
    }
}

/// The sandbox leg of the gateway (ADR-0028 decision 3): the gateways in the broker's
/// order, the claim SVID to present, the identity every gateway must prove.
pub struct Forwarder {
    gateways: Vec<Endpoint>,
    material: Arc<dyn MaterialSource>,
    gateway_id: SpiffeId,
    attempt_timeout: Duration,
}

impl fmt::Debug for Forwarder {
    /// The list and the identity expected; never the material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Forwarder")
            .field("gateways", &self.gateways)
            .field("gateway_id", &self.gateway_id.to_string())
            .finish_non_exhaustive()
    }
}

impl Forwarder {
    /// A forwarder over `gateways` (as `GET /v1/me` listed them), presenting whatever
    /// `material` holds now at each dial, so a rotated SVID is used by the next tunnel. The
    /// gateway identity is `spiffe://<td>/gateway` for the material's trust domain.
    ///
    /// # Errors
    /// An empty list (the caller dials directly instead), or no material to read the trust
    /// domain from.
    pub fn new(gateways: Vec<Endpoint>, material: Arc<dyn MaterialSource>) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !gateways.is_empty(),
            "no gateways: nothing to forward through"
        );
        let own = material.current()?;
        let gateway_id = SpiffeId::new(format!("spiffe://{}/gateway", own.trust_domain()))?;
        Ok(Self {
            gateways,
            material,
            gateway_id,
            attempt_timeout: ATTEMPT_TIMEOUT,
        })
    }

    /// The same forwarder with each attempt bounded by `timeout` instead of
    /// [`ATTEMPT_TIMEOUT`].
    #[must_use]
    pub fn with_attempt_timeout(mut self, timeout: Duration) -> Self {
        self.attempt_timeout = timeout;
        self
    }

    /// The gateways, in the order the list is walked from a random start.
    #[must_use]
    pub fn gateways(&self) -> &[Endpoint] {
        &self.gateways
    }

    /// The identity every gateway must prove.
    #[must_use]
    pub fn gateway_id(&self) -> &SpiffeId {
        &self.gateway_id
    }

    /// A tunnel to `authority` through the first gateway that carries it, starting at a
    /// random position in the list (decision 7).
    ///
    /// # Errors
    /// [`DialError::Unreachable`] when none did, [`DialError::Refused`] when one answered no.
    pub async fn tunnel(&self, authority: &Endpoint) -> Result<Dialed, DialError> {
        let start = random_start(self.gateways.len());
        failover(&self.gateways, start, |gateway| {
            self.attempt(gateway, authority)
        })
        .await
    }

    /// One attempt at one gateway, bounded.
    async fn attempt(&self, gateway: &Endpoint, authority: &Endpoint) -> Result<Conn, Attempt> {
        match tokio::time::timeout(self.attempt_timeout, self.connect(gateway, authority)).await {
            Ok(r) => r,
            Err(_elapsed) => Err(Attempt::Failed(format!(
                "no answer within {}s",
                self.attempt_timeout.as_secs_f32()
            ))),
        }
    }

    /// TCP to the gateway, TLS 1.3 presenting the claim SVID and verifying the gateway's,
    /// `CONNECT authority`, the answer read; on `200` the stream is the tunnel.
    async fn connect(&self, gateway: &Endpoint, authority: &Endpoint) -> Result<Conn, Attempt> {
        let material = self
            .material
            .current()
            .map_err(|e| Attempt::Failed(format!("no claim SVID: {e}")))?;
        let cfg = mediatore_tls::client_config(&material, &self.gateway_id)
            .map_err(|e| Attempt::Failed(format!("client config: {e}")))?;
        let tcp = TcpStream::connect((gateway.host.as_str(), gateway.port))
            .await
            .map_err(|e| Attempt::Failed(format!("connect: {e}")))?;
        // SNI carries no trust (ADR-0007 decision 5): the gateway is verified by its
        // SPIFFE ID, so the name is a placeholder.
        let name = ServerName::try_from("gateway").map_err(|e| Attempt::Failed(e.to_string()))?;
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
            .map_err(|e| Attempt::Failed(format!("handshake: {e}")))?;
        tls.write_all(connect_request(authority).as_bytes())
            .await
            .map_err(|e| Attempt::Failed(format!("write: {e}")))?;
        let answer = read_answer(&mut tls)
            .await
            .map_err(|e| Attempt::Failed(format!("read: {e}")))?;
        if answer.status == 200 {
            Ok(Box::new(Prefixed::new(answer.rest, tls)))
        } else {
            Err(Attempt::Refused {
                status: answer.status,
                code: answer.code,
            })
        }
    }
}

/// How one attempt at one gateway ended, short of a tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Attempt {
    /// No connection, no handshake, no answer: try the next gateway.
    Failed(String),
    /// The gateway answered no: the verdict, no next.
    Refused {
        /// The HTTP status.
        status: u16,
        /// The code in the body, or the reason phrase.
        code: String,
    },
}

/// Walk `gateways` from `start`, wrapping around, until one attempt yields a tunnel.
async fn failover<'a, F, Fut>(
    gateways: &'a [Endpoint],
    start: usize,
    mut attempt: F,
) -> Result<Dialed, DialError>
where
    F: FnMut(&'a Endpoint) -> Fut,
    Fut: Future<Output = Result<Conn, Attempt>>,
{
    let mut last = String::from("no gateway listed");
    let mut tried = 0;
    for i in 0..gateways.len() {
        let gateway = &gateways[(start + i) % gateways.len()];
        tried += 1;
        match attempt(gateway).await {
            Ok(conn) => {
                return Ok(Dialed {
                    conn,
                    via: Some(gateway.clone()),
                });
            }
            Err(Attempt::Refused { status, code }) => {
                return Err(DialError::Refused {
                    gateway: gateway.clone(),
                    status,
                    code,
                });
            }
            Err(Attempt::Failed(why)) => {
                tracing::warn!(gateway = %gateway, error = %why, "gateway unreachable; trying the next");
                last = format!("{gateway}: {why}");
            }
        }
    }
    Err(DialError::Unreachable { tried, last })
}

/// A random position in a list of `len`, from the provider's random source; `0` if the
/// source fails, which only costs the spread.
fn random_start(len: usize) -> usize {
    let mut bytes = [0u8; 8];
    if len < 2 || aws_lc_rs::rand::fill(&mut bytes).is_err() {
        return 0;
    }
    let len = u64::try_from(len).unwrap_or(1);
    usize::try_from(u64::from_le_bytes(bytes) % len).unwrap_or(0)
}

/// The `CONNECT` the gateway sees: the authority as `host:port` (an IPv6 address in
/// brackets), the one shape the authorizer admits.
fn connect_request(authority: &Endpoint) -> String {
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
}

/// What a gateway answered a `CONNECT` with.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    /// The status line's code.
    status: u16,
    /// For a refusal, the body's first line (the authorizer's code) or the reason phrase.
    code: String,
    /// Bytes read past the head on a `200`: the tunnel's, handed on.
    rest: Vec<u8>,
}

/// Read one HTTP/1.1 response to a `CONNECT`: the head, and for anything but `200` the
/// body (bounded by `Content-Length` and [`MAX_ANSWER`]), which carries the code.
async fn read_answer<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<Answer> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_ANSWER {
            return Err(std::io::Error::other("the answer's head is too long"));
        }
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::other(
                "the connection closed before an answer",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut status_line = head.lines().next().unwrap_or("").splitn(3, ' ');
    let version = status_line.next().unwrap_or("");
    let status: u16 = status_line
        .next()
        .and_then(|s| s.parse().ok())
        .filter(|_| version.starts_with("HTTP/1."))
        .ok_or_else(|| std::io::Error::other(format!("not an HTTP answer: {head:?}")))?;
    let reason = status_line.next().unwrap_or("").trim().to_owned();
    let rest = buf[head_end..].to_vec();
    if status == 200 {
        return Ok(Answer {
            status,
            code: reason,
            rest,
        });
    }
    let length = head
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        })
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_ANSWER);
    let mut body = rest;
    while body.len() < length {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    let code = String::from_utf8_lossy(&body)
        .lines()
        .next()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map_or(reason, ToOwned::to_owned);
    Ok(Answer {
        status,
        code,
        rest: Vec::new(),
    })
}

/// A stream with bytes already read from it put back in front: what the tunnel is when
/// the gateway's `200` head came with more in the same read.
struct Prefixed<S> {
    buf: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(buf: Vec<u8>, inner: S) -> Self {
        Self { buf, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.buf.len() {
            let n = buf.remaining().min(self.buf.len() - self.pos);
            let (from, to) = (self.pos, self.pos + n);
            buf.put_slice(&self.buf[from..to]);
            self.pos = to;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    fn ep(s: &str) -> Endpoint {
        s.parse().unwrap()
    }

    fn gateways() -> Vec<Endpoint> {
        vec![
            ep("192.0.2.1:8443"),
            ep("192.0.2.2:8443"),
            ep("[2001:db8::3]:8443"),
        ]
    }

    /// A tunnel that goes nowhere, for the scripted attempts.
    fn conn() -> Conn {
        Box::new(tokio::io::duplex(8).0)
    }

    /// Runs `failover` over a script of what each gateway answers, by its position in the
    /// list, and records the order the gateways were tried in.
    async fn walk(
        start: usize,
        script: &[Result<(), Attempt>],
    ) -> (Result<Dialed, DialError>, Vec<Endpoint>) {
        let gws = gateways();
        let tried = RefCell::new(Vec::new());
        let result = failover(&gws, start, |gw| {
            tried.borrow_mut().push(gw.clone());
            let i = gws.iter().position(|g| g == gw).unwrap();
            let outcome = script[i].clone();
            async move { outcome.map(|()| conn()) }
        })
        .await;
        (result, tried.into_inner())
    }

    fn failed() -> Result<(), Attempt> {
        Err(Attempt::Failed("connect: refused".into()))
    }

    #[tokio::test]
    async fn the_list_is_walked_from_the_start_position_and_wraps_around() {
        let (result, tried) = walk(1, &[Ok(()), failed(), failed()]).await;
        assert_eq!(
            tried,
            [
                ep("192.0.2.2:8443"),
                ep("[2001:db8::3]:8443"),
                ep("192.0.2.1:8443")
            ]
        );
        assert_eq!(
            result.unwrap().via,
            Some(ep("192.0.2.1:8443")),
            "the third tried, the first in the list, carried it"
        );
        let (result, tried) = walk(0, &[Ok(()), Ok(()), Ok(())]).await;
        assert_eq!(
            tried,
            [ep("192.0.2.1:8443")],
            "the first that answers is the one"
        );
        assert_eq!(result.unwrap().via, Some(ep("192.0.2.1:8443")));
    }

    #[tokio::test]
    async fn a_gateway_that_fails_is_skipped_and_the_next_carries_the_tunnel() {
        let (result, tried) = walk(0, &[failed(), Ok(()), Ok(())]).await;
        assert_eq!(tried.len(), 2);
        assert_eq!(result.unwrap().via, Some(ep("192.0.2.2:8443")));
    }

    #[tokio::test]
    async fn a_refusal_is_the_verdict_and_no_other_gateway_is_asked() {
        let refused = Err(Attempt::Refused {
            status: 403,
            code: "not_allowed".into(),
        });
        let (result, tried) = walk(2, &[Ok(()), Ok(()), refused]).await;
        assert_eq!(tried, [ep("[2001:db8::3]:8443")]);
        let err = result.err().expect("refused");
        assert!(
            matches!(&err, DialError::Refused { gateway, status: 403, code } if *gateway == ep("[2001:db8::3]:8443") && code == "not_allowed"),
            "{err}"
        );
        assert_eq!(err.code(), "gateway_refused");
        assert_eq!(
            err.to_string(),
            "gateway [2001:db8::3]:8443 refused the tunnel: 403 not_allowed"
        );
    }

    #[tokio::test]
    async fn every_gateway_down_is_unreachable_after_one_pass() {
        let (result, tried) = walk(1, &[failed(), failed(), failed()]).await;
        assert_eq!(tried.len(), 3, "each once, no second pass");
        let err = result.err().expect("unreachable");
        assert!(
            matches!(&err, DialError::Unreachable { tried: 3, last } if last.starts_with("192.0.2.1:8443: ")),
            "{err}"
        );
        assert_eq!(err.code(), "gateway_unreachable");
        assert_eq!(
            DialError::Connect(std::io::Error::other("x")).code(),
            "upstream_unreachable"
        );
    }

    #[test]
    fn the_random_start_is_a_position_in_the_list() {
        for _ in 0..64 {
            assert!(random_start(3) < 3);
        }
        assert_eq!(random_start(1), 0);
        assert_eq!(random_start(0), 0);
        // Over enough draws every position comes up: the spread decision 7 asks for.
        let seen: std::collections::BTreeSet<usize> = (0..256).map(|_| random_start(3)).collect();
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn the_connect_names_the_authority_as_host_port_with_ipv6_in_brackets() {
        assert_eq!(
            connect_request(&ep("api.home.example:443")),
            "CONNECT api.home.example:443 HTTP/1.1\r\nHost: api.home.example:443\r\n\r\n"
        );
        assert_eq!(
            connect_request(&ep("[2001:db8::1]:8443")),
            "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn the_answer_is_the_status_and_the_code_in_the_body() {
        let mut ok: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n\x16\x03\x03";
        let a = read_answer(&mut ok).await.unwrap();
        assert_eq!(a.status, 200);
        assert_eq!(
            a.rest, b"\x16\x03\x03",
            "bytes past the head belong to the tunnel"
        );

        let mut denied: &[u8] =
            b"HTTP/1.1 403 Forbidden\r\ncontent-length: 11\r\ndate: x\r\n\r\nnot_allowed";
        let a = read_answer(&mut denied).await.unwrap();
        assert_eq!((a.status, a.code.as_str()), (403, "not_allowed"));
        assert_eq!(a.rest, Vec::<u8>::new());

        let mut bare: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\r\n";
        let a = read_answer(&mut bare).await.unwrap();
        assert_eq!(
            (a.status, a.code.as_str()),
            (503, "Service Unavailable"),
            "no body: the reason phrase"
        );

        let mut short: &[u8] = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 40\r\n\r\nclaim_gone";
        let a = read_answer(&mut short).await.unwrap();
        assert_eq!(
            a.code, "claim_gone",
            "a body cut short still gives its first line"
        );

        let mut garbage: &[u8] = b"\x16\x03\x01 not http\r\n\r\n";
        assert!(read_answer(&mut garbage).await.is_err());
        let mut closed: &[u8] = b"HTTP/1.1 200";
        assert!(read_answer(&mut closed).await.is_err());
        let long = vec![b'x'; MAX_ANSWER + 1];
        let mut long: &[u8] = &long;
        assert!(read_answer(&mut long).await.is_err());
    }

    #[tokio::test]
    async fn the_prefixed_stream_hands_the_leftover_bytes_out_first() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b"rest").await.unwrap();
        let mut p = Prefixed::new(b"head".to_vec(), b);
        let mut out = [0u8; 8];
        p.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"headrest");
        p.write_all(b"back").await.unwrap();
        p.flush().await.unwrap();
        let mut back = [0u8; 4];
        a.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"back");
        p.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_dialer_says_what_it_is_and_a_forwarder_needs_a_gateway_and_a_trust_domain() {
        assert_eq!(Dialer::Direct.to_string(), "direct");
        let ca = mediatore_testkit::TestCa::new("sandbox.test");
        let material = mediatore_testkit::MemoryMaterial::new(
            ca.svid("spiffe://sandbox.test/banlieue/claim/00000000-0000-0000-0000-000000000001"),
        );
        let f = Forwarder::new(gateways(), material.clone()).unwrap();
        assert_eq!(f.gateway_id().to_string(), "spiffe://sandbox.test/gateway");
        assert_eq!(f.gateways(), gateways());
        assert_eq!(Dialer::Gateways(f).to_string(), "3 gateway(s)");
        let err = Forwarder::new(vec![], material).unwrap_err().to_string();
        assert!(err.contains("no gateways"), "{err}");
    }

    #[tokio::test]
    async fn a_direct_dial_to_nothing_is_a_connect_error_with_the_upstream_code() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = Dialer::Direct
            .dial(&ep(&format!("127.0.0.1:{port}")))
            .await
            .err()
            .expect("nothing listens there");
        assert_eq!(err.code(), "upstream_unreachable");
    }
}
