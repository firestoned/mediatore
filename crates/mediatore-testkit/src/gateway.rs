// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! A stand-in for the egress gateway (ADR-0028), for the forwarder's e2e: a mutual-TLS
//! listener on the production sandbox-leg configuration (`mediatore_tls::TlsConfigs`),
//! presenting whatever SVID a test gives it, admitting claim identities only (the gateway's
//! validator), answering each `CONNECT` from a fixed allowlist as the authorizer would
//! (`200` and the tunnel relayed untouched to the authority, or `403` with the code
//! `not_allowed` in the body) and recording every tunnel it was asked for: the peer, the
//! authority, the verdict. No Envoy, no broker; the kind tier has the real ones.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use mediatore_proto::Endpoint;
use mediatore_tls::{Authorizer, SpiffeId, TlsConfigs};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::TestCa;

/// One `CONNECT` the stand-in saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenTunnel {
    /// The peer's SPIFFE ID, from its verified certificate.
    pub peer: String,
    /// The authority asked for, as written in the request.
    pub authority: String,
    /// Whether it was in the allowlist and the tunnel opened.
    pub allowed: bool,
}

/// A running stand-in for one test.
pub struct StandInGateway {
    /// Where it listens.
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<SeenTunnel>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for StandInGateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl StandInGateway {
    /// Listen on an ephemeral loopback port as `identity` (an SVID from `ca`; the real
    /// gateway's is `spiffe://<td>/gateway`), admitting peers under
    /// `spiffe://<td>/banlieue/claim/` only, opening tunnels to the endpoints in `allow`.
    ///
    /// # Panics
    /// On a config or bind failure: a broken test environment.
    pub async fn start(ca: &TestCa, identity: &str, allow: Vec<Endpoint>) -> Self {
        Self::start_with(ca, identity, allow, false).await
    }

    /// A gateway in trouble of its own: it answers every `CONNECT` with `503` and `DNS
    /// resolution failure`, as Envoy does when its resolver fails, and records the ask.
    /// No verdict is given, so the forwarder moves to the next gateway (ADR-0028 decision
    /// 7 as amended).
    ///
    /// # Panics
    /// As [`Self::start`].
    pub async fn start_unwell(ca: &TestCa, identity: &str) -> Self {
        Self::start_with(ca, identity, vec![], true).await
    }

    async fn start_with(ca: &TestCa, identity: &str, allow: Vec<Endpoint>, unwell: bool) -> Self {
        mediatore_proto::tls::ensure_provider();
        let material = ca.svid(identity);
        let prefix = format!("spiffe://{}/banlieue/claim/", ca.trust_domain());
        let authorizer: Authorizer =
            Arc::new(move |peer: &SpiffeId| peer.to_string().starts_with(&prefix));
        let config = TlsConfigs::build(&material, &authorizer).expect("gateway config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen: Arc<Mutex<Vec<SeenTunnel>>> = Arc::default();
        let allow = Arc::new(allow);
        let recorder = seen.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let allow = allow.clone();
                let seen = recorder.clone();
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
                    serve(tls, &peer, &allow, unwell, &seen).await;
                });
            }
        });
        Self { addr, seen, task }
    }

    /// The stand-in as a gateway endpoint: `127.0.0.1:<port>`.
    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        Endpoint {
            host: self.addr.ip().to_string(),
            port: self.addr.port(),
        }
    }

    /// Every `CONNECT` seen so far, in order.
    ///
    /// # Panics
    /// If the lock is poisoned.
    #[must_use]
    pub fn tunnels(&self) -> Vec<SeenTunnel> {
        self.seen.lock().expect("tunnels lock").clone()
    }
}

/// An endpoint nothing listens on: a port that was bound and released. A dial gets a
/// connection refused, which is what a gateway that is down looks like.
///
/// # Panics
/// On a bind failure.
pub async fn dead_endpoint() -> Endpoint {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    Endpoint {
        host: addr.ip().to_string(),
        port: addr.port(),
    }
}

/// One connection: read the `CONNECT`, record it, answer, relay.
async fn serve(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    peer: &str,
    allow: &[Endpoint],
    unwell: bool,
    seen: &Mutex<Vec<SeenTunnel>>,
) {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > 8192 {
            break;
        }
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut line = text.lines().next().unwrap_or("").split_whitespace();
    let (method, authority) = (line.next().unwrap_or(""), line.next().unwrap_or(""));
    let allowed = method == "CONNECT"
        && authority
            .parse::<Endpoint>()
            .is_ok_and(|e| allow.contains(&e));
    seen.lock().expect("tunnels lock").push(SeenTunnel {
        peer: peer.to_owned(),
        authority: authority.to_owned(),
        allowed,
    });
    if unwell {
        let body = "DNS resolution failure";
        let _ = tls
            .write_all(
                format!(
                    "HTTP/1.1 503 Service Unavailable\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
        let _ = tls.shutdown().await;
        return;
    }
    if !allowed {
        let body = "not_allowed";
        let _ = tls
            .write_all(
                format!(
                    "HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
        let _ = tls.shutdown().await;
        return;
    }
    let Ok(endpoint) = authority.parse::<Endpoint>() else {
        return;
    };
    let Ok(mut upstream) = TcpStream::connect((endpoint.host.as_str(), endpoint.port)).await else {
        let _ = tls
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
            .await;
        return;
    };
    if tls
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
}
