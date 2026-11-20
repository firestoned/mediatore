// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The sandbox listener: rotating server configs and the accept loop.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use axum::{Extension, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::server::graceful::Watcher;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::server::NoServerSessionStorage;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use x509_cert::Certificate;
use x509_cert::der::Decode;

use crate::provider::sandbox_provider;
use crate::verify::{Authorizer, SpiffeClientVerifier};
use crate::{Material, MaterialSource, TlsError};

/// How long a peer has to finish the TLS handshake. Until then it is nobody: a connection
/// that says nothing, or says it slowly, is dropped here and never holds a task for longer.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections the listener holds at once, handshaking ones included. One more is accepted
/// and closed at once, so the accept loop never waits on a slot.
const MAX_CONNECTIONS: usize = 4096;
/// At most one warning per this long while the listener is at [`MAX_CONNECTIONS`].
const CAP_WARN_INTERVAL: Duration = Duration::from_secs(10);
/// How long the drain waits for open connections once `shutdown` resolved.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// The accept loop's bounds: [`serve`] uses the constants, a test its own.
#[derive(Debug, Clone, Copy)]
struct Limits {
    handshake_timeout: Duration,
    max_connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            handshake_timeout: HANDSHAKE_TIMEOUT,
            max_connections: MAX_CONNECTIONS,
        }
    }
}

/// The verified SPIFFE ID of the connection's client certificate, attached to every request
/// on that connection as an axum extension. Only the accept loop constructs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerSpiffeId(pub String);

/// The current server config, rebuilt whenever the source rotates.
pub struct TlsConfigs {
    current: ArcSwap<ServerConfig>,
}

impl TlsConfigs {
    /// A server config from one snapshot of material on [`sandbox_provider`]: TLS 1.3
    /// only, X25519MLKEM768 only, AES-256-GCM only, client certificate required and
    /// verified by [`SpiffeClientVerifier`], no session resumption (a resumed handshake
    /// would skip the verifier, so an expired or revoked SVID could resume).
    pub fn build(material: &Material, authorizer: &Authorizer) -> Result<ServerConfig, TlsError> {
        mediatore_proto::tls::ensure_provider();
        let verifier = SpiffeClientVerifier::new(
            material.roots.clone(),
            material.trust_domain().clone(),
            authorizer.clone(),
        )?;
        let mut cfg = ServerConfig::builder_with_provider(sandbox_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| TlsError::Config(format!("protocol versions: {e}")))?
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(material.chain.clone(), material.key.clone_key())
            .map_err(|e| TlsError::Config(format!("server identity: {e}")))?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        cfg.session_storage = Arc::new(NoServerSessionStorage {});
        cfg.send_tls13_tickets = 0;
        Ok(cfg)
    }

    /// Build from the source's current material and keep rebuilding on each rotation (a
    /// task on the current runtime). A rotation that fails to build keeps the previous
    /// config, which expires on its own.
    pub fn spawn(
        source: Arc<dyn MaterialSource>,
        authorizer: Authorizer,
    ) -> Result<Arc<Self>, TlsError> {
        let initial = Self::build(source.current()?.as_ref(), &authorizer)?;
        let configs = Arc::new(Self {
            current: ArcSwap::from_pointee(initial),
        });
        let weak = Arc::downgrade(&configs);
        tokio::spawn(async move {
            loop {
                if let Err(e) = source.changed().await {
                    tracing::warn!(error = %e, "svid updates ended; serving the last material until it expires");
                    break;
                }
                let Some(configs) = weak.upgrade() else { break };
                match source
                    .current()
                    .and_then(|m| Self::build(m.as_ref(), &authorizer).map(|c| (m, c)))
                {
                    Ok((m, cfg)) => {
                        configs.current.store(Arc::new(cfg));
                        tracing::info!(spiffe_id = %m.spiffe_id, "sandbox listener: material rotated");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "sandbox listener: rotation failed; keeping the previous material");
                    }
                }
            }
        });
        Ok(configs)
    }

    /// The config new handshakes use.
    pub fn current(&self) -> Arc<ServerConfig> {
        self.current.load_full()
    }
}

/// Serve `router` over SPIFFE mTLS on `listener` until `shutdown` resolves, then drain.
///
/// Each connection handshakes with the config current at accept time; the verified client
/// SPIFFE ID becomes a [`PeerSpiffeId`] extension on every request of that connection. A
/// connection that fails the handshake is logged and dropped; no HTTP is ever parsed on it.
///
/// A handshake has [`HANDSHAKE_TIMEOUT`] to finish. At most [`MAX_CONNECTIONS`] connections
/// are held at once; beyond that a new one is accepted and closed at once (the loop keeps
/// accepting and keeps hearing `shutdown`, where waiting for a slot would stall every peer
/// behind the one that is waiting).
///
/// A connection lives no longer than the certificate it was verified with: it is closed at
/// the peer leaf's `notAfter` at the latest, whatever is in flight on it. The verifier
/// judged that certificate once, at the handshake; without this bound a peer whose SVID has
/// expired, or whose entry was retracted and whose SVID was therefore never renewed, would
/// keep the identity for as long as it kept the connection open. A peer with a renewed
/// SVID connects again and is verified again.
pub async fn serve(
    listener: TcpListener,
    configs: Arc<TlsConfigs>,
    router: Router,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    serve_with(listener, configs, router, shutdown, Limits::default()).await
}

/// [`serve`] with its bounds given.
async fn serve_with(
    listener: TcpListener,
    configs: Arc<TlsConfigs>,
    router: Router,
    shutdown: impl Future<Output = ()>,
    limits: Limits,
) -> std::io::Result<()> {
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    // Connections closed at the cap since the last warning, and when that was.
    let mut refused: u64 = 0;
    let mut warned: Option<Instant> = None;
    loop {
        let (tcp, addr) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "sandbox listener: accept failed");
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        // The slot is taken before the task exists and given back when the task ends, however
        // it ends. None free: `tcp` is dropped here, which closes it.
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            refused += 1;
            let now = Instant::now();
            if warned.is_none_or(|at| now.duration_since(at) >= CAP_WARN_INTERVAL) {
                tracing::warn!(
                    peer = %addr,
                    refused,
                    max_connections = limits.max_connections,
                    "sandbox listener: at its connection cap; new connections are closed"
                );
                warned = Some(now);
                refused = 0;
            }
            continue;
        };
        // A failure only costs latency (Nagle against delayed ACKs on a streamed answer).
        let _ = tcp.set_nodelay(true);
        let acceptor = TlsAcceptor::from(configs.current());
        let router = router.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            connection(
                tcp,
                addr,
                &acceptor,
                router,
                watcher,
                limits.handshake_timeout,
            )
            .await;
            // Held for the connection's life, however it ended.
            drop(slot);
        });
    }
    tracing::info!("sandbox listener: draining");
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, graceful.shutdown()).await;
    Ok(())
}

/// One accepted connection, from the handshake to its end: the handshake within
/// `handshake_timeout`, then HTTP with the verified peer attached to every request, until
/// the peer or the drain ends it or the peer certificate's `notAfter` passes, whichever
/// comes first.
async fn connection(
    tcp: TcpStream,
    addr: SocketAddr,
    acceptor: &TlsAcceptor,
    router: Router,
    watcher: Watcher,
    handshake_timeout: Duration,
) {
    let handshake = tokio::time::timeout(handshake_timeout, acceptor.accept(tcp));
    let tls = match handshake.await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            tracing::info!(peer = %addr, error = %e, "mtls handshake refused");
            return;
        }
        Err(_) => {
            tracing::debug!(
                peer = %addr,
                timeout_ms = handshake_timeout.as_millis(),
                "mtls handshake not finished in time; dropping"
            );
            return;
        }
    };
    let session = tls.get_ref().1;
    let verified = session
        .peer_certificates()
        .and_then(<[_]>::first)
        .and_then(|leaf| peer_of(leaf).zip(lifetime_left(leaf, SystemTime::now())));
    let Some((peer, left)) = verified else {
        tracing::error!(peer = %addr, "handshake completed without a verified client SVID; dropping");
        return;
    };
    tracing::debug!(
        peer = %addr,
        spiffe_id = %peer.0,
        kx = ?session.negotiated_key_exchange_group().map(rustls::crypto::SupportedKxGroup::name),
        suite = ?session.negotiated_cipher_suite().map(|s| s.suite()),
        max_age_secs = left.as_secs(),
        "mtls connection"
    );
    let spiffe_id = peer.0.clone();
    let service = TowerToHyperService::new(router.layer(Extension(peer)));
    let builder = auto::Builder::new(TokioExecutor::new());
    let served = watcher.watch(builder.serve_connection(TokioIo::new(tls), service));
    // Dropping `served` closes the connection: nothing is answered under a certificate
    // that is no longer valid.
    match tokio::time::timeout(left, served).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::debug!(peer = %addr, error = %e, "connection ended"),
        Err(_) => {
            tracing::info!(peer = %addr, %spiffe_id, "the peer certificate's notAfter passed; connection closed");
        }
    }
}

/// How long a connection verified with `leaf` may still live at `now`: until the
/// certificate's `notAfter`, zero when that has passed. `None` for a certificate that does
/// not parse (or a clock before 1970), which the caller treats as no verified peer at all.
fn lifetime_left(leaf: &CertificateDer<'_>, now: SystemTime) -> Option<Duration> {
    let cert = Certificate::from_der(leaf).ok()?;
    let not_after = cert
        .tbs_certificate()
        .validity()
        .not_after
        .to_unix_duration();
    let now = now.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    Some(not_after.saturating_sub(now))
}

/// The peer identity the verifier accepted: the leaf's SPIFFE ID, re-read from the
/// connection's own certificate so the request sees exactly what was verified.
fn peer_of(leaf: &CertificateDer<'_>) -> Option<PeerSpiffeId> {
    spiffe::cert::spiffe_id_from_der(leaf)
        .ok()
        .map(|id| PeerSpiffeId(id.to_string()))
}

#[cfg(test)]
mod tests {
    use rustls::RootCertStore;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use spiffe::SpiffeId;
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpStream;

    use super::*;

    const BROKER: &str = "spiffe://sandbox.test/mediatore";

    /// A server config over a self-signed SVID that is its own trust anchor. Built here and
    /// not with the test kit: the kit depends on this crate, and a unit test would get a
    /// second copy of its types. Enough for a listener; no peer in these tests gets as far
    /// as presenting a certificate.
    fn configs() -> Arc<TlsConfigs> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            BROKER.try_into().expect("an IA5 string"),
        )];
        let cert = params.self_signed(&key).expect("a certificate");
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).expect("a trust anchor");
        let id = SpiffeId::new(BROKER).expect("a SPIFFE ID");
        let material = Material {
            spiffe_id: id.clone(),
            chain: vec![cert.der().clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            roots: Arc::new(roots),
        };
        let config = TlsConfigs::build(&material, &crate::verify::exact(id)).expect("a config");
        Arc::new(TlsConfigs {
            current: ArcSwap::from_pointee(config),
        })
    }

    /// A listener with these bounds; returns its address and its task.
    async fn listen(limits: Limits) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("an address");
        let configs = configs();
        let task = tokio::spawn(async move {
            let _ = serve_with(
                listener,
                configs,
                Router::new(),
                std::future::pending(),
                limits,
            )
            .await;
        });
        (addr, task)
    }

    /// Whether the listener closed `peer` (an end of stream, or a reset) within `wait`.
    async fn closed_within(peer: &mut TcpStream, wait: Duration) -> bool {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(wait, peer.read(&mut byte)).await {
            Ok(Ok(n)) => n == 0,
            Ok(Err(_)) => true,
            Err(_) => false,
        }
    }

    /// 2030-01-01T00:00:00Z, the `notAfter` of [`leaf_until_2030`], in Unix seconds.
    const Y2030: u64 = 1_893_456_000;

    /// A leaf whose `notAfter` is the first second of 2030.
    fn leaf_until_2030() -> CertificateDer<'static> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
        let mut params = rcgen::CertificateParams::default();
        params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        params
            .self_signed(&key)
            .expect("a certificate")
            .der()
            .clone()
    }

    #[test]
    fn a_connection_may_live_until_the_peer_certificates_not_after_and_no_longer() {
        let leaf = leaf_until_2030();
        let at = |secs: u64| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        assert_eq!(
            lifetime_left(&leaf, at(Y2030 - 90)),
            Some(Duration::from_secs(90)),
            "ninety seconds before notAfter, ninety seconds are left"
        );
        assert_eq!(
            lifetime_left(&leaf, at(Y2030)),
            Some(Duration::ZERO),
            "at notAfter nothing is left"
        );
        assert_eq!(
            lifetime_left(&leaf, at(Y2030 + 3600)),
            Some(Duration::ZERO),
            "past notAfter nothing is left, never a negative or a wrapped age"
        );
        assert_eq!(
            lifetime_left(&CertificateDer::from(vec![0x30, 0x00]), at(Y2030 - 90)),
            None,
            "a certificate that does not parse bounds nothing: the connection is dropped"
        );
    }

    #[test]
    fn the_bounds_serve_uses_are_the_named_ones() {
        let limits = Limits::default();
        assert_eq!(limits.handshake_timeout, Duration::from_secs(10));
        assert_eq!(limits.max_connections, 4096);
    }

    #[tokio::test]
    async fn a_peer_that_connects_and_says_nothing_is_dropped_at_the_handshake_timeout() {
        let timeout = Duration::from_millis(300);
        let (addr, task) = listen(Limits {
            handshake_timeout: timeout,
            max_connections: 8,
        })
        .await;
        let mut peer = TcpStream::connect(addr).await.expect("connect");
        // Not before the timeout: a slow peer keeps its chance.
        assert!(
            !closed_within(&mut peer, timeout / 3).await,
            "dropped before the handshake timeout"
        );
        assert!(
            closed_within(&mut peer, Duration::from_secs(10)).await,
            "a silent peer was kept past the handshake timeout"
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_peer_that_sends_half_a_hello_is_dropped_at_the_handshake_timeout() {
        use tokio::io::AsyncWriteExt as _;
        let (addr, task) = listen(Limits {
            handshake_timeout: Duration::from_millis(300),
            max_connections: 8,
        })
        .await;
        let mut peer = TcpStream::connect(addr).await.expect("connect");
        // A TLS record header announcing a handshake message that never comes.
        peer.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00])
            .await
            .expect("write");
        assert!(
            closed_within(&mut peer, Duration::from_secs(10)).await,
            "a stalled handshake was kept past the timeout"
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_connection_over_the_cap_is_closed_at_once_and_the_slot_comes_back() {
        // A handshake timeout far longer than the test: only the cap closes anything here.
        let (addr, task) = listen(Limits {
            handshake_timeout: Duration::from_secs(120),
            max_connections: 1,
        })
        .await;
        let mut first = TcpStream::connect(addr).await.expect("connect");
        assert!(
            !closed_within(&mut first, Duration::from_millis(200)).await,
            "the first connection has the slot"
        );
        let mut second = TcpStream::connect(addr).await.expect("connect");
        assert!(
            closed_within(&mut second, Duration::from_secs(10)).await,
            "a connection over the cap was kept"
        );
        // The loop is still accepting, and the first peer leaving frees its slot.
        drop(first);
        let mut kept = false;
        for _ in 0..50 {
            let mut next = TcpStream::connect(addr).await.expect("connect");
            if !closed_within(&mut next, Duration::from_millis(200)).await {
                kept = true;
                break;
            }
        }
        assert!(kept, "the slot of a connection that ended never came back");
        task.abort();
    }
}
