// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The sandbox listener: rotating server configs and the accept loop.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::{Extension, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use rustls::server::NoServerSessionStorage;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::provider::sandbox_provider;
use crate::verify::{Authorizer, SpiffeClientVerifier};
use crate::{Material, MaterialSource, TlsError};

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
pub async fn serve(
    listener: TcpListener,
    configs: Arc<TlsConfigs>,
    router: Router,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
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
        let acceptor = TlsAcceptor::from(configs.current());
        let router = router.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::info!(peer = %addr, error = %e, "mtls handshake refused");
                    return;
                }
            };
            let Some(peer) = peer_of(tls.get_ref().1) else {
                tracing::error!(peer = %addr, "handshake completed without a verified client SVID; dropping");
                return;
            };
            let conn = tls.get_ref().1;
            tracing::debug!(
                peer = %addr,
                spiffe_id = %peer.0,
                kx = ?conn.negotiated_key_exchange_group().map(rustls::crypto::SupportedKxGroup::name),
                suite = ?conn.negotiated_cipher_suite().map(|s| s.suite()),
                "mtls connection"
            );
            let service = TowerToHyperService::new(router.layer(Extension(peer)));
            let builder = auto::Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection(TokioIo::new(tls), service);
            if let Err(e) = watcher.watch(conn).await {
                tracing::debug!(peer = %addr, error = %e, "connection ended");
            }
        });
    }
    tracing::info!("sandbox listener: draining");
    let _ = tokio::time::timeout(Duration::from_secs(10), graceful.shutdown()).await;
    Ok(())
}

/// The peer identity the verifier accepted: the leaf's SPIFFE ID, re-read from the
/// connection so the request sees exactly what was verified.
fn peer_of(conn: &rustls::ServerConnection) -> Option<PeerSpiffeId> {
    let leaf = conn.peer_certificates()?.first()?;
    spiffe::cert::spiffe_id_from_der(leaf)
        .ok()
        .map(|id| PeerSpiffeId(id.to_string()))
}
