// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Where SVIDs and bundles come from.

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use spiffe::{SpiffeId, TrustDomain, X509Source};

use crate::TlsError;

/// One identity's TLS material: its SVID chain and key, and the trust-domain bundle it
/// verifies peers against. The key exists only here, in memory.
pub struct Material {
    /// The SVID's SPIFFE ID (the leaf's URI SAN).
    pub spiffe_id: SpiffeId,
    /// Leaf first, then intermediates, DER.
    pub chain: Vec<CertificateDer<'static>>,
    /// The leaf's private key, PKCS#8 DER.
    pub key: PrivateKeyDer<'static>,
    /// The local trust domain's X.509 authorities.
    pub roots: Arc<RootCertStore>,
}

impl Material {
    /// The trust domain of the SVID.
    pub fn trust_domain(&self) -> &TrustDomain {
        self.spiffe_id.trust_domain()
    }
}

impl std::fmt::Debug for Material {
    /// Never the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Material")
            .field("spiffe_id", &self.spiffe_id.to_string())
            .field("chain_len", &self.chain.len())
            .field("roots", &self.roots.len())
            .finish_non_exhaustive()
    }
}

/// A live supply of [`Material`].
pub trait MaterialSource: Send + Sync + 'static {
    /// The current material. An error means no usable SVID right now (fail closed).
    fn current(&self) -> Result<Arc<Material>, TlsError>;

    /// Resolves once the material has changed since this call (rotation). An error means
    /// the source stopped delivering updates for good.
    fn changed(&self) -> BoxFuture<'_, Result<(), TlsError>>;
}

/// A Workload API endpoint from either a bare socket path (`/run/spire/agent.sock`) or an
/// already-formed endpoint (`unix:///run/spire/agent.sock`, `tcp://127.0.0.1:8081`).
pub fn endpoint(socket: &str) -> String {
    if socket.contains("://") {
        socket.to_owned()
    } else {
        format!("unix://{socket}")
    }
}

/// The Workload API as a source: the `spiffe` crate's `X509Source`, which keeps the SVID
/// and its key in memory and re-fetches on rotation (ADR-0007 decision 1).
pub struct WorkloadApiSource {
    source: X509Source,
}

impl WorkloadApiSource {
    /// Connect to the agent at `endpoint` (`unix:///run/spire/sockets/spire-agent.sock`) and
    /// wait for the first SVID, at most `wait`. The `spiffe` crate retries a socket that is
    /// absent and waits on one that never answers, both without end; a role that cannot
    /// get its identity has to fail closed, not hang, so the wait is bounded here.
    pub async fn connect(endpoint: &str, wait: Duration) -> Result<Self, TlsError> {
        let build = X509Source::builder().endpoint(endpoint).build();
        let source = tokio::time::timeout(wait, build)
            .await
            .map_err(|_elapsed| {
                TlsError::WorkloadApi(format!(
                    "no SVID from {endpoint} within {}s",
                    wait.as_secs_f32()
                ))
            })?
            .map_err(|e| TlsError::WorkloadApi(e.to_string()))?;
        Ok(Self { source })
    }

    /// Stop the background stream.
    pub async fn shutdown(&self) {
        self.source.shutdown().await;
    }
}

impl MaterialSource for WorkloadApiSource {
    fn current(&self) -> Result<Arc<Material>, TlsError> {
        let svid = self
            .source
            .svid()
            .map_err(|e| TlsError::Material(e.to_string()))?;
        let bundles = self
            .source
            .bundle_set()
            .map_err(|e| TlsError::Material(e.to_string()))?;
        let td = svid.spiffe_id().trust_domain();
        let bundle = bundles
            .get(td)
            .ok_or_else(|| TlsError::Material(format!("no X.509 bundle for trust domain {td}")))?;
        let mut roots = RootCertStore::empty();
        for ca in bundle.authorities() {
            roots
                .add(CertificateDer::from(ca.as_bytes().to_vec()))
                .map_err(|e| TlsError::Material(format!("bundle authority: {e}")))?;
        }
        let chain = svid
            .cert_chain()
            .iter()
            .map(|c| CertificateDer::from(c.as_bytes().to_vec()))
            .collect();
        let key = PrivateKeyDer::Pkcs8(svid.private_key().as_bytes().to_vec().into());
        Ok(Arc::new(Material {
            spiffe_id: svid.spiffe_id().clone(),
            chain,
            key,
            roots: Arc::new(roots),
        }))
    }

    fn changed(&self) -> BoxFuture<'_, Result<(), TlsError>> {
        let mut updates = self.source.updated();
        Box::pin(async move {
            updates
                .changed()
                .await
                .map(|_generation| ())
                .map_err(|e| TlsError::WorkloadApi(e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::WorkloadApiSource;
    use crate::TlsError;

    /// A private directory of this test's own (mode 0700, a random name, gone on drop) and
    /// the socket path inside it: never a predictable name in the shared temp directory.
    fn socket_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("a private directory");
        let path = dir.path().join("agent.sock");
        (dir, path)
    }

    #[tokio::test]
    async fn a_workload_api_that_never_answers_fails_the_connect_within_the_wait() {
        let (_dir, path) = socket_dir();
        // Bound, never accepted: a connect succeeds and the first SVID never comes.
        let _listener = tokio::net::UnixListener::bind(&path).expect("bind");
        let started = Instant::now();
        let err = WorkloadApiSource::connect(
            &crate::endpoint(&path.to_string_lossy()),
            Duration::from_millis(300),
        )
        .await
        .err()
        .expect("no SVID, no source");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(
            matches!(&err, TlsError::WorkloadApi(m) if m.contains("within")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_workload_api_socket_that_does_not_exist_fails_the_connect_within_the_wait() {
        let (_dir, path) = socket_dir();
        let started = Instant::now();
        let err = WorkloadApiSource::connect(
            &crate::endpoint(&path.to_string_lossy()),
            Duration::from_millis(300),
        )
        .await
        .err()
        .expect("no socket, no source");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(matches!(err, TlsError::WorkloadApi(_)), "{err}");
    }
}
