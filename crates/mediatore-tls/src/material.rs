// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Where SVIDs and bundles come from.

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use spiffe::x509_source::SvidPicker;
use spiffe::{SpiffeId, TrustDomain, X509Source, X509Svid};

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
    /// The path of the one SPIFFE ID this source serves, when it was asked for one
    /// ([`Self::connect_as`]); `None` takes the agent's default SVID.
    required: Option<String>,
}

/// Selects the SVID whose SPIFFE ID has exactly the path asked for, among however many the
/// agent hands this workload (a user with two entries is handed two, ADR-0053 decision 2).
/// The trust domain is the agent's own: a role learns it from its SVID, so the ID asked
/// for is `spiffe://<the agent's trust domain><path>`, whole, never a prefix of it.
/// None with that path selects nothing: the `spiffe` crate never falls back to another SVID.
struct ExactPath(String);

impl SvidPicker for ExactPath {
    fn pick_svid(&self, svids: &[Arc<X509Svid>]) -> Option<usize> {
        svids
            .iter()
            .position(|svid| svid.spiffe_id().path() == self.0)
    }
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
        Ok(Self {
            source,
            required: None,
        })
    }

    /// [`Self::connect`] for one stated SPIFFE ID (ADR-0053 decision 2), given as its path
    /// (`/gateway/authorizer`): the SVID whose ID is exactly `spiffe://<trust domain><path>`
    /// is selected among those the agent hands this workload, at the first answer and at
    /// every rotation, and the agent's default is never taken. No SVID of that ID within
    /// `wait` is an error, whatever other SVIDs the agent offered: a role that must act
    /// under one name does not start under another.
    pub async fn connect_as(endpoint: &str, path: &str, wait: Duration) -> Result<Self, TlsError> {
        let build = X509Source::builder()
            .endpoint(endpoint)
            .picker(ExactPath(path.to_owned()))
            .build();
        let source = tokio::time::timeout(wait, build)
            .await
            .map_err(|_elapsed| {
                TlsError::WorkloadApi(format!(
                    "no SVID with the path {path} from {endpoint} within {}s",
                    wait.as_secs_f32()
                ))
            })?
            .map_err(|e| TlsError::WorkloadApi(e.to_string()))?;
        Ok(Self {
            source,
            required: Some(path.to_owned()),
        })
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
        // The picker already selected by ID; checked again here so that nothing this source
        // hands out can carry another name, whatever the stream delivered.
        if let Some(required) = &self.required
            && svid.spiffe_id().path() != required
        {
            return Err(TlsError::Material(format!(
                "the selected SVID is {}, whose path is not {required}",
                svid.spiffe_id()
            )));
        }
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

    use std::sync::Arc;

    use spiffe::x509_source::SvidPicker as _;
    use spiffe::{SpiffeId, X509Svid};

    use super::{ExactPath, WorkloadApiSource};
    use crate::TlsError;

    /// An SVID as the Workload API would hand it: a leaf with one URI SAN and
    /// `digitalSignature`, self-signed here since the picker reads the ID alone.
    fn svid(spiffe_id: &str) -> Arc<X509Svid> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            spiffe_id.try_into().expect("an IA5 string"),
        )];
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let cert = params.self_signed(&key).expect("a certificate");
        Arc::new(
            X509Svid::parse_from_der(cert.der().as_ref(), &key.serialize_der()).expect("an SVID"),
        )
    }

    #[test]
    fn a_source_asked_for_one_id_returns_that_svid_among_several_and_fails_without_it() {
        // ADR-0053 decision 2. A user that holds two entries is handed two SVIDs; the
        // source's selection is by ID, exact, wherever the SVID sits in the answer, and it
        // selects nothing (which the `spiffe` crate never turns into a fallback) when the
        // ID is not among them.
        const GATEWAY: &str = "spiffe://sandbox.test/gateway";
        const AUTHORIZER: &str = "spiffe://sandbox.test/gateway/authorizer";
        let asked = SpiffeId::new(AUTHORIZER).expect("a SPIFFE ID");
        let picker = ExactPath(asked.path().to_owned());
        let listener = svid(GATEWAY);
        let authorizer = svid(AUTHORIZER);
        assert_eq!(
            picker.pick_svid(&[listener.clone(), authorizer.clone()]),
            Some(1),
            "the default (first) SVID is not taken"
        );
        assert_eq!(
            picker.pick_svid(&[authorizer.clone(), listener.clone()]),
            Some(0)
        );
        assert_eq!(picker.pick_svid(&[authorizer]), Some(0));
        let near = [
            listener,
            svid("spiffe://sandbox.test/gateway/authorizer/extra"),
            svid("spiffe://sandbox.test/gateway/authorizerx"),
            svid("spiffe://sandbox.test/authorizer"),
            svid("spiffe://sandbox.test/banlieue/node/gateway/authorizer"),
        ];
        assert_eq!(
            picker.pick_svid(&near),
            None,
            "no SVID of that ID, no selection"
        );
        assert_eq!(picker.pick_svid(&[]), None);
    }

    #[tokio::test]
    async fn a_source_asked_for_one_id_fails_the_connect_within_the_wait_and_names_the_id() {
        let (_dir, path) = socket_dir();
        let started = Instant::now();
        let err = WorkloadApiSource::connect_as(
            &crate::endpoint(&path.to_string_lossy()),
            "/gateway/authorizer",
            Duration::from_millis(300),
        )
        .await
        .err()
        .expect("no agent, no source");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(matches!(err, TlsError::WorkloadApi(_)), "{err}");
    }

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
