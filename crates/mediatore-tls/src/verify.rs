// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The two SPIFFE verifiers: leaf constraints, local trust domain, chain, authorizer.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ParsedCertificate, WebPkiClientVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use spiffe::{SpiffeId, TrustDomain};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::oid::AssociatedOid;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

use crate::TlsError;
use crate::provider::sandbox_provider;

/// Decides whether an authenticated peer SPIFFE ID may proceed. Runs after the chain
/// verified; a `false` closes the handshake.
pub type Authorizer = Arc<dyn Fn(&SpiffeId) -> bool + Send + Sync>;

/// Accept exactly `id` and nothing else.
pub fn exact(id: SpiffeId) -> Authorizer {
    Arc::new(move |peer| *peer == id)
}

/// Why a peer certificate was refused. Logged on the refusing side; the peer sees a TLS alert.
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    /// The leaf is not shaped like an SVID.
    #[error("leaf certificate: {0}")]
    Leaf(String),
    /// The SVID belongs to another trust domain.
    #[error("trust domain {0} is not the local {1}")]
    ForeignTrustDomain(TrustDomain, TrustDomain),
    /// Authenticated, but not allowed here.
    #[error("{0} is not authorized on this listener")]
    Unauthorized(SpiffeId),
}

/// SPIFFE leaf constraints, then the SPIFFE ID from the single URI SAN.
///
/// Refuses a CA certificate, a key usage that permits signing certificates or CRLs, a missing
/// `digitalSignature`, and an ID without a path (the trust domain's root is never a workload).
pub fn leaf_spiffe_id(der: &CertificateDer<'_>) -> Result<SpiffeId, PeerError> {
    let cert =
        Certificate::from_der(der).map_err(|e| PeerError::Leaf(format!("not parseable: {e}")))?;
    let mut key_usage = None;
    for ext in cert
        .tbs_certificate()
        .extensions()
        .map_or(&[][..], Vec::as_slice)
    {
        if ext.extn_id == BasicConstraints::OID {
            let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
                .map_err(|e| PeerError::Leaf(format!("basic constraints: {e}")))?;
            if bc.ca {
                return Err(PeerError::Leaf("basic constraints CA is true".into()));
            }
        } else if ext.extn_id == KeyUsage::OID {
            key_usage = Some(
                KeyUsage::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| PeerError::Leaf(format!("key usage: {e}")))?,
            );
        }
    }
    match key_usage {
        None => return Err(PeerError::Leaf("key usage extension is missing".into())),
        Some(ku) => {
            if ku.key_cert_sign() {
                return Err(PeerError::Leaf("keyCertSign key usage is set".into()));
            }
            if ku.crl_sign() {
                return Err(PeerError::Leaf("cRLSign key usage is set".into()));
            }
            if !ku.digital_signature() {
                return Err(PeerError::Leaf(
                    "digitalSignature key usage is not set".into(),
                ));
            }
        }
    }
    let id = spiffe::cert::spiffe_id_from_der(der)
        .map_err(|e| PeerError::Leaf(format!("SPIFFE ID: {e}")))?;
    if id.path().is_empty() {
        return Err(PeerError::Leaf("SPIFFE ID has no path".into()));
    }
    Ok(id)
}

fn refuse(e: PeerError) -> rustls::Error {
    rustls::Error::Other(rustls::OtherError(Arc::new(e)))
}

fn local_only(id: &SpiffeId, local: &TrustDomain) -> Result<(), rustls::Error> {
    if id.trust_domain() == local {
        Ok(())
    } else {
        Err(refuse(PeerError::ForeignTrustDomain(
            id.trust_domain().clone(),
            local.clone(),
        )))
    }
}

/// Server side: verifies the client certificate. Chain verification is rustls's
/// `WebPkiClientVerifier` over the trust domain's bundle (`clientAuth` required).
pub(crate) struct SpiffeClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    local: TrustDomain,
    authorizer: Authorizer,
}

impl SpiffeClientVerifier {
    pub(crate) fn new(
        roots: Arc<RootCertStore>,
        local: TrustDomain,
        authorizer: Authorizer,
    ) -> Result<Self, TlsError> {
        let inner = WebPkiClientVerifier::builder_with_provider(roots, sandbox_provider())
            .build()
            .map_err(|e| TlsError::Config(format!("client verifier: {e}")))?;
        Ok(Self {
            inner,
            local,
            authorizer,
        })
    }
}

impl std::fmt::Debug for SpiffeClientVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeClientVerifier")
            .field("local", &self.local.to_string())
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for SpiffeClientVerifier {
    /// No hint: the peer learns nothing about the bundle from the request.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let id = leaf_spiffe_id(end_entity).map_err(refuse)?;
        local_only(&id, &self.local)?;
        let ok = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        if !(self.authorizer)(&id) {
            tracing::info!(spiffe_id = %id, "peer authenticated but not authorized here");
            return Err(refuse(PeerError::Unauthorized(id)));
        }
        Ok(ok)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Client side: verifies the server certificate by SPIFFE ID, never by hostname or SNI.
/// Chain verification is rustls's trust-anchor path check (`serverAuth` required).
pub(crate) struct SpiffeServerVerifier {
    roots: Arc<RootCertStore>,
    algs: WebPkiSupportedAlgorithms,
    local: TrustDomain,
    authorizer: Authorizer,
}

impl SpiffeServerVerifier {
    pub(crate) fn new(
        roots: Arc<RootCertStore>,
        local: TrustDomain,
        authorizer: Authorizer,
    ) -> Self {
        mediatore_proto::tls::ensure_provider();
        let algs = sandbox_provider().signature_verification_algorithms;
        Self {
            roots,
            algs,
            local,
            authorizer,
        }
    }
}

impl std::fmt::Debug for SpiffeServerVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeServerVerifier")
            .field("local", &self.local.to_string())
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for SpiffeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let id = leaf_spiffe_id(end_entity).map_err(refuse)?;
        local_only(&id, &self.local)?;
        let cert = ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.algs.all,
        )?;
        if !(self.authorizer)(&id) {
            return Err(refuse(PeerError::Unauthorized(id)));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}
