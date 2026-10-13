// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Client configs for the guests: present an SVID, accept one server identity.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::client::danger::ServerCertVerifier;
use spiffe::{SpiffeId, TrustDomain};

use crate::provider::sandbox_provider;
use crate::verify::{SpiffeServerVerifier, exact};
use crate::{Material, TlsError};

/// A verifier that accepts only the server whose SPIFFE ID is exactly `server`, chained to
/// `roots`. Exposed so a client with no identity of its own (a probe, a test) can be built.
pub fn server_verifier(
    roots: Arc<RootCertStore>,
    local: TrustDomain,
    server: SpiffeId,
) -> Arc<dyn ServerCertVerifier> {
    Arc::new(SpiffeServerVerifier::new(roots, local, exact(server)))
}

/// TLS 1.3 client config on [`sandbox_provider`] (X25519MLKEM768 only, AES-256-GCM):
/// `material`'s SVID as the client certificate, the server accepted only if its SPIFFE ID
/// is exactly `server` (ADR-0007 decision 5). SNI and hostnames carry no trust, so the
/// broker's address is free to change.
pub fn client_config(material: &Material, server: &SpiffeId) -> Result<ClientConfig, TlsError> {
    mediatore_proto::tls::ensure_provider();
    let verifier = server_verifier(
        material.roots.clone(),
        material.trust_domain().clone(),
        server.clone(),
    );
    ClientConfig::builder_with_provider(sandbox_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(format!("protocol versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(material.chain.clone(), material.key.clone_key())
        .map_err(|e| TlsError::Config(format!("client identity: {e}")))
}
