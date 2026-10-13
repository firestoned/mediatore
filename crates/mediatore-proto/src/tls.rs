// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The process-wide TLS provider (ADR-0007 decision 6).
//!
//! Every TLS client and server in the workspace is rustls on `aws-lc-rs`, and nothing else
//! is compiled in: `reqwest` and `kube` are built without a provider and `cargo deny` bans
//! `ring`. `reqwest` refuses to build a client until a provider is installed, so every
//! binary calls this first and every constructor that builds a client calls it too.
//!
//! Post-quantum posture: the provider is built with rustls's `prefer-post-quantum`, so
//! every key share we offer lists X25519MLKEM768 first and a peer that supports it gets
//! ML-KEM; the sandbox leg, where both ends are ours, accepts nothing else
//! (`mediatore-tls`). Outbound clients to systems we do not control (the identity provider, the
//! Kubernetes API) keep a classical fallback, since refusing them would only deny service.

/// Install `aws-lc-rs` as the default provider if none is installed yet. Idempotent: a
/// second call is a no-op, and with `ring` banned from the graph the provider already in
/// place can only be this one.
pub fn ensure_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Err means another thread won the race to install the same provider.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

/// A TLS 1.3-only client config over the Mozilla root store, for HTTPS to systems we do
/// not operate (identity-provider discovery, JWKS and token endpoints). Key exchange prefers
/// X25519MLKEM768 and falls back to classical groups, because the far end is not ours.
pub fn https_client_config() -> rustls::ClientConfig {
    ensure_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_aws_lc_rs_once_and_tolerates_repeats() {
        ensure_provider();
        ensure_provider();
        let p = rustls::crypto::CryptoProvider::get_default().expect("a provider");
        // aws-lc-rs is the only provider compiled in (cargo deny bans ring), and with
        // `prefer-post-quantum` its first key exchange group is the ML-KEM hybrid: that
        // is the key share every client we build sends first.
        assert_eq!(
            p.kx_groups.first().map(|g| g.name()),
            Some(rustls::NamedGroup::X25519MLKEM768),
            "expected X25519MLKEM768 to be preferred"
        );
    }

    #[test]
    fn the_https_client_offers_mlkem_first() {
        let cfg = https_client_config();
        assert_eq!(
            cfg.crypto_provider().kx_groups.first().map(|g| g.name()),
            Some(rustls::NamedGroup::X25519MLKEM768)
        );
    }
}
