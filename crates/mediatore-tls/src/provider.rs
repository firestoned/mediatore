// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The cryptography of the sandbox leg, pinned.

use std::sync::{Arc, OnceLock};

use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{cipher_suite, default_provider, kx_group};

/// `aws-lc-rs` restricted to what the sandbox listener and the guests use between
/// themselves: X25519MLKEM768 as the only key exchange group (post-quantum hybrid, the
/// same posture as the homelab datastore's TLS), TLS 1.3 AES-256-GCM-SHA384 as the only
/// cipher suite. Everything else in the provider (signature verification, the random
/// source, key loading) is its default, which includes ML-DSA.
pub fn sandbox_provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            let mut p = default_provider();
            p.kx_groups = vec![kx_group::X25519MLKEM768];
            p.cipher_suites = vec![cipher_suite::TLS13_AES_256_GCM_SHA384];
            Arc::new(p)
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_mlkem_hybrid_and_aes_256_remain() {
        let p = sandbox_provider();
        assert_eq!(
            p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>(),
            vec![rustls::NamedGroup::X25519MLKEM768]
        );
        assert_eq!(
            p.cipher_suites
                .iter()
                .map(rustls::SupportedCipherSuite::suite)
                .collect::<Vec<_>>(),
            vec![rustls::CipherSuite::TLS13_AES_256_GCM_SHA384]
        );
        assert!(
            p.signature_verification_algorithms
                .supported_schemes()
                .contains(&rustls::SignatureScheme::ML_DSA_65),
            "ML-DSA verification stays available for the day SPIRE issues it"
        );
    }
}
