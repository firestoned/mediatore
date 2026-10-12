// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The process-wide TLS provider (ADR-0007 decision 6).
//!
//! Every TLS client and server in the workspace is rustls on `aws-lc-rs`, and nothing else
//! is compiled in: `reqwest` and `kube` are built without a provider and `cargo deny` bans
//! `ring`. `reqwest` refuses to build a client until a provider is installed, so every
//! binary calls this first and every constructor that builds a client calls it too.

/// Install `aws-lc-rs` as the default provider if none is installed yet. Idempotent: a
/// second call is a no-op, and with `ring` banned from the graph the provider already in
/// place can only be this one.
pub fn ensure_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Err means another thread won the race to install the same provider.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_aws_lc_rs_once_and_tolerates_repeats() {
        ensure_provider();
        ensure_provider();
        let p = rustls::crypto::CryptoProvider::get_default().expect("a provider");
        // aws-lc-rs is the only provider compiled in (cargo deny bans ring), so the
        // installed one offers its post-quantum hybrid key exchange.
        assert!(
            p.kx_groups
                .iter()
                .any(|g| g.name() == rustls::NamedGroup::X25519MLKEM768),
            "expected the aws-lc-rs provider with X25519MLKEM768"
        );
    }
}
