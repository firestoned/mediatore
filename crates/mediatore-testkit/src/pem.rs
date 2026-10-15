// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! PEM armour and a throwaway CA, for fixtures (rcgen is built without its `pem` feature).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

/// Wrap `der` in PEM armour under `label` (`CERTIFICATE`, `PRIVATE KEY`).
#[must_use]
pub fn armour(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        // Base64 is ASCII, so every chunk is valid UTF-8.
        .filter_map(|c| std::str::from_utf8(c).ok())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// A fresh self-signed CA certificate as PEM: what a test hands to code that takes a
/// `ca_file`. Its key is dropped, so nothing can be signed by it.
///
/// # Panics
///
/// If rcgen cannot generate a key or sign the certificate, which no test should see.
#[must_use]
pub fn fixture_ca_pem() -> String {
    mediatore_proto::tls::ensure_provider();
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a P-256 key");
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "mediatore fixture CA");
    ca.distinguished_name = dn;
    let cert = ca.self_signed(&key).expect("a self-signed CA");
    armour("CERTIFICATE", cert.der())
}
