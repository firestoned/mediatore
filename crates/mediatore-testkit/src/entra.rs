// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Fixtures for the Entra path (ADR-0016): an RSA-2048 key generated once per test
//! process and a self-signed certificate on it, standing in for the certificate
//! credential registered on an app. Nothing is embedded in the source: the fake issuer
//! accepts a client assertion signed by this key once the certificate is registered for
//! the client, and the fake `OpenBao` holds the same key when a test asks for an RSA
//! transit key. Test material only, never written anywhere but a test's own directory.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// The generated client credential: the key as PKCS#8 (DER and PEM) and its certificate.
pub struct ClientCredential {
    /// PKCS#8 DER of the RSA key, for the fake `OpenBao`.
    pub key_der: Vec<u8>,
    /// The same key as PEM, as `issuers[].entra.key_file` would hold it.
    pub key_pem: String,
    /// A self-signed certificate on the key, as registered on the app.
    pub certificate_pem: String,
}

/// A single-object PEM around `der`.
///
/// # Panics
/// Never in practice: base64 is ASCII, so every 64-byte chunk is valid UTF-8.
#[must_use]
pub fn pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("base64 is ascii"))
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// A fresh RSA-2048 key as PKCS#8 PEM, for a test that needs a key that is not the
/// certificate's.
///
/// # Panics
/// On a key generation failure; this is test scaffolding.
#[must_use]
pub fn fresh_rsa_key_pem() -> String {
    let pair = KeyPair::generate(KeySize::Rsa2048).expect("generate an RSA key");
    pem("PRIVATE KEY", pair.as_der().expect("pkcs8").as_ref())
}

/// A fresh P-256 signing key as PKCS#8 PEM, for a test's STS: no test key lives in the
/// source.
///
/// # Panics
/// On a key generation failure; this is test scaffolding.
#[must_use]
pub fn fresh_p256_key_pem() -> String {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
    let pair =
        EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("generate a P-256 key");
    pem("PRIVATE KEY", pair.to_pkcs8v1().expect("pkcs8").as_ref())
}

/// The process-wide client credential, generated on first use.
///
/// # Panics
/// On a key generation or certificate failure; this is test scaffolding.
pub fn client_credential() -> &'static ClientCredential {
    static CREDENTIAL: OnceLock<ClientCredential> = OnceLock::new();
    CREDENTIAL.get_or_init(|| {
        let pair = KeyPair::generate(KeySize::Rsa2048).expect("generate an RSA key");
        let key_der = pair.as_der().expect("pkcs8").as_ref().to_vec();
        let signer = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.clone()),
            &rcgen::PKCS_RSA_SHA256,
        )
        .expect("rcgen takes the RSA key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "mediatore test client assertion");
        let cert = params
            .self_signed(&signer)
            .expect("self-signed certificate");
        ClientCredential {
            key_pem: pem("PRIVATE KEY", &key_der),
            certificate_pem: pem("CERTIFICATE", cert.der()),
            key_der,
        }
    })
}

/// Write the key and the certificate into `dir`, as a Secret volume would hold them:
/// `(key_file, certificate_file)`.
///
/// # Panics
/// On an I/O failure; this is test scaffolding.
pub fn write_client_credential(dir: &Path) -> (PathBuf, PathBuf) {
    let cred = client_credential();
    let key = dir.join("key.pem");
    let cert = dir.join("cert.pem");
    std::fs::write(&key, &cred.key_pem).expect("write key");
    std::fs::write(&cert, &cred.certificate_pem).expect("write certificate");
    (key, cert)
}

/// A fresh directory for one test under the workspace's `target/`, never the shared
/// system temporary directory: `target/testkit-tmp/<uuid>`.
///
/// # Panics
/// On an I/O failure; this is test scaffolding.
#[must_use]
pub fn tempdir() -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/testkit-tmp")
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&dir).expect("create the test directory");
    dir
}
