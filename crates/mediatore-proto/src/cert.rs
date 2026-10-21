// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The X.509 certificate a client assertion names (ADR-0016): its SHA-256 thumbprint for
//! the `x5t#S256` header, and the RSA public key the signature verifies against.

use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::{DecodePem, Encode};

/// `rsaEncryption`.
const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";

/// Why a certificate could not serve a client assertion.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// Not a PEM-encoded X.509 certificate.
    #[error("certificate: {0}")]
    Parse(String),
    /// The certificate's key is not RSA, so it cannot verify a PS256 assertion.
    #[error("certificate key is not RSA ({0})")]
    NotRsa(String),
}

/// A client certificate, as registered on an Entra app registration.
#[derive(Debug, Clone)]
pub struct ClientCertificate {
    der: Vec<u8>,
    public_key: Vec<u8>,
}

impl ClientCertificate {
    /// Parse the first certificate in `pem`; its key must be RSA.
    pub fn from_pem(pem: &[u8]) -> Result<Self, CertError> {
        let cert = Certificate::from_pem(pem).map_err(|e| CertError::Parse(e.to_string()))?;
        let spki = cert.tbs_certificate().subject_public_key_info();
        let oid = spki.algorithm.oid.to_string();
        if oid != RSA_ENCRYPTION_OID {
            return Err(CertError::NotRsa(oid));
        }
        let public_key = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| CertError::Parse("public key is not byte-aligned".into()))?
            .to_vec();
        let der = cert.to_der().map_err(|e| CertError::Parse(e.to_string()))?;
        Ok(Self { der, public_key })
    }

    /// SHA-256 of the DER encoding: what `x5t#S256` carries, before base64url.
    #[must_use]
    pub fn thumbprint_s256(&self) -> [u8; 32] {
        Sha256::digest(&self.der).into()
    }

    /// The RSA public key as PKCS#1 `RSAPublicKey` DER (the bit string inside the
    /// `SubjectPublicKeyInfo`), the form a JWT verifier takes.
    #[must_use]
    pub fn rsa_public_key_der(&self) -> &[u8] {
        &self.public_key
    }

    /// The DER encoding of the whole certificate.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    #[test]
    fn a_non_certificate_and_an_ec_certificate_are_refused() {
        assert!(matches!(
            ClientCertificate::from_pem(b"nope"),
            Err(CertError::Parse(_))
        ));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["x.example".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let body = base64::engine::general_purpose::STANDARD.encode(cert.der());
        let lines: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            lines.join("\n")
        );
        assert!(matches!(
            ClientCertificate::from_pem(pem.as_bytes()),
            Err(CertError::NotRsa(_))
        ));
    }
}
