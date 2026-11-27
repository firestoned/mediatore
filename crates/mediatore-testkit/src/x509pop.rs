// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! A host's signing CA for the `x509pop` attestation path (ADR-0049), for fixtures: the
//! certificate an administrator asserts on a `Provider` (`spec.attestation.hostCa`), and the
//! leaves its signer issues to its guests. Stands in for banlieue's `banlieue-attestation-ca`.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

use crate::pem::armour;

/// A throwaway host CA and its key.
pub struct HostCa {
    params: CertificateParams,
    key: KeyPair,
    pem: String,
}

fn named(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    p.distinguished_name = dn;
    p
}

impl HostCa {
    /// A host CA as ADR-0049 decision 2 needs it: common name `cn`, `cA` true, a path length
    /// of zero.
    ///
    /// # Panics
    /// If rcgen cannot generate a key or sign, which no test should see.
    #[must_use]
    pub fn new(cn: &str) -> Self {
        Self::with_constraints(cn, IsCa::Ca(BasicConstraints::Constrained(0)))
    }

    /// A self-signed certificate named `cn` with the given `basicConstraints`: the shapes a
    /// host CA must *not* have (a CA that may sign further CAs, a certificate that is none).
    ///
    /// # Panics
    /// If rcgen cannot generate a key or sign, which no test should see.
    #[must_use]
    pub fn with_constraints(cn: &str, is_ca: IsCa) -> Self {
        mediatore_proto::tls::ensure_provider();
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a P-256 key");
        let mut params = named(cn);
        params.is_ca = is_ca;
        let cert = params.self_signed(&key).expect("a self-signed host CA");
        let pem = armour("CERTIFICATE", cert.der());
        Self { params, key, pem }
    }

    /// The CA certificate, as PEM: what goes inline on the `Provider`.
    #[must_use]
    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// A leaf for a guest, as the host's signer issues it (decision 3): subject common name
    /// `subject_cn`, `CA:FALSE`, `digitalSignature`, signed by this CA. As PEM. The guest's
    /// key is generated and dropped: a fixture for what reads the certificate, not for an
    /// agent that must prove possession.
    ///
    /// # Panics
    /// If rcgen cannot generate a key or sign, which no test should see.
    #[must_use]
    pub fn leaf_pem(&self, subject_cn: &str) -> String {
        let guest = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a P-256 key");
        let mut leaf = named(subject_cn);
        leaf.is_ca = IsCa::ExplicitNoCa;
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let issuer = Issuer::from_params(&self.params, &self.key);
        let cert = leaf.signed_by(&guest, &issuer).expect("a signed leaf");
        armour("CERTIFICATE", cert.der())
    }
}
