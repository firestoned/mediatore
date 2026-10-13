// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! A test CA that mints SPIFFE-shaped X.509 SVIDs, and an in-memory material source, so
//! the e2e suite drives the real mTLS verifiers with no SPIRE (ADR-0007 decision 8).
//!
//! The SVIDs have the shape SPIRE issues: not a CA, `digitalSignature` and `keyAgreement`,
//! `serverAuth` and `clientAuth`, one URI SAN. Everything is generated per process and
//! never written anywhere.

use std::sync::{Arc, RwLock};

use futures::future::BoxFuture;
use mediatore_tls::{Material, MaterialSource, SpiffeId, TlsError};
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SignatureAlgorithm,
};
use rustls::RootCertStore;
use rustls::pki_types::PrivateKeyDer;
use time::{Duration, OffsetDateTime};

/// A trust domain's root CA for tests.
pub struct TestCa {
    trust_domain: String,
    issuer: Issuer<'static, KeyPair>,
    roots: Arc<RootCertStore>,
    alg: &'static SignatureAlgorithm,
}

impl TestCa {
    /// A fresh self-signed root for `trust_domain`, ECDSA P-256 like SPIRE's default.
    pub fn new(trust_domain: &str) -> Self {
        Self::with_algorithm(trust_domain, &rcgen::PKCS_ECDSA_P256_SHA256)
    }

    /// A fresh self-signed root for `trust_domain` whose key, and every SVID key, uses
    /// `alg` (for example `rcgen::PKCS_ML_DSA_65`).
    ///
    /// # Panics
    /// On key generation or signing failure, which is a broken test environment.
    pub fn with_algorithm(trust_domain: &str, alg: &'static SignatureAlgorithm) -> Self {
        mediatore_proto::tls::ensure_provider();
        let key = KeyPair::generate_for(alg).expect("ca key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "mediatore-testkit");
        dn.push(DnType::CommonName, format!("{trust_domain} test CA"));
        params.distinguished_name = dn;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(1);
        let cert = params.self_signed(&key).expect("ca cert");
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).expect("root");
        Self {
            trust_domain: trust_domain.to_owned(),
            issuer: Issuer::new(params, key),
            roots: Arc::new(roots),
            alg,
        }
    }

    /// The trust domain this CA signs for.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// The bundle: this root alone.
    pub fn roots(&self) -> Arc<RootCertStore> {
        self.roots.clone()
    }

    /// An SVID for `spiffe_id`, valid for the next hour.
    pub fn svid(&self, spiffe_id: &str) -> Material {
        let now = OffsetDateTime::now_utc();
        self.svid_valid_between(
            spiffe_id,
            now - Duration::minutes(1),
            now + Duration::hours(1),
        )
    }

    /// An SVID for `spiffe_id` whose validity ended an hour ago.
    pub fn expired_svid(&self, spiffe_id: &str) -> Material {
        let now = OffsetDateTime::now_utc();
        self.svid_valid_between(
            spiffe_id,
            now - Duration::hours(2),
            now - Duration::hours(1),
        )
    }

    /// A certificate signed by this CA that carries `spiffe_id` but is flagged as a CA
    /// with `keyCertSign`: a valid chain, the wrong shape. The verifiers must refuse it.
    ///
    /// # Panics
    /// If `spiffe_id` is not a SPIFFE ID, or on signing failure.
    pub fn ca_shaped_svid(&self, spiffe_id: &str) -> Material {
        let now = OffsetDateTime::now_utc();
        let mut m = self.svid_valid_between(
            spiffe_id,
            now - Duration::minutes(1),
            now + Duration::hours(1),
        );
        let id = SpiffeId::new(spiffe_id).expect("a SPIFFE ID");
        let key = KeyPair::generate_for(self.alg).expect("key");
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(spiffe_id).expect("ia5 uri"),
        )];
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.not_before = now - Duration::minutes(1);
        params.not_after = now + Duration::hours(1);
        let cert = params.signed_by(&key, &self.issuer).expect("cert");
        m.spiffe_id = id;
        m.chain = vec![cert.der().clone()];
        m.key = PrivateKeyDer::Pkcs8(key.serialize_der().into());
        m
    }

    /// An SVID for `spiffe_id` with an explicit validity window.
    ///
    /// # Panics
    /// If `spiffe_id` is not a SPIFFE ID, or on signing failure.
    pub fn svid_valid_between(
        &self,
        spiffe_id: &str,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> Material {
        let id = SpiffeId::new(spiffe_id).expect("a SPIFFE ID");
        let key = KeyPair::generate_for(self.alg).expect("svid key");
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(spiffe_id).expect("ia5 uri"),
        )];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyAgreement,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "mediatore-testkit");
        params.distinguished_name = dn;
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params.signed_by(&key, &self.issuer).expect("svid");
        Material {
            spiffe_id: id,
            chain: vec![cert.der().clone()],
            key: PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            roots: self.roots.clone(),
        }
    }
}

impl std::fmt::Debug for TestCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCa")
            .field("trust_domain", &self.trust_domain)
            .finish_non_exhaustive()
    }
}

/// Material held in memory and swapped on demand, to test rotation.
#[derive(Debug)]
pub struct MemoryMaterial {
    current: RwLock<Arc<Material>>,
    notify: tokio::sync::Notify,
}

impl MemoryMaterial {
    /// Start with `material`.
    pub fn new(material: Material) -> Arc<Self> {
        Arc::new(Self {
            current: RwLock::new(Arc::new(material)),
            notify: tokio::sync::Notify::new(),
        })
    }

    /// Replace the material and wake whoever waits on [`MaterialSource::changed`].
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn rotate(&self, material: Material) {
        *self.current.write().expect("material lock") = Arc::new(material);
        self.notify.notify_one();
    }
}

impl MaterialSource for MemoryMaterial {
    fn current(&self) -> Result<Arc<Material>, TlsError> {
        Ok(self.current.read().expect("material lock").clone())
    }

    fn changed(&self) -> BoxFuture<'_, Result<(), TlsError>> {
        Box::pin(async {
            self.notify.notified().await;
            Ok(())
        })
    }
}
