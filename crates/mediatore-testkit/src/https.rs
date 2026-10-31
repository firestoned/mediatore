// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! A TLS upstream for tests: an axum router behind a fresh CA on an ephemeral loopback
//! port, with the client configuration that trusts it. What the egress proxy forwards to in
//! the e2e suite (ADR-0025), so the upstream leg is real TLS without the public roots.

use std::net::SocketAddr;
use std::sync::Arc;

use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::RootCertStore;
use rustls::pki_types::PrivateKeyDer;
use time::{Duration, OffsetDateTime};

/// A running TLS server for one test.
pub struct TlsUpstream {
    /// Where it listens.
    pub addr: SocketAddr,
    roots: Arc<RootCertStore>,
    ca_pem: String,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for TlsUpstream {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl TlsUpstream {
    /// Serve `router` over TLS 1.3 with a certificate for `127.0.0.1` and `localhost`
    /// signed by a CA generated for this server alone.
    ///
    /// # Panics
    /// On key generation, signing, or a bind failure: a broken test environment.
    pub async fn start(router: axum::Router) -> Self {
        mediatore_proto::tls::ensure_provider();
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
        let mut ca = CertificateParams::default();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "mediatore-testkit upstream CA");
        ca.distinguished_name = dn;
        let now = OffsetDateTime::now_utc();
        ca.not_before = now - Duration::hours(1);
        ca.not_after = now + Duration::days(1);
        let ca_cert = ca.self_signed(&ca_key).expect("ca cert");
        let mut roots = RootCertStore::empty();
        roots.add(ca_cert.der().clone()).expect("root");
        let ca_pem = crate::pem::armour("CERTIFICATE", ca_cert.der());
        let issuer = Issuer::new(ca, ca_key);

        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut leaf = CertificateParams::default();
        leaf.subject_alt_names = vec![
            SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            SanType::DnsName("localhost".try_into().expect("dns name")),
        ];
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.not_before = now - Duration::minutes(1);
        leaf.not_after = now + Duration::hours(1);
        let leaf_cert = leaf.signed_by(&key, &issuer).expect("leaf cert");

        let mut config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf_cert.der().clone()],
                    PrivateKeyDer::Pkcs8(key.serialize_der().into()),
                )
                .expect("server config");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let service = TowerToHyperService::new(router.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Self {
            addr,
            roots: Arc::new(roots),
            ca_pem,
            server,
        }
    }

    /// This server's CA as PEM: what an operator puts in `audiences[].ca_file`.
    #[must_use]
    pub fn ca_pem(&self) -> String {
        self.ca_pem.clone()
    }

    /// A TLS 1.3 client configuration trusting this server's CA and nothing else.
    #[must_use]
    pub fn client_config(&self) -> rustls::ClientConfig {
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(self.roots.clone())
            .with_no_client_auth()
    }

    /// The server as an `egress` endpoint: `127.0.0.1:<port>`.
    #[must_use]
    pub fn endpoint(&self) -> mediatore_proto::Endpoint {
        mediatore_proto::Endpoint {
            host: self.addr.ip().to_string(),
            port: self.addr.port(),
        }
    }
}
