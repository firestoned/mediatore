// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The sandbox leg's cryptography, observed on real handshakes over loopback: TLS 1.3,
//! X25519MLKEM768 and nothing else, AES-256-GCM-SHA384, and the verifiers accepting
//! ML-DSA SVIDs. An integration test rather than a unit test because the testkit depends
//! on this crate, and a dev-dependency cycle gives the lib's own tests a second copy.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use mediatore_testkit::{MemoryMaterial, TestCa};
use mediatore_tls::{
    Authorizer, Material, SpiffeId, TlsConfigs, client_config, serve, server_verifier,
};
use rustls::pki_types::ServerName;
use rustls::{CipherSuite, ClientConfig, NamedGroup, ProtocolVersion};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const TD: &str = "sandbox.test";

fn broker() -> SpiffeId {
    SpiffeId::new(format!("spiffe://{TD}/mediatore")).unwrap()
}

fn node() -> String {
    format!("spiffe://{TD}/banlieue/node/ab")
}

/// A listener serving `/healthz` with `ca`'s broker SVID; returns its address.
async fn listen(ca: &TestCa) -> SocketAddr {
    let source = MemoryMaterial::new(ca.svid(&broker().to_string()));
    let node = node();
    let authorizer: Authorizer = Arc::new(move |id| id.to_string() == node);
    let configs = TlsConfigs::spawn(source, authorizer).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route("/healthz", get(|| async { "ok" }));
    tokio::spawn(serve(listener, configs, router, std::future::pending()));
    addr
}

async fn handshake(
    addr: SocketAddr,
    cfg: ClientConfig,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::from(IpAddr::V4(Ipv4Addr::LOCALHOST)), tcp)
        .await
}

#[tokio::test]
async fn the_handshake_is_tls13_mlkem_hybrid_aes256() {
    let ca = TestCa::new(TD);
    let addr = listen(&ca).await;
    let tls = handshake(addr, client_config(&ca.svid(&node()), &broker()).unwrap())
        .await
        .expect("handshake");
    let (_, conn) = tls.get_ref();
    assert_eq!(conn.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(
        conn.negotiated_key_exchange_group()
            .map(rustls::crypto::SupportedKxGroup::name),
        Some(NamedGroup::X25519MLKEM768)
    );
    assert_eq!(
        conn.negotiated_cipher_suite().map(|s| s.suite()),
        Some(CipherSuite::TLS13_AES_256_GCM_SHA384)
    );
}

#[tokio::test]
async fn a_client_without_mlkem_does_not_get_in() {
    let ca = TestCa::new(TD);
    let addr = listen(&ca).await;
    // Same identity, same trust, but only classical key exchange on offer.
    let m: Material = ca.svid(&node());
    let mut classical = rustls::crypto::aws_lc_rs::default_provider();
    classical.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let cfg = ClientConfig::builder_with_provider(Arc::new(classical))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier(
            m.roots.clone(),
            m.trust_domain().clone(),
            broker(),
        ))
        .with_client_auth_cert(m.chain.clone(), m.key.clone_key())
        .unwrap();
    assert!(handshake(addr, cfg).await.is_err());
}

#[tokio::test]
async fn ml_dsa_svids_pass_the_same_verifiers() {
    // What SPIRE does not issue yet, the path already accepts: a trust domain whose CA
    // and SVIDs are ML-DSA-65 completes the handshake on both sides.
    let ca = TestCa::with_algorithm(TD, &rcgen::PKCS_ML_DSA_65);
    let addr = listen(&ca).await;
    let tls = handshake(addr, client_config(&ca.svid(&node()), &broker()).unwrap())
        .await
        .expect("ML-DSA handshake");
    assert_eq!(
        tls.get_ref()
            .1
            .negotiated_key_exchange_group()
            .map(rustls::crypto::SupportedKxGroup::name),
        Some(NamedGroup::X25519MLKEM768)
    );
}
