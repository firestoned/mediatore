// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The egress proxy's trust for a policy bundle's direct egress (ADR-0030): a host with no
//! audience, no CA on its route and no credential, reached over TLS the proxy verifies itself.
//!
//! Two things the proxy could not do before, each behind its own setting, neither on by default:
//! trust the operator's private PKI for these hosts (`MEDIATORE_EGRESS_CA`), and accept TLS 1.2
//! from a host that has no 1.3 (`MEDIATORE_EGRESS_MIN_TLS=1.2`, the proxy still offering 1.3
//! first). The upstreams here are real TLS servers, one TLS 1.2 only and one TLS 1.3 only, each
//! with a CA generated for it, so every row is a real handshake.

use std::sync::Arc;

use mediatore_guest::egress::{Phantom, Proxy, Routes, TokenSource};
use mediatore_guest::forward::Dialer;
use mediatore_proto::tls::UpstreamTls;
use mediatore_proto::{Credential, Route, TokenResponse};
use mediatore_testkit::TlsUpstream;

struct NoTokens;

#[async_trait::async_trait]
impl TokenSource for NoTokens {
    async fn token(&self, _: &str) -> anyhow::Result<TokenResponse> {
        anyhow::bail!("a direct egress route fetches no token")
    }
}

fn router() -> axum::Router {
    axum::Router::new().route("/", axum::routing::get(|| async { "up" }))
}

/// One GET through a proxy built with these settings, to `upstream`'s root: the status the
/// workload would see, `502` when the proxy could not reach the upstream.
async fn through_proxy(upstream: &TlsUpstream, ca: Option<&str>, min: UpstreamTls) -> u16 {
    mediatore_proto::tls::ensure_provider();
    let route = Route {
        audience: None,
        endpoint: upstream.endpoint(),
        rules: vec![],
        ca_pem: None,
        credential: Credential::None,
        credential_header: None,
        inject_port: None,
    };
    let proxy = Arc::new(
        Proxy::with_upstream_trust(
            Routes::new(vec![route]).expect("routes"),
            Phantom::generate().expect("phantom"),
            Arc::new(NoTokens),
            Dialer::Direct,
            ca.map(str::as_bytes),
            min,
        )
        .expect("a proxy"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy");
    let url = format!(
        "http://{}/{}/",
        listener.local_addr().expect("addr"),
        upstream.endpoint()
    );
    let server = tokio::spawn(proxy.serve(listener));
    let status = reqwest::get(url).await.expect("the proxy answers").status();
    server.abort();
    status.as_u16()
}

#[tokio::test]
async fn a_tls12_only_host_on_a_private_ca_needs_both_settings_and_neither_is_the_default() {
    let old = TlsUpstream::start_with_versions(router(), &[&rustls::version::TLS12]).await;
    let ca = old.ca_pem();

    // The defaults: TLS 1.3 only, public roots only. The host is refused on both counts.
    assert_eq!(through_proxy(&old, None, UpstreamTls::Tls13).await, 502);
    // The CA alone: trusted, but the proxy offers nothing the host speaks (ProtocolVersion).
    assert_eq!(
        through_proxy(&old, Some(&ca), UpstreamTls::Tls13).await,
        502,
        "a CA does not buy TLS 1.2"
    );
    // TLS 1.2 alone: spoken, but the host's certificate chains to a CA the proxy does not trust.
    assert_eq!(
        through_proxy(&old, None, UpstreamTls::Tls12).await,
        502,
        "TLS 1.2 does not buy trust"
    );
    // Both: the request goes through.
    assert_eq!(
        through_proxy(&old, Some(&ca), UpstreamTls::Tls12).await,
        200
    );
}

#[tokio::test]
async fn allowing_tls12_does_not_downgrade_a_host_that_has_tls13() {
    let current = TlsUpstream::start(router()).await;
    let ca = current.ca_pem();
    // A TLS 1.3 host works at either setting: the proxy offers 1.3 first and gets it.
    assert_eq!(
        through_proxy(&current, Some(&ca), UpstreamTls::Tls13).await,
        200
    );
    assert_eq!(
        through_proxy(&current, Some(&ca), UpstreamTls::Tls12).await,
        200
    );
}

#[tokio::test]
async fn an_egress_ca_with_no_certificate_refuses_the_proxy_rather_than_doing_nothing() {
    let route = Route {
        audience: None,
        endpoint: "192.0.2.1:443".parse().unwrap(),
        rules: vec![],
        ca_pem: None,
        credential: Credential::None,
        credential_header: None,
        inject_port: None,
    };
    let err = Proxy::with_upstream_trust(
        Routes::new(vec![route]).unwrap(),
        Phantom::generate().unwrap(),
        Arc::new(NoTokens),
        Dialer::Direct,
        Some(b"not a certificate"),
        UpstreamTls::Tls13,
    )
    .err()
    .expect("a CA setting that holds no certificate must not start a proxy");
    assert!(err.to_string().contains("no certificate"), "{err:#}");
}

#[tokio::test]
async fn the_clients_that_were_always_tls13_still_cannot_reach_a_tls12_only_host() {
    // `tls12` is a cargo feature of the whole binary now. The identity-provider and registry
    // clients pin their versions and must not have gained 1.2 by it: against a host that has
    // only 1.2 they fail the handshake, with the host's own CA trusted.
    let old = TlsUpstream::start_with_versions(router(), &[&rustls::version::TLS12]).await;
    let ca = old.ca_pem();
    let url = format!("https://{}/", old.endpoint());
    for cfg in [
        mediatore_proto::tls::https_client_config_with_ca(ca.as_bytes()).unwrap(),
        mediatore_proto::tls::https_client_config_with_extra_roots(ca.as_bytes()).unwrap(),
    ] {
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(cfg)
            .build()
            .unwrap();
        let err = client.get(&url).send().await.unwrap_err();
        assert!(
            format!("{err:?}").to_lowercase().contains("protocol"),
            "refused for its version, not for something else: {err:?}"
        );
    }
}
