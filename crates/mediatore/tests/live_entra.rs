// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The Entra path against a real tenant (ADR-0016 decision 6). Ignored by default; run by
//! hand with the fixture in the environment, and it fails, never skips, when a variable
//! is missing:
//!
//! ```sh
//! MEDIATORE_LIVE_ENTRA_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0 \
//! MEDIATORE_LIVE_ENTRA_CLIENT_ID=<broker app id> \
//! MEDIATORE_LIVE_ENTRA_CERTIFICATE_FILE=cert.pem \
//! MEDIATORE_LIVE_ENTRA_KEY_FILE=key.pem \
//! MEDIATORE_LIVE_ENTRA_USER_TOKEN=$(az account get-access-token --scope <broker app id>/.default --query accessToken -o tsv) \
//! MEDIATORE_LIVE_ENTRA_AUDIENCE=api://trading-data \
//! cargo test -p mediatore --test live_entra -- --ignored --nocapture
//! ```
//!
//! `MEDIATORE_LIVE_ENTRA_TOKEN_FILE` in place of the certificate and key uses a federated
//! credential. Nothing secret is printed: the test reports claim names and expiries.

use mediatore_entra::{Backend, ClientAssertion, EntraConfig, IdpError, IssuerConfig, Validator};

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required for the live Entra run"))
}

#[tokio::test]
#[ignore = "needs a tenant: see the module doc"]
async fn the_live_tenant_exchanges_refreshes_for_mediatore_and_refreshes_for_the_audience() {
    let issuer_url = var("MEDIATORE_LIVE_ENTRA_ISSUER");
    let client_id = var("MEDIATORE_LIVE_ENTRA_CLIENT_ID");
    let user_token = var("MEDIATORE_LIVE_ENTRA_USER_TOKEN");
    let audience = var("MEDIATORE_LIVE_ENTRA_AUDIENCE");
    let entra = match std::env::var("MEDIATORE_LIVE_ENTRA_TOKEN_FILE") {
        Ok(token_file) => EntraConfig {
            token_file: Some(token_file.into()),
            ..Default::default()
        },
        Err(_) => EntraConfig {
            certificate_file: Some(var("MEDIATORE_LIVE_ENTRA_CERTIFICATE_FILE").into()),
            key_file: Some(var("MEDIATORE_LIVE_ENTRA_KEY_FILE").into()),
            ..Default::default()
        },
    };
    let issuer = IssuerConfig {
        url: issuer_url.clone(),
        backend: Backend::EntraObo,
        client_id: client_id.clone(),
        subject_claim: "oid".into(),
        required_group: None,
        session: None,
        ca_file: None,
        entra: Some(entra.clone()),
        groups_claim: None,
    };
    let assertion = ClientAssertion::build(&entra)
        .await
        .expect("the credential builds and probes");
    let v = Validator::new(vec![issuer.clone()]).with_client_assertion(&issuer_url, assertion);

    // The login: the user's token must be for mediatore (aud = client id, v2 tokens).
    let login = v
        .validate(&user_token)
        .await
        .expect("the user token validates");
    println!(
        "login: subject {} expires {}",
        login.subject.id, login.expires_at
    );

    // ADR-0016 decision 1: the exchange, for the downstream audience.
    let session = v
        .exchange(&issuer, &user_token, &audience)
        .await
        .expect("the On-Behalf-Of exchange");
    println!("exchange: a refresh token was issued for {audience}");

    // Decision 2, the STS shape: a token for mediatore itself, validated like a login.
    let own = v
        .refresh_entra(&issuer, &session.0, &client_id)
        .await
        .expect("a refresh for mediatore's own resource");
    let validated = own.validated.expect("a token for mediatore is validated");
    assert_eq!(validated.subject.id, login.subject.id, "the same user");
    println!(
        "refresh for self: subject {} groups {:?} expires {}",
        validated.subject.id, validated.groups, own.expires_at
    );

    // Decision 2, the OBO shape: a token for the audience, unread.
    let downstream = v
        .refresh_entra(&issuer, &own.refresh_token.0, &audience)
        .await
        .expect("a refresh for the audience");
    assert!(downstream.validated.is_none());
    assert!(downstream.expires_at > chrono::Utc::now());
    println!(
        "refresh for {audience}: a token expiring {}",
        downstream.expires_at
    );

    // A refresh token that is not Entra's: a refusal, not an outage.
    let err = v
        .refresh_entra(&issuer, "not-a-refresh-token", &audience)
        .await
        .unwrap_err();
    assert!(matches!(err, IdpError::SessionRevoked(_)), "{err}");
    println!("a bogus refresh token: {err}");
}
