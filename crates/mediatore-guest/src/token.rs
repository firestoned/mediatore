// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! `mediatore token --audience <aud>` prints a bearer token for that audience.
//!
//! Runs inside the jail as the sandbox user, from the binary the guest role mounted there
//! (ADR-0014 decision 4). Fetches the claim SVID from the Workload API socket, opens an
//! mTLS session to mediatore, and calls `POST /v1/token`. Nothing is cached to disk, and
//! the token is the only thing written to standard output.

use mediatore_proto::{TokenRequest, TokenResponse};
use reqwest::Method;

use crate::client::SandboxClient;

/// Arguments of the `token` role.
#[derive(Debug, clap::Args)]
pub struct TokenArgs {
    /// Downstream audience
    #[arg(long)]
    pub audience: String,
    /// mediatore sandbox-facing base URL
    #[arg(long, env = "MEDIATORE_URL")]
    pub mediatore_url: String,
    /// SPIRE Workload API socket
    #[arg(
        long,
        env = "SPIFFE_ENDPOINT_SOCKET",
        default_value = "unix:///run/spire/agent.sock"
    )]
    pub workload_api_socket: String,
    /// Dev only: send this SPIFFE ID as a header instead of doing mTLS
    #[cfg(feature = "dev")]
    #[arg(long, env = "MEDIATORE_DEV_SPIFFE_ID", hide = true)]
    pub dev_spiffe_id: Option<String>,
    /// Print the whole response as JSON instead of just the token
    #[arg(long)]
    pub json: bool,
}

/// Obtain the transport identity for this workload. Fails closed: no Workload API, no client.
async fn connect(args: &TokenArgs) -> anyhow::Result<SandboxClient> {
    #[cfg(feature = "dev")]
    if let Some(id) = &args.dev_spiffe_id {
        return Ok(SandboxClient::dev_header(&args.mediatore_url, id));
    }
    SandboxClient::connect(&args.mediatore_url, &args.workload_api_socket).await
}

/// Run the token role: one `POST /v1/token`, the token on standard output.
pub async fn run(args: TokenArgs) -> anyhow::Result<()> {
    let client = connect(&args).await?;
    let req = TokenRequest {
        audience: args.audience,
    };
    let resp = client.send(Method::POST, "/v1/token", Some(&req)).await?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "mediatore: {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let tok: TokenResponse = resp.json().await?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&tok)?);
    } else {
        println!("{}", tok.access_token);
    }
    Ok(())
}
