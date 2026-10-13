// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! sandbox-token: `sandbox-token --audience <aud>` prints a bearer token for that audience.
//!
//! Runs inside the jail as the sandbox user. Fetches the claim SVID from the Workload API
//! socket, opens an mTLS session to mediatore, and calls `POST /v1/token`. Nothing is cached
//! to disk.

use clap::Parser;
use mediatore_proto::{TokenRequest, TokenResponse};
use mediatore_tls::{MaterialSource, SpiffeId, WorkloadApiSource};

#[derive(Parser)]
#[command(
    name = "sandbox-token",
    version,
    about = "Fetch an audience-scoped token for this sandbox"
)]
struct Cli {
    /// Downstream audience
    #[arg(long)]
    audience: String,
    /// mediatore sandbox-facing base URL
    #[arg(long, env = "MEDIATORE_URL")]
    mediatore_url: String,
    /// SPIRE Workload API socket
    #[arg(
        long,
        env = "SPIFFE_ENDPOINT_SOCKET",
        default_value = "unix:///run/spire/agent.sock"
    )]
    workload_api_socket: String,
    /// Dev only: send this SPIFFE ID as a header instead of doing mTLS
    #[cfg(feature = "dev")]
    #[arg(long, env = "MEDIATORE_DEV_SPIFFE_ID", hide = true)]
    dev_spiffe_id: Option<String>,
    /// Print the whole response as JSON instead of just the token
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mediatore_proto::tls::ensure_provider();
    let cli = Cli::parse();
    let url = format!("{}/v1/token", cli.mediatore_url.trim_end_matches('/'));

    let req = if let Some(id) = dev_header(&cli) {
        reqwest::Client::new()
            .post(&url)
            .header("x-mediatore-peer-spiffe-id", id)
    } else {
        // The claim SVID from the jail's agent socket is the client certificate; the
        // broker is accepted only as spiffe://<td>/mediatore (ADR-0007 decision 5).
        let endpoint = mediatore_tls::endpoint(&cli.workload_api_socket);
        let source = WorkloadApiSource::connect(&endpoint)
            .await
            .map_err(|e| anyhow::anyhow!("Workload API at {endpoint}: {e}"))?;
        let own = source.current()?;
        let server = SpiffeId::new(format!("spiffe://{}/mediatore", own.trust_domain()))?;
        let cfg = mediatore_tls::client_config(&own, &server)?;
        reqwest::Client::builder()
            .use_preconfigured_tls(cfg)
            .build()?
            .post(&url)
    };
    let resp = req
        .json(&TokenRequest {
            audience: cli.audience,
        })
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "mediatore: {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let tok: TokenResponse = resp.json().await?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&tok)?);
    } else {
        println!("{}", tok.access_token);
    }
    Ok(())
}

/// The dev header path exists only in a `dev` build.
#[cfg(feature = "dev")]
fn dev_header(cli: &Cli) -> Option<&str> {
    cli.dev_spiffe_id.as_deref()
}

#[cfg(not(feature = "dev"))]
fn dev_header(_cli: &Cli) -> Option<&str> {
    None
}
