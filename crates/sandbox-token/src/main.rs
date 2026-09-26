//! sandbox-token: `sandbox-token --audience <aud>` prints a bearer token for that audience.
//!
//! Runs inside the jail as the sandbox user. Fetches the claim SVID from the Workload API
//! socket, opens an mTLS session to mediatore, and calls `POST /v1/token`. Nothing is cached
//! to disk.

use clap::Parser;
use mediatore_proto::{TokenRequest, TokenResponse};

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
    #[arg(long, env = "MEDIATORE_DEV_SPIFFE_ID", hide = true)]
    dev_spiffe_id: Option<String>,
    /// Print the whole response as JSON instead of just the token
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let url = format!("{}/v1/token", cli.mediatore_url.trim_end_matches('/'));

    let client = reqwest::Client::builder().build()?;
    let mut req = client.post(&url).json(&TokenRequest {
        audience: cli.audience,
    });
    if let Some(id) = &cli.dev_spiffe_id {
        req = req.header("x-mediatore-peer-spiffe-id", id);
    } else {
        // mTLS with the claim SVID from `cli.workload_api_socket` goes here (spiffe crate).
        anyhow::bail!("mTLS not wired yet; set MEDIATORE_DEV_SPIFFE_ID against a dev_mode server");
    }
    let resp = req.send().await?;
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
