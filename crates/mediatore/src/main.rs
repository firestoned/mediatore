//! mediatore: identity broker for banlieue sandbox VMs.

mod config;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use mediatore_api::AppState;
use mediatore_entra::Validator;
use mediatore_spire::Naming;
use mediatore_store::MemoryStore;
use mediatore_sts::Sts;
use tracing_subscriber::EnvFilter;

use crate::config::Config;

#[derive(Parser)]
#[command(
    name = "mediatore",
    version,
    about = "Identity broker for banlieue sandbox VMs"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server.
    Serve {
        /// Path to mediatore.yaml
        #[arg(long, env = "MEDIATORE_CONFIG", default_value = "mediatore.yaml")]
        config: PathBuf,
    },
    /// Revoke a claim immediately: delete its SPIRE entry, stop issuing, optionally ban the node.
    Revoke {
        /// Claim name
        #[arg(long)]
        claim: String,
        /// Also ban the bound node's EK hash
        #[arg(long)]
        ban_node: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Serve { config } => serve(&config).await,
        Cmd::Revoke { claim, ban_node } => {
            tracing::warn!(claim, ban_node, "revoke: admin client not wired yet");
            anyhow::bail!("not implemented: revoke needs the admin endpoint")
        }
    }
}

async fn serve(path: &std::path::Path) -> anyhow::Result<()> {
    let cfg = Config::load(path)?;
    if !cfg.dev_mode {
        anyhow::bail!("only dev_mode is runnable in this scaffold: mTLS + sqlx store are next");
    }
    tracing::warn!("dev_mode: peer identity from header, in-memory store, no mTLS");

    let sts = match &cfg.sts {
        Some(s) => {
            let pem = std::fs::read(&s.signing_key_file)?;
            let max = cfg.audiences.iter().map(|a| a.max_ttl).max().unwrap_or(900);
            Some(Sts::new(
                &s.issuer,
                &s.kid,
                &pem,
                chrono::Duration::seconds(max),
            )?)
        }
        None => None,
    };

    let state = Arc::new(AppState {
        store: MemoryStore::shared(),
        spire: Arc::new(mediatore_spire::Noop),
        naming: Naming {
            trust_domain: cfg.trust_domain.clone(),
        },
        validator: Validator::new(cfg.issuers.clone()),
        sts,
        audiences: cfg.audiences.iter().map(|a| a.name.clone()).collect(),
        dev_mode: cfg.dev_mode,
    });

    let user = tokio::net::TcpListener::bind(&cfg.listen.user).await?;
    let sandbox = tokio::net::TcpListener::bind(&cfg.listen.sandbox).await?;
    tracing::info!(user = %cfg.listen.user, sandbox = %cfg.listen.sandbox, "listening");

    let u = axum::serve(user, mediatore_api::user_router(state.clone()))
        .with_graceful_shutdown(shutdown());
    let s = axum::serve(sandbox, mediatore_api::sandbox_router(state))
        .with_graceful_shutdown(shutdown());
    tokio::try_join!(u, s)?;
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
