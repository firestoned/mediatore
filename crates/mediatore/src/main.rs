// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! mediatore: identity broker for banlieue sandbox VMs.

mod config;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use mediatore_api::AppState;
use mediatore_entra::Validator;
use mediatore_spire::{EntryManager, KubeEntryManager, MemoryEntries, Naming};
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
    let naming = Naming {
        trust_domain: cfg.trust_domain.clone(),
    };
    let spire = entry_manager(&cfg, naming.clone()).await?;
    if !cfg.dev_mode {
        anyhow::bail!(
            "only dev_mode is runnable in this scaffold: the mTLS listener (ADR-0007) and the sqlx store are next"
        );
    }
    tracing::warn!("dev_mode: peer identity from header, in-memory store and entries, no mTLS");

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
        spire,
        naming,
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

/// In `dev_mode` entries live in memory; otherwise they are `ClusterStaticEntry` resources
/// in the cluster `spire.entries.kubeconfig` names (in-cluster when unset), ADR-0006.
async fn entry_manager(cfg: &Config, naming: Naming) -> anyhow::Result<Arc<dyn EntryManager>> {
    let Some(spire) = (!cfg.dev_mode).then_some(cfg.spire.as_ref()).flatten() else {
        return Ok(Arc::new(MemoryEntries::default()));
    };
    let client = match &spire.entries.kubeconfig {
        Some(path) => {
            let kc = kube::config::Kubeconfig::read_from(path)?;
            let opts = kube::config::KubeConfigOptions::default();
            kube::Client::try_from(kube::Config::from_custom_kubeconfig(kc, &opts).await?)?
        }
        None => kube::Client::try_default().await?,
    };
    tracing::info!(
        class_name = %spire.entries.class_name,
        workload_api_socket = %spire.workload_api_socket,
        "entries: ClusterStaticEntry via the Kubernetes API; own SVID from the Workload API (listener lands with ADR-0007)"
    );
    Ok(Arc::new(KubeEntryManager::new(
        client,
        naming,
        (&spire.entries).into(),
    )))
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
