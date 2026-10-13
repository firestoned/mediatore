// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! mediatore: identity broker for banlieue sandbox VMs.

mod config;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use mediatore_api::AppState;
use mediatore_claims::Reconciler;
use mediatore_claims::lease::LeaseConfig;
use mediatore_claims::watch::{KubeClaimsApi, Watcher, WatcherConfig};
use mediatore_entra::Validator;
use mediatore_spire::{EntryManager, KubeEntryManager, MemoryEntries, Naming};
use mediatore_store::MemoryStore;
use mediatore_sts::Sts;
use mediatore_tls::MaterialSource;
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
    mediatore_proto::tls::ensure_provider();
    tracing_subscriber::fmt()
        // Colour only on a terminal: pod logs are read by programs.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
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
    let client = kube_client(&cfg).await?;
    let spire = entry_manager(&cfg, naming.clone(), client.as_ref());
    if cfg.dev_mode {
        tracing::warn!("dev_mode: peer identity from header, in-memory store and entries, no mTLS");
    } else {
        tracing::warn!(
            "store: in-memory until roadmap 05; claims do not survive a restart and bind only through the dev binder until roadmap 03"
        );
    }

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
        naming: naming.clone(),
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
    let sandbox_router = mediatore_api::sandbox_router(state.clone());
    if let (Some(spire), Some(client)) = ((!cfg.dev_mode).then_some(cfg.spire.as_ref()).flatten(), client) {
        let configs = broker_identity(&spire.workload_api_socket, &naming).await?;
        let s = mediatore_tls::serve(sandbox, configs, sandbox_router, shutdown());
        let w = async {
            claim_watcher(&cfg, client, &state)
                .await
                .map_err(std::io::Error::other)
        };
        tokio::try_join!(u, s, w)?;
    } else {
        let s = axum::serve(sandbox, sandbox_router).with_graceful_shutdown(shutdown());
        tokio::try_join!(u, s)?;
    }
    Ok(())
}

/// The claim watcher on the replica holding the Lease (ADR-0011), until shutdown.
async fn claim_watcher(
    cfg: &Config,
    client: kube::Client,
    state: &Arc<AppState>,
) -> anyhow::Result<()> {
    let reconciler = Reconciler {
        store: state.store.clone(),
        spire: state.spire.clone(),
        naming: state.naming.clone(),
    };
    let watcher = Arc::new(Watcher::new(
        reconciler,
        Arc::new(KubeClaimsApi::new(client.clone())),
        WatcherConfig {
            resync: std::time::Duration::from_secs(cfg.watcher.resync_secs),
            resolve_timeout: std::time::Duration::from_secs(cfg.watcher.resolve_timeout_secs),
            ..WatcherConfig::default()
        },
    ));
    let lease = LeaseConfig {
        namespace: client.default_namespace().to_owned(),
        name: "mediatore-watcher".into(),
        // The pod name in a Deployment; anything unique will do elsewhere.
        holder: std::env::var("HOSTNAME").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string()),
        duration: std::time::Duration::from_secs(cfg.watcher.lease_duration_secs),
    };
    let work_client = client.clone();
    let leader = mediatore_claims::lease::run_as_leader(client, lease, move || {
        mediatore_claims::watch::run(work_client.clone(), watcher.clone())
    });
    tokio::select! {
        r = leader => r,
        () = shutdown() => Ok(()),
    }
}

/// The broker's own SVID from the Workload API, and the sandbox listener's rotating TLS
/// config over it (ADR-0007 decisions 1 and 2). Fails closed: no socket, no SVID, or an
/// SVID that is not `spiffe://<td>/mediatore` (a wrong `ClusterSPIFFEID`) and the process
/// does not start.
async fn broker_identity(
    workload_api_socket: &str,
    naming: &Naming,
) -> anyhow::Result<Arc<mediatore_tls::TlsConfigs>> {
    let source = mediatore_tls::WorkloadApiSource::connect(workload_api_socket).await?;
    let own = source.current()?;
    anyhow::ensure!(
        own.spiffe_id.to_string() == naming.broker_id(),
        "the Workload API issued {} but the broker identity is {}: check the ClusterSPIFFEID",
        own.spiffe_id,
        naming.broker_id()
    );
    tracing::info!(spiffe_id = %own.spiffe_id, "broker identity from the Workload API");
    let configs = mediatore_tls::TlsConfigs::spawn(
        Arc::new(source),
        mediatore_api::sandbox_authorizer(naming.clone()),
    )?;
    Ok(configs)
}

/// The Kubernetes client outside `dev_mode`: the cluster `spire.entries.kubeconfig` names,
/// in-cluster when unset. `None` under `dev_mode`, which needs no cluster.
async fn kube_client(cfg: &Config) -> anyhow::Result<Option<kube::Client>> {
    let Some(spire) = (!cfg.dev_mode).then_some(cfg.spire.as_ref()).flatten() else {
        return Ok(None);
    };
    let client = match &spire.entries.kubeconfig {
        Some(path) => {
            let kc = kube::config::Kubeconfig::read_from(path)?;
            let opts = kube::config::KubeConfigOptions::default();
            kube::Client::try_from(kube::Config::from_custom_kubeconfig(kc, &opts).await?)?
        }
        None => kube::Client::try_default().await?,
    };
    Ok(Some(client))
}

/// In `dev_mode` entries live in memory; otherwise they are `ClusterStaticEntry` resources
/// through `client` (ADR-0006).
fn entry_manager(
    cfg: &Config,
    naming: Naming,
    client: Option<&kube::Client>,
) -> Arc<dyn EntryManager> {
    let (Some(spire), Some(client)) = ((!cfg.dev_mode).then_some(cfg.spire.as_ref()).flatten(), client) else {
        return Arc::new(MemoryEntries::default());
    };
    tracing::info!(
        class_name = %spire.entries.class_name,
        workload_api_socket = %spire.workload_api_socket,
        "entries: ClusterStaticEntry via the Kubernetes API"
    );
    Arc::new(KubeEntryManager::new(
        client.clone(),
        naming,
        (&spire.entries).into(),
    ))
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
