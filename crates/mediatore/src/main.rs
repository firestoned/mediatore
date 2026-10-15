// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! mediatore: identity broker for banlieue sandbox VMs. One binary, every role a subcommand
//! (ADR-0014): `serve` is the broker, `guest` and `token` are the VM side, `login`,
//! `sandbox` and `session` are the user's tools, `revoke` the admin stub.

mod config;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use mediatore_api::{AppState, Limiter};
use mediatore_claims::Reconciler;
use mediatore_claims::lease::LeaseConfig;
use mediatore_claims::sandbox::{KubeSandboxes, SandboxFrontDoor};
use mediatore_claims::watch::{KubeClaimsApi, Watcher, WatcherConfig};
use mediatore_entra::Validator;
use mediatore_spire::{EntryManager, KubeEntryManager, MemoryEntries, Naming};
use mediatore_store::seal::{LocalKeySealer, Sealer};
use mediatore_store::sql::{SqlStore, redacted};
use mediatore_store::{ClaimStore, MemoryStore};
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

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the broker.
    Serve {
        /// Path to mediatore.yaml
        #[arg(long, env = "MEDIATORE_CONFIG", default_value = "mediatore.yaml")]
        config: PathBuf,
    },
    /// The in-guest agent on a pool member: register the node, fetch the subject, jail the workload.
    Guest(mediatore_guest::guest::GuestArgs),
    /// Inside the jail: trade the claim SVID for one audience-scoped token.
    Token(mediatore_guest::token::TokenArgs),
    /// The user's tools: `login`, `sandbox create|get|delete`, `session`.
    #[command(flatten)]
    User(mediatore_client::cli::UserCmd),
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
        // Logs on stderr for every role, so stdout is the role's result alone (`token`
        // prints a token, `sandbox create --json` a document). Colour only on a terminal:
        // pod logs are read by programs.
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Serve { config } => serve(&config).await,
        Cmd::Guest(args) => mediatore_guest::guest::run(args).await,
        Cmd::Token(args) => mediatore_guest::token::run(args).await,
        Cmd::User(cmd) => mediatore_client::cli::run(cmd).await,
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
        tracing::warn!("dev_mode: peer identity from header, in-memory entries, no mTLS");
    }
    let store = store(&cfg).await?;
    let sealer = sealer(&cfg)?;
    let sandboxes: Option<Arc<dyn SandboxFrontDoor>> = client
        .as_ref()
        .map(|c| Arc::new(KubeSandboxes::new(c.clone())) as Arc<dyn SandboxFrontDoor>);

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
        store,
        spire,
        naming: naming.clone(),
        validator: Validator::new(cfg.issuers.clone()),
        sts,
        audiences: cfg.audiences.iter().map(|a| a.name.clone()).collect(),
        sandboxes,
        sandbox_namespace: cfg.sandboxes.namespace.clone(),
        sealer,
        limiter: Limiter::new(cfg.token.rate_per_minute),
        dev_mode: cfg.dev_mode,
    });

    let user = tokio::net::TcpListener::bind(&cfg.listen.user).await?;
    let sandbox = tokio::net::TcpListener::bind(&cfg.listen.sandbox).await?;
    tracing::info!(user = %cfg.listen.user, sandbox = %cfg.listen.sandbox, "listening");

    let u = axum::serve(user, mediatore_api::user_router(state.clone()))
        .with_graceful_shutdown(shutdown());
    let sandbox_router = mediatore_api::sandbox_router(state.clone());
    if let (Some(spire), Some(client)) = (
        (!cfg.dev_mode).then_some(cfg.spire.as_ref()).flatten(),
        client,
    ) {
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
            audiences: cfg.audiences.iter().map(|a| a.name.clone()).collect(),
            issuers: cfg.issuers.iter().map(|i| i.url.clone()).collect(),
            retention: std::time::Duration::from_secs(cfg.store.retention_secs),
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

/// The claim store (ADR-0012): sqlx over the configured URL, migrated at startup; in
/// memory only under `dev_mode` with no URL (`Config::parse` refuses that elsewhere).
async fn store(cfg: &Config) -> anyhow::Result<Arc<dyn ClaimStore>> {
    let Some(url) = cfg.store.url.as_deref() else {
        tracing::warn!("store: in-memory (dev_mode); nothing survives a restart");
        return Ok(MemoryStore::shared());
    };
    let store = SqlStore::connect(url, cfg.store.max_connections).await?;
    tracing::info!(
        store = %redacted(url),
        engine = ?store.engine(),
        retention_secs = cfg.store.retention_secs,
        "store: migrated and connected"
    );
    Ok(Arc::new(store))
}

/// The refresh-material sealer (ADR-0012 decision 3), when `store.sealing` names a key.
/// The key is read and checked now so a bad Secret fails the start, not the first claim.
fn sealer(cfg: &Config) -> anyhow::Result<Option<Arc<dyn Sealer>>> {
    let Some(sealing) = &cfg.store.sealing else {
        tracing::info!("sealing: no key configured; refresh material cannot be persisted");
        return Ok(None);
    };
    let sealer = LocalKeySealer::from_file(&sealing.key_file)?;
    tracing::info!(key_id = sealer.key_id(), "sealing: local key loaded");
    Ok(Some(Arc::new(sealer)))
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
    let (Some(spire), Some(client)) = (
        (!cfg.dev_mode).then_some(cfg.spire.as_ref()).flatten(),
        client,
    ) else {
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

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    fn parse(argv: &[&str]) -> Result<Cmd, clap::Error> {
        Cli::try_parse_from(argv).map(|c| c.cmd)
    }

    #[test]
    fn the_command_tree_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_role_is_a_subcommand_of_the_one_binary() {
        assert!(matches!(
            parse(&["mediatore", "serve", "--config", "x.yaml"]),
            Ok(Cmd::Serve { .. })
        ));
        let guest = parse(&[
            "mediatore",
            "guest",
            "--mediatore-url",
            "https://mediatore-sandbox.banlieue-system.svc",
            "--dev-ek-hash",
            "ec00000000000000000000000000000000000000000000000000000000000007",
            "--dev-dmi-uuid",
            "1d2c3b4a-5f6e-4d7c-8b9a-0f1e2d3c4b5a",
            "--dev-skip-setup",
            "--provider",
            "libvirt",
        ]);
        assert!(
            matches!(guest, Ok(Cmd::Guest(ref a)) if a.dev_skip_setup),
            "{guest:?}"
        );
        let token = parse(&[
            "mediatore",
            "token",
            "--audience",
            "e2e",
            "--mediatore-url",
            "https://mediatore-sandbox.banlieue-system.svc",
        ]);
        assert!(
            matches!(token, Ok(Cmd::Token(ref a)) if a.audience == "e2e"),
            "{token:?}"
        );
        assert!(matches!(
            parse(&["mediatore", "login", "--issuer", "https://dex.home.example"]),
            Ok(Cmd::User(mediatore_client::cli::UserCmd::Login(_)))
        ));
        let create = parse(&[
            "mediatore",
            "sandbox",
            "create",
            "--mediatore",
            "https://mediatore.sandbox.example",
            "--pool",
            "pool-a",
            "--audience",
            "api://trading-data",
            "--image",
            "registry.internal:5000/sandbox:latest",
            "--arg",
            "/bin/sh",
        ]);
        assert!(
            matches!(
                create,
                Ok(Cmd::User(mediatore_client::cli::UserCmd::Sandbox(
                    mediatore_client::cli::SandboxCmd::Create(ref a)
                ))) if a.pool == "pool-a" && a.args == ["/bin/sh"]
            ),
            "{create:?}"
        );
        assert!(matches!(
            parse(&[
                "mediatore",
                "sandbox",
                "get",
                "--mediatore",
                "https://mediatore.sandbox.example",
                "sandbox-3f9a1c2e"
            ]),
            Ok(Cmd::User(mediatore_client::cli::UserCmd::Sandbox(
                mediatore_client::cli::SandboxCmd::Get { ref name, .. }
            ))) if name == "sandbox-3f9a1c2e"
        ));
        assert!(matches!(
            parse(&["mediatore", "session"]),
            Ok(Cmd::User(mediatore_client::cli::UserCmd::Session(_)))
        ));
        assert!(matches!(
            parse(&["mediatore", "revoke", "--claim", "sandbox-3f9a1c2e"]),
            Ok(Cmd::Revoke { .. })
        ));
    }

    /// The jail mounts the path the node entry selects (ADR-0014 decision 5), so the two
    /// constants are one.
    #[test]
    fn the_guest_mounts_the_path_the_node_entry_pins() {
        let guest = parse(&["mediatore", "guest", "--mediatore-url", "https://b"]);
        let Ok(Cmd::Guest(args)) = guest else {
            panic!("{guest:?}");
        };
        assert_eq!(
            args.agent_binary.to_str(),
            Some(mediatore_spire::GUEST_AGENT_PATH)
        );
        assert_eq!(
            mediatore_guest::jail::JAIL_BINARY,
            mediatore_spire::GUEST_AGENT_PATH
        );
    }

    #[test]
    fn the_old_binary_names_are_not_subcommands() {
        for old in ["mediatore-guest", "sandbox-token", "mediatore-cli", "claim"] {
            assert!(parse(&["mediatore", old]).is_err(), "{old} parsed");
        }
    }

    /// The header path exists only in a `dev` build (ADR-0007 decision 5).
    #[test]
    fn the_dev_header_flag_follows_the_dev_feature() {
        let argv = [
            "mediatore",
            "token",
            "--audience",
            "e2e",
            "--mediatore-url",
            "http://127.0.0.1:8443",
            "--dev-spiffe-id",
            "spiffe://sandbox.test/banlieue/claim/1d2c3b4a-5f6e-4d7c-8b9a-0f1e2d3c4b5a",
        ];
        assert_eq!(parse(&argv).is_ok(), cfg!(feature = "dev"));
    }
}
