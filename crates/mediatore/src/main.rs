// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! mediatore: identity broker for banlieue sandbox VMs. One binary, every role a subcommand
//! (ADR-0014): `serve` is the broker, `guest`, `egress-proxy`, `jail-exec` and `token` are
//! the VM side, `login`, `sandbox` and `session` are the user's tools, `revoke` the admin stub.

mod config;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use mediatore_api::{AppState, Limiter};
use mediatore_claims::Reconciler;
use mediatore_claims::lease::LeaseConfig;
use mediatore_claims::policy::BundleReflector;
use mediatore_claims::sandbox::{KubeSandboxes, SandboxFrontDoor};
use mediatore_claims::watch::{KubeClaimsApi, Watcher, WatcherConfig};
use mediatore_entra::{Backend, ClientAssertion, Validator};
use mediatore_spire::{EntryManager, KubeEntryManager, MemoryEntries, Naming};
use mediatore_store::seal::{LocalKeySealer, Sealer, TransitSealer};
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
    /// Inside the jail, before the workload: apply Landlock to this process, then exec the argv (ADR-0024).
    JailExec(mediatore_guest::confine::JailExecArgs),
    /// Beside the jail, as the sandbox user: the reverse proxy that swaps the jail's phantom token for the audience's real one (ADR-0025).
    EgressProxy(mediatore_guest::egress::EgressArgs),
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
        Cmd::EgressProxy(args) => mediatore_guest::egress::run(args).await,
        Cmd::JailExec(args) => {
            // Returns only when the workload did not run; on success this process is the workload.
            let err = mediatore_guest::confine::run(&args);
            tracing::error!(error = %err, "jail-exec: the workload did not run");
            std::process::exit(err.exit_code());
        }
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
    let sealer = sealer(&cfg).await?;
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

    let registries = registries(&cfg)?;

    let state = Arc::new(AppState {
        store,
        spire,
        naming: naming.clone(),
        validator: validator(&cfg).await?,
        sts,
        audiences: cfg.audiences.iter().map(|a| a.name.clone()).collect(),
        obo_audiences: cfg
            .audiences
            .iter()
            .filter(|a| a.via == Backend::EntraObo)
            .map(|a| a.name.clone())
            .collect(),
        egress: cfg
            .audiences
            .iter()
            .map(|a| (a.name.clone(), a.egress.clone()))
            .collect(),
        rules: cfg
            .audiences
            .iter()
            .map(|a| (a.name.clone(), a.rules.clone()))
            .collect(),
        cas: audience_cas(&cfg)?,
        registries,
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
        let policy_client = client.clone();
        let p = async {
            policy_reflector(&cfg, policy_client, &state)
                .await
                .map_err(std::io::Error::other)
        };
        let w = async {
            claim_watcher(&cfg, client, &state)
                .await
                .map_err(std::io::Error::other)
        };
        tokio::try_join!(u, s, w, p)?;
    } else {
        if cfg.policy.is_some() {
            tracing::warn!("policy configured but no cluster client (dev_mode): no bundle is read");
        }
        let s = axum::serve(sandbox, sandbox_router).with_graceful_shutdown(shutdown());
        tokio::try_join!(u, s)?;
    }
    Ok(())
}

/// notaio's bundle reflector (ADR-0026 decision 3) on every replica, outside the Lease:
/// each replica needs the cache it will compare with (decision 4). Until shutdown; nothing
/// to do without a `policy` section. A watch that ends is an error, so the pod restarts
/// with the cause in its log instead of comparing against a cache going stale.
async fn policy_reflector(
    cfg: &Config,
    client: kube::Client,
    state: &Arc<AppState>,
) -> anyhow::Result<()> {
    let Some(policy) = cfg.policy.as_ref() else {
        return Ok(());
    };
    let keys = mediatore_policy::trusted_keys(&policy.trusted_keys)?;
    let reflector = Arc::new(BundleReflector::new(
        state.store.clone(),
        keys,
        policy.namespaces.clone(),
    ));
    tokio::select! {
        r = mediatore_claims::policy::run(client, reflector) => r,
        () = shutdown() => Ok(()),
    }
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

/// How long the broker waits for its own SVID at start. Longer than a VM-side role's: the
/// agent beside it in the pod may still be attesting; and bounded, so a pod with no
/// Workload API restarts with the cause in its log instead of hanging as Running.
const BROKER_WORKLOAD_API_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// The broker's own SVID from the Workload API, and the sandbox listener's rotating TLS
/// config over it (ADR-0007 decisions 1 and 2). Fails closed: no socket, no SVID, or an
/// SVID that is not `spiffe://<td>/mediatore` (a wrong `ClusterSPIFFEID`) and the process
/// does not start.
async fn broker_identity(
    workload_api_socket: &str,
    naming: &Naming,
) -> anyhow::Result<Arc<mediatore_tls::TlsConfigs>> {
    let source =
        mediatore_tls::WorkloadApiSource::connect(workload_api_socket, BROKER_WORKLOAD_API_WAIT)
            .await?;
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

/// The CA bundles the egress proxy trusts per audience (`audiences[].ca_file`, ADR-0025
/// amended): each file read at start and refused unless it builds a client config, so a
/// missing or empty file stops the broker rather than a claim.
fn audience_cas(cfg: &Config) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
    let mut out = std::collections::BTreeMap::new();
    for a in &cfg.audiences {
        if let Some(path) = &a.ca_file {
            let pem = std::fs::read(path).map_err(|e| {
                anyhow::anyhow!("audience {} ca_file {}: {e}", a.name, path.display())
            })?;
            mediatore_proto::tls::https_client_config_with_ca(&pem).map_err(|e| {
                anyhow::anyhow!("audience {} ca_file {}: {e}", a.name, path.display())
            })?;
            let pem = String::from_utf8(pem).map_err(|e| {
                anyhow::anyhow!(
                    "audience {} ca_file {}: not UTF-8 PEM: {e}",
                    a.name,
                    path.display()
                )
            })?;
            tracing::info!(audience = %a.name, ca_file = %path.display(), "audience pinned to a private CA for the egress proxy");
            out.insert(a.name.clone(), pem);
        }
    }
    Ok(out)
}

/// The upstream validator, with each issuer that names a `ca_file` pinned to that CA. The
/// file is read now so a missing or empty one fails the start, not the first login.
async fn validator(cfg: &Config) -> anyhow::Result<Validator> {
    let mut v = Validator::new(cfg.issuers.clone());
    for issuer in &cfg.issuers {
        if let Some(path) = &issuer.ca_file {
            let pem = std::fs::read(path).map_err(|e| {
                anyhow::anyhow!("issuer {} ca_file {}: {e}", issuer.url, path.display())
            })?;
            v = v.with_issuer_ca(&issuer.url, &pem)?;
            tracing::info!(issuer = %issuer.url, ca_file = %path.display(), "issuer pinned to a private CA");
        }
        // ADR-0017: the secret an issuer's token endpoint wants from the public client
        // (Google), read now.
        if let Some(path) = issuer
            .session
            .as_ref()
            .and_then(|s| s.client_secret_file.as_ref())
        {
            let secret = std::fs::read_to_string(path).map_err(|e| {
                anyhow::anyhow!(
                    "issuer {} client_secret_file {}: {e}",
                    issuer.url,
                    path.display()
                )
            })?;
            v = v.with_session_secret(
                &issuer.url,
                mediatore_proto::Secret(secret.trim().to_owned()),
            );
            tracing::info!(issuer = %issuer.url, "session: the client secret is sent on refreshes");
        }
        // ADR-0016 decision 4: the credential is read and exercised now, so a key that is
        // not the certificate's, a wrong transit role or key or an unreadable token file
        // fails the start, not the first claim.
        if let Some(entra) = &issuer.entra {
            let assertion = ClientAssertion::build(entra)
                .await
                .map_err(|e| anyhow::anyhow!("issuer {}: {e}", issuer.url))?;
            tracing::info!(issuer = %issuer.url, client_id = %issuer.client_id, credential = ?assertion, "entra: client assertion ready");
            v = v.with_client_assertion(&issuer.url, assertion);
        }
    }
    Ok(v)
}

/// The refresh-material sealer (ADR-0012 decision 3): the local key file, or `OpenBao`
/// transit (ADR-0015). Either is read and probed now, so a bad Secret, role, policy or
/// key fails the start, not the first claim. `Config::parse` guarantees exactly one is set.
async fn sealer(cfg: &Config) -> anyhow::Result<Option<Arc<dyn Sealer>>> {
    let Some(sealing) = &cfg.store.sealing else {
        tracing::info!("sealing: no key configured; refresh material cannot be persisted");
        return Ok(None);
    };
    if let Some(transit) = &sealing.transit {
        let sealer = TransitSealer::connect(transit).await?;
        tracing::info!(
            key_id = sealer.key_id(),
            url = %transit.url,
            role = %transit.role,
            "sealing: OpenBao transit probed; the key stays there"
        );
        return Ok(Some(Arc::new(sealer)));
    }
    let Some(key_file) = &sealing.key_file else {
        anyhow::bail!("store.sealing needs key_file or transit");
    };
    let sealer = LocalKeySealer::from_file(key_file)?;
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

/// SIGINT or SIGTERM: the latter is what a rollout sends, and without it every restart
/// waited for the kill.
async fn shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("a SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
    tracing::info!("shutting down");
}

/// The pull credentials (ADR-0022): each password file read once, at start, like the STS
/// key; keyed by the registry host as the API reaches it. The host and login are logged,
/// the password never.
fn registries(
    cfg: &Config,
) -> anyhow::Result<std::collections::BTreeMap<String, mediatore_proto::RegistryCredential>> {
    let mut out = std::collections::BTreeMap::new();
    for r in &cfg.registries {
        let password = std::fs::read_to_string(&r.password_file).map_err(|e| {
            anyhow::anyhow!(
                "registries[{}].password_file {}: {e}",
                r.host,
                r.password_file.display()
            )
        })?;
        let password = password.trim();
        anyhow::ensure!(
            !password.is_empty(),
            "registries[{}].password_file {} is empty",
            r.host,
            r.password_file.display()
        );
        let host = mediatore_proto::image::canonical_registry(&r.host);
        tracing::info!(registry = %host, username = %r.username, "registry credential loaded");
        out.insert(
            host.clone(),
            mediatore_proto::RegistryCredential {
                host,
                username: r.username.clone(),
                password: mediatore_proto::Secret(password.to_string()),
            },
        );
    }
    Ok(out)
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
    fn jail_exec_is_a_subcommand_with_its_writable_dirs_ports_and_argv() {
        let jail_exec = parse(&[
            "mediatore",
            "jail-exec",
            "--writable",
            "/work",
            "--writable",
            "/tmp",
            "--connect-port",
            "443",
            "--",
            "/bin/sh",
            "-c",
            "id",
        ]);
        assert!(
            matches!(
                jail_exec,
                Ok(Cmd::JailExec(ref a))
                    if a.connect_ports == [443]
                        && a.writable.len() == 2
                        && a.argv == ["/bin/sh", "-c", "id"]
            ),
            "{jail_exec:?}"
        );
        // ADR-0024 decision 4 at the parser: the argv is required.
        assert!(parse(&["mediatore", "jail-exec", "--connect-port", "443"]).is_err());
    }

    #[test]
    fn egress_proxy_is_a_subcommand_with_its_files_and_a_loopback_default() {
        let proxy = parse(&[
            "mediatore",
            "egress-proxy",
            "--mediatore-url",
            "https://mediatore.test:8443",
            "--routes",
            "/mnt/sandbox/egress/routes.json",
            "--phantom-file",
            "/mnt/sandbox/egress/phantom",
        ]);
        let Ok(Cmd::EgressProxy(args)) = proxy else {
            panic!("{proxy:?}");
        };
        assert_eq!(args.listen.to_string(), "127.0.0.1:3128");
        assert_eq!(
            args.workload_api_socket, "/run/spire/sockets/agent.sock",
            "the host's socket path: the proxy runs outside the jail"
        );
        assert_eq!(
            args.routes.to_str(),
            Some("/mnt/sandbox/egress/routes.json")
        );
        // The guest's command line for it is what the parser accepts.
        let files = mediatore_guest::egress::EgressFiles {
            routes: "/r".into(),
            phantom: "/p".into(),
        };
        let mut line = vec!["mediatore".to_owned()];
        line.extend(mediatore_guest::egress::command_args(
            "127.0.0.1:3128".parse().unwrap(),
            "https://b",
            "/run/spire/sockets/agent.sock",
            &files,
        ));
        let line: Vec<&str> = line.iter().map(String::as_str).collect();
        assert!(matches!(parse(&line), Ok(Cmd::EgressProxy(_))), "{line:?}");
        // The routes and the phantom are required.
        assert!(parse(&["mediatore", "egress-proxy", "--mediatore-url", "https://b"]).is_err());
    }

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
    fn an_audiences_ca_file_is_read_at_start_and_an_empty_or_missing_one_stops_the_broker() {
        let dir = mediatore_testkit::tempdir();
        let good = dir.join("home.pem");
        std::fs::write(&good, mediatore_testkit::fixture_ca_pem()).unwrap();
        let empty = dir.join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        let base = |ca: &str| {
            format!(
                "trust_domain: sandbox.test\nissuers: []\nlisten: {{ user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }}\ndev_mode: true\nsts: {{ issuer: https://mediatore.test, kid: k, signing_key_file: /k }}\naudiences:\n  - {{ name: internal-git, via: sts, egress: [\"git.home.example:443\"], ca_file: {ca} }}\n  - {{ name: public, via: sts, egress: [\"api.example.com:443\"] }}\n"
            )
        };
        let cfg = Config::parse(&base(good.to_str().unwrap())).unwrap();
        let cas = audience_cas(&cfg).unwrap();
        assert_eq!(cas.len(), 1, "only the audience that named a file");
        assert!(cas["internal-git"].starts_with("-----BEGIN CERTIFICATE-----"));
        let err = audience_cas(&Config::parse(&base(empty.to_str().unwrap())).unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("no certificate"), "{err}");
        let err =
            audience_cas(&Config::parse(&base(dir.join("absent.pem").to_str().unwrap())).unwrap())
                .unwrap_err()
                .to_string();
        assert!(err.contains("absent.pem"), "{err}");
    }

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
