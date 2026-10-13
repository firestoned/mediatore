// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! mediatore-guest: turns a bound banlieue claim into a jailed, identity-bearing workload.
//!
//! State machine (runbook Part 6.1):
//! boot → node registered → subject fetched → user created → jail running → torn down.
//!
//! Transport: SPIFFE mTLS with the node SVID from the Workload API, verifying the broker
//! as exactly `spiffe://<td>/mediatore` (ADR-0007 decision 5). With the `dev` cargo
//! feature only, `--dev-spiffe-id` sends the identity as a header to a loopback `dev_mode`
//! server instead; release builds have no such path.

mod identity;
mod jail;
mod supervise;
mod user;

use std::path::PathBuf;

use clap::Parser;
use mediatore_proto::{Me, NodeRegistered, NodeRegistration, Provider};
use mediatore_tls::{MaterialSource, SpiffeId, WorkloadApiSource};
use reqwest::Method;
use serde::Serialize;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

/// Header carrying the peer SPIFFE ID against a `dev_mode` server.
#[cfg(feature = "dev")]
const DEV_PEER_HEADER: &str = "x-mediatore-peer-spiffe-id";
/// Seconds between registration retries while mediatore is unreachable.
const REGISTER_RETRY_SECS: u64 = 5;
/// Seconds between `GET /v1/me` polls while no claim is bound.
const ME_POLL_SECS: u64 = 5;

#[derive(Parser)]
#[command(
    name = "mediatore-guest",
    version,
    about = "banlieue sandbox in-guest agent"
)]
struct Cli {
    /// mediatore sandbox-facing base URL
    #[arg(long, env = "MEDIATORE_URL")]
    mediatore_url: String,
    /// SPIRE Workload API socket
    #[arg(
        long,
        env = "SPIFFE_ENDPOINT_SOCKET",
        default_value = "/run/spire/sockets/agent.sock"
    )]
    workload_api_socket: PathBuf,
    /// TPM device
    #[arg(long, default_value = "/dev/tpmrm0")]
    tpm: PathBuf,
    /// Hypervisor hint for audit
    #[arg(long, value_enum)]
    provider: Option<ProviderArg>,
    /// Sandbox root
    #[arg(long, default_value = jail::SANDBOX_ROOT)]
    sandbox_root: PathBuf,
    /// Dev only: send this SPIFFE ID as a header instead of doing mTLS
    #[cfg(feature = "dev")]
    #[arg(long, env = "MEDIATORE_DEV_SPIFFE_ID", hide = true)]
    dev_spiffe_id: Option<String>,
    /// Dev only: use this EK hash instead of reading the TPM
    #[arg(long, hide = true)]
    dev_ek_hash: Option<String>,
    /// Dev only: use this DMI UUID instead of reading sysfs
    #[arg(long, hide = true)]
    dev_dmi_uuid: Option<Uuid>,
    /// Dev only: stop after fetching the subject; no user, no jail
    #[arg(long, hide = true)]
    dev_skip_setup: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ProviderArg {
    Vsphere,
    CloudHypervisor,
    Libvirt,
}

impl From<ProviderArg> for Provider {
    fn from(p: ProviderArg) -> Self {
        match p {
            ProviderArg::Vsphere => Provider::Vsphere,
            ProviderArg::CloudHypervisor => Provider::CloudHypervisor,
            ProviderArg::Libvirt => Provider::Libvirt,
        }
    }
}

/// HTTP client for the sandbox listener.
struct SandboxClient {
    base: String,
    transport: Transport,
}

enum Transport {
    /// The node SVID from the Workload API as the client certificate; the broker accepted
    /// only as `spiffe://<td>/mediatore`.
    Mtls {
        source: WorkloadApiSource,
        server: SpiffeId,
    },
    /// The peer identity as a header, for a loopback `dev_mode` server.
    #[cfg(feature = "dev")]
    DevHeader(String),
}

impl SandboxClient {
    /// Obtain the transport identity. Fails closed: no Workload API, no client.
    async fn connect(cli: &Cli) -> anyhow::Result<Self> {
        let base = cli.mediatore_url.trim_end_matches('/').to_owned();
        #[cfg(feature = "dev")]
        if let Some(id) = &cli.dev_spiffe_id {
            tracing::warn!(
                "dev: peer identity sent as a header; only a loopback dev_mode server accepts this"
            );
            return Ok(Self {
                base,
                transport: Transport::DevHeader(id.clone()),
            });
        }
        let endpoint = mediatore_tls::endpoint(&cli.workload_api_socket.to_string_lossy());
        let source = WorkloadApiSource::connect(&endpoint)
            .await
            .map_err(|e| anyhow::anyhow!("Workload API at {endpoint}: {e}"))?;
        let own = source.current()?;
        let server = SpiffeId::new(format!("spiffe://{}/mediatore", own.trust_domain()))?;
        tracing::info!(spiffe_id = %own.spiffe_id, broker = %server, "node SVID from the Workload API");
        Ok(Self {
            base,
            transport: Transport::Mtls { source, server },
        })
    }

    /// Send one request with this node's identity. The mTLS client is built per request
    /// from the current material, so a rotated SVID is used by the next call.
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> anyhow::Result<reqwest::Response> {
        let url = format!("{}{path}", self.base);
        let req = match &self.transport {
            Transport::Mtls { source, server } => {
                let cfg = mediatore_tls::client_config(source.current()?.as_ref(), server)?;
                reqwest::Client::builder()
                    .use_preconfigured_tls(cfg)
                    .build()?
                    .request(method, url)
            }
            #[cfg(feature = "dev")]
            Transport::DevHeader(id) => reqwest::Client::new()
                .request(method, url)
                .header(DEV_PEER_HEADER, id),
        };
        let req = match body {
            Some(b) => req.json(b),
            None => req,
        };
        Ok(req.send().await?)
    }

    /// Register this node until mediatore accepts it. A 409 is fatal: it means this EK is
    /// already known under another VM, which is exactly the cloned-TPM case.
    async fn register(&self, reg: &NodeRegistration) -> anyhow::Result<NodeRegistered> {
        loop {
            match self.send(Method::POST, "/v1/nodes", Some(reg)).await {
                Ok(r) if r.status().is_success() => return Ok(r.json().await?),
                Ok(r) if r.status() == reqwest::StatusCode::CONFLICT => {
                    anyhow::bail!(
                        "EK already registered for another VM: {}",
                        r.text().await.unwrap_or_default()
                    );
                }
                Ok(r) => {
                    tracing::warn!(status = %r.status(), "registration refused; retrying");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "mediatore unreachable; retrying");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(REGISTER_RETRY_SECS)).await;
        }
    }

    /// Poll until a claim is bound to this node.
    async fn wait_for_subject(&self) -> anyhow::Result<Me> {
        loop {
            match self.send(Method::GET, "/v1/me", None::<&()>).await {
                Ok(r) if r.status().is_success() => return Ok(r.json().await?),
                Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                    tracing::debug!("no claim bound yet");
                }
                Ok(r) => {
                    anyhow::bail!(
                        "/v1/me refused: {} {}",
                        r.status(),
                        r.text().await.unwrap_or_default()
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "mediatore unreachable; retrying");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(ME_POLL_SECS)).await;
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mediatore_proto::tls::ensure_provider();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();

    // 1. Who am I, as a node.
    let ek_hash = if let Some(h) = &cli.dev_ek_hash {
        h.clone()
    } else {
        std::fs::create_dir_all("/run/mediatore-guest")?;
        identity::ek_hash(&cli.tpm).await?
    };
    let dmi_uuid = match cli.dev_dmi_uuid {
        Some(u) => u,
        None => identity::dmi_uuid()?,
    };
    let reg = NodeRegistration {
        ek_hash,
        dmi_uuid,
        hostname: identity::hostname().unwrap_or_else(|_| "unknown".into()),
        provider: cli.provider.map(Into::into),
    };
    tracing::info!(ek_hash = %reg.ek_hash, dmi = %reg.dmi_uuid, "node identity computed");

    // 2. Talk to mediatore. Fail closed without a transport identity.
    let client = SandboxClient::connect(&cli).await?;
    let registered = client.register(&reg).await?;
    tracing::info!(node_id = %registered.node_id, "node registered");

    // 3. Wait for a claim, then learn who the sandbox is for.
    let me = client.wait_for_subject().await?;
    let username = me.subject.sandbox_username();
    tracing::info!(
        claim_uid = %me.claim_uid,
        subject = %me.subject.id,
        user = %username,
        expires_at = %me.expires_at,
        "subject fetched"
    );
    if cli.dev_skip_setup {
        tracing::warn!("dev: skipping user creation and jail; done");
        return Ok(());
    }

    // 4. User, sandbox filesystem, jail.
    anyhow::ensure!(
        !me.workload.args.is_empty(),
        "claim has no workload command to run"
    );
    user::ensure(&me.subject).await?;
    let (rootfs, work) = jail::JailSpec::default_paths(&cli.sandbox_root);
    anyhow::ensure!(
        rootfs.is_dir(),
        "workload rootfs {} does not exist; unpacking {} is not wired yet",
        rootfs.display(),
        me.workload.image
    );
    std::fs::create_dir_all(&work)?;
    let spec = jail::JailSpec {
        user: username.clone(),
        rootfs,
        work,
        workload_api_socket: cli.workload_api_socket.clone(),
        mediatore_url: cli.mediatore_url.clone(),
        argv: me.workload.args.clone(),
        rlimit_as_mib: jail::DEFAULT_RLIMIT_AS_MIB,
    };

    // 5. Supervise until the deadline, then tear down. Also tear down on a supervision
    //    error: no partial-trust mode.
    let result = supervise::run(&spec, me.expires_at).await;
    supervise::teardown(&cli.sandbox_root, &username).await;
    result
}
