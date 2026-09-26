//! mediatore-guest: turns a bound banlieue claim into a jailed, identity-bearing workload.
//!
//! State machine (runbook Part 6.1):
//! boot → node registered → subject fetched → user created → jail running → torn down.
//!
//! Transport: mTLS with the node SVID from the Workload API is the production path and is
//! not wired yet. Until it is, the binary only talks to a `dev_mode` server, sending the
//! peer identity as a header; without `--dev-spiffe-id` it fails closed.

mod identity;
mod jail;
mod supervise;
mod user;

use std::path::PathBuf;

use clap::Parser;
use mediatore_proto::{Me, NodeRegistered, NodeRegistration, Provider};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

/// Header carrying the peer SPIFFE ID against a `dev_mode` server.
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

/// HTTP client for the sandbox listener. Dev header now, SPIFFE mTLS next.
struct SandboxClient {
    base: String,
    http: reqwest::Client,
    dev_spiffe_id: String,
}

impl SandboxClient {
    fn new(base: &str, dev_spiffe_id: &str) -> anyhow::Result<Self> {
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            http: reqwest::Client::builder().build()?,
            dev_spiffe_id: dev_spiffe_id.to_owned(),
        })
    }

    /// Register this node until mediatore accepts it. A 409 is fatal: it means this EK is
    /// already known under another VM, which is exactly the cloned-TPM case.
    async fn register(&self, reg: &NodeRegistration) -> anyhow::Result<NodeRegistered> {
        loop {
            let resp = self
                .http
                .post(format!("{}/v1/nodes", self.base))
                .header(DEV_PEER_HEADER, &self.dev_spiffe_id)
                .json(reg)
                .send()
                .await;
            match resp {
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
            let resp = self
                .http
                .get(format!("{}/v1/me", self.base))
                .header(DEV_PEER_HEADER, &self.dev_spiffe_id)
                .send()
                .await;
            match resp {
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
    let Some(dev_id) = &cli.dev_spiffe_id else {
        anyhow::bail!("mTLS not wired yet; set --dev-spiffe-id against a dev_mode server");
    };
    let client = SandboxClient::new(&cli.mediatore_url, dev_id)?;
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
