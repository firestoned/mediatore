//! mediatore-guest: turns a bound banlieue claim into a jailed, identity-bearing workload.
//!
//! State machine (runbook Part 6.1):
//! boot → node registered → subject fetched → user created → jail running → torn down.

mod identity;
mod jail;
mod user;

use std::path::PathBuf;

use clap::Parser;
use mediatore_proto::{NodeRegistration, Provider};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "mediatore-guest", version, about = "banlieue sandbox in-guest agent")]
struct Cli {
    /// mediatore sandbox-facing base URL
    #[arg(long, env = "MEDIATORE_URL")]
    mediatore_url: String,
    /// SPIRE Workload API socket
    #[arg(long, env = "SPIFFE_ENDPOINT_SOCKET", default_value = "/run/spire/sockets/agent.sock")]
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let cli = Cli::parse();

    // 1. Who am I, as a node.
    std::fs::create_dir_all("/run/mediatore-guest")?;
    let reg = NodeRegistration {
        ek_hash: identity::ek_hash(&cli.tpm).await?,
        dmi_uuid: identity::dmi_uuid()?,
        hostname: identity::hostname()?,
        provider: cli.provider.map(Into::into),
    };
    tracing::info!(ek_hash = %reg.ek_hash, dmi = %reg.dmi_uuid, "node identity computed");

    // 2. Register with mediatore over the node SVID (mTLS via the Workload API): next step.
    //    Then poll GET /v1/me until a claim is bound, create the user, unpack the rootfs and
    //    supervise the jail until expires_at.
    tracing::warn!(
        url = %cli.mediatore_url,
        socket = %cli.workload_api_socket.display(),
        root = %cli.sandbox_root.display(),
        "scaffold: registration, subject fetch and jail supervision not wired yet"
    );
    Ok(())
}
