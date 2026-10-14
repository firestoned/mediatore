// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! `mediatore guest`: turns a bound banlieue claim into a jailed, identity-bearing workload.
//!
//! State machine (runbook Part 6.1):
//! boot → node registered → subject fetched → user created → jail running → torn down.

use std::path::PathBuf;

use mediatore_proto::{Me, NodeRegistered, NodeRegistration, Provider};
use reqwest::Method;
use uuid::Uuid;

use crate::client::SandboxClient;
use crate::{identity, jail, supervise, user};

/// Seconds between registration retries while mediatore is unreachable.
const REGISTER_RETRY_SECS: u64 = 5;
/// Seconds between `GET /v1/me` polls while no claim is bound.
const ME_POLL_SECS: u64 = 5;

/// Arguments of the `guest` role.
#[derive(Debug, clap::Args)]
pub struct GuestArgs {
    /// mediatore sandbox-facing base URL
    #[arg(long, env = "MEDIATORE_URL")]
    pub mediatore_url: String,
    /// SPIRE Workload API socket
    #[arg(
        long,
        env = "SPIFFE_ENDPOINT_SOCKET",
        default_value = "/run/spire/sockets/agent.sock"
    )]
    pub workload_api_socket: PathBuf,
    /// TPM device
    #[arg(long, default_value = "/dev/tpmrm0")]
    pub tpm: PathBuf,
    /// Hypervisor hint for audit
    #[arg(long, value_enum)]
    pub provider: Option<ProviderArg>,
    /// Sandbox root
    #[arg(long, default_value = jail::SANDBOX_ROOT)]
    pub sandbox_root: PathBuf,
    /// The mediatore binary to mount read-only into the jail: the path the node entry pins,
    /// never the path this process happens to run from
    #[arg(long, default_value = mediatore_proto::AGENT_BINARY_PATH)]
    pub agent_binary: PathBuf,
    /// Dev only: send this SPIFFE ID as a header instead of doing mTLS
    #[cfg(feature = "dev")]
    #[arg(long, env = "MEDIATORE_DEV_SPIFFE_ID", hide = true)]
    pub dev_spiffe_id: Option<String>,
    /// Dev only: use this EK hash instead of reading the TPM
    #[arg(long, hide = true)]
    pub dev_ek_hash: Option<String>,
    /// Dev only: use this DMI UUID instead of reading sysfs
    #[arg(long, hide = true)]
    pub dev_dmi_uuid: Option<Uuid>,
    /// Dev only: stop after fetching the subject; no user, no jail
    #[arg(long, hide = true)]
    pub dev_skip_setup: bool,
}

/// The hypervisor, as the command line names it.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ProviderArg {
    /// `vSphere`.
    #[value(help = "VMware vSphere")]
    Vsphere,
    /// Cloud Hypervisor
    CloudHypervisor,
    /// libvirt (KVM)
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

/// Obtain the transport identity for this node. Fails closed: no Workload API, no client.
async fn connect(args: &GuestArgs) -> anyhow::Result<SandboxClient> {
    #[cfg(feature = "dev")]
    if let Some(id) = &args.dev_spiffe_id {
        return Ok(SandboxClient::dev_header(&args.mediatore_url, id));
    }
    SandboxClient::connect(
        &args.mediatore_url,
        &args.workload_api_socket.to_string_lossy(),
    )
    .await
}

/// Register this node until mediatore accepts it. A 409 is fatal: it means this EK is
/// already known under another VM, which is exactly the cloned-TPM case.
async fn register(
    client: &SandboxClient,
    reg: &NodeRegistration,
) -> anyhow::Result<NodeRegistered> {
    loop {
        match client.send(Method::POST, "/v1/nodes", Some(reg)).await {
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
async fn wait_for_subject(client: &SandboxClient) -> anyhow::Result<Me> {
    loop {
        match client.send(Method::GET, "/v1/me", None::<&()>).await {
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

/// Run the guest role: register, wait for a claim, set up the user and the jail, supervise
/// until the deadline, tear down.
pub async fn run(args: GuestArgs) -> anyhow::Result<()> {
    // 1. Who am I, as a node.
    let ek_hash = if let Some(h) = &args.dev_ek_hash {
        h.clone()
    } else {
        std::fs::create_dir_all("/run/mediatore-guest")?;
        identity::ek_hash(&args.tpm).await?
    };
    let dmi_uuid = match args.dev_dmi_uuid {
        Some(u) => u,
        None => identity::dmi_uuid()?,
    };
    let reg = NodeRegistration {
        ek_hash,
        dmi_uuid,
        hostname: identity::hostname().unwrap_or_else(|_| "unknown".into()),
        provider: args.provider.map(Into::into),
    };
    tracing::info!(ek_hash = %reg.ek_hash, dmi = %reg.dmi_uuid, "node identity computed");

    // 2. Talk to mediatore. Fail closed without a transport identity.
    let client = connect(&args).await?;
    let registered = register(&client, &reg).await?;
    tracing::info!(node_id = %registered.node_id, "node registered");

    // 3. Wait for a claim, then learn who the sandbox is for.
    let me = wait_for_subject(&client).await?;
    let username = me.subject.sandbox_username();
    tracing::info!(
        claim_uid = %me.claim_uid,
        subject = %me.subject.id,
        user = %username,
        expires_at = %me.expires_at,
        "subject fetched"
    );
    if args.dev_skip_setup {
        tracing::warn!("dev: skipping user creation and jail; done");
        return Ok(());
    }

    // 4. User, sandbox filesystem, jail.
    anyhow::ensure!(
        !me.workload.args.is_empty(),
        "claim has no workload command to run"
    );
    user::ensure(&me.subject).await?;
    let (rootfs, work) = jail::JailSpec::default_paths(&args.sandbox_root);
    anyhow::ensure!(
        rootfs.is_dir(),
        "workload rootfs {} does not exist; unpacking {} is not wired yet",
        rootfs.display(),
        me.workload.image
    );
    std::fs::create_dir_all(&work)?;
    // The pinned path (ADR-0014 decision 5), not `current_exe`: what the node entry selects
    // is what the workload gets, and a guest started from elsewhere mounts nothing else.
    anyhow::ensure!(
        args.agent_binary.is_file(),
        "agent binary {} is not a file; the jail needs the pinned binary",
        args.agent_binary.display()
    );
    let spec = jail::JailSpec {
        user: username.clone(),
        rootfs,
        work,
        workload_api_socket: args.workload_api_socket.clone(),
        mediatore_url: args.mediatore_url.clone(),
        agent_binary: args.agent_binary.clone(),
        argv: me.workload.args.clone(),
        rlimit_as_mib: jail::DEFAULT_RLIMIT_AS_MIB,
    };

    // 5. Supervise until the deadline, then tear down. Also tear down on a supervision
    //    error: no partial-trust mode.
    let result = supervise::run(&spec, me.expires_at).await;
    supervise::teardown(&args.sandbox_root, &username).await;
    result
}
