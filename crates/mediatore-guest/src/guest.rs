// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! `mediatore guest`: turns a bound banlieue claim into a jailed, identity-bearing workload.
//!
//! State machine (runbook Part 6.1):
//! boot → node registered → `GuestReady` announced → subject fetched → user created →
//! tmpfs mounted → image pulled → ruleset loaded → jail running → torn down.

use std::path::{Path, PathBuf};

use mediatore_proto::{Me, NodeRegistered, NodeRegistration, Provider};
use reqwest::Method;
use uuid::Uuid;

use crate::client::SandboxClient;
use crate::{identity, image, jail, net, ready, sandboxfs, supervise, user};

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
    /// Sandbox root: a tmpfs mounted per claim (ADR-0021)
    #[arg(long, default_value = jail::SANDBOX_ROOT)]
    pub sandbox_root: PathBuf,
    /// Size of that tmpfs, in the kernel's syntax: bytes with k, m or g, or a percentage of RAM
    #[arg(
        long,
        env = "MEDIATORE_SANDBOX_SIZE",
        default_value = sandboxfs::DEFAULT_SIZE,
        value_parser = tmpfs_size
    )]
    pub sandbox_size: String,
    /// A registry (host[:port]) reached over plain HTTP instead of HTTPS; repeatable, or
    /// comma-separated in the environment
    #[arg(
        long = "plain-http-registry",
        env = "MEDIATORE_PLAIN_HTTP_REGISTRIES",
        value_name = "HOST[:PORT]",
        value_delimiter = ','
    )]
    pub plain_http_registries: Vec<String>,
    /// The mediatore binary to mount read-only into the jail: the path the node entry pins,
    /// never the path this process happens to run from
    #[arg(long, default_value = mediatore_proto::AGENT_BINARY_PATH)]
    pub agent_binary: PathBuf,
    /// Where the installed-guest marker goes once the node is registered (banlieue
    /// ADR-0043, read by libvirt's provider through the guest agent; ADR-0019)
    #[arg(long, default_value = ready::PHASE_FILE)]
    pub phase_file: PathBuf,
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

fn tmpfs_size(s: &str) -> Result<String, String> {
    if sandboxfs::size_is_valid(s) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "{s:?} is not a tmpfs size (a number with k, m, g or %)"
        ))
    }
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
    // Only now is this member ready for a claim (ADR-0019): attested (the SVID came from
    // the agent) and known to mediatore as a node. Tell the pool, on whatever channel the
    // hypervisor reads. Not fatal: a member that cannot say so is never handed out.
    ready::announce(&ready::Channels::detect(args.phase_file.clone()))
        .await
        .log();

    // 3. Wait for a claim, then learn who the sandbox is for.
    let me = wait_for_subject(&client).await?;
    let username = me.subject.sandbox_username();
    tracing::info!(
        claim_uid = %me.claim_uid,
        subject = %me.subject.id,
        user = %username,
        expires_at = %me.expires_at,
        egress = me.egress.len(),
        registry_credential = me.registry_credential.as_ref().map(|c| c.host.as_str()),
        "subject fetched"
    );
    if args.dev_skip_setup {
        tracing::warn!("dev: skipping user creation and jail; done");
        return Ok(());
    }

    // 4. What the claim asks for, checked before anything is built.
    anyhow::ensure!(
        !me.workload.args.is_empty(),
        "claim has no workload command to run"
    );
    let reference: mediatore_proto::image::ImageReference = me
        .workload
        .image
        .parse()
        .map_err(|e| anyhow::anyhow!("claim workload image: {e}"))?;
    // The pinned path (ADR-0014 decision 5), not `current_exe`: what the node entry selects
    // is what the workload gets, and a guest started from elsewhere mounts nothing else.
    anyhow::ensure!(
        args.agent_binary.is_file(),
        "agent binary {} is not a file; the jail needs the pinned binary",
        args.agent_binary.display()
    );
    user::ensure(&me.subject).await?;
    let uid = user::uid(&username).await?;
    let gid = user::gid(&username).await?;

    // 5. Build and run the sandbox, then tear down. Also tear down on an error: no
    //    partial-trust mode.
    let result = serve_claim(&args, &me, &username, &reference, uid, gid).await;
    supervise::teardown(&args.sandbox_root, &username).await;
    result
}

/// Tmpfs, rootfs, ruleset, jail (ADR-0021 decision 5), then supervise until the deadline.
/// No jail without the ruleset (ADR-0020 decision 5), no ruleset without the rootfs.
async fn serve_claim(
    args: &GuestArgs,
    me: &Me,
    username: &str,
    reference: &mediatore_proto::image::ImageReference,
    uid: u32,
    gid: u32,
) -> anyhow::Result<()> {
    let tmpfs = sandboxfs::Tmpfs {
        root: args.sandbox_root.clone(),
        size: args.sandbox_size.clone(),
    };
    tmpfs.mount().await?;
    let layout = sandboxfs::prepare(&args.sandbox_root, uid, gid)?;
    let pulled = image::Puller::new(&args.plain_http_registries)?
        .pull(
            reference,
            me.registry_credential.as_ref(),
            &layout.rootfs,
            &layout.layers,
        )
        .await?;
    tracing::info!(
        claim_uid = %me.claim_uid,
        image = %reference,
        image_digest = %pulled.digest,
        layers = pulled.layers,
        bytes = pulled.bytes,
        "workload image pulled"
    );
    let ruleset = net::Ruleset::resolve(
        uid,
        &args.mediatore_url,
        &me.egress,
        Path::new(net::RESOLV_CONF),
    )
    .await?;
    // The inner layer gets the same destinations' ports (ADR-0024 decision 2).
    let spec = jail::JailSpec {
        user: username.to_string(),
        rootfs: layout.rootfs,
        work: layout.work,
        workload_api_socket: args.workload_api_socket.clone(),
        mediatore_url: args.mediatore_url.clone(),
        agent_binary: args.agent_binary.clone(),
        argv: me.workload.args.clone(),
        rlimit_as_mib: jail::DEFAULT_RLIMIT_AS_MIB,
        connect_ports: jail::connect_ports(ruleset.allow.iter()),
    };
    let sha256 = net::load(&ruleset).await?;
    tracing::info!(
        claim_uid = %me.claim_uid,
        user = username,
        uid,
        destinations = ruleset.allow.len(),
        resolvers = ruleset.dns.len(),
        ruleset_sha256 = %sha256,
        "sandbox ruleset loaded"
    );
    supervise::run(&spec, me.expires_at).await
}
