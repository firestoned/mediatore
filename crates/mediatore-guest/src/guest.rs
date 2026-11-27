// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! `mediatore guest`: turns a bound banlieue claim into a jailed, identity-bearing workload.
//!
//! State machine (runbook Part 6.1):
//! boot → node registered → `GuestReady` announced → subject fetched → user created →
//! tmpfs mounted → image pulled → ruleset loaded → egress proxy up → jail running → torn down.
//!
//! The gateways the ruleset and the proxy use come from `GET /v1/me`, or from the pool's
//! bootstrap file when the broker lists none (ADR-0027 decision 4); with none at all the
//! proxy dials its upstreams directly (ADR-0028's implementation notes).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use mediatore_proto::{Attestation, Me, NodeRegistered, NodeRegistration, Provider};
use reqwest::Method;
use uuid::Uuid;

use crate::client::SandboxClient;
use crate::{egress, identity, image, jail, logs, net, ready, report, sandboxfs, supervise, user};

/// Seconds between registration retries while mediatore is unreachable.
const REGISTER_RETRY_SECS: u64 = 5;
/// Seconds between `GET /v1/me` polls while no claim is bound.
const ME_POLL_SECS: u64 = 5;
/// How long the egress proxy gets to report ready before the claim fails. Longer than the
/// proxy's own wait for the claim SVID (`client::WORKLOAD_API_WAIT`), so that a claim
/// whose entry never reaches the agent ends with the proxy's error, which names it.
const PROXY_READY_SECS: u64 = 120;

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
    /// TPM device; read only under `--node-attestation tpm`
    #[arg(long, default_value = "/dev/tpmrm0")]
    pub tpm: PathBuf,
    /// How this node's SPIRE agent attested (ADR-0049 decision 8): `tpm` on a guest with a
    /// vTPM, `x509pop` on one without, whose names are read from the certificate
    /// `mediatore node-cert` wrote. Any other value is refused
    #[arg(
        long,
        env = "MEDIATORE_NODE_ATTESTATION",
        value_enum,
        default_value_t = NodeAttestationArg::Tpm
    )]
    pub node_attestation: NodeAttestationArg,
    /// The directory `mediatore node-cert` keeps the node certificate in; read only under
    /// `--node-attestation x509pop`
    #[arg(long, env = "MEDIATORE_NODE_CERT_DIR", default_value = crate::nodecert::DEFAULT_DIR)]
    pub node_cert_dir: PathBuf,
    /// Hypervisor hint for audit; read from the firmware vendor when absent
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
    /// Refused when set (ADR-0063 decision 4): the gateway's registry leg of ADR-0038 is gone. Read only so that an
    /// old env file fails the boot instead of being ignored
    #[arg(
        long = "relay-registry",
        env = "MEDIATORE_RELAY_REGISTRIES",
        value_name = "HOST=PORT",
        value_delimiter = ','
    )]
    pub relay_registries: Vec<String>,
    /// A PEM of CA certificates trusted beside the Mozilla roots for the pull: the
    /// registry mirror on the segment, on the operator's PKI (ADR-0029 decision 1)
    #[arg(long, env = "MEDIATORE_REGISTRY_CA", value_name = "PEM")]
    pub registry_ca: Option<PathBuf>,
    /// A PEM of CA certificates the egress proxy trusts beside the Mozilla roots for the hosts a
    /// policy bundle lists (direct egress): an operator's private CA bundle (the public image
    /// carries none). Without it only publicly trusted hosts verify
    #[arg(long, env = "MEDIATORE_EGRESS_CA", value_name = "PEM")]
    pub egress_ca: Option<PathBuf>,
    /// The lowest TLS version the egress proxy offers those hosts: `1.3` (the default) or
    /// `1.2`, which still offers 1.3 first and falls back only for a host that has no 1.3.
    /// It reaches nothing else: the broker, the registry pull and the identity provider
    /// stay TLS 1.3 only
    #[arg(
        long,
        env = "MEDIATORE_EGRESS_MIN_TLS",
        default_value_t = mediatore_proto::tls::UpstreamTls::Tls13
    )]
    pub egress_min_tls: mediatore_proto::tls::UpstreamTls,
    /// The mediatore binary to mount read-only into the jail and to start the egress proxy
    /// from: the path the node entry pins, never the path this process happens to run from
    #[arg(long, default_value = mediatore_proto::AGENT_BINARY_PATH)]
    pub agent_binary: PathBuf,
    /// The egress proxy's loopback port (ADR-0025): the one TCP port the jail may connect to
    #[arg(
        long,
        env = "MEDIATORE_EGRESS_PROXY_PORT",
        default_value_t = egress::DEFAULT_PORT
    )]
    pub egress_proxy_port: u16,
    /// The loopback port of the proxy's pull listener (ADR-0043 decision 3), used only for a claim whose image is on a
    /// registry the gateway places a credential for: root's puller reaches the registry through it. A port no jail
    /// rule lists.
    #[arg(
        long,
        env = "MEDIATORE_EGRESS_PULL_PORT",
        default_value_t = egress::DEFAULT_PULL_PORT
    )]
    pub egress_pull_port: u16,
    /// How long the pull may go with nothing read, in seconds (ADR-0063 decision 9): a registry, proxy or gateway that
    /// stalls fails the claim before the jail, with the registry named
    #[arg(long, env = "MEDIATORE_PULL_IDLE_SECS", default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
    pub pull_idle_secs: u64,
    /// How long the whole pull may take, in seconds (ADR-0063 decision 9), and never past the claim's own deadline
    #[arg(long, env = "MEDIATORE_PULL_DEADLINE_SECS", default_value_t = 900, value_parser = clap::value_parser!(u64).range(1..))]
    pub pull_deadline_secs: u64,
    /// The pool's bootstrap list of egress gateways (ADR-0027 decision 4), one host:port
    /// per line, used when the broker lists none; absent on a pool with no gateway
    #[arg(long, env = "MEDIATORE_GATEWAYS_FILE", default_value = net::GATEWAYS_FILE)]
    pub gateways_file: PathBuf,
    /// Where the installed-guest marker goes once the node is registered (banlieue
    /// ADR-0043, read by libvirt's provider through the guest agent; ADR-0019)
    #[arg(long, default_value = ready::PHASE_FILE)]
    pub phase_file: PathBuf,
    /// Dev only: send this SPIFFE ID as a header instead of doing mTLS
    #[cfg(feature = "dev")]
    #[arg(long, env = "MEDIATORE_DEV_SPIFFE_ID", hide = true)]
    pub dev_spiffe_id: Option<String>,
    /// Dev only: use this EK hash instead of reading the TPM (`--node-attestation tpm` only)
    #[arg(long, hide = true)]
    pub dev_ek_hash: Option<String>,
    /// Dev only: use this DMI UUID instead of reading sysfs
    #[arg(long, hide = true)]
    pub dev_dmi_uuid: Option<Uuid>,
    /// Dev only: stop after fetching the subject; no user, no jail
    #[arg(long, hide = true)]
    pub dev_skip_setup: bool,
}

/// The pull client for this guest: plain-HTTP registries and the operator's CA (a direct pool, ADR-0029). A pool with
/// gateways pulls through the claim's proxy (ADR-0063), which [`image::Puller::with_placed_registry`] adds per claim.
fn puller(
    plain_http: &[String],
    registry_ca: Option<&std::path::Path>,
) -> anyhow::Result<image::Puller> {
    let mut client = image::Puller::new(plain_http)?;
    if let Some(ca) = registry_ca {
        let pem =
            std::fs::read(ca).map_err(|e| anyhow::anyhow!("registry CA {}: {e}", ca.display()))?;
        client = client
            .with_registry_ca(&pem)
            .map_err(|e| anyhow::anyhow!("registry CA {}: {e}", ca.display()))?;
    }
    Ok(client)
}

/// The pull's bounds for one claim (ADR-0063 decision 9): the configured idle and whole-pull values, the whole pull cut
/// to what is left of the claim. A claim already past its deadline is not pulled at all.
fn pull_bounds(
    idle_secs: u64,
    deadline_secs: u64,
    claim_expires_at: jiff::Timestamp,
    now: jiff::Timestamp,
) -> anyhow::Result<image::PullBounds> {
    let left = claim_expires_at.duration_since(now);
    anyhow::ensure!(
        left.is_positive(),
        "the claim's deadline {claim_expires_at} has passed; nothing is pulled"
    );
    let left = std::time::Duration::try_from(left)?;
    Ok(image::PullBounds {
        idle: std::time::Duration::from_secs(idle_secs),
        deadline: std::time::Duration::from_secs(deadline_secs).min(left),
        ..image::PullBounds::default()
    })
}

/// Which registry, if any, the claim's image is pulled from through its egress proxy (ADR-0063 decision 1): with
/// gateways, always, by the claim's route for it, and a claim with no such route is refused (the broker refuses it
/// first, `registry_not_granted`); without gateways, only a registry a route serves (ADR-0043), `None` otherwise.
fn through_the_proxy(
    routes: &[mediatore_proto::Route],
    registry: &str,
    with_gateways: bool,
) -> anyhow::Result<Option<String>> {
    let host = egress::pull_registry(routes, registry);
    anyhow::ensure!(
        host.is_some() || !with_gateways,
        "the image's registry {registry} has no route on this claim: with gateways every pull goes through the claim's egress proxy and a gateway, never around them (ADR-0063 decision 1)"
    );
    Ok(host)
}

/// The pull settings that would reach a registry around the gateway, refused on a pool that names gateways (ADR-0063
/// decision 4): the relay's registry leg and plain HTTP to a registry on the segment.
fn refuse_bypasses(args: &GuestArgs, with_gateways: bool) -> anyhow::Result<()> {
    // The relay's registry leg is gone from every gateway, so the variable names nothing anywhere.
    anyhow::ensure!(
        args.relay_registries.is_empty(),
        "MEDIATORE_RELAY_REGISTRIES is set: the relay has no registry leg any more; the pull goes through the claim's egress proxy and a gateway; remove it (ADR-0063 decision 4)"
    );
    anyhow::ensure!(
        !with_gateways || args.plain_http_registries.is_empty(),
        "MEDIATORE_PLAIN_HTTP_REGISTRIES is set on a pool with gateways: the pull goes through the claim's egress proxy and a gateway, never around them; remove it (ADR-0063 decision 4)"
    );
    Ok(())
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

/// The node attestor, as the command line names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NodeAttestationArg {
    /// The TPM attestor: the node is its endorsement key's hash
    Tpm,
    /// The x509pop attestor: the node is its certificate's issuer and subject common names
    X509pop,
}

/// What this node tells the broker about how it attested: the top-level EK hash and no
/// attestation for a TPM node (byte for byte what every guest up to v0.4.0 sent, so an older
/// broker takes it), or the `x509pop` attestation and no EK hash (ADR-0049 decision 8).
///
/// Under `x509pop` the TPM is never opened and `--dev-ek-hash` is refused: the names come
/// from the node certificate or the guest does not start.
async fn node_attestation(args: &GuestArgs) -> anyhow::Result<(String, Option<Attestation>)> {
    match args.node_attestation {
        NodeAttestationArg::Tpm => {
            let ek_hash = if let Some(h) = &args.dev_ek_hash {
                h.clone()
            } else {
                std::fs::create_dir_all("/run/mediatore-guest")?;
                identity::ek_hash(&args.tpm).await?
            };
            Ok((ek_hash, None))
        }
        NodeAttestationArg::X509pop => {
            anyhow::ensure!(
                args.dev_ek_hash.is_none(),
                "--dev-ek-hash is for --node-attestation tpm; an x509pop node has no EK hash"
            );
            let names = identity::x509pop_names(&args.node_cert_dir)?;
            Ok((
                String::new(),
                Some(Attestation::X509pop {
                    issuer_cn: names.issuer_cn,
                    subject_cn: names.subject_cn,
                }),
            ))
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

/// Bring an `x509pop` node's registration up to the certificate as it is on disk now.
/// `mediatore node-cert renew` replaces the file beside a running guest, and a host whose CA
/// was replaced by one of another name issues a leaf under that name: the agent then
/// attests under the new names, and a registration that kept sending the old ones would be
/// refused for as long as it retried. A TPM node's registration never changes.
///
/// # Errors
/// The certificate cannot be read or has no usable names: the same reason not to start.
fn refresh_attestation(args: &GuestArgs, reg: &mut NodeRegistration) -> anyhow::Result<()> {
    if args.node_attestation != NodeAttestationArg::X509pop {
        return Ok(());
    }
    let names = identity::x509pop_names(&args.node_cert_dir)?;
    let now = Some(Attestation::X509pop {
        issuer_cn: names.issuer_cn,
        subject_cn: names.subject_cn,
    });
    if reg.attestation != now {
        tracing::info!("the node certificate's names changed; registering under the new ones");
        reg.attestation = now;
    }
    Ok(())
}

/// Register this node until mediatore accepts it, each attempt with the node certificate's
/// names as they then are ([`refresh_attestation`]). A 409 is fatal: this node key (the EK,
/// or the x509pop identity) is already known under another VM, which is exactly the
/// cloned-TPM case, or under another agent ID.
async fn register(
    client: &SandboxClient,
    args: &GuestArgs,
    mut reg: NodeRegistration,
) -> anyhow::Result<NodeRegistered> {
    loop {
        refresh_attestation(args, &mut reg)?;
        match client.send(Method::POST, "/v1/nodes", Some(&reg)).await {
            Ok(r) if r.status().is_success() => return Ok(r.json().await?),
            Ok(r) if r.status() == reqwest::StatusCode::CONFLICT => {
                anyhow::bail!(
                    "node identity (EK or x509pop names) already registered for another VM, or under another agent ID: {}",
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
    // 0. A pool with gateways reaches a registry only through a claim's proxy (ADR-0063 decision 4): an env file that
    //    still names another way fails the boot loudly, before anything registers.
    refuse_bypasses(
        &args,
        !net::bootstrap_gateways(&args.gateways_file)?.is_empty(),
    )?;
    // 1. Who am I, as a node.
    let (ek_hash, attestation) = node_attestation(&args).await?;
    let dmi_uuid = match args.dev_dmi_uuid {
        Some(u) => u,
        None => identity::dmi_uuid()?,
    };
    let reg = NodeRegistration {
        ek_hash,
        attestation,
        dmi_uuid,
        hostname: identity::hostname().unwrap_or_else(|_| "unknown".into()),
        provider: args.provider.map(Into::into).or_else(|| {
            ready::provider_of(&std::fs::read_to_string(ready::DMI_SYS_VENDOR).unwrap_or_default())
        }),
    };
    match &reg.attestation {
        Some(Attestation::X509pop {
            issuer_cn,
            subject_cn,
        }) => {
            tracing::info!(attestation = "x509pop", %issuer_cn, %subject_cn, dmi = %reg.dmi_uuid, "node identity read from the node certificate");
        }
        _ => {
            tracing::info!(attestation = "tpm", ek_hash = %reg.ek_hash, dmi = %reg.dmi_uuid, "node identity computed");
        }
    }

    // 2. Talk to mediatore. Fail closed without a transport identity.
    let client = Arc::new(connect(&args).await?);
    let registered = register(&client, &args, reg).await?;
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
        routes = me.routes.len(),
        gateways = me.gateways.len(),
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
    let result = serve_claim(&args, &client, &me, &username, &reference, uid, gid).await;
    supervise::teardown(&args.sandbox_root, &username).await;
    result
}

/// Pull the claim's image and say so. `credential` is the operator's pull credential (ADR-0022), `None` for a
/// registry the gateway places a credential for (ADR-0043): the VM presents nothing there.
async fn pull_image(
    client: &image::Puller,
    credential: Option<&mediatore_proto::RegistryCredential>,
    me: &Me,
    reference: &mediatore_proto::image::ImageReference,
    layout: &sandboxfs::Layout,
) -> anyhow::Result<image::Pulled> {
    let pulled = client
        .pull(reference, credential, &layout.rootfs, &layout.layers)
        .await?;
    tracing::info!(
        claim_uid = %me.claim_uid,
        image = %reference,
        image_digest = %pulled.digest,
        layers = pulled.layers,
        bytes = pulled.bytes,
        "workload image pulled"
    );
    Ok(pulled)
}

/// Tmpfs, rootfs, ruleset, egress proxy, jail (ADR-0021 decision 5, ADR-0025), then
/// supervise until the deadline. No jail without the ruleset (ADR-0020 decision 5) or
/// without the proxy (ADR-0025 decision 1), no ruleset without the rootfs.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)] // one straight line of steps, each logged; splitting it would hide the order
async fn serve_claim(
    args: &GuestArgs,
    client: &Arc<SandboxClient>,
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
    let registry_client = puller(&args.plain_http_registries, args.registry_ca.as_deref())?
        .with_bounds(pull_bounds(
            args.pull_idle_secs,
            args.pull_deadline_secs,
            me.expires_at,
            jiff::Timestamp::now(),
        )?)?;
    // The gateways (ADR-0028 decision 6, ADR-0027 decision 4): the broker's list, or the
    // pool's bootstrap file when the broker has none, or neither and the proxy dials
    // directly. Which one decides the ruleset's shape and the proxy's dialer alike.
    let bootstrap = net::bootstrap_gateways(&args.gateways_file)?;
    let (gateways, source) = net::choose_gateways(&me.gateways, &bootstrap);
    match source {
        net::GatewaySource::Broker if !bootstrap.is_empty() && bootstrap != gateways => {
            tracing::info!(
                claim_uid = %me.claim_uid,
                broker = gateways.len(),
                bootstrap = bootstrap.len(),
                "the broker's gateways replace the pool's bootstrap list (ADR-0027 decision 4)"
            );
        }
        net::GatewaySource::Broker => {}
        net::GatewaySource::Bootstrap => tracing::info!(
            claim_uid = %me.claim_uid,
            file = %args.gateways_file.display(),
            gateways = gateways.len(),
            "the broker lists no gateway: the pool's bootstrap list is used (ADR-0027 decision 4)"
        ),
        net::GatewaySource::None => tracing::warn!(
            claim_uid = %me.claim_uid,
            "the environment lists no egress gateway: the proxy dials its upstreams directly and the ruleset admits the audiences' endpoints and DNS"
        ),
    }
    // With gateways every pull goes through the claim's own egress proxy and a gateway, decided there like any egress
    // (ADR-0063 decision 1): it waits for the proxy. Without gateways, a registry the gateway places a credential for
    // (ADR-0043) is pulled the same way, and every other registry here, as it always was.
    let pull_host = through_the_proxy(
        &me.routes,
        &reference.registry,
        source != net::GatewaySource::None,
    )?;
    let early = if pull_host.is_none() {
        Some(
            pull_image(
                &registry_client,
                me.registry_credential.as_ref(),
                me,
                reference,
                &layout,
            )
            .await?,
        )
    } else {
        None
    };
    let ruleset = net::Ruleset::resolve(
        uid,
        &args.mediatore_url,
        &me.egress,
        &gateways,
        Path::new(net::RESOLV_CONF),
        args.egress_proxy_port,
    )
    .await?;
    // A gateway-placed route's request goes from the proxy to `gateway:INJECT_PORT`, and the
    // proxy's sockets carry the sandbox uid (ADR-0040 decision 7): the uid's table names that
    // port at each gateway for a claim that has such a route, and for no other.
    let inject_ports = egress::inject_ports(&me.routes);
    let ruleset = ruleset.with_inject_ports(&gateways, &inject_ports)?;
    if !inject_ports.is_empty() {
        tracing::info!(
            claim_uid = %me.claim_uid,
            ports = ?inject_ports,
            gateways = gateways.len(),
            "gateway-placed routes: the sandbox uid may reach each gateway's inject port (ADR-0040 decision 7)"
        );
    }
    // The proxy's inputs (ADR-0025, ADR-0028): the routes, the gateways and a fresh
    // phantom, in files of the sandbox user's outside the jail; the phantom also goes to
    // the jail through nsjail's environment.
    let phantom = egress::Phantom::generate()?;
    let routes = egress::Routes::new(me.routes.clone())?;
    if routes.is_empty() {
        tracing::warn!(claim_uid = %me.claim_uid, "the claim has no routes: the jail reaches nowhere");
    }
    let files = egress::write_files(&layout.egress, &me.routes, &gateways, &phantom, uid, gid)?;
    let listen = std::net::SocketAddr::from(([127, 0, 0, 1], args.egress_proxy_port));
    let proxy_args = egress::command_args(
        listen,
        &args.mediatore_url,
        &args.workload_api_socket.to_string_lossy(),
        &files,
        &egress::UpstreamArgs {
            ca: args.egress_ca.clone(),
            min_tls: args.egress_min_tls,
        },
    );
    let pull_addr = std::net::SocketAddr::from(([127, 0, 0, 1], args.egress_pull_port));
    let mut proxy_args = proxy_args;
    if let Some(host) = &pull_host {
        // The pull port must be one no jail rule lists: not the proxy's, and not a port of any destination the
        // sandbox uid's table names (Landlock admits a listed port at any address; the table is what pins the address).
        anyhow::ensure!(
            args.egress_pull_port != args.egress_proxy_port
                && !ruleset
                    .allow
                    .iter()
                    .any(|(_, p)| *p == args.egress_pull_port),
            "the pull port {} is the proxy's or a destination's: choose another (MEDIATORE_EGRESS_PULL_PORT)",
            args.egress_pull_port
        );
        proxy_args.extend(egress::pull_args(pull_addr, host));
        tracing::info!(
            claim_uid = %me.claim_uid,
            registry = %host,
            %pull_addr,
            "the image is pulled through the claim's egress proxy and a gateway, no credential on this VM (ADR-0043, ADR-0063)"
        );
    }
    if args.egress_min_tls != mediatore_proto::tls::UpstreamTls::Tls13 {
        tracing::warn!(
            min_tls = %args.egress_min_tls,
            "the egress proxy accepts TLS {} from the hosts a policy lists: a weaker upstream than the default 1.3",
            args.egress_min_tls
        );
    }
    let sha256 = net::load(&ruleset).await?;
    tracing::info!(
        claim_uid = %me.claim_uid,
        user = username,
        uid,
        shape = %ruleset.shape,
        destinations = ruleset.allow.len(),
        resolvers = ruleset.dns.len(),
        proxy_port = ruleset.proxy_port,
        ruleset_sha256 = %sha256,
        "sandbox ruleset loaded"
    );
    // The proxy before the jail: the workload's only route out must exist when its first
    // instruction runs (ADR-0025 decision 1). For a gateway-placed registry it is also the pull's route, so it starts
    // before the pull (ADR-0043 decision 3).
    let mut proxy = egress::spawn(
        &args.agent_binary,
        &proxy_args,
        uid,
        gid,
        std::time::Duration::from_secs(PROXY_READY_SECS),
    )
    .await?;
    tracing::info!(
        claim_uid = %me.claim_uid,
        pid = proxy.id(),
        user = username,
        %listen,
        routes = routes.len(),
        gateways = gateways.len(),
        gateways_from = ?source,
        "egress proxy ready"
    );
    let pulled = if let Some(pulled) = early {
        pulled
    } else {
        let host = pull_host.as_deref().unwrap_or_default();
        let pulled = match registry_client
            .clone()
            .with_placed_registry(host, pull_addr)
        {
            // No credential: the gateway places it. Whatever fails ends the claim, with the proxy.
            Ok(client) => pull_image(&client, None, me, reference, &layout).await,
            Err(e) => Err(e),
        };
        match pulled {
            Ok(p) => p,
            Err(e) => {
                let _ = proxy.start_kill();
                let _ = proxy.wait().await;
                return Err(e);
            }
        }
    };
    // What ran, to the record (ADR-0029 decision 5): the image's digest, the sandbox
    // table's hash, the host table as nft lists it. The record's, not the jail's gate.
    let guest_report = mediatore_proto::GuestReport {
        image_digest: pulled.digest.clone(),
        sandbox_ruleset_sha256: sha256.clone(),
        host_table: report::host_table(ruleset.shape == net::Shape::Gateways).await,
    };
    match report::send(client, &guest_report).await {
        Ok(()) => tracing::info!(
            claim_uid = %me.claim_uid,
            image_digest = %guest_report.image_digest,
            host_table = ?guest_report.host_table,
            "report recorded at the broker"
        ),
        Err(e) => tracing::warn!(
            claim_uid = %me.claim_uid,
            error = %e,
            "the report did not reach the broker; the record will show none"
        ),
    }
    let spec = jail::JailSpec {
        user: username.to_string(),
        rootfs: layout.rootfs,
        work: layout.work,
        agent_binary: args.agent_binary.clone(),
        argv: me.workload.args.clone(),
        rlimit_as_mib: jail::DEFAULT_RLIMIT_AS_MIB,
        proxy_port: args.egress_proxy_port,
        phantom,
    };
    // The workload's output, when the claim asked for it (ADR-0045 decision 1): tee'd,
    // redacted (the phantom and every other credential the jail was given, decision 2) and
    // shipped over the node SVID; without the opt-in the jail inherits the console as before.
    let shipping = me.workload.logs.then(|| {
        let queue = Arc::new(logs::Queue::default());
        let capture = Arc::new(logs::Capture::new(spec.secret_values(), queue.clone()));
        let sink: Arc<dyn logs::LogSink> = Arc::new(logs::BrokerSink::new(client.clone(), me.claim_uid));
        let shipping = logs::Shipping::start(queue, sink, logs::ShipperConfig::default());
        tracing::info!(claim_uid = %me.claim_uid, logs = true, "workload output captured, redacted and shipped to the broker (ADR-0045)");
        (capture, shipping)
    });
    let result = supervise::run(
        &spec,
        me.expires_at,
        &mut proxy,
        me.workload.restart,
        shipping.as_ref().map(|(c, _)| c),
    )
    .await;
    // What is still queued goes before the exit is reported, bounded: the exit releases
    // the claim and the broker drops a batch after it (ADR-0045 decision 8).
    if let Some((_, shipping)) = shipping {
        let flushed = shipping.flush(logs::FLUSH_TIMEOUT).await;
        tracing::info!(claim_uid = %me.claim_uid, flushed, "workload output flushed");
    }
    // The proxy ends with the claim, whichever way it ended.
    if let Err(e) = proxy.start_kill() {
        tracing::debug!(error = %e, "egress proxy already gone");
    }
    let _ = proxy.wait().await;
    // A workload done by its restart policy: the broker ends the claim (ADR-0033
    // decision 2). Said once, bounded; the deadline still bounds the claim if unheard.
    if let Ok(supervise::Outcome::WorkloadDone { status, restarts }) = &result {
        use std::os::unix::process::ExitStatusExt as _;
        let exit = mediatore_proto::GuestExit {
            code: status.code(),
            signal: status.signal(),
            restarts: *restarts,
        };
        match report::send_exit(client, &exit).await {
            Ok(()) => {
                tracing::info!(claim_uid = %me.claim_uid, code = ?exit.code, signal = ?exit.signal, restarts = exit.restarts, "workload exit recorded at the broker; the claim is released");
            }
            Err(e) => {
                tracing::warn!(claim_uid = %me.claim_uid, error = %e, "the exit did not reach the broker; the claim ends at its deadline");
            }
        }
    }
    result.map(|_| ())
}

#[cfg(test)]
mod tests {
    /// The guest role's arguments, parsed as the binary parses them.
    fn guest_args(extra: &[&str]) -> Result<super::GuestArgs, clap::Error> {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            guest: super::GuestArgs,
        }
        let mut v = vec!["guest", "--mediatore-url", "https://192.0.2.1:3130"];
        v.extend_from_slice(extra);
        Cli::try_parse_from(v).map(|c| c.guest)
    }

    const EK: &str = "ec00000000000000000000000000000000000000000000000000000000000007";

    #[test]
    fn the_node_attestation_is_tpm_by_default_and_any_other_word_is_refused_at_start() {
        use super::NodeAttestationArg;
        assert_eq!(
            guest_args(&[]).unwrap().node_attestation,
            NodeAttestationArg::Tpm
        );
        assert_eq!(
            guest_args(&["--node-attestation", "tpm"])
                .unwrap()
                .node_attestation,
            NodeAttestationArg::Tpm
        );
        let x509pop = guest_args(&["--node-attestation", "x509pop"]).unwrap();
        assert_eq!(x509pop.node_attestation, NodeAttestationArg::X509pop);
        assert_eq!(
            x509pop.node_cert_dir,
            std::path::Path::new(crate::nodecert::DEFAULT_DIR),
            "where node-cert writes by default"
        );
        for refused in ["join_token", "X509POP", "x509", "", "tpm,x509pop"] {
            assert!(
                guest_args(&["--node-attestation", refused]).is_err(),
                "{refused:?} was accepted"
            );
        }
    }

    #[tokio::test]
    async fn a_tpm_node_sends_its_ek_hash_at_the_top_level_and_no_attestation() {
        let args = guest_args(&["--dev-ek-hash", EK]).unwrap();
        assert_eq!(
            super::node_attestation(&args).await.unwrap(),
            (EK.to_owned(), None),
            "what a v0.4.0 guest sent, so an older broker registers it"
        );
    }

    #[tokio::test]
    async fn an_x509pop_node_sends_its_leafs_names_and_never_opens_the_tpm() {
        let dir = tempfile::tempdir().unwrap();
        let ca = mediatore_testkit::x509pop::HostCa::new("hv-01");
        std::fs::write(
            dir.path().join(crate::nodecert::CERT_FILE),
            format!("{}{}", ca.leaf_pem("vm-uid-1"), ca.pem()),
        )
        .unwrap();
        // A TPM device that does not exist: reading it would fail the call.
        let no_tpm = dir.path().join("no-such-tpm");
        let args = guest_args(&[
            "--node-attestation",
            "x509pop",
            "--node-cert-dir",
            dir.path().to_str().unwrap(),
            "--tpm",
            no_tpm.to_str().unwrap(),
        ])
        .unwrap();
        let (ek_hash, attestation) = super::node_attestation(&args).await.unwrap();
        assert_eq!(ek_hash, "", "no EK hash beside an x509pop attestation");
        assert_eq!(
            attestation,
            Some(mediatore_proto::Attestation::X509pop {
                issuer_cn: "hv-01".into(),
                subject_cn: "vm-uid-1".into()
            })
        );
    }

    #[tokio::test]
    async fn an_x509pop_node_without_a_usable_certificate_does_not_start() {
        let dir = tempfile::tempdir().unwrap();
        let dir_arg = dir.path().to_str().unwrap();
        let args = |extra: &[&str]| {
            let mut v = vec!["--node-attestation", "x509pop", "--node-cert-dir", dir_arg];
            v.extend_from_slice(extra);
            guest_args(&v).unwrap()
        };
        // No certificate file: no fallback to the TPM, no registration.
        let err = super::node_attestation(&args(&[])).await.unwrap_err();
        assert!(err.to_string().contains("cannot read the node certificate"));
        // A leaf whose subject is not one path segment.
        let cert = dir.path().join(crate::nodecert::CERT_FILE);
        std::fs::write(
            &cert,
            mediatore_testkit::x509pop::HostCa::new("hv-01").leaf_pem("a/b"),
        )
        .unwrap();
        let err = super::node_attestation(&args(&[])).await.unwrap_err();
        assert!(err.to_string().contains("unusable"));
        // The dev EK hash is the TPM kind's: beside x509pop it is refused, even with a
        // good certificate on disk.
        std::fs::write(
            &cert,
            mediatore_testkit::x509pop::HostCa::new("hv-01").leaf_pem("vm-uid-1"),
        )
        .unwrap();
        let err = super::node_attestation(&args(&["--dev-ek-hash", EK]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("--dev-ek-hash"));
    }

    #[tokio::test]
    async fn each_registration_attempt_carries_the_names_of_the_certificate_as_it_is_then() {
        use mediatore_proto::{Attestation, NodeRegistration};
        use mediatore_testkit::x509pop::HostCa;
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join(crate::nodecert::CERT_FILE);
        std::fs::write(&cert, HostCa::new("hv-01").leaf_pem("vm-uid-1")).unwrap();
        let args = guest_args(&[
            "--node-attestation",
            "x509pop",
            "--node-cert-dir",
            dir.path().to_str().unwrap(),
        ])
        .unwrap();
        let (ek_hash, attestation) = super::node_attestation(&args).await.unwrap();
        let mut reg = NodeRegistration {
            ek_hash,
            attestation,
            dmi_uuid: uuid::Uuid::nil(),
            hostname: "member".into(),
            provider: None,
        };
        let names = |reg: &NodeRegistration| match &reg.attestation {
            Some(Attestation::X509pop {
                issuer_cn,
                subject_cn,
            }) => (issuer_cn.clone(), subject_cn.clone()),
            _ => panic!("not an x509pop registration"),
        };
        super::refresh_attestation(&args, &mut reg).unwrap();
        assert_eq!(names(&reg), ("hv-01".to_owned(), "vm-uid-1".to_owned()));
        // The host's CA was replaced by one of another name, and node-cert renewed.
        std::fs::write(&cert, HostCa::new("hv-01-2027").leaf_pem("vm-uid-1")).unwrap();
        super::refresh_attestation(&args, &mut reg).unwrap();
        assert_eq!(
            names(&reg),
            ("hv-01-2027".to_owned(), "vm-uid-1".to_owned())
        );
        assert_eq!(reg.ek_hash, "", "still no EK hash beside it");
        // The certificate gone or unusable: no attempt is made with stale names.
        std::fs::remove_file(&cert).unwrap();
        assert!(super::refresh_attestation(&args, &mut reg).is_err());
        // A TPM node's registration is left as it is, with no file read at all.
        let tpm = guest_args(&["--dev-ek-hash", EK]).unwrap();
        let mut reg = NodeRegistration::tpm(EK.into(), uuid::Uuid::nil(), "member".into());
        super::refresh_attestation(&tpm, &mut reg).unwrap();
        assert_eq!((reg.ek_hash.as_str(), &reg.attestation), (EK, &None));
    }

    #[test]
    fn a_pool_with_gateways_refuses_the_settings_that_reach_a_registry_around_them() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            guest: super::GuestArgs,
        }
        let args = |extra: &[&str]| {
            let mut v = vec!["guest", "--mediatore-url", "https://192.0.2.1:3130"];
            v.extend_from_slice(extra);
            Cli::try_parse_from(v).unwrap().guest
        };
        let plain = args(&["--plain-http-registry=registry.internal:5000"]);
        let err = super::refuse_bypasses(&plain, true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("MEDIATORE_PLAIN_HTTP_REGISTRIES") && err.contains("ADR-0063"),
            "{err}"
        );
        assert!(
            super::refuse_bypasses(&plain, false).is_ok(),
            "a direct pool keeps it"
        );
        // The relay leg is gone everywhere: refused with or without gateways.
        let relay = args(&["--relay-registry=registry.example=3132"]);
        for with_gateways in [true, false] {
            let err = super::refuse_bypasses(&relay, with_gateways)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("MEDIATORE_RELAY_REGISTRIES") && err.contains("ADR-0063"),
                "{err}"
            );
        }
        assert!(super::refuse_bypasses(&args(&[]), true).is_ok());
    }

    #[test]
    fn with_gateways_every_pull_goes_through_the_proxy_and_one_with_no_route_is_refused() {
        // ADR-0063 decision 1: there is no path around the gateway, the pull included.
        let mirror = mediatore_proto::Route {
            audience: Some("mirror".into()),
            endpoint: "mirror.home.example:443".parse().unwrap(),
            rules: vec![],
            ca_pem: None,
            credential: mediatore_proto::Credential::None,
            credential_header: None,
            inject_port: None,
            pull_only: true,
        };
        let routes = vec![mirror];
        assert_eq!(
            super::through_the_proxy(&routes, "mirror.home.example", true)
                .unwrap()
                .as_deref(),
            Some("mirror.home.example")
        );
        let err = super::through_the_proxy(&routes, "ghcr.io", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ghcr.io") && err.contains("ADR-0063"), "{err}");
        // Without gateways, a registry no route serves is pulled directly, as before.
        assert_eq!(
            super::through_the_proxy(&routes, "ghcr.io", false).unwrap(),
            None
        );
    }

    #[test]
    fn the_pull_is_bounded_by_the_configuration_and_never_past_the_claim() {
        let now: jiff::Timestamp = "2026-11-22T12:00:00Z".parse().unwrap();
        let far = now + jiff::SignedDuration::from_hours(4);
        let b = super::pull_bounds(60, 900, far, now).unwrap();
        assert_eq!(b.idle, std::time::Duration::from_mins(1));
        assert_eq!(b.deadline, std::time::Duration::from_mins(15));
        assert_eq!(b.connect, crate::image::PullBounds::default().connect);
        // A claim with five minutes left gets five minutes, not fifteen.
        let near = now + jiff::SignedDuration::from_mins(5);
        assert_eq!(
            super::pull_bounds(60, 900, near, now).unwrap().deadline,
            std::time::Duration::from_mins(5)
        );
        let err = super::pull_bounds(60, 900, now, now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("has passed"), "{err}");
    }

    #[test]
    fn a_pull_bound_of_zero_is_refused_at_start() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            guest: super::GuestArgs,
        }
        for (flag, env) in [
            ("--pull-idle-secs", "MEDIATORE_PULL_IDLE_SECS"),
            ("--pull-deadline-secs", "MEDIATORE_PULL_DEADLINE_SECS"),
        ] {
            let err = Cli::try_parse_from([
                "guest",
                "--mediatore-url",
                "https://192.0.2.1:3130",
                flag,
                "0",
            ])
            .map(|c| drop(c.guest))
            .unwrap_err()
            .to_string();
            assert!(err.contains(flag), "{env}: {err}");
        }
    }

    #[test]
    fn the_proxys_readiness_wait_outlasts_its_wait_for_the_claim_svid() {
        assert!(
            super::PROXY_READY_SECS > crate::client::WORKLOAD_API_WAIT.as_secs(),
            "a proxy still waiting for its SVID would be killed before it could say why"
        );
    }
}
