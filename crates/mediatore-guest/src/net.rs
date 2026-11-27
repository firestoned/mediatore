// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The jail's network bound (ADR-0020): one nftables table per claim whose output hook
//! sends the sandbox uid's packets to a chain that admits a short list of TCP destinations
//! and then logs and drops. The list has two shapes ([`Shape`]). In an environment with
//! egress gateways (ADR-0028 decision 6, amending ADR-0020 decisions 2 to 4): the broker,
//! which is the control relay at a gateway's `sandbox` address (ADR-0027 decisions 3 and
//! 6), the gateways' data-plane port and the egress proxy on loopback (ADR-0025), every one
//! an address the broker or the pool handed over; no audience endpoint and no DNS, since the
//! proxy tunnels every upstream through a gateway and the segment has no resolver. Without a
//! gateway (an older environment, the dev loop): the broker, the resolved egress endpoints
//! of the claim's audiences, the proxy on loopback and DNS to the VM's resolvers, as
//! ADR-0020 first shaped it. Every other uid is untouched, except that a packet to the
//! proxy's loopback port from any other uid is dropped (ADR-0025 decision 5). Rendered as
//! text so the exact ruleset is pinned by tests and hashed in the log; loaded in one
//! `nft -f` transaction before the jail starts.
//!
//! Under a tripwire (ADR-0069, `policy.traps` `shadow` or `enforce`) the table also carries
//! the claim's draw ([`Ruleset::with_decoys`]): the decoy ports on loopback, on which nothing
//! listens, and the metadata address when that decoy is drawn (decision 13), each redirected
//! for the sandbox uid alone to the one trap listener's port, which nothing reaches but
//! through that redirect (the maintainer's decision 13 of 2026-11-27: a listing of the VM's
//! sockets names no decoy); every other uid refused a new connection to a decoy port, logged
//! and counted (decision 2, amended: a connection the trap listener accepts is therefore the
//! sandbox uid's, to a decoy, with no lookup); and two sets that hold what the chain's end
//! dropped, which the guest reads for the `denied` classes (decision 10). With no decoy none
//! of it is rendered and the script is, byte for byte, what it was before the ADR.
//!
//! Every `nft` process goes through an [`NftRunner`], so the scripts and the reads are tested
//! against a recorder and the guest runs [`SystemNft`].
//!
//! Also here: the pool's bootstrap list of gateways (ADR-0027 decision 4), the file the
//! guest reads when the broker lists none.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;
use std::process::Stdio;

use anyhow::Context as _;
use async_trait::async_trait;
use mediatore_proto::Endpoint;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};

/// The table, `inet` family so one ruleset covers both address families.
pub const TABLE: &str = "mediatore_sandbox";
/// The `nftables` command; `/usr/sbin` is on root's path under systemd.
pub const NFT: &str = "nft";
/// Where the VM's resolvers are read from.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";
/// The pool's bootstrap list of gateways (ADR-0027 decision 4): one `host:port` per line,
/// written by the pool's cloud-config. Absent on a pool with no gateway.
pub const GATEWAYS_FILE: &str = "/etc/mediatore/gateways";
/// Prefix of the kernel log line for a dropped packet.
const LOG_PREFIX: &str = "mediatore-sandbox drop: ";
/// Prefix of the kernel log line for a packet to a decoy port from a uid that is not the
/// sandbox's (ADR-0069 decision 2, amended): dropped, counted, and never a trip.
const LOG_DECOY_OTHER_UID: &str = "mediatore-sandbox decoy other uid: ";
/// Prefix of the kernel log line for a connection made to the trap listener's port itself,
/// by any uid: only a redirected connection to a decoy reaches it.
const LOG_TRAP_DIRECT: &str = "mediatore-sandbox trap port direct: ";
/// The set of the decoy ports on loopback. Nothing listens on them.
pub const DECOYS: &str = "decoys";
/// The sets the chain's end keeps what it dropped in, for the `denied` classes (ADR-0069
/// decision 10): a new TCP connection's destination address and port, IPv4 and IPv6.
pub const DENIED4: &str = "denied4";
/// See [`DENIED4`].
pub const DENIED6: &str = "denied6";
/// How many destinations a `denied` set holds. Full, the chain's last rule still drops and
/// logs; the destination is not named to the guest.
const DENIED_SIZE: u32 = 1024;
/// The metadata address and port the sandbox uid's table redirects (ADR-0069 decision 13).
const METADATA_IP: &str = "169.254.169.254";
/// See [`METADATA_IP`]. Landlock in the jail admits this port when the decoy is drawn.
pub const METADATA_PORT: u16 = 80;
/// The most of one `nft` process's standard output that is kept: more is an error, never a
/// longer buffer (a set of 4096 elements lists in under half a megabyte).
pub const NFT_OUTPUT_MAX: usize = 4 * 1024 * 1024;
/// The most of its standard error that is kept, for the log line.
const NFT_STDERR_MAX: usize = 16 * 1024;

/// What one `nft` process answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftOutput {
    /// Whether it exited `0`.
    pub success: bool,
    /// Its standard output, at most [`NFT_OUTPUT_MAX`].
    pub stdout: Vec<u8>,
    /// Its standard error, trimmed and bounded, for a log line.
    pub stderr: String,
}

/// Whoever runs `nft`: the VM's own in the guest, a recorder in a test. Everything the guest
/// loads into or reads from a table goes through one.
#[async_trait]
pub trait NftRunner: Send + Sync {
    /// Run `nft` with `args`, `stdin` on its standard input when there is one.
    ///
    /// # Errors
    /// `nft` could not be started or read, or printed more than [`NFT_OUTPUT_MAX`]. A refusal
    /// by `nft` itself is not an error: it is [`NftOutput::success`] false.
    async fn run(&self, args: &[&str], stdin: Option<&str>) -> std::io::Result<NftOutput>;
}

/// The VM's `nft` ([`NFT`]). A caller that bounds the call with a timeout kills the process
/// by dropping the future.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemNft;

/// Read `reader` to its end and keep at most `cap` bytes; whether there were more.
async fn read_capped<R: AsyncRead + Unpin>(
    reader: Option<R>,
    cap: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::new();
    let mut over = false;
    let Some(mut reader) = reader else {
        return Ok((kept, over));
    };
    let mut buf = [0_u8; 8192];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok((kept, over));
        }
        let room = cap.saturating_sub(kept.len()).min(n);
        kept.extend_from_slice(&buf[..room]);
        over |= room < n;
    }
}

#[async_trait]
impl NftRunner for SystemNft {
    async fn run(&self, args: &[&str], stdin: Option<&str>) -> std::io::Result<NftOutput> {
        let mut child = tokio::process::Command::new(NFT)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        if let (Some(mut pipe), Some(text)) = (child.stdin.take(), stdin) {
            pipe.write_all(text.as_bytes()).await?;
            pipe.shutdown().await?;
        }
        let (stdout, stderr) = tokio::join!(
            read_capped(child.stdout.take(), NFT_OUTPUT_MAX),
            read_capped(child.stderr.take(), NFT_STDERR_MAX)
        );
        let (stdout, over) = stdout?;
        let (stderr, _) = stderr?;
        let status = child.wait().await?;
        if over {
            return Err(std::io::Error::other(format!(
                "{NFT} printed more than {NFT_OUTPUT_MAX} bytes"
            )));
        }
        Ok(NftOutput {
            success: status.success(),
            stdout,
            stderr: String::from_utf8_lossy(&stderr).trim().to_owned(),
        })
    }
}

/// Which list the sandbox uid gets (ADR-0028 decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// No gateway: the broker, the audiences' endpoints, the proxy and DNS (ADR-0020 as
    /// first written). The proxy dials its upstreams directly and resolves their names.
    Direct,
    /// Gateways: the broker through the relay, the gateways and the proxy, by address;
    /// no audience endpoint and no DNS. The proxy tunnels every upstream through a gateway,
    /// which resolves the name (ADR-0028 decision 5).
    Gateways,
}

impl std::fmt::Display for Shape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Direct => "direct",
            Self::Gateways => "gateways",
        })
    }
}

/// What the sandbox uid may reach, with every name already resolved (decision 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    /// The sandbox user's uid, what `meta skuid` matches.
    pub uid: u32,
    /// TCP destinations as addresses: the broker and the proxy on loopback, then the
    /// gateways or the claim's egress, by [`Self::shape`].
    pub allow: BTreeSet<(IpAddr, u16)>,
    /// Resolvers DNS may go to, UDP and TCP 53. Empty with gateways: no DNS rule is
    /// rendered at all.
    pub dns: BTreeSet<IpAddr>,
    /// The egress proxy's loopback port: admitted for the sandbox uid, refused to every
    /// other uid (ADR-0025 decision 5).
    pub proxy_port: u16,
    /// Which list this is.
    pub shape: Shape,
    /// The drawn decoy ports on loopback (ADR-0069 decision 2): nothing listens on them. A
    /// connection of the sandbox uid to one is redirected to [`Self::trap_port`]; another uid
    /// is refused. Empty with no traps armed, and the script is then what it was before the
    /// ADR.
    pub decoy_ports: BTreeSet<u16>,
    /// Whether the metadata address is redirected to [`Self::trap_port`] for the sandbox uid
    /// alone (ADR-0069 decision 13): the draw picked that decoy.
    pub metadata: bool,
    /// The one loopback port the guest's trap listener is on (the maintainer's decision 13 of
    /// 2026-11-27): reached only through the redirect, never by a connection made to it, so a
    /// listing of the VM's sockets names this port and no decoy.
    pub trap_port: Option<u16>,
}

impl Ruleset {
    /// The list for `uid`: with `gateways`, the broker and the gateways by address and the
    /// proxy at `127.0.0.1:proxy_port`, nothing else; without, the broker, `egress`
    /// resolved, the proxy, and the resolvers read from `resolv_conf`.
    ///
    /// # Errors
    /// A broker URL without a host or port, or a broker that resolves to nothing: nothing
    /// would work. A broker, egress endpoint or gateway on the proxy's port: the workload's
    /// one allowed port must name one destination (ADR-0025 decision 5). With gateways, a
    /// broker or a gateway given by name: the sandbox has no resolver on the segment
    /// (ADR-0027 decision 3, ADR-0028 decision 6), so the proxy could never dial it, and a
    /// claim that cannot fetch a token or open a tunnel is refused before it starts rather
    /// than left to fail on its first request. Without gateways, an egress endpoint that
    /// does not resolve is omitted with a warning.
    pub async fn resolve(
        uid: u32,
        mediatore_url: &str,
        egress: &[Endpoint],
        gateways: &[Endpoint],
        resolv_conf: &Path,
        proxy_port: u16,
    ) -> anyhow::Result<Self> {
        let broker = broker_endpoint(mediatore_url)?;
        let mut allow = BTreeSet::new();
        let shape = if gateways.is_empty() {
            Shape::Direct
        } else {
            Shape::Gateways
        };
        match shape {
            Shape::Gateways => {
                for (what, e) in std::iter::once(("the broker", &broker))
                    .chain(gateways.iter().map(|g| ("a gateway", g)))
                {
                    let ip: IpAddr = e.host.parse().map_err(|_| {
                        anyhow::anyhow!(
                            "{what} is given by name, {e}: in an environment with egress gateways the sandbox has no resolver (ADR-0027 decision 3, ADR-0028 decision 6); give the broker as the control relay's address at a gateway and the gateways by address"
                        )
                    })?;
                    allow.insert((ip, e.port));
                }
                if !egress.is_empty() {
                    tracing::info!(
                        egress = egress.len(),
                        "the claim's egress endpoints are reached through the gateways, which admit them per claim; the ruleset does not name them (ADR-0028 decision 6)"
                    );
                }
            }
            Shape::Direct => {
                let addrs = lookup(&broker)
                    .await
                    .with_context(|| format!("resolving the broker {broker}"))?;
                anyhow::ensure!(
                    !addrs.is_empty(),
                    "the broker {broker} resolves to no address"
                );
                allow.extend(addrs);
                for e in egress {
                    match lookup(e).await {
                        Ok(a) if !a.is_empty() => allow.extend(a),
                        Ok(_) => {
                            tracing::warn!(endpoint = %e, "egress endpoint resolves to no address; omitted");
                        }
                        Err(err) => {
                            tracing::warn!(endpoint = %e, error = %err, "egress endpoint does not resolve; omitted");
                        }
                    }
                }
            }
        }
        if let Some((ip, _)) = allow.iter().find(|(_, p)| *p == proxy_port) {
            anyhow::bail!(
                "{ip}:{proxy_port} is a destination of this claim and {proxy_port} is the egress proxy's port: the workload's one allowed port would name two destinations (ADR-0025); choose another --egress-proxy-port"
            );
        }
        allow.insert((IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), proxy_port));
        Ok(Self {
            uid,
            allow,
            dns: match shape {
                Shape::Direct => resolvers(resolv_conf),
                Shape::Gateways => BTreeSet::new(),
            },
            proxy_port,
            shape,
            decoy_ports: BTreeSet::new(),
            metadata: false,
            trap_port: None,
        })
    }

    /// The same list with each gateway's inject port added (ADR-0040 decision 7): a claim with
    /// a gateway-placed route has its proxy send the request to `gateway:INJECT_PORT` over the
    /// claim's mutual TLS, and the proxy's sockets carry the sandbox uid, so the uid's table
    /// names that destination. `ports` is the set of those routes' ports; empty (a claim with
    /// no gateway-placed route) returns the list unchanged, exactly as it was.
    ///
    /// # Errors
    /// Ports given without the gateways shape (the proxy would have no gateway to send to), port
    /// `0`, the egress proxy's own port (the workload's one allowed port must name one
    /// destination, ADR-0025), or a gateway given by name (the sandbox has no resolver).
    pub fn with_inject_ports(
        mut self,
        gateways: &[Endpoint],
        ports: &BTreeSet<u16>,
    ) -> anyhow::Result<Self> {
        if ports.is_empty() {
            return Ok(self);
        }
        anyhow::ensure!(
            self.shape == Shape::Gateways,
            "a gateway-placed route needs the environment's egress gateways, and this claim has none (ADR-0040 decision 1)"
        );
        for &port in ports {
            anyhow::ensure!(
                port != 0,
                "a gateway-placed route names inject port 0 (ADR-0040 decision 7)"
            );
            anyhow::ensure!(
                port != self.proxy_port,
                "inject port {port} is the egress proxy's port {}: the workload's one allowed port would name two destinations (ADR-0025)",
                self.proxy_port
            );
        }
        for g in gateways {
            let ip: IpAddr = g.host.parse().map_err(|_| {
                anyhow::anyhow!(
                    "a gateway is given by name, {g}: the sandbox has no resolver, so the gateways are given by address (ADR-0028 decision 6)"
                )
            })?;
            for &port in ports {
                self.allow.insert((ip, port));
            }
        }
        Ok(self)
    }

    /// The list with the claim's drawn decoys (ADR-0069 decisions 2 and 13, and the
    /// maintainer's decision 13 of 2026-11-27): a connection of the sandbox uid to a decoy port
    /// on loopback, and with `metadata` to the metadata address, is redirected to the one trap
    /// listener on `trap_port`, which is admitted on loopback for those redirected connections
    /// alone. Nothing listens on a decoy port, so no listing of the VM's sockets names one.
    /// Every other uid is refused the decoy ports, and every uid a connection made to
    /// `trap_port` itself. No port and no metadata decoy returns the list unchanged.
    ///
    /// # Errors
    /// A decoy or the trap port on port `0`, twice, on the proxy's port, or on a port any
    /// destination of the list has: Landlock in the jail admits a listed port at every address
    /// (`--connect-port`), so a decoy on a destination's port would let the workload reach that
    /// destination around the proxy. For the same reason the metadata decoy, which makes the
    /// jail admit port 80, is refused on a list with a destination on port 80
    /// ([`Self::admits_the_metadata_decoy`]). A draw that names such a port was made without
    /// the list's ports reserved ([`Self::ports`]); it is refused, never trimmed.
    pub fn with_decoys(
        mut self,
        ports: &[u16],
        metadata: bool,
        trap_port: u16,
    ) -> anyhow::Result<Self> {
        if ports.is_empty() && !metadata {
            return Ok(self);
        }
        anyhow::ensure!(
            !self.is_armed(),
            "the ruleset already carries a draw (ADR-0069 decision 3: one draw a claim)"
        );
        anyhow::ensure!(
            !metadata || self.admits_the_metadata_decoy(),
            "a destination of this claim is on port {METADATA_PORT}: the metadata decoy would make the jail admit that port at every address (ADR-0069 decision 13)"
        );
        let taken: BTreeSet<u16> = self.ports().into_iter().collect();
        let mut drawn = BTreeSet::new();
        for &port in ports.iter().chain([trap_port].iter()) {
            anyhow::ensure!(port != 0, "a decoy on port 0 (ADR-0069 decision 2)");
            anyhow::ensure!(
                !taken.contains(&port),
                "a decoy on a port this claim already uses: the jail would admit it at every address (ADR-0069 decision 3)"
            );
            anyhow::ensure!(
                drawn.insert(port),
                "a decoy port drawn twice (ADR-0069 decision 3)"
            );
        }
        anyhow::ensure!(
            !metadata || trap_port != METADATA_PORT,
            "the trap port is the metadata decoy's port (ADR-0069 decision 13)"
        );
        // Only the trap listener is a destination: a decoy's connection reaches the filter
        // already redirected to it.
        self.allow
            .insert((IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), trap_port));
        self.decoy_ports = ports.iter().copied().collect();
        self.metadata = metadata;
        self.trap_port = Some(trap_port);
        Ok(self)
    }

    /// Every port the list uses: each destination's and the proxy's. What a draw must
    /// reserve (`DrawInputs::reserved_ports`) so that no decoy is drawn on one.
    #[must_use]
    pub fn ports(&self) -> Vec<u16> {
        let ports: BTreeSet<u16> = self
            .allow
            .iter()
            .map(|(_, port)| *port)
            .chain([self.proxy_port])
            .collect();
        ports.into_iter().collect()
    }

    /// Whether the metadata decoy may be drawn for this list (`DrawInputs::metadata`): no
    /// destination is on port 80, the port the jail would then admit at every address. A
    /// route to the address must exist besides, which the list cannot tell.
    #[must_use]
    pub fn admits_the_metadata_decoy(&self) -> bool {
        !self.allow.iter().any(|(_, port)| *port == METADATA_PORT)
    }

    /// Whether the list carries a draw: the decoy rules and the `denied` sets are rendered.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.trap_port.is_some()
    }

    /// The `nft -f` script: creates the table if absent, deletes it, defines it again, so
    /// a stale table from an earlier claim is replaced in the same transaction.
    #[must_use]
    pub fn render(&self) -> String {
        let uid = self.uid;
        let proxy = self.proxy_port;
        let mut out = String::new();
        match self.shape {
            Shape::Direct => {
                let _ = writeln!(
                    out,
                    "# mediatore guest (ADR-0020, ADR-0025): uid {uid} reaches the broker, the claim's egress, the egress proxy and DNS; nothing else, and nobody else reaches the proxy"
                );
            }
            Shape::Gateways => {
                let _ = writeln!(
                    out,
                    "# mediatore guest (ADR-0020, ADR-0025, ADR-0028 decision 6): uid {uid} reaches the broker through the control relay, the egress gateways and the egress proxy; no DNS, nothing else, and nobody else reaches the proxy"
                );
            }
        }
        let _ = writeln!(out, "table inet {TABLE}");
        let _ = writeln!(out, "delete table inet {TABLE}");
        let _ = writeln!(out, "table inet {TABLE} {{");
        let (v4, v6): (Vec<_>, Vec<_>) = self.allow.iter().partition(|(ip, _)| ip.is_ipv4());
        let pairs = |v: &[&(IpAddr, u16)]| {
            v.iter()
                .map(|(ip, port)| format!("{ip} . {port}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        set(&mut out, "allow4", "ipv4_addr . inet_service", &pairs(&v4));
        set(&mut out, "allow6", "ipv6_addr . inet_service", &pairs(&v6));
        if self.shape == Shape::Direct {
            let (d4, d6): (Vec<_>, Vec<_>) = self.dns.iter().partition(|ip| ip.is_ipv4());
            let addrs = |v: &[&IpAddr]| {
                v.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            set(&mut out, "dns4", "ipv4_addr", &addrs(&d4));
            set(&mut out, "dns6", "ipv6_addr", &addrs(&d6));
        }
        let armed = self.is_armed();
        if armed {
            self.render_draw_sets(&mut out);
        }
        let _ = writeln!(out, "  chain output {{");
        let _ = writeln!(
            out,
            "    type filter hook output priority filter; policy accept;"
        );
        let _ = writeln!(
            out,
            "    oifname \"lo\" tcp dport {proxy} meta skuid != {uid} drop"
        );
        if let Some(trap) = self.trap_port {
            // Decision 2, amended: nobody but the sandbox uid opens a connection to a decoy
            // port (`ct state new`: a reply to a client whose own port is a decoy's is not
            // touched), and nobody at all reaches the trap listener but through the redirect,
            // so an accepted connection there is the sandbox uid's, to a decoy.
            let _ = writeln!(
                out,
                "    oifname \"lo\" tcp dport @{DECOYS} meta skuid != {uid} ct state new log prefix \"{LOG_DECOY_OTHER_UID}\" counter drop"
            );
            let _ = writeln!(
                out,
                "    oifname \"lo\" tcp dport {trap} ct original proto-dst {trap} log prefix \"{LOG_TRAP_DIRECT}\" counter drop"
            );
        }
        let _ = writeln!(out, "    meta skuid {uid} jump sandbox");
        let _ = writeln!(out, "  }}");
        let _ = writeln!(out, "  chain sandbox {{");
        for rule in [
            "ct state established,related accept",
            "ip daddr . tcp dport @allow4 accept",
            "ip6 daddr . tcp dport @allow6 accept",
        ] {
            let _ = writeln!(out, "    {rule}");
        }
        if self.shape == Shape::Direct {
            for rule in [
                "ip daddr @dns4 udp dport 53 accept",
                "ip daddr @dns4 tcp dport 53 accept",
                "ip6 daddr @dns6 udp dport 53 accept",
                "ip6 daddr @dns6 tcp dport 53 accept",
            ] {
                let _ = writeln!(out, "    {rule}");
            }
        }
        if armed {
            render_denied_rules(&mut out);
        }
        let _ = writeln!(out, "    log prefix \"{LOG_PREFIX}\" counter drop");
        let _ = writeln!(out, "  }}");
        if let Some(trap) = self.trap_port {
            render_redirect(&mut out, uid, trap, self.metadata);
        }
        let _ = writeln!(out, "}}");
        out
    }

    /// The sets a draw adds (ADR-0069): the decoy ports, and the two that keep what the
    /// chain's end dropped.
    fn render_draw_sets(&self, out: &mut String) {
        let decoys = self
            .decoy_ports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        set(out, DECOYS, "inet_service", &decoys);
        for (name, ty) in [(DENIED4, "ipv4_addr"), (DENIED6, "ipv6_addr")] {
            let _ = writeln!(
                out,
                "  set {name} {{ type {ty} . inet_service; size {DENIED_SIZE}; flags dynamic,timeout; counter; timeout 1m; }}"
            );
        }
    }

    /// SHA-256 of [`Self::render`], hex: what the log carries so a change is visible.
    #[must_use]
    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(self.render().as_bytes()))
    }

    /// SHA-256 of the script with the draw left out, hex: the decoy ports, their loopback
    /// admissions, the rule that keeps other uids off them, the metadata redirect and the
    /// `denied` sets elided, so it is the hash of the script the same claim would have with
    /// no tripwire. This is the hash the guest reports to the broker and logs (ADR-0069
    /// decision 13, amended): the whole script's hash would let whoever reads the report
    /// search for the few drawn ports offline. With no decoy it is [`Self::sha256`].
    #[must_use]
    pub fn public_sha256(&self) -> String {
        let mut public = self.clone();
        let loopback = IpAddr::from([127, 0, 0, 1]);
        if let Some(trap) = self.trap_port {
            public.allow.remove(&(loopback, trap));
        }
        public.decoy_ports.clear();
        public.metadata = false;
        public.trap_port = None;
        public.sha256()
    }
}

/// ADR-0069 decision 10: a new TCP connection the chain refuses is kept, by destination, for
/// the guest to read. The update comes before the log: with a set full the rest of the rule
/// is skipped and the chain's last rule drops and logs.
fn render_denied_rules(out: &mut String) {
    for (nfproto, name, daddr) in [("ipv4", DENIED4, "ip"), ("ipv6", DENIED6, "ip6")] {
        let _ = writeln!(
            out,
            "    meta nfproto {nfproto} meta l4proto tcp ct state new update @{name} {{ {daddr} daddr . tcp dport }} log prefix \"{LOG_PREFIX}\" counter drop"
        );
    }
}

/// The maintainer's decision 13 of 2026-11-27: the sandbox uid's connections to a decoy port
/// on loopback, and with `metadata` to the metadata address (ADR-0069 decision 13), are
/// redirected to the trap listener on loopback `trap`, which learns the decoy from the
/// connection's original destination. Every other uid is not redirected, and still meets
/// ADR-0068's drop for the metadata address. The priority is the number: `nft` takes the name
/// `dstnat` on the prerouting hook only.
fn render_redirect(out: &mut String, uid: u32, trap: u16, metadata: bool) {
    let _ = writeln!(out, "  chain nat_out {{");
    let _ = writeln!(
        out,
        "    type nat hook output priority -100; policy accept;"
    );
    let _ = writeln!(
        out,
        "    meta skuid {uid} ip daddr 127.0.0.1 tcp dport @{DECOYS} dnat ip to 127.0.0.1:{trap}"
    );
    if metadata {
        let _ = writeln!(
            out,
            "    meta skuid {uid} ip daddr {METADATA_IP} tcp dport {METADATA_PORT} dnat ip to 127.0.0.1:{trap}"
        );
    }
    let _ = writeln!(out, "  }}");
}

/// One named set; `elements` only when there are any (`nft` refuses an empty list).
fn set(out: &mut String, name: &str, ty: &str, elements: &str) {
    if elements.is_empty() {
        let _ = writeln!(out, "  set {name} {{ type {ty}; }}");
    } else {
        let _ = writeln!(
            out,
            "  set {name} {{ type {ty}; elements = {{ {elements} }} }}"
        );
    }
}

/// The host and port of the broker's URL: always admitted.
///
/// # Errors
/// A URL that does not parse or names no host or port.
pub fn broker_endpoint(url: &str) -> anyhow::Result<Endpoint> {
    let u = reqwest::Url::parse(url).with_context(|| format!("mediatore URL {url:?}"))?;
    let host = u
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("mediatore URL {url:?} has no host"))?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = u
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("mediatore URL {url:?} has no port"))?;
    Ok(Endpoint {
        host: host.to_owned(),
        port,
    })
}

/// The `nameserver` lines of a `resolv.conf`; a scope suffix (`%eth0`) is dropped and a
/// line that is not an address is ignored.
#[must_use]
pub fn resolvers(path: &Path) -> BTreeSet<IpAddr> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeSet::new();
    };
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|addr| addr.split('%').next()?.parse().ok())
        .collect()
}

/// The pool's bootstrap list of gateways (ADR-0027 decision 4): one `host:port` per line,
/// blank lines and `#` comments skipped. A missing file is an empty list (a pool with no
/// gateway); a line that is not an endpoint is an error, since a list the pool wrote
/// wrong is better refused than silently shortened.
///
/// # Errors
/// The file exists and cannot be read, or holds a line that is not `host:port`.
pub fn bootstrap_gateways(path: &Path) -> anyhow::Result<Vec<Endpoint>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            l.parse::<Endpoint>()
                .map_err(|e| anyhow::anyhow!("{}: {l:?}: {e}", path.display()))
        })
        .collect()
}

/// Where the gateway list came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewaySource {
    /// `GET /v1/me`, the authoritative list (ADR-0028 decision 7).
    Broker,
    /// The pool's bootstrap file, because the broker listed none (ADR-0027 decision 4).
    Bootstrap,
    /// Neither: the environment has no gateway and the proxy dials directly.
    None,
}

/// The broker's list when it has one, the pool's otherwise (ADR-0027 decision 4: the
/// guest follows `/v1/me` once it has it).
#[must_use]
pub fn choose_gateways(
    broker: &[Endpoint],
    bootstrap: &[Endpoint],
) -> (Vec<Endpoint>, GatewaySource) {
    if !broker.is_empty() {
        (broker.to_vec(), GatewaySource::Broker)
    } else if !bootstrap.is_empty() {
        (bootstrap.to_vec(), GatewaySource::Bootstrap)
    } else {
        (Vec::new(), GatewaySource::None)
    }
}

async fn lookup(e: &Endpoint) -> std::io::Result<Vec<(IpAddr, u16)>> {
    Ok(tokio::net::lookup_host((e.host.as_str(), e.port))
        .await?
        .map(|a| (a.ip(), a.port()))
        .collect())
}

/// Load the ruleset in one transaction with the VM's `nft`. Returns the hash to log and
/// to report: [`Ruleset::public_sha256`], which is [`Ruleset::sha256`] with no draw.
///
/// # Errors
/// `nft` missing or refusing the script: the jail must not start (decision 5).
pub async fn load(rs: &Ruleset) -> anyhow::Result<String> {
    load_with(&SystemNft, rs).await
}

/// [`load`] through `nft`. The hash returned is the public one: the whole script's hash
/// would give the draw away at `info` and in the report (ADR-0069 decisions 3 and 13).
///
/// # Errors
/// As [`load`]. Under a tripwire this is a failure to arm, the redirect's `nat` chain
/// included.
pub async fn load_with(nft: &dyn NftRunner, rs: &Ruleset) -> anyhow::Result<String> {
    let out = nft
        .run(&["-f", "-"], Some(&rs.render()))
        .await
        .with_context(|| format!("running {NFT}: is nftables on the image?"))?;
    anyhow::ensure!(
        out.success,
        "{NFT} refused the ruleset: {}",
        without_the_draw(&out.stderr, rs)
    );
    Ok(rs.public_sha256())
}

/// `text` (what `nft` said of a script, which echoes the line it refused) with every number
/// that is a port of `rs`'s draw replaced by `<drawn>`: the error is logged, and a discarded
/// draw's ports must not be (a NIT of the review).
fn without_the_draw(text: &str, rs: &Ruleset) -> String {
    let drawn: BTreeSet<u16> = rs.decoy_ports.iter().copied().chain(rs.trap_port).collect();
    if drawn.is_empty() {
        return text.to_owned();
    }
    let flush = |digits: &mut String, out: &mut String| {
        if digits.parse::<u16>().is_ok_and(|n| drawn.contains(&n)) {
            out.push_str("<drawn>");
        } else {
            out.push_str(digits);
        }
        digits.clear();
    };
    let mut out = String::with_capacity(text.len());
    let mut digits = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            flush(&mut digits, &mut out);
            out.push(c);
        }
    }
    flush(&mut digits, &mut out);
    out
}

/// Delete the table. Best effort: logged, never fatal; the next claim replaces it anyway.
pub async fn unload() {
    unload_with(&SystemNft).await;
}

/// [`unload`] through `nft`.
pub async fn unload_with(nft: &dyn NftRunner) {
    match nft.run(&["delete", "table", "inet", TABLE], None).await {
        Ok(out) if out.success => tracing::info!(table = TABLE, "sandbox ruleset removed"),
        Ok(out) => tracing::warn!(
            table = TABLE,
            error = %out.stderr,
            "could not remove the sandbox ruleset (already gone?)"
        ),
        Err(e) => {
            tracing::warn!(table = TABLE, error = %e, "could not run nft to remove the sandbox ruleset");
        }
    }
}

/// What `nft -j` lists of one set with a counter per element.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SetRead {
    /// The set's declared size, when it has one.
    pub(crate) size: Option<u64>,
    /// How many elements it holds, whatever their shape.
    pub(crate) held: u64,
    /// Each element's key as `nft` prints it, and its counter's packets.
    pub(crate) elements: Vec<(serde_json::Value, u64)>,
}

/// The items of an `nft -j` document: `{"nftables": [ ... ]}`.
///
/// # Errors
/// Not that document.
pub(crate) fn json_items(json: &[u8]) -> anyhow::Result<Vec<serde_json::Value>> {
    let doc: serde_json::Value =
        serde_json::from_slice(json).context("nft -j printed something that is not JSON")?;
    match doc.get("nftables") {
        Some(serde_json::Value::Array(items)) => Ok(items.clone()),
        _ => anyhow::bail!("nft -j printed no `nftables` list"),
    }
}

/// The set `name` of `table` in an `nft -j` listing. An empty set has no `elem` member at
/// all; an element without a counter, or of any shape this does not know, is counted in
/// `held` and left out of `elements`, never an error for the whole read.
///
/// # Errors
/// Not an `nft -j` document, or one without the set.
pub(crate) fn parse_set(json: &[u8], table: &str, name: &str) -> anyhow::Result<SetRead> {
    let items = json_items(json)?;
    let set = items
        .iter()
        .filter_map(|item| item.get("set"))
        .find(|s| {
            s.get("name").and_then(serde_json::Value::as_str) == Some(name)
                && s.get("table").and_then(serde_json::Value::as_str) == Some(table)
        })
        .with_context(|| format!("nft -j printed no set {name} of table {table}"))?;
    let listed = set
        .get("elem")
        .and_then(serde_json::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let elements = listed
        .iter()
        .filter_map(|e| {
            let e = e.get("elem")?;
            let packets = e.get("counter")?.get("packets")?.as_u64()?;
            Some((e.get("val")?.clone(), packets))
        })
        .collect();
    Ok(SetRead {
        size: set.get("size").and_then(serde_json::Value::as_u64),
        held: listed.len() as u64,
        elements,
    })
}

/// An address and a port from a set's `{"concat": ["<address>", <port>]}` key. `None` for
/// any other shape, an address that does not parse, or port `0`.
pub(crate) fn address_and_port(key: &serde_json::Value) -> Option<(IpAddr, u16)> {
    let [address, port] = key.get("concat")?.as_array()?.as_slice() else {
        return None;
    };
    let port = u16::try_from(port.as_u64()?).ok().filter(|p| *p != 0)?;
    Some((address.as_str()?.parse().ok()?, port))
}

/// One destination the sandbox uid's chain refused since the last read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied {
    /// Where the connection was going.
    pub address: IpAddr,
    /// The TCP port.
    pub port: u16,
    /// How many new connections to it were dropped since the last read.
    pub packets: u64,
}

/// What the chain's end dropped since the last read (ADR-0069 decision 10): both `denied`
/// sets, read and zeroed with `nft reset`, one process a set (two `reset set` in one `nft`
/// process fail on nftables 1.1.3). An element that saw nothing since the last read is
/// skipped. The guest keeps no state between reads.
///
/// # Errors
/// `nft` could not be run, refused (the table is gone: the claim ended, or was cut after a
/// trip), or printed something that is not the set.
pub async fn read_denied(nft: &dyn NftRunner) -> anyhow::Result<Vec<Denied>> {
    let mut denied = Vec::new();
    for name in [DENIED4, DENIED6] {
        let out = nft
            .run(&["-j", "-n", "reset", "set", "inet", TABLE, name], None)
            .await
            .with_context(|| format!("running {NFT}"))?;
        anyhow::ensure!(
            out.success,
            "{NFT} could not read the set {name}: {}",
            out.stderr
        );
        denied.extend(
            parse_set(&out.stdout, TABLE, name)?
                .elements
                .iter()
                .filter(|(_, packets)| *packets > 0)
                .filter_map(|(key, packets)| {
                    let (address, port) = address_and_port(key)?;
                    Some(Denied {
                        address,
                        port,
                        packets: *packets,
                    })
                }),
        );
    }
    Ok(denied)
}

/// A recorder in `nft`'s place, for this crate's tests.
#[cfg(test)]
pub(crate) mod testing {
    use super::{NftOutput, NftRunner};
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// What the recorder answers once its queue is empty.
    #[derive(Debug, Clone)]
    enum Rest {
        Accept,
        Refuse(String),
        Absent,
        Hang,
    }

    /// Records every call; answers from a queue of standard outputs, then as told.
    #[derive(Debug)]
    pub(crate) struct FakeNft {
        calls: Mutex<Vec<(Vec<String>, Option<String>)>>,
        answers: Mutex<VecDeque<String>>,
        rest: Rest,
    }

    impl Default for FakeNft {
        fn default() -> Self {
            Self::with(Rest::Accept)
        }
    }

    impl FakeNft {
        fn with(rest: Rest) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                answers: Mutex::new(VecDeque::new()),
                rest,
            }
        }

        /// Every call exits non-zero with `stderr`.
        pub(crate) fn refusing(stderr: &str) -> Self {
            Self::with(Rest::Refuse(stderr.to_owned()))
        }

        /// There is no `nft` to run.
        pub(crate) fn absent() -> Self {
            Self::with(Rest::Absent)
        }

        /// No call ever returns.
        pub(crate) fn hanging() -> Self {
            Self::with(Rest::Hang)
        }

        /// The calls print `outputs` in turn and exit `0`; once they are used up, a call is
        /// refused as `nft` refuses a table that does not exist.
        pub(crate) fn answering<const N: usize>(outputs: [&str; N]) -> Self {
            let fake = Self::with(Rest::Refuse("Error: No such file or directory".to_owned()));
            fake.answers
                .lock()
                .unwrap()
                .extend(outputs.iter().map(|o| (*o).to_owned()));
            fake
        }

        /// The arguments and the standard input of every call so far.
        pub(crate) fn calls(&self) -> Vec<(Vec<String>, Option<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl NftRunner for FakeNft {
        async fn run(&self, args: &[&str], stdin: Option<&str>) -> std::io::Result<NftOutput> {
            self.calls.lock().unwrap().push((
                args.iter().map(|a| (*a).to_owned()).collect(),
                stdin.map(str::to_owned),
            ));
            let queued = self.answers.lock().unwrap().pop_front();
            if let Some(stdout) = queued {
                return Ok(NftOutput {
                    success: true,
                    stdout: stdout.into_bytes(),
                    stderr: String::new(),
                });
            }
            match &self.rest {
                Rest::Accept => Ok(NftOutput {
                    success: true,
                    stdout: Vec::new(),
                    stderr: String::new(),
                }),
                Rest::Refuse(stderr) => Ok(NftOutput {
                    success: false,
                    stdout: Vec::new(),
                    stderr: stderr.clone(),
                }),
                Rest::Absent => Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
                Rest::Hang => std::future::pending().await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> Endpoint {
        s.parse().unwrap()
    }

    fn full() -> Ruleset {
        Ruleset {
            uid: 1234,
            allow: [
                ("198.51.100.7".parse().unwrap(), 443),
                ("192.0.2.10".parse().unwrap(), 8443),
                ("2001:db8::1".parse().unwrap(), 8443),
            ]
            .into_iter()
            .collect(),
            dns: [
                "2001:db8::53".parse().unwrap(),
                "192.0.2.53".parse().unwrap(),
            ]
            .into_iter()
            .collect(),
            proxy_port: 3128,
            shape: Shape::Direct,
            decoy_ports: BTreeSet::new(),
            metadata: false,
            trap_port: None,
        }
    }

    /// `gateways()` with a draw on it: two decoy ports, the metadata decoy, the trap listener.
    fn drawn() -> Ruleset {
        gateways()
            .with_decoys(&[41_000, 6379], true, 41_001)
            .expect("a draw that collides with nothing")
    }

    #[test]
    fn the_public_hash_does_not_move_with_the_draw_and_moves_with_everything_else() {
        let plain = gateways();
        assert_eq!(plain.public_sha256(), plain.sha256());
        // Two claims that differ in their draw alone: different scripts, one public hash,
        // and that hash is the one the same claim has with no tripwire at all.
        let one = drawn();
        let other = gateways()
            .with_decoys(&[2222, 50_123, 9200], false, 40_404)
            .unwrap();
        assert_ne!(one.render(), other.render());
        assert_ne!(one.sha256(), other.sha256());
        assert_ne!(one.sha256(), plain.sha256());
        assert_eq!(one.public_sha256(), other.public_sha256());
        assert_eq!(one.public_sha256(), plain.sha256());
        // And it moves with everything else.
        let mut wider = one.clone();
        wider.allow.insert(("203.0.113.9".parse().unwrap(), 443));
        assert_ne!(wider.public_sha256(), plain.sha256());
        let mut another_uid = one.clone();
        another_uid.uid = 1235;
        assert_ne!(another_uid.public_sha256(), plain.sha256());
        let mut direct = full().with_decoys(&[6379], false, 40_404).unwrap();
        assert_eq!(direct.public_sha256(), full().sha256());
        direct.dns.insert("192.0.2.54".parse().unwrap());
        assert_ne!(direct.public_sha256(), full().sha256());
    }

    #[test]
    fn with_no_decoys_the_ruleset_is_byte_identical_to_before() {
        // The two renders are pinned, whole, by the tests of each shape below; a claim with
        // no tripwire goes through `with_decoys` with nothing and gets exactly those.
        for rs in [full(), gateways()] {
            let unarmed = rs.clone().with_decoys(&[], false, 40_404).unwrap();
            assert_eq!(unarmed, rs);
            assert!(!unarmed.is_armed());
            let text = unarmed.render();
            assert_eq!(text, rs.render());
            for word in [
                "decoy", "denied", "nat", "169.254", "dnat", "update", "40404",
            ] {
                assert!(
                    !text.contains(word),
                    "nothing of a tripwire with none armed"
                );
            }
        }
    }

    #[test]
    fn the_decoy_ports_are_redirected_to_the_one_trap_listener_for_the_uid_alone() {
        // The maintainer's decision 13 of 2026-11-27: nothing listens on a decoy port; the
        // sandbox uid's connection to one is redirected to the trap listener, which nothing
        // reaches directly, and every other uid is refused a new connection to a decoy port.
        let expected = "\
# mediatore guest (ADR-0020, ADR-0025, ADR-0028 decision 6): uid 1234 reaches the broker through the control relay, the egress gateways and the egress proxy; no DNS, nothing else, and nobody else reaches the proxy
table inet mediatore_sandbox
delete table inet mediatore_sandbox
table inet mediatore_sandbox {
  set allow4 { type ipv4_addr . inet_service; elements = { 127.0.0.1 . 3128, 127.0.0.1 . 41001, 198.51.100.1 . 3130, 198.51.100.1 . 8443, 198.51.100.2 . 8443 } }
  set allow6 { type ipv6_addr . inet_service; elements = { 2001:db8::3 . 8443 } }
  set decoys { type inet_service; elements = { 6379, 41000 } }
  set denied4 { type ipv4_addr . inet_service; size 1024; flags dynamic,timeout; counter; timeout 1m; }
  set denied6 { type ipv6_addr . inet_service; size 1024; flags dynamic,timeout; counter; timeout 1m; }
  chain output {
    type filter hook output priority filter; policy accept;
    oifname \"lo\" tcp dport 3128 meta skuid != 1234 drop
    oifname \"lo\" tcp dport @decoys meta skuid != 1234 ct state new log prefix \"mediatore-sandbox decoy other uid: \" counter drop
    oifname \"lo\" tcp dport 41001 ct original proto-dst 41001 log prefix \"mediatore-sandbox trap port direct: \" counter drop
    meta skuid 1234 jump sandbox
  }
  chain sandbox {
    ct state established,related accept
    ip daddr . tcp dport @allow4 accept
    ip6 daddr . tcp dport @allow6 accept
    meta nfproto ipv4 meta l4proto tcp ct state new update @denied4 { ip daddr . tcp dport } log prefix \"mediatore-sandbox drop: \" counter drop
    meta nfproto ipv6 meta l4proto tcp ct state new update @denied6 { ip6 daddr . tcp dport } log prefix \"mediatore-sandbox drop: \" counter drop
    log prefix \"mediatore-sandbox drop: \" counter drop
  }
  chain nat_out {
    type nat hook output priority -100; policy accept;
    meta skuid 1234 ip daddr 127.0.0.1 tcp dport @decoys dnat ip to 127.0.0.1:41001
    meta skuid 1234 ip daddr 169.254.169.254 tcp dport 80 dnat ip to 127.0.0.1:41001
  }
}
";
        let rs = drawn();
        assert_eq!(rs.render(), expected);
        assert!(rs.is_armed());
        assert_eq!(rs.decoy_ports, BTreeSet::from([6379, 41_000]));
        assert_eq!(rs.trap_port, Some(41_001));
        // The other uids' rule and the direct-connection rule come before the uid's jump,
        // beside the proxy's, and are counted and logged.
        let lines: Vec<&str> = expected.lines().map(str::trim).collect();
        let at = |needle: &str| lines.iter().position(|l| l.contains(needle)).unwrap();
        assert!(at("decoy other uid") < at("jump sandbox"));
        assert!(at("trap port direct") < at("jump sandbox"));
        // No decoy port is a destination: only the trap listener, on loopback.
        for port in [6379, 41_000] {
            assert!(!rs.allow.iter().any(|(_, p)| *p == port));
        }
        let admitted: Vec<_> = rs.allow.iter().filter(|(_, p)| *p == 41_001).collect();
        assert_eq!(admitted.len(), 1);
        assert!(admitted[0].0.is_loopback());
    }

    #[test]
    fn the_metadata_redirect_is_keyed_on_the_uid_alone_and_absent_without_the_decoy() {
        let with = full().with_decoys(&[6379], true, 41_001).unwrap().render();
        let redirect: Vec<&str> = with.lines().filter(|l| l.contains("169.254")).collect();
        assert_eq!(
            redirect,
            [
                "    meta skuid 1234 ip daddr 169.254.169.254 tcp dport 80 dnat ip to 127.0.0.1:41001"
            ],
            "one rule, for the sandbox uid alone: every other uid keeps ADR-0068's drop"
        );
        assert!(with.contains(
            "  chain nat_out {\n    type nat hook output priority -100; policy accept;\n"
        ));
        assert!(
            with.contains("set decoys { type inet_service; elements = { 6379 } }"),
            "the trap listener's port is no decoy"
        );
        // The address itself is admitted nowhere: only the loopback port it is redirected to.
        assert!(!with.contains("169.254.169.254 ."));
        let without = full().with_decoys(&[6379], false, 41_001).unwrap().render();
        assert!(
            !without.contains("169.254.169.254"),
            "no metadata redirect without the metadata decoy"
        );
        assert!(without.contains("set decoys { type inet_service; elements = { 6379 } }"));
        // The metadata decoy alone: the decoy set is empty, the redirect is there.
        let alone = full().with_decoys(&[], true, 41_001).unwrap().render();
        assert!(alone.contains("set decoys { type inet_service; }"));
        assert!(alone.contains("169.254.169.254 tcp dport 80 dnat ip to 127.0.0.1:41001"));
    }

    #[test]
    fn a_decoy_that_collides_with_the_list_is_refused_and_never_trimmed() {
        let refused = |rs: Ruleset, ports: &[u16], metadata: bool, trap: u16| {
            rs.with_decoys(ports, metadata, trap)
                .unwrap_err()
                .to_string()
        };
        assert!(refused(gateways(), &[0], false, 40_404).contains("port 0"));
        assert!(refused(gateways(), &[6379], false, 0).contains("port 0"));
        // The proxy's port and a destination's port: Landlock would admit either at every
        // address, around the proxy.
        assert!(refused(gateways(), &[3128], false, 40_404).contains("already uses"));
        assert!(refused(gateways(), &[6379, 8443], false, 40_404).contains("already uses"));
        assert!(refused(gateways(), &[6379], false, 3130).contains("already uses"));
        assert!(refused(gateways(), &[6379, 6379], false, 40_404).contains("twice"));
        assert!(refused(gateways(), &[6379], false, 6379).contains("twice"));
        assert!(refused(drawn(), &[2222], false, 40_404).contains("already carries a draw"));
        // The metadata decoy makes the jail admit port 80: never beside a destination on it.
        let mut plain_http = gateways();
        plain_http
            .allow
            .insert(("198.51.100.9".parse().unwrap(), 80));
        assert!(!plain_http.admits_the_metadata_decoy());
        assert!(refused(plain_http.clone(), &[6379], true, 41_001).contains("port 80"));
        assert!(plain_http.with_decoys(&[6379], false, 41_001).is_ok());
        assert!(gateways().admits_the_metadata_decoy());
        // What a draw reserves: every destination's port and the proxy's.
        assert_eq!(gateways().ports(), [3128, 3130, 8443]);
    }

    #[tokio::test]
    async fn a_refused_armed_ruleset_names_no_drawn_port_in_its_error() {
        // A NIT of the review: `nft` echoes the line it refused, and a discarded draw's ports
        // must not reach the log line the arming's failure is.
        let nft = testing::FakeNft::refusing(
            "/dev/stdin:6:42-46: Error: Could not process rule: No such file or directory\n  set decoys { type inet_service; elements = { 6379, 41000 } }\n    oifname \"lo\" tcp dport 41001 ct original proto-dst 41001 counter drop",
        );
        let error = format!("{:#}", load_with(&nft, &drawn()).await.unwrap_err());
        assert!(error.contains("refused the ruleset"), "{error}");
        for port in ["6379", "41000", "41001"] {
            assert!(!error.contains(port), "a drawn port is in the error");
        }
        assert!(error.contains("Could not process rule"), "the reason stays");
        // With no draw nothing is elided: the error is what nft said.
        let plain = testing::FakeNft::refusing("Error: syntax error near 8443");
        let error = format!("{:#}", load_with(&plain, &gateways()).await.unwrap_err());
        assert!(error.contains("8443"));
    }

    #[tokio::test]
    async fn the_ruleset_goes_to_nft_in_one_transaction_and_the_hash_returned_is_the_public_one() {
        let nft = testing::FakeNft::default();
        let rs = drawn();
        let hash = load_with(&nft, &rs).await.unwrap();
        assert_eq!(hash, rs.public_sha256());
        assert_ne!(
            hash,
            rs.sha256(),
            "the whole script's hash gives the draw away"
        );
        assert_eq!(
            nft.calls(),
            [(vec!["-f".to_owned(), "-".to_owned()], Some(rs.render()))]
        );
        // With no draw the two hashes are one, as before.
        assert_eq!(
            load_with(&nft, &gateways()).await.unwrap(),
            gateways().sha256()
        );
        // A refusal, or no nft at all, is an error: no jail (ADR-0020 decision 5).
        let refusing = testing::FakeNft::refusing("Error: syntax error");
        let err = load_with(&refusing, &rs).await.unwrap_err().to_string();
        assert!(err.contains("refused the ruleset") && err.contains("syntax error"));
        let absent = testing::FakeNft::absent();
        assert!(load_with(&absent, &rs).await.is_err());
        unload_with(&nft).await;
        assert_eq!(
            nft.calls().last().unwrap().0,
            ["delete", "table", "inet", "mediatore_sandbox"]
        );
    }

    /// A `denied4` listing in the shape nftables 1.1.3 prints a set with a counter per
    /// element (`image/host-table`'s `inbound_sources`, captured on a real kernel by the
    /// gateway lane); the element values here are this test's own.
    const DENIED4_JSON: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "denied4", "table": "mediatore_sandbox", "type": ["ipv4_addr", "inet_service"], "handle": 7, "size": 1024, "flags": ["timeout", "dynamic"], "timeout": 60, "elem": [{"elem": {"val": {"concat": ["10.0.0.5", 80]}, "expires": 57, "counter": {"packets": 2, "bytes": 120}}}, {"elem": {"val": {"concat": ["203.0.113.9", 6379]}, "expires": 58, "counter": {"packets": 1, "bytes": 60}}}, {"elem": {"val": {"concat": ["192.0.2.77", 80]}, "expires": 12, "counter": {"packets": 0, "bytes": 0}}}, {"elem": {"val": {"concat": ["not an address", 80]}, "counter": {"packets": 4, "bytes": 240}}}, {"elem": {"val": 25, "counter": {"packets": 9, "bytes": 540}}}, {"elem": {"val": {"concat": ["192.0.2.78", 0]}, "counter": {"packets": 1, "bytes": 60}}}, "odd"], "stmt": [{"counter": null}]}}]}"#;
    /// `nft -j -n reset set inet mediatore_sandbox denied4` as captured on a real kernel
    /// (Debian 13, kernel 6.12, nftables 1.1.3, 2026-11-27): the armed table of
    /// `the_decoy_ports_are_redirected_to_the_one_trap_listener_for_the_uid_alone`
    /// loaded in a fresh network namespace, and the sandbox uid dialling a closed loopback
    /// port, a private address and a public one. A count is of packets: a connect that
    /// waited a second and a half sent its SYN twice.
    const DENIED4_CAPTURED: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "denied4", "table": "mediatore_sandbox", "type": ["ipv4_addr", "inet_service"], "handle": 7, "size": 1024, "flags": ["timeout", "dynamic"], "timeout": 60, "elem": [{"elem": {"val": {"concat": ["127.0.0.1", 9999]}, "expires": 59, "counter": {"packets": 2, "bytes": 120}}}, {"elem": {"val": {"concat": ["10.0.0.5", 80]}, "expires": 56, "counter": {"packets": 4, "bytes": 240}}}, {"elem": {"val": {"concat": ["203.0.113.9", 6379]}, "expires": 57, "counter": {"packets": 2, "bytes": 120}}}], "stmt": [{"counter": null}]}}]}"#;
    /// The same set read again at once, as captured: the elements are still listed, with
    /// nothing counted since the reset.
    const DENIED4_CAPTURED_IDLE: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "denied4", "table": "mediatore_sandbox", "type": ["ipv4_addr", "inet_service"], "handle": 7, "size": 1024, "flags": ["timeout", "dynamic"], "timeout": 60, "elem": [{"elem": {"val": {"concat": ["127.0.0.1", 9999]}, "expires": 59, "counter": {"packets": 0, "bytes": 0}}}, {"elem": {"val": {"concat": ["10.0.0.5", 80]}, "expires": 56, "counter": {"packets": 0, "bytes": 0}}}, {"elem": {"val": {"concat": ["203.0.113.9", 6379]}, "expires": 57, "counter": {"packets": 0, "bytes": 0}}}], "stmt": [{"counter": null}]}}]}"#;
    /// An empty set, as captured: no `elem` member at all.
    const DENIED6_JSON: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "denied6", "table": "mediatore_sandbox", "type": ["ipv6_addr", "inet_service"], "handle": 8, "size": 1024, "flags": ["timeout", "dynamic"], "timeout": 60, "stmt": [{"counter": null}]}}]}"#;

    #[tokio::test]
    async fn the_denied_sets_are_read_and_zeroed_one_process_a_set_and_idle_elements_are_skipped() {
        let nft = testing::FakeNft::answering([DENIED4_JSON, DENIED6_JSON]);
        let denied = read_denied(&nft).await.unwrap();
        assert_eq!(
            denied,
            [
                Denied {
                    address: "10.0.0.5".parse().unwrap(),
                    port: 80,
                    packets: 2
                },
                Denied {
                    address: "203.0.113.9".parse().unwrap(),
                    port: 6379,
                    packets: 1
                },
            ],
            "the idle element, the one that is no address, the bare port and port 0 are skipped"
        );
        let calls: Vec<Vec<String>> = nft.calls().into_iter().map(|(args, _)| args).collect();
        assert_eq!(
            calls,
            [
                [
                    "-j",
                    "-n",
                    "reset",
                    "set",
                    "inet",
                    "mediatore_sandbox",
                    "denied4"
                ],
                [
                    "-j",
                    "-n",
                    "reset",
                    "set",
                    "inet",
                    "mediatore_sandbox",
                    "denied6"
                ],
            ]
        );
        // The captured listings: three destinations, then the same three with nothing new.
        let live = testing::FakeNft::answering([
            DENIED4_CAPTURED,
            DENIED6_JSON,
            DENIED4_CAPTURED_IDLE,
            DENIED6_JSON,
        ]);
        let first: Vec<(String, u16, u64)> = read_denied(&live)
            .await
            .unwrap()
            .iter()
            .map(|d| (d.address.to_string(), d.port, d.packets))
            .collect();
        assert_eq!(
            first,
            [
                ("127.0.0.1".to_owned(), 9999, 2),
                ("10.0.0.5".to_owned(), 80, 4),
                ("203.0.113.9".to_owned(), 6379, 2)
            ]
        );
        assert_eq!(read_denied(&live).await.unwrap(), [], "nothing twice");
        // The table gone (the claim ended, or a trip cut it): an error, not an empty read.
        let gone = testing::FakeNft::refusing("Error: No such file or directory");
        assert!(read_denied(&gone).await.is_err());
        assert!(
            read_denied(&testing::FakeNft::answering(["not json"]))
                .await
                .is_err()
        );
        // A listing of another set is not this one.
        assert!(
            read_denied(&testing::FakeNft::answering([DENIED6_JSON]))
                .await
                .is_err()
        );
    }

    #[test]
    fn the_nft_json_of_a_set_parses_and_an_element_of_another_shape_is_never_an_error() {
        let set = parse_set(DENIED4_JSON.as_bytes(), TABLE, DENIED4).unwrap();
        assert_eq!(set.size, Some(1024));
        assert_eq!(
            set.held, 7,
            "every listed element is held, whatever its shape"
        );
        assert_eq!(
            set.elements.len(),
            6,
            "the string that is no element has no counter"
        );
        let empty = parse_set(DENIED6_JSON.as_bytes(), TABLE, DENIED6).unwrap();
        assert_eq!((empty.held, empty.elements.len()), (0, 0));
        assert!(parse_set(DENIED4_JSON.as_bytes(), "another_table", DENIED4).is_err());
        assert!(parse_set(b"{\"nftables\": 3}", TABLE, DENIED4).is_err());
        assert_eq!(
            address_and_port(&serde_json::json!({"concat": ["2001:db8::7", 443]})),
            Some(("2001:db8::7".parse().unwrap(), 443))
        );
        for odd in [
            serde_json::json!(25),
            serde_json::json!({"concat": ["192.0.2.1"]}),
            serde_json::json!({"concat": ["192.0.2.1", 70_000]}),
            serde_json::json!({"concat": [22, "192.0.2.1"]}),
            serde_json::json!({"prefix": {"addr": "192.0.2.0", "len": 24}}),
        ] {
            assert_eq!(address_and_port(&odd), None);
        }
    }

    fn gateways() -> Ruleset {
        Ruleset {
            uid: 1234,
            allow: [
                ("198.51.100.1".parse().unwrap(), 3130),
                ("198.51.100.1".parse().unwrap(), 8443),
                ("198.51.100.2".parse().unwrap(), 8443),
                ("2001:db8::3".parse().unwrap(), 8443),
                ("127.0.0.1".parse().unwrap(), 3128),
            ]
            .into_iter()
            .collect(),
            dns: BTreeSet::new(),
            proxy_port: 3128,
            shape: Shape::Gateways,
            decoy_ports: BTreeSet::new(),
            metadata: false,
            trap_port: None,
        }
    }

    #[test]
    fn with_gateways_the_ruleset_admits_the_uid_to_the_relay_the_gateways_and_the_proxy_and_no_dns()
    {
        let expected = "\
# mediatore guest (ADR-0020, ADR-0025, ADR-0028 decision 6): uid 1234 reaches the broker through the control relay, the egress gateways and the egress proxy; no DNS, nothing else, and nobody else reaches the proxy
table inet mediatore_sandbox
delete table inet mediatore_sandbox
table inet mediatore_sandbox {
  set allow4 { type ipv4_addr . inet_service; elements = { 127.0.0.1 . 3128, 198.51.100.1 . 3130, 198.51.100.1 . 8443, 198.51.100.2 . 8443 } }
  set allow6 { type ipv6_addr . inet_service; elements = { 2001:db8::3 . 8443 } }
  chain output {
    type filter hook output priority filter; policy accept;
    oifname \"lo\" tcp dport 3128 meta skuid != 1234 drop
    meta skuid 1234 jump sandbox
  }
  chain sandbox {
    ct state established,related accept
    ip daddr . tcp dport @allow4 accept
    ip6 daddr . tcp dport @allow6 accept
    log prefix \"mediatore-sandbox drop: \" counter drop
  }
}
";
        let text = gateways().render();
        assert_eq!(text, expected);
        assert!(!text.contains("53"), "no DNS rule of any kind");
        assert!(!text.contains("dns"), "no DNS set either");
    }

    fn gateway_list() -> Vec<Endpoint> {
        vec![
            ep("198.51.100.1:8443"),
            ep("198.51.100.2:8443"),
            ep("[2001:db8::3]:8443"),
        ]
    }

    #[test]
    fn a_claim_with_a_gateway_placed_route_admits_each_gateways_inject_port_and_only_then() {
        // ADR-0040 decision 7: the proxy's sockets carry the sandbox uid, so the uid's table gains
        // gateway:INJECT_PORT for each gateway, and only for a claim that has such a route.
        let without = gateways();
        let none = BTreeSet::new();
        assert_eq!(
            without
                .clone()
                .with_inject_ports(&gateway_list(), &none)
                .unwrap()
                .render(),
            without.render(),
            "no gateway-placed route: exactly the ruleset the claim always had"
        );
        let with = without
            .clone()
            .with_inject_ports(&gateway_list(), &BTreeSet::from([3133]))
            .unwrap();
        let expected = "\
# mediatore guest (ADR-0020, ADR-0025, ADR-0028 decision 6): uid 1234 reaches the broker through the control relay, the egress gateways and the egress proxy; no DNS, nothing else, and nobody else reaches the proxy
table inet mediatore_sandbox
delete table inet mediatore_sandbox
table inet mediatore_sandbox {
  set allow4 { type ipv4_addr . inet_service; elements = { 127.0.0.1 . 3128, 198.51.100.1 . 3130, 198.51.100.1 . 3133, 198.51.100.1 . 8443, 198.51.100.2 . 3133, 198.51.100.2 . 8443 } }
  set allow6 { type ipv6_addr . inet_service; elements = { 2001:db8::3 . 3133, 2001:db8::3 . 8443 } }
  chain output {
    type filter hook output priority filter; policy accept;
    oifname \"lo\" tcp dport 3128 meta skuid != 1234 drop
    meta skuid 1234 jump sandbox
  }
  chain sandbox {
    ct state established,related accept
    ip daddr . tcp dport @allow4 accept
    ip6 daddr . tcp dport @allow6 accept
    log prefix \"mediatore-sandbox drop: \" counter drop
  }
}
";
        assert_eq!(with.render(), expected);
        assert_ne!(
            with.sha256(),
            without.sha256(),
            "a change is visible in the log"
        );
        // Nothing else moved: the data ports, the relay port and the proxy are as before.
        assert!(
            without.allow.is_subset(&with.allow),
            "the inject ports are added, nothing is taken away"
        );
    }

    #[tokio::test]
    async fn a_claims_routes_decide_whether_the_inject_port_is_admitted() {
        // The guest's own sequence: resolve the list, then add the inject ports its routes name.
        use mediatore_proto::{Credential, Route};
        let route = |credential: Credential, inject_port: Option<u16>| Route {
            traps_body: mediatore_proto::trip::TrapsBody::Match,
            audience: Some("anthropic".into()),
            endpoint: ep("api.anthropic.example:443"),
            rules: vec![],
            ca_pem: None,
            credential,
            credential_header: None,
            inject_port,
            pull_only: false,
        };
        let dir = mediatore_testkit::tempdir();
        let resolv = dir.join("resolv.conf");
        std::fs::write(&resolv, "").unwrap();
        let list = vec![ep("198.51.100.1:3128"), ep("198.51.100.2:3128")];
        let ruleset = |routes: &[Route]| {
            let ports = crate::egress::inject_ports(routes);
            let list = list.clone();
            let resolv = resolv.clone();
            async move {
                Ruleset::resolve(
                    1234,
                    "https://198.51.100.1:3130",
                    &[],
                    &list,
                    &resolv,
                    18128,
                )
                .await
                .unwrap()
                .with_inject_ports(&list, &ports)
                .unwrap()
            }
        };
        let plain = ruleset(&[
            route(Credential::Token, None),
            route(Credential::None, None),
        ])
        .await;
        assert!(
            !plain.render().contains(". 3133"),
            "a token or no-credential route admits no inject port"
        );
        let placed = ruleset(&[route(Credential::Gateway, Some(3133))]).await;
        let text = placed.render();
        assert!(
            text.contains("198.51.100.1 . 3133") && text.contains("198.51.100.2 . 3133"),
            "{text}"
        );
        assert_eq!(
            plain.allow.len() + 2,
            placed.allow.len(),
            "one added destination per gateway, nothing else"
        );
    }

    #[test]
    fn an_inject_port_that_cannot_be_admitted_refuses_the_claim_before_it_starts() {
        let list = gateway_list();
        let one = |p: u16| BTreeSet::from([p]);
        let direct = Ruleset {
            shape: Shape::Direct,
            decoy_ports: BTreeSet::new(),
            metadata: false,
            trap_port: None,
            ..gateways()
        };
        let err = direct
            .with_inject_ports(&list, &one(3133))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("gateways") && err.contains("ADR-0040"),
            "{err}"
        );
        let err = gateways()
            .with_inject_ports(&list, &one(0))
            .unwrap_err()
            .to_string();
        assert!(err.contains("port 0"), "{err}");
        let err = gateways()
            .with_inject_ports(&list, &one(3128))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("3128") && err.contains("proxy"),
            "the workload's one allowed port must name one destination: {err}"
        );
        let err = gateways()
            .with_inject_ports(&[ep("gateway-1.home.example:8443")], &one(3133))
            .unwrap_err()
            .to_string();
        assert!(err.contains("by name"), "{err}");
    }

    #[test]
    fn the_ruleset_admits_the_uid_to_the_broker_the_egress_and_dns_and_drops_the_rest() {
        let expected = "\
# mediatore guest (ADR-0020, ADR-0025): uid 1234 reaches the broker, the claim's egress, the egress proxy and DNS; nothing else, and nobody else reaches the proxy
table inet mediatore_sandbox
delete table inet mediatore_sandbox
table inet mediatore_sandbox {
  set allow4 { type ipv4_addr . inet_service; elements = { 192.0.2.10 . 8443, 198.51.100.7 . 443 } }
  set allow6 { type ipv6_addr . inet_service; elements = { 2001:db8::1 . 8443 } }
  set dns4 { type ipv4_addr; elements = { 192.0.2.53 } }
  set dns6 { type ipv6_addr; elements = { 2001:db8::53 } }
  chain output {
    type filter hook output priority filter; policy accept;
    oifname \"lo\" tcp dport 3128 meta skuid != 1234 drop
    meta skuid 1234 jump sandbox
  }
  chain sandbox {
    ct state established,related accept
    ip daddr . tcp dport @allow4 accept
    ip6 daddr . tcp dport @allow6 accept
    ip daddr @dns4 udp dport 53 accept
    ip daddr @dns4 tcp dport 53 accept
    ip6 daddr @dns6 udp dport 53 accept
    ip6 daddr @dns6 tcp dport 53 accept
    log prefix \"mediatore-sandbox drop: \" counter drop
  }
}
";
        assert_eq!(full().render(), expected);
    }

    #[test]
    fn only_the_uids_packets_enter_the_chain_and_the_chain_ends_in_a_drop() {
        let text = full().render();
        let output: Vec<&str> = text
            .lines()
            .skip_while(|l| !l.contains("chain output"))
            .skip(1)
            .take_while(|l| l.trim() != "}")
            .map(str::trim)
            .collect();
        assert_eq!(
            output,
            [
                "type filter hook output priority filter; policy accept;",
                "oifname \"lo\" tcp dport 3128 meta skuid != 1234 drop",
                "meta skuid 1234 jump sandbox"
            ],
            "two rules in the base chain: nobody but the uid reaches the proxy's port (ADR-0025), and the uid's packets are judged; everyone else keeps the policy"
        );
        let last = text
            .lines()
            .map(str::trim)
            .rfind(|l| l.ends_with("accept") || l.ends_with("drop"))
            .unwrap();
        assert!(last.ends_with("counter drop"), "{last}");
    }

    #[test]
    fn empty_sets_render_without_elements_and_the_broker_alone_is_enough() {
        let rs = Ruleset {
            uid: 7,
            allow: [("192.0.2.10".parse().unwrap(), 8443)]
                .into_iter()
                .collect(),
            dns: BTreeSet::new(),
            proxy_port: 3128,
            shape: Shape::Direct,
            decoy_ports: BTreeSet::new(),
            metadata: false,
            trap_port: None,
        };
        let text = rs.render();
        assert!(text.contains(
            "  set allow4 { type ipv4_addr . inet_service; elements = { 192.0.2.10 . 8443 } }\n"
        ));
        assert!(text.contains("  set allow6 { type ipv6_addr . inet_service; }\n"));
        assert!(text.contains("  set dns4 { type ipv4_addr; }\n"));
        assert!(text.contains("  set dns6 { type ipv6_addr; }\n"));
    }

    #[test]
    fn the_hash_is_of_the_rendered_text_and_does_not_depend_on_insertion_order() {
        let a = full();
        let mut b = a.clone();
        b.allow = a.allow.iter().rev().copied().collect();
        assert_eq!(a.sha256(), b.sha256());
        assert_eq!(
            a.sha256(),
            hex::encode(Sha256::digest(a.render().as_bytes()))
        );
        assert_eq!(a.sha256().len(), 64);
    }

    #[test]
    fn resolvers_come_from_nameserver_lines_only() {
        let dir = mediatore_testkit::tempdir();
        let path = dir.join("resolv.conf");
        std::fs::write(
            &path,
            "# generated\nsearch home.example\nnameserver 192.0.2.53\n  nameserver fe80::1%eth0\nnameserver bogus\noptions edns0\nnameserver\n",
        )
        .unwrap();
        let got = resolvers(&path);
        let want: BTreeSet<IpAddr> = ["192.0.2.53".parse().unwrap(), "fe80::1".parse().unwrap()]
            .into_iter()
            .collect();
        assert_eq!(got, want);
        assert_eq!(resolvers(&dir.join("absent")), BTreeSet::new());
    }

    #[test]
    fn the_broker_endpoint_is_the_urls_host_and_port() {
        assert_eq!(
            broker_endpoint("https://mediatore.home.example").unwrap(),
            ep("mediatore.home.example:443")
        );
        assert_eq!(
            broker_endpoint("https://mediatore.home.example:8443/").unwrap(),
            ep("mediatore.home.example:8443")
        );
        assert_eq!(
            broker_endpoint("https://[2001:db8::1]:8443").unwrap(),
            ep("[2001:db8::1]:8443")
        );
        assert_eq!(
            broker_endpoint("http://127.0.0.1:8080").unwrap(),
            ep("127.0.0.1:8080")
        );
        assert!(broker_endpoint("file:///tmp/x").is_err());
        assert!(broker_endpoint("not a url").is_err());
    }

    #[tokio::test]
    async fn the_registry_leg_on_a_gateways_address_is_never_in_the_sandbox_ruleset() {
        // ADR-0038 decision 4: the leg is on the same gateway address the jail is admitted to
        // (the relay's broker port, the data port), but a rule is an address and a port, and
        // the registry's port is on no list the jail's table is built from.
        let dir = mediatore_testkit::tempdir();
        let resolv = dir.join("resolv.conf");
        std::fs::write(&resolv, "").unwrap();
        let rs = Ruleset::resolve(
            4242,
            "https://198.51.100.1:3130",
            &[],
            &[ep("198.51.100.1:8443"), ep("198.51.100.2:8443")],
            &resolv,
            3128,
        )
        .await
        .unwrap();
        let text = rs.render();
        assert!(
            text.contains("198.51.100.1 . 3130"),
            "the broker's relay port is admitted"
        );
        for leg in ["3132", "3131", "3129"] {
            assert!(
                !text.contains(&format!(" . {leg}")),
                "no relay leg but the broker's is in the jail's table ({leg}): {text}"
            );
        }
        assert!(
            rs.allow
                .iter()
                .all(|(_, port)| [3130_u16, 3128, 8443].contains(port)),
            "{:?}",
            rs.allow
        );
    }

    #[tokio::test]
    async fn without_gateways_address_literals_need_no_dns_and_a_name_that_does_not_resolve_is_omitted()
     {
        let dir = mediatore_testkit::tempdir();
        let resolv = dir.join("resolv.conf");
        std::fs::write(&resolv, "nameserver 192.0.2.53\n").unwrap();
        let rs = Ruleset::resolve(
            4242,
            "https://192.0.2.10:8443",
            &[ep("198.51.100.7:443"), ep("no-such-host.invalid:443")],
            &[],
            &resolv,
            3128,
        )
        .await
        .unwrap();
        let want: BTreeSet<(IpAddr, u16)> = [
            ("192.0.2.10".parse().unwrap(), 8443),
            ("198.51.100.7".parse().unwrap(), 443),
            ("127.0.0.1".parse().unwrap(), 3128),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            rs.allow, want,
            "the broker always, the literal, the proxy on loopback, not the unresolvable name"
        );
        assert_eq!(rs.shape, Shape::Direct);
        assert_eq!(rs.uid, 4242);
        assert_eq!(rs.proxy_port, 3128);
        assert_eq!(
            rs.dns.len(),
            1,
            "DNS to the VM's resolver, for the proxy's own lookups"
        );
    }

    #[tokio::test]
    async fn with_gateways_the_list_is_the_relay_the_gateways_and_the_proxy_by_address_and_nothing_is_resolved()
     {
        let dir = mediatore_testkit::tempdir();
        let resolv = dir.join("resolv.conf");
        std::fs::write(&resolv, "nameserver 192.0.2.53\n").unwrap();
        let rs = Ruleset::resolve(
            1234,
            "https://198.51.100.1:3130",
            &[ep("grafana.home.example:443"), ep("198.51.100.7:443")],
            &[
                ep("198.51.100.1:8443"),
                ep("198.51.100.2:8443"),
                ep("[2001:db8::3]:8443"),
            ],
            &resolv,
            3128,
        )
        .await
        .unwrap();
        assert_eq!(
            rs,
            gateways(),
            "the audiences' endpoints are not in it, by name or by address, and no resolver is"
        );
    }

    #[tokio::test]
    async fn with_gateways_a_broker_or_a_gateway_given_by_name_is_refused() {
        let err = Ruleset::resolve(
            1,
            "https://mediatore.home.example:8443",
            &[],
            &[ep("198.51.100.1:8443")],
            Path::new("/nonexistent"),
            3128,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("the broker is given by name") && err.contains("ADR-0027 decision 3"),
            "{err}"
        );
        let err = Ruleset::resolve(
            1,
            "https://198.51.100.1:3130",
            &[],
            &[ep("198.51.100.1:8443"), ep("gateway-2.home.example:8443")],
            Path::new("/nonexistent"),
            3128,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("a gateway is given by name, gateway-2.home.example:8443"),
            "{err}"
        );
    }

    #[test]
    fn the_bootstrap_list_is_one_endpoint_per_line_absent_means_none_and_a_bad_line_is_an_error() {
        let dir = mediatore_testkit::tempdir();
        let path = dir.join("gateways");
        assert_eq!(bootstrap_gateways(&path).unwrap(), Vec::<Endpoint>::new());
        std::fs::write(
            &path,
            "# the pool's gateways (ADR-0027 decision 4)\n198.51.100.1:8443\n\n  198.51.100.2:8443  \n[2001:db8::3]:8443\n",
        )
        .unwrap();
        assert_eq!(
            bootstrap_gateways(&path).unwrap(),
            vec![
                ep("198.51.100.1:8443"),
                ep("198.51.100.2:8443"),
                ep("[2001:db8::3]:8443")
            ]
        );
        std::fs::write(&path, "198.51.100.1:8443\nnot an endpoint\n").unwrap();
        let err = bootstrap_gateways(&path).unwrap_err().to_string();
        assert!(
            err.contains("not an endpoint") && err.contains("gateways"),
            "{err}"
        );
    }

    #[test]
    fn the_brokers_gateways_win_then_the_pools_then_none() {
        let broker = [ep("198.51.100.1:8443")];
        let pool = [ep("198.51.100.9:8443")];
        assert_eq!(
            choose_gateways(&broker, &pool),
            (broker.to_vec(), GatewaySource::Broker)
        );
        assert_eq!(
            choose_gateways(&[], &pool),
            (pool.to_vec(), GatewaySource::Bootstrap)
        );
        assert_eq!(choose_gateways(&[], &[]), (Vec::new(), GatewaySource::None));
        assert_eq!(Shape::Direct.to_string(), "direct");
        assert_eq!(Shape::Gateways.to_string(), "gateways");
    }

    #[tokio::test]
    async fn a_destination_on_the_proxys_port_is_refused() {
        let err = Ruleset::resolve(
            1,
            "https://192.0.2.10:8443",
            &[ep("198.51.100.7:3128")],
            &[],
            Path::new("/nonexistent"),
            3128,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("198.51.100.7:3128") && err.contains("ADR-0025"),
            "{err}"
        );
        let err = Ruleset::resolve(
            1,
            "https://192.0.2.10:8443",
            &[],
            &[ep("203.0.113.1:3128")],
            Path::new("/nonexistent"),
            3128,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("203.0.113.1:3128"),
            "a gateway on the proxy's port: {err}"
        );
        let err = Ruleset::resolve(
            1,
            "https://192.0.2.10:3128",
            &[],
            &[],
            Path::new("/nonexistent"),
            3128,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("egress proxy's port"), "{err}");
    }

    #[tokio::test]
    async fn a_broker_that_does_not_resolve_is_an_error_not_a_ruleset() {
        let err = Ruleset::resolve(
            1,
            "https://no-such-host.invalid",
            &[],
            &[],
            Path::new("/nonexistent"),
            3128,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("no-such-host.invalid"), "{err}");
    }

    /// Hands the rendered text to a real `nft -c`, which checks syntax through netlink and
    /// therefore wants `CAP_NET_ADMIN` even to check. Set `MEDIATORE_NFT` to the command,
    /// `sudo /usr/sbin/nft` on the build host; the test fails, never skips, without it.
    #[tokio::test]
    #[ignore = "needs an nft with CAP_NET_ADMIN: MEDIATORE_NFT='sudo /usr/sbin/nft'"]
    async fn nft_accepts_the_rendered_ruleset() {
        let cmd = std::env::var("MEDIATORE_NFT").unwrap_or_else(|_| {
            panic!("set MEDIATORE_NFT to an nft command that may open netlink, e.g. 'sudo /usr/sbin/nft'")
        });
        let mut parts = cmd.split_whitespace();
        let program = parts.next().expect("a command");
        let args: Vec<&str> = parts.collect();
        let empty = Ruleset {
            uid: 7,
            allow: [("192.0.2.10".parse().unwrap(), 8443)]
                .into_iter()
                .collect(),
            dns: BTreeSet::new(),
            proxy_port: 3128,
            shape: Shape::Direct,
            decoy_ports: BTreeSet::new(),
            metadata: false,
            trap_port: None,
        };
        for rs in [full(), empty, gateways()] {
            check(program, &args, &rs.render()).await;
        }
    }

    /// `nft -c -f -` on `script` with the command of `MEDIATORE_NFT`; panics on a refusal.
    async fn check(program: &str, args: &[&str], script: &str) {
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .args(["-c", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn nft");
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(script.as_bytes()).await.unwrap();
        stdin.shutdown().await.unwrap();
        drop(stdin);
        let out = child.wait_with_output().await.unwrap();
        // nft names the offending line; the text itself is pinned by the unit tests above.
        assert!(
            out.status.success(),
            "nft -c refused the ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    /// The command of `MEDIATORE_NFT`, split; the test fails, never skips, without it.
    fn live_nft() -> (String, Vec<String>) {
        let cmd = std::env::var("MEDIATORE_NFT").unwrap_or_else(|_| {
            panic!("set MEDIATORE_NFT to an nft command that may open netlink, e.g. 'sudo /usr/sbin/nft'")
        });
        let mut parts = cmd.split_whitespace().map(str::to_owned);
        let program = parts.next().expect("a command");
        (program, parts.collect())
    }

    /// The armed scripts against a real `nft -c`: both shapes with decoys, with and without
    /// the metadata redirect. `-c` checks and loads nothing; that the kernel takes the `nat`
    /// chain and that the redirect answers is proven only by loading it (the live jail tests).
    #[tokio::test]
    #[ignore = "needs an nft with CAP_NET_ADMIN: MEDIATORE_NFT='sudo /usr/sbin/nft'"]
    async fn nft_accepts_the_ruleset_with_decoys_and_the_metadata_redirect() {
        let (program, args) = live_nft();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        for rs in [
            drawn(),
            gateways().with_decoys(&[2222], false, 40_404).unwrap(),
            full().with_decoys(&[6379, 41_000], true, 41_001).unwrap(),
            full().with_decoys(&[], true, 41_001).unwrap(),
        ] {
            check(&program, &args, &rs.render()).await;
        }
    }

    /// The cut's script against a real `nft -c`.
    #[tokio::test]
    #[ignore = "needs an nft with CAP_NET_ADMIN: MEDIATORE_NFT='sudo /usr/sbin/nft'"]
    async fn nft_accepts_the_drop_all_ruleset() {
        let (program, args) = live_nft();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        check(&program, &args, &crate::trip::drop_all_ruleset(1234)).await;
    }
}
