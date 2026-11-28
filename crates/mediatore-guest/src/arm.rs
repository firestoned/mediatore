// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Arming a claim's tripwire (ADR-0069), in the one order that never leaves a trap reachable
//! by the wrong uid or a jail running beside a proxy that is not armed:
//!
//! 1. the draw ([`crate::draw`]), from the OS's random source, the trap listener's port
//!    ([`crate::draw::trap_port`]) and the chaff ports ([`crate::draw::chaff_ports`],
//!    ADR-0077);
//! 2. the claim's ruleset with the decoy ports redirected to that listener
//!    ([`Ruleset::with_decoys`]) and the chaff ports counted ([`Ruleset::with_chaff`]);
//! 3. the home, planted before anything runs as the sandbox user
//!    ([`crate::sandboxfs::plant_home`]);
//! 4. the tripwire's tasks ([`crate::trip::start`]);
//! 5. the ruleset loaded, so no other uid reaches the trap listener before it listens;
//! 6. the trap listener ([`crate::decoy::listen`]), the one socket that answers for every
//!    decoy (nothing listens on a decoy port);
//! 7. the trap socket ([`crate::trip::serve_socket`]);
//! 8. the egress proxy with `--trap-socket`, and its `armed` answer;
//! 9. the reader of what the chain dropped and of the chaff ports' uses
//!    ([`crate::trip::watch_denied`]).
//!
//! Only then does the guest start the jail, with what the draw plants in it
//! ([`crate::jail::JailTraps`]).
//!
//! A failure of any step is a failure to arm (decision 5, amended). Under `enforce` it is
//! returned: no jail starts, and the claim ends as after any failure to build the sandbox.
//! Under `shadow` it is logged at `warn` and the claim runs unarmed: the ruleset without
//! decoys loaded again, the proxy without the socket, the jail without bait. With no `traps`
//! in `GET /v1/me`, or under `off`, none of this runs and [`load`] does what the guest always
//! did.
//!
//! Nothing here logs a drawn port, host, variable or value.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mediatore_proto::Route;
use mediatore_proto::trip::{METADATA_ADDRESS, TrapsPolicy, TripMode};

use crate::draw::{self, DrawInputs, OsEntropy};
use crate::egress::{PHANTOM_ENV, PROXY_URL_ENV};
use crate::jail::JailTraps;
use crate::net::{self, NftRunner, Ruleset, SystemNft};
use crate::trip::{self, Cause, DeniedReader, SocketGuard, Timing, TripSink, Tripwire};
use crate::{decoy, egress, sandboxfs};

/// How long the proxy's `armed` may take to arrive once its ready line was read. The proxy
/// answers `armed` before it prints that line, so this is a bound on the guest's own reader.
pub const PROXY_ARMED: Duration = Duration::from_secs(10);

/// How long events still pending (`would_trip`, `reported`) may take to reach the broker at
/// the end of a run no trip ended.
pub const PENDING_FLUSH: Duration = Duration::from_secs(5);

/// The variables the guest itself sets in the jail: no decoy and no bait takes one.
const GUEST_ENV: [&str; 3] = ["HOME", PROXY_URL_ENV, PHANTOM_ENV];

/// What arming needs to know of the claim.
pub struct Arming<'a> {
    /// What `GET /v1/me` said of traps: the `denied` switches and the deployment's catalogue.
    pub policy: &'a TrapsPolicy,
    /// `shadow` or `enforce`.
    pub mode: TripMode,
    /// The sandbox user.
    pub uid: u32,
    /// Its group.
    pub gid: u32,
    /// The claim's real routes.
    pub routes: &'a [Route],
    /// The egress proxy's loopback port.
    pub proxy_port: u16,
    /// The proxy's pull listener's port.
    pub pull_port: u16,
    /// The claim's tmpfs: the home is planted under it.
    pub sandbox_root: &'a Path,
    /// The trap socket's directory (`mediatore_proto::trip::TRAP_SOCKET_DIR` in a guest).
    pub socket_dir: &'a Path,
    /// Where trip reports go.
    pub sink: Arc<dyn TripSink>,
}

impl std::fmt::Debug for Arming<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Arming")
            .field("mode", &self.mode)
            .field("uid", &self.uid)
            .finish_non_exhaustive()
    }
}

/// The `shadow` or `enforce` policy a claim carries, if any: `None` when `GET /v1/me` has no
/// `traps` (an older broker, or one with none configured) and under `off`.
#[must_use]
pub fn requested(traps: Option<&TrapsPolicy>) -> Option<(TripMode, &TrapsPolicy)> {
    let policy = traps?;
    Some((policy.mode.trip_mode()?, policy))
}

/// Whether the VM has a route to the metadata address (the plan's D25): without one a connect
/// to it fails before any hook, and a decoy there could never be reached. A UDP socket's
/// `connect` asks the routing table and sends nothing.
#[must_use]
pub fn metadata_is_routed() -> bool {
    let Ok(address) = METADATA_ADDRESS.parse::<std::net::SocketAddr>() else {
        return false;
    };
    std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|socket| socket.connect(address))
        .is_ok()
}

/// A claim's armed tripwire. Held for the whole run: dropping it closes the decoy listeners
/// and the trap socket and stops the reader of the chain's drops, and the supervision ends a
/// run whose tripwire is gone.
pub struct Armed {
    mode: TripMode,
    uid: u32,
    wire: Tripwire,
    ruleset: Ruleset,
    sha256: String,
    jail: JailTraps,
    home: PathBuf,
    socket: SocketGuard,
    _listeners: decoy::Listeners,
    denied: Option<DeniedReader>,
    nft: Arc<dyn NftRunner>,
    /// How long the proxy's `armed` may take once it is ready ([`PROXY_ARMED`]).
    proxy_within: Duration,
}

impl std::fmt::Debug for Armed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Armed")
            .field("mode", &self.mode)
            .field("uid", &self.uid)
            .finish_non_exhaustive()
    }
}

/// Steps 1 to 7 with the VM's `nft`: everything but the proxy.
///
/// # Errors
/// Any step failing: nothing is left listening, and the caller decides by the mode.
pub async fn arm(arming: &Arming<'_>, unarmed: &Ruleset) -> anyhow::Result<Armed> {
    arm_with(
        arming,
        unarmed,
        &Vm::observed(),
        Arc::new(SystemNft),
        Timing::default(),
    )
    .await
}

/// What arming needs to know of the VM it runs on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vm {
    /// Whether the metadata address is routed ([`metadata_is_routed`]).
    pub metadata_routed: bool,
    /// The TCP ports something on the VM already listens on ([`listening_ports`]): a decoy is
    /// redrawn off them (ADR-0069 decision 3: a collision with anything real is redrawn), since
    /// a decoy that could not bind would be a failure to arm.
    pub listening: Vec<u16>,
}

impl Vm {
    /// The VM as it is now.
    #[must_use]
    pub fn observed() -> Self {
        Self {
            metadata_routed: metadata_is_routed(),
            listening: listening_ports(),
        }
    }
}

/// The TCP ports something listens on in this network namespace, at any address, from the
/// kernel's socket tables. Empty where they cannot be read: a decoy on a taken port then fails
/// to bind, which is a failure to arm, never a decoy silently missing.
#[must_use]
pub fn listening_ports() -> Vec<u16> {
    let mut ports: Vec<u16> = ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .filter_map(|table| std::fs::read_to_string(table).ok())
        .flat_map(|table| parse_listening(&table))
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The local ports of the listening sockets in one `/proc/net/tcp` table: the lines whose
/// state is `0A` (`TCP_LISTEN`), the port being the hexadecimal number after the last colon of
/// the local address.
fn parse_listening(table: &str) -> Vec<u16> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let local = fields.nth(1)?;
            let state = fields.nth(1)?;
            if state != "0A" {
                return None;
            }
            u16::from_str_radix(local.rsplit(':').next()?, 16).ok()
        })
        .collect()
}

/// [`arm`] through `nft`, with the tripwire's bounds and what is known of the VM.
///
/// # Errors
/// As [`arm`].
pub async fn arm_with(
    arming: &Arming<'_>,
    unarmed: &Ruleset,
    vm: &Vm,
    nft: Arc<dyn NftRunner>,
    timing: Timing,
) -> anyhow::Result<Armed> {
    let mut attempt = 1;
    loop {
        match arm_once(arming, unarmed, vm, nft.clone(), timing).await {
            Err(e) if draws_again(&e, attempt) => {
                tracing::warn!(
                    attempt,
                    "the trap listener's drawn port was taken before it could be bound: drawing again"
                );
                attempt += 1;
            }
            armed => return armed,
        }
    }
}

/// How many draws one arming makes at most.
const ARM_ATTEMPTS: u32 = 3;

/// The marker of the one failure a new draw can cure: the trap listener that could not be
/// bound, because something took the port between the look at the VM's listeners and the
/// bind. It carries no port.
#[derive(Debug, thiserror::Error)]
#[error("the trap listener could not be bound")]
struct Unbound;

/// Whether a failed arming is tried again with a new draw: only for [`Unbound`], and only
/// [`ARM_ATTEMPTS`] times in all. Every other failure is a failure to arm at once.
fn draws_again(error: &anyhow::Error, attempt: u32) -> bool {
    attempt < ARM_ATTEMPTS && error.downcast_ref::<Unbound>().is_some()
}

/// One draw, armed up to the trap socket.
async fn arm_once(
    arming: &Arming<'_>,
    unarmed: &Ruleset,
    vm: &Vm,
    nft: Arc<dyn NftRunner>,
    timing: Timing,
) -> anyhow::Result<Armed> {
    let mut reserved_ports = unarmed.ports();
    reserved_ports.extend(&vm.listening);
    let drawn = draw::draw(
        &mut OsEntropy,
        &DrawInputs {
            routes: arming.routes,
            proxy_port: arming.proxy_port,
            pull_port: arming.pull_port,
            reserved_ports: &reserved_ports,
            reserved_env: &GUEST_ENV,
            catalogue: arming.policy.catalogue.as_ref(),
            metadata: vm.metadata_routed && unarmed.admits_the_metadata_decoy(),
        },
    )?;
    // The decoy ports, not `connect_ports()`: that list has 80 for the metadata decoy, which is
    // the metadata address's redirect. Nothing listens on a decoy port: the one trap listener
    // is on a port drawn here, off every port the claim, the VM and the draw use (the
    // maintainer's decision 13 of 2026-11-27).
    let ports: Vec<u16> = drawn.ports.iter().map(|p| p.port).collect();
    let mut taken = reserved_ports.clone();
    taken.extend(&ports);
    taken.extend(drawn.metadata_port);
    taken.extend([arming.proxy_port, arming.pull_port]);
    let trap_port = draw::trap_port(&mut OsEntropy, &taken)?;
    // The chaff (ADR-0077 decision 2): drawn last, off everything above and the trap
    // listener's port, so neither the claim's draw nor the trap port changes.
    taken.push(trap_port);
    let chaff = draw::chaff_ports(&mut OsEntropy, arming.routes, &taken)?;
    let ruleset = unarmed
        .clone()
        .with_decoys(&ports, drawn.metadata_port.is_some(), trap_port)?
        .with_chaff(&chaff)?;
    let files: Vec<(&str, &[u8])> = drawn
        .credentials
        .iter()
        .flat_map(|bait| &bait.files)
        .map(|(path, content)| (path.as_str(), content.expose().as_bytes()))
        .collect();
    let home = sandboxfs::plant_home(arming.sandbox_root, arming.uid, arming.gid, &files)?;
    let armed = async {
        let jail = JailTraps::new(
            &drawn,
            &format!("http://127.0.0.1:{}", arming.proxy_port),
            home.clone(),
        )?
        .with_chaff(&chaff);
        let wire = trip::start_with(
            arming.mode,
            arming.policy.denied,
            arming.uid,
            arming.sink.clone(),
            nft.clone(),
            timing,
        );
        // Loaded before the trap listener listens, so no other uid ever reaches it.
        let sha256 = net::load_with(nft.as_ref(), &ruleset).await?;
        let listeners = decoy::listen(
            &drawn.ports,
            drawn.metadata_port.is_some(),
            trap_port,
            wire.trips.clone(),
        )
        .await
        .map_err(|e| e.context(Unbound))?;
        let socket = trip::serve_socket(
            arming.socket_dir,
            arming.uid,
            drawn.proxy_traps(arming.mode, arming.policy.denied.unknown_host),
            wire.trips.clone(),
        )
        .await?;
        anyhow::Ok(Armed {
            mode: arming.mode,
            uid: arming.uid,
            wire,
            ruleset,
            sha256,
            jail,
            home: home.clone(),
            socket,
            _listeners: listeners,
            denied: None,
            nft,
            proxy_within: PROXY_ARMED,
        })
    }
    .await;
    if armed.is_err() {
        unplant(&home);
    }
    armed
}

/// Remove a planted home that no jail will be given.
fn unplant(home: &Path) {
    if let Err(e) = std::fs::remove_dir_all(home)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(error = %e, "the planted home could not be removed");
    }
}

impl Armed {
    /// The trap socket's path: what the proxy is started with (`--trap-socket`).
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        self.socket.path()
    }

    /// The claim's ruleset with its draw, as loaded.
    #[must_use]
    pub fn ruleset(&self) -> &Ruleset {
        &self.ruleset
    }

    /// The loaded ruleset's public hash (ADR-0069 decision 13, amended): what is logged and
    /// reported, the same as the claim's hash with no tripwire.
    #[must_use]
    pub fn ruleset_sha256(&self) -> &str {
        &self.sha256
    }

    /// What the jail is given.
    #[must_use]
    pub fn jail_traps(&self) -> JailTraps {
        self.jail.clone()
    }

    /// The tripwire: its handle, and the signal the supervision watches.
    pub fn wire(&mut self) -> &mut Tripwire {
        &mut self.wire
    }

    /// Steps 8 and 9: start the proxy with `start`, which is given the trap socket's path and
    /// returns once the proxy's ready line was read; wait at most `within` for the proxy's
    /// `armed`; start the reader of what the chain dropped.
    ///
    /// # Errors
    /// The proxy did not start, or did not say it is armed: it is killed, and the caller
    /// decides by the mode.
    pub async fn proxy_with<F, Fut>(
        &mut self,
        within: Duration,
        start: F,
    ) -> anyhow::Result<tokio::process::Child>
    where
        F: FnOnce(PathBuf) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<tokio::process::Child>>,
    {
        let mut proxy = start(self.socket.path().to_owned()).await?;
        if let Err(e) = self.socket.armed(within).await {
            let _ = proxy.start_kill();
            let _ = proxy.wait().await;
            return Err(e);
        }
        self.denied = Some(trip::watch_denied_with(
            self.nft.clone(),
            self.wire.trips.clone(),
            trip::DENIED_EVERY,
        ));
        Ok(proxy)
    }
}

/// How the egress proxy is started for a claim.
#[derive(Debug, Clone, Copy)]
pub struct ProxyStart<'a> {
    /// The pinned binary.
    pub binary: &'a Path,
    /// Its arguments with no tripwire ([`egress::command_args`], and the pull listener's).
    pub args: &'a [String],
    /// The sandbox user.
    pub uid: u32,
    /// Its group.
    pub gid: u32,
    /// How long it gets to report ready.
    pub ready: Duration,
}

/// A claim's loaded ruleset, armed or not.
#[derive(Debug)]
pub struct Loaded {
    armed: Option<Armed>,
    /// The ruleset without decoys, for the `shadow` fall-back at the proxy.
    unarmed: Ruleset,
    /// The ruleset as loaded.
    pub ruleset: Ruleset,
    /// Its public hash: what is logged and reported.
    pub sha256: String,
}

/// Load the claim's ruleset: armed when `arming` asks (steps 1 to 7), and as the guest always
/// did otherwise.
///
/// # Errors
/// The ruleset could not be loaded; or, under `enforce`, the traps could not be armed: no jail
/// starts (ADR-0069 decision 5, amended).
pub async fn load(arming: Option<&Arming<'_>>, unarmed: Ruleset) -> anyhow::Result<Loaded> {
    let Some(arming) = arming else {
        let sha256 = net::load(&unarmed).await?;
        return Ok(Loaded {
            armed: None,
            ruleset: unarmed.clone(),
            unarmed,
            sha256,
        });
    };
    load_with(
        arm(arming, &unarmed).await,
        arming.mode,
        unarmed,
        &SystemNft,
    )
    .await
}

/// [`load`] from the outcome of the arming, reloading through `nft` on the fall-back.
async fn load_with(
    armed: anyhow::Result<Armed>,
    mode: TripMode,
    unarmed: Ruleset,
    nft: &dyn NftRunner,
) -> anyhow::Result<Loaded> {
    match armed {
        Ok(armed) => Ok(Loaded {
            ruleset: armed.ruleset().clone(),
            sha256: armed.ruleset_sha256().to_owned(),
            armed: Some(armed),
            unarmed,
        }),
        Err(e) if mode == TripMode::Enforce => Err(e.context(
            "the claim's traps could not be armed: under enforce no jail starts (ADR-0069 decision 5)",
        )),
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "the claim's traps could not be armed: under shadow the claim runs unarmed (ADR-0069 decision 5)");
            // Whatever of an armed ruleset was loaded is replaced by the claim's own.
            let sha256 = net::load_with(nft, &unarmed).await?;
            Ok(Loaded {
                armed: None,
                ruleset: unarmed.clone(),
                unarmed,
                sha256,
            })
        }
    }
}

impl Loaded {
    /// Start the egress proxy: armed (steps 8 and 9) when the tripwire is, and as the guest
    /// always did otherwise.
    ///
    /// # Errors
    /// The proxy did not start; or, under `enforce`, it did not arm: no jail starts.
    pub async fn start_proxy(
        &mut self,
        start: ProxyStart<'_>,
    ) -> anyhow::Result<tokio::process::Child> {
        self.start_proxy_through(|socket| async move {
            let Some(socket) = socket else {
                return egress::spawn(start.binary, start.args, start.uid, start.gid, start.ready)
                    .await;
            };
            let mut args = start.args.to_vec();
            args.extend(egress::trap_args(&socket));
            egress::spawn(start.binary, &args, start.uid, start.gid, start.ready).await
        })
        .await
    }

    /// [`Self::start_proxy`] through whatever starts the proxy: `start` is given the trap
    /// socket's path when the proxy is to be armed and `None` when it is not (no tripwire, or
    /// the `shadow` fall-back), and returns once the proxy is ready.
    ///
    /// # Errors
    /// As [`Self::start_proxy`].
    pub async fn start_proxy_through<F, Fut>(
        &mut self,
        start: F,
    ) -> anyhow::Result<tokio::process::Child>
    where
        F: Fn(Option<PathBuf>) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<tokio::process::Child>>,
    {
        let Some(armed) = &mut self.armed else {
            return start(None).await;
        };
        let (mode, within) = (armed.mode, armed.proxy_within);
        let started = armed.proxy_with(within, |socket| start(Some(socket))).await;
        match started {
            Ok(proxy) => Ok(proxy),
            Err(e) if mode == TripMode::Enforce => Err(e.context(
                "the egress proxy could not be armed: under enforce no jail starts (ADR-0069 decision 5)",
            )),
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "the egress proxy could not be armed: under shadow the claim runs unarmed (ADR-0069 decision 5)");
                self.disarm().await?;
                start(None).await
            }
        }
    }

    /// The `shadow` fall-back after the ruleset was loaded with its draw: the listeners and
    /// the socket closed, the planted home removed, the ruleset without decoys loaded again.
    async fn disarm(&mut self) -> anyhow::Result<()> {
        let Some(armed) = self.armed.take() else {
            return Ok(());
        };
        let (home, nft) = (armed.home.clone(), armed.nft.clone());
        drop(armed);
        unplant(&home);
        self.sha256 = net::load_with(nft.as_ref(), &self.unarmed).await?;
        self.ruleset = self.unarmed.clone();
        Ok(())
    }

    /// Whether the claim runs with its traps armed.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.armed.is_some()
    }

    /// The mode the claim's traps are armed under, when they are.
    #[must_use]
    pub fn mode(&self) -> Option<TripMode> {
        self.armed.as_ref().map(|a| a.mode)
    }

    /// What the jail is given; `None` unarmed, and the jail is then what it always was.
    #[must_use]
    pub fn jail_traps(&self) -> Option<JailTraps> {
        self.armed.as_ref().map(Armed::jail_traps)
    }

    /// The signal the supervision watches for the first trip.
    pub fn tripped(&mut self) -> Option<&mut tokio::sync::watch::Receiver<Option<Cause>>> {
        self.armed.as_mut().map(|a| &mut a.wire.tripped)
    }

    /// The cause of the trip that cut the sandbox uid off, once there is one. From then on
    /// the claim's table is the cut and must not be unloaded.
    #[must_use]
    pub fn cause(&self) -> Option<Cause> {
        self.armed
            .as_ref()
            .and_then(|a| a.wire.tripped.borrow().clone())
    }

    /// After a run a trip ended: wait until the broker has the report of it, or refused it
    /// for good. As long as the broker is unreachable this waits (ADR-0069 decision 7:
    /// retried until `204` or the VM is gone); the cut and the kill are long done.
    pub async fn reported(&self) {
        if let Some(armed) = &self.armed {
            armed.wire.trips.reported().await;
        }
    }

    /// [`Self::reported`], for at most `within`: whether the broker acknowledged (or refused
    /// for good) the report of the trip in time. True unarmed.
    pub async fn reported_within(&self, within: Duration) -> bool {
        match &self.armed {
            Some(armed) => armed.wire.trips.reported_within(within).await,
            None => true,
        }
    }

    /// Once the run's jail is gone, whatever ended it: the cause of a trip that ended the run,
    /// waiting [`trip::SETTLE`] for a use still on its way and for a cut still in `nft`
    /// ([`trip::Trips::settle`]). A run a trip raced is the tripped run (decision 12 of the
    /// review). `None` unarmed or under `shadow`.
    pub async fn settle(&self) -> Option<Cause> {
        match &self.armed {
            Some(armed) => armed.wire.trips.settle(trip::SETTLE).await,
            None => None,
        }
    }

    /// After a run no trip ended: send what is still pending (`would_trip`, `reported`),
    /// bounded by [`PENDING_FLUSH`]. Whether nothing was left unsent.
    pub async fn flush(&self) -> bool {
        match &self.armed {
            Some(armed) => armed.wire.trips.flush(PENDING_FLUSH).await,
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::testing::FakeNft;
    use mediatore_proto::trip::{TrapsMode, TripReport};
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::Mutex;

    struct NoBroker;

    #[async_trait::async_trait]
    impl TripSink for NoBroker {
        async fn post(&self, _: &TripReport) -> anyhow::Result<trip::PostOutcome> {
            anyhow::bail!("no broker in this test")
        }
    }

    /// The VM of a test that is not root: what the machine running it listens on, and every
    /// privileged port, since a decoy there could not be bound by the test (a guest is root and
    /// binds them).
    fn test_vm() -> Vm {
        let mut listening = listening_ports();
        listening.extend(1..1024);
        Vm {
            metadata_routed: false,
            listening,
        }
    }

    /// One arming at a time in this test binary: two draws may pick the same seed port, and
    /// only one listener can have it.
    static ONE_ARMING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[test]
    fn the_listening_ports_are_read_from_the_kernels_table_and_a_decoy_is_drawn_off_them() {
        // Two listeners (22 on every address, 3128 on loopback) and one established connection.
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1 0000000000000000 100 0 0 10 0\n\
   1: 0100007F:0C38 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 1235 1 0000000000000000 100 0 0 10 0\n\
   2: 0100007F:D431 0100007F:0C38 01 00000000:00000000 00:00000000 00000000  1001        0 1236 1 0000000000000000 20 4 30 10 -1\n";
        assert_eq!(parse_listening(table), [22, 3128]);
        let v6 = "  sl  local_address                         remote_address                        st\n\
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 0 0\n";
        assert_eq!(parse_listening(v6), [443]);
        assert_eq!(parse_listening(""), [] as [u16; 0]);
        // The draw never takes a port the VM listens on: here, every seed port under 1024.
        for _ in 0..500 {
            let routes = [route()];
            let mut reserved = vec![3128, 443];
            reserved.extend(test_vm().listening);
            let drawn = draw::draw(
                &mut OsEntropy,
                &DrawInputs {
                    routes: &routes,
                    proxy_port: 3128,
                    pull_port: 18129,
                    reserved_ports: &reserved,
                    reserved_env: &GUEST_ENV,
                    catalogue: None,
                    metadata: true,
                },
            )
            .unwrap();
            assert!(
                drawn.ports.len() + usize::from(drawn.metadata_port.is_some()) >= 2,
                "the draw is never shortened"
            );
            assert!(drawn.ports.iter().all(|p| p.port >= 1024));
            assert!(drawn.metadata_port.is_none_or(|p| p >= 1024));
        }
    }

    fn unarmed(uid: u32) -> Ruleset {
        Ruleset {
            uid,
            shape: net::Shape::Direct,
            allow: [("198.51.100.7".parse().unwrap(), 443)]
                .into_iter()
                .collect(),
            dns: std::collections::BTreeSet::new(),
            proxy_port: 3128,
            decoy_ports: std::collections::BTreeSet::new(),
            metadata: false,
            trap_port: None,
            chaff_ports: std::collections::BTreeSet::new(),
        }
    }

    fn route() -> Route {
        Route {
            traps_body: mediatore_proto::trip::TrapsBody::Match,
            audience: Some("internal-api".into()),
            endpoint: "api.example.com:443".parse().unwrap(),
            rules: vec![],
            ca_pem: None,
            credential: mediatore_proto::Credential::Token,
            credential_header: None,
            inject_port: None,
            pull_only: false,
        }
    }

    struct Fixture {
        root: PathBuf,
        /// A short path: a unix socket's is bounded.
        _socket_tmp: tempfile::TempDir,
        socket_dir: PathBuf,
        uid: u32,
        gid: u32,
        policy: TrapsPolicy,
        routes: Vec<Route>,
    }

    impl Fixture {
        fn new(mode: TrapsMode) -> Self {
            let root = mediatore_testkit::tempdir();
            let me = std::fs::metadata(&root).unwrap();
            let socket_tmp = tempfile::tempdir().unwrap();
            Self {
                socket_dir: socket_tmp.path().join("trap"),
                _socket_tmp: socket_tmp,
                root,
                uid: me.uid(),
                gid: me.gid(),
                policy: TrapsPolicy {
                    mode,
                    ..TrapsPolicy::default()
                },
                routes: vec![route()],
            }
        }

        fn arming(&self, mode: TripMode) -> Arming<'_> {
            Arming {
                policy: &self.policy,
                mode,
                uid: self.uid,
                gid: self.gid,
                routes: &self.routes,
                proxy_port: 3128,
                pull_port: 18129,
                sandbox_root: &self.root,
                socket_dir: &self.socket_dir,
                sink: Arc::new(NoBroker),
            }
        }
    }

    #[test]
    fn traps_absent_or_off_ask_for_nothing_and_shadow_and_enforce_ask_for_their_mode() {
        assert!(requested(None).is_none(), "an older broker: no `traps`");
        let policy = |mode| TrapsPolicy {
            mode,
            ..TrapsPolicy::default()
        };
        assert!(requested(Some(&policy(TrapsMode::Off))).is_none());
        assert_eq!(
            requested(Some(&policy(TrapsMode::Shadow))).map(|(m, _)| m),
            Some(TripMode::Shadow)
        );
        assert_eq!(
            requested(Some(&policy(TrapsMode::Enforce))).map(|(m, _)| m),
            Some(TripMode::Enforce)
        );
    }

    #[tokio::test]
    async fn arming_loads_the_draw_before_anything_listens_and_plants_the_home() {
        let _one = ONE_ARMING.lock().await;
        let fixture = Fixture::new(TrapsMode::Enforce);
        let nft = Arc::new(FakeNft::default());
        let plain = unarmed(fixture.uid);
        let mut armed = arm_with(
            &fixture.arming(TripMode::Enforce),
            &plain,
            &test_vm(),
            nft.clone(),
            Timing::default(),
        )
        .await
        .expect("armed");
        // One load a draw (one draw, unless a drawn port was taken at that instant and it drew again): the
        // last is the ruleset with this draw's decoys, and its reported hash is the public one.
        let calls = nft.calls();
        let script = calls
            .last()
            .and_then(|call| call.1.clone())
            .expect("a script on stdin");
        assert!(armed.ruleset().is_armed());
        assert_eq!(script, armed.ruleset().render());
        assert_eq!(armed.ruleset_sha256(), plain.public_sha256());
        assert_eq!(armed.ruleset_sha256(), armed.ruleset().public_sha256());
        assert!(
            !armed.ruleset().metadata,
            "no metadata decoy where the address is not routed"
        );
        // Nothing listens on a decoy port (the maintainer's decision 13 of 2026-11-27): the
        // one trap listener does, on a port of its own, and the socket is there for the proxy.
        let trap = armed.ruleset().trap_port.expect("a trap listener's port");
        assert!(!armed.ruleset().decoy_ports.contains(&trap));
        for port in &armed.ruleset().decoy_ports {
            assert!(
                tokio::net::TcpStream::connect(("127.0.0.1", *port))
                    .await
                    .is_err(),
                "a decoy port listens"
            );
        }
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", trap))
                .await
                .is_ok(),
            "the trap listener does not listen"
        );
        assert!(armed.socket_path().starts_with(&fixture.socket_dir));
        assert!(std::fs::symlink_metadata(armed.socket_path()).is_ok());
        // The home: the sandbox user's, 0700, beside the work dir.
        let home = fixture.root.join("home");
        let stat = std::fs::metadata(&home).unwrap();
        assert_eq!(stat.mode() & 0o7777, 0o700);
        assert_eq!((stat.uid(), stat.gid()), (fixture.uid, fixture.gid));
        // The connect to the trap listener above was a use (here, with no redirect in front of
        // it, one that names no decoy: noted all the same): under enforce the run is ended.
        let cause = tokio::time::timeout(
            Duration::from_secs(10),
            armed.wire().tripped.wait_for(Option::is_some),
        )
        .await
        .expect("a decoy port's use reaches the supervision")
        .expect("the tripwire is alive")
        .clone();
        assert_eq!(
            cause.map(|c| c.kind),
            Some(mediatore_proto::trip::TripKind::Port)
        );
    }

    #[tokio::test]
    async fn arming_draws_chaff_into_the_ruleset_and_the_jail_off_every_port_the_claim_uses() {
        let _one = ONE_ARMING.lock().await;
        let fixture = Fixture::new(TrapsMode::Shadow);
        let plain = unarmed(fixture.uid);
        let armed = arm_with(
            &fixture.arming(TripMode::Shadow),
            &plain,
            &test_vm(),
            Arc::new(FakeNft::default()),
            Timing::default(),
        )
        .await
        .expect("armed");
        let rs = armed.ruleset();
        let n = rs.chaff_ports.len();
        assert!(
            (16..=32).contains(&n),
            "{n} chaff ports (ADR-0077 decision 2)"
        );
        let vm = test_vm();
        for port in &rs.chaff_ports {
            assert!(*port >= 1024);
            assert!(!rs.decoy_ports.contains(port), "chaff on a decoy port");
            assert_ne!(Some(*port), rs.trap_port, "chaff on the trap listener");
            assert!(!plain.ports().contains(port), "chaff on the claim's own");
            assert!(![3128, 18_129, 443].contains(port));
            assert!(!vm.listening.contains(port), "chaff on a VM listener");
        }
        // The jail admits every chaff port beside the decoys: a count, never a port.
        let printed = format!("{:?}", armed.jail_traps());
        let admitted = rs.decoy_ports.len() + usize::from(rs.metadata) + n;
        assert!(
            printed.contains(&format!("connect_ports: {admitted}")),
            "{printed}"
        );
        // And what is reported is still the hash of the claim with no tripwire.
        assert_eq!(armed.ruleset_sha256(), plain.public_sha256());
        assert!(rs.render().contains("update @chaff_used"));
    }

    #[tokio::test]
    async fn under_enforce_a_guest_that_cannot_arm_starts_no_jail() {
        let _one = ONE_ARMING.lock().await;
        // ADR-0069 decision 5 (amended) and the plan's D12: the error comes back before any
        // proxy or jail could start, and nothing is left behind.
        let fixture = Fixture::new(TrapsMode::Enforce);
        let refusing = Arc::new(FakeNft::refusing("Error: Could not process rule"));
        let plain = unarmed(fixture.uid);
        let armed = arm_with(
            &fixture.arming(TripMode::Enforce),
            &plain,
            &test_vm(),
            refusing.clone(),
            Timing::default(),
        )
        .await;
        assert!(armed.is_err(), "nft refused the armed ruleset");
        assert!(
            !fixture.root.join("home").exists(),
            "no planted home is left for a jail that never starts"
        );
        let loaded = load_with(armed, TripMode::Enforce, plain, refusing.as_ref()).await;
        let error = format!("{:#}", loaded.expect_err("enforce returns the failure"));
        assert!(error.contains("under enforce no jail starts"), "{error}");
        assert_eq!(
            refusing.calls().len(),
            1,
            "nothing is loaded in its place under enforce"
        );
    }

    #[tokio::test]
    async fn under_shadow_a_guest_that_cannot_arm_runs_unarmed_on_the_ruleset_without_decoys() {
        let _one = ONE_ARMING.lock().await;
        let fixture = Fixture::new(TrapsMode::Shadow);
        let plain = unarmed(fixture.uid);
        // The socket's directory cannot be made: a file is in the way.
        std::fs::write(&fixture.socket_dir, b"").unwrap();
        let nft = Arc::new(FakeNft::default());
        let armed = arm_with(
            &fixture.arming(TripMode::Shadow),
            &plain,
            &test_vm(),
            nft.clone(),
            Timing::default(),
        )
        .await;
        assert!(armed.is_err(), "the trap socket could not be served");
        let loaded = load_with(armed, TripMode::Shadow, plain.clone(), nft.as_ref())
            .await
            .expect("shadow goes on");
        assert!(!loaded.is_armed());
        assert!(loaded.jail_traps().is_none(), "no bait in the jail");
        assert!(loaded.cause().is_none());
        assert_eq!(loaded.ruleset.render(), plain.render());
        assert_eq!(loaded.sha256, plain.public_sha256());
        let calls = nft.calls();
        assert!(
            calls.len() >= 2,
            "the armed ruleset, then the claim's own again"
        );
        assert_eq!(
            calls.last().and_then(|call| call.1.as_deref()),
            Some(plain.render().as_str()),
            "the ruleset without decoys is what stays loaded"
        );
        assert!(!fixture.root.join("home").exists());
        // And no decoy port of the failed attempt still listens.
        let armed_script = calls[0].1.clone().unwrap();
        assert_ne!(armed_script, plain.render());
    }

    #[tokio::test]
    async fn a_proxy_that_does_not_arm_is_killed_and_the_failure_returned() {
        let _one = ONE_ARMING.lock().await;
        let fixture = Fixture::new(TrapsMode::Enforce);
        let nft = Arc::new(FakeNft::default());
        let mut armed = arm_with(
            &fixture.arming(TripMode::Enforce),
            &unarmed(fixture.uid),
            &test_vm(),
            nft,
            Timing::default(),
        )
        .await
        .expect("armed");
        // A proxy that never connects to the socket: it cannot have armed.
        let started = tokio::time::timeout(
            Duration::from_secs(10),
            armed.proxy_with(Duration::from_millis(300), |_socket| async {
                Ok(tokio::process::Command::new("sleep")
                    .arg("600")
                    .kill_on_drop(true)
                    .spawn()?)
            }),
        )
        .await
        .expect("bounded");
        let error = format!("{:#}", started.expect_err("the proxy did not arm"));
        assert!(error.contains("did not arm"), "{error}");
    }

    /// A proxy that starts and never says it is armed: `sleep`, with the socket's path or none.
    fn silent_proxy(
        socket: Option<&PathBuf>,
        started: &Mutex<Vec<bool>>,
    ) -> anyhow::Result<tokio::process::Child> {
        started.lock().unwrap().push(socket.is_some());
        Ok(tokio::process::Command::new("sleep")
            .arg("600")
            .kill_on_drop(true)
            .spawn()?)
    }

    #[tokio::test]
    async fn under_shadow_a_proxy_that_does_not_arm_is_started_again_without_the_socket_on_the_ruleset_without_decoys()
     {
        let _one = ONE_ARMING.lock().await;
        let fixture = Fixture::new(TrapsMode::Shadow);
        let nft = Arc::new(FakeNft::default());
        let plain = unarmed(fixture.uid);
        let mut armed = arm_with(
            &fixture.arming(TripMode::Shadow),
            &plain,
            &test_vm(),
            nft.clone(),
            Timing::default(),
        )
        .await
        .expect("armed");
        armed.proxy_within = Duration::from_millis(200);
        let ports: Vec<u16> = armed.ruleset().trap_port.into_iter().collect();
        let socket = armed.socket_path().to_owned();
        let mut loaded = load_with(Ok(armed), TripMode::Shadow, plain.clone(), nft.as_ref())
            .await
            .expect("loaded");
        assert!(loaded.is_armed() && loaded.jail_traps().is_some());
        let started = Mutex::new(Vec::new());
        let mut proxy = loaded
            .start_proxy_through(|socket| {
                std::future::ready(silent_proxy(socket.as_ref(), &started))
            })
            .await
            .expect("shadow goes on with a proxy that has no traps");
        assert_eq!(
            *started.lock().unwrap(),
            [true, false],
            "first with the socket, then again without it"
        );
        assert!(!loaded.is_armed());
        assert!(loaded.jail_traps().is_none(), "no bait in the jail");
        assert!(
            loaded.tripped().is_none(),
            "nothing for the supervision to watch"
        );
        assert_eq!(loaded.ruleset.render(), plain.render());
        assert_eq!(loaded.sha256, plain.public_sha256());
        let calls = nft.calls();
        assert_eq!(
            calls.last().and_then(|c| c.1.clone()),
            Some(plain.render()),
            "the ruleset without decoys is what stays loaded"
        );
        assert!(
            !fixture.root.join("home").exists(),
            "the planted home is gone"
        );
        assert!(
            std::fs::symlink_metadata(&socket).is_err(),
            "the trap socket is gone"
        );
        // The listeners' tasks are stopped by the runtime at their next turn: soon, not at once.
        for port in ports {
            let closed = tokio::time::timeout(Duration::from_secs(5), async {
                while tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_ok()
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            assert!(closed.is_ok(), "the trap listener still listens");
        }
        let _ = proxy.start_kill();
    }

    #[tokio::test]
    async fn under_enforce_a_proxy_that_does_not_arm_ends_the_claim_before_any_jail() {
        let _one = ONE_ARMING.lock().await;
        let fixture = Fixture::new(TrapsMode::Enforce);
        let nft = Arc::new(FakeNft::default());
        let plain = unarmed(fixture.uid);
        let mut armed = arm_with(
            &fixture.arming(TripMode::Enforce),
            &plain,
            &test_vm(),
            nft.clone(),
            Timing::default(),
        )
        .await
        .expect("armed");
        armed.proxy_within = Duration::from_millis(200);
        let mut loaded = load_with(Ok(armed), TripMode::Enforce, plain.clone(), nft.as_ref())
            .await
            .expect("loaded");
        let started = Mutex::new(Vec::new());
        let refused = loaded
            .start_proxy_through(|socket| {
                std::future::ready(silent_proxy(socket.as_ref(), &started))
            })
            .await;
        let error = format!("{:#}", refused.expect_err("enforce returns the failure"));
        assert!(error.contains("under enforce no jail starts"), "{error}");
        assert_eq!(
            *started.lock().unwrap(),
            [true],
            "no second proxy is started in its place"
        );
        assert!(
            nft.calls()
                .iter()
                .all(|call| call.1.as_deref() != Some(plain.render().as_str())),
            "nothing is loaded in place of the armed ruleset"
        );
    }

    #[test]
    fn only_a_listener_that_could_not_be_bound_is_cured_by_a_new_draw_and_only_twice() {
        let unbound = || anyhow::anyhow!("Address already in use").context(Unbound);
        assert!(draws_again(&unbound(), 1));
        assert!(draws_again(&unbound(), 2));
        assert!(
            !draws_again(&unbound(), ARM_ATTEMPTS),
            "three draws at most"
        );
        assert!(
            draws_again(&unbound().context("arming"), 1),
            "under more context too"
        );
        assert!(
            !draws_again(&anyhow::anyhow!("nft refused the ruleset"), 1),
            "any other failure is a failure to arm at once"
        );
        assert!(
            !format!("{:#}", unbound()).contains("127.0.0.1:"),
            "the marker names no port"
        );
    }

    #[test]
    fn no_two_bait_files_of_a_draw_share_a_path() {
        // The home is planted with `create_new`: a path drawn twice would fail the arming.
        for _ in 0..2000 {
            let routes = [route()];
            let drawn = draw::draw(
                &mut OsEntropy,
                &DrawInputs {
                    routes: &routes,
                    proxy_port: 3128,
                    pull_port: 18129,
                    reserved_ports: &[3128, 443],
                    reserved_env: &GUEST_ENV,
                    catalogue: None,
                    metadata: true,
                },
            )
            .unwrap();
            let mut paths: Vec<&str> = drawn
                .credentials
                .iter()
                .flat_map(|b| &b.files)
                .map(|(p, _)| p.as_str())
                .collect();
            let all = paths.len();
            paths.sort_unstable();
            paths.dedup();
            assert_eq!(paths.len(), all, "two bait files share a path");
        }
    }
}
