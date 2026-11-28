// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The real `jail-exec` (ADR-0024) on a Linux kernel with Landlock: what the unit tests
//! pin as a plan, proven against the kernel. Run by hand on the build host:
//!
//! ```sh
//! cargo test -p mediatore --test jail_exec_live -- --include-ignored
//! ```
//!
//! A write inside a granted directory succeeds and one outside fails; a TCP connect to a
//! granted port succeeds and one to another port fails; a bind fails; a run with no port is
//! refused with exit 125 and runs nothing. Since ADR-0051 the same run proves the seccomp
//! layer: `AF_VSOCK`, `AF_NETLINK` and `AF_PACKET` fail `EAFNOSUPPORT`, a UDP or raw inet
//! socket and `io_uring_setup` fail `EPERM`, a non-blocking inet stream socket and `AF_UNIX`
//! work, and a forked child inherits the filter. Since its amendment of 2026-11-19 an inet
//! stream socket opened as MPTCP (protocol 262) fails `EPERM` too, and one that names
//! `IPPROTO_TCP` works. Needs `python3` on the host.
//!
//! # The tripwire tests (ADR-0069)
//!
//! The tests after the first one run a real jail (`nsjail`, the `jail-exec` role, Landlock and
//! seccomp) beside a claim's armed tripwire: the real draw, the real ruleset loaded with the
//! real `nft`, the real decoy listeners, the real cut and the real kill. What stands in: the
//! egress proxy (a process of the sandbox uid that answers `armed` on the trap socket, since
//! the real one needs a claim SVID) and the broker (a recorder, or nothing at all).
//!
//! They load a table and cut a uid off, so they refuse to run in the machine's own network or
//! mount namespace: run them as root inside throwaway ones, with a scratch directory on a
//! mount of that namespace, `nsjail`, `nft`, `useradd` and `python3` on `PATH`:
//!
//! ```sh
//! cargo test -p mediatore --test jail_exec_live --no-run
//! sudo unshare --net --mount sh -c '
//!   mount -t tmpfs tmpfs /mnt &&
//!   MEDIATORE_LIVE_ROOT=/mnt PATH=<dir of nsjail>:/usr/sbin:/usr/bin \
//!     <the test binary> --ignored --test-threads=1 --nocapture'
//! ```
//!
//! Each test makes a system user of its own (`sbt-` and eight random characters) and removes
//! it. A test whose fixture is missing fails; none of them skips.

#[test]
#[ignore = "needs a Linux kernel with Landlock (5.13+, 6.7+ for the ports): run on the build host"]
fn jail_exec_confines_what_it_was_told_and_refuses_otherwise() {
    #[cfg(not(target_os = "linux"))]
    panic!("this test proves Landlock and needs Linux; it must not pass anywhere else");
    #[cfg(target_os = "linux")]
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::TcpListener;
    use std::process::Command;

    const PROBE: &str = r#"
import ctypes, errno, os, socket, sys
def ok(f, code):
    try:
        f()
    except OSError as e:
        print(f"step {code}: expected success, got {e}", file=sys.stderr); sys.exit(code)
def denied(f, code):
    try:
        f()
    except OSError as e:
        if e.errno in (errno.EACCES, errno.EPERM):
            return
        print(f"step {code}: expected EACCES, got {e}", file=sys.stderr); sys.exit(code)
    print(f"step {code}: expected EACCES, got success", file=sys.stderr); sys.exit(code)
a = os.environ["ALLOWED"]; d = os.environ["DENIED"]
ok(lambda: open(a + "/f", "w").close(), 10)
denied(lambda: open(d + "/f", "w").close(), 11)
ok(lambda: socket.create_connection(("127.0.0.1", int(os.environ["PORT_A"])), 2).close(), 12)
denied(lambda: socket.create_connection(("127.0.0.1", int(os.environ["PORT_B"])), 2).close(), 13)
s = socket.socket()
denied(lambda: s.bind(("127.0.0.1", 0)), 14)
ok(lambda: open("/etc/hostname").close(), 15)

def errno_of(f):
    try:
        f()
    except OSError as e:
        return e.errno
    return 0
def refused(f, want, code):
    got = errno_of(f)
    if got != want:
        print(f"step {code}: expected errno {want}, got {got}", file=sys.stderr); sys.exit(code)
def sock(domain, ty):
    return lambda: socket.socket(domain, ty).close()
libc = ctypes.CDLL(None, use_errno=True)
def uring():
    if libc.syscall(425, 1, 0) == -1:
        raise OSError(ctypes.get_errno(), "io_uring_setup")
refused(sock(socket.AF_VSOCK, socket.SOCK_STREAM), errno.EAFNOSUPPORT, 16)
refused(sock(socket.AF_NETLINK, socket.SOCK_RAW), errno.EAFNOSUPPORT, 17)
refused(sock(socket.AF_PACKET, socket.SOCK_RAW), errno.EAFNOSUPPORT, 18)
refused(sock(socket.AF_INET, socket.SOCK_DGRAM), errno.EPERM, 19)
refused(sock(socket.AF_INET6, socket.SOCK_DGRAM), errno.EPERM, 20)
refused(sock(socket.AF_INET, socket.SOCK_RAW), errno.EPERM, 21)
refused(uring, errno.EPERM, 22)
ok(lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_NONBLOCK).close(), 23)
ok(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close(), 24)
ok(lambda: socket.socketpair().__getitem__(0).close(), 25)
def proto(domain, protocol):
    return lambda: socket.socket(domain, socket.SOCK_STREAM, protocol).close()
refused(proto(socket.AF_INET, 262), errno.EPERM, 27)
refused(proto(socket.AF_INET6, 262), errno.EPERM, 28)
ok(proto(socket.AF_INET, socket.IPPROTO_TCP), 29)
pid = os.fork()
if pid == 0:
    os._exit(0 if errno_of(sock(socket.AF_VSOCK, socket.SOCK_STREAM)) == errno.EAFNOSUPPORT else 1)
_, st = os.waitpid(pid, 0)
if st != 0:
    print("step 26: a forked child escaped the filter", file=sys.stderr); sys.exit(26)
sys.exit(0)
"#;

    pub fn run() {
        let bin = env!("CARGO_BIN_EXE_mediatore");
        // A private directory of this test's own, a random name, gone on drop.
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let allowed = root.join("allowed");
        let denied = root.join("denied");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&denied).unwrap();
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let b = TcpListener::bind("127.0.0.1:0").unwrap();
        let port_a = a.local_addr().unwrap().port();
        let port_b = b.local_addr().unwrap().port();

        let status = Command::new(bin)
            .args(["jail-exec", "--writable"])
            .arg(&allowed)
            .args([
                "--connect-port",
                &port_a.to_string(),
                "--",
                "python3",
                "-I",
                "-c",
                PROBE,
            ])
            .env("ALLOWED", &allowed)
            .env("DENIED", &denied)
            .env("PORT_A", port_a.to_string())
            .env("PORT_B", port_b.to_string())
            .status()
            .expect("spawn mediatore jail-exec");
        let code = status.code();
        assert_eq!(
            code,
            Some(0),
            "the probe failed at the step its exit code names (10 write allowed, 11 write denied, \
             12 connect allowed, 13 connect denied, 14 bind, 15 read, 16 to 18 families, 19 to 21 non-stream \
             inet sockets, 22 io_uring, 23 to 25 allowed sockets, 26 child inheritance, 27 and 28 an \
             MPTCP socket, 29 an explicit TCP one); 125 means confinement refused"
        );

        let refused = Command::new(bin)
            .args(["jail-exec", "--", "/bin/true"])
            .status()
            .expect("spawn mediatore jail-exec");
        assert_eq!(
            refused.code(),
            Some(125),
            "ADR-0024 decision 4: no port, refused with 125, nothing run"
        );
        drop((a, b));
    }
}

macro_rules! live {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[test]
        #[ignore = "needs root in a throwaway network and mount namespace, nsjail, nft and a Landlock kernel: see the module's doc"]
        fn $name() {
            #[cfg(not(target_os = "linux"))]
            panic!("this test runs a jail and needs Linux; it must not pass anywhere else");
            #[cfg(target_os = "linux")]
            tripwires::run(tripwires::$name());
        }
    };
}

live!(
    /// Under `shadow` every decoy port answers a connect from the jail and each is reported as `would_trip`; the
    /// jail goes on.
    every_drawn_port_trips_from_the_jail
);
live!(
    /// With no tripwire the jail's environment and home are what they always were, the table has no decoy, and
    /// nothing listens.
    nothing_is_open_under_off
);
live!(
    /// Under `enforce` a connect to a decoy port ends the run: the uid is cut, every process of it is gone, and the
    /// measured figure is in the report.
    after_a_trip_nothing_from_the_sandbox_uid_leaves_and_no_jail_process_remains
);
live!(
    /// The same with no broker to report to.
    containment_holds_with_the_broker_unreachable
);
live!(
    /// Reading every bait file and printing the environment is discovery: nothing trips, and no bait value is in
    /// the captured output.
    reading_the_bait_files_and_running_env_trips_nothing
);
live!(
    /// A loopback port that is neither the proxy's nor drawn is refused in the syscall by Landlock: no packet, no
    /// event, no trip, even with the `loopback_port` class switched to `trip` (ADR-0069 decision 10, amended).
    a_closed_loopback_port_is_refused_by_landlock_and_trips_nothing
);
live!(
    /// The workload cannot read the ports it may connect to from any command line, nor list the VM's loopback
    /// listeners.
    the_jail_cannot_read_its_connect_ports_or_list_the_listeners
);
live!(
    /// Where the metadata address is routed, a connect to it from the jail reaches the drawn loopback listener and
    /// trips as the `metadata` trap (ADR-0069 decision 13).
    the_metadata_address_trips_from_the_jail_where_it_is_routed
);
live!(
    /// ADR-0077: under `shadow` a connect from the jail to a chaff port, on loopback, at another routed address and
    /// over IPv6, is reported as `port` with the trap `chaff`; root's connection to the same port is untouched.
    a_connect_to_a_chaff_port_is_a_use_at_any_address
);
live!(
    /// ADR-0077: under `enforce` a probe of an admitted port at an address the decoys' redirect does not cover ends
    /// the run at its first chaff port, as the sweep of ADR-0069's R-83 would.
    a_probe_of_a_chaff_port_ends_the_run_under_enforce
);
live!(
    /// The per-process views of the network namespace (`/proc/self/net`, `/proc/<pid>/net`,
    /// `/proc/thread-self/net`) list no decoy port to the jail: `subset=pid` hides `/proc/net`, and these are
    /// the other doors to the same tables.
    the_jail_cannot_list_the_decoys_through_its_own_proc_net
);

#[cfg(target_os = "linux")]
mod tripwires {
    use std::collections::BTreeSet;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use mediatore_guest::arm::{self, Arming, Loaded};
    use mediatore_guest::egress::Phantom;
    use mediatore_guest::jail::JailSpec;
    use mediatore_guest::logs::{Capture, Queue};
    use mediatore_guest::net::{self, Ruleset, Shape};
    use mediatore_guest::sandboxfs;
    use mediatore_guest::supervise::{self, Outcome};
    use mediatore_guest::trip::{PostOutcome, TripSink};
    use mediatore_proto::RestartPolicy;
    use mediatore_proto::trip::{
        ClassAction, DeniedSwitches, TrapsMode, TrapsPolicy, TripClass, TripEvent, TripKind,
        TripMode, TripReport, TripTarget,
    };

    /// The proxy's port in these tests: nothing listens on it.
    const PROXY_PORT: u16 = 3128;
    const PULL_PORT: u16 = 18129;
    /// One jail at a time: the claim's table has one name.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    /// The stand-in for the egress proxy, run as the sandbox uid outside the jail: it takes the draw from the trap
    /// socket, answers `armed`, and stays.
    const PROXY_STAND_IN: &str = r#"
import socket, sys, time
if len(sys.argv) > 1:
    s = socket.socket(socket.AF_UNIX)
    s.connect(sys.argv[1])
    f = s.makefile('rwb', 0)
    f.readline()
    f.write(b'{"type":"armed","patterns":0}\n')
while True:
    time.sleep(3600)
"#;

    pub fn run(test: impl std::future::Future<Output = ()>) {
        // One jail at a time, whatever the harness was told about threads.
        let _one = ONE_AT_A_TIME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(test);
    }

    /// Where reports go: kept, or nowhere.
    #[derive(Default)]
    struct Broker {
        unreachable: bool,
        reports: Mutex<Vec<TripReport>>,
        attempts: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl TripSink for Broker {
        async fn post(&self, report: &TripReport) -> anyhow::Result<PostOutcome> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            anyhow::ensure!(!self.unreachable, "no broker");
            self.reports.lock().unwrap().push(report.clone());
            Ok(PostOutcome::Acknowledged)
        }
    }

    impl Broker {
        fn events(&self) -> Vec<TripEvent> {
            self.reports
                .lock()
                .unwrap()
                .iter()
                .flat_map(|r| r.events.clone())
                .collect()
        }
    }

    fn sh(program: &str, args: &[&str]) -> std::process::Output {
        std::process::Command::new(program)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("{program} is needed by this test and did not run: {e}"))
    }

    fn needs(program: &str, probe: &[&str]) {
        let out = sh(program, probe);
        assert!(
            out.status.success() || !out.stdout.is_empty() || !out.stderr.is_empty(),
            "{program} is needed by this test and is not usable"
        );
    }

    /// Copy `program` and every library `ldd` names for it into `rootfs`, each at its own path.
    fn install(rootfs: &Path, program: &Path, copy_program: bool) {
        let mut files: Vec<PathBuf> =
            String::from_utf8_lossy(&sh("ldd", &[program.to_str().expect("a path")]).stdout)
                .split_whitespace()
                .filter(|token| token.starts_with('/'))
                .map(PathBuf::from)
                .collect();
        if copy_program {
            files.push(program.to_owned());
        }
        for file in files {
            let to = rootfs.join(file.strip_prefix("/").expect("absolute"));
            std::fs::create_dir_all(to.parent().expect("a parent")).expect("mkdir in the rootfs");
            if !to.exists() {
                std::fs::copy(&file, &to).expect("copy into the rootfs");
            }
        }
    }

    /// One test's sandbox: a system user of its own, the claim's tmpfs with a small root filesystem (bash and a few
    /// tools from the host), and the checks that make running it safe.
    struct Live {
        root: PathBuf,
        socket_dir: PathBuf,
        user: String,
        uid: u32,
        gid: u32,
        rootfs: PathBuf,
        work: PathBuf,
    }

    impl Live {
        async fn start() -> Self {
            assert_eq!(
                std::fs::metadata("/proc/self").expect("procfs").uid(),
                0,
                "this test loads a table, mounts and runs a jail: it needs root"
            );
            for ns in ["net", "mnt"] {
                let own = std::fs::read_link(format!("/proc/self/ns/{ns}")).expect("own namespace");
                let init =
                    std::fs::read_link(format!("/proc/1/ns/{ns}")).expect("init's namespace");
                assert_ne!(
                    own, init,
                    "this test loads an nftables table, cuts a uid off and mounts: it never does that in the \
                     machine's own {ns} namespace. Run it under `unshare --net --mount` (see the module's doc)"
                );
            }
            let scratch = PathBuf::from(std::env::var("MEDIATORE_LIVE_ROOT").unwrap_or_else(|_| {
                panic!("set MEDIATORE_LIVE_ROOT to a scratch directory on a mount of this namespace")
            }));
            assert!(scratch.is_dir(), "MEDIATORE_LIVE_ROOT is not a directory");
            needs("nsjail", &["--help"]);
            needs("nft", &["--version"]);
            needs("python3", &["--version"]);
            needs("useradd", &["--help"]);
            // Loopback of this namespace, and nothing left of an earlier test in it.
            let _ = std::fs::remove_dir_all(scratch.join("trap"));
            assert!(
                sh("ip", &["link", "set", "lo", "up"]).status.success(),
                "lo up"
            );
            net::unload().await;
            let user = format!("sbt-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
            let made = sh(
                "useradd",
                &[
                    "--system",
                    "--user-group",
                    "--no-create-home",
                    "--home-dir",
                    "/nonexistent",
                    "--shell",
                    "/usr/sbin/nologin",
                    &user,
                ],
            );
            assert!(
                made.status.success(),
                "useradd failed for the test's own user"
            );
            let id = |flag: &str| -> u32 {
                String::from_utf8_lossy(&sh("id", &[flag, &user]).stdout)
                    .trim()
                    .parse()
                    .expect("an id")
            };
            let (uid, gid) = (id("-u"), id("-g"));
            assert!(uid != 0, "the test's user is not root");
            let root = scratch.join("sandbox");
            sandboxfs::Tmpfs {
                root: root.clone(),
                size: "256m".into(),
            }
            .mount()
            .await
            .expect("the claim's tmpfs");
            let layout = sandboxfs::prepare(&root, uid, gid).expect("the layout");
            // The image: bash, a few tools, and what the mediatore binary links against.
            for tool in [
                "bash", "cat", "env", "ls", "find", "sleep", "sort", "tr", "ss",
            ] {
                let host = Path::new("/usr/bin").join(tool);
                if host.exists() {
                    install(&layout.rootfs, &host, true);
                }
            }
            install(
                &layout.rootfs,
                Path::new(env!("CARGO_BIN_EXE_mediatore")),
                false,
            );
            for dir in ["work", "tmp", "home/sandbox", "proc", "dev", "etc"] {
                std::fs::create_dir_all(layout.rootfs.join(dir)).expect("mount points");
            }
            for file in ["dev/null", "dev/zero", "dev/urandom", "usr/bin/mediatore"] {
                std::fs::write(layout.rootfs.join(file), b"").expect("mount points");
            }
            Self {
                socket_dir: scratch.join("trap"),
                root,
                user,
                uid,
                gid,
                rootfs: layout.rootfs,
                work: layout.work,
            }
        }

        fn unarmed(&self) -> Ruleset {
            Ruleset {
                uid: self.uid,
                allow: BTreeSet::new(),
                dns: BTreeSet::new(),
                proxy_port: PROXY_PORT,
                shape: Shape::Direct,
                decoy_ports: BTreeSet::new(),
                metadata: false,
                trap_port: None,
                chaff_ports: BTreeSet::new(),
            }
        }

        /// The ruleset loaded and, with `mode`, the tripwire armed up to the proxy (the stand-in).
        async fn load(
            &self,
            mode: Option<TripMode>,
            denied: DeniedSwitches,
            broker: &Arc<Broker>,
        ) -> (Loaded, tokio::process::Child) {
            let policy = TrapsPolicy {
                mode: match mode {
                    Some(TripMode::Enforce) => TrapsMode::Enforce,
                    Some(TripMode::Shadow) => TrapsMode::Shadow,
                    None => TrapsMode::Off,
                },
                denied,
                ..TrapsPolicy::default()
            };
            let arming = mode.map(|mode| Arming {
                policy: &policy,
                mode,
                uid: self.uid,
                gid: self.gid,
                routes: &[],
                proxy_port: PROXY_PORT,
                pull_port: PULL_PORT,
                sandbox_root: &self.root,
                socket_dir: &self.socket_dir,
                sink: broker.clone(),
            });
            let mut loaded = arm::load(arming.as_ref(), self.unarmed())
                .await
                .expect("the ruleset loads and the tripwire arms");
            let (uid, gid) = (self.uid, self.gid);
            let proxy = loaded
                .start_proxy_through(|socket| async move {
                    let mut stand_in = tokio::process::Command::new("python3");
                    stand_in.args(["-I", "-c", PROXY_STAND_IN]);
                    if let Some(socket) = socket {
                        stand_in.arg(socket);
                    }
                    Ok(stand_in.uid(uid).gid(gid).kill_on_drop(true).spawn()?)
                })
                .await
                .expect("the stand-in proxy armed");
            assert_eq!(loaded.mode(), mode, "armed exactly when asked");
            (loaded, proxy)
        }

        /// Run `script` with bash in the jail until it ends, a trip ends it, or a minute passes; the outcome and
        /// every line of its output as captured (redacted, as it would be shipped).
        async fn jail(
            &self,
            loaded: &mut Loaded,
            proxy: &mut tokio::process::Child,
            script: &str,
        ) -> (Outcome, Vec<String>) {
            let spec = JailSpec {
                user: self.user.clone(),
                rootfs: self.rootfs.clone(),
                work: self.work.clone(),
                agent_binary: PathBuf::from(env!("CARGO_BIN_EXE_mediatore")),
                argv: vec!["/usr/bin/bash".into(), "-c".into(), script.to_owned()],
                rlimit_as_mib: 8192,
                proxy_port: PROXY_PORT,
                phantom: Phantom::generate().expect("a phantom"),
                traps: loaded.jail_traps(),
            };
            let queue = Arc::new(Queue::new(8 * 1024 * 1024, 1));
            let capture =
                Arc::new(Capture::new(spec.secret_values(), queue.clone()).without_console());
            let outcome = supervise::run(
                &spec,
                jiff::Timestamp::now() + jiff::SignedDuration::from_mins(1),
                proxy,
                RestartPolicy::Never,
                Some(&capture),
                loaded.tripped(),
            )
            .await
            .expect("the jail ran");
            let mut lines = Vec::new();
            loop {
                let batch = queue.take_batch(usize::MAX);
                if batch.records.is_empty() {
                    break;
                }
                lines.extend(batch.records.into_iter().map(|r| r.text));
            }
            (outcome, lines)
        }

        /// How many processes run as the sandbox uid. One that was killed and waits for its parent to collect it
        /// runs nothing and is not counted.
        fn processes(&self) -> usize {
            std::fs::read_dir("/proc")
                .expect("procfs")
                .flatten()
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.bytes().all(|b| b.is_ascii_digit()))
                        && entry.metadata().is_ok_and(|m| m.uid() == self.uid)
                        && std::fs::read_to_string(entry.path().join("status"))
                            .is_ok_and(|status| !status.contains("State:\tZ"))
                })
                .count()
        }

        /// Whether a TCP connect to `port` on loopback succeeds within a second, as the sandbox uid or as root.
        fn connects(&self, port: u16, as_sandbox: bool) -> bool {
            use std::os::unix::process::CommandExt as _;
            let mut probe = std::process::Command::new("python3");
            probe.args([
                "-I",
                "-c",
                "import socket,sys; socket.create_connection(('127.0.0.1', int(sys.argv[1])), 1)",
                &port.to_string(),
            ]);
            if as_sandbox {
                probe.uid(self.uid).gid(self.gid);
            }
            probe
                .stderr(std::process::Stdio::null())
                .status()
                .expect("python3")
                .success()
        }
    }

    impl Drop for Live {
        fn drop(&mut self) {
            // Whatever the test left: its processes, its table (in this throwaway namespace), its mount, its user.
            let _ = sh("pkill", &["-KILL", "-U", &self.uid.to_string()]);
            let _ = sh("nft", &["delete", "table", "inet", net::TABLE]);
            let _ = sh("umount", &["-l", self.root.to_str().unwrap_or_default()]);
            let _ = sh("userdel", &["--force", &self.user]);
        }
    }

    /// The decoy ports of the loaded ruleset.
    fn decoy_ports(loaded: &Loaded) -> Vec<u16> {
        loaded.ruleset.decoy_ports.iter().copied().collect()
    }

    fn port_list(ports: &[u16]) -> String {
        ports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// A table listing, for what it does and does not hold.
    fn table() -> String {
        String::from_utf8_lossy(&sh("nft", &["list", "table", "inet", net::TABLE]).stdout)
            .into_owned()
    }

    pub async fn every_drawn_port_trips_from_the_jail() {
        let live = Live::start().await;
        let broker = Arc::new(Broker::default());
        let (mut loaded, mut proxy) = live
            .load(Some(TripMode::Shadow), DeniedSwitches::default(), &broker)
            .await;
        let ports = decoy_ports(&loaded);
        assert!(ports.len() >= 2, "a draw has at least two decoy ports");
        // Each port: connect, read what the listener says first if anything, say so.
        let script = format!(
            "for p in {}; do if exec 3<>/dev/tcp/127.0.0.1/$p; then read -r -t 1 -u 3 line; echo \"connected $p\"; exec 3<&-; else echo \"refused $p\"; fi; done; echo done",
            port_list(&ports)
        );
        let (outcome, lines) = live.jail(&mut loaded, &mut proxy, &script).await;
        assert!(
            matches!(outcome, Outcome::WorkloadDone { status, .. } if status.success()),
            "under shadow the jail runs to its end"
        );
        for port in &ports {
            assert!(
                lines.iter().any(|l| *l == format!("connected {port}")),
                "a decoy port did not answer a connect from the jail"
            );
        }
        assert!(loaded.flush().await, "the events reached the broker");
        let events = broker.events();
        for port in &ports {
            assert!(
                events
                    .iter()
                    .any(|e| e.kind == TripKind::Port && e.target == Some(TripTarget::Port(*port))),
                "a decoy port's use was not reported"
            );
        }
        assert!(
            broker
                .reports
                .lock()
                .unwrap()
                .iter()
                .all(|r| r.mode == TripMode::Shadow),
            "reported as shadow: would_trip"
        );
        assert!(loaded.cause().is_none(), "nothing is ended under shadow");
        assert!(
            table().contains("decoys"),
            "the table is the armed one, not the cut"
        );
        // Root is refused the decoy ports by the table (the plan's D9): a use is the sandbox uid's by construction.
        assert!(!live.connects(ports[0], false), "root reached a decoy port");
        println!(
            "LIVE every_drawn_port_trips_from_the_jail: {} decoy ports, each answered and each reported as would_trip",
            ports.len()
        );
        drop(loaded);
        let _ = proxy.start_kill();
        supervise::teardown_after(&live.root, &live.user, false).await;
    }

    pub async fn nothing_is_open_under_off() {
        let live = Live::start().await;
        let broker = Arc::new(Broker::default());
        let (mut loaded, mut proxy) = live.load(None, DeniedSwitches::default(), &broker).await;
        assert!(!loaded.is_armed() && loaded.jail_traps().is_none());
        let script = "/usr/bin/env | /usr/bin/sort | while read -r l; do echo \"env ${l%%=*}\"; done; \
                      echo \"home $(/usr/bin/ls -A /home/sandbox | /usr/bin/tr -d '\\n')\"; echo done";
        let (outcome, lines) = live.jail(&mut loaded, &mut proxy, script).await;
        assert!(matches!(outcome, Outcome::WorkloadDone { status, .. } if status.success()));
        let mut variables: Vec<&str> = lines
            .iter()
            .filter_map(|l| l.strip_prefix("env "))
            // What bash itself sets.
            .filter(|v| !["PWD", "SHLVL", "_", "OLDPWD"].contains(v))
            .collect();
        variables.sort_unstable();
        assert_eq!(
            variables,
            ["HOME", "MEDIATORE_EGRESS_PROXY", "MEDIATORE_TOKEN"],
            "the three variables the jail always had, and nothing planted"
        );
        assert!(lines.iter().any(|l| l == "home "), "the home is empty");
        assert!(lines.iter().any(|l| l == "done"));
        let listing = table();
        assert!(
            !listing.contains("decoys") && !listing.contains("nat_out"),
            "no decoy in the table"
        );
        assert!(
            !listing.contains("chaff"),
            "no chaff in the table (ADR-0077)"
        );
        assert!(!live.root.join("home").exists(), "no home was planted");
        assert!(
            !live
                .socket_dir
                .join(mediatore_proto::trip::TRAP_SOCKET_NAME)
                .exists(),
            "no trap socket"
        );
        // Nothing listens in this namespace: no decoy, and the stand-in proxy listens on nothing.
        let listening = std::fs::read_to_string("/proc/net/tcp")
            .expect("this namespace's sockets")
            .lines()
            .skip(1)
            .filter(|l| l.split_whitespace().nth(3) == Some("0A"))
            .count();
        assert_eq!(listening, 0, "something listens under off");
        assert!(
            broker.events().is_empty()
                && broker.attempts.load(std::sync::atomic::Ordering::SeqCst) == 0
        );
        println!(
            "LIVE nothing_is_open_under_off: three variables, an empty home, no decoy set, no listener, no socket"
        );
        drop(loaded);
        let _ = proxy.start_kill();
        supervise::teardown_after(&live.root, &live.user, false).await;
    }

    /// The run a trip ends, with a broker or none: what both tests check.
    async fn contained(live: &Live, broker: &Arc<Broker>, name: &str) {
        let (mut loaded, mut proxy) = live
            .load(Some(TripMode::Enforce), DeniedSwitches::default(), broker)
            .await;
        let ports = decoy_ports(&loaded);
        // A listener of root's on loopback, to try afterwards.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let reachable = listener.local_addr().expect("addr").port();
        // The workload starts children of its own, takes a decoy, and would go on for ever.
        let script = format!(
            "/usr/bin/sleep 300 & /usr/bin/sleep 300 & echo started; exec 3<>/dev/tcp/127.0.0.1/{}; echo took-it; while true; do /usr/bin/sleep 1; echo alive; done",
            ports[0]
        );
        let started = Instant::now();
        let (outcome, lines) = live.jail(&mut loaded, &mut proxy, &script).await;
        let ended = started.elapsed();
        assert_eq!(outcome, Outcome::Tripped, "the trip ended the run");
        assert!(lines.iter().any(|l| l == "started"));
        let cause = loaded.cause().expect("the cause of the trip");
        assert_eq!(cause.kind, TripKind::Port);
        assert_eq!(cause.target, Some(TripTarget::Port(ports[0])));
        let killed_ms = jiff::Timestamp::now().duration_since(cause.at).as_millis();
        // No process of the sandbox uid is left: the jail, its children, the proxy (killed with the uid, and
        // collected here as the guest collects it).
        let _ = proxy.wait().await;
        assert_eq!(
            live.processes(),
            0,
            "a process of the sandbox uid survived the trip"
        );
        // The table is the cut: one rule, a drop of everything the uid sends.
        let listing = table();
        assert!(
            listing.contains(&format!("meta skuid {}", live.uid)) && listing.contains("drop"),
            "the cut is not loaded"
        );
        assert!(
            !listing.contains("decoys") && !listing.contains("accept\n"),
            "the cut still admits something"
        );
        // A new process of that uid reaches nothing, not even loopback; root still does.
        assert!(
            !live.connects(reachable, true),
            "the sandbox uid still has a network"
        );
        assert!(live.connects(reachable, false), "root's own path is cut");
        // The teardown keeps the cut and the user it is keyed on.
        supervise::teardown_after(&live.root, &live.user, true).await;
        assert!(
            table().contains(&format!("meta skuid {}", live.uid)),
            "the teardown removed the cut"
        );
        assert!(
            sh("id", &["-u", &live.user]).status.success(),
            "the teardown removed the user"
        );
        assert!(
            !live.connects(reachable, true),
            "the cut is gone after the teardown"
        );
        if broker.unreachable {
            // Nothing was acknowledged, and nothing waited on that.
            let waited = tokio::time::timeout(Duration::from_millis(500), loaded.reported()).await;
            assert!(waited.is_err(), "a report was acknowledged by no broker");
            assert!(
                broker.attempts.load(std::sync::atomic::Ordering::SeqCst) >= 1,
                "the guest did not try to report"
            );
            println!(
                "LIVE {name}: broker unreachable; cut and kill done {killed_ms} ms after the listener's verdict (jail ended {} ms after it started); {} report attempts so far, none acknowledged",
                ended.as_millis(),
                broker.attempts.load(std::sync::atomic::Ordering::SeqCst)
            );
        } else {
            tokio::time::timeout(Duration::from_secs(10), loaded.reported())
                .await
                .expect("the broker has the report");
            let events = broker.events();
            let event = events
                .iter()
                .find(|e| e.kind == TripKind::Port && e.containment_ms.is_some())
                .expect("the event that ended the run, with its figure");
            let containment = event.containment_ms.expect("a figure");
            assert!(containment < 5000, "the cut took longer than its bound");
            println!(
                "LIVE {name}: containment_ms={containment} (the listener's verdict to the end of the nft cut); every process of the uid gone {killed_ms} ms after the verdict"
            );
        }
    }

    pub async fn after_a_trip_nothing_from_the_sandbox_uid_leaves_and_no_jail_process_remains() {
        let live = Live::start().await;
        let broker = Arc::new(Broker::default());
        contained(
            &live,
            &broker,
            "after_a_trip_nothing_from_the_sandbox_uid_leaves_and_no_jail_process_remains",
        )
        .await;
    }

    pub async fn containment_holds_with_the_broker_unreachable() {
        let live = Live::start().await;
        let broker = Arc::new(Broker {
            unreachable: true,
            ..Broker::default()
        });
        contained(
            &live,
            &broker,
            "containment_holds_with_the_broker_unreachable",
        )
        .await;
    }

    pub async fn reading_the_bait_files_and_running_env_trips_nothing() {
        let live = Live::start().await;
        let broker = Arc::new(Broker::default());
        let (mut loaded, mut proxy) = live
            .load(Some(TripMode::Enforce), DeniedSwitches::default(), &broker)
            .await;
        // The planted home, from outside: the sandbox user's, 0700, every file 0600.
        let home = live.root.join("home");
        let stat = std::fs::metadata(&home).expect("the planted home");
        assert_eq!(
            (stat.mode() & 0o7777, stat.uid(), stat.gid()),
            (0o700, live.uid, live.gid)
        );
        let mut planted = 0;
        let mut dirs = vec![home.clone()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable by root").flatten() {
                let meta = entry.metadata().expect("stat");
                assert_eq!((meta.uid(), meta.gid()), (live.uid, live.gid));
                if meta.is_dir() {
                    assert_eq!(meta.mode() & 0o7777, 0o700);
                    dirs.push(entry.path());
                } else {
                    assert_eq!(meta.mode() & 0o7777, 0o600);
                    planted += 1;
                }
            }
        }
        let script = "/usr/bin/env; /usr/bin/find /home/sandbox -type f | while read -r f; do echo \"file $f\"; /usr/bin/cat \"$f\"; echo; done; \
                      /usr/bin/ls -laR /home/sandbox; echo kept > /home/sandbox/.written-by-the-workload; echo done";
        let (outcome, lines) = live.jail(&mut loaded, &mut proxy, script).await;
        assert!(
            matches!(outcome, Outcome::WorkloadDone { status, .. } if status.success()),
            "reading and listing ended nothing"
        );
        assert!(lines.iter().any(|l| l == "done"));
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.starts_with("file /home/sandbox/"))
                .count(),
            planted,
            "the workload read every planted file"
        );
        assert!(loaded.flush().await);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(loaded.cause().is_none(), "discovery tripped");
        assert!(broker.events().is_empty(), "discovery was reported");
        assert!(
            table().contains("decoys"),
            "the table is still the armed one"
        );
        // What the workload printed is what would be shipped: no bait value is in it (the plan's D14).
        let spec_secrets = JailSpec {
            user: live.user.clone(),
            rootfs: live.rootfs.clone(),
            work: live.work.clone(),
            agent_binary: PathBuf::from(env!("CARGO_BIN_EXE_mediatore")),
            argv: vec![],
            rlimit_as_mib: 0,
            proxy_port: PROXY_PORT,
            phantom: Phantom::generate().expect("a phantom"),
            traps: loaded.jail_traps(),
        }
        .secret_values();
        assert!(
            spec_secrets.len() >= 4,
            "the phantom and at least three bait values"
        );
        let output = lines.join("\n");
        for secret in spec_secrets.iter().skip(1) {
            assert!(
                !output.contains(secret.as_str()),
                "a bait value is in the captured output"
            );
        }
        assert!(output.contains("[REDACTED]"), "nothing was redacted");
        // The home is the claim's, not the jail run's: what the workload wrote is there afterwards.
        assert!(
            home.join(".written-by-the-workload").exists(),
            "the bound home did not keep a write"
        );
        println!(
            "LIVE reading_the_bait_files_and_running_env_trips_nothing: {planted} planted files read, env printed, nothing reported, no bait value in the captured output"
        );
        drop(loaded);
        let _ = proxy.start_kill();
        supervise::teardown_after(&live.root, &live.user, false).await;
    }

    pub async fn a_closed_loopback_port_is_refused_by_landlock_and_trips_nothing() {
        let live = Live::start().await;
        let broker = Arc::new(Broker::default());
        // Even with the class switched to `trip`: nothing of the connect reaches the chain.
        let denied = DeniedSwitches {
            loopback_port: ClassAction::Trip,
            ..DeniedSwitches::default()
        };
        let (mut loaded, mut proxy) = live.load(Some(TripMode::Enforce), denied, &broker).await;
        let drawn = decoy_ports(&loaded);
        let closed = (20_000..21_000u16)
            .find(|p| !drawn.contains(p) && *p != PROXY_PORT)
            .expect("a port that is neither the proxy's nor drawn");
        let script = format!(
            "if (exec 3<>/dev/tcp/127.0.0.1/{closed}) 2>/tmp/err; then echo connected; else echo \"refused: $(/usr/bin/cat /tmp/err)\"; fi; echo done"
        );
        let (outcome, lines) = live.jail(&mut loaded, &mut proxy, &script).await;
        assert!(matches!(outcome, Outcome::WorkloadDone { status, .. } if status.success()));
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("refused:") && l.contains("Permission denied")),
            "the connect was not refused in the syscall"
        );
        assert!(loaded.flush().await);
        // Longer than the reader's interval over the chain's drops: nothing was dropped to read.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            loaded.cause().is_none(),
            "a connect Landlock refused tripped"
        );
        assert!(
            !broker
                .events()
                .iter()
                .any(|e| e.class == Some(TripClass::LoopbackPort)),
            "a connect Landlock refused was seen by the chain"
        );
        println!(
            "LIVE a_closed_loopback_port_is_refused_by_landlock_and_trips_nothing: EACCES in the syscall, no loopback_port event, no trip with the class at trip"
        );
        drop(loaded);
        let _ = proxy.start_kill();
        supervise::teardown_after(&live.root, &live.user, false).await;
    }

    pub async fn the_jail_cannot_read_its_connect_ports_or_list_the_listeners() {
        let live = Live::start().await;
        let broker = Arc::new(Broker::default());
        let (mut loaded, mut proxy) = live
            .load(Some(TripMode::Shadow), DeniedSwitches::default(), &broker)
            .await;
        let ports = decoy_ports(&loaded);
        let script = "for f in /proc/[0-9]*/cmdline /proc/self/cmdline; do echo \"cmdline $f: $(/usr/bin/tr '\\0' ' ' < \"$f\" 2>&1)\"; done; \
                      echo \"proc: $(/usr/bin/ls /proc 2>&1 | /usr/bin/tr '\\n' ' ')\"; \
                      echo \"net-tcp: $(/usr/bin/cat /proc/net/tcp 2>&1)\"; \
                      if [ -x /usr/bin/ss ]; then echo \"ss: $(/usr/bin/ss -ltn 2>&1 | /usr/bin/tr '\\n' ' ')\"; else echo 'ss: absent'; fi; echo done";
        let (outcome, lines) = live.jail(&mut loaded, &mut proxy, script).await;
        assert!(matches!(outcome, Outcome::WorkloadDone { status, .. } if status.success()));
        let output = lines.join("\n");
        for line in &lines {
            println!("LIVE jail: {line}");
        }
        assert!(output.contains("done"));
        assert!(
            !output.contains("connect-port"),
            "jail-exec's arguments are readable in the jail"
        );
        assert!(
            !output.contains("jail-exec"),
            "the wrapper's command line is readable in the jail"
        );
        assert!(
            !output.contains("nsjail"),
            "nsjail's command line is readable in the jail"
        );
        for port in &ports {
            assert!(
                !output.contains(&port.to_string()),
                "a decoy port is named in what the jail can read"
            );
        }
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("net-tcp:") && l.contains("No such file")),
            "the jail has a /proc/net"
        );
        assert!(
            !lines
                .iter()
                .any(|l| l.starts_with("ss:") && l.contains("LISTEN")),
            "the jail listed the listeners"
        );
        // Nor a chaff port (ADR-0077), as a whole number anywhere in it.
        let chaff = chaff_ports(&loaded);
        let numbers: BTreeSet<&str> = output
            .split(|c: char| !c.is_ascii_digit())
            .filter(|n| !n.is_empty())
            .collect();
        for port in &chaff {
            assert!(
                !numbers.contains(port.to_string().as_str()),
                "a chaff port is named in what the jail can read"
            );
        }
        // And the line jail-exec writes on the workload's stderr names how many ports, never which: the proxy's,
        // the decoys, 80 with the metadata decoy, and the chaff.
        let admitted = 1 + ports.len() + usize::from(loaded.ruleset.metadata) + chaff.len();
        assert!(
            output.contains(&format!("connect_ports={admitted} ports")),
            "the confinement line is not the counted one"
        );
        println!(
            "LIVE the_jail_cannot_read_its_connect_ports_or_list_the_listeners: no command line with the ports, no /proc/net, no netlink listing"
        );
        drop(loaded);
        let _ = proxy.start_kill();
        supervise::teardown_after(&live.root, &live.user, false).await;
    }

    pub async fn the_jail_cannot_list_the_decoys_through_its_own_proc_net() {
        let live = Live::start().await;
        let broker = Arc::new(Broker::default());
        let (mut loaded, mut proxy) = live
            .load(Some(TripMode::Shadow), DeniedSwitches::default(), &broker)
            .await;
        let ports = decoy_ports(&loaded);
        assert!(ports.len() >= 2, "a draw has at least two decoy ports");
        // Every door to the namespace's socket tables a process has of its own: one line a table, the text or the
        // error, newlines made spaces.
        // Then every port a table lists as listening is tried from the jail: the trap listener's own port is not one
        // Landlock admits, and a connection made to it is no decoy's.
        let script = "for f in /proc/self/net/tcp /proc/self/net/tcp6 /proc/$$/net/tcp /proc/$$/net/tcp6 \
                      /proc/thread-self/net/tcp /proc/thread-self/net/tcp6 /proc/1/net/tcp; do \
                      echo \"table $f: $(/usr/bin/cat \"$f\" 2>&1 | /usr/bin/tr '\\n' ' ')\"; done; \
                      while read -r sl local rem st rest; do if [ \"$st\" = 0A ]; then p=$((16#${local##*:})); \
                      if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/tmp/err; then echo \"listed $p: connected\"; \
                      else echo \"listed $p: refused $(/usr/bin/cat /tmp/err)\"; fi; fi; done < /proc/self/net/tcp; echo done";
        let (outcome, lines) = live.jail(&mut loaded, &mut proxy, script).await;
        assert!(matches!(outcome, Outcome::WorkloadDone { status, .. } if status.success()));
        let tables: Vec<&String> = lines.iter().filter(|l| l.starts_with("table ")).collect();
        for line in &tables {
            println!("LIVE jail: {line}");
        }
        assert_eq!(tables.len(), 7, "every table was tried");
        for port in &ports {
            let hex = format!(":{port:04X} ");
            assert!(
                !tables.iter().any(|l| l.contains(&hex)),
                "a decoy port is listed by a table the jail can read"
            );
        }
        // What is listed is the one trap listener (the maintainer's decision 13 of 2026-11-27): one listening socket,
        // on a port that is no decoy, which the jail cannot connect to and whose listing gives no decoy away.
        let trap = loaded.ruleset.trap_port.expect("the trap listener's port");
        let listed: Vec<&String> = lines.iter().filter(|l| l.starts_with("listed ")).collect();
        for line in &listed {
            println!("LIVE jail: {line}");
        }
        assert_eq!(
            listed.len(),
            1,
            "one listening socket in the namespace: the trap listener"
        );
        assert!(
            listed[0].starts_with(&format!("listed {trap}: refused"))
                && listed[0].contains("Permission denied"),
            "the jail reached the trap listener's own port"
        );
        // Outside the jail, where Landlock does not stand, the table refuses a connection made to the trap listener's
        // port itself, to the sandbox uid (the proxy's) and to root alike: only a redirected decoy reaches it.
        assert!(
            !live.connects(trap, true),
            "the sandbox uid reached the trap listener directly"
        );
        assert!(
            !live.connects(trap, false),
            "root reached the trap listener directly"
        );
        assert!(loaded.flush().await);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            broker.events().is_empty(),
            "listing the tables, or trying what they list, was a use"
        );
        println!(
            "LIVE the_jail_cannot_list_the_decoys_through_its_own_proc_net: {} decoy ports, none listed by any per-process table; the one listed listener is the trap listener, refused to the jail by Landlock, nothing reported",
            ports.len()
        );
        drop(loaded);
        let _ = proxy.start_kill();
        supervise::teardown_after(&live.root, &live.user, false).await;
    }

    pub async fn the_metadata_address_trips_from_the_jail_where_it_is_routed() {
        let live = Live::start().await;
        // A route to the metadata address in this namespace: without one a connect fails before any hook.
        let routed = sh("ip", &["route", "add", "169.254.169.254/32", "dev", "lo"]);
        assert!(
            routed.status.success(),
            "the route could not be added in this namespace"
        );
        assert!(
            arm::metadata_is_routed(),
            "the guest does not see the route"
        );
        let broker = Arc::new(Broker::default());
        // The metadata decoy is drawn or not: arm until it is.
        let mut armed = None;
        for _ in 0..40 {
            let (loaded, mut proxy) = live
                .load(Some(TripMode::Enforce), DeniedSwitches::default(), &broker)
                .await;
            if loaded.ruleset.metadata {
                armed = Some((loaded, proxy));
                break;
            }
            drop(loaded);
            let _ = proxy.start_kill();
            let _ = proxy.wait().await;
            let _ = std::fs::remove_dir_all(live.root.join("home"));
        }
        let (mut loaded, mut proxy) =
            armed.expect("the metadata decoy was not drawn in forty draws");
        assert!(
            table().contains("nat_out"),
            "the redirect is not in the loaded table"
        );
        let script = "exec 3<>/dev/tcp/169.254.169.254/80; printf 'GET /latest/meta-data/ HTTP/1.0\\r\\n\\r\\n' >&3; echo asked; while true; do /usr/bin/sleep 1; done";
        let (outcome, _lines) = live.jail(&mut loaded, &mut proxy, script).await;
        assert_eq!(
            outcome,
            Outcome::Tripped,
            "the metadata address did not trip"
        );
        let cause = loaded.cause().expect("a cause");
        assert_eq!(cause.kind, TripKind::Port);
        assert_eq!(cause.trap.as_deref(), Some("metadata"));
        assert_eq!(
            cause.target,
            Some(TripTarget::Address(
                mediatore_proto::trip::METADATA_ADDRESS.to_owned()
            ))
        );
        let _ = proxy.wait().await;
        assert_eq!(
            live.processes(),
            0,
            "a process of the sandbox uid survived the trip"
        );
        println!(
            "LIVE the_metadata_address_trips_from_the_jail_where_it_is_routed: the redirect carried the jail's connect to the drawn listener; tripped as `metadata`"
        );
        supervise::teardown_after(&live.root, &live.user, true).await;
    }

    /// The chaff ports of the loaded ruleset.
    fn chaff_ports(loaded: &Loaded) -> Vec<u16> {
        loaded.ruleset.chaff_ports.iter().copied().collect()
    }

    /// An address of the documentation range, routed through loopback in this namespace so that a connect to it
    /// reaches the output hook (with no route it fails before any, ADR-0077's residual).
    const ROUTED_ELSEWHERE: &str = "192.0.2.10";

    fn route_elsewhere() {
        let routed = sh("ip", &["route", "replace", "192.0.2.0/24", "dev", "lo"]);
        assert!(
            routed.status.success(),
            "the route could not be added in this namespace"
        );
    }

    pub async fn a_connect_to_a_chaff_port_is_a_use_at_any_address() {
        let live = Live::start().await;
        route_elsewhere();
        let broker = Arc::new(Broker::default());
        let (mut loaded, mut proxy) = live
            .load(Some(TripMode::Shadow), DeniedSwitches::default(), &broker)
            .await;
        let chaff = chaff_ports(&loaded);
        assert!(
            (16..=32).contains(&chaff.len()),
            "{} chaff ports",
            chaff.len()
        );
        let listing = table();
        assert!(
            listing.contains("chaff_used"),
            "the chaff set is not in the loaded table"
        );
        // Three chaff ports, three ways: loopback, another routed address, IPv6 loopback. A dropped SYN leaves the
        // connect waiting, so each is a background connect, killed after a moment.
        let tried = [
            ("127.0.0.1", chaff[0]),
            (ROUTED_ELSEWHERE, chaff[1]),
            ("::1", chaff[2]),
        ];
        let mut script = String::new();
        for (address, port) in tried {
            use std::fmt::Write as _;
            let _ = write!(
                script,
                "(exec 3<>/dev/tcp/{address}/{port}) 2>/dev/null & pid=$!; /usr/bin/sleep 1; kill $pid 2>/dev/null; echo tried {port};"
            );
        }
        script.push_str(" echo done");
        let (outcome, lines) = live.jail(&mut loaded, &mut proxy, &script).await;
        assert!(
            matches!(outcome, Outcome::WorkloadDone { status, .. } if status.success()),
            "under shadow the jail runs to its end"
        );
        assert!(lines.iter().any(|l| l == "done"));
        // Longer than the reader's interval: every use was read.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(loaded.flush().await, "the events reached the broker");
        let events = broker.events();
        for (address, port) in tried {
            assert!(
                events.iter().any(|e| e.kind == TripKind::Port
                    && e.trap.as_deref() == Some("chaff")
                    && e.target == Some(TripTarget::Port(port))
                    && e.source == mediatore_proto::trip::TripSource::Drawn),
                "a chaff port tried at {address} was not reported"
            );
        }
        assert!(
            !events.iter().any(|e| e.kind == TripKind::Denied),
            "a chaff port was taken for a denied class"
        );
        assert!(loaded.cause().is_none(), "nothing is ended under shadow");
        // Root is untouched: a listener of root's on a chaff port is reached, and nothing is reported.
        let before = broker.events().len();
        let root_port = chaff[3];
        let listener =
            std::net::TcpListener::bind(("127.0.0.1", root_port)).expect("a free chaff port");
        assert!(
            live.connects(root_port, false),
            "root was refused a chaff port"
        );
        drop(listener);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(loaded.flush().await);
        assert_eq!(broker.events().len(), before, "root's connection was a use");
        println!(
            "LIVE a_connect_to_a_chaff_port_is_a_use_at_any_address: {} chaff ports; loopback, {ROUTED_ELSEWHERE} and ::1 each reported as port/chaff under shadow; root untouched",
            chaff.len()
        );
        drop(loaded);
        let _ = proxy.start_kill();
        supervise::teardown_after(&live.root, &live.user, false).await;
    }

    pub async fn a_probe_of_a_chaff_port_ends_the_run_under_enforce() {
        let live = Live::start().await;
        route_elsewhere();
        let broker = Arc::new(Broker::default());
        let (mut loaded, mut proxy) = live
            .load(Some(TripMode::Enforce), DeniedSwitches::default(), &broker)
            .await;
        let chaff = chaff_ports(&loaded);
        // The probe of R-83: an admitted port at an address the decoys' redirect does not cover. It would go on.
        let script = format!(
            "/usr/bin/sleep 300 & echo started; (exec 3<>/dev/tcp/{ROUTED_ELSEWHERE}/{}) 2>/dev/null & while true; do /usr/bin/sleep 1; echo alive; done",
            chaff[0]
        );
        let started = Instant::now();
        let (outcome, lines) = live.jail(&mut loaded, &mut proxy, &script).await;
        let ended = started.elapsed();
        assert_eq!(outcome, Outcome::Tripped, "the probe did not end the run");
        assert!(lines.iter().any(|l| l == "started"));
        let cause = loaded.cause().expect("the cause of the trip");
        assert_eq!(cause.kind, TripKind::Port);
        assert_eq!(cause.trap.as_deref(), Some("chaff"));
        assert_eq!(cause.target, Some(TripTarget::Port(chaff[0])));
        let killed_ms = jiff::Timestamp::now().duration_since(cause.at).as_millis();
        let _ = proxy.wait().await;
        assert_eq!(
            live.processes(),
            0,
            "a process of the sandbox uid survived the trip"
        );
        tokio::time::timeout(Duration::from_secs(10), loaded.reported())
            .await
            .expect("the broker has the report");
        let containment = broker
            .events()
            .iter()
            .find(|e| e.trap.as_deref() == Some("chaff") && e.containment_ms.is_some())
            .and_then(|e| e.containment_ms)
            .expect("the event that ended the run, with its figure");
        println!(
            "LIVE a_probe_of_a_chaff_port_ends_the_run_under_enforce: tripped as port/chaff; containment_ms={containment}; every process of the uid gone {killed_ms} ms after the reader's verdict; the run ended {} ms after it started",
            ended.as_millis()
        );
        supervise::teardown_after(&live.root, &live.user, true).await;
    }
}
