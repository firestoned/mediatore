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
//! refused with exit 125 and runs nothing. Needs `python3` on the host.

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
import errno, os, socket, sys
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
sys.exit(0)
"#;

    pub fn run() {
        let bin = env!("CARGO_BIN_EXE_mediatore");
        let root =
            std::env::temp_dir().join(format!("mediatore-jail-exec-{}", uuid::Uuid::new_v4()));
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
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(
            code,
            Some(0),
            "the probe failed at the step its exit code names (10 write allowed, 11 write denied, \
             12 connect allowed, 13 connect denied, 14 bind, 15 read); 125 means confinement refused"
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
