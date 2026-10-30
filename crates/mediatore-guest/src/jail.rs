// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! nsjail configuration for the workload: the outer jail (ADR-0020, ADR-0021). What it execs
//! is the binary's `jail-exec` role, the inner layer (ADR-0024), then the workload. The jail's
//! only route out is the egress proxy on loopback (ADR-0025): no Workload API socket, no
//! broker, a phantom token in the environment.

use std::path::PathBuf;

use crate::egress::{PHANTOM_ENV, PROXY_URL_ENV, Phantom};

/// Where the sandbox lives on the guest.
pub const SANDBOX_ROOT: &str = "/mnt/sandbox";

/// Default address-space limit for the workload, in MiB.
pub const DEFAULT_RLIMIT_AS_MIB: u64 = 8192;

/// Where the mediatore binary appears inside the jail: the same path as on the host.
pub const JAIL_BINARY: &str = mediatore_proto::AGENT_BINARY_PATH;

/// What the workload may write inside the jail, and nothing else (ADR-0024 decision 2):
/// its work dir, a tmpfs `/tmp` and a tmpfs home.
pub const WRITABLE_IN_JAIL: [&str; 3] = ["/work", "/tmp", "/home/sandbox"];

/// Inputs to the jail.
#[derive(Debug, Clone)]
pub struct JailSpec {
    /// Sandbox user (also the group).
    pub user: String,
    /// Unpacked rootfs.
    pub rootfs: PathBuf,
    /// Writable work dir bound at `/work`.
    pub work: PathBuf,
    /// The one mediatore binary on the host (the pinned path, not `current_exe`), mounted
    /// read-only at [`JAIL_BINARY`] so `nsjail` can exec its `jail-exec` role (ADR-0014
    /// decision 4, ADR-0024).
    pub agent_binary: PathBuf,
    /// Command to exec.
    pub argv: Vec<String>,
    /// Address-space limit in MiB.
    pub rlimit_as_mib: u64,
    /// The egress proxy's loopback port: the one TCP port the workload may connect to
    /// (ADR-0025 decision 5), named to it as `MEDIATORE_EGRESS_PROXY`.
    pub proxy_port: u16,
    /// The phantom token the workload presents to the proxy, handed over through `nsjail`'s
    /// environment and never its argument list (ADR-0025 decision 3).
    pub phantom: Phantom,
}

impl JailSpec {
    /// The proxy's base URL as the jail sees it.
    #[must_use]
    pub fn proxy_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.proxy_port)
    }

    /// Build the `nsjail` argument vector. Kept as data so it is testable and reviewable.
    /// The phantom is not in it: `--env MEDIATORE_TOKEN` without a value tells `nsjail` to
    /// copy the variable from its own environment, which [`Self::env`] provides.
    #[must_use]
    pub fn to_args(&self) -> Vec<String> {
        let mut a: Vec<String> = vec![
            "--mode".into(),
            "o".into(),
            "--user".into(),
            self.user.clone(),
            "--group".into(),
            self.user.clone(),
            "--chroot".into(),
            self.rootfs.display().to_string(),
            "--bindmount_ro".into(),
            format!("{}:{JAIL_BINARY}", self.agent_binary.display()),
            "--bindmount".into(),
            format!("{}:/work", self.work.display()),
            "--tmpfsmount".into(),
            "/tmp".into(),
            "--tmpfsmount".into(),
            "/home/sandbox".into(),
            "--disable_proc".into(),
            // The VM's network namespace, not a fresh one: the workload's sockets carry the
            // sb- uid, which the guest's nftables ruleset keys on (ADR-0020 decision 1).
            "--disable_clone_newnet".into(),
            "--rlimit_as".into(),
            self.rlimit_as_mib.to_string(),
            "--rlimit_nproc".into(),
            "512".into(),
            "--rlimit_fsize".into(),
            "4096".into(),
            "--time_limit".into(),
            "0".into(),
            "--env".into(),
            "HOME=/home/sandbox".into(),
            "--env".into(),
            format!("{PROXY_URL_ENV}={}", self.proxy_url()),
            "--env".into(),
            PHANTOM_ENV.into(),
            "--".into(),
            // The inner layer (ADR-0024): the binary confines itself, then execs the argv.
            JAIL_BINARY.into(),
            "jail-exec".into(),
        ];
        for dir in WRITABLE_IN_JAIL {
            a.push("--writable".into());
            a.push(dir.into());
        }
        a.push("--connect-port".into());
        a.push(self.proxy_port.to_string());
        a.push("--".into());
        a.extend(self.argv.iter().cloned());
        a
    }

    /// The environment `nsjail` itself runs with, for the variables it copies into the jail.
    #[must_use]
    pub fn env(&self) -> Vec<(String, String)> {
        vec![(PHANTOM_ENV.to_owned(), self.phantom.expose().to_owned())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phantom() -> Phantom {
        Phantom::parse("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap()
    }

    fn spec() -> JailSpec {
        JailSpec {
            user: "sb-abc".into(),
            rootfs: "/mnt/sandbox/rootfs".into(),
            work: "/mnt/sandbox/work".into(),
            agent_binary: "/usr/bin/mediatore".into(),
            argv: vec!["/bin/sh".into(), "-c".into(), "id".into()],
            rlimit_as_mib: 8192,
            proxy_port: 3128,
            phantom: phantom(),
        }
    }

    #[test]
    fn args_end_with_command() {
        let a = spec().to_args();
        let sep = a.iter().rposition(|x| x == "--").unwrap();
        assert_eq!(&a[sep + 1..], &["/bin/sh", "-c", "id"]);
        assert!(a.iter().any(|x| x == "--disable_proc"));
    }

    #[test]
    fn nsjail_execs_jail_exec_with_the_writable_dirs_the_proxy_port_then_the_argv() {
        let a = spec().to_args();
        let first = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(
            &a[first + 1..],
            &[
                "/usr/bin/mediatore",
                "jail-exec",
                "--writable",
                "/work",
                "--writable",
                "/tmp",
                "--writable",
                "/home/sandbox",
                "--connect-port",
                "3128",
                "--",
                "/bin/sh",
                "-c",
                "id"
            ],
            "ADR-0024 decision 1 and ADR-0025 decision 5: the binary confines itself to the proxy's port, then execs"
        );
    }

    #[test]
    fn the_jail_has_no_socket_and_no_broker_only_the_proxy_and_the_phantom() {
        let s = spec();
        let a = s.to_args();
        let envs: Vec<&str> = a
            .windows(2)
            .filter(|w| w[0] == "--env")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(
            envs,
            [
                "HOME=/home/sandbox",
                "MEDIATORE_EGRESS_PROXY=http://127.0.0.1:3128",
                "MEDIATORE_TOKEN",
            ],
            "the proxy's URL, and the phantom copied from nsjail's own environment"
        );
        assert!(
            !a.iter().any(|x| x.contains("agent.sock")
                || x.contains("MEDIATORE_URL")
                || x.contains("SPIFFE_ENDPOINT_SOCKET")),
            "ADR-0025 decision 5: no Workload API socket and no broker in the jail: {a:?}"
        );
        assert!(
            !a.iter().any(|x| x.contains(s.phantom.expose())),
            "ADR-0025 decision 3: the phantom is never on the command line"
        );
        assert_eq!(
            s.env(),
            [("MEDIATORE_TOKEN".to_owned(), s.phantom.expose().to_owned())]
        );
        assert_eq!(s.proxy_url(), "http://127.0.0.1:3128");
    }

    #[test]
    fn the_jail_keeps_the_vms_network_namespace() {
        let a = spec().to_args();
        assert!(
            a.iter().any(|x| x == "--disable_clone_newnet"),
            "ADR-0020: the sockets must be the sb- uid's in the VM's namespace"
        );
        assert!(
            !a.iter().any(|x| x.starts_with("--iface_no_lo")),
            "loopback setup belongs to a namespace the jail no longer has"
        );
    }

    #[test]
    fn the_agent_binary_is_mounted_read_only_and_nothing_else_is_writable_but_work() {
        let s = JailSpec {
            agent_binary: "/opt/mediatore/bin/mediatore".into(),
            ..spec()
        };
        let a = s.to_args();
        let ro: Vec<&str> = a
            .windows(2)
            .filter(|w| w[0] == "--bindmount_ro")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(
            ro,
            ["/opt/mediatore/bin/mediatore:/usr/bin/mediatore"],
            "the binary alone: the socket left the jail with ADR-0025"
        );
        let rw: Vec<&str> = a
            .windows(2)
            .filter(|w| w[0] == "--bindmount")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(rw, ["/mnt/sandbox/work:/work"]);
    }
}
