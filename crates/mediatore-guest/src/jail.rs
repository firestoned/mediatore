// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! nsjail configuration for the workload: the outer jail (ADR-0020, ADR-0021). What it execs
//! is the binary's `jail-exec` role, the inner layer (ADR-0024), then the workload.

use std::path::PathBuf;

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
    /// SPIRE Workload API socket on the host.
    pub workload_api_socket: PathBuf,
    /// mediatore sandbox-facing URL.
    pub mediatore_url: String,
    /// The one mediatore binary on the host (the pinned path, not `current_exe`), mounted
    /// read-only at [`JAIL_BINARY`] so the workload can run `mediatore token` (ADR-0014
    /// decision 4).
    pub agent_binary: PathBuf,
    /// Command to exec.
    pub argv: Vec<String>,
    /// Address-space limit in MiB.
    pub rlimit_as_mib: u64,
    /// TCP ports the workload may connect to: those of the broker and the claim's `egress`,
    /// the same destinations the ruleset resolved (ADR-0024 decision 2).
    pub connect_ports: Vec<u16>,
}

/// The connect ports of a ruleset's destinations, sorted and deduplicated: what `jail-exec`
/// is told, so the two layers cannot disagree.
#[must_use]
pub fn connect_ports<'a>(allow: impl IntoIterator<Item = &'a (std::net::IpAddr, u16)>) -> Vec<u16> {
    let mut ports: Vec<u16> = allow.into_iter().map(|(_, port)| *port).collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

impl JailSpec {
    /// Build the `nsjail` argument vector. Kept as data so it is testable and reviewable.
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
            format!(
                "{}:/run/spire/agent.sock",
                self.workload_api_socket.display()
            ),
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
            "SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent.sock".into(),
            "--env".into(),
            format!("MEDIATORE_URL={}", self.mediatore_url),
            "--".into(),
            // The inner layer (ADR-0024): the binary confines itself, then execs the argv.
            JAIL_BINARY.into(),
            "jail-exec".into(),
        ];
        for dir in WRITABLE_IN_JAIL {
            a.push("--writable".into());
            a.push(dir.into());
        }
        for port in &self.connect_ports {
            a.push("--connect-port".into());
            a.push(port.to_string());
        }
        a.push("--".into());
        a.extend(self.argv.iter().cloned());
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_end_with_command() {
        let s = JailSpec {
            user: "sb-abc".into(),
            rootfs: "/mnt/sandbox/rootfs".into(),
            work: "/mnt/sandbox/work".into(),
            workload_api_socket: "/run/spire/sockets/agent.sock".into(),
            mediatore_url: "https://mediatore.test".into(),
            agent_binary: "/usr/bin/mediatore".into(),
            argv: vec!["/bin/sh".into(), "-c".into(), "id".into()],
            rlimit_as_mib: 8192,
            connect_ports: vec![443],
        };
        let a = s.to_args();
        let sep = a.iter().rposition(|x| x == "--").unwrap();
        assert_eq!(&a[sep + 1..], &["/bin/sh", "-c", "id"]);
        assert!(a.iter().any(|x| x == "--disable_proc"));
    }

    #[test]
    fn nsjail_execs_jail_exec_with_the_writable_dirs_and_the_claims_ports_then_the_argv() {
        let s = JailSpec {
            user: "sb-abc".into(),
            rootfs: "/mnt/sandbox/rootfs".into(),
            work: "/mnt/sandbox/work".into(),
            workload_api_socket: "/run/spire/sockets/agent.sock".into(),
            mediatore_url: "https://mediatore.test".into(),
            agent_binary: "/usr/bin/mediatore".into(),
            argv: vec!["/bin/sh".into(), "-c".into(), "id".into()],
            rlimit_as_mib: 8192,
            connect_ports: vec![443, 8443],
        };
        let a = s.to_args();
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
                "443",
                "--connect-port",
                "8443",
                "--",
                "/bin/sh",
                "-c",
                "id"
            ],
            "ADR-0024 decision 1: the binary at the pinned path confines itself, then execs"
        );
    }

    #[test]
    fn the_connect_ports_are_the_rulesets_sorted_and_deduplicated() {
        use std::net::{IpAddr, Ipv4Addr};
        let allow = [
            (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 8443),
            (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)), 443),
            (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21)), 443),
        ];
        assert_eq!(connect_ports(allow.iter()), [443, 8443]);
    }

    #[test]
    fn the_jail_keeps_the_vms_network_namespace() {
        let s = JailSpec {
            user: "sb-abc".into(),
            rootfs: "/mnt/sandbox/rootfs".into(),
            work: "/mnt/sandbox/work".into(),
            workload_api_socket: "/run/spire/sockets/agent.sock".into(),
            mediatore_url: "https://mediatore.test".into(),
            agent_binary: "/usr/bin/mediatore".into(),
            argv: vec!["/bin/sh".into()],
            rlimit_as_mib: 8192,
            connect_ports: vec![443],
        };
        let a = s.to_args();
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
            user: "sb-abc".into(),
            rootfs: "/mnt/sandbox/rootfs".into(),
            work: "/mnt/sandbox/work".into(),
            workload_api_socket: "/run/spire/sockets/agent.sock".into(),
            mediatore_url: "https://mediatore.test".into(),
            agent_binary: "/opt/mediatore/bin/mediatore".into(),
            argv: vec!["/bin/sh".into()],
            rlimit_as_mib: 8192,
            connect_ports: vec![443],
        };
        let a = s.to_args();
        let ro: Vec<&str> = a
            .windows(2)
            .filter(|w| w[0] == "--bindmount_ro")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(
            ro,
            [
                "/run/spire/sockets/agent.sock:/run/spire/agent.sock",
                "/opt/mediatore/bin/mediatore:/usr/bin/mediatore",
            ]
        );
        let rw: Vec<&str> = a
            .windows(2)
            .filter(|w| w[0] == "--bindmount")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(rw, ["/mnt/sandbox/work:/work"]);
    }
}
