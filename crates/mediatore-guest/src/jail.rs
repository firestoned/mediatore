// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! nsjail configuration for the workload.

use std::path::PathBuf;

/// Where the sandbox lives on the guest.
pub const SANDBOX_ROOT: &str = "/mnt/sandbox";

/// Default address-space limit for the workload, in MiB.
pub const DEFAULT_RLIMIT_AS_MIB: u64 = 8192;

/// Where the mediatore binary appears inside the jail: the same path as on the host.
pub const JAIL_BINARY: &str = mediatore_proto::AGENT_BINARY_PATH;

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
        ];
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
            agent_binary: "/usr/local/bin/mediatore".into(),
            argv: vec!["/bin/sh".into(), "-c".into(), "id".into()],
            rlimit_as_mib: 8192,
        };
        let a = s.to_args();
        let sep = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(&a[sep + 1..], &["/bin/sh", "-c", "id"]);
        assert!(a.iter().any(|x| x == "--disable_proc"));
    }

    #[test]
    fn the_jail_keeps_the_vms_network_namespace() {
        let s = JailSpec {
            user: "sb-abc".into(),
            rootfs: "/mnt/sandbox/rootfs".into(),
            work: "/mnt/sandbox/work".into(),
            workload_api_socket: "/run/spire/sockets/agent.sock".into(),
            mediatore_url: "https://mediatore.test".into(),
            agent_binary: "/usr/local/bin/mediatore".into(),
            argv: vec!["/bin/sh".into()],
            rlimit_as_mib: 8192,
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
                "/opt/mediatore/bin/mediatore:/usr/local/bin/mediatore",
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
