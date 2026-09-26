//! nsjail configuration for the workload.

use std::path::{Path, PathBuf};

/// Where the sandbox lives on the guest.
pub const SANDBOX_ROOT: &str = "/mnt/sandbox";

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
            "--mode".into(), "o".into(),
            "--user".into(), self.user.clone(),
            "--group".into(), self.user.clone(),
            "--chroot".into(), self.rootfs.display().to_string(),
            "--bindmount_ro".into(), format!("{}:/run/spire/agent.sock", self.workload_api_socket.display()),
            "--bindmount".into(), format!("{}:/work", self.work.display()),
            "--tmpfsmount".into(), "/tmp".into(),
            "--tmpfsmount".into(), "/home/sandbox".into(),
            "--disable_proc".into(),
            "--iface_no_lo=false".into(),
            "--rlimit_as".into(), self.rlimit_as_mib.to_string(),
            "--rlimit_nproc".into(), "512".into(),
            "--rlimit_fsize".into(), "4096".into(),
            "--time_limit".into(), "0".into(),
            "--env".into(), "HOME=/home/sandbox".into(),
            "--env".into(), "SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent.sock".into(),
            "--env".into(), format!("MEDIATORE_URL={}", self.mediatore_url),
            "--".into(),
        ];
        a.extend(self.argv.iter().cloned());
        a
    }

    /// Default layout under [`SANDBOX_ROOT`].
    #[must_use]
    pub fn default_paths(root: &Path) -> (PathBuf, PathBuf) {
        (root.join("rootfs"), root.join("work"))
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
            argv: vec!["/bin/sh".into(), "-c".into(), "id".into()],
            rlimit_as_mib: 8192,
        };
        let a = s.to_args();
        let sep = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(&a[sep + 1..], &["/bin/sh", "-c", "id"]);
        assert!(a.iter().any(|x| x == "--disable_proc"));
    }
}
