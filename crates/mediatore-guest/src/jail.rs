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
/// The only device nodes the jail has, bind-mounted from the VM: a sink, zeros and the
/// kernel's random source. The image's root has no device nodes (ADR-0021), and tools expect
/// these three: `git` fails with `could not open '/dev/null'` without the first. Nothing
/// else under `/dev` is there, and no `/dev` tree.
pub const DEVICES_IN_JAIL: [&str; 3] = ["/dev/null", "/dev/zero", "/dev/urandom"];
/// The one device the workload may also write (Landlock grants it as a single file, not a
/// directory): the sink. `/dev/zero` and `/dev/urandom` are read-only to it, like the rest.
pub const WRITABLE_FILES_IN_JAIL: [&str; 1] = ["/dev/null"];
/// The jail's `/proc` (ADR-0036): a procfs showing nothing but the process directories
/// (`subset=pid`), and of those only the ones the workload may ptrace (`hidepid=invisible`).
/// nsjail's `--mount` carries filesystem options, not mount flags: writes are denied by the
/// inner layer's Landlock set, which grants read on `/` and write on the three directories.
pub const JAIL_PROC_MOUNT: &str = "none:/proc:proc:subset=pid,hidepid=invisible";

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
        ];
        // Read-only mounts: the flag covers files, directories and symlinks, not device nodes,
        // so `/dev/null` still opens for writing, and the one read-write mount stays `/work`.
        for dev in DEVICES_IN_JAIL {
            a.push("--bindmount_ro".into());
            a.push(format!("{dev}:{dev}"));
        }
        a.extend([
            // nsjail's own full `/proc` stays off; the one the workload gets shows the
            // jail's processes alone (ADR-0036). Landlock makes it read-only (decision 2).
            "--disable_proc".into(),
            "--mount".into(),
            JAIL_PROC_MOUNT.into(),
            // The VM's network namespace, not a fresh one: the workload's sockets carry the
            // sb- uid, which the guest's nftables ruleset keys on (ADR-0020 decision 1).
            "--disable_clone_newnet".into(),
            // And no user namespace: nsjail's default maps the jail's uid to the invoker's,
            // so the workload would be global root, outside everything keyed on the sb-
            // uid (the ruleset, the unix attestor, the proxy's gate); and its read-only
            // remount of the mount tree fails inside a user namespace under a systemd
            // /run. The jail's uid is the global one (ADR-0020 decision 1, amended).
            "--disable_clone_newuser".into(),
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
        ]);
        for dir in WRITABLE_IN_JAIL {
            a.push("--writable".into());
            a.push(dir.into());
        }
        for file in WRITABLE_FILES_IN_JAIL {
            a.push("--writable-file".into());
            a.push(file.into());
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

    /// Every environment value the guest places in the jail that bears a credential, for the
    /// output redactor's literal set (ADR-0045 decision 2): today the phantom alone. A new
    /// credential-bearing variable is added here in the same change that adds it to
    /// [`Self::env`]; the unit test fails otherwise.
    #[must_use]
    pub fn secret_values(&self) -> Vec<String> {
        vec![self.phantom.expose().to_owned()]
    }
}

/// An environment key that bears a credential, by its name: redaction must know its value.
#[must_use]
pub fn is_credential_key(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    key == PHANTOM_ENV
        || k.contains("TOKEN")
        || k.contains("SECRET")
        || k.contains("PASSWORD")
        || k.contains("KEY")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_credential_bearing_environment_value_is_in_the_redaction_set() {
        // ADR-0045 decision 2: a credential placed in the jail that the redactor does not
        // know would leave the VM in the output. The phantom is the one there is today.
        let spec = spec();
        let secrets = spec.secret_values();
        assert_ne!(secrets.len(), 0);
        for (key, value) in spec.env() {
            if is_credential_key(&key) {
                assert!(
                    secrets.contains(&value),
                    "{key} bears a credential but its value is not in secret_values()"
                );
            }
        }
        assert!(secrets.contains(&phantom().expose().to_owned()));
        assert!(is_credential_key(PHANTOM_ENV));
        assert!(is_credential_key("AWS_SECRET_ACCESS_KEY"));
        assert!(is_credential_key("db_password"));
        assert!(!is_credential_key("HOME"));
        assert!(!is_credential_key(PROXY_URL_ENV));
    }

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
    fn proc_is_mounted_with_the_jails_own_processes_only() {
        let a = spec().to_args();
        let mounts: Vec<&str> = a
            .windows(2)
            .filter(|w| w[0] == "--mount")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(
            mounts,
            ["none:/proc:proc:subset=pid,hidepid=invisible"],
            "one procfs, the process directories alone (ADR-0036)"
        );
        assert!(
            a.iter().any(|x| x == "--disable_proc"),
            "nsjail's own full /proc stays off"
        );
        assert!(
            !a.iter().any(|x| x == "/dev" || x.ends_with(":/dev")),
            "no /dev tree: only the three device nodes below"
        );
    }

    #[test]
    fn the_jail_has_exactly_three_device_nodes_and_may_write_only_the_sink() {
        let a = spec().to_args();
        let binds: Vec<&str> = a
            .windows(2)
            .filter(|w| w[0] == "--bindmount_ro")
            .map(|w| w[1].as_str())
            .collect();
        assert!(binds.contains(&"/dev/null:/dev/null"));
        assert!(binds.contains(&"/dev/zero:/dev/zero"));
        assert!(binds.contains(&"/dev/urandom:/dev/urandom"));
        let devs: Vec<&&str> = binds.iter().filter(|b| b.contains("/dev/")).collect();
        assert_eq!(devs.len(), 3, "no other device: {binds:?}");
        assert!(
            a.windows(2)
                .filter(|w| w[0] == "--bindmount_ro" || w[0] == "--bindmount")
                .all(|w| !w[1].starts_with("/dev/tty") && !w[1].starts_with("/dev/mem")),
            "no terminal, no kernel memory"
        );
        let writable_files: Vec<&str> = a
            .windows(2)
            .filter(|w| w[0] == "--writable-file")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(writable_files, ["/dev/null"], "Landlock grants one file");
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
                "--writable-file",
                "/dev/null",
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
    fn the_jail_has_no_user_namespace_so_its_uid_is_the_global_sandbox_uid() {
        let a = spec().to_args();
        assert!(
            a.iter().any(|x| x == "--disable_clone_newuser"),
            "ADR-0020 decision 1 (amended): nsjail's user namespace maps the jail's uid to the \
             invoker's, root, and the ruleset, the attestor and the proxy's gate key on the \
             global uid: {a:?}"
        );
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
        let ro_files: Vec<&&str> = ro.iter().filter(|m| !m.starts_with("/dev/")).collect();
        assert_eq!(
            ro_files,
            [&"/opt/mediatore/bin/mediatore:/usr/bin/mediatore"],
            "the binary alone, beside the three device nodes: the socket left the jail with ADR-0025"
        );
        let rw: Vec<&str> = a
            .windows(2)
            .filter(|w| w[0] == "--bindmount")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(rw, ["/mnt/sandbox/work:/work"]);
    }
}
