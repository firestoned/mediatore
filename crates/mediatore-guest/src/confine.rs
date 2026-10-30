// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The inner layer of the jail (ADR-0024): `mediatore jail-exec`, what `nsjail` execs as
//! the sandbox user. It builds the workload's capability set from its arguments, applies
//! it to itself with Landlock through the `nono` library (irreversible, inherited by every
//! child) and execs the workload's argv. A refusal exits with
//! [`EXIT_CONFINEMENT_REFUSED`], which the supervisor treats as fatal for the claim, never
//! as a crash to restart.

use std::path::PathBuf;

/// Exit status of `jail-exec` when confinement cannot be applied (ADR-0024 decision 4).
pub const EXIT_CONFINEMENT_REFUSED: i32 = 125;

/// Exit status of `jail-exec` when the workload's argv cannot be executed after confinement.
/// The workload's own problem (a missing binary in its image): restarted like any early exit.
pub const EXIT_EXEC_FAILED: i32 = 127;

/// `mediatore jail-exec`: confine this process, then exec the argv after `--`.
#[derive(Debug, clap::Args)]
pub struct JailExecArgs {
    /// A directory the workload may write (repeatable); the rest of the tree is read-only.
    #[arg(long = "writable", value_name = "DIR")]
    pub writable: Vec<PathBuf>,
    /// A TCP port the workload may connect to (repeatable); nothing else, and no bind.
    #[arg(long = "connect-port", value_name = "PORT")]
    pub connect_ports: Vec<u16>,
    /// The workload's argv, after `--`.
    #[arg(last = true, required = true, value_name = "ARGV")]
    pub argv: Vec<String>,
}

/// What the workload may touch, as data (ADR-0024 decision 2). Pinned by unit tests on
/// every platform; applied on Linux only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Readable and executable: the jail's root, the image plus the mounts.
    pub readable_root: PathBuf,
    /// Readable and writable, sorted, deduplicated.
    pub writable: Vec<PathBuf>,
    /// TCP connect ports, sorted, deduplicated, never empty. There is no bind port.
    pub connect_ports: Vec<u16>,
}

/// Why a plan cannot be made from the arguments.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    /// The broker is always a destination, so an empty list means the jail was started wrong.
    #[error(
        "no connect port: the broker is always one, so the jail was started wrong; refusing to run the workload unconfined"
    )]
    NoPorts,
    /// A writable path given relative to nothing.
    #[error("a writable path must be absolute, got {0}")]
    RelativePath(String),
}

impl Plan {
    /// The plan for these arguments: the jail's root readable, the given directories
    /// writable, the given ports connectable.
    ///
    /// # Errors
    ///
    /// No port, or a relative writable path.
    pub fn from_args(args: &JailExecArgs) -> Result<Self, PlanError> {
        if args.connect_ports.is_empty() {
            return Err(PlanError::NoPorts);
        }
        let mut writable = Vec::new();
        for dir in &args.writable {
            if !dir.is_absolute() {
                return Err(PlanError::RelativePath(dir.display().to_string()));
            }
            writable.push(dir.clone());
        }
        writable.sort();
        writable.dedup();
        let mut connect_ports = args.connect_ports.clone();
        connect_ports.sort_unstable();
        connect_ports.dedup();
        Ok(Self {
            readable_root: PathBuf::from("/"),
            writable,
            connect_ports,
        })
    }
}

/// Why `jail-exec` did not run the workload. It never returns otherwise: on success the
/// process is the workload.
#[derive(Debug, thiserror::Error)]
pub enum JailExecError {
    /// The plan could not be made or applied: exit [`EXIT_CONFINEMENT_REFUSED`].
    #[error("confinement refused: {0:#}")]
    Refused(anyhow::Error),
    /// Confined, but the argv could not be executed: exit [`EXIT_EXEC_FAILED`].
    #[error("exec {argv0}: {source}")]
    Exec {
        /// What was to be executed.
        argv0: String,
        /// The kernel's answer.
        #[source]
        source: std::io::Error,
    },
}

impl JailExecError {
    /// The exit status this failure ends the process with.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Refused(_) => EXIT_CONFINEMENT_REFUSED,
            Self::Exec { .. } => EXIT_EXEC_FAILED,
        }
    }
}

/// The plan as nono capabilities: the root readable and executable, the writable
/// directories read-write, the ports connectable. No bind port is ever added, so Landlock
/// denies every TCP `bind()` once the set handles the network.
///
/// # Errors
///
/// A path that does not exist or cannot be canonicalised.
#[cfg(target_os = "linux")]
pub fn capability_set(plan: &Plan) -> anyhow::Result<nono::CapabilitySet> {
    use anyhow::Context as _;

    let mut caps = nono::CapabilitySet::new()
        .allow_path(&plan.readable_root, nono::AccessMode::Read)
        .with_context(|| format!("granting read on {}", plan.readable_root.display()))?;
    for dir in &plan.writable {
        caps = caps
            .allow_path(dir, nono::AccessMode::ReadWrite)
            .with_context(|| format!("granting write on {}", dir.display()))?;
    }
    for port in &plan.connect_ports {
        caps = caps.allow_tcp_connect(*port);
    }
    Ok(caps)
}

/// Confine this process with the plan, then exec the argv. Returns only on failure.
///
/// `apply_landlock` rather than `apply_auto`: a kernel whose Landlock cannot enforce the
/// network rules is a refusal, never a seccomp approximation (ADR-0024 decision 4).
#[cfg(target_os = "linux")]
pub fn run(args: &JailExecArgs) -> JailExecError {
    use std::os::unix::process::CommandExt as _;

    let plan = match Plan::from_args(args) {
        Ok(plan) => plan,
        Err(e) => return JailExecError::Refused(e.into()),
    };
    let caps = match capability_set(&plan) {
        Ok(caps) => caps,
        Err(e) => return JailExecError::Refused(e),
    };
    if let Err(e) = nono::Sandbox::apply_landlock(&caps) {
        return JailExecError::Refused(anyhow::anyhow!("{e}"));
    }
    tracing::info!(
        writable = ?plan.writable,
        connect_ports = ?plan.connect_ports,
        "confinement applied; exec"
    );
    let argv0 = args.argv[0].clone();
    let source = std::process::Command::new(&argv0)
        .args(&args.argv[1..])
        .exec();
    JailExecError::Exec { argv0, source }
}

/// Not Linux: no Landlock, no substitute, no workload (ADR-0024 decision 4).
#[cfg(not(target_os = "linux"))]
pub fn run(args: &JailExecArgs) -> JailExecError {
    let _ = args;
    JailExecError::Refused(anyhow::anyhow!(
        "jail-exec needs Linux: Landlock is the confinement and nothing stands in for it on {}",
        std::env::consts::OS
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(writable: &[&str], ports: &[u16]) -> JailExecArgs {
        JailExecArgs {
            writable: writable.iter().map(PathBuf::from).collect(),
            connect_ports: ports.to_vec(),
            argv: vec!["/bin/sh".into()],
        }
    }

    #[test]
    fn the_plan_reads_the_root_and_writes_only_what_it_was_told_sorted_and_deduplicated() {
        let plan =
            Plan::from_args(&args(&["/tmp", "/work", "/home/sandbox", "/work"], &[443])).unwrap();
        assert_eq!(plan.readable_root, PathBuf::from("/"));
        assert_eq!(
            plan.writable,
            [
                PathBuf::from("/home/sandbox"),
                PathBuf::from("/tmp"),
                PathBuf::from("/work")
            ]
        );
    }

    #[test]
    fn the_ports_are_sorted_deduplicated_and_never_empty() {
        let plan = Plan::from_args(&args(&["/work"], &[8443, 443, 443])).unwrap();
        assert_eq!(plan.connect_ports, [443, 8443]);
        assert_eq!(
            Plan::from_args(&args(&["/work"], &[])),
            Err(PlanError::NoPorts),
            "ADR-0024 decision 4: no port, no workload"
        );
    }

    #[test]
    fn a_relative_writable_path_is_refused() {
        assert_eq!(
            Plan::from_args(&args(&["work"], &[443])),
            Err(PlanError::RelativePath("work".into()))
        );
    }

    #[test]
    fn a_refusal_and_a_failed_exec_have_distinct_exit_codes() {
        let refused = JailExecError::Refused(anyhow::anyhow!("no landlock"));
        let exec = JailExecError::Exec {
            argv0: "/nope".into(),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        };
        assert_eq!(refused.exit_code(), EXIT_CONFINEMENT_REFUSED);
        assert_eq!(exec.exit_code(), EXIT_EXEC_FAILED);
        assert_ne!(EXIT_CONFINEMENT_REFUSED, EXIT_EXEC_FAILED);
        assert!(refused.to_string().contains("confinement refused"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn without_linux_the_role_refuses_instead_of_running_the_workload() {
        let err = run(&args(&["/tmp"], &[443]));
        assert_eq!(err.exit_code(), EXIT_CONFINEMENT_REFUSED, "{err}");
    }
}
