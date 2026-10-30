// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Jail supervision: run the workload until the claim's deadline, restart on crash,
//! tear everything down at the end.

use std::path::Path;

use chrono::{DateTime, Utc};

use crate::confine::EXIT_CONFINEMENT_REFUSED;
use crate::jail::JailSpec;
use crate::{net, sandboxfs, user};

/// Seconds to wait before restarting a crashed workload.
const RESTART_DELAY_SECS: u64 = 2;

/// What the supervisor does after the jail exits before the deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// The workload exited or crashed: start it again.
    Restart,
    /// `jail-exec` refused to confine the workload (ADR-0024 decision 4): the claim is
    /// over, nothing may run unconfined.
    Stop,
}

/// The decision for an exit status: only the confinement refusal stops the claim.
#[must_use]
pub fn after_exit(status: std::process::ExitStatus) -> Next {
    if status.code() == Some(EXIT_CONFINEMENT_REFUSED) {
        Next::Stop
    } else {
        Next::Restart
    }
}

/// Run `nsjail` with the spec's arguments until `expires_at`, restarting on exit.
///
/// Returns when the deadline passes; the running child is killed first. An error spawning
/// the jail is returned immediately: a sandbox that cannot start must not linger half-built.
pub async fn run(spec: &JailSpec, expires_at: DateTime<Utc>) -> anyhow::Result<()> {
    loop {
        let remaining = expires_at - Utc::now();
        let Ok(remaining) = remaining.to_std() else {
            tracing::info!("claim deadline reached");
            return Ok(());
        };

        let mut child = tokio::process::Command::new("nsjail")
            .args(spec.to_args())
            .spawn()?;
        tracing::info!(pid = child.id(), user = %spec.user, "jail started");

        tokio::select! {
            status = child.wait() => {
                let status = status?;
                match after_exit(status) {
                    Next::Stop => {
                        tracing::error!(%status, "the jail refused to confine the workload; not restarting");
                        anyhow::bail!("confinement refused (exit {EXIT_CONFINEMENT_REFUSED}): the workload did not run");
                    }
                    Next::Restart => {
                        tracing::warn!(%status, "workload exited before the deadline; restarting");
                        tokio::time::sleep(std::time::Duration::from_secs(RESTART_DELAY_SECS)).await;
                    }
                }
            }
            () = tokio::time::sleep(remaining) => {
                tracing::info!("claim deadline reached; stopping the jail");
                child.start_kill()?;
                let _ = child.wait().await;
                return Ok(());
            }
        }
    }
}

/// Best-effort teardown: drop the ruleset, unmount the sandbox tmpfs (ADR-0021), wipe
/// whatever is left under the root when there was no mount, and remove the user. Failures
/// are logged, never fatal; the VM is about to be destroyed anyway.
pub async fn teardown(sandbox_root: &Path, username: &str) {
    net::unload().await;
    match sandboxfs::is_mounted(sandbox_root) {
        Ok(true) => sandboxfs::unmount(sandbox_root).await,
        Ok(false) => {}
        Err(e) => tracing::warn!(error = %e, "could not read the mount table"),
    }
    if !sandboxfs::is_mounted(sandbox_root).unwrap_or(false) {
        for name in ["work", "layers", "rootfs"] {
            let dir = sandbox_root.join(name);
            if let Err(e) = tokio::fs::remove_dir_all(&dir).await
                && e.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(dir = %dir.display(), error = %e, "could not wipe sandbox dir");
            }
        }
    }
    if let Err(e) = user::remove(username).await {
        tracing::warn!(user = username, error = %e, "could not remove sandbox user");
    }
    tracing::info!(user = username, "teardown complete");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::ExitStatus;

    #[test]
    fn only_the_confinement_refusal_stops_the_claim() {
        assert_eq!(
            after_exit(ExitStatus::from_raw(EXIT_CONFINEMENT_REFUSED << 8)),
            Next::Stop
        );
        assert_eq!(after_exit(ExitStatus::from_raw(0)), Next::Restart);
        assert_eq!(after_exit(ExitStatus::from_raw(1 << 8)), Next::Restart);
        assert_eq!(after_exit(ExitStatus::from_raw(127 << 8)), Next::Restart);
        // Killed by a signal: no code at all, restarted.
        assert_eq!(after_exit(ExitStatus::from_raw(9)), Next::Restart);
    }
}
