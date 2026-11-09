// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Jail supervision: run the workload until the claim's deadline, restart it as its
//! restart policy says (ADR-0033), end the claim when the egress proxy goes (ADR-0025),
//! tear everything down at the end.

use std::path::Path;

use chrono::{DateTime, Utc};

use mediatore_proto::RestartPolicy;

use crate::confine::EXIT_CONFINEMENT_REFUSED;
use crate::jail::JailSpec;
use crate::{net, sandboxfs, user};

/// Seconds to wait before restarting a crashed workload.
const RESTART_DELAY_SECS: u64 = 2;

/// What the supervisor does after the jail exits before the deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// The workload exited or crashed and its policy says so: start it again.
    Restart,
    /// `jail-exec` refused to confine the workload (ADR-0024 decision 4), or the egress
    /// proxy is gone (ADR-0025 decision 1): the claim is over, nothing may run unconfined
    /// or with no way out.
    Stop,
    /// The workload is done by its restart policy (ADR-0033 decision 1): the claim ends,
    /// and the broker is told how it ended.
    Done,
}

/// How a round of supervision ended, for the guest to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The deadline passed; the jail was killed.
    Deadline,
    /// The workload exited and its restart policy ended the claim: the status, and how
    /// many times it had been restarted before (ADR-0033 decision 2).
    WorkloadDone {
        /// The last exit.
        status: std::process::ExitStatus,
        /// Restarts before it.
        restarts: u32,
    },
}

/// What ended a round of supervision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The jail exited with this status.
    JailExited(std::process::ExitStatus),
    /// The egress proxy exited with this status.
    ProxyExited(std::process::ExitStatus),
}

/// The decision for an exit status of the jail under `policy` (ADR-0033 decision 1): the
/// confinement refusal stops the claim whatever the policy; otherwise `always` restarts,
/// `on-failure` restarts a non-zero exit and is done on `0`, `never` is done on any exit.
#[must_use]
pub fn after_exit(status: std::process::ExitStatus, policy: RestartPolicy) -> Next {
    if status.code() == Some(EXIT_CONFINEMENT_REFUSED) {
        return Next::Stop;
    }
    match policy {
        RestartPolicy::Never => Next::Done,
        RestartPolicy::OnFailure if status.success() => Next::Done,
        RestartPolicy::Always | RestartPolicy::OnFailure => Next::Restart,
    }
}

/// The decision for an event: the jail's as [`after_exit`]; the proxy's exit, whatever its
/// status, stops the claim (the proxy is the guest's own code and the jail's only route out).
#[must_use]
pub fn after_event(event: Event, policy: RestartPolicy) -> Next {
    match event {
        Event::JailExited(status) => after_exit(status, policy),
        Event::ProxyExited(_) => Next::Stop,
    }
}

/// Run `nsjail` with the spec's arguments until `expires_at`, restarting on exit as
/// `policy` says, with the egress proxy `proxy` watched beside it.
///
/// Returns when the deadline passes (the running jail killed first; the proxy is the
/// caller's to kill) or when the policy ends the claim on an exit. An error spawning the
/// jail is returned immediately: a sandbox that cannot start must not linger half-built.
/// The proxy exiting is an error too.
pub async fn run(
    spec: &JailSpec,
    expires_at: DateTime<Utc>,
    proxy: &mut tokio::process::Child,
    policy: RestartPolicy,
) -> anyhow::Result<Outcome> {
    let mut restarts: u32 = 0;
    loop {
        let remaining = expires_at - Utc::now();
        let Ok(remaining) = remaining.to_std() else {
            tracing::info!("claim deadline reached");
            return Ok(Outcome::Deadline);
        };

        let mut child = tokio::process::Command::new("nsjail")
            .args(spec.to_args())
            .envs(spec.env())
            .spawn()?;
        tracing::info!(pid = child.id(), user = %spec.user, "jail started");

        let event = tokio::select! {
            status = child.wait() => Event::JailExited(status?),
            status = proxy.wait() => {
                let status = status?;
                child.start_kill()?;
                let _ = child.wait().await;
                Event::ProxyExited(status)
            }
            () = tokio::time::sleep(remaining) => {
                tracing::info!("claim deadline reached; stopping the jail");
                child.start_kill()?;
                let _ = child.wait().await;
                return Ok(Outcome::Deadline);
            }
        };
        match (event, after_event(event, policy)) {
            (Event::ProxyExited(status), _) => {
                tracing::error!(%status, "the egress proxy exited; the jail has no way out, not restarting");
                anyhow::bail!("egress proxy exited ({status}): the claim ends");
            }
            (Event::JailExited(status), Next::Stop) => {
                tracing::error!(%status, "the jail refused to confine the workload; not restarting");
                anyhow::bail!(
                    "confinement refused (exit {EXIT_CONFINEMENT_REFUSED}): the workload did not run"
                );
            }
            (Event::JailExited(status), Next::Done) => {
                tracing::info!(%status, %policy, restarts, "workload exited and its restart policy ends the claim (ADR-0033)");
                return Ok(Outcome::WorkloadDone { status, restarts });
            }
            (Event::JailExited(status), Next::Restart) => {
                restarts = restarts.saturating_add(1);
                tracing::warn!(%status, %policy, restarts, "workload exited before the deadline; restarting");
                tokio::time::sleep(std::time::Duration::from_secs(RESTART_DELAY_SECS)).await;
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
        for name in ["work", "layers", "rootfs", "egress"] {
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
        for policy in [
            RestartPolicy::Always,
            RestartPolicy::OnFailure,
            RestartPolicy::Never,
        ] {
            assert_eq!(
                after_exit(ExitStatus::from_raw(EXIT_CONFINEMENT_REFUSED << 8), policy),
                Next::Stop,
                "{policy}: nothing runs unconfined"
            );
        }
        let always = RestartPolicy::Always;
        assert_eq!(after_exit(ExitStatus::from_raw(0), always), Next::Restart);
        assert_eq!(
            after_exit(ExitStatus::from_raw(1 << 8), always),
            Next::Restart
        );
        assert_eq!(
            after_exit(ExitStatus::from_raw(127 << 8), always),
            Next::Restart
        );
        // Killed by a signal: no code at all, restarted.
        assert_eq!(after_exit(ExitStatus::from_raw(9), always), Next::Restart);
    }

    #[test]
    fn the_restart_policy_decides_what_an_exit_means() {
        // on-failure: the agent that runs once and may be retried (ADR-0033 decision 1).
        let on_failure = RestartPolicy::OnFailure;
        assert_eq!(after_exit(ExitStatus::from_raw(0), on_failure), Next::Done);
        assert_eq!(
            after_exit(ExitStatus::from_raw(1 << 8), on_failure),
            Next::Restart
        );
        assert_eq!(
            after_exit(ExitStatus::from_raw(9), on_failure),
            Next::Restart
        );
        // never: any exit is the end.
        let never = RestartPolicy::Never;
        assert_eq!(after_exit(ExitStatus::from_raw(0), never), Next::Done);
        assert_eq!(after_exit(ExitStatus::from_raw(1 << 8), never), Next::Done);
        assert_eq!(after_exit(ExitStatus::from_raw(9), never), Next::Done);
    }

    #[test]
    fn the_proxy_going_away_stops_the_claim_whatever_its_status() {
        for raw in [0, 1 << 8, 9, EXIT_CONFINEMENT_REFUSED << 8] {
            assert_eq!(
                after_event(
                    Event::ProxyExited(ExitStatus::from_raw(raw)),
                    RestartPolicy::Never
                ),
                Next::Stop,
                "ADR-0025 decision 1: no proxy, no way out, no workload"
            );
        }
        assert_eq!(
            after_event(
                Event::JailExited(ExitStatus::from_raw(1 << 8)),
                RestartPolicy::Always
            ),
            Next::Restart
        );
        assert_eq!(
            after_event(
                Event::JailExited(ExitStatus::from_raw(EXIT_CONFINEMENT_REFUSED << 8)),
                RestartPolicy::Always
            ),
            Next::Stop
        );
    }
}
