// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Jail supervision: run the workload until the claim's deadline, restart it as its
//! restart policy says (ADR-0033), end the claim when the egress proxy goes (ADR-0025),
//! tear everything down at the end. Killing `nsjail` is not the end of the workload (it is
//! pid 1 of the jail's PID namespace and can clear its parent-death signal), so wherever
//! the jail is killed every process of the sandbox uid is killed after it, and the
//! teardown removes the ruleset only once none is left.

use std::path::Path;
use std::sync::Arc;

use jiff::Timestamp;

use mediatore_proto::RestartPolicy;

use crate::confine::EXIT_CONFINEMENT_REFUSED;
use crate::jail::JailSpec;
use crate::logs::Capture;
use crate::{net, sandboxfs, user};

/// Seconds to wait before restarting a crashed workload.
const RESTART_DELAY_SECS: u64 = 2;

/// `nsjail`'s flag for warnings and above only, added under output capture (ADR-0045
/// decision 1) so its informational lines stay out of the workload's stderr records.
pub const NSJAIL_QUIET: &str = "--quiet";

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

/// What the teardown may remove, decided by whether a process of the sandbox uid is still
/// alive after the kill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cleanup {
    /// Nobody is left: the ruleset and the user go, as ADR-0020 decision 6 says.
    Everything,
    /// A process of the uid survived (or the process table could not be read): the ruleset
    /// stays loaded, so the survivor keeps its network bound, and the user stays, so its
    /// uid is not freed for another name. The VM is destroyed with the claim anyway.
    KeepRulesetAndUser,
}

impl Cleanup {
    /// Whether the uid-keyed table may be deleted.
    #[must_use]
    pub fn unloads_ruleset(self) -> bool {
        self == Self::Everything
    }

    /// Whether the sandbox user may be removed.
    #[must_use]
    pub fn removes_user(self) -> bool {
        self == Self::Everything
    }
}

/// The teardown's decision: survivors mean the ruleset and the user stay.
#[must_use]
pub fn cleanup_after(survivors: bool) -> Cleanup {
    if survivors {
        Cleanup::KeepRulesetAndUser
    } else {
        Cleanup::Everything
    }
}

/// Kill every process of the sandbox user except `spare` and wait for them to be gone
/// (`user::kill_all`); whether any is left. Not knowing (no uid for the name, a process
/// table that cannot be read) counts as survivors: the teardown fails closed on it. Logs
/// the count alone, never a command line or an environment.
async fn kill_sandbox_processes(username: &str, spare: Option<u32>) -> bool {
    let uid = match user::uid(username).await {
        Ok(uid) => uid,
        Err(e) => {
            tracing::error!(user = username, error = %e, "no uid for the sandbox user; its processes cannot be told apart, assuming some are alive");
            return true;
        }
    };
    match user::kill_all(uid, spare).await {
        Ok(0) => false,
        Ok(survivors) => {
            tracing::error!(
                user = username,
                uid,
                survivors,
                "processes of the sandbox user are still alive after SIGKILL"
            );
            true
        }
        Err(e) => {
            tracing::error!(user = username, uid, error = %e, "could not look for the sandbox user's processes, assuming some are alive");
            true
        }
    }
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
/// With `capture` (the claim opted in, ADR-0045 decision 1) the jail's stdout and stderr are
/// pipes the capture's readers drain, redact, tee to the console and queue; the readers are
/// drained to EOF after every exit before the next step. Without it the jail inherits the
/// guest's stdio, as before.
///
/// Returns when the deadline passes (the running jail killed first, then every other
/// process of the sandbox user but the proxy, which is the caller's to kill once the output
/// is flushed) or when the policy ends the claim on an exit. An error spawning the
/// jail is returned immediately: a sandbox that cannot start must not linger half-built.
/// The proxy exiting is an error too.
pub async fn run(
    spec: &JailSpec,
    expires_at: Timestamp,
    proxy: &mut tokio::process::Child,
    policy: RestartPolicy,
    capture: Option<&Arc<Capture>>,
) -> anyhow::Result<Outcome> {
    let mut restarts: u32 = 0;
    loop {
        let remaining = expires_at.duration_since(Timestamp::now());
        let Ok(remaining) = std::time::Duration::try_from(remaining) else {
            tracing::info!("claim deadline reached");
            return Ok(Outcome::Deadline);
        };

        let mut command = tokio::process::Command::new("nsjail");
        command.args(spec.to_args()).envs(spec.env());
        if capture.is_some() {
            // nsjail writes its own diagnostics to its stderr, which under capture is the
            // workload's stderr pipe: `--quiet` keeps its informational lines (the mounts,
            // the pid) out of the owner's stream; its warnings and fatal messages (a
            // refused mount, a confinement failure) still reach it, which is wanted.
            command
                .arg(NSJAIL_QUIET)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
        }
        let mut child = command.spawn()?;
        let readers = match capture {
            Some(c) => Some(c.attach(&mut child)?),
            None => None,
        };
        tracing::info!(pid = child.id(), user = %spec.user, logs = capture.is_some(), "jail started");

        let event = tokio::select! {
            status = child.wait() => Event::JailExited(status?),
            status = proxy.wait() => {
                let status = status?;
                child.start_kill()?;
                let _ = child.wait().await;
                // The proxy is reaped: `id()` is `None`, nobody is spared.
                kill_sandbox_processes(&spec.user, proxy.id()).await;
                Event::ProxyExited(status)
            }
            () = tokio::time::sleep(remaining) => {
                tracing::info!("claim deadline reached; stopping the jail");
                child.start_kill()?;
                let _ = child.wait().await;
                // Before the drain: a survivor holds the pipes open. The proxy is spared
                // here and stopped by the caller; the teardown looks again without it.
                kill_sandbox_processes(&spec.user, proxy.id()).await;
                if let Some(r) = readers {
                    r.drain().await;
                }
                return Ok(Outcome::Deadline);
            }
        };
        // The pipes close with the jail; what is left in them is queued before anything
        // else happens (ADR-0045 decision 8: the end of the output matters most).
        if let Some(r) = readers {
            r.drain().await;
        }
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

/// Best-effort teardown: kill whatever still runs as the sandbox user (the caller has
/// stopped the egress proxy by now, so nothing is spared), drop the ruleset, unmount the
/// sandbox tmpfs (ADR-0021), wipe whatever is left under the root when there was no mount,
/// and remove the user. With a survivor the ruleset and the user stay ([`cleanup_after`]);
/// the unmount is still tried, lazily. Failures are logged, never fatal; the VM is about to
/// be destroyed anyway.
pub async fn teardown(sandbox_root: &Path, username: &str) {
    let cleanup = cleanup_after(kill_sandbox_processes(username, None).await);
    if cleanup.unloads_ruleset() {
        net::unload().await;
    } else {
        tracing::error!(
            user = username,
            "the sandbox ruleset stays loaded and the user stays: a process of the uid may still be alive"
        );
    }
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
    if cleanup.removes_user()
        && let Err(e) = user::remove(username).await
    {
        tracing::warn!(user = username, error = %e, "could not remove sandbox user");
    }
    tracing::info!(user = username, ?cleanup, "teardown complete");
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
    fn survivors_mean_the_ruleset_and_the_user_stay() {
        let kept = cleanup_after(true);
        assert_eq!(kept, Cleanup::KeepRulesetAndUser);
        assert!(
            !kept.unloads_ruleset(),
            "a live process of the uid keeps its network bound"
        );
        assert!(!kept.removes_user(), "a uid in use is not freed");
    }

    #[test]
    fn with_nobody_left_the_teardown_removes_everything() {
        let all = cleanup_after(false);
        assert_eq!(all, Cleanup::Everything);
        assert!(all.unloads_ruleset() && all.removes_user());
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
