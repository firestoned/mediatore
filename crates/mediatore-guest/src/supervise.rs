// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Jail supervision: run the workload until the claim's deadline, restart it as its
//! restart policy says (ADR-0033), end the claim when the egress proxy goes (ADR-0025) or
//! when a trap is used (ADR-0069 decision 7), tear everything down at the end. Killing `nsjail` is not the end of the workload (it is
//! pid 1 of the jail's PID namespace and can clear its parent-death signal), so wherever
//! the jail is killed every process of the sandbox uid is killed after it, and the
//! teardown removes the ruleset only once none is left.

use std::path::Path;
use std::sync::Arc;

use jiff::Timestamp;
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncRead, BufReader};

use mediatore_proto::{LogStream, RestartPolicy};

use crate::confine::EXIT_CONFINEMENT_REFUSED;
use crate::jail::JailSpec;
use crate::logs::{
    CONSOLE_PREFIX, Capture, DRAIN_TIMEOUT, RAW_LINE_CAP, Readers, neutralise_controls,
};
use crate::{net, sandboxfs, user};

/// Seconds to wait before restarting a crashed workload.
const RESTART_DELAY_SECS: u64 = 2;

/// `nsjail`'s flag for warnings and above only, added under output capture (ADR-0045
/// decision 1) so its informational lines stay out of the workload's stderr records.
pub const NSJAIL_QUIET: &str = "--quiet";

/// The jail's output when the claim did not opt into capture (`workload.logs` off): the
/// guest still owns both pipes, so nothing the workload writes reaches the guest's own
/// stdout or stderr (the unit's journal stream) as the workload wrote it. Each line goes to
/// the console as the capture's console copy does (ADR-0045 decision 9, amended
/// 2026-11-19): control characters written out as text, [`CONSOLE_PREFIX`] in front.
/// Nothing is queued, shipped or redacted here.
///
/// Read `reader` to EOF and hand each line, ready for the console (prefix, neutralised
/// text, one newline), to `write`. A last line without its newline counts. A line over
/// [`RAW_LINE_CAP`] is written in pieces of at most that, each a console line of its own,
/// so a workload writing without newlines cannot grow the guest's memory; a char split by
/// a cut waits for its other bytes.
async fn relay_stream<R, W>(reader: R, mut write: W)
where
    R: AsyncRead + Unpin,
    W: FnMut(&str),
{
    let mut reader = BufReader::new(reader);
    // At most `RAW_LINE_CAP` bytes of the line being read; after a cut, the bytes (0 to 3) of
    // the char it split.
    let mut raw: Vec<u8> = Vec::new();
    loop {
        let read = match read_line_capped(&mut reader, &mut raw, RAW_LINE_CAP).await {
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(error = %e, "output pipe closed with an error");
                0
            }
        };
        if read == 0 {
            // The pipe closed: what is buffered is the end of a line with no newline.
            if !raw.is_empty() {
                write(&console_copy(&raw));
            }
            return;
        }
        if raw.last() == Some(&b'\n') {
            raw.pop();
            if raw.last() == Some(&b'\r') {
                raw.pop();
            }
            write(&console_copy(&raw));
            raw.clear();
        } else if raw.len() >= RAW_LINE_CAP {
            // Cut before its end: the piece is written, the split char's bytes stay.
            let whole = raw.len() - split_char_suffix(&raw);
            write(&console_copy(&raw[..whole]));
            raw.drain(..whole);
        }
        // Otherwise the read stopped short of both the newline and the cap (it does at
        // EOF): the next read says which.
    }
}

/// The console line for the raw bytes of one workload line: lossy UTF-8, control characters
/// neutralised ([`neutralise_controls`]), behind [`CONSOLE_PREFIX`], one newline at the end.
/// The same text `logs.rs` writes for a captured line (its `console_line` is private).
fn console_copy(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    format!("{CONSOLE_PREFIX}{}\n", neutralise_controls(&text))
}

/// How many bytes at the end of `bytes` are the start of a UTF-8 char whose other bytes
/// have not been read yet: 0 to 3.
fn split_char_suffix(bytes: &[u8]) -> usize {
    (1..=bytes.len().min(3))
        .find(|back| {
            matches!(
                std::str::from_utf8(&bytes[bytes.len() - back..]),
                Err(e) if e.valid_up_to() == 0 && e.error_len().is_none()
            )
        })
        .unwrap_or(0)
}

/// Read up to and including the next `\n`, or until `buf` holds `cap` bytes, or EOF; the
/// bytes read. (`logs.rs` has the same reader, private to it.)
async fn read_line_capped<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    cap: usize,
) -> std::io::Result<usize> {
    let mut total = 0;
    loop {
        let avail = reader.fill_buf().await?;
        if avail.is_empty() {
            return Ok(total);
        }
        let room = cap.saturating_sub(buf.len());
        let newline = avail.iter().position(|b| *b == b'\n');
        let take = match newline {
            Some(i) if i < room => i + 1,
            _ => room.min(avail.len()),
        };
        buf.extend_from_slice(&avail[..take]);
        reader.consume(take);
        total += take;
        if buf.last() == Some(&b'\n') || buf.len() >= cap {
            return Ok(total);
        }
    }
}

/// One console line to the guest's stdout or stderr, in one write, as the capture's tee.
fn write_console(stream: LogStream, line: &str) {
    use std::io::Write as _;

    let _ = match stream {
        LogStream::Stdout => std::io::stdout().lock().write_all(line.as_bytes()),
        LogStream::Stderr => std::io::stderr().lock().write_all(line.as_bytes()),
    };
}

/// Who reads the jail's two pipes: the capture's readers, or the relay to the console.
enum Output {
    /// The claim opted in (ADR-0045): redact, tee, queue.
    Captured(Readers),
    /// It did not: neutralise, prefix, write to the console, keep nothing.
    Relayed(Vec<tokio::task::JoinHandle<()>>),
}

impl Output {
    /// Take the child's piped stdout and stderr and relay both until EOF.
    fn relay(child: &mut tokio::process::Child) -> anyhow::Result<Self> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("the jail's stdout is not a pipe"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("the jail's stderr is not a pipe"))?;
        Ok(Self::Relayed(vec![
            tokio::spawn(relay_stream(stdout, |line: &str| {
                write_console(LogStream::Stdout, line);
            })),
            tokio::spawn(relay_stream(stderr, |line: &str| {
                write_console(LogStream::Stderr, line);
            })),
        ]))
    }

    /// Wait for the pipes to close, bounded by [`DRAIN_TIMEOUT`] on either path.
    async fn drain(self) {
        match self {
            Self::Captured(readers) => readers.drain().await,
            Self::Relayed(tasks) => {
                let all = async {
                    for handle in tasks {
                        let _ = handle.await;
                    }
                };
                if tokio::time::timeout(DRAIN_TIMEOUT, all).await.is_err() {
                    tracing::warn!(
                        "the workload's output pipes did not close in time; the tail may be lost"
                    );
                }
            }
        }
    }
}

/// `nsjail`'s argument list for `spec`. Under capture [`NSJAIL_QUIET`] comes first: nsjail
/// writes its own diagnostics to its stderr, which is the workload's stderr pipe, and the
/// flag keeps its informational lines (the mounts, the pid) out of the owner's stream while
/// its warnings and fatal messages still reach it. It must precede the spec's arguments,
/// which end in `--` and the workload's argv: anything after that is the workload's, not
/// nsjail's. Without capture the informational lines stay, on the console behind the prefix.
fn nsjail_args(spec: &JailSpec, quiet: bool) -> Vec<String> {
    let mut args = Vec::new();
    if quiet {
        args.push(NSJAIL_QUIET.to_owned());
    }
    args.extend(spec.to_args());
    args
}

/// Spawn `nsjail` for the spec with both of its output streams as pipes, always (the jail
/// never inherits the guest's stdout or stderr), and start whoever reads them.
fn spawn_jail(
    spec: &JailSpec,
    capture: Option<&Arc<Capture>>,
) -> anyhow::Result<(tokio::process::Child, Output)> {
    let mut command = tokio::process::Command::new("nsjail");
    command
        .args(nsjail_args(spec, capture.is_some()))
        .envs(spec.env())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn()?;
    let output = match capture {
        Some(c) => Output::Captured(c.attach(&mut child)?),
        None => Output::relay(&mut child)?,
    };
    Ok((child, output))
}

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
    /// A trap was used (ADR-0069 decision 7): the jail and every process of the sandbox user
    /// were killed, the egress proxy with them, and nothing is restarted whatever the policy.
    Tripped,
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

/// The teardown's decision after a run a trip may have ended (ADR-0069 decision 7): after a
/// trip the table is the cut, a drop of everything the sandbox uid sends, and deleting it
/// would remove the cut, so it stays, and the user with it, survivors or none.
#[must_use]
pub fn cleanup_for(survivors: bool, tripped: bool) -> Cleanup {
    if tripped {
        Cleanup::KeepRulesetAndUser
    } else {
        cleanup_after(survivors)
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

/// Wait for the first trip. Never resolves without a tripwire.
///
/// # Errors
/// The tripwire is gone while the run it guards goes on: every handle to it was dropped.
async fn tripped(
    trip: &mut Option<&mut tokio::sync::watch::Receiver<Option<crate::trip::Cause>>>,
) -> anyhow::Result<()> {
    match trip {
        None => std::future::pending().await,
        Some(rx) => rx
            .wait_for(Option::is_some)
            .await
            .map(|_| ())
            .map_err(|_| anyhow::anyhow!("the tripwire is gone: the run is no longer guarded")),
    }
}

/// Run `nsjail` with the spec's arguments until `expires_at`, restarting on exit as
/// `policy` says, with the egress proxy `proxy` watched beside it.
///
/// The jail's stdout and stderr are always pipes. With `capture` (the claim opted in,
/// ADR-0045 decision 1) the capture's readers drain, redact, tee to the console and queue
/// them; without it the guest relays each line to its own console, neutralised and prefixed
/// (`relay_stream`), and keeps nothing. Either way the readers are drained to EOF after
/// every exit before the next step.
///
/// Returns when the deadline passes (the running jail killed first, then every other
/// process of the sandbox user but the proxy, which is the caller's to kill once the output
/// is flushed) or when the policy ends the claim on an exit. An error spawning the
/// jail is returned immediately: a sandbox that cannot start must not linger half-built.
/// The proxy exiting is an error too.
///
/// With `trip` (the claim's tripwire, ADR-0069 decision 7) the first cause on it ends the
/// run with [`Outcome::Tripped`]: the jail is killed, then every process of the sandbox
/// user, the proxy included, and nothing is restarted whatever the policy. The trip is
/// looked at before anything else, so a proxy that died with the uid is never read as the
/// proxy failing. A jail is never started after a trip.
pub async fn run(
    spec: &JailSpec,
    expires_at: Timestamp,
    proxy: &mut tokio::process::Child,
    policy: RestartPolicy,
    capture: Option<&Arc<Capture>>,
    trip: Option<&mut tokio::sync::watch::Receiver<Option<crate::trip::Cause>>>,
) -> anyhow::Result<Outcome> {
    supervise(
        || {
            let (child, output) = spawn_jail(spec, capture)?;
            tracing::info!(pid = child.id(), user = %spec.user, logs = capture.is_some(), "jail started");
            Ok((child, output))
        },
        |spare| kill_sandbox_processes(&spec.user, spare),
        expires_at,
        proxy,
        policy,
        trip,
    )
    .await
}

/// [`run`] over whatever starts the jail (`start`) and whatever kills every process of the
/// sandbox user but the one spared (`kill_user`).
async fn supervise<S, K, F>(
    mut start: S,
    kill_user: K,
    expires_at: Timestamp,
    proxy: &mut tokio::process::Child,
    policy: RestartPolicy,
    mut trip: Option<&mut tokio::sync::watch::Receiver<Option<crate::trip::Cause>>>,
) -> anyhow::Result<Outcome>
where
    S: FnMut() -> anyhow::Result<(tokio::process::Child, Output)>,
    K: Fn(Option<u32>) -> F,
    F: std::future::Future<Output = bool>,
{
    let mut restarts: u32 = 0;
    loop {
        let remaining = expires_at.duration_since(Timestamp::now());
        let Ok(remaining) = std::time::Duration::try_from(remaining) else {
            tracing::info!("claim deadline reached");
            return Ok(Outcome::Deadline);
        };
        // ADR-0069 decision 7: no jail starts after a trip. Whatever of the sandbox user is
        // still alive (the proxy) is killed here, as the trip arm below does.
        if trip.as_ref().is_some_and(|rx| rx.borrow().is_some()) {
            tracing::error!("a trap was used before the jail started; it is not started");
            kill_user(None).await;
            return Ok(Outcome::Tripped);
        }

        let (mut child, output) = start()?;

        // One round: the trip (when armed), the jail's exit, the proxy's exit, the deadline.
        // With a tripwire the trip is looked at first (`biased`); without one the round is the
        // select it was before ADR-0069, with no fixed order (a NIT of the review: `off` is
        // what it was).
        macro_rules! round {
            ($($biased:tt)*) => {
                tokio::select! {
                    $($biased)*
                    // The trip kills the proxy with the uid, and that exit must not be read as
                    // the proxy failing (and an exit of the jail in the same instant must not
                    // restart it).
                    guarded = tripped(&mut trip) => {
                        tracing::error!("a trap was used; killing the jail and every process of the sandbox user (ADR-0069 decision 7)");
                        // An error here is a jail that has already exited: the uid's kill
                        // follows either way.
                        let _ = child.start_kill();
                        let _ = child.wait().await;
                        // Nobody is spared: the proxy is the workload's way out and goes too.
                        kill_user(None).await;
                        output.drain().await;
                        guarded?;
                        return Ok(Outcome::Tripped);
                    }
                    status = child.wait() => Event::JailExited(status?),
                    status = proxy.wait() => {
                        let status = status?;
                        child.start_kill()?;
                        let _ = child.wait().await;
                        // The proxy is reaped: `id()` is `None`, nobody is spared.
                        kill_user(proxy.id()).await;
                        Event::ProxyExited(status)
                    }
                    () = tokio::time::sleep(remaining) => {
                        tracing::info!("claim deadline reached; stopping the jail");
                        child.start_kill()?;
                        let _ = child.wait().await;
                        // Before the drain: a survivor holds the pipes open. The proxy is
                        // spared here and stopped by the caller; the teardown looks again
                        // without it.
                        kill_user(proxy.id()).await;
                        output.drain().await;
                        return Ok(Outcome::Deadline);
                    }
                }
            };
        }
        let event = if trip.is_some() {
            round!(biased;)
        } else {
            round!()
        };
        // The pipes close with the jail; what is left in them is queued (or written to the
        // console) before anything else happens (ADR-0045 decision 8: the end of the output
        // matters most).
        output.drain().await;
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
                // A trip during the wait is seen at the top of the loop, before any jail.
                tokio::select! {
                    biased;
                    guarded = tripped(&mut trip) => guarded?,
                    () = tokio::time::sleep(std::time::Duration::from_secs(RESTART_DELAY_SECS)) => {}
                }
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
    teardown_after(sandbox_root, username, false).await;
}

/// [`teardown`] for a run a trip may have ended (ADR-0069 decision 7). With `tripped` the
/// table stays, whoever is left: it is the cut, and deleting it would give the sandbox uid
/// its network back ([`cleanup_for`]). The user stays with it, so the uid the cut is keyed
/// on is not freed for another name. Everything else is torn down as ever.
pub async fn teardown_after(sandbox_root: &Path, username: &str, tripped: bool) {
    let survivors = kill_sandbox_processes(username, None).await;
    let cleanup = cleanup_for(survivors, tripped);
    if cleanup.unloads_ruleset() {
        net::unload().await;
    } else if tripped {
        tracing::warn!(
            user = username,
            survivors,
            "the sandbox table stays loaded and the user stays: after a trip the table is the cut (ADR-0069 decision 7)"
        );
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
        for name in ["work", "layers", "rootfs", "egress", "home"] {
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
    tracing::info!(user = username, ?cleanup, tripped, "teardown complete");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::ExitStatus;

    #[test]
    fn quiet_is_nsjails_flag_and_never_one_of_the_workloads_arguments() {
        let spec = JailSpec {
            user: "sb-abc".into(),
            rootfs: "/mnt/sandbox/rootfs".into(),
            work: "/mnt/sandbox/work".into(),
            agent_binary: "/usr/bin/mediatore".into(),
            argv: vec!["/bin/sh".into(), "-c".into(), "id".into()],
            rlimit_as_mib: 8192,
            proxy_port: 3128,
            phantom: crate::egress::Phantom::parse(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            )
            .unwrap(),
            traps: None,
        };
        let quiet = nsjail_args(&spec, true);
        let flag = quiet.iter().position(|a| a == NSJAIL_QUIET);
        let separator = quiet.iter().position(|a| a == "--");
        assert_eq!(flag, Some(0), "the flag is nsjail's first argument");
        assert!(flag < separator, "and comes before the command");
        assert_eq!(quiet[1..], spec.to_args()[..], "the rest is the spec's");
        assert_eq!(quiet.last().map(String::as_str), Some("id"));
        assert_eq!(nsjail_args(&spec, false), spec.to_args());
    }

    /// What the relay writes for `input`, one entry per console line.
    async fn relayed(input: &[u8]) -> Vec<String> {
        let mut lines = Vec::new();
        relay_stream(input, |line: &str| lines.push(line.to_owned())).await;
        lines
    }

    /// The workload's part of a console line: no prefix, no final newline.
    fn payload(line: &str) -> &str {
        line.strip_prefix(CONSOLE_PREFIX)
            .and_then(|l| l.strip_suffix('\n'))
            .expect("a console line starts with the prefix and ends with a newline")
    }

    #[tokio::test]
    async fn every_relayed_line_is_prefixed_and_ends_with_one_newline() {
        let lines = relayed(b"one\ntwo\r\n\nlast without newline").await;
        assert_eq!(
            lines,
            [
                "workload: one\n",
                "workload: two\n",
                "workload: \n",
                "workload: last without newline\n"
            ],
            "CRLF stripped, an empty line kept, the last line counts"
        );
        let nothing = relayed(b"").await;
        assert!(nothing.is_empty(), "no output, no console line");
    }

    #[tokio::test]
    async fn a_relayed_line_cannot_open_with_a_priority_or_carry_a_control_character() {
        let lines = relayed(
            b"<3>disk failure\n2026-01-01T00:00:00Z  INFO mediatore: claim bound\n\x1b[2Jx\rforged\x07\n",
        )
        .await;
        assert_eq!(
            lines,
            [
                "workload: <3>disk failure\n",
                "workload: 2026-01-01T00:00:00Z  INFO mediatore: claim bound\n",
                "workload: \\x1b[2Jx\\x0dforged\\x07\n",
            ]
        );
        for line in &lines {
            assert!(
                line.starts_with(CONSOLE_PREFIX),
                "the guest writes the start"
            );
            assert_eq!(line.matches('\n').count(), 1, "one console line each");
            assert!(
                !payload(line).contains(char::is_control),
                "no control character reaches the journal as itself"
            );
        }
    }

    #[tokio::test]
    async fn a_relayed_line_over_the_raw_cap_is_written_in_pieces_not_buffered() {
        let mut input = "y".repeat(RAW_LINE_CAP + 10).into_bytes();
        input.extend_from_slice(b"\nnext\n");
        let lines = relayed(&input).await;
        assert_eq!(
            lines.len(),
            3,
            "the cut piece, the rest of the line, the next line"
        );
        assert_eq!(payload(&lines[0]).len(), RAW_LINE_CAP);
        assert_eq!(payload(&lines[1]), "y".repeat(10));
        assert_eq!(payload(&lines[2]), "next");

        // No newline at all: nothing lost, and no piece is over the cap.
        let endless = "z".repeat(3 * RAW_LINE_CAP + 7);
        let pieces = relayed(endless.as_bytes()).await;
        assert_eq!(pieces.len(), 4);
        assert!(pieces.iter().all(|p| payload(p).len() <= RAW_LINE_CAP));
        let total: usize = pieces.iter().map(|p| payload(p).len()).sum();
        assert_eq!(total, endless.len(), "nothing lost, just cut");
    }

    #[tokio::test]
    async fn a_char_split_by_the_cut_is_relayed_whole() {
        // The two bytes of the e-acute straddle the cap.
        let input = format!("{}\u{e9}z\n", "y".repeat(RAW_LINE_CAP - 1));
        let lines = relayed(input.as_bytes()).await;
        assert_eq!(lines.len(), 2);
        assert_eq!(payload(&lines[0]).len(), RAW_LINE_CAP - 1);
        assert_eq!(lines[1], "workload: \u{e9}z\n");
        assert!(lines.iter().all(|l| !l.contains('\u{fffd}')));

        // Bytes that are not UTF-8 at all are written lossily, never dropped or left raw.
        let lossy = relayed(b"ok \xff\n").await;
        assert_eq!(lossy, ["workload: ok \u{fffd}\n"]);
    }

    #[test]
    fn the_start_of_a_char_at_the_end_of_a_piece_is_told_from_a_whole_one() {
        assert_eq!(split_char_suffix(b""), 0);
        assert_eq!(split_char_suffix(b"abc"), 0);
        assert_eq!(split_char_suffix("a\u{e9}".as_bytes()), 0);
        assert_eq!(split_char_suffix(b"a\xc3"), 1);
        assert_eq!(split_char_suffix(b"a\xe2\x82"), 2);
        assert_eq!(split_char_suffix(b"a\xf0\x9f\x98"), 3);
        assert_eq!(split_char_suffix("a\u{1f600}".as_bytes()), 0);
        // Not the start of anything: lossy, not held back.
        assert_eq!(split_char_suffix(b"a\xff"), 0);
        assert_eq!(split_char_suffix(b"\x82\x82\x82"), 0);
    }

    #[tokio::test]
    async fn a_line_written_to_the_pipe_in_parts_is_one_console_line() {
        use tokio::io::AsyncWriteExt as _;

        let (mut tx, rx) = tokio::io::duplex(8);
        let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = lines.clone();
        let reader = tokio::spawn(relay_stream(rx, move |line: &str| {
            sink.lock().unwrap().push(line.to_owned());
        }));
        tx.write_all(b"<6>par").await.unwrap();
        tx.flush().await.unwrap();
        tokio::task::yield_now().await;
        tx.write_all(b"tial\nthe end, no newline").await.unwrap();
        // The writer closes as the jail's end of the pipe does at exit: the reader sees EOF.
        drop(tx);
        reader.await.unwrap();
        assert_eq!(
            *lines.lock().unwrap(),
            ["workload: <6>partial\n", "workload: the end, no newline\n"]
        );
    }

    #[tokio::test]
    async fn the_relay_refuses_a_jail_whose_output_is_not_a_pipe() {
        let mut inherited = tokio::process::Command::new("true").spawn().unwrap();
        assert!(
            Output::relay(&mut inherited).is_err(),
            "a jail on the guest's own stdout must not start"
        );
        let _ = inherited.wait().await;

        let mut piped = tokio::process::Command::new("true")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let output = Output::relay(&mut piped).unwrap();
        assert!(piped.stdout.is_none() && piped.stderr.is_none());
        let _ = piped.wait().await;
        // Both pipes closed with the child: the drain ends well inside its bound.
        tokio::time::timeout(std::time::Duration::from_secs(2), output.drain())
            .await
            .expect("the relay's readers saw EOF");
    }

    /// A workload that outlived its parent: a child and a grandchild of the spawned process,
    /// each with its parent-death signal cleared, both asleep; the spawned process exits `0`
    /// once the grandchild has said it is ready.
    const SURVIVORS: &str = r#"
import ctypes, os, time
libc = ctypes.CDLL(None, use_errno=True)
def detach():
    if libc.prctl(1, 0, 0, 0, 0) != 0:
        os._exit(3)
r, w = os.pipe()
if os.fork() == 0:
    detach()
    if os.fork() == 0:
        detach()
        os.write(w, b"x")
    time.sleep(300)
    os._exit(0)
os.close(w)
os._exit(0 if os.read(r, 1) == b"x" else 4)
"#;

    /// Whether `program args` exits `0`, its output discarded.
    async fn succeeds(program: &str, args: &[&str]) -> bool {
        tokio::process::Command::new(program)
            .args(args)
            .output()
            .await
            .unwrap_or_else(|e| panic!("could not run {program}: {e}"))
            .status
            .success()
    }

    /// A ruleset for `uid` that admits one documentation address and nothing else.
    fn live_ruleset(uid: u32) -> net::Ruleset {
        net::Ruleset {
            uid,
            allow: [("192.0.2.10".parse().unwrap(), 8443)]
                .into_iter()
                .collect(),
            dns: std::collections::BTreeSet::new(),
            proxy_port: 3128,
            shape: net::Shape::Direct,
            decoy_ports: std::collections::BTreeSet::new(),
            metadata: false,
            trap_port: None,
            chaff_ports: std::collections::BTreeSet::new(),
        }
    }

    /// Run [`SURVIVORS`] as the sandbox user and wait for the process that was spawned; the
    /// two it forked are still asleep when this returns.
    async fn start_survivors(uid: u32, gid: u32) -> std::io::Result<ExitStatus> {
        tokio::process::Command::new("python3")
            .args(["-I", "-c", SURVIVORS])
            .uid(uid)
            .gid(gid)
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
    }

    /// The teardown order of ADR-0020 decision 6 (amended 2026-11-19) against a real kernel:
    /// a sandbox user, the uid-keyed table loaded for it, and two processes of the uid that
    /// cleared their parent-death signal and outlived the process that started them. After
    /// [`teardown`] none is left, the table is gone and the user is gone. It does not start
    /// `nsjail` and does not go through [`run`] (that needs a jail root and an egress proxy).
    ///
    /// Run as root on the build host, never on a pool VM (it loads and deletes the table a
    /// guest uses); it fails, never skips, anywhere else.
    #[tokio::test]
    #[ignore = "needs root, Linux, nft, useradd and python3; loads and deletes the sandbox table: run on the build host"]
    async fn teardown_ends_processes_that_outlived_the_jail_before_the_table_and_the_user_go() {
        assert_eq!(
            std::env::consts::OS,
            "linux",
            "this test proves the teardown against a Linux process table; it must not pass anywhere else"
        );
        let me = tokio::process::Command::new("id")
            .arg("-u")
            .output()
            .await
            .expect("run id");
        assert_eq!(
            String::from_utf8_lossy(&me.stdout).trim(),
            "0",
            "run this test as root: it creates a user and loads an nftables table"
        );
        let table = ["list", "table", "inet", net::TABLE];
        assert!(
            !succeeds(net::NFT, &table).await,
            "a sandbox ruleset is already loaded here: this is a guest, not the build host"
        );

        let subject = mediatore_proto::Subject {
            issuer: "https://issuer.example.com".into(),
            id: format!("teardown-live-{}", uuid::Uuid::new_v4()),
            display: None,
        };
        let name = user::ensure(&subject)
            .await
            .expect("create the sandbox user");
        let uid = user::uid(&name).await.expect("the user's uid");
        let gid = user::gid(&name).await.expect("the user's gid");
        let loaded = net::load(&live_ruleset(uid)).await;
        let started = start_survivors(uid, gid).await;
        // The spawned process is reaped; what is left of the uid is the two it left behind.
        let before = user::processes_of(Path::new(user::PROC_ROOT), uid).map(|pids| pids.len());

        let root = mediatore_testkit::tempdir();
        teardown(&root, &name).await;

        let after = user::processes_of(Path::new(user::PROC_ROOT), uid).map(|pids| pids.len());
        let table_left = succeeds(net::NFT, &table).await;
        let user_left = succeeds("id", &[name.as_str()]).await;
        // Whatever the answers, leave the host as it was before asserting on them.
        let _ = user::kill_all(uid, None).await;
        if table_left {
            net::unload().await;
        }
        if user_left {
            let _ = user::remove(&name).await;
        }

        assert!(
            loaded.is_ok(),
            "nft refused the ruleset: {:?}",
            loaded.err()
        );
        assert!(
            started
                .as_ref()
                .is_ok_and(std::process::ExitStatus::success),
            "the workload did not start as the sandbox user (python3 missing?): {started:?}"
        );
        assert_eq!(
            before.ok(),
            Some(2),
            "two processes of the sandbox user outlived the one that started them"
        );
        assert_eq!(
            after.ok(),
            Some(0),
            "a process of the sandbox user is still alive after the teardown"
        );
        assert!(
            !table_left,
            "the sandbox table is still loaded after the teardown"
        );
        assert!(
            !user_left,
            "the sandbox user still exists after the teardown"
        );
    }

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
    /// The spec the argument tests share: what `guest.rs` builds for a claim with no
    /// tripwire.
    fn plain_spec() -> JailSpec {
        JailSpec {
            user: "sb-abc".into(),
            rootfs: "/mnt/sandbox/rootfs".into(),
            work: "/mnt/sandbox/work".into(),
            agent_binary: "/usr/bin/mediatore".into(),
            argv: vec!["/bin/sh".into(), "-c".into(), "id".into()],
            rlimit_as_mib: 8192,
            proxy_port: 3128,
            phantom: crate::egress::Phantom::parse(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            )
            .unwrap(),
            traps: None,
        }
    }

    #[test]
    fn with_no_tripwire_the_nsjail_argv_is_byte_identical_to_before() {
        // ADR-0069 decision 5: under `off` nothing of the workload's environment changes.
        // This is the argument list as it was before the ADR, whole: one `--connect-port`
        // (the proxy's), the three variables, a tmpfs home.
        let expected = [
            "--mode",
            "o",
            "--user",
            "sb-abc",
            "--group",
            "sb-abc",
            "--chroot",
            "/mnt/sandbox/rootfs",
            "--bindmount_ro",
            "/usr/bin/mediatore:/usr/bin/mediatore",
            "--bindmount",
            "/mnt/sandbox/work:/work",
            "--tmpfsmount",
            "/tmp",
            "--tmpfsmount",
            "/home/sandbox",
            "--bindmount_ro",
            "/dev/null:/dev/null",
            "--bindmount_ro",
            "/dev/zero:/dev/zero",
            "--bindmount_ro",
            "/dev/urandom:/dev/urandom",
            "--disable_proc",
            "--mount",
            "none:/proc:proc:subset=pid,hidepid=invisible",
            "--disable_clone_newnet",
            "--disable_clone_newuser",
            "--rlimit_as",
            "8192",
            "--rlimit_nproc",
            "512",
            "--rlimit_fsize",
            "4096",
            "--time_limit",
            "0",
            "--env",
            "HOME=/home/sandbox",
            "--env",
            "MEDIATORE_EGRESS_PROXY=http://127.0.0.1:3128",
            "--env",
            "MEDIATORE_TOKEN",
            "--",
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
            "id",
        ];
        let spec = plain_spec();
        assert_eq!(nsjail_args(&spec, false), expected);
        assert_eq!(
            nsjail_args(&spec, false)
                .iter()
                .filter(|a| *a == "--connect-port")
                .count(),
            1,
            "Landlock admits the proxy's port and no other"
        );
        // And what nsjail itself is run with: the phantom, nothing else.
        let env = spec.env();
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].0, "MEDIATORE_TOKEN");
    }

    /// A process that outlives the test unless something kills it.
    fn sleeper() -> tokio::process::Child {
        tokio::process::Command::new("sleep")
            .arg("300")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn sleep")
    }

    /// A stand-in for the jail: `command`, with its output relayed nowhere a test reads.
    fn jail_of(program: &str, args: &[&str]) -> anyhow::Result<(tokio::process::Child, Output)> {
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let output = Output::relay(&mut child)?;
        Ok((child, output))
    }

    fn a_cause() -> crate::trip::Cause {
        crate::trip::Cause {
            at: Timestamp::now(),
            kind: mediatore_proto::trip::TripKind::Port,
            trap: Some("redis".into()),
            class: None,
            target: Some(mediatore_proto::trip::TripTarget::Port(6379)),
            source: mediatore_proto::trip::TripSource::Drawn,
        }
    }

    fn in_an_hour() -> Timestamp {
        Timestamp::now() + std::time::Duration::from_secs(3600)
    }

    #[tokio::test]
    async fn a_trip_ends_the_supervision_with_tripped_and_no_restart_whatever_the_policy() {
        for policy in [
            RestartPolicy::Always,
            RestartPolicy::OnFailure,
            RestartPolicy::Never,
        ] {
            let (tx, mut rx) = tokio::sync::watch::channel(None);
            let mut proxy = sleeper();
            let started = Arc::new(std::sync::Mutex::new(Vec::new()));
            let kills = Arc::new(std::sync::Mutex::new(Vec::new()));
            let (pids, spared) = (started.clone(), kills.clone());
            let trip = tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                tx.send(Some(a_cause())).expect("the supervision listens");
                tx
            });
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                supervise(
                    || {
                        let (child, output) = jail_of("sleep", &["300"])?;
                        pids.lock().unwrap().push(child.id());
                        Ok((child, output))
                    },
                    |spare| {
                        spared.lock().unwrap().push(spare);
                        async { false }
                    },
                    in_an_hour(),
                    &mut proxy,
                    policy,
                    Some(&mut rx),
                ),
            )
            .await
            .expect("the trip ended the run, not the deadline")
            .expect("a trip is an outcome, not an error");
            let _tx = trip.await.unwrap();
            assert_eq!(outcome, Outcome::Tripped, "{policy}");
            assert_eq!(
                started.lock().unwrap().len(),
                1,
                "{policy}: one jail, never a second"
            );
            assert_eq!(
                *kills.lock().unwrap(),
                [None],
                "{policy}: every process of the sandbox user, the proxy included"
            );
            // The jail itself was killed and reaped: its pid is nobody's child any more.
            let pid = started.lock().unwrap()[0].expect("the jail had a pid");
            assert!(
                !Path::new(&format!("/proc/{pid}/stat")).exists(),
                "the jail is gone"
            );
        }
    }

    #[tokio::test]
    async fn a_trip_wins_over_the_proxys_exit_and_over_the_jails() {
        // ADR-0069 decision 7, plan D26: the trip kills the proxy with the uid. When the
        // supervision looks, the trip, the proxy's exit and the jail's exit are all there;
        // it must say `Tripped`, never "egress proxy exited" and never a restart.
        let (tx, mut rx) = tokio::sync::watch::channel(None);
        let mut proxy = tokio::process::Command::new("true").spawn().unwrap();
        let starts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let count = starts.clone();
        let outcome = supervise(
            move || {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let jail = jail_of("true", &[]);
                // By the time the supervision waits, everything has happened.
                tx.send(Some(a_cause())).expect("the supervision listens");
                std::thread::sleep(std::time::Duration::from_millis(300));
                jail
            },
            |_| async { false },
            in_an_hour(),
            &mut proxy,
            RestartPolicy::Always,
            Some(&mut rx),
        )
        .await
        .expect("a trip is an outcome, not the proxy's error");
        assert_eq!(outcome, Outcome::Tripped);
        assert_eq!(starts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_jail_starts_after_a_trip_and_a_trip_during_the_restart_wait_ends_the_run() {
        // Tripped before the first start: nothing is started, the uid is still killed.
        let (tx, mut rx) = tokio::sync::watch::channel(Some(a_cause()));
        let mut proxy = sleeper();
        let kills = Arc::new(std::sync::Mutex::new(Vec::new()));
        let spared = kills.clone();
        let outcome = supervise(
            || anyhow::bail!("a jail was started after a trip"),
            |spare| {
                spared.lock().unwrap().push(spare);
                async { false }
            },
            in_an_hour(),
            &mut proxy,
            RestartPolicy::Always,
            Some(&mut rx),
        )
        .await
        .unwrap();
        assert_eq!(outcome, Outcome::Tripped);
        assert_eq!(*kills.lock().unwrap(), [None]);
        drop(tx);

        // The workload exits, the policy says restart, and the trip lands in the wait.
        let (tx, mut rx) = tokio::sync::watch::channel(None);
        let starts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let count = starts.clone();
        let trip = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            tx.send(Some(a_cause())).expect("the supervision listens");
            tx
        });
        let began = std::time::Instant::now();
        let outcome = supervise(
            move || {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                jail_of("true", &[])
            },
            |_| async { false },
            in_an_hour(),
            &mut proxy,
            RestartPolicy::Always,
            Some(&mut rx),
        )
        .await
        .unwrap();
        let _tx = trip.await.unwrap();
        assert_eq!(outcome, Outcome::Tripped);
        assert_eq!(
            starts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the workload that exited is not started again"
        );
        assert!(
            began.elapsed() < std::time::Duration::from_secs(RESTART_DELAY_SECS),
            "the restart wait did not have to end first"
        );
    }

    #[tokio::test]
    async fn without_a_tripwire_the_supervision_is_what_it_was_and_a_lost_tripwire_ends_the_run() {
        // No tripwire: the policy decides, as before.
        let mut proxy = sleeper();
        let outcome = supervise(
            || jail_of("true", &[]),
            |_| async { false },
            in_an_hour(),
            &mut proxy,
            RestartPolicy::Never,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, Outcome::WorkloadDone { restarts: 0, .. }));
        // The proxy's exit is still the claim's end when no trap was used.
        let (tx, mut rx) = tokio::sync::watch::channel(None);
        let mut gone = tokio::process::Command::new("true").spawn().unwrap();
        let err = supervise(
            || jail_of("sleep", &["300"]),
            |_| async { false },
            in_an_hour(),
            &mut gone,
            RestartPolicy::Always,
            Some(&mut rx),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("egress proxy exited"));
        // Every handle to the tripwire dropped while the jail runs: the run is not guarded
        // any more, so it ends, as an error and never as a clean outcome.
        drop(tx);
        let err = supervise(
            || jail_of("sleep", &["300"]),
            |_| async { false },
            in_an_hour(),
            &mut proxy,
            RestartPolicy::Always,
            Some(&mut rx),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("no longer guarded"));
    }

    #[tokio::test]
    async fn without_a_tripwire_a_jail_and_a_proxy_that_exit_together_are_taken_as_before() {
        // A NIT of the review: under `off` the supervision is what it was before ADR-0069, so a
        // jail and a proxy that both exited when it looks are taken in no fixed order (tokio's
        // random start), not always the jail first as a `biased` select would.
        let (mut jail_first, mut proxy_first) = (0, 0);
        for _ in 0..48 {
            let mut proxy = tokio::process::Command::new("true").spawn().unwrap();
            let outcome = supervise(
                || {
                    let jail = jail_of("true", &[]);
                    // Both have exited by the time the supervision waits.
                    std::thread::sleep(std::time::Duration::from_millis(30));
                    jail
                },
                |_| async { false },
                in_an_hour(),
                &mut proxy,
                RestartPolicy::Never,
                None,
            )
            .await;
            match outcome {
                Ok(Outcome::WorkloadDone { .. }) => jail_first += 1,
                Err(e) if e.to_string().contains("egress proxy exited") => proxy_first += 1,
                other => panic!("an outcome neither exit gives: {}", other.is_ok()),
            }
        }
        assert!(
            jail_first > 0 && proxy_first > 0,
            "one exit always wins: {jail_first} jail, {proxy_first} proxy"
        );
    }

    #[test]
    fn after_a_trip_the_teardown_keeps_the_table() {
        // Nobody left and a trip: the table is the cut, and it stays, the user with it.
        let kept = cleanup_for(false, true);
        assert_eq!(kept, Cleanup::KeepRulesetAndUser);
        assert!(
            !kept.unloads_ruleset(),
            "deleting the table would remove the cut"
        );
        assert!(
            !kept.removes_user(),
            "the uid the cut is keyed on is not freed"
        );
        assert_eq!(cleanup_for(true, true), Cleanup::KeepRulesetAndUser);
        // Without a trip the decision is the one it always was.
        assert_eq!(cleanup_for(false, false), cleanup_after(false));
        assert_eq!(cleanup_for(true, false), cleanup_after(true));
        assert_eq!(cleanup_for(false, false), Cleanup::Everything);
    }
}
