// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Per-subject Linux user, and the end of every process that runs as it.

use std::path::Path;
use std::time::Duration;

use mediatore_proto::Subject;

/// The process table as the guest sees it: root, in the VM's own PID namespace, so a
/// process inside the jail's namespace is listed too (ADR-0036 hides the others from the
/// jail, not the jail from the guest).
pub const PROC_ROOT: &str = "/proc";

/// How long [`kill_all`] keeps killing before it reports who is left.
const KILL_BOUND: Duration = Duration::from_secs(5);

/// The pause between a kill and the next look at the process table.
const KILL_POLL: Duration = Duration::from_millis(50);

/// Create the sandbox user for `subject`. Idempotent: an existing user of that name is kept.
pub async fn ensure(subject: &Subject) -> anyhow::Result<String> {
    let name = subject.sandbox_username();
    let exists = tokio::process::Command::new("id")
        .arg(&name)
        .output()
        .await?
        .status
        .success();
    if exists {
        return Ok(name);
    }
    let gecos = subject
        .display
        .clone()
        .unwrap_or_else(|| subject.id.clone());
    let status = tokio::process::Command::new("useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "--comment",
            &gecos,
            "--user-group",
            &name,
        ])
        .status()
        .await?;
    anyhow::ensure!(status.success(), "useradd {name} failed: {status}");
    tracing::info!(user = %name, "sandbox user created");
    Ok(name)
}

/// The uid of `name`, what the ruleset keys on (ADR-0020).
///
/// # Errors
/// No such user, or `id` unavailable.
pub async fn uid(name: &str) -> anyhow::Result<u32> {
    id("-u", name).await
}

/// The primary gid of `name`, what `work/` is owned by (ADR-0021).
///
/// # Errors
/// No such user, or `id` unavailable.
pub async fn gid(name: &str) -> anyhow::Result<u32> {
    id("-g", name).await
}

async fn id(flag: &str, name: &str) -> anyhow::Result<u32> {
    let out = tokio::process::Command::new("id")
        .args([flag, name])
        .output()
        .await?;
    anyhow::ensure!(
        out.status.success(),
        "id {flag} {name} failed: {}",
        out.status
    );
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("id {flag} {name} printed {:?}: {e}", text.trim()))
}

/// Remove the sandbox user and its group. Idempotent.
pub async fn remove(name: &str) -> anyhow::Result<()> {
    let status = tokio::process::Command::new("userdel")
        .arg("--force")
        .arg(name)
        .status()
        .await?;
    if !status.success() {
        tracing::warn!(user = name, %status, "userdel did not succeed (already gone?)");
    }
    Ok(())
}

/// Whether a `/proc/<pid>/status` text describes a live process of `uid`: any of the four
/// ids on its `Uid:` line (real, effective, saved, filesystem) is `uid`, and it is not a
/// zombie waiting to be reaped (which holds no socket and cannot be killed further).
fn status_is_live_process_of(status: &str, uid: u32) -> bool {
    let mut owned = false;
    for line in status.lines() {
        if let Some(state) = line.strip_prefix("State:") {
            if matches!(state.trim_start().chars().next(), Some('Z' | 'X')) {
                return false;
            }
        } else if let Some(ids) = line.strip_prefix("Uid:") {
            owned = ids
                .split_whitespace()
                .any(|id| id.parse::<u32>() == Ok(uid));
        }
    }
    owned
}

/// The pids under `proc_root` whose process runs as `uid`, sorted. An entry that is not a
/// pid, or whose `status` cannot be read (the process ended between the listing and the
/// read), is skipped.
///
/// # Errors
/// `proc_root` itself cannot be listed: the caller then knows nothing and must not conclude
/// that nobody is left.
pub fn processes_of(proc_root: &Path, uid: u32) -> std::io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in std::fs::read_dir(proc_root)? {
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        if status_is_live_process_of(&status, uid) {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

/// Kill every process of `uid` under `proc_root` except `spare`, with `kill`, until a pass
/// finds none or `bound` has passed; the number still there at the end. At least one kill
/// is sent whatever the bound. `kill` is a parameter so a test records the pids instead of
/// signalling.
///
/// # Errors
/// `proc_root` cannot be listed ([`processes_of`]).
pub async fn kill_processes<K, F>(
    proc_root: &Path,
    uid: u32,
    spare: Option<u32>,
    bound: Duration,
    mut kill: K,
) -> std::io::Result<usize>
where
    K: FnMut(Vec<u32>) -> F,
    F: Future<Output = ()>,
{
    let targets = || -> std::io::Result<Vec<u32>> {
        let mut pids = processes_of(proc_root, uid)?;
        pids.retain(|pid| Some(*pid) != spare);
        Ok(pids)
    };
    let deadline = tokio::time::Instant::now() + bound;
    let mut pids = targets()?;
    while !pids.is_empty() {
        kill(pids).await;
        tokio::time::sleep(KILL_POLL).await;
        pids = targets()?;
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    Ok(pids.len())
}

/// `SIGKILL` to `pids`, through `kill` with an argument vector (no shell; the workspace
/// forbids `unsafe`, so there is no `kill(2)` of its own). Best effort: a pid that is
/// already gone makes `kill` exit non-zero, which is what was wanted.
async fn sigkill(pids: Vec<u32>) {
    let count = pids.len();
    let mut command = tokio::process::Command::new("kill");
    command
        .args(["-s", "KILL"])
        .args(pids.into_iter().map(|pid| pid.to_string()));
    match command.output().await {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            tracing::debug!(count, status = %out.status, "kill did not reach every process (already gone?)");
        }
        Err(e) => {
            tracing::warn!(count, error = %e, "could not run kill for the sandbox user's processes");
        }
    }
}

/// Kill every process of the sandbox `uid` except `spare` (the egress proxy while the
/// claim's output is still being flushed) and wait until none is left, at most
/// `KILL_BOUND`; the number still there. The uid is created per claim and nothing else
/// runs as it, so this reaches a workload that outlived `nsjail` (it is pid 1 of the jail's
/// PID namespace and dies with `nsjail` only through a parent-death signal it can clear).
///
/// # Errors
/// uid 0 (never a sandbox user: refused, not killed), or the process table cannot be read.
pub async fn kill_all(uid: u32, spare: Option<u32>) -> std::io::Result<usize> {
    if uid == 0 {
        return Err(std::io::Error::other(
            "uid 0 is not a sandbox user; refusing to kill its processes",
        ));
    }
    kill_processes(Path::new(PROC_ROOT), uid, spare, KILL_BOUND, sigkill).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const UID: u32 = 993;

    /// A `status` file as the kernel writes it, for a process of these four ids.
    fn status(state: &str, uids: [u32; 4]) -> String {
        let [real, effective, saved, fs] = uids;
        format!(
            "Name:\tsleep\nUmask:\t0022\nState:\t{state}\nTgid:\t1\nPid:\t1\nPPid:\t0\n\
             Uid:\t{real}\t{effective}\t{saved}\t{fs}\nGid:\t{UID}\t{UID}\t{UID}\t{UID}\n"
        )
    }

    fn process(root: &Path, name: &str, status: &str) {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("status"), status).unwrap();
    }

    /// A fake `/proc`: two processes of the sandbox uid (one by its effective id alone),
    /// and everything the walk must pass over.
    fn fake_proc() -> PathBuf {
        let root = mediatore_testkit::tempdir();
        process(&root, "1", &status("S (sleeping)", [0; 4]));
        process(&root, "4242", &status("S (sleeping)", [UID; 4]));
        process(&root, "77", &status("R (running)", [0, UID, 0, 0]));
        // Another user's, and one whose gid alone is the number.
        process(&root, "500", &status("S (sleeping)", [1000; 4]));
        // Killed already, not yet reaped by its parent.
        process(&root, "600", &status("Z (zombie)", [UID; 4]));
        // Not processes: `/proc/self`, `/proc/sys`, a file.
        process(&root, "self", &status("S (sleeping)", [UID; 4]));
        process(&root, "sys", &status("S (sleeping)", [UID; 4]));
        std::fs::write(root.join("uptime"), "1.00 1.00\n").unwrap();
        // Ended between the listing and the read: the directory is there, `status` is not.
        std::fs::create_dir_all(root.join("700")).unwrap();
        // `status` is a directory: the read fails with something other than not-found.
        std::fs::create_dir_all(root.join("701").join("status")).unwrap();
        // No `Uid:` line at all.
        process(&root, "702", "Name:\tkthreadd\n");
        root
    }

    #[test]
    fn the_walk_selects_the_processes_of_the_uid_and_no_other() {
        let root = fake_proc();
        assert_eq!(processes_of(&root, UID).unwrap(), vec![77, 4242]);
        assert_eq!(processes_of(&root, 1000).unwrap(), vec![500]);
        assert_eq!(processes_of(&root, 4242).unwrap(), Vec::<u32>::new());
    }

    #[test]
    fn any_of_the_four_ids_counts_and_a_zombie_does_not() {
        for uids in [
            [UID, 0, 0, 0],
            [0, UID, 0, 0],
            [0, 0, UID, 0],
            [0, 0, 0, UID],
        ] {
            assert!(status_is_live_process_of(
                &status("S (sleeping)", uids),
                UID
            ));
        }
        assert!(!status_is_live_process_of(
            &status("S (sleeping)", [0; 4]),
            UID
        ));
        assert!(!status_is_live_process_of(
            &status("Z (zombie)", [UID; 4]),
            UID
        ));
        assert!(!status_is_live_process_of(
            &status("X (dead)", [UID; 4]),
            UID
        ));
        // A longer number that merely starts with the uid, and a gid line, are not it.
        assert!(!status_is_live_process_of(
            "Uid:\t9930\t9930\t9930\t9930\n",
            UID
        ));
        assert!(!status_is_live_process_of(
            "Gid:\t993\t993\t993\t993\n",
            UID
        ));
        assert!(!status_is_live_process_of("", UID));
    }

    #[test]
    fn a_process_table_that_cannot_be_listed_is_an_error_not_an_empty_answer() {
        let root = mediatore_testkit::tempdir().join("absent");
        assert!(processes_of(&root, UID).is_err());
    }

    #[tokio::test]
    async fn every_process_of_the_uid_is_killed_and_none_is_left() {
        let root = fake_proc();
        let mut killed: Vec<u32> = Vec::new();
        let left = kill_processes(&root, UID, None, Duration::from_secs(5), |pids| {
            for pid in &pids {
                std::fs::remove_dir_all(root.join(pid.to_string())).unwrap();
            }
            killed.extend(pids);
            std::future::ready(())
        })
        .await
        .unwrap();
        assert_eq!(left, 0);
        assert_eq!(killed, vec![77, 4242], "one pass, the uid's processes only");
        assert!(root.join("500").is_dir() && root.join("1").is_dir());
    }

    #[tokio::test]
    async fn the_spared_pid_is_neither_killed_nor_counted() {
        let root = fake_proc();
        let mut killed: Vec<u32> = Vec::new();
        let left = kill_processes(&root, UID, Some(77), Duration::from_secs(5), |pids| {
            for pid in &pids {
                std::fs::remove_dir_all(root.join(pid.to_string())).unwrap();
            }
            killed.extend(pids);
            std::future::ready(())
        })
        .await
        .unwrap();
        assert_eq!(left, 0);
        assert_eq!(killed, vec![4242]);
        assert!(
            root.join("77").is_dir(),
            "the proxy is the caller's to stop"
        );
    }

    #[tokio::test]
    async fn processes_that_outlive_the_bound_are_counted_after_at_least_one_kill() {
        let root = fake_proc();
        let mut passes: Vec<Vec<u32>> = Vec::new();
        // A kill that reaches nobody, and no time at all: still one attempt, then the count.
        let left = kill_processes(&root, UID, None, Duration::ZERO, |pids| {
            passes.push(pids);
            std::future::ready(())
        })
        .await
        .unwrap();
        assert_eq!(left, 2);
        assert_eq!(passes, vec![vec![77, 4242]]);
    }

    #[tokio::test]
    async fn uid_zero_is_refused_before_anything_is_killed() {
        assert!(kill_all(0, None).await.is_err());
    }
}
