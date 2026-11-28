// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The image pull's attempts (ADR-0076): a bounded number of them inside one budget, each failed
//! one said to the owner on the claim's output stream, and the last one's failure handed back so
//! that the guest ends the claim with a reason instead of crash-looping until its deadline.
//!
//! This is the pull alone, before any workload runs. The workload's own restarts
//! (ADR-0033) are the supervisor's and start after it.
//!
//! What an attempt failed with reaches the owner and the record as a [`PullError`] kind, from a
//! closed set: never the error's text, which can name a URL path, a token realm or what a gateway
//! answered. The guest's journal keeps the whole error, as before.

use std::path::Path;
use std::time::Duration;

use mediatore_proto::PullError;

/// How many times the pull is attempted (ADR-0076 decision 1).
pub const ATTEMPTS: u32 = 3;

/// The waits between attempts: after the first failure, then after the second.
pub const BACKOFF: [Duration; 2] = [Duration::from_secs(5), Duration::from_secs(15)];

/// How the attempts run.
#[derive(Debug, Clone)]
pub struct Plan {
    /// How many attempts at most.
    pub attempts: u32,
    /// The time every attempt and every wait share: the pull's deadline
    /// (`MEDIATORE_PULL_DEADLINE_SECS`), never past the claim's own.
    pub budget: Duration,
    /// The wait after the n-th failure; the last entry for any later one.
    pub backoff: Vec<Duration>,
}

impl Plan {
    /// [`ATTEMPTS`] and [`BACKOFF`] within `budget`.
    #[must_use]
    pub fn new(budget: Duration) -> Self {
        Self {
            attempts: ATTEMPTS,
            budget,
            backoff: BACKOFF.to_vec(),
        }
    }

    fn wait_after(&self, failed: u32) -> Duration {
        let i = usize::try_from(failed.saturating_sub(1)).unwrap_or(usize::MAX);
        self.backoff
            .get(i)
            .or_else(|| self.backoff.last())
            .copied()
            .unwrap_or_default()
    }
}

/// The pull failed for good: how many attempts were made, the kind of the last failure, and the
/// last error for the guest's own log.
#[derive(Debug)]
pub struct Failure {
    /// Attempts made.
    pub attempts: u32,
    /// What the last one failed with.
    pub error: PullError,
    /// The last error, whole: for the journal, never for the owner or the record.
    pub last: anyhow::Error,
}

impl Failure {
    /// The reason the guest's exit carries (ADR-0076 decision 4).
    #[must_use]
    pub fn reason(&self) -> mediatore_proto::ExitReason {
        mediatore_proto::ExitReason::PullFailed {
            attempts: self.attempts,
            error: self.error,
        }
    }
}

/// The owner's line for a failed attempt: the attempt, the registry, the kind, and what comes
/// next. Every word is the guest's own.
#[must_use]
pub fn failed_line(
    attempt: u32,
    of: u32,
    registry: &str,
    error: PullError,
    next: Option<Duration>,
) -> String {
    let then = next.map_or_else(
        || "giving up: the claim ends".to_owned(),
        |wait| format!("retrying in {} s", wait.as_secs()),
    );
    format!(
        "mediatore: image pull attempt {attempt} of {of} from {registry} failed ({error}); {then}"
    )
}

/// Run `attempt` until it succeeds, at most `plan.attempts` times, all inside `plan.budget`.
/// `attempt` gets the attempt's number (from 1). After each failure `say` gets the owner's
/// line ([`failed_line`]) and the full error goes to the journal; an attempt that outlives
/// what is left of the budget is cut there and counts as a [`PullError::Timeout`]. A wait that
/// would end past the budget is not waited: that failure is the last.
///
/// # Errors
/// [`Failure`] once no attempt is left, or no time.
pub async fn attempts<T, F, Fut>(
    plan: &Plan,
    registry: &str,
    say: &mut dyn FnMut(&str),
    mut attempt: F,
) -> Result<T, Failure>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let started = tokio::time::Instant::now();
    let left = |now: tokio::time::Instant| plan.budget.saturating_sub(now - started);
    let mut n = 0;
    loop {
        n += 1;
        let result = match tokio::time::timeout(left(tokio::time::Instant::now()), attempt(n)).await
        {
            Ok(r) => r,
            Err(_) => Err(anyhow::anyhow!(
                "the pull's budget of {} s (MEDIATORE_PULL_DEADLINE_SECS) passed during attempt {n}",
                plan.budget.as_secs()
            )),
        };
        let e = match result {
            Ok(v) => return Ok(v),
            Err(e) => e,
        };
        let error = if left(tokio::time::Instant::now()).is_zero() {
            PullError::Timeout
        } else {
            crate::image::kind_of(&e)
        };
        let wait = plan.wait_after(n);
        let next = (n < plan.attempts && wait < left(tokio::time::Instant::now())).then_some(wait);
        tracing::warn!(
            attempt = n,
            attempts = plan.attempts,
            registry,
            error = error.as_str(),
            cause = %format!("{e:#}"),
            retry_in_secs = next.map(|w| w.as_secs()),
            "the image pull failed"
        );
        say(&failed_line(n, plan.attempts, registry, error, next));
        match next {
            Some(wait) => tokio::time::sleep(wait).await,
            None => {
                return Err(Failure {
                    attempts: n,
                    error,
                    last: e,
                });
            }
        }
    }
}

/// Empty `dir` before another attempt, which needs its `rootfs` and staging directory empty:
/// every entry goes, and a link is removed as a link, never followed.
///
/// # Errors
/// An entry could not be removed.
pub fn empty_dir(dir: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if std::fs::symlink_metadata(&path)?.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn plan(attempts: u32, budget_ms: u64, backoff_ms: &[u64]) -> Plan {
        Plan {
            attempts,
            budget: Duration::from_millis(budget_ms),
            backoff: backoff_ms
                .iter()
                .copied()
                .map(Duration::from_millis)
                .collect(),
        }
    }

    /// A pull whose deadline passed.
    fn deadline_passed() -> anyhow::Error {
        anyhow::Error::from(crate::image::DeadlinePassed("stand-in".into()))
    }

    #[test]
    fn the_defaults_are_three_attempts_five_then_fifteen_seconds_apart() {
        let p = Plan::new(Duration::from_mins(15));
        assert_eq!(p.attempts, 3);
        assert_eq!(p.wait_after(1), Duration::from_secs(5));
        assert_eq!(p.wait_after(2), Duration::from_secs(15));
        assert_eq!(
            p.wait_after(7),
            Duration::from_secs(15),
            "the last for any later"
        );
    }

    #[tokio::test]
    async fn a_pull_that_fails_then_succeeds_says_each_failure_and_returns_the_image() {
        let said = Mutex::new(Vec::new());
        let mut say = |l: &str| said.lock().unwrap().push(l.to_owned());
        let got = attempts(
            &plan(3, 10_000, &[5, 5]),
            "registry.example",
            &mut say,
            |n| async move {
                if n < 3 {
                    Err(anyhow::anyhow!("not yet"))
                } else {
                    Ok(n)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(got, 3);
        assert_eq!(
            *said.lock().unwrap(),
            [
                "mediatore: image pull attempt 1 of 3 from registry.example failed (invalid); retrying in 0 s",
                "mediatore: image pull attempt 2 of 3 from registry.example failed (invalid); retrying in 0 s",
            ]
        );
    }

    #[tokio::test]
    async fn the_last_failed_attempt_gives_up_with_its_kind_and_count() {
        let said = Mutex::new(Vec::new());
        let mut say = |l: &str| said.lock().unwrap().push(l.to_owned());
        let calls = Mutex::new(0);
        let failure =
            attempts::<(), _, _>(&plan(3, 10_000, &[1]), "registry.example", &mut say, |_| {
                *calls.lock().unwrap() += 1;
                async { Err(deadline_passed()) }
            })
            .await
            .unwrap_err();
        assert_eq!(
            *calls.lock().unwrap(),
            3,
            "bounded: three attempts, never a fourth"
        );
        assert_eq!((failure.attempts, failure.error), (3, PullError::Timeout));
        assert_eq!(
            failure.reason(),
            mediatore_proto::ExitReason::PullFailed {
                attempts: 3,
                error: PullError::Timeout
            }
        );
        let said = said.lock().unwrap();
        assert_eq!(said.len(), 3, "one line per failed attempt");
        assert!(
            said[2].ends_with("(timeout); giving up: the claim ends"),
            "{}",
            said[2]
        );
    }

    #[tokio::test]
    async fn an_attempt_that_outlives_the_budget_is_cut_and_no_other_starts() {
        // A registry that never answers: the budget, not the attempts, ends the pull.
        let mut said = Vec::new();
        let mut say = |l: &str| said.push(l.to_owned());
        let started = tokio::time::Instant::now();
        let failure = attempts::<(), _, _>(
            &plan(3, 300, &[50, 150]),
            "registry.example",
            &mut say,
            |_| async {
                std::future::pending::<()>().await;
                Ok(())
            },
        )
        .await
        .unwrap_err();
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(300) && took < Duration::from_secs(5),
            "the budget is the bound: {took:?}"
        );
        assert_eq!((failure.attempts, failure.error), (1, PullError::Timeout));
        assert_eq!(said.len(), 1);
        assert!(said[0].ends_with("giving up: the claim ends"));
    }

    #[tokio::test]
    async fn a_wait_that_would_end_past_the_budget_is_not_waited() {
        let mut said = Vec::new();
        let mut say = |l: &str| said.push(l.to_owned());
        let started = tokio::time::Instant::now();
        let failure = attempts::<(), _, _>(
            &plan(3, 1_000, &[200, 5_000]),
            "registry.example",
            &mut say,
            |_| async { Err(anyhow::anyhow!("refused")) },
        )
        .await
        .unwrap_err();
        // Attempt 1, a 200 ms wait, attempt 2; the 5 s wait would pass the 1 s budget.
        assert_eq!(failure.attempts, 2);
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(200) && took < Duration::from_millis(1_000),
            "{took:?}"
        );
        assert_eq!(said.len(), 2);
    }

    #[test]
    fn the_owners_line_carries_the_kind_and_never_the_errors_text() {
        let line = failed_line(
            2,
            3,
            "registry.example",
            PullError::Refused,
            Some(Duration::from_secs(15)),
        );
        assert_eq!(
            line,
            "mediatore: image pull attempt 2 of 3 from registry.example failed (refused); retrying in 15 s"
        );
    }

    #[test]
    fn emptying_a_directory_removes_links_and_never_what_they_point_at() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("victim"), b"keep").unwrap();
        let dir = root.path().join("rootfs");
        std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
        std::fs::write(dir.join("usr/bin/sh"), b"sh").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.join("out")).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.join("usr/out")).unwrap();
        empty_dir(&dir).unwrap();
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none(), "empty");
        assert!(dir.is_dir(), "the directory itself stays");
        assert_eq!(
            std::fs::read(outside.path().join("victim")).unwrap(),
            b"keep"
        );
    }
}
