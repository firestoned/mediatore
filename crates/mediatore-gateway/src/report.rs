// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The authorizer's decisions, reported to the broker (ADR-0062): which gateway decided which
//! claim's tunnel or inject request to which host. Never on the decision's path (decision 4): a
//! decision is queued without waiting, a full queue drops it and counts it, and a batch goes
//! every [`EVERY`] or at [`MAX_GATEWAY_DECISIONS`], once, with no retry.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mediatore_proto::{GatewayDecision, GatewayDecisions, MAX_GATEWAY_DECISIONS, gateway_name_ok};
use tokio::sync::mpsc;

use crate::broker::AskError;

/// Decisions queued and not yet sent; past it a decision is dropped and counted.
pub const QUEUE: usize = 1024;

/// How often a batch goes when fewer than [`MAX_GATEWAY_DECISIONS`] are waiting.
pub const EVERY: Duration = Duration::from_secs(2);

/// Where batches go: the broker's `POST /v1/gateway/decisions`.
#[async_trait::async_trait]
pub trait Reports: Send + Sync {
    /// Send one batch, once.
    async fn report(&self, batch: &GatewayDecisions) -> Result<(), AskError>;
}

/// The handle the checks note decisions on. Cloning it shares the queue.
#[derive(Clone)]
pub struct Reporter {
    tx: mpsc::Sender<GatewayDecision>,
    dropped: Arc<AtomicU64>,
}

impl Reporter {
    /// A reporter for the gateway `name`, sending to `sink` from a task of its own. The task
    /// ends once every handle is dropped, after one last batch.
    pub fn spawn(
        name: String,
        sink: Arc<dyn Reports>,
        every: Duration,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (reporter, rx) = Self::queue(QUEUE);
        let dropped = reporter.dropped.clone();
        let task = tokio::spawn(run(name, sink, rx, dropped, every));
        (reporter, task)
    }

    pub(crate) fn queue(capacity: usize) -> (Self, mpsc::Receiver<GatewayDecision>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Self {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    /// Queue `decision` for the next batch, without waiting. A full queue drops it.
    pub fn note(&self, decision: GatewayDecision) {
        if self.tx.try_send(decision).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn run(
    name: String,
    sink: Arc<dyn Reports>,
    mut rx: mpsc::Receiver<GatewayDecision>,
    dropped: Arc<AtomicU64>,
    every: Duration,
) {
    let mut batch = Vec::new();
    let mut failing = false;
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let open = tokio::select! {
            got = rx.recv() => match got {
                Some(d) => {
                    batch.push(d);
                    if batch.len() < MAX_GATEWAY_DECISIONS {
                        continue;
                    }
                    true
                }
                None => false,
            },
            _ = tick.tick() => true,
        };
        flush(&name, &*sink, &mut batch, &dropped, &mut failing).await;
        if !open {
            return;
        }
    }
}

/// Send what is waiting, once. A failure drops the batch and is logged at the first of a run
/// of failures only, so a broker that does not know the route is one line, not one per batch.
async fn flush(
    name: &str,
    sink: &dyn Reports,
    batch: &mut Vec<GatewayDecision>,
    dropped: &AtomicU64,
    failing: &mut bool,
) {
    let lost = dropped.swap(0, Ordering::Relaxed);
    if lost > 0 {
        tracing::warn!(
            lost,
            "decisions not reported to the broker: the queue was full"
        );
    }
    if batch.is_empty() {
        return;
    }
    let sent = GatewayDecisions {
        gateway: name.to_owned(),
        decisions: std::mem::take(batch),
    };
    match sink.report(&sent).await {
        Ok(()) => {
            if *failing {
                tracing::info!("reporting decisions to the broker again");
            }
            *failing = false;
        }
        Err(why) => {
            if !*failing {
                tracing::warn!(
                    error = %why,
                    lost = sent.decisions.len(),
                    "decisions not reported to the broker (ADR-0062); dropped, and further failures are quiet until one succeeds"
                );
            }
            *failing = true;
        }
    }
}

/// The gateway's name (ADR-0062 decision 3): `given`, or the kernel's host name, lowercased.
/// Refused unless it is 1 to 63 of `a-z`, `0-9`, `-` and `.`, the shape the broker accepts.
pub fn gateway_name(given: Option<&str>) -> anyhow::Result<String> {
    let name = match given {
        Some(n) => n.trim().to_owned(),
        None => std::fs::read_to_string("/proc/sys/kernel/hostname")
            .or_else(|_| std::fs::read_to_string("/etc/hostname"))
            .map_err(|e| anyhow::anyhow!("no --name and no host name to use: {e}"))?
            .trim()
            .to_ascii_lowercase(),
    };
    anyhow::ensure!(
        gateway_name_ok(&name),
        "gateway name {name:?} is not 1 to 63 of a-z, 0-9, '-' and '.': give one with --name"
    );
    Ok(name)
}

#[cfg(test)]
mod tests {
    use mediatore_proto::{DecisionKind, DecisionVerdict};
    use uuid::Uuid;

    use super::*;

    #[derive(Default)]
    struct Sink {
        batches: std::sync::Mutex<Vec<GatewayDecisions>>,
        fail: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl Reports for Sink {
        async fn report(&self, batch: &GatewayDecisions) -> Result<(), AskError> {
            if self.fail.load(Ordering::Relaxed) {
                return Err(AskError::Unreachable("status 404".into()));
            }
            self.batches.lock().unwrap().push(batch.clone());
            Ok(())
        }
    }

    fn decision(authority: &str) -> GatewayDecision {
        GatewayDecision {
            at: jiff::Timestamp::now(),
            claim_uid: Uuid::nil(),
            kind: DecisionKind::Tunnel,
            authority: authority.into(),
            audience: None,
            verdict: DecisionVerdict::Allow,
            reason: None,
            served: Some("cache".into()),
        }
    }

    async fn sent(sink: &Sink, n: usize) -> Vec<GatewayDecisions> {
        for _ in 0..200 {
            let got = sink.batches.lock().unwrap().clone();
            if got.iter().map(|b| b.decisions.len()).sum::<usize>() >= n {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        sink.batches.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn noted_decisions_go_to_the_broker_in_a_batch_under_the_gateways_name() {
        let sink = Arc::new(Sink::default());
        let (r, _task) =
            Reporter::spawn("gateway-02".into(), sink.clone(), Duration::from_millis(20));
        r.note(decision("pypi.org:443"));
        r.note(decision("github.com:443"));
        let got = sent(&sink, 2).await;
        let all: Vec<&str> = got
            .iter()
            .flat_map(|b| b.decisions.iter().map(|d| d.authority.as_str()))
            .collect();
        assert_eq!(all, ["pypi.org:443", "github.com:443"]);
        assert!(got.iter().all(|b| b.gateway == "gateway-02"));
    }

    #[tokio::test]
    async fn a_failing_broker_loses_that_batch_and_not_the_next() {
        let sink = Arc::new(Sink::default());
        sink.fail.store(true, Ordering::Relaxed);
        let (r, _task) =
            Reporter::spawn("gateway-02".into(), sink.clone(), Duration::from_millis(20));
        r.note(decision("lost.example:443"));
        tokio::time::sleep(Duration::from_millis(80)).await;
        sink.fail.store(false, Ordering::Relaxed);
        r.note(decision("pypi.org:443"));
        let got = sent(&sink, 1).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].decisions[0].authority, "pypi.org:443");
    }

    #[test]
    fn a_full_queue_drops_and_counts_without_waiting() {
        let (r, _rx) = Reporter::queue(2);
        for _ in 0..5 {
            r.note(decision("pypi.org:443"));
        }
        assert_eq!(r.dropped.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn a_given_name_is_used_as_it_is_and_one_the_broker_would_refuse_is_refused_at_start() {
        assert_eq!(gateway_name(Some("gateway-02")).unwrap(), "gateway-02");
        assert!(gateway_name(Some("Gateway 02")).is_err());
        assert!(gateway_name(Some("")).is_err());
    }
}
