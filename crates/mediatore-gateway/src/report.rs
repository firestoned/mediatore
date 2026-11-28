// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The authorizer's decisions, reported to the broker (ADR-0062): which gateway decided which
//! claim's tunnel or inject request to which host. Never on the decision's path (decision 4): a
//! decision is queued without waiting, a full queue drops it and counts it, and a batch goes
//! every [`EVERY`] or at [`MAX_GATEWAY_DECISIONS`], once, with no retry.
//!
//! The same batch carries the gateway's probes (ADR-0070 decision 8): what the host table
//! dropped, read by another process and left in a summary ([`crate::probes`]). The reporter
//! looks for a new summary at each flush, and a batch of probes alone is still sent. Probes are
//! as lossy as decisions and cost them nothing: a summary that does not read, or that the
//! broker's own check would refuse, is dropped and the decisions go without it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mediatore_proto::trip::GatewayProbe;
use mediatore_proto::{GatewayDecision, GatewayDecisions, MAX_GATEWAY_DECISIONS, gateway_name_ok};
use tokio::sync::mpsc;

use crate::broker::AskError;
use crate::probes::Inbox;

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
    /// ends once every handle is dropped, after one last batch. With `probes`, each batch also
    /// carries the summary the probes reader left there since the last one.
    pub fn spawn(
        name: String,
        sink: Arc<dyn Reports>,
        every: Duration,
        probes: Option<Inbox>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (reporter, rx) = Self::queue(QUEUE);
        let dropped = reporter.dropped.clone();
        let task = tokio::spawn(run(name, sink, rx, dropped, every, probes));
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
    mut probes: Option<Inbox>,
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
        let found = probes.as_mut().map(Inbox::take).unwrap_or_default();
        flush(&name, &*sink, &mut batch, found, &dropped, &mut failing).await;
        if !open {
            return;
        }
    }
}

/// The probes the broker's check would take under this gateway's name, or none: the broker
/// refuses a batch whole, so probes that would fail it are dropped here, before they can cost
/// the decisions beside them.
fn checked(name: &str, probes: Vec<GatewayProbe>) -> Vec<GatewayProbe> {
    if probes.is_empty() {
        return probes;
    }
    let alone = GatewayDecisions {
        gateway: name.to_owned(),
        decisions: vec![],
        probes,
    };
    match alone.check() {
        Ok(()) => alone.probes,
        Err(why) => {
            tracing::warn!(
                why,
                lost = alone.probes.len(),
                "probes not reported to the broker: the summary does not pass the batch's check (ADR-0070)"
            );
            Vec::new()
        }
    }
}

/// Send what is waiting, once. A failure drops the batch and is logged at the first of a run
/// of failures only, so a broker that does not know the route is one line, not one per batch.
async fn flush(
    name: &str,
    sink: &dyn Reports,
    batch: &mut Vec<GatewayDecision>,
    probes: Vec<GatewayProbe>,
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
    let probes = checked(name, probes);
    if batch.is_empty() && probes.is_empty() {
        return;
    }
    let sent = GatewayDecisions {
        gateway: name.to_owned(),
        decisions: std::mem::take(batch),
        probes,
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
                    lost_probes = sent.probes.len(),
                    "decisions not reported to the broker (ADR-0062); dropped, and further failures are quiet until one succeeds"
                );
            }
            *failing = true;
        }
    }
}

/// Where a gateway's name came from (ADR-0062 decision 3, amended 2026-11-27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    /// `--name` or `MEDIATORE_GATEWAY_NAME`.
    Given,
    /// The VM's SMBIOS system UUID, which the hypervisor sets per VM.
    MachineUuid,
    /// A host name somebody set.
    HostName,
    /// A host name a distribution boots with when nobody set one: the same on every VM.
    DefaultHostName,
}

/// The copy of the VM's SMBIOS UUID the gateway image's unit makes for the authorizer.
pub const MACHINE_UUID_FILE: &str = "/run/mediatore-gateway/machine-uuid";

/// The VM's SMBIOS UUID as the kernel shows it: readable by root alone.
pub const DMI_PRODUCT_UUID: &str = "/sys/class/dmi/id/product_uuid";

/// Host names a distribution boots with when nobody set one (Kairos's is `kairos`): a name
/// every gateway of a deployment would share, so the last resort and logged as such.
const DEFAULT_HOST_NAMES: &[&str] = &["kairos", "localhost", "localhost.localdomain", "none"];

/// The longest name the broker accepts (`gateway_name_ok`).
const MAX_NAME: usize = 63;

/// The gateway's name (ADR-0062 decision 3, amended 2026-11-27), from the first of:
///
/// 1. `given` (`--name`, `MEDIATORE_GATEWAY_NAME`), trimmed and otherwise as it is: one the
///    broker would refuse is refused here, at start, never rewritten;
/// 2. the VM's SMBIOS system UUID, lowercase and hyphenated, unless it is the nil or the
///    all-ones UUID or not a UUID at all: the hypervisor sets it per VM (the libvirt domain
///    UUID; the machine's uid on Cloud Hypervisor), so every gateway of a deployment has its
///    own with no setting of any kind, and the operator finds the VM by it;
/// 3. the host name, lowercased, every character the broker refuses made a `-`, cut to 63
///    and never ending in `-` or `.`; a distribution's default ([`NameSource::DefaultHostName`])
///    only when nothing else is there.
///
/// # Errors
///
/// A given name the broker would refuse, or nothing to name the gateway by.
pub fn derive_gateway_name(
    given: Option<&str>,
    machine_uuid: Option<&str>,
    host_name: Option<&str>,
) -> anyhow::Result<(String, NameSource)> {
    if let Some(given) = given {
        let name = given.trim().to_owned();
        anyhow::ensure!(
            gateway_name_ok(&name),
            "gateway name {name:?} is not 1 to 63 of a-z, 0-9, '-' and '.': give one with --name"
        );
        return Ok((name, NameSource::Given));
    }
    if let Some(name) = machine_uuid.and_then(uuid_name) {
        return Ok((name, NameSource::MachineUuid));
    }
    let name = host_name
        .map(sanitised)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("no --name, no SMBIOS UUID and no host name to name this gateway by")
        })?;
    let from = if DEFAULT_HOST_NAMES.contains(&name.as_str()) {
        NameSource::DefaultHostName
    } else {
        NameSource::HostName
    };
    Ok((name, from))
}

/// The SMBIOS UUID as a name, or `None` for one that names no VM.
fn uuid_name(text: &str) -> Option<String> {
    let id = uuid::Uuid::parse_str(text.trim()).ok()?;
    (!id.is_nil() && id != uuid::Uuid::from_u128(u128::MAX)).then(|| id.hyphenated().to_string())
}

/// A host name as a name the broker accepts.
fn sanitised(host_name: &str) -> String {
    let mapped: String = host_name
        .trim()
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = mapped.trim_start_matches(['-', '.']);
    let cut = &trimmed[..trimmed.len().min(MAX_NAME)];
    cut.trim_end_matches(['-', '.']).to_owned()
}

/// The gateway's name, as [`derive_gateway_name`] picks it: the first of `machine_uuid_files`
/// that reads as a UUID (the image's copy, then sysfs, which only root reads), and the kernel's
/// host name (`/etc/hostname` where `/proc` has none). The files are read only when no name
/// is given.
///
/// # Errors
///
/// As [`derive_gateway_name`].
pub fn gateway_name(
    given: Option<&str>,
    machine_uuid_files: &[&std::path::Path],
) -> anyhow::Result<(String, NameSource)> {
    if given.is_some() {
        return derive_gateway_name(given, None, None);
    }
    let machine_uuid = machine_uuid_files
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .find(|t| uuid_name(t).is_some());
    let host_name = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .ok();
    derive_gateway_name(None, machine_uuid.as_deref(), host_name.as_deref())
}

#[cfg(test)]
mod tests {
    use mediatore_proto::trip::TripClass;
    use mediatore_proto::{DecisionKind, DecisionVerdict};
    use uuid::Uuid;

    use super::*;
    use crate::probes::{Summary, write_summary};

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
        let (r, _task) = Reporter::spawn(
            "gateway-02".into(),
            sink.clone(),
            Duration::from_millis(20),
            None,
        );
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
        let (r, _task) = Reporter::spawn(
            "gateway-02".into(),
            sink.clone(),
            Duration::from_millis(20),
            None,
        );
        r.note(decision("lost.example:443"));
        tokio::time::sleep(Duration::from_millis(80)).await;
        sink.fail.store(false, Ordering::Relaxed);
        r.note(decision("pypi.org:443"));
        let got = sent(&sink, 1).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].decisions[0].authority, "pypi.org:443");
    }

    fn probe(class: TripClass, count: u64) -> GatewayProbe {
        GatewayProbe {
            at: jiff::Timestamp::now(),
            class,
            count,
            port: Some(2375),
            source_address: None,
            user: None,
        }
    }

    fn summary(probes: Vec<GatewayProbe>) -> Summary {
        Summary {
            at: jiff::Timestamp::now(),
            probes,
        }
    }

    /// The batches that carried a probe, once at least `n` probes arrived.
    async fn with_probes(sink: &Sink, n: usize) -> Vec<GatewayDecisions> {
        for _ in 0..200 {
            let got: Vec<_> = sink
                .batches
                .lock()
                .unwrap()
                .iter()
                .filter(|b| !b.probes.is_empty())
                .cloned()
                .collect();
            if got.iter().map(|b| b.probes.len()).sum::<usize>() >= n {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Vec::new()
    }

    fn spawn_on(dir: &std::path::Path, sink: &Arc<Sink>) -> Reporter {
        Reporter::spawn(
            "gateway-02".into(),
            sink.clone(),
            Duration::from_millis(20),
            Some(Inbox::open(dir)),
        )
        .0
    }

    #[tokio::test]
    async fn a_summary_is_sent_once_with_the_next_batch() {
        let dir = mediatore_testkit::tempdir();
        let sink = Arc::new(Sink::default());
        let r = spawn_on(&dir, &sink);
        let probes = vec![
            probe(TripClass::GatewayPort, 3),
            probe(TripClass::GatewayOutput, 1),
        ];
        write_summary(&dir, &summary(probes.clone())).unwrap();
        r.note(decision("pypi.org:443"));
        let got = with_probes(&sink, 2).await;
        assert_eq!(got.len(), 1, "one batch carries the summary");
        assert_eq!(got[0].probes, probes);
        assert_eq!(got[0].gateway, "gateway-02");
        assert_eq!(got[0].check(), Ok(()), "the broker takes the batch");
        // Later batches, with the file still where the reader left it, carry it no more.
        for _ in 0..3 {
            r.note(decision("pypi.org:443"));
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let all = sink.batches.lock().unwrap().clone();
        assert!(all.len() > 1);
        assert_eq!(all.iter().map(|b| b.probes.len()).sum::<usize>(), 2);
        assert!(dir.join(crate::probes::SUMMARY).exists());
    }

    #[tokio::test]
    async fn a_batch_with_only_probes_is_still_sent() {
        let dir = mediatore_testkit::tempdir();
        let sink = Arc::new(Sink::default());
        let _r = spawn_on(&dir, &sink);
        write_summary(&dir, &summary(vec![probe(TripClass::GatewayPort, 3)])).unwrap();
        let got = with_probes(&sink, 1).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].decisions, vec![]);
        assert_eq!(got[0].probes.len(), 1);
        assert_eq!(got[0].check(), Ok(()));
        // And with no summary and no decision, nothing is sent at all.
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(sink.batches.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_missing_or_malformed_summary_sends_no_probe_and_fails_nothing() {
        let dir = mediatore_testkit::tempdir();
        let sink = Arc::new(Sink::default());
        // No summary, and no directory either: decisions go as they always did.
        let r = spawn_on(&dir.join("absent"), &sink);
        r.note(decision("pypi.org:443"));
        assert_eq!(sent(&sink, 1).await[0].probes, vec![]);

        let sink = Arc::new(Sink::default());
        let r = spawn_on(&dir, &sink);
        std::fs::write(dir.join(crate::probes::SUMMARY), "{ not a summary").unwrap();
        r.note(decision("pypi.org:443"));
        let got = sent(&sink, 1).await;
        assert_eq!(got[0].decisions.len(), 1, "the decision is not lost");
        assert_eq!(got[0].probes, vec![]);
        // The reporter is still running, and takes the next good summary.
        write_summary(&dir, &summary(vec![probe(TripClass::GatewayPort, 1)])).unwrap();
        assert_eq!(with_probes(&sink, 1).await.len(), 1);
    }

    #[tokio::test]
    async fn a_summary_the_broker_would_refuse_is_dropped_and_the_decisions_still_go() {
        // The broker refuses a batch whole (`400 invalid_decisions`): a summary that would
        // fail its check must not take the decisions down with it.
        let dir = mediatore_testkit::tempdir();
        let sink = Arc::new(Sink::default());
        let r = spawn_on(&dir, &sink);
        for bad in [
            probe(TripClass::PoolInbound, 1),
            probe(TripClass::GatewayPort, 0),
            GatewayProbe {
                source_address: Some("a.example\nforged".into()),
                ..probe(TripClass::GatewayPort, 1)
            },
        ] {
            write_summary(&dir, &summary(vec![probe(TripClass::GatewayPort, 1), bad])).unwrap();
            r.note(decision("pypi.org:443"));
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        let got = sent(&sink, 3).await;
        assert_eq!(got.iter().map(|b| b.decisions.len()).sum::<usize>(), 3);
        assert!(
            got.iter()
                .all(|b| b.probes.is_empty() && b.check() == Ok(())),
            "no probe of a refused summary is sent"
        );
    }

    #[tokio::test]
    async fn a_failing_broker_loses_the_probes_with_the_batch_and_they_are_not_kept() {
        // Single attempt, as the decisions (ADR-0062 decision 4): nothing queues behind a
        // broker that is down.
        let dir = mediatore_testkit::tempdir();
        let sink = Arc::new(Sink::default());
        sink.fail.store(true, Ordering::Relaxed);
        let _r = spawn_on(&dir, &sink);
        write_summary(&dir, &summary(vec![probe(TripClass::GatewayPort, 3)])).unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        sink.fail.store(false, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(sink.batches.lock().unwrap().len(), 0);
    }

    #[test]
    fn a_full_queue_drops_and_counts_without_waiting() {
        let (r, _rx) = Reporter::queue(2);
        for _ in 0..5 {
            r.note(decision("pypi.org:443"));
        }
        assert_eq!(r.dropped.load(Ordering::Relaxed), 3);
    }

    const UUID: &str = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b";

    #[test]
    fn a_given_name_is_used_as_it_is_and_one_the_broker_would_refuse_is_refused_at_start() {
        let given = |n: &str| derive_gateway_name(Some(n), Some(UUID), Some("gateway-01"));
        assert_eq!(
            given("gateway-02").unwrap(),
            ("gateway-02".into(), NameSource::Given)
        );
        assert_eq!(given(" gateway-02\n").unwrap().0, "gateway-02");
        // Not sanitised: an operator's typo is refused at start, not quietly rewritten.
        assert!(given("Gateway 02").is_err());
        assert!(given("Gateway-02").is_err());
        assert!(given("").is_err());
        assert!(given(&"g".repeat(64)).is_err());
        assert_eq!(given(&"g".repeat(63)).unwrap().0.len(), 63);
    }

    #[test]
    fn with_no_name_given_the_vms_uuid_comes_before_any_host_name() {
        assert_eq!(
            derive_gateway_name(None, Some(UUID), Some("gateway-01")).unwrap(),
            (UUID.into(), NameSource::MachineUuid)
        );
        assert_eq!(
            derive_gateway_name(None, Some(UUID), Some("kairos")).unwrap(),
            (UUID.into(), NameSource::MachineUuid)
        );
    }

    #[test]
    fn the_uuid_is_read_as_sysfs_prints_it_and_sent_lowercase_and_hyphenated() {
        let upper = format!("{}\n", UUID.to_ascii_uppercase());
        let (name, from) = derive_gateway_name(None, Some(&upper), None).unwrap();
        assert_eq!((name.as_str(), from), (UUID, NameSource::MachineUuid));
        assert_eq!(name.len(), 36);
        assert!(gateway_name_ok(&name));
    }

    #[test]
    fn a_uuid_that_names_no_vm_is_skipped_for_the_host_name() {
        for bad in [
            "00000000-0000-0000-0000-000000000000",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            "not a uuid",
            "",
            "Not Settable",
        ] {
            assert_eq!(
                derive_gateway_name(None, Some(bad), Some("gateway-01")).unwrap(),
                ("gateway-01".into(), NameSource::HostName),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_host_name_is_lowercased_and_what_the_broker_refuses_becomes_a_hyphen() {
        let name = |h| derive_gateway_name(None, None, Some(h)).unwrap();
        assert_eq!(
            name("Gateway_02.Home.Example\n"),
            ("gateway-02.home.example".into(), NameSource::HostName)
        );
        assert_eq!(name("-gw 03-").0, "gw-03");
        assert_eq!(name("gw\u{e9}04").0, "gw-04");
    }

    #[test]
    fn a_long_host_name_is_cut_to_63_and_never_ends_in_a_hyphen_or_a_dot() {
        let long = format!("{}-{}", "a".repeat(62), "b".repeat(10));
        let (name, _) = derive_gateway_name(None, None, Some(&long)).unwrap();
        assert_eq!(name, "a".repeat(62));
        let dotted = format!("{}.{}", "a".repeat(62), "b".repeat(10));
        assert_eq!(
            derive_gateway_name(None, None, Some(&dotted)).unwrap().0,
            "a".repeat(62)
        );
        let (name, _) = derive_gateway_name(None, None, Some(&"x".repeat(200))).unwrap();
        assert_eq!(name.len(), 63);
        assert!(gateway_name_ok(&name));
    }

    #[test]
    fn a_distribution_default_host_name_is_the_last_resort_and_says_so() {
        for d in [
            "kairos",
            "KAIROS",
            "localhost",
            "localhost.localdomain",
            "(none)",
        ] {
            let (_, from) = derive_gateway_name(None, None, Some(d)).unwrap();
            assert_eq!(from, NameSource::DefaultHostName, "{d:?}");
        }
        assert_eq!(
            derive_gateway_name(None, None, Some("kairos")).unwrap().0,
            "kairos"
        );
    }

    #[test]
    fn nothing_to_name_the_gateway_by_refuses_the_start() {
        assert!(derive_gateway_name(None, None, None).is_err());
        assert!(derive_gateway_name(None, Some("garbage"), Some("___")).is_err());
        assert!(derive_gateway_name(None, None, Some("")).is_err());
    }

    #[test]
    fn the_uuid_files_are_tried_in_order_and_a_missing_or_empty_one_is_passed_over() {
        let dir = mediatore_testkit::tempdir();
        let missing = dir.join("missing");
        let empty = dir.join("empty");
        let copy = dir.join("machine-uuid");
        std::fs::write(&empty, "").unwrap();
        std::fs::write(&copy, format!("{UUID}\n")).unwrap();
        assert_eq!(
            gateway_name(None, &[&missing, &empty, &copy]).unwrap(),
            (UUID.into(), NameSource::MachineUuid)
        );
        assert_eq!(
            gateway_name(Some("gateway-02"), &[&copy]).unwrap(),
            ("gateway-02".into(), NameSource::Given)
        );
    }
}
