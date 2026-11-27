// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The pool VM's segment reader (ADR-0070 decisions 4 and 8): what the host table
//! (`image/host-table`, `table inet mediatore_host`) dropped, read on a timer and sent to the
//! broker as `kind: segment` events (`pool_inbound`, `pool_output`), which a registered node
//! may send with no claim. A `segment` event never ends anything (decision 5), so a reader
//! that reads nothing loses a record and admits nothing.
//!
//! What it reads, each with `nft -j -n reset` so the kernel hands over the figures and zeroes
//! them in one dump and the reader keeps no state (a restarted guest reports nothing twice),
//! one command a process (two `reset set` in one `nft` process fail on nftables 1.1.3):
//!
//! - the named counters `pool_inbound` and `pool_output`: every new TCP connection the table
//!   dropped, inbound (IPv4) and outbound;
//! - the set `inbound_sources`: the same inbound connections by source address and
//!   destination port, each element with its own counter;
//! - the set `output_ports`: the same outbound connections by destination port.
//!
//! An event needs a port, and `pool_inbound` a source, so **the sets make the events and the
//! counters make none**. A counter's use is the overflow: when a set is full its `update`
//! fails and the packet is counted and dropped unnamed, and the difference between the
//! counter and its set's elements is logged, never reported under an invented port.
//!
//! A pool with no gateways loads no host table: `nft` then says the table does not exist,
//! which is no event and no error. `pool_output` counts every uid, the sandbox uid's own
//! dropped connections included where the host table's chain runs before the claim's: an
//! event of that class during a claim proves nothing about anything outside the jail. The
//! source address of `pool_inbound` can be forged on a shared segment (decision 5) and is
//! never acted on.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use mediatore_proto::trip::{
    MAX_TRIP_COUNT, MAX_TRIP_EVENTS, TripClass, TripEvent, TripKind, TripMode, TripReport,
    TripSource, TripTarget,
};
use uuid::Uuid;

use crate::net::{NftRunner, SystemNft, address_and_port, json_items, parse_set};
use crate::report::HOST_TABLE;
use crate::trip::{Timing, TripSink, report_with};

/// The named counter of dropped inbound connections.
const POOL_INBOUND: &str = "pool_inbound";
/// The named counter of dropped outbound connections.
const POOL_OUTPUT: &str = "pool_output";
/// The set of dropped inbound connections' sources and ports.
const INBOUND_SOURCES: &str = "inbound_sources";
/// The set of dropped outbound connections' ports.
const OUTPUT_PORTS: &str = "output_ports";
/// How long one `nft` process may take (a full `inbound_sources` lists in about 120 ms).
const READ_WITHIN: Duration = Duration::from_secs(5);
/// How often a report is tried before it is given up: the channel is lossy by design, and a
/// reader stuck on one report would let the sets' elements time out unread.
const ATTEMPTS: u32 = 3;
/// How `nft` begins when the table, or an object of it, does not exist.
const NO_SUCH: &str = "Error: No such file or directory";

/// One dropped destination since the last read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Dropped {
    class: TripClass,
    port: u16,
    /// The peer, on `pool_inbound`.
    source: Option<IpAddr>,
    packets: u64,
}

/// One set's part of a read: what moved, and whether the set is full.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Named {
    moved: Vec<Dropped>,
    full: bool,
}

/// One read of the host table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Reading {
    /// `pool_inbound`'s packets since the last read.
    inbound_total: u64,
    /// `pool_output`'s packets since the last read.
    output_total: u64,
    inbound: Named,
    output: Named,
}

/// The named counters of the host table in `nft -j reset counters`'s output: each name and
/// its packets. Items of any other kind, table or shape are skipped.
fn parse_counters(json: &[u8]) -> anyhow::Result<Vec<(String, u64)>> {
    Ok(json_items(json)?
        .iter()
        .filter_map(|item| {
            let c = item.get("counter")?;
            (c.get("table")?.as_str()? == HOST_TABLE).then_some(())?;
            Some((
                c.get("name")?.as_str()?.to_owned(),
                c.get("packets")?.as_u64()?,
            ))
        })
        .collect())
}

/// `inbound_sources` in `nft -j reset set`'s output: an element is an IPv4 address and a
/// port. One of any other shape, or that saw nothing since the last read, is skipped.
fn parse_inbound(json: &[u8]) -> anyhow::Result<Named> {
    let set = parse_set(json, HOST_TABLE, INBOUND_SOURCES)?;
    let moved = set
        .elements
        .iter()
        .filter(|(_, packets)| *packets > 0)
        .filter_map(|(key, packets)| {
            let (source, port) = address_and_port(key)?;
            source.is_ipv4().then_some(Dropped {
                class: TripClass::PoolInbound,
                port,
                source: Some(source),
                packets: *packets,
            })
        })
        .collect();
    Ok(Named {
        moved,
        full: set.size.is_some_and(|size| set.held >= size),
    })
}

/// `output_ports` in `nft -j reset set`'s output: an element is a bare port.
fn parse_output(json: &[u8]) -> anyhow::Result<Named> {
    let set = parse_set(json, HOST_TABLE, OUTPUT_PORTS)?;
    let moved = set
        .elements
        .iter()
        .filter(|(_, packets)| *packets > 0)
        .filter_map(|(key, packets)| {
            let port = u16::try_from(key.as_u64()?).ok().filter(|p| *p != 0)?;
            Some(Dropped {
                class: TripClass::PoolOutput,
                port,
                source: None,
                packets: *packets,
            })
        })
        .collect();
    Ok(Named {
        moved,
        full: set.size.is_some_and(|size| set.held >= size),
    })
}

/// One `nft -j -n reset ...` of the host table: its standard output, or `None` when `nft`
/// says the object does not exist.
async fn reset(nft: &dyn NftRunner, what: &[&str]) -> anyhow::Result<Option<Vec<u8>>> {
    let mut args = vec!["-j", "-n", "reset"];
    args.extend_from_slice(what);
    let out = tokio::time::timeout(READ_WITHIN, nft.run(&args, None))
        .await
        .map_err(|_| anyhow::anyhow!("nft did not answer within {}s", READ_WITHIN.as_secs()))??;
    if out.success {
        Ok(Some(out.stdout))
    } else if out.stderr.starts_with(NO_SUCH) {
        Ok(None)
    } else {
        anyhow::bail!("nft could not read the host table: {}", out.stderr)
    }
}

/// Read the host table and zero what was read. `None` when there is no host table: a pool
/// with no gateways, or the unit has not run yet.
///
/// # Errors
/// `nft` could not be run, did not answer, refused for another reason, or printed something
/// that is not the table's objects.
async fn read(nft: &dyn NftRunner) -> anyhow::Result<Option<Reading>> {
    let Some(counters) = reset(nft, &["counters", "table", "inet", HOST_TABLE]).await? else {
        return Ok(None);
    };
    let counters = parse_counters(&counters)?;
    let total = |name: &str| {
        counters
            .iter()
            .find(|(n, _)| n == name)
            .map_or(0, |(_, packets)| *packets)
    };
    let Some(inbound) = reset(nft, &["set", "inet", HOST_TABLE, INBOUND_SOURCES]).await? else {
        return Ok(None);
    };
    let Some(output) = reset(nft, &["set", "inet", HOST_TABLE, OUTPUT_PORTS]).await? else {
        return Ok(None);
    };
    Ok(Some(Reading {
        inbound_total: total(POOL_INBOUND),
        output_total: total(POOL_OUTPUT),
        inbound: parse_inbound(&inbound)?,
        output: parse_output(&output)?,
    }))
}

impl Reading {
    /// What a full set could not name, by class: the counter's packets less its elements'.
    /// Compared only when the set is full: the three reads are three dumps, and a packet
    /// between two of them otherwise shows as a difference of one either way.
    fn unnamed(&self) -> [(TripClass, u64); 2] {
        let beyond = |total: u64, named: &Named| {
            if named.full {
                total.saturating_sub(named.moved.iter().map(|d| d.packets).sum())
            } else {
                0
            }
        };
        [
            (
                TripClass::PoolInbound,
                beyond(self.inbound_total, &self.inbound),
            ),
            (
                TripClass::PoolOutput,
                beyond(self.output_total, &self.output),
            ),
        ]
    }

    /// The events of this read, at most [`MAX_TRIP_EVENTS`], the largest counts kept, and
    /// how many destinations were left out.
    fn events(&self, at: Timestamp) -> (Vec<TripEvent>, usize) {
        let mut moved: Vec<&Dropped> = self
            .inbound
            .moved
            .iter()
            .chain(self.output.moved.iter())
            .collect();
        moved.sort_by_key(|d| std::cmp::Reverse(d.packets));
        let left_out = moved.len().saturating_sub(MAX_TRIP_EVENTS);
        let events = moved
            .into_iter()
            .take(MAX_TRIP_EVENTS)
            .map(|d| TripEvent {
                id: Uuid::new_v4(),
                at,
                kind: TripKind::Segment,
                trap: None,
                class: Some(d.class),
                target: Some(TripTarget::Port(d.port)),
                source: TripSource::Peer,
                containment_ms: None,
                count: d.packets.clamp(1, MAX_TRIP_COUNT),
                source_address: d.source.map(|a| a.to_string()),
            })
            .collect();
        (events, left_out)
    }
}

/// What the reader has already said, so a standing condition is one line and not one a read.
#[derive(Debug, Default)]
struct Said {
    no_table: bool,
    failures: u64,
}

/// One read and, when anything moved, one report. How many events were sent.
async fn once(nft: &dyn NftRunner, sink: &dyn TripSink, timing: &Timing, said: &mut Said) -> usize {
    let reading = match read(nft).await {
        Ok(Some(reading)) => reading,
        Ok(None) => {
            if !said.no_table {
                tracing::info!(
                    table = HOST_TABLE,
                    "no host table is loaded (a pool with no gateways loads none): the segment reader has nothing to read (ADR-0070 decision 4)"
                );
                said.no_table = true;
            }
            return 0;
        }
        Err(e) => {
            if said.failures.is_multiple_of(64) {
                tracing::warn!(error = %e, failures = said.failures, "the host table's drops could not be read");
            }
            said.failures = said.failures.saturating_add(1);
            return 0;
        }
    };
    said.no_table = false;
    said.failures = 0;
    for (class, unnamed) in reading.unnamed() {
        if unnamed > 0 {
            tracing::warn!(
                class = class.as_str(),
                unnamed,
                "the host table dropped connections its full set could not name: counted, not reported"
            );
        }
    }
    let (events, left_out) = reading.events(Timestamp::now());
    if left_out > 0 {
        tracing::warn!(
            left_out,
            sent = events.len(),
            "more dropped destinations than one report holds: the largest counts are reported"
        );
    }
    if events.is_empty() {
        return 0;
    }
    // `shadow`: a segment event acts on nothing under any mode (ADR-0070 decision 5).
    let report = TripReport {
        mode: TripMode::Shadow,
        events,
    };
    if let Err(fault) = report.validate() {
        tracing::error!(
            fault,
            "a segment report the broker would not take is not sent"
        );
        return 0;
    }
    if report_with(sink, &report, timing, Some(ATTEMPTS)).await {
        tracing::debug!(events = report.events.len(), "segment events reported");
        report.events.len()
    } else {
        0
    }
}

/// Start the reader: every `every`, the counters that moved go to `sink` in one report.
pub fn spawn(sink: Arc<dyn TripSink>, every: Duration) -> tokio::task::JoinHandle<()> {
    spawn_with(Arc::new(SystemNft), sink, every)
}

/// [`spawn`] through `nft`.
fn spawn_with(
    nft: Arc<dyn NftRunner>,
    sink: Arc<dyn TripSink>,
    every: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let timing = Timing {
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(10),
            ..Timing::default()
        };
        let mut said = Said::default();
        loop {
            tokio::time::sleep(every).await;
            once(nft.as_ref(), sink.as_ref(), &timing, &mut said).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::testing::FakeNft;
    use crate::trip::PostOutcome;
    use async_trait::async_trait;
    use std::sync::Mutex;

    // The three documents as captured on a real kernel (Debian 13, kernel 6.12, nftables
    // 1.1.3) by the lane that owns `image/host-table`, with the rendered table loaded in a
    // fresh network namespace and probed over a veth pair.
    const COUNTERS: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"counter": {"family": "inet", "name": "pool_inbound", "table": "mediatore_host", "handle": 4, "packets": 3, "bytes": 180}}, {"counter": {"family": "inet", "name": "pool_output", "table": "mediatore_host", "handle": 5, "packets": 3, "bytes": 180}}]}"#;
    const INBOUND: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "inbound_sources", "table": "mediatore_host", "type": ["ipv4_addr", "inet_service"], "handle": 7, "size": 4096, "flags": ["timeout", "dynamic"], "timeout": 300, "elem": [{"elem": {"val": {"concat": ["198.51.100.9", 22]}, "expires": 297, "counter": {"packets": 2, "bytes": 120}}}, {"elem": {"val": {"concat": ["203.0.113.9", 6379]}, "expires": 298, "counter": {"packets": 1, "bytes": 60}}}], "stmt": [{"counter": null}]}}]}"#;
    const OUTPUT: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "output_ports", "table": "mediatore_host", "type": "inet_service", "handle": 8, "size": 1024, "flags": ["timeout", "dynamic"], "timeout": 300, "elem": [{"elem": {"val": 25, "expires": 299, "counter": {"packets": 1, "bytes": 60}}}, {"elem": {"val": 443, "expires": 299, "counter": {"packets": 2, "bytes": 120}}}], "stmt": [{"counter": null}]}}]}"#;
    /// An empty set, as captured: no `elem` member at all.
    const INBOUND_EMPTY: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "inbound_sources", "table": "mediatore_host", "type": ["ipv4_addr", "inet_service"], "handle": 7, "size": 4096, "flags": ["timeout", "dynamic"], "timeout": 300, "stmt": [{"counter": null}]}}]}"#;
    const OUTPUT_EMPTY: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "output_ports", "table": "mediatore_host", "type": "inet_service", "handle": 8, "size": 1024, "flags": ["timeout", "dynamic"], "timeout": 300, "stmt": [{"counter": null}]}}]}"#;
    /// After a reset: the elements are still listed until they time out, with nothing counted.
    const COUNTERS_IDLE: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"counter": {"family": "inet", "name": "pool_inbound", "table": "mediatore_host", "handle": 4, "packets": 0, "bytes": 0}}, {"counter": {"family": "inet", "name": "pool_output", "table": "mediatore_host", "handle": 5, "packets": 0, "bytes": 0}}]}"#;
    const INBOUND_IDLE: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "inbound_sources", "table": "mediatore_host", "type": ["ipv4_addr", "inet_service"], "handle": 7, "size": 4096, "flags": ["timeout", "dynamic"], "timeout": 300, "elem": [{"elem": {"val": {"concat": ["198.51.100.9", 22]}, "expires": 237, "counter": {"packets": 0, "bytes": 0}}}, {"elem": {"val": {"concat": ["203.0.113.9", 6379]}, "expires": 238, "counter": {"packets": 0, "bytes": 0}}}], "stmt": [{"counter": null}]}}]}"#;

    /// A broker that records what it was sent and answers as told.
    struct Recorder {
        posts: Mutex<Vec<TripReport>>,
        answer: anyhow::Result<PostOutcome>,
    }

    impl Recorder {
        fn new(outcome: PostOutcome) -> Self {
            Self {
                posts: Mutex::new(Vec::new()),
                answer: Ok(outcome),
            }
        }

        fn posts(&self) -> Vec<TripReport> {
            self.posts.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl TripSink for Recorder {
        async fn post(&self, report: &TripReport) -> anyhow::Result<PostOutcome> {
            self.posts.lock().unwrap().push(report.clone());
            match &self.answer {
                Ok(outcome) => Ok(*outcome),
                Err(_) => anyhow::bail!("unreachable"),
            }
        }
    }

    fn quick() -> Timing {
        Timing {
            post: Duration::from_millis(200),
            backoff_min: Duration::from_millis(5),
            backoff_max: Duration::from_millis(10),
            ..Timing::default()
        }
    }

    /// What an event says, without its id and its time.
    fn said(e: &TripEvent) -> (TripClass, u16, Option<&str>, u64) {
        let Some(TripTarget::Port(port)) = e.target else {
            panic!("a segment event's target is a port");
        };
        (
            e.class.expect("a segment event has a class"),
            port,
            e.source_address.as_deref(),
            e.count,
        )
    }

    #[test]
    fn the_nft_json_of_the_spike_parses() {
        assert_eq!(
            parse_counters(COUNTERS.as_bytes()).unwrap(),
            [
                ("pool_inbound".to_owned(), 3),
                ("pool_output".to_owned(), 3)
            ]
        );
        let inbound = parse_inbound(INBOUND.as_bytes()).unwrap();
        assert_eq!(
            inbound.moved,
            [
                Dropped {
                    class: TripClass::PoolInbound,
                    port: 22,
                    source: Some("198.51.100.9".parse().unwrap()),
                    packets: 2
                },
                Dropped {
                    class: TripClass::PoolInbound,
                    port: 6379,
                    source: Some("203.0.113.9".parse().unwrap()),
                    packets: 1
                },
            ]
        );
        assert!(!inbound.full);
        let output = parse_output(OUTPUT.as_bytes()).unwrap();
        assert_eq!(
            output
                .moved
                .iter()
                .map(|d| (d.port, d.packets, d.source))
                .collect::<Vec<_>>(),
            [(25, 1, None), (443, 2, None)]
        );
        // An empty set has no `elem` at all, and is not an error.
        assert_eq!(
            parse_inbound(INBOUND_EMPTY.as_bytes()).unwrap(),
            Named::default()
        );
        assert_eq!(
            parse_output(OUTPUT_EMPTY.as_bytes()).unwrap(),
            Named::default()
        );
        // A listing of another set, or of another table, is not the one asked for.
        assert!(parse_inbound(OUTPUT.as_bytes()).is_err());
        assert!(parse_output(INBOUND.as_bytes()).is_err());
        assert!(parse_counters(b"[]").is_err());
        // A counter of another table, an item of another kind: skipped.
        let other = r#"{"nftables": [{"counter": {"name": "pool_inbound", "table": "mediatore_gateway", "packets": 9}}, {"chain": {"name": "input"}}, {"counter": {"name": "pool_output", "table": "mediatore_host", "packets": "many"}}]}"#;
        assert_eq!(parse_counters(other.as_bytes()).unwrap(), []);
    }

    #[test]
    fn an_element_of_another_shape_is_skipped_and_never_an_error_for_the_read() {
        let odd = r#"{"nftables": [{"set": {"name": "inbound_sources", "table": "mediatore_host", "size": 4096, "elem": [{"elem": {"val": {"concat": ["2001:db8::9", 22]}, "counter": {"packets": 4, "bytes": 0}}}, {"elem": {"val": {"concat": ["198.51.100.9", 0]}, "counter": {"packets": 4, "bytes": 0}}}, {"elem": {"val": 22, "counter": {"packets": 4, "bytes": 0}}}, {"elem": {"val": {"concat": ["198.51.100.9", 22]}}}, "198.51.100.9", {"elem": {"val": {"concat": ["198.51.100.7", 8080]}, "counter": {"packets": 1, "bytes": 60}}}]}}]}"#;
        let inbound = parse_inbound(odd.as_bytes()).unwrap();
        assert_eq!(
            inbound.moved.len(),
            1,
            "the one element that is an IPv4 source and a port"
        );
        assert_eq!(inbound.moved[0].port, 8080);
        let odd = r#"{"nftables": [{"set": {"name": "output_ports", "table": "mediatore_host", "size": 1024, "elem": [{"elem": {"val": 0, "counter": {"packets": 4, "bytes": 0}}}, {"elem": {"val": 70000, "counter": {"packets": 4, "bytes": 0}}}, {"elem": {"val": "ssh", "counter": {"packets": 4, "bytes": 0}}}, {"elem": {"val": {"concat": ["198.51.100.9", 22]}, "counter": {"packets": 4, "bytes": 0}}}, {"elem": {"val": 53, "counter": {"packets": 2, "bytes": 0}}}]}}]}"#;
        let output = parse_output(odd.as_bytes()).unwrap();
        assert_eq!(
            output.moved.iter().map(|d| d.port).collect::<Vec<_>>(),
            [53]
        );
    }

    #[tokio::test]
    async fn a_counter_that_moved_becomes_one_event_with_the_delta() {
        let nft = FakeNft::answering([COUNTERS, INBOUND, OUTPUT]);
        let sink = Recorder::new(PostOutcome::Acknowledged);
        let sent = once(&nft, &sink, &quick(), &mut Said::default()).await;
        assert_eq!(sent, 4);
        let posts = sink.posts();
        assert_eq!(posts.len(), 1, "one report a read");
        let report = &posts[0];
        assert_eq!(report.validate(), Ok(()));
        assert!(
            report.is_segment_only(),
            "what a node with no claim may send"
        );
        assert_eq!(report.mode, TripMode::Shadow);
        // The largest counts first; each element's own packets are the delta.
        assert_eq!(
            report.events.iter().map(said).collect::<Vec<_>>(),
            [
                (TripClass::PoolInbound, 22, Some("198.51.100.9"), 2),
                (TripClass::PoolOutput, 443, None, 2),
                (TripClass::PoolInbound, 6379, Some("203.0.113.9"), 1),
                (TripClass::PoolOutput, 25, None, 1),
            ]
        );
        for e in &report.events {
            assert_eq!(
                (e.kind, e.source, e.trap.as_deref(), e.containment_ms),
                (TripKind::Segment, TripSource::Peer, None, None)
            );
            assert!(!e.id.is_nil());
        }
        // Read and zeroed, one command a process, the counters first.
        let calls: Vec<Vec<String>> = nft.calls().into_iter().map(|(args, _)| args).collect();
        assert_eq!(
            calls,
            [
                vec![
                    "-j",
                    "-n",
                    "reset",
                    "counters",
                    "table",
                    "inet",
                    "mediatore_host"
                ],
                vec![
                    "-j",
                    "-n",
                    "reset",
                    "set",
                    "inet",
                    "mediatore_host",
                    "inbound_sources"
                ],
                vec![
                    "-j",
                    "-n",
                    "reset",
                    "set",
                    "inet",
                    "mediatore_host",
                    "output_ports"
                ],
            ]
        );
    }

    #[tokio::test]
    async fn a_source_in_the_set_is_named_once_per_read() {
        // The first read names each source once; the second finds the same elements still
        // listed (they live five minutes) with nothing counted since, and reports nothing.
        let nft = FakeNft::answering([
            COUNTERS,
            INBOUND,
            OUTPUT_EMPTY,
            COUNTERS_IDLE,
            INBOUND_IDLE,
            OUTPUT_EMPTY,
        ]);
        let sink = Recorder::new(PostOutcome::Acknowledged);
        let mut said_so_far = Said::default();
        assert_eq!(once(&nft, &sink, &quick(), &mut said_so_far).await, 2);
        assert_eq!(once(&nft, &sink, &quick(), &mut said_so_far).await, 0);
        let posts = sink.posts();
        assert_eq!(posts.len(), 1, "a read with nothing moved sends no report");
        let sources: Vec<_> = posts[0]
            .events
            .iter()
            .map(|e| e.source_address.clone().unwrap())
            .collect();
        assert_eq!(sources, ["198.51.100.9", "203.0.113.9"]);
    }

    #[tokio::test]
    async fn no_host_table_means_no_event_and_no_error() {
        // As captured: rc 1, nothing on stdout, stderr begins with this.
        let nft = FakeNft::refusing(
            "Error: No such file or directory\nlist table inet mediatore_host\n                ^^^^^^^^^^^^^^",
        );
        let sink = Recorder::new(PostOutcome::Acknowledged);
        let mut said = Said::default();
        assert_eq!(read(&nft).await.unwrap(), None);
        for _ in 0..3 {
            assert_eq!(once(&nft, &sink, &quick(), &mut said).await, 0);
        }
        assert!(sink.posts().is_empty(), "no table, no report");
        assert!(said.no_table);
        assert_eq!(said.failures, 0, "an absent table is not a failure");
        // Any other refusal, no nft, and something that is not the listing are failures of
        // the read: still no event, and the reader goes on.
        for broken in [
            FakeNft::refusing("Error: Operation not permitted"),
            FakeNft::absent(),
            FakeNft::answering(["not json"]),
            FakeNft::answering([COUNTERS, OUTPUT, OUTPUT]),
        ] {
            assert!(read(&broken).await.is_err());
        }
        let mut said = Said::default();
        let denied = FakeNft::refusing("Error: Operation not permitted");
        assert_eq!(once(&denied, &sink, &quick(), &mut said).await, 0);
        assert_eq!(said.failures, 1);
        // The table went between two of the three reads: as if it was never there.
        assert_eq!(read(&FakeNft::answering([COUNTERS])).await.unwrap(), None);
    }

    #[test]
    fn a_report_holds_the_32_largest_counts_and_says_how_many_were_left_out() {
        let dropped = |n: u16| Dropped {
            class: TripClass::PoolOutput,
            port: 1000 + n,
            source: None,
            packets: u64::from(n) + 1,
        };
        let reading = Reading {
            output: Named {
                moved: (0..40).map(dropped).collect(),
                full: false,
            },
            ..Reading::default()
        };
        let (events, left_out) = reading.events(Timestamp::now());
        assert_eq!((events.len(), left_out), (MAX_TRIP_EVENTS, 8));
        assert_eq!(events[0].count, 40);
        assert_eq!(
            events[31].count, 9,
            "the eight smallest are the ones left out"
        );
        let report = TripReport {
            mode: TripMode::Shadow,
            events,
        };
        assert_eq!(report.validate(), Ok(()));
        assert_eq!(Reading::default().events(Timestamp::now()).0.len(), 0);
    }

    #[test]
    fn what_a_full_set_could_not_name_is_counted_and_never_an_event() {
        let one = Dropped {
            class: TripClass::PoolInbound,
            port: 22,
            source: Some("198.51.100.9".parse().unwrap()),
            packets: 5,
        };
        let mut reading = Reading {
            inbound_total: 12,
            output_total: 4,
            inbound: Named {
                moved: vec![one],
                full: true,
            },
            output: Named::default(),
        };
        assert_eq!(
            reading.unnamed(),
            [(TripClass::PoolInbound, 7), (TripClass::PoolOutput, 0)],
            "seven connections the full set did not name; the other set is not full, so its difference is two dumps apart and says nothing"
        );
        assert_eq!(
            reading.events(Timestamp::now()).0.len(),
            1,
            "no event for them"
        );
        reading.inbound.full = false;
        assert_eq!(reading.unnamed()[0].1, 0);
        // A set that holds as many elements as its size is full.
        let full = r#"{"nftables": [{"set": {"name": "output_ports", "table": "mediatore_host", "size": 2, "elem": [{"elem": {"val": 25, "counter": {"packets": 1, "bytes": 60}}}, {"elem": {"val": 443, "counter": {"packets": 0, "bytes": 0}}}]}}]}"#;
        assert!(parse_output(full.as_bytes()).unwrap().full);
    }

    #[tokio::test]
    async fn a_broker_that_does_not_take_the_report_is_given_up_and_the_reader_goes_on() {
        // Unreachable: tried a few times, then dropped. The channel is lossy by design.
        let nft = FakeNft::answering([COUNTERS, INBOUND, OUTPUT]);
        let down = Recorder {
            posts: Mutex::new(Vec::new()),
            answer: Err(anyhow::anyhow!("unreachable")),
        };
        assert_eq!(once(&nft, &down, &quick(), &mut Said::default()).await, 0);
        assert_eq!(down.posts().len(), ATTEMPTS as usize);
        // `501` under a broker at `off`: said once, never again for that report.
        let nft = FakeNft::answering([COUNTERS, INBOUND, OUTPUT]);
        let off = Recorder::new(PostOutcome::Refused);
        assert_eq!(once(&nft, &off, &quick(), &mut Said::default()).await, 0);
        assert_eq!(off.posts().len(), 1);
    }

    #[tokio::test]
    async fn the_reader_reads_on_its_timer_until_it_is_stopped() {
        let nft = Arc::new(FakeNft::answering([COUNTERS, INBOUND, OUTPUT]));
        let sink = Arc::new(Recorder::new(PostOutcome::Acknowledged));
        let task = spawn_with(nft.clone(), sink.clone(), Duration::from_millis(10));
        tokio::time::timeout(Duration::from_secs(5), async {
            while sink.posts().is_empty() || nft.calls().len() < 5 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the reader read, reported, and read again");
        assert_eq!(sink.posts().len(), 1, "the later reads found no table");
        task.abort();
    }
}
