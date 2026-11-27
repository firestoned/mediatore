// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The gateway's probes (ADR-0070 decisions 4, 5 and 8): what the host table dropped that no
//! honest machine sends, read by a oneshot role and handed to the authorizer for its next
//! batch of decisions.
//!
//! Two halves, in two processes that share one file:
//!
//! - **The reader**, `mediatore gateway-probes` ([`run`]), a oneshot under a timer
//!   (`mediatore-gateway-probes.service`). It is a user of its own with `CAP_NET_ADMIN` and no
//!   other capability, no address family but netlink and no listener. It runs `nft -j -n reset`
//!   twice: on the set `probe_sources`, then on the table's named counters. A reset prints the
//!   values and zeroes them in the kernel in one dump, so the reader keeps no state and each
//!   drop is read once. What moved becomes at most [`MAX_GATEWAY_PROBES`] probes in
//!   [`SUMMARY`], written beside its final name and renamed into place.
//! - **The authorizer's side**, [`Inbox`], asked by the reporter at each flush. It reads the
//!   summary when the file is one it has not seen, and never writes: the directory is the
//!   reader's and the authorizer's group may only read it, so the role that holds a capability
//!   never works in a directory another user can write. "Once" is therefore the inbox's memory of
//!   the file it last read, not a removal, and a summary already there when the authorizer
//!   starts is taken as read.
//!
//! Both are lossy on purpose, as the decisions are (ADR-0062 decision 4): a summary nobody
//! read before the next one replaced it is gone, and a fault on either side is no probe. A
//! probe never ends anything (decision 5), so losing one admits nothing.
//!
//! The classes and the counters behind them (`image/gateway/nftables.conf.in`):
//!
//! | Class | Read from | Carries |
//! | --- | --- | --- |
//! | `gateway_port` | the elements of `probe_sources`, each with its own counter | the port and the source address |
//! | `gateway_port` | the counter `gateway_port`, less what the set named, when the set is full | a count alone |
//! | `gateway_output` | the counters `gateway_output_*`, one per dropping rule | the user, where the rule is in one user's chain |

use std::io::{Read as _, Write as _};
use std::net::Ipv4Addr;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context as _;
use jiff::Timestamp;
use mediatore_proto::trip::{GatewayProbe, MAX_GATEWAY_PROBES, MAX_TRIP_COUNT, TripClass};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt as _;

/// Where the reader writes its summary and the authorizer reads it.
pub const PROBES_DIR: &str = "/run/mediatore-gateway/probes";

/// The summary's name in the directory.
pub const SUMMARY: &str = "summary.json";

/// The most bytes of a summary the authorizer reads; a larger file is no probe.
pub const MAX_SUMMARY_BYTES: u64 = 64 * 1024;

/// `nft`, by its path on the image: the reader holds a capability and resolves nothing through `PATH`.
const NFT: &str = "/usr/sbin/nft";

/// The gateway's table.
const TABLE: &str = "mediatore_gateway";

/// The set of `source address . destination port` the input chain's probe rule fills.
const SOURCES: &str = "probe_sources";

/// The counter on the input chain's probe rule.
const PORT_COUNTER: &str = "gateway_port";

/// The counters on the output chains' dropping rules, and the one user whose chain each rule
/// is in. `None` where the rule holds for every user, or for both Envoys.
const OUTPUT_COUNTERS: [(&str, Option<&str>); 10] = [
    ("gateway_output_sandbox", None),
    ("gateway_output_imds", None),
    ("gateway_output_wireserver", None),
    ("gateway_output_broker", None),
    ("gateway_output_authorizer", Some("mediatore-gateway")),
    ("gateway_output_relay", Some("envoy-relay")),
    ("gateway_output_agent", Some("spire")),
    ("gateway_output_loopback", None),
    ("gateway_output_ipv6", None),
    ("gateway_output_refused", None),
];

/// How long one `nft` may take. A full set of 4096 elements was 122 ms on the build host.
const NFT_TIMEOUT: Duration = Duration::from_secs(10);

/// The most bytes read from one `nft`. A full set of 4096 elements was 430 kB.
const MAX_NFT_BYTES: u64 = 4 * 1024 * 1024;

/// `mediatore gateway-probes`'s arguments.
#[derive(Debug, clap::Args)]
pub struct ProbeArgs {
    /// The directory the summary is written to, atomically, for the authorizer to read
    #[arg(long, value_name = "DIR", default_value = PROBES_DIR)]
    pub dir: PathBuf,
}

/// What the reader hands the authorizer: the probes of one read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    /// The reader's clock at the read.
    pub at: Timestamp,
    /// What moved since the read before, at most [`MAX_GATEWAY_PROBES`].
    pub probes: Vec<GatewayProbe>,
}

/// One element of `probe_sources` whose counter moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Source {
    address: Ipv4Addr,
    port: u16,
    packets: u64,
}

/// `probe_sources` as one read found it.
#[derive(Debug, Default, PartialEq, Eq)]
struct Sources {
    /// The set's bound, where `nft` printed one.
    size: Option<u64>,
    /// Elements the set holds, whatever their counters say.
    held: u64,
    /// The elements whose counter moved, in `nft`'s order.
    moved: Vec<Source>,
}

impl Sources {
    /// The set holds as many elements as it may: a source it could not add was dropped and
    /// counted by the rule's own counter, and named nowhere.
    fn full(&self) -> bool {
        self.size.is_some_and(|size| self.held >= size)
    }
}

/// The items of `nft -j`'s document.
fn items(json: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    #[derive(Deserialize)]
    struct Doc {
        nftables: Vec<serde_json::Value>,
    }
    let doc: Doc = serde_json::from_str(json).context("nft -j printed no nftables document")?;
    Ok(doc.nftables)
}

/// The named counters of the gateway's table in `nft -j reset counters`'s output: each name
/// and its packets. Items of any other kind, table or shape are skipped.
fn parse_counters(json: &str) -> anyhow::Result<Vec<(String, u64)>> {
    Ok(items(json)?
        .iter()
        .filter_map(|item| {
            let c = item.get("counter")?;
            (c.get("table")?.as_str()? == TABLE).then_some(())?;
            Some((
                c.get("name")?.as_str()?.to_owned(),
                c.get("packets")?.as_u64()?,
            ))
        })
        .collect())
}

/// `probe_sources` in `nft -j reset set`'s output. An element of another shape is held and not
/// named; a document without the set is an error.
fn parse_set(json: &str) -> anyhow::Result<Sources> {
    let items = items(json)?;
    let set = items
        .iter()
        .filter_map(|item| item.get("set"))
        .find(|s| {
            s.get("name").and_then(serde_json::Value::as_str) == Some(SOURCES)
                && s.get("table").and_then(serde_json::Value::as_str) == Some(TABLE)
        })
        .with_context(|| format!("nft -j printed no set {SOURCES}"))?;
    // An empty set has no `elem` member at all.
    let elements = set
        .get("elem")
        .and_then(serde_json::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let moved = elements
        .iter()
        .filter_map(|e| {
            let e = e.get("elem")?;
            let key = e.get("val")?.get("concat")?.as_array()?;
            let [address, port] = key.as_slice() else {
                return None;
            };
            let source = Source {
                address: address.as_str()?.parse().ok()?,
                port: u16::try_from(port.as_u64()?).ok().filter(|p| *p != 0)?,
                packets: e.get("counter")?.get("packets")?.as_u64()?,
            };
            (source.packets > 0).then_some(source)
        })
        .collect();
    Ok(Sources {
        size: set.get("size").and_then(serde_json::Value::as_u64),
        held: elements.len() as u64,
        moved,
    })
}

/// The probes of one read, at most [`MAX_GATEWAY_PROBES`], and how many sources were left
/// without a probe of their own. Output drops first (at most one probe a user), then the
/// sources with the most packets; what is left over, and what a full set could not name, is
/// one last `gateway_port` probe that carries a count alone, so cutting loses the names and
/// never the count.
fn summarize(
    counters: &[(String, u64)],
    sources: &Sources,
    at: Timestamp,
) -> (Vec<GatewayProbe>, usize) {
    let packets = |name: &str| {
        counters
            .iter()
            .filter(|(n, _)| n == name)
            .fold(0u64, |sum, (_, p)| sum.saturating_add(*p))
    };
    let probe = |class, count: u64| GatewayProbe {
        at,
        class,
        count: count.min(MAX_TRIP_COUNT),
        port: None,
        source_address: None,
        user: None,
    };
    let mut probes = Vec::new();
    let mut users: Vec<Option<&str>> = Vec::new();
    for (_, user) in OUTPUT_COUNTERS {
        if !users.contains(&user) {
            users.push(user);
        }
    }
    for user in users {
        let count = OUTPUT_COUNTERS
            .iter()
            .filter(|(_, u)| *u == user)
            .fold(0u64, |sum, (name, _)| sum.saturating_add(packets(name)));
        if count > 0 {
            probes.push(GatewayProbe {
                user: user.map(str::to_owned),
                ..probe(TripClass::GatewayOutput, count)
            });
        }
    }

    let mut moved = sources.moved.clone();
    moved.sort_by(|a, b| b.packets.cmp(&a.packets).then(a.cmp(b)));
    // One probe is kept back for the count that has no name.
    let room = MAX_GATEWAY_PROBES.saturating_sub(probes.len() + 1);
    let cut = moved.len().saturating_sub(room);
    let sum = |s: &[Source]| s.iter().fold(0u64, |sum, s| sum.saturating_add(s.packets));
    let (named, left) = moved.split_at(moved.len() - cut);
    let beyond = if sources.full() {
        packets(PORT_COUNTER).saturating_sub(sum(&moved))
    } else {
        0
    };
    probes.extend(named.iter().map(|s| GatewayProbe {
        port: Some(s.port),
        source_address: Some(s.address.to_string()),
        ..probe(TripClass::GatewayPort, s.packets)
    }));
    let unnamed = sum(left).saturating_add(beyond);
    if unnamed > 0 {
        probes.push(probe(TripClass::GatewayPort, unnamed));
    }
    (probes, cut)
}

/// Run `nft -j -n <command>` and return what it printed: within [`NFT_TIMEOUT`], at most
/// [`MAX_NFT_BYTES`]. Its standard error is this process's, so `nft`'s own words reach the
/// journal.
async fn nft(nft: &Path, command: &[&str]) -> anyhow::Result<String> {
    let mut child = tokio::process::Command::new(nft)
        .args(["-j", "-n"])
        .args(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning {}", nft.display()))?;
    let stdout = child.stdout.take().context("nft has no standard output")?;
    let what = command.join(" ");
    let read = async {
        let mut out = Vec::new();
        stdout.take(MAX_NFT_BYTES + 1).read_to_end(&mut out).await?;
        anyhow::ensure!(
            out.len() as u64 <= MAX_NFT_BYTES,
            "nft {what} printed more than {MAX_NFT_BYTES} bytes"
        );
        let status = child.wait().await?;
        anyhow::ensure!(status.success(), "nft {what} failed ({status})");
        Ok(String::from_utf8(out)?)
    };
    tokio::time::timeout(NFT_TIMEOUT, read)
        .await
        .with_context(|| format!("nft {what} did not end in {NFT_TIMEOUT:?}"))?
}

/// One read: the set, then the counters, both reset. The set goes first so that a failure
/// there leaves the counters as they were for the next run.
async fn collect(nft_path: &Path, at: Timestamp) -> anyhow::Result<(Summary, usize)> {
    let sources = parse_set(&nft(nft_path, &["reset", "set", "inet", TABLE, SOURCES]).await?)?;
    let counters =
        parse_counters(&nft(nft_path, &["reset", "counters", "table", "inet", TABLE]).await?)?;
    for (name, packets) in &counters {
        let known = name == PORT_COUNTER || OUTPUT_COUNTERS.iter().any(|(n, _)| n == name);
        if known && *packets > 0 {
            tracing::warn!(
                counter = name,
                packets,
                "the host table dropped what no honest machine sends (ADR-0070 decision 4)"
            );
        }
    }
    let (probes, cut) = summarize(&counters, &sources, at);
    Ok((Summary { at, probes }, cut))
}

/// Write `summary` as [`SUMMARY`] in `dir`: a new file, mode `0640`, renamed over the last
/// one, so a reader sees the old summary or the new one and never part of either.
///
/// # Errors
/// The directory missing or not writable.
pub fn write_summary(dir: &Path, summary: &Summary) -> anyhow::Result<()> {
    let tmp = dir.join(format!("{SUMMARY}.tmp"));
    // A file left by a run that died between the write and the rename.
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    // Whatever the umask says.
    file.set_permissions(std::fs::Permissions::from_mode(0o640))?;
    file.write_all(&serde_json::to_vec(summary)?)?;
    drop(file);
    std::fs::rename(&tmp, dir.join(SUMMARY))
        .with_context(|| format!("renaming {} into place", tmp.display()))
}

/// The oneshot role: read and reset the host table's drop counters, write the summary when
/// anything moved, exit. Nothing moved writes nothing, and the last summary stays.
///
/// # Errors
/// `nft` failing (no table, no capability), or the summary not written.
pub async fn run(args: ProbeArgs) -> anyhow::Result<()> {
    let (summary, cut) = collect(Path::new(NFT), Timestamp::now()).await?;
    if summary.probes.is_empty() {
        return Ok(());
    }
    if cut > 0 {
        tracing::warn!(
            cut,
            kept = summary.probes.len(),
            "more sources probed the gateway than one summary names; the rest are in its last probe as a count"
        );
    }
    write_summary(&args.dir, &summary)
}

/// What tells one summary file from the next: the rename gives each a new inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    ino: u64,
    size: u64,
    mtime: (i64, i64),
}

impl Stamp {
    fn of(path: &Path) -> Option<Self> {
        let m = std::fs::symlink_metadata(path).ok()?;
        Some(Self {
            ino: m.ino(),
            size: m.size(),
            mtime: (m.mtime(), m.mtime_nsec()),
        })
    }
}

/// The authorizer's side: the summary directory, and the file last read from it.
#[derive(Debug)]
pub struct Inbox {
    path: PathBuf,
    seen: Option<Stamp>,
}

impl Inbox {
    /// The inbox on `dir`. A summary already there is taken as read: whether the authorizer
    /// that ran before this one sent it cannot be known, and a probe is reported once.
    #[must_use]
    pub fn open(dir: &Path) -> Self {
        let path = dir.join(SUMMARY);
        let seen = Stamp::of(&path);
        Self { path, seen }
    }

    /// The probes of a summary not seen before, at most [`MAX_GATEWAY_PROBES`]; none when
    /// there is no summary, no new one, or one that does not read. A fault is logged once for
    /// that file and fails nothing.
    pub fn take(&mut self) -> Vec<GatewayProbe> {
        let Some(now) = Stamp::of(&self.path) else {
            return Vec::new();
        };
        if self.seen == Some(now) {
            return Vec::new();
        }
        self.seen = Some(now);
        match read_summary(&self.path) {
            Ok(mut summary) => {
                if summary.probes.len() > MAX_GATEWAY_PROBES {
                    tracing::warn!(
                        lost = summary.probes.len() - MAX_GATEWAY_PROBES,
                        "the probes summary holds more than a batch takes; the rest are not reported"
                    );
                    summary.probes.truncate(MAX_GATEWAY_PROBES);
                }
                summary.probes
            }
            Err(why) => {
                tracing::warn!(
                    error = %why,
                    "the probes summary does not read; no probe is reported from it (ADR-0070 decision 4)"
                );
                Vec::new()
            }
        }
    }
}

/// The summary at `path`: a regular file of at most [`MAX_SUMMARY_BYTES`] that parses. What
/// was opened is what is checked (`fstat` of the descriptor), so nothing swapped in between a
/// check and the open is read.
fn read_summary(path: &Path) -> anyhow::Result<Summary> {
    let file = open_summary(path)?;
    let meta = file.metadata()?;
    anyhow::ensure!(meta.file_type().is_file(), "not a regular file");
    anyhow::ensure!(
        meta.len() <= MAX_SUMMARY_BYTES,
        "larger than {MAX_SUMMARY_BYTES} bytes"
    );
    let mut bytes = Vec::new();
    file.take(MAX_SUMMARY_BYTES + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_SUMMARY_BYTES,
        "larger than {MAX_SUMMARY_BYTES} bytes"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

/// Open the summary for reading, without following a link (`O_NOFOLLOW`: a link is an
/// error) and without waiting (`O_NONBLOCK`: a FIFO with no writer opens at once, and is then
/// refused as no regular file). The probes user owns the directory, so either could be put in
/// the summary's place; neither can stall a thread of the authorizer or send it elsewhere.
fn open_summary(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(test)]
mod tests {
    use mediatore_proto::GatewayDecisions;

    use super::*;

    // Captured on the build host (kernel 6.12, nftables 1.1.3) from the table
    // `image/gateway/nftables.conf.in` renders with the example env, loaded in a network
    // namespace of its own and probed over a veth pair: three SYNs from the sandbox side to
    // two ports nothing serves, and one connection attempt for each output rule but the IPv6
    // one (two for the refused set).
    const COUNTERS: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"counter": {"family": "inet", "name": "gateway_port", "table": "mediatore_gateway", "handle": 10, "packets": 3, "bytes": 180}}, {"counter": {"family": "inet", "name": "gateway_output_sandbox", "table": "mediatore_gateway", "handle": 11, "packets": 1, "bytes": 60}}, {"counter": {"family": "inet", "name": "gateway_output_imds", "table": "mediatore_gateway", "handle": 12, "packets": 1, "bytes": 60}}, {"counter": {"family": "inet", "name": "gateway_output_wireserver", "table": "mediatore_gateway", "handle": 13, "packets": 1, "bytes": 60}}, {"counter": {"family": "inet", "name": "gateway_output_broker", "table": "mediatore_gateway", "handle": 14, "packets": 1, "bytes": 60}}, {"counter": {"family": "inet", "name": "gateway_output_authorizer", "table": "mediatore_gateway", "handle": 15, "packets": 1, "bytes": 60}}, {"counter": {"family": "inet", "name": "gateway_output_relay", "table": "mediatore_gateway", "handle": 16, "packets": 1, "bytes": 60}}, {"counter": {"family": "inet", "name": "gateway_output_agent", "table": "mediatore_gateway", "handle": 17, "packets": 1, "bytes": 60}}, {"counter": {"family": "inet", "name": "gateway_output_loopback", "table": "mediatore_gateway", "handle": 18, "packets": 1, "bytes": 60}}, {"counter": {"family": "inet", "name": "gateway_output_ipv6", "table": "mediatore_gateway", "handle": 19, "packets": 0, "bytes": 0}}, {"counter": {"family": "inet", "name": "gateway_output_refused", "table": "mediatore_gateway", "handle": 20, "packets": 2, "bytes": 120}}]}"#;
    const SET: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "probe_sources", "table": "mediatore_gateway", "type": ["ipv4_addr", "inet_service"], "handle": 26, "size": 4096, "flags": ["timeout", "dynamic"], "timeout": 300, "elem": [{"elem": {"val": {"concat": ["198.51.100.9", 22]}, "expires": 293, "counter": {"packets": 1, "bytes": 60}}}, {"elem": {"val": {"concat": ["198.51.100.9", 2375]}, "expires": 294, "counter": {"packets": 2, "bytes": 120}}}], "stmt": [{"counter": null}]}}]}"#;
    // The same set before any packet: no `elem` member.
    const SET_EMPTY: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "probe_sources", "table": "mediatore_gateway", "type": ["ipv4_addr", "inet_service"], "handle": 26, "size": 4096, "flags": ["timeout", "dynamic"], "timeout": 300, "stmt": [{"counter": null}]}}]}"#;
    // The set after a reset and one more SYN: an element that saw nothing since is still
    // listed, at zero.
    const SET_AFTER_RESET: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "probe_sources", "table": "mediatore_gateway", "type": ["ipv4_addr", "inet_service"], "handle": 26, "size": 4096, "flags": ["timeout", "dynamic"], "timeout": 300, "elem": [{"elem": {"val": {"concat": ["198.51.100.9", 22]}, "expires": 299, "counter": {"packets": 1, "bytes": 60}}}, {"elem": {"val": {"concat": ["198.51.100.9", 2375]}, "expires": 294, "counter": {"packets": 0, "bytes": 0}}}], "stmt": [{"counter": null}]}}]}"#;

    fn at() -> Timestamp {
        "2026-11-27T10:00:00Z".parse().unwrap()
    }

    fn port_probe(address: &str, port: u16, count: u64) -> GatewayProbe {
        GatewayProbe {
            at: at(),
            class: TripClass::GatewayPort,
            count,
            port: Some(port),
            source_address: Some(address.into()),
            user: None,
        }
    }

    fn output_probe(user: Option<&str>, count: u64) -> GatewayProbe {
        GatewayProbe {
            at: at(),
            class: TripClass::GatewayOutput,
            count,
            port: None,
            source_address: None,
            user: user.map(str::to_owned),
        }
    }

    /// What the broker does with a batch before it logs any of it.
    fn brokers_check(probes: Vec<GatewayProbe>) -> Result<(), &'static str> {
        GatewayDecisions {
            gateway: "gateway-02".into(),
            decisions: vec![],
            probes,
        }
        .check()
    }

    #[test]
    fn the_nft_json_becomes_probes_with_class_port_and_source() {
        let counters = parse_counters(COUNTERS).unwrap();
        assert_eq!(counters.len(), 11);
        assert_eq!(counters[0], ("gateway_port".to_owned(), 3));
        let sources = parse_set(SET).unwrap();
        assert_eq!((sources.size, sources.held), (Some(4096), 2));
        let (probes, cut) = summarize(&counters, &sources, at());
        assert_eq!(cut, 0);
        assert_eq!(
            probes,
            vec![
                // Seven rules that hold for every user or for both Envoys: 1+1+1+1+1+0+2.
                output_probe(None, 7),
                output_probe(Some("mediatore-gateway"), 1),
                output_probe(Some("envoy-relay"), 1),
                output_probe(Some("spire"), 1),
                // The most packets first.
                port_probe("198.51.100.9", 2375, 2),
                port_probe("198.51.100.9", 22, 1),
            ]
        );
        assert_eq!(brokers_check(probes), Ok(()), "the broker takes the batch");
    }

    #[test]
    fn an_empty_set_and_an_element_at_zero_name_nothing() {
        let empty = parse_set(SET_EMPTY).unwrap();
        assert_eq!(
            empty,
            Sources {
                size: Some(4096),
                held: 0,
                moved: vec![]
            }
        );
        let after = parse_set(SET_AFTER_RESET).unwrap();
        assert_eq!(after.held, 2);
        assert_eq!(
            after.moved,
            vec![Source {
                address: Ipv4Addr::new(198, 51, 100, 9),
                port: 22,
                packets: 1
            }]
        );
        // Counters that did not move are no probe.
        let still = COUNTERS
            .replace("\"packets\": 1", "\"packets\": 0")
            .replace("\"packets\": 2", "\"packets\": 0")
            .replace("\"packets\": 3", "\"packets\": 0");
        let (probes, _) = summarize(&parse_counters(&still).unwrap(), &empty, at());
        assert_eq!(probes, vec![]);
    }

    #[test]
    fn what_is_not_the_tables_or_not_the_shape_is_skipped_and_what_is_no_document_is_an_error() {
        let other = r#"{"nftables": [{"metainfo": {"json_schema_version": 1}},
            {"counter": {"family": "inet", "name": "gateway_port", "table": "another", "packets": 9}},
            {"counter": {"family": "inet", "name": "gateway_port", "table": "mediatore_gateway", "packets": "9"}},
            {"counter": {"family": "inet", "name": "unknown_to_this_build", "table": "mediatore_gateway", "packets": 9}},
            {"chain": {"name": "input"}}, 7, "text"]}"#;
        let counters = parse_counters(other).unwrap();
        assert_eq!(counters, vec![("unknown_to_this_build".to_owned(), 9)]);
        let (probes, _) = summarize(&counters, &Sources::default(), at());
        assert_eq!(
            probes,
            vec![],
            "a counter this build does not know is no probe"
        );

        let odd = r#"{"nftables": [{"set": {"name": "probe_sources", "table": "mediatore_gateway", "size": 4096, "elem": [
            {"elem": {"val": {"concat": ["198.51.100.9", 22]}, "counter": {"packets": 4}}},
            {"elem": {"val": {"concat": ["198.51.100.9", 0]}, "counter": {"packets": 4}}},
            {"elem": {"val": {"concat": ["198.51.100.9", 70000]}, "counter": {"packets": 4}}},
            {"elem": {"val": {"concat": ["a.example", 22]}, "counter": {"packets": 4}}},
            {"elem": {"val": {"concat": ["2001:db8::1", 22]}, "counter": {"packets": 4}}},
            {"elem": {"val": {"concat": ["198.51.100.9", 22, 6]}, "counter": {"packets": 4}}},
            {"elem": {"val": {"concat": ["198.51.100.9", 23]}}},
            {"val": 22}, "198.51.100.9", 22]}}]}"#;
        let sources = parse_set(odd).unwrap();
        assert_eq!(sources.held, 10);
        assert_eq!(
            sources.moved,
            vec![Source {
                address: Ipv4Addr::new(198, 51, 100, 9),
                port: 22,
                packets: 4
            }]
        );

        for bad in [
            "",
            "Error: No such file or directory",
            "{}",
            r#"{"nftables": 3}"#,
        ] {
            assert!(parse_counters(bad).is_err(), "counters from {bad:?}");
            assert!(parse_set(bad).is_err(), "a set from {bad:?}");
        }
        assert!(
            parse_set(COUNTERS).is_err(),
            "a document without the set is not an empty set"
        );
    }

    fn many(n: u32) -> Sources {
        Sources {
            size: Some(4096),
            held: u64::from(n),
            moved: (0..n)
                .map(|i| Source {
                    address: Ipv4Addr::from(0xc633_6400 + (i % 250)),
                    port: 1000 + u16::try_from(i).unwrap(),
                    packets: u64::from(i) + 1,
                })
                .collect(),
        }
    }

    #[test]
    fn more_than_64_probes_are_cut_and_counted() {
        let counters = parse_counters(COUNTERS).unwrap();
        let (probes, cut) = summarize(&counters, &many(200), at());
        assert_eq!(probes.len(), MAX_GATEWAY_PROBES);
        // Four output probes, one kept back, so 59 sources are named and 141 are not.
        assert_eq!(cut, 141);
        assert_eq!(probes[4].count, 200, "the most packets first");
        let last = probes.last().unwrap();
        assert_eq!(
            (last.class, last.port, last.source_address.as_deref()),
            (TripClass::GatewayPort, None, None)
        );
        assert_eq!(
            last.count,
            (1..=141).sum::<u64>(),
            "what was cut is counted"
        );
        let port_total: u64 = probes
            .iter()
            .filter(|p| p.class == TripClass::GatewayPort)
            .map(|p| p.count)
            .sum();
        assert_eq!(
            port_total,
            (1..=200).sum::<u64>(),
            "no packet is lost to the cut"
        );
        assert_eq!(brokers_check(probes), Ok(()));

        // Exactly what fits is not cut, and has no last probe.
        let (probes, cut) = summarize(&counters, &many(59), at());
        assert_eq!((probes.len(), cut), (63, 0));
    }

    #[test]
    fn a_full_set_reports_what_it_could_not_name_as_a_count() {
        // The rule's counter saw 3 packets more than the elements did: the set was full.
        let mut sources = many(4);
        sources.size = Some(4);
        let counters = vec![("gateway_port".to_owned(), 10 + 3)];
        let (probes, cut) = summarize(&counters, &sources, at());
        assert_eq!(cut, 0);
        assert_eq!(probes.len(), 5);
        assert_eq!(
            probes[4],
            GatewayProbe {
                at: at(),
                class: TripClass::GatewayPort,
                count: 3,
                port: None,
                source_address: None,
                user: None
            }
        );
        // A set with room: the counter and the elements are two dumps a packet may fall
        // between, so their difference is not a probe.
        sources.size = Some(4096);
        let (probes, _) = summarize(&counters, &sources, at());
        assert_eq!(probes.len(), 4);
        // A count past what the wire carries is held to the wire's bound.
        let huge = vec![("gateway_output_relay".to_owned(), u64::MAX)];
        let (probes, _) = summarize(&huge, &Sources::default(), at());
        assert_eq!(probes[0].count, MAX_TRIP_COUNT);
        assert_eq!(brokers_check(probes), Ok(()));
    }

    /// A stand-in `nft`: prints the fixture for the command it is given and records its
    /// arguments, or fails as `nft` does when the table is not loaded.
    fn fake_nft(dir: &Path, fail: bool) -> PathBuf {
        std::fs::write(dir.join("counters.json"), COUNTERS).unwrap();
        std::fs::write(dir.join("set.json"), SET).unwrap();
        let script = if fail {
            "#!/bin/sh\necho 'Error: No such file or directory' >&2\nexit 1\n".to_owned()
        } else {
            format!(
                "#!/bin/sh\necho \"$*\" >> {0}/calls\ncase \"$*\" in\n*'reset counters'*) cat {0}/counters.json ;;\n*'reset set'*) cat {0}/set.json ;;\n*) exit 2 ;;\nesac\n",
                dir.display()
            )
        };
        let path = dir.join("nft");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[tokio::test]
    async fn the_reader_resets_the_set_then_the_counters_and_the_summary_reaches_the_inbox() {
        let dir = mediatore_testkit::tempdir();
        let nft = fake_nft(&dir, false);
        let mut inbox = Inbox::open(&dir);
        assert_eq!(inbox.take(), vec![], "no summary yet");

        let (summary, cut) = collect(&nft, at()).await.unwrap();
        assert_eq!((summary.at, summary.probes.len(), cut), (at(), 6, 0));
        assert_eq!(
            std::fs::read_to_string(dir.join("calls")).unwrap(),
            "-j -n reset set inet mediatore_gateway probe_sources\n-j -n reset counters table inet mediatore_gateway\n",
            "reset, never list: the kernel zeroes what was read"
        );
        write_summary(&dir, &summary).unwrap();
        let mode = std::fs::metadata(dir.join(SUMMARY)).unwrap().mode() & 0o7777;
        assert_eq!(mode, 0o640);
        assert!(!dir.join(format!("{SUMMARY}.tmp")).exists());

        assert_eq!(inbox.take(), summary.probes);
        assert_eq!(inbox.take(), vec![], "a summary is read once");
        // The next run's summary replaces it and is read once as well.
        let next = Summary {
            at: at() + jiff::SignedDuration::from_secs(30),
            probes: vec![port_probe("198.51.100.9", 22, 1)],
        };
        write_summary(&dir, &next).unwrap();
        assert_eq!(inbox.take(), next.probes);
        assert_eq!(inbox.take(), vec![]);
    }

    #[tokio::test]
    async fn nft_failing_is_an_error_and_writes_nothing() {
        let dir = mediatore_testkit::tempdir();
        let nft = fake_nft(&dir, true);
        assert!(collect(&nft, at()).await.is_err(), "no table, no summary");
        assert!(
            collect(&dir.join("absent"), at()).await.is_err(),
            "no nft at all"
        );
        assert!(!dir.join(SUMMARY).exists());
        // And a summary that cannot be written is the role's error, not a silent success.
        let summary = Summary {
            at: at(),
            probes: vec![],
        };
        assert!(write_summary(&dir.join("absent"), &summary).is_err());
    }

    #[test]
    fn a_summary_present_when_the_authorizer_starts_is_taken_as_read() {
        let dir = mediatore_testkit::tempdir();
        let old = Summary {
            at: at(),
            probes: vec![port_probe("198.51.100.9", 22, 1)],
        };
        write_summary(&dir, &old).unwrap();
        let mut inbox = Inbox::open(&dir);
        assert_eq!(inbox.take(), vec![], "it may have been sent already");
    }

    #[test]
    fn a_missing_or_malformed_summary_is_no_probe_and_fails_nothing() {
        let dir = mediatore_testkit::tempdir();
        let mut inbox = Inbox::open(&dir.join("absent"));
        assert_eq!(inbox.take(), vec![], "no directory");
        let mut inbox = Inbox::open(&dir);
        let path = dir.join(SUMMARY);
        let good = Summary {
            at: at(),
            probes: vec![port_probe("198.51.100.9", 22, 1)],
        };
        let mut unknown = serde_json::to_value(&good).unwrap();
        unknown["path"] = "/x".into();
        let big = format!(
            "{}{}",
            serde_json::to_string(&good).unwrap(),
            " ".repeat(70_000)
        );
        for bad in [
            String::new(),
            "not json".to_owned(),
            "{\"at\":\"2026-11-27T10:00:00Z\"}".to_owned(),
            unknown.to_string(),
            big,
        ] {
            std::fs::write(&path, bad).unwrap();
            assert_eq!(inbox.take(), vec![], "a summary that does not read");
            assert_eq!(inbox.take(), vec![]);
            std::fs::remove_file(&path).unwrap();
        }
        // Not a regular file: a directory where the summary should be.
        std::fs::create_dir(&path).unwrap();
        assert_eq!(inbox.take(), vec![]);
        std::fs::remove_dir(&path).unwrap();
        // The next good summary is read as if nothing had happened.
        write_summary(&dir, &good).unwrap();
        assert_eq!(inbox.take(), good.probes);
    }

    /// `f` on a thread of its own, or `None` if it has not returned within two seconds.
    fn within_two_seconds<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(2)).ok()
    }

    #[test]
    fn a_fifo_or_a_symlink_where_the_summary_is_opened_is_refused_without_waiting() {
        // The probes user owns the directory and can put anything there: the open itself
        // must neither wait on a FIFO with no writer nor follow a link (the review's N3).
        let dir = mediatore_testkit::tempdir();
        let fifo = dir.join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "mkfifo made the FIFO");
        let opened = within_two_seconds(move || open_summary(&fifo).map(|_| ()));
        assert!(opened.is_some(), "the open of a FIFO did not return");
        let elsewhere = dir.join("elsewhere.json");
        let good = Summary {
            at: at(),
            probes: vec![port_probe("198.51.100.9", 22, 1)],
        };
        std::fs::write(&elsewhere, serde_json::to_vec(&good).unwrap()).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        assert!(open_summary(&link).is_err(), "a link is not followed");
        assert!(read_summary(&link).is_err());
        let fifo = dir.join("fifo");
        let read = within_two_seconds(move || read_summary(&fifo).is_err());
        assert_eq!(
            read,
            Some(true),
            "a FIFO is not a summary, and is said so at once"
        );

        // In the inbox's place: no probe, and the inbox goes on.
        let inbox_dir = mediatore_testkit::tempdir();
        let mut inbox = Inbox::open(&inbox_dir);
        std::os::unix::fs::symlink(&elsewhere, inbox_dir.join(SUMMARY)).unwrap();
        assert_eq!(inbox.take(), vec![], "a link is no summary");
        std::fs::remove_file(inbox_dir.join(SUMMARY)).unwrap();
        let path = inbox_dir.join(SUMMARY);
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo runs");
        assert!(made.success());
        let taken = within_two_seconds(move || inbox.take());
        assert_eq!(
            taken,
            Some(vec![]),
            "a FIFO is no summary, and nothing waits on it"
        );
        // A regular file is read as always.
        assert!(open_summary(&elsewhere).is_ok());
        assert_eq!(read_summary(&elsewhere).unwrap().probes, good.probes);
    }

    #[test]
    fn a_summary_with_more_probes_than_a_batch_takes_is_cut_to_the_bound() {
        let dir = mediatore_testkit::tempdir();
        let mut inbox = Inbox::open(&dir);
        let over = Summary {
            at: at(),
            probes: vec![output_probe(Some("envoy-relay"), 1); MAX_GATEWAY_PROBES + 5],
        };
        write_summary(&dir, &over).unwrap();
        let got = inbox.take();
        assert_eq!(got.len(), MAX_GATEWAY_PROBES);
        assert_eq!(brokers_check(got), Ok(()));
    }
}
