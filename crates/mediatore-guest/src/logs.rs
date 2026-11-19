// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The workload's output, captured at the jail and shipped to the broker (ADR-0045 decisions
//! 1, 3 and 8). Opt-in per claim (`workload.logs`): without it the jail inherits the guest's
//! stdio as before and nothing here runs.
//!
//! Two readers drain the jail's stdout and stderr pipes line by line, redact each line
//! ([`crate::redact`], decision 2; a line over [`RAW_LINE_CAP`] in pieces, with the end of each
//! piece held back unredacted until the next is read, so a secret across a cut is seen whole), write it through to the VM console (the operator's view is
//! unchanged) and queue it as a [`LogRecord`] with a per-claim `seq`. A batcher posts the queue
//! to `POST /v1/me/logs` every [`ShipperConfig::interval`] or at [`ShipperConfig::batch_bytes`],
//! whichever comes first. The workload never waits for mediatore: the readers only touch the
//! queue under a mutex, and a queue over its cap drops its oldest records and counts the bytes,
//! which travel with the next batch so the reader sees the gap (decision 8). Delivery is
//! at-least-once with idempotent writes at the broker: a retried batch keeps its `seq` range.
//!
//! Nothing here logs record text or a token: the lines say `claim_uid`, counts and statuses.
//!
//! The workload chooses its output, so a redacted line is neutralised before it goes anywhere
//! ([`neutralise_controls`]: no control character reaches the VM journal or the owner's
//! terminal as itself), and the console copy starts with [`CONSOLE_PREFIX`], which the guest
//! writes, so no workload line begins with a syslog priority (`<3>`) or passes for a line of
//! the guest's own log.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jiff::Timestamp;
use mediatore_proto::{LOG_RETRY_AFTER_SECS, LogBatch, LogRecord, LogStream, MAX_LOG_RECORD_BYTES};
use reqwest::Method;
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncRead, BufReader};
use tokio::sync::{Notify, watch};
use uuid::Uuid;

use crate::client::SandboxClient;
use crate::redact::Redactor;

/// Record text the guest queues before it drops the oldest (ADR-0045 decision 8).
pub const QUEUE_MAX_BYTES: usize = 1024 * 1024;
/// A raw line is cut here, so a workload writing without newlines cannot grow the guest's
/// memory; each piece lands in the queue as a line of its own. The cut is not where redaction
/// stops: the end of a piece ([`Redactor::redact_head`] says how much) stays in memory in front
/// of what is read next, so at most this and that held-back end are buffered at once.
pub const RAW_LINE_CAP: usize = 4 * MAX_LOG_RECORD_BYTES;
/// What every console copy of a workload line starts with. The guest writes it, the workload
/// cannot: a line that begins with `<3>` or with a forged timestamp and level is, in the
/// journal, visibly the workload's.
pub const CONSOLE_PREFIX: &str = "workload: ";
/// How long the guest waits for the readers to see EOF once the jail exited.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the flush at workload exit may take, before `POST /v1/me/exit` (decision 8).
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// A queue of records waiting for the broker, with the bytes dropped from it since the last
/// accepted batch (ADR-0045 decision 8).
pub struct Queue {
    inner: Mutex<QueueInner>,
    max_bytes: usize,
    /// Signalled when the queued text crosses the batcher's threshold.
    full: Notify,
    threshold: usize,
}

#[derive(Default)]
struct QueueInner {
    records: VecDeque<LogRecord>,
    bytes: usize,
    dropped_stdout: u64,
    dropped_stderr: u64,
}

impl Default for Queue {
    fn default() -> Self {
        Self::new(QUEUE_MAX_BYTES, ShipperConfig::default().batch_bytes)
    }
}

impl Queue {
    /// A queue keeping at most `max_bytes` of record text, waking the batcher at `threshold`.
    #[must_use]
    pub fn new(max_bytes: usize, threshold: usize) -> Self {
        Self {
            inner: Mutex::new(QueueInner::default()),
            max_bytes,
            full: Notify::new(),
            threshold,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QueueInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queue one record; beyond the cap the oldest go, their bytes counted per stream.
    pub fn push(&self, record: LogRecord) {
        let mut q = self.lock();
        q.bytes += record.text.len();
        q.records.push_back(record);
        while q.bytes > self.max_bytes {
            let Some(old) = q.records.pop_front() else {
                break;
            };
            let n = old.text.len();
            q.bytes -= n;
            match old.stream {
                LogStream::Stdout => q.dropped_stdout += n as u64,
                LogStream::Stderr => q.dropped_stderr += n as u64,
            }
        }
        let wake = q.bytes >= self.threshold;
        drop(q);
        if wake {
            self.full.notify_one();
        }
    }

    /// Take the next batch: records from the front up to `batch_bytes` of text (at least one,
    /// so a record near the record limit still ships), and the dropped counters, which are
    /// reset here and belong to the batch from now on.
    pub fn take_batch(&self, batch_bytes: usize) -> LogBatch {
        let mut q = self.lock();
        let mut records = Vec::new();
        let mut bytes = 0;
        while let Some(front) = q.records.front() {
            if !records.is_empty() && bytes + front.text.len() > batch_bytes {
                break;
            }
            let n = front.text.len();
            if let Some(r) = q.records.pop_front() {
                bytes += n;
                q.bytes -= n;
                records.push(r);
            }
        }
        let batch = LogBatch {
            records,
            dropped_stdout: q.dropped_stdout,
            dropped_stderr: q.dropped_stderr,
        };
        q.dropped_stdout = 0;
        q.dropped_stderr = 0;
        batch
    }

    /// Record text bytes waiting.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.lock().bytes
    }

    /// Records waiting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().records.len()
    }

    /// Nothing waiting and nothing dropped since the last batch.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let q = self.lock();
        q.records.is_empty() && q.dropped_stdout == 0 && q.dropped_stderr == 0
    }
}

/// The capture of one claim's output: what to redact, the shared `seq`, the queue.
pub struct Capture {
    secrets: Vec<String>,
    seq: AtomicU64,
    queue: Arc<Queue>,
    /// Write every redacted line through to the guest's own stdio (the VM console).
    tee_console: bool,
}

/// The two reader tasks of one jail; [`Readers::drain`] waits for both to see EOF.
pub struct Readers {
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Readers {
    /// Wait for the pipes to close, bounded by [`DRAIN_TIMEOUT`].
    pub async fn drain(self) {
        let all = async {
            for t in self.tasks {
                let _ = t.await;
            }
        };
        if tokio::time::timeout(DRAIN_TIMEOUT, all).await.is_err() {
            tracing::warn!(
                "the workload's output pipes did not close in time; the tail may be lost"
            );
        }
    }
}

impl Capture {
    /// Capture with these literals redacted (`JailSpec::secret_values`), queueing into `queue`.
    #[must_use]
    pub fn new(secrets: Vec<String>, queue: Arc<Queue>) -> Self {
        Self {
            secrets,
            seq: AtomicU64::new(0),
            queue,
            tee_console: true,
        }
    }

    /// For tests: queue only, nothing written to the test's stdio.
    #[must_use]
    pub fn without_console(mut self) -> Self {
        self.tee_console = false;
        self
    }

    /// The queue the readers fill.
    #[must_use]
    pub fn queue(&self) -> Arc<Queue> {
        self.queue.clone()
    }

    fn redactor(&self) -> Redactor {
        let mut r = Redactor::new();
        for s in &self.secrets {
            r.add_secret(s);
        }
        r
    }

    /// Take the child's piped stdout and stderr and read both until EOF.
    ///
    /// # Errors
    /// The child was not spawned with both pipes.
    pub fn attach(self: &Arc<Self>, child: &mut tokio::process::Child) -> anyhow::Result<Readers> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("the jail's stdout is not a pipe"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("the jail's stderr is not a pipe"))?;
        let out = self.clone();
        let err = self.clone();
        Ok(Readers {
            tasks: vec![
                tokio::spawn(async move { out.read_stream(stdout, LogStream::Stdout).await }),
                tokio::spawn(async move { err.read_stream(stderr, LogStream::Stderr).await }),
            ],
        })
    }

    /// Read `reader` to EOF as `stream`: each line redacted, written to the console, split at
    /// [`MAX_LOG_RECORD_BYTES`] and queued. A last line without its newline counts. A line
    /// over [`RAW_LINE_CAP`] is redacted and queued in pieces, the unredacted end of each
    /// piece kept in front of the next read.
    pub async fn read_stream<R: AsyncRead + Unpin>(&self, reader: R, stream: LogStream) {
        let mut reader = BufReader::new(reader);
        let mut redactor = self.redactor();
        // What a cut held back of the line being read (`held` bytes, unredacted), then what
        // is read after it.
        let mut raw = Vec::new();
        let mut held = 0;
        loop {
            let limit = held + RAW_LINE_CAP;
            let read = match read_line_bounded(&mut reader, &mut raw, limit).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!(?stream, error = %e, "output pipe closed with an error");
                    0
                }
            };
            if read == 0 {
                // The pipe closed: what a cut held back is the end of its line.
                if !raw.is_empty()
                    && let Some(redacted) = redactor.redact_line(&String::from_utf8_lossy(&raw))
                {
                    self.emit(stream, &redacted);
                }
                return;
            }
            if raw.last() == Some(&b'\n') || raw.len() < limit {
                // The whole line, or the end of one that was cut.
                if raw.last() == Some(&b'\n') {
                    raw.pop();
                    if raw.last() == Some(&b'\r') {
                        raw.pop();
                    }
                }
                if let Some(redacted) = redactor.redact_line(&String::from_utf8_lossy(&raw)) {
                    self.emit(stream, &redacted);
                }
                raw.clear();
                held = 0;
                continue;
            }
            // Cut before its end. A char split by the cut waits for its other bytes.
            let (redacted, rest) = {
                let whole = raw.len() - incomplete_utf8_suffix(&raw);
                let piece = String::from_utf8_lossy(&raw[..whole]);
                let (redacted, covered) = redactor.redact_head(&piece);
                let mut rest = piece.as_bytes()[covered..].to_vec();
                rest.extend_from_slice(&raw[whole..]);
                (redacted, rest)
            };
            if let Some(redacted) = redacted {
                self.emit(stream, &redacted);
            }
            raw = rest;
            held = raw.len();
        }
    }

    /// One redacted line, or piece of an overlong one: its control characters neutralised
    /// ([`neutralise_controls`]), then to the console behind [`CONSOLE_PREFIX`], and to the
    /// queue in records of at most [`MAX_LOG_RECORD_BYTES`]. The split comes after the
    /// escaping, which lengthens a line, so the record limit holds on what is queued.
    fn emit(&self, stream: LogStream, redacted: &str) {
        let safe = neutralise_controls(redacted);
        if self.tee_console {
            tee(stream, &safe);
        }
        for text in split_record(&safe, MAX_LOG_RECORD_BYTES) {
            let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
            self.queue.push(LogRecord {
                seq,
                stream,
                ts: Timestamp::now(),
                text,
            });
        }
    }
}

/// How many bytes at the end of `bytes` are the start of a UTF-8 char whose other bytes have
/// not been read yet: 0 to 3.
fn incomplete_utf8_suffix(bytes: &[u8]) -> usize {
    for back in 1..=bytes.len().min(3) {
        let b = bytes[bytes.len() - back];
        // Not a continuation byte: the last char starts here, whole or not.
        if b & 0xC0 != 0x80 {
            let needs = match b {
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF7 => 4,
                _ => 1,
            };
            return if needs > back { back } else { 0 };
        }
    }
    0
}

/// Whether `c` is written out as an escape: every C0 control but tab, DEL, and the C1 range
/// (U+0080 to U+009F). That is Unicode's `Cc` category less the tab.
fn is_neutralised(c: char) -> bool {
    c != '\t' && c.is_control()
}

/// `line` with every control character but the tab replaced by its visible spelling: `\x1b`
/// (backslash, `x`, two lowercase hex digits) for a C0 control or DEL, `\u{9b}` for a C1
/// control. Everything else, the backslash included, is kept as it is, so the result holds no
/// control character and a second pass changes nothing. Borrowed when there is nothing to do.
///
/// The workload chooses these bytes: an ESC starts a terminal sequence (OSC 52 writes the
/// reader's clipboard), a carriage return overwrites what was printed before it, and a newline
/// inside a record would start a line of the workload's choosing.
#[must_use]
pub fn neutralise_controls(line: &str) -> Cow<'_, str> {
    let Some(first) = line.find(is_neutralised) else {
        return Cow::Borrowed(line);
    };
    let mut out = String::with_capacity(line.len() + 16);
    out.push_str(&line[..first]);
    for c in line[first..].chars() {
        if !is_neutralised(c) {
            out.push(c);
            continue;
        }
        // Writing to a String does not fail.
        let _ = if c.is_ascii() {
            write!(out, "\\x{:02x}", u32::from(c))
        } else {
            write!(out, "\\u{{{:x}}}", u32::from(c))
        };
    }
    Cow::Owned(out)
}

/// The console copy of one neutralised line: [`CONSOLE_PREFIX`], the line, a newline.
fn console_line(line: &str) -> String {
    format!("{CONSOLE_PREFIX}{line}\n")
}

/// The console copy: the guest's stdout for the workload's stdout, stderr for stderr, each
/// line in one write.
fn tee(stream: LogStream, line: &str) {
    let line = console_line(line);
    let _ = match stream {
        LogStream::Stdout => std::io::stdout().lock().write_all(line.as_bytes()),
        LogStream::Stderr => std::io::stderr().lock().write_all(line.as_bytes()),
    };
}

/// Read up to and including the next `\n`, or `cap` bytes, or EOF. Returns the bytes read.
async fn read_line_bounded<R: AsyncBufRead + Unpin>(
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
        if let Some(i) = avail.iter().position(|b| *b == b'\n') {
            buf.extend_from_slice(&avail[..=i]);
            reader.consume(i + 1);
            return Ok(total + i + 1);
        }
        let room = cap.saturating_sub(buf.len());
        let take = room.min(avail.len());
        buf.extend_from_slice(&avail[..take]);
        reader.consume(take);
        total += take;
        if buf.len() >= cap {
            return Ok(total);
        }
    }
}

/// Split a redacted line into pieces of at most `max` bytes, at char boundaries. An empty line
/// is one empty record.
#[must_use]
pub fn split_record(text: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while rest.len() > max {
        let mut i = max;
        while !rest.is_char_boundary(i) {
            i -= 1;
        }
        out.push(rest[..i].to_owned());
        rest = &rest[i..];
    }
    out.push(rest.to_owned());
    out
}

/// What the broker said to a batch, as the batcher acts on it (ADR-0045 decision 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostOutcome {
    /// `204`: stored (or a known replay).
    Accepted,
    /// `429`: one batch per second per claim; wait this long and send the same batch again.
    RetryAfter(Duration),
    /// `501` or `404`: this broker stores no output; stop shipping, keep the console copy.
    Off,
    /// Any other refusal (`400`, `413`, `403`): the batch is dropped, shipping goes on.
    Refused(u16),
}

/// Where batches go: the broker, or a fake in tests.
#[async_trait::async_trait]
pub trait LogSink: Send + Sync + 'static {
    /// Post one batch. `Err` is a transport failure, retried with backoff.
    async fn post(&self, batch: &LogBatch) -> anyhow::Result<PostOutcome>;
}

/// `POST /v1/me/logs` over the node SVID.
pub struct BrokerSink {
    client: Arc<SandboxClient>,
    claim_uid: Uuid,
}

impl BrokerSink {
    /// The sink for this claim.
    #[must_use]
    pub fn new(client: Arc<SandboxClient>, claim_uid: Uuid) -> Self {
        Self { client, claim_uid }
    }
}

#[async_trait::async_trait]
impl LogSink for BrokerSink {
    async fn post(&self, batch: &LogBatch) -> anyhow::Result<PostOutcome> {
        let resp = self
            .client
            .send(Method::POST, "/v1/me/logs", Some(batch))
            .await?;
        let status = resp.status();
        let outcome = classify(
            status.as_u16(),
            resp.headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok()),
        );
        tracing::debug!(
            claim_uid = %self.claim_uid,
            records = batch.records.len(),
            bytes = batch.text_bytes(),
            status = status.as_u16(),
            ?outcome,
            "log batch posted"
        );
        Ok(outcome)
    }
}

/// The batcher's reading of a status and its `Retry-After` seconds.
#[must_use]
pub fn classify(status: u16, retry_after_secs: Option<u64>) -> PostOutcome {
    match status {
        200..=299 => PostOutcome::Accepted,
        429 => PostOutcome::RetryAfter(Duration::from_secs(
            retry_after_secs.unwrap_or(LOG_RETRY_AFTER_SECS),
        )),
        404 | 501 => PostOutcome::Off,
        other => PostOutcome::Refused(other),
    }
}

/// The batcher's timings (ADR-0045 decisions 1 and 8).
#[derive(Debug, Clone, Copy)]
pub struct ShipperConfig {
    /// Post at least this often while anything is queued.
    pub interval: Duration,
    /// Post as soon as this much record text is queued.
    pub batch_bytes: usize,
    /// First wait after a transport failure, doubled each time up to `backoff_max`.
    pub backoff_min: Duration,
    /// The cap of that wait.
    pub backoff_max: Duration,
}

impl Default for ShipperConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(2),
            batch_bytes: 32 * 1024,
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
        }
    }
}

/// A running batcher. [`Shipping::flush`] ends it.
pub struct Shipping {
    task: tokio::task::JoinHandle<()>,
    stop: watch::Sender<bool>,
    off: Arc<AtomicBool>,
}

impl Shipping {
    /// Start the batcher over `queue` and `sink`.
    #[must_use]
    pub fn start(queue: Arc<Queue>, sink: Arc<dyn LogSink>, cfg: ShipperConfig) -> Self {
        let (stop, stopped) = watch::channel(false);
        let off = Arc::new(AtomicBool::new(false));
        let flag = off.clone();
        let task = tokio::spawn(async move { run(queue, sink, cfg, stopped, flag).await });
        Self { task, stop, off }
    }

    /// The broker said it stores no output: shipping stopped for the rest of the claim.
    #[must_use]
    pub fn is_off(&self) -> bool {
        self.off.load(Ordering::SeqCst)
    }

    /// Tell the batcher to post everything queued and end, waiting at most `timeout`
    /// (decision 8: bounded, before `POST /v1/me/exit`). Returns whether it finished.
    pub async fn flush(self, timeout: Duration) -> bool {
        let _ = self.stop.send(true);
        if tokio::time::timeout(timeout, self.task).await.is_ok() {
            return true;
        }
        tracing::warn!(
            timeout_secs = timeout.as_secs(),
            "the output flush did not finish in time; the tail is lost"
        );
        false
    }
}

/// The batcher loop: wait for the interval, the threshold or the stop; take a batch; post it
/// until the broker takes it or refuses it; on stop, drain and leave.
async fn run(
    queue: Arc<Queue>,
    sink: Arc<dyn LogSink>,
    cfg: ShipperConfig,
    mut stopped: watch::Receiver<bool>,
    off: Arc<AtomicBool>,
) {
    let mut backoff = cfg.backoff_min;
    loop {
        let stopping = *stopped.borrow();
        if !stopping {
            tokio::select! {
                () = tokio::time::sleep(cfg.interval) => {}
                () = queue.full.notified() => {}
                _ = stopped.changed() => {}
            }
        }
        if queue.is_empty() {
            if *stopped.borrow() {
                return;
            }
            continue;
        }
        let batch = queue.take_batch(cfg.batch_bytes);
        loop {
            match sink.post(&batch).await {
                Ok(PostOutcome::Accepted) => {
                    backoff = cfg.backoff_min;
                    break;
                }
                Ok(PostOutcome::RetryAfter(wait)) => {
                    tracing::debug!(
                        wait_secs = wait.as_secs(),
                        "log batch rate limited; retrying the same batch"
                    );
                    tokio::time::sleep(wait).await;
                }
                Ok(PostOutcome::Off) => {
                    off.store(true, Ordering::SeqCst);
                    tracing::info!(
                        "the broker stores no workload output (not enabled, or an older release); the console copy stays"
                    );
                    return;
                }
                Ok(PostOutcome::Refused(status)) => {
                    tracing::warn!(
                        status,
                        records = batch.records.len(),
                        bytes = batch.text_bytes(),
                        "the broker refused a log batch; those records are lost"
                    );
                    break;
                }
                Err(e) => {
                    tracing::debug!(error = %e, wait_secs = backoff.as_secs(), "log batch did not reach the broker; retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(cfg.backoff_max);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHANTOM: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn capture() -> Arc<Capture> {
        Arc::new(
            Capture::new(vec![PHANTOM.to_owned()], Arc::new(Queue::default())).without_console(),
        )
    }

    fn records(q: &Queue) -> Vec<LogRecord> {
        q.take_batch(usize::MAX).records
    }

    #[tokio::test]
    async fn both_streams_are_read_line_by_line_with_one_seq_across_them() {
        let c = capture();
        let (a, b) = tokio::join!(
            c.read_stream(&b"one\ntwo\r\nlast without newline"[..], LogStream::Stdout),
            c.read_stream(&b"err\n"[..], LogStream::Stderr),
        );
        let _ = (a, b);
        let mut got = records(&c.queue());
        got.sort_by_key(|r| r.seq);
        assert_eq!(got.len(), 4);
        let seqs: Vec<u64> = got.iter().map(|r| r.seq).collect();
        assert_eq!(
            seqs,
            vec![1, 2, 3, 4],
            "strictly increasing across both streams"
        );
        let texts: Vec<(&str, LogStream)> =
            got.iter().map(|r| (r.text.as_str(), r.stream)).collect();
        assert!(texts.contains(&("one", LogStream::Stdout)));
        assert!(texts.contains(&("two", LogStream::Stdout)), "CRLF stripped");
        assert!(texts.contains(&("last without newline", LogStream::Stdout)));
        assert!(texts.contains(&("err", LogStream::Stderr)));
    }

    #[tokio::test]
    async fn the_phantom_never_reaches_the_queue() {
        let c = capture();
        let input = format!("token is {PHANTOM} and again Bearer {PHANTOM}\n");
        c.read_stream(input.as_bytes(), LogStream::Stdout).await;
        let got = records(&c.queue());
        assert_eq!(got.len(), 1);
        assert!(!got[0].text.contains(PHANTOM), "{}", got[0].text);
        assert!(got[0].text.contains(crate::redact::REDACTED));
    }

    #[tokio::test]
    async fn an_overlong_line_is_split_at_the_record_limit_after_redaction() {
        let c = capture();
        let line = format!("{}{PHANTOM}\n", "x".repeat(70 * 1024));
        c.read_stream(line.as_bytes(), LogStream::Stderr).await;
        let got = records(&c.queue());
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].text.len(), MAX_LOG_RECORD_BYTES);
        assert_eq!(got[0].seq, 1);
        assert_eq!(got[1].seq, 2);
        assert!(got[1].text.ends_with(crate::redact::REDACTED));
        assert!(got.iter().all(|r| r.stream == LogStream::Stderr));
    }

    #[tokio::test]
    async fn a_line_longer_than_the_raw_cap_is_cut_not_buffered() {
        let c = capture();
        let line = "y".repeat(RAW_LINE_CAP + 10);
        c.read_stream(line.as_bytes(), LogStream::Stdout).await;
        let got = records(&c.queue());
        let total: usize = got.iter().map(|r| r.text.len()).sum();
        assert_eq!(total, RAW_LINE_CAP + 10, "nothing lost, just cut");
        assert!(got.iter().all(|r| r.text.len() <= MAX_LOG_RECORD_BYTES));
    }

    // ----- a secret across the raw cut (red-team review 2026-11-19, G-9) -----

    /// The queue's text for one stream, joined in order.
    fn joined(q: &Queue) -> String {
        let got = records(q);
        assert!(got.iter().all(|r| r.text.len() <= MAX_LOG_RECORD_BYTES));
        got.into_iter().map(|r| r.text).collect()
    }

    #[tokio::test]
    async fn a_secret_across_the_raw_cut_is_redacted() {
        // The cut falls inside the secret: after its first byte, in its middle, before its last.
        for before in [1, 20, PHANTOM.len() - 1] {
            let c = capture();
            let pad = "x".repeat(RAW_LINE_CAP - before);
            let line = format!("{pad}{PHANTOM} tail\n");
            c.read_stream(line.as_bytes(), LogStream::Stdout).await;
            let text = joined(&c.queue());
            let leaked = text.contains(&PHANTOM[..before]) || text.contains(&PHANTOM[before..]);
            assert!(
                !leaked,
                "part of the secret crossed the cut, {before} bytes before it"
            );
            let intact = text == format!("{pad}{} tail", crate::redact::REDACTED);
            assert!(
                intact,
                "nothing else was lost or changed, {before} bytes before the cut"
            );
        }
    }

    #[tokio::test]
    async fn a_secret_across_a_later_cut_or_at_the_end_of_the_pipe_is_redacted() {
        // No newline at all: three cuts, the secret across the third, the pipe closing after.
        let c = capture();
        let pad = "x ".repeat(3 * RAW_LINE_CAP / 2 - 10);
        let input = format!("{pad}{PHANTOM}");
        c.read_stream(input.as_bytes(), LogStream::Stderr).await;
        let text = joined(&c.queue());
        let leaked = text.contains(&PHANTOM[..8]) || text.contains(&PHANTOM[20..]);
        assert!(!leaked, "part of the secret crossed a cut");
        let intact = text == format!("{pad}{}", crate::redact::REDACTED);
        assert!(intact, "nothing else was lost or changed");

        // An `Authorization` value across the cut, with no secret known.
        let c = Arc::new(Capture::new(Vec::new(), Arc::new(Queue::default())).without_console());
        let pad = "x".repeat(RAW_LINE_CAP - 30);
        let line = format!("{pad} Authorization: Bearer abc123def456ghi789 tail\n");
        c.read_stream(line.as_bytes(), LogStream::Stdout).await;
        let text = joined(&c.queue());
        let intact = text
            == format!(
                "{pad} Authorization: Bearer {} tail",
                crate::redact::REDACTED
            );
        assert!(intact, "the value was cut in two and let through");
    }

    #[tokio::test]
    async fn a_char_split_by_the_raw_cut_is_read_whole() {
        let c = capture();
        let line = format!("{}\u{20ac}\u{20ac} end\n", "x".repeat(RAW_LINE_CAP - 1));
        c.read_stream(line.as_bytes(), LogStream::Stdout).await;
        let text = joined(&c.queue());
        assert!(!text.contains('\u{FFFD}'), "the char at the cut was broken");
        assert!(text.ends_with("x\u{20ac}\u{20ac} end"));
        assert_eq!(text.len(), line.len() - 1);
    }

    #[test]
    fn the_start_of_a_char_at_the_end_of_a_read_is_told_from_a_whole_one() {
        assert_eq!(incomplete_utf8_suffix(b""), 0);
        assert_eq!(incomplete_utf8_suffix(b"abc"), 0);
        assert_eq!(incomplete_utf8_suffix("a\u{e9}".as_bytes()), 0);
        assert_eq!(incomplete_utf8_suffix("a\u{20ac}".as_bytes()), 0);
        assert_eq!(incomplete_utf8_suffix("a\u{1f600}".as_bytes()), 0);
        assert_eq!(incomplete_utf8_suffix(&"a\u{e9}".as_bytes()[..2]), 1);
        assert_eq!(incomplete_utf8_suffix(&"a\u{20ac}".as_bytes()[..2]), 1);
        assert_eq!(incomplete_utf8_suffix(&"a\u{20ac}".as_bytes()[..3]), 2);
        assert_eq!(incomplete_utf8_suffix(&"a\u{1f600}".as_bytes()[..4]), 3);
        // Bytes that are no char at all are left to the lossy decoding.
        assert_eq!(incomplete_utf8_suffix(b"a\xff"), 0);
        assert_eq!(incomplete_utf8_suffix(b"\x80\x80\x80"), 0);
    }

    #[tokio::test]
    async fn a_line_many_times_the_raw_cap_keeps_only_the_held_back_end_between_reads() {
        let c = Arc::new(
            Capture::new(
                vec![PHANTOM.to_owned()],
                Arc::new(Queue::new(8 * RAW_LINE_CAP, usize::MAX)),
            )
            .without_console(),
        );
        let line = "y".repeat(5 * RAW_LINE_CAP + 10);
        c.read_stream(line.as_bytes(), LogStream::Stdout).await;
        let text = joined(&c.queue());
        assert_eq!(text.len(), line.len(), "nothing lost, just cut");
    }

    #[test]
    fn a_split_lands_on_char_boundaries() {
        let text = "é".repeat(5); // 10 bytes
        let parts = split_record(&text, 3);
        assert_eq!(parts, vec!["é", "é", "é", "é", "é"]);
        assert_eq!(split_record("", 10), vec![""]);
        assert_eq!(split_record("abc", 10), vec!["abc"]);
    }

    #[tokio::test]
    async fn a_private_key_block_is_dropped_whole_and_invalid_utf8_is_lossy() {
        let c = capture();
        let mut input = b"before\n-----BEGIN PRIVATE KEY-----\nMIIE\nMIIF\n-----END PRIVATE KEY-----\nafter \xff\xfe\n".to_vec();
        input.extend_from_slice(b"");
        c.read_stream(&input[..], LogStream::Stdout).await;
        let texts: Vec<String> = records(&c.queue()).into_iter().map(|r| r.text).collect();
        assert_eq!(
            texts,
            vec![
                "before".to_owned(),
                crate::redact::REDACTED.to_owned(),
                "after \u{FFFD}\u{FFFD}".to_owned()
            ]
        );
    }

    fn record(seq: u64, stream: LogStream, text: &str) -> LogRecord {
        LogRecord {
            seq,
            stream,
            ts: Timestamp::UNIX_EPOCH,
            text: text.to_owned(),
        }
    }

    #[test]
    fn a_full_queue_drops_its_oldest_and_counts_the_bytes_per_stream() {
        let q = Queue::new(100, usize::MAX);
        q.push(record(1, LogStream::Stdout, &"a".repeat(40)));
        q.push(record(2, LogStream::Stderr, &"b".repeat(40)));
        q.push(record(3, LogStream::Stdout, &"c".repeat(40)));
        assert_eq!(q.len(), 2, "the oldest went");
        assert_eq!(q.bytes(), 80);
        let batch = q.take_batch(usize::MAX);
        assert_eq!(batch.dropped_stdout, 40);
        assert_eq!(batch.dropped_stderr, 0);
        assert_eq!(
            batch.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(q.is_empty(), "the counters reset when taken");
        q.push(record(4, LogStream::Stderr, &"d".repeat(60)));
        q.push(record(5, LogStream::Stderr, &"e".repeat(60)));
        let batch = q.take_batch(usize::MAX);
        assert_eq!(batch.dropped_stderr, 60);
        assert_eq!(batch.dropped_stdout, 0);
    }

    #[test]
    fn a_batch_takes_at_least_one_record_and_otherwise_stays_under_its_size() {
        let q = Queue::new(usize::MAX, usize::MAX);
        q.push(record(1, LogStream::Stdout, &"a".repeat(50)));
        q.push(record(2, LogStream::Stdout, &"b".repeat(50)));
        q.push(record(3, LogStream::Stdout, &"c".repeat(50)));
        let b = q.take_batch(120);
        assert_eq!(b.records.len(), 2);
        let b = q.take_batch(10);
        assert_eq!(
            b.records.len(),
            1,
            "a record larger than the batch size still ships"
        );
        assert_eq!(q.len(), 0);
    }

    /// A sink that answers a script, then `Accepted`, and keeps what it was sent.
    struct Scripted {
        outcomes: Mutex<VecDeque<Result<PostOutcome, String>>>,
        posted: Mutex<Vec<LogBatch>>,
    }

    impl Scripted {
        fn new(script: Vec<Result<PostOutcome, String>>) -> Arc<Self> {
            Arc::new(Self {
                outcomes: Mutex::new(script.into()),
                posted: Mutex::new(Vec::new()),
            })
        }

        fn posted(&self) -> Vec<LogBatch> {
            self.posted.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl LogSink for Scripted {
        async fn post(&self, batch: &LogBatch) -> anyhow::Result<PostOutcome> {
            self.posted.lock().unwrap().push(batch.clone());
            match self.outcomes.lock().unwrap().pop_front() {
                Some(Ok(o)) => Ok(o),
                Some(Err(e)) => Err(anyhow::anyhow!(e)),
                None => Ok(PostOutcome::Accepted),
            }
        }
    }

    fn fast() -> ShipperConfig {
        ShipperConfig {
            interval: Duration::from_millis(20),
            batch_bytes: 32 * 1024,
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(40),
        }
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn a_rate_limit_retries_the_same_seq_range_after_the_wait() {
        let sink = Scripted::new(vec![Ok(PostOutcome::RetryAfter(Duration::from_millis(30)))]);
        let q = Arc::new(Queue::default());
        q.push(record(1, LogStream::Stdout, "a"));
        q.push(record(2, LogStream::Stdout, "b"));
        let s = Shipping::start(q.clone(), sink.clone(), fast());
        settle().await;
        let posted = sink.posted();
        assert_eq!(posted.len(), 2, "{posted:?}");
        assert_eq!(posted[0], posted[1], "the same batch, the same seq range");
        assert_eq!(
            posted[0].records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(!s.is_off());
        assert!(s.flush(Duration::from_secs(1)).await);
    }

    #[tokio::test]
    async fn a_broker_without_the_feature_stops_the_shipping_for_the_claim() {
        let sink = Scripted::new(vec![Ok(PostOutcome::Off)]);
        let q = Arc::new(Queue::default());
        q.push(record(1, LogStream::Stdout, "a"));
        let s = Shipping::start(q.clone(), sink.clone(), fast());
        settle().await;
        assert!(s.is_off());
        q.push(record(2, LogStream::Stdout, "b"));
        settle().await;
        assert_eq!(sink.posted().len(), 1, "nothing more is posted");
        assert!(
            s.flush(Duration::from_secs(1)).await,
            "the task already ended"
        );
        assert_eq!(sink.posted().len(), 1);
    }

    #[tokio::test]
    async fn a_transport_failure_retries_the_same_batch_with_backoff() {
        let sink = Scripted::new(vec![
            Err("connection refused".into()),
            Err("timeout".into()),
        ]);
        let q = Arc::new(Queue::default());
        q.push(record(1, LogStream::Stderr, "a"));
        let s = Shipping::start(q.clone(), sink.clone(), fast());
        settle().await;
        let posted = sink.posted();
        assert_eq!(posted.len(), 3, "{posted:?}");
        assert!(posted.iter().all(|b| *b == posted[0]));
        let _flushed = s.flush(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn a_refusal_drops_that_batch_and_shipping_goes_on() {
        let sink = Scripted::new(vec![Ok(PostOutcome::Refused(400))]);
        let q = Arc::new(Queue::default());
        q.push(record(1, LogStream::Stdout, "a"));
        let s = Shipping::start(q.clone(), sink.clone(), fast());
        settle().await;
        q.push(record(2, LogStream::Stdout, "b"));
        settle().await;
        let posted = sink.posted();
        assert_eq!(posted.len(), 2);
        assert_eq!(posted[1].records[0].seq, 2);
        assert!(!s.is_off());
        let _flushed = s.flush(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn flush_posts_what_is_queued_and_ends() {
        let sink = Scripted::new(vec![]);
        let q = Arc::new(Queue::default());
        let cfg = ShipperConfig {
            interval: Duration::from_secs(3600),
            ..fast()
        };
        let s = Shipping::start(q.clone(), sink.clone(), cfg);
        q.push(record(1, LogStream::Stdout, "a"));
        q.push(record(2, LogStream::Stdout, "b"));
        assert!(s.flush(Duration::from_secs(1)).await);
        let posted = sink.posted();
        assert_eq!(posted.len(), 1);
        assert_eq!(posted[0].records.len(), 2);
        assert_eq!(q.len(), 0);
    }

    #[tokio::test]
    async fn a_flush_that_cannot_reach_the_broker_gives_up_at_its_bound() {
        let sink = Scripted::new(vec![Err("down".into()); 100]);
        let q = Arc::new(Queue::default());
        let s = Shipping::start(q.clone(), sink.clone(), fast());
        q.push(record(1, LogStream::Stdout, "a"));
        assert!(!s.flush(Duration::from_millis(100)).await);
    }

    #[tokio::test]
    async fn dropped_counters_travel_with_the_next_batch_and_reset_after_acceptance() {
        let sink = Scripted::new(vec![]);
        let q = Arc::new(Queue::new(100, usize::MAX));
        q.push(record(1, LogStream::Stdout, &"a".repeat(60)));
        q.push(record(2, LogStream::Stderr, &"b".repeat(60)));
        let cfg = ShipperConfig {
            interval: Duration::from_secs(3600),
            ..fast()
        };
        let s = Shipping::start(q.clone(), sink.clone(), cfg);
        q.full.notify_one();
        settle().await;
        q.push(record(3, LogStream::Stdout, "c"));
        assert!(s.flush(Duration::from_secs(1)).await);
        let posted = sink.posted();
        assert_eq!(posted.len(), 2, "{posted:?}");
        assert_eq!(posted[0].dropped_stdout, 60);
        assert_eq!(posted[0].dropped_stderr, 0);
        assert_eq!(posted[1].dropped_stdout, 0);
        assert_eq!(posted[1].dropped_stderr, 0);
        assert_eq!(posted[1].records[0].seq, 3);
    }

    #[tokio::test]
    async fn no_batch_exceeds_the_brokers_limit() {
        let sink = Scripted::new(vec![]);
        let q = Arc::new(Queue::default());
        for i in 0..2048_u64 {
            q.push(record(i + 1, LogStream::Stdout, &"z".repeat(512)));
        }
        let s = Shipping::start(q.clone(), sink.clone(), fast());
        assert!(s.flush(Duration::from_secs(5)).await);
        let posted = sink.posted();
        assert_ne!(posted.len(), 0);
        let total: usize = posted.iter().map(|b| b.records.len()).sum();
        assert_eq!(total, 2048);
        for b in &posted {
            assert!(b.text_bytes() <= mediatore_proto::MAX_LOG_BATCH_BYTES);
            assert!(b.validate().is_ok());
        }
    }

    // ----- control characters in workload output (red-team review 2026-11-19, A-10 / G-8) -----

    #[test]
    fn escape_csi_and_osc_sequences_are_written_out() {
        assert_eq!(neutralise_controls("\x1b"), "\\x1b");
        assert_eq!(
            neutralise_controls("\x1b[31mred\x1b[0m"),
            "\\x1b[31mred\\x1b[0m"
        );
        // OSC 52 (a clipboard write), ended by BEL and by ST.
        assert_eq!(
            neutralise_controls("\x1b]52;c;aGk=\x07"),
            "\\x1b]52;c;aGk=\\x07"
        );
        assert_eq!(
            neutralise_controls("\x1b]0;title\x1b\\"),
            "\\x1b]0;title\\x1b\\"
        );
        // The same introducers as single C1 characters.
        assert_eq!(
            neutralise_controls("\u{9b}31m \u{9d}52;c;aGk=\u{9c}"),
            "\\u{9b}31m \\u{9d}52;c;aGk=\\u{9c}"
        );
    }

    #[test]
    fn every_control_but_the_tab_is_neutralised() {
        for c in (0..=0x1f_u32).chain(0x7f..=0x9f) {
            let c = char::from_u32(c).unwrap();
            let got = neutralise_controls(&format!("a{c}b")).into_owned();
            if c == '\t' {
                assert_eq!(got, "a\tb");
                continue;
            }
            assert!(
                !got.chars().any(char::is_control),
                "U+{:04X} left as itself",
                u32::from(c)
            );
            assert!(got.starts_with("a\\") && got.ends_with('b'));
        }
        assert_eq!(neutralise_controls("\0"), "\\x00");
        assert_eq!(neutralise_controls("\x07"), "\\x07");
        assert_eq!(neutralise_controls("\x7f"), "\\x7f");
        assert_eq!(neutralise_controls("\u{80}\u{9f}"), "\\u{80}\\u{9f}");
        assert_eq!(
            neutralise_controls("progress 10%\rprogress 99%"),
            "progress 10%\\x0dprogress 99%"
        );
        assert_eq!(neutralise_controls("one\ntwo"), "one\\x0atwo");
    }

    #[test]
    fn ordinary_text_is_borrowed_unchanged() {
        for line in [
            "",
            "plain",
            "col\tcol",
            "caf\u{e9} \u{65e5}\u{672c}\u{8a9e} \u{1f980}",
            "a\u{a0}b",
            "<3>looks like a priority",
            "C:\\x1b is only text",
            "token=[REDACTED] Bearer [REDACTED]",
        ] {
            let got = neutralise_controls(line);
            assert!(matches!(got, Cow::Borrowed(_)), "{line:?} was rewritten");
            assert_eq!(got, line);
        }
        assert_eq!(
            crate::redact::REDACTED,
            neutralise_controls(crate::redact::REDACTED)
        );
    }

    #[test]
    fn neutralising_twice_changes_nothing() {
        let once = neutralise_controls("\x1b[2J\u{9b}H\r<3>x\x07").into_owned();
        assert_eq!(neutralise_controls(&once), once);
    }

    #[test]
    fn the_console_copy_starts_with_the_guests_prefix() {
        // A syslog priority, and a line shaped like the guest's own log: neither starts the
        // console line.
        for forged in [
            "<3>disk failure",
            "2026-01-01T00:00:00Z  INFO mediatore: claim bound",
        ] {
            let line = console_line(&neutralise_controls(forged));
            assert_eq!(line, format!("{CONSOLE_PREFIX}{forged}\n"));
            assert!(!line.starts_with('<'));
        }
        // A newline the workload smuggled in does not start a console line of its own.
        let line = console_line(&neutralise_controls("ok\r\n<3>forged"));
        assert_eq!(line, "workload: ok\\x0d\\x0a<3>forged\n");
        assert_eq!(line.matches('\n').count(), 1);
    }

    #[tokio::test]
    async fn the_queue_holds_neutralised_text_and_keeps_redaction() {
        let c = capture();
        let input =
            format!("\x1b]52;c;{PHANTOM}\x07 tab\there \u{9b}2J caf\u{e9}\n<3>next\rline\n");
        c.read_stream(input.as_bytes(), LogStream::Stdout).await;
        let got = records(&c.queue());
        assert_eq!(got.len(), 2);
        assert!(!got[0].text.contains(PHANTOM), "the secret was queued");
        assert_eq!(
            got[0].text,
            format!(
                "\\x1b]52;c;{}\\x07 tab\there \\u{{9b}}2J caf\u{e9}",
                crate::redact::REDACTED
            )
        );
        assert_eq!(got[1].text, "<3>next\\x0dline");
    }

    #[tokio::test]
    async fn the_record_and_batch_limits_hold_after_escaping() {
        // Every byte becomes four: a line under the record limit becomes four records' worth,
        // and one over the raw cap more than the default queue keeps (it would drop its oldest
        // and count them), so this queue is larger and the sum can be checked.
        let batch_bytes = ShipperConfig::default().batch_bytes;
        for len in [MAX_LOG_RECORD_BYTES - 1, RAW_LINE_CAP + 10] {
            let queue = Arc::new(Queue::new(8 * QUEUE_MAX_BYTES, batch_bytes));
            let c = Capture::new(vec![PHANTOM.to_owned()], queue).without_console();
            let mut line = "\x1b".repeat(len);
            line.push('\n');
            c.read_stream(line.as_bytes(), LogStream::Stdout).await;
            let q = c.queue();
            let mut total = 0;
            let mut seq = 0;
            loop {
                let batch = q.take_batch(batch_bytes);
                if batch.records.is_empty() {
                    break;
                }
                assert!(batch.validate().is_ok());
                assert!(batch.text_bytes() <= mediatore_proto::MAX_LOG_BATCH_BYTES);
                for r in &batch.records {
                    assert!(r.text.len() <= MAX_LOG_RECORD_BYTES);
                    assert!(!r.text.chars().any(char::is_control));
                    assert_eq!(r.seq, seq + 1);
                    seq = r.seq;
                    total += r.text.len();
                }
            }
            assert_eq!(total, 4 * len, "nothing lost to the escaping");
        }
    }

    #[test]
    fn the_brokers_statuses_are_read_as_the_adr_says() {
        assert_eq!(classify(204, None), PostOutcome::Accepted);
        assert_eq!(
            classify(429, Some(3)),
            PostOutcome::RetryAfter(Duration::from_secs(3))
        );
        assert_eq!(
            classify(429, None),
            PostOutcome::RetryAfter(Duration::from_secs(LOG_RETRY_AFTER_SECS))
        );
        assert_eq!(classify(501, None), PostOutcome::Off);
        assert_eq!(classify(404, None), PostOutcome::Off, "an older broker");
        assert_eq!(classify(400, None), PostOutcome::Refused(400));
        assert_eq!(classify(413, None), PostOutcome::Refused(413));
        assert_eq!(classify(403, None), PostOutcome::Refused(403));
        assert_eq!(classify(500, None), PostOutcome::Refused(500));
    }
}
