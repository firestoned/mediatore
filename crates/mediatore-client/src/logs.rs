// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! `mediatore sandbox logs` (ADR-0045 decision 9): the query the CLI sends and the reader of
//! the broker's NDJSON answer. The reader prints stdout records to one writer and stderr
//! records to another, so a shell can split them as it would a terminal's; a truncation or a
//! gap is one line on the error writer. Redaction happened in the VM and is best effort; the
//! CLI only prints what the broker stored.

use std::io::Write;

use mediatore_proto::{LogEnd, LogLine, LogStream};

/// What `GET /v1/claims/{name}/logs` takes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogsQuery {
    /// Keep the connection open until the claim ends.
    pub follow: bool,
    /// Only records whose `seq` is greater.
    pub since: Option<u64>,
    /// Only the last `n` records.
    pub tail: Option<u64>,
}

impl LogsQuery {
    /// The query string, `&`-joined, without a leading `?`; empty when nothing is set.
    /// `follow` only when true, `since` and `tail` only when given.
    #[must_use]
    pub fn to_query(&self) -> String {
        let mut parts = Vec::new();
        if self.follow {
            parts.push("follow=true".to_owned());
        }
        if let Some(t) = self.tail {
            parts.push(format!("tail={t}"));
        }
        if let Some(s) = self.since {
            parts.push(format!("since={s}"));
        }
        parts.join("&")
    }
}

/// An incremental reader of the NDJSON stream: fed chunks as they arrive, it prints each
/// complete line and reports the end line when it comes. A chunk boundary inside a line is
/// reassembled; empty keepalive lines are skipped.
pub struct LogPrinter<'a, O: Write, E: Write> {
    out: &'a mut O,
    err: &'a mut E,
    timestamps: bool,
    buf: Vec<u8>,
    /// Lines seen so far, for error messages (the line itself is never echoed: it may carry
    /// what redaction missed).
    lines: usize,
}

impl<'a, O: Write, E: Write> LogPrinter<'a, O, E> {
    /// Print stdout records to `out`, stderr records and the gap and truncation notes to
    /// `err`; `timestamps` prefixes each record with the broker's RFC 3339 time.
    pub fn new(out: &'a mut O, err: &'a mut E, timestamps: bool) -> Self {
        Self {
            out,
            err,
            timestamps,
            buf: Vec::new(),
            lines: 0,
        }
    }

    /// Consume one chunk of the body. Returns the end reason once the end line is read;
    /// anything after it is ignored.
    ///
    /// # Errors
    /// A line that is not a `LogLine`, named by its number, or a writer failing.
    pub fn feed(&mut self, chunk: &[u8]) -> anyhow::Result<Option<LogEnd>> {
        self.buf.extend_from_slice(chunk);
        while let Some(nl) = self.buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=nl).collect();
            if let Some(end) = self.line(&line[..nl])? {
                return Ok(Some(end));
            }
        }
        Ok(None)
    }

    /// The body ended: a last line without a terminator is read; without an end line the
    /// stream was cut and the reader says so.
    ///
    /// # Errors
    /// A malformed last line, or a stream that ended with no end line.
    pub fn finish(&mut self) -> anyhow::Result<LogEnd> {
        let rest = std::mem::take(&mut self.buf);
        if let Some(end) = self.line(&rest)? {
            return Ok(end);
        }
        anyhow::bail!(
            "the log stream ended without an end line after {} lines",
            self.lines
        )
    }

    fn line(&mut self, line: &[u8]) -> anyhow::Result<Option<LogEnd>> {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            // The follower's keepalive.
            return Ok(None);
        }
        self.lines += 1;
        let parsed: LogLine = serde_json::from_slice(line)
            .map_err(|e| anyhow::anyhow!("log line {}: not a log line ({e})", self.lines))?;
        match parsed {
            LogLine::Header(h) => {
                if h.truncated_before > 0 {
                    writeln!(
                        self.err,
                        "[{} bytes of older output dropped by the broker]",
                        h.truncated_before
                    )?;
                }
            }
            LogLine::Record(r) => {
                let prefix = if self.timestamps {
                    format!("{} ", r.ts)
                } else {
                    String::new()
                };
                match r.stream {
                    LogStream::Stdout => writeln!(self.out, "{prefix}{}", r.text)?,
                    LogStream::Stderr => writeln!(self.err, "{prefix}{}", r.text)?,
                }
            }
            LogLine::Gap(g) => writeln!(
                self.err,
                "[{} bytes of stdout and {} bytes of stderr lost before this point]",
                g.lost_stdout, g.lost_stderr
            )?,
            LogLine::End(e) => return Ok(Some(e.reason)),
        }
        Ok(None)
    }
}

/// Read a broker's answer to the end, printing as it comes.
///
/// # Errors
/// The body failing mid-way, a malformed line, or a stream cut before its end line.
pub async fn print_response<O: Write, E: Write>(
    mut resp: reqwest::Response,
    out: &mut O,
    err: &mut E,
    timestamps: bool,
) -> anyhow::Result<LogEnd> {
    let mut printer = LogPrinter::new(out, err, timestamps);
    while let Some(chunk) = resp.chunk().await? {
        if let Some(end) = printer.feed(&chunk)? {
            return Ok(end);
        }
    }
    printer.finish()
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;
    use mediatore_proto::{LogEndLine, LogGap, LogHeader, LogRecord};

    use super::*;

    fn record(seq: u64, stream: LogStream, text: &str) -> String {
        serde_json::to_string(&LogLine::Record(LogRecord {
            seq,
            stream,
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            text: text.into(),
        }))
        .unwrap()
    }

    fn header(truncated_before: u64) -> String {
        serde_json::to_string(&LogLine::Header(LogHeader {
            truncated_before,
            claim_phase: "Bound".into(),
        }))
        .unwrap()
    }

    fn end(reason: LogEnd) -> String {
        serde_json::to_string(&LogLine::End(LogEndLine::new(reason))).unwrap()
    }

    fn stream() -> String {
        [
            header(0),
            record(1, LogStream::Stdout, "first"),
            record(2, LogStream::Stderr, "warn: careful"),
            String::new(),
            serde_json::to_string(&LogLine::Gap(LogGap {
                lost_stdout: 4096,
                lost_stderr: 12,
            }))
            .unwrap(),
            record(9, LogStream::Stdout, "last"),
            end(LogEnd::ClaimEnded),
        ]
        .join("\n")
            + "\n"
    }

    #[test]
    fn the_query_carries_only_what_is_set() {
        assert_eq!(LogsQuery::default().to_query(), "");
        assert_eq!(
            LogsQuery {
                follow: true,
                since: Some(7),
                tail: Some(20),
            }
            .to_query(),
            "follow=true&tail=20&since=7"
        );
        assert_eq!(
            LogsQuery {
                follow: false,
                since: None,
                tail: Some(5),
            }
            .to_query(),
            "tail=5"
        );
    }

    #[test]
    fn stdout_goes_to_out_stderr_and_gaps_to_err_and_the_end_reason_comes_back() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut p = LogPrinter::new(&mut out, &mut err, false);
        let reason = p.feed(stream().as_bytes()).unwrap();
        assert_eq!(reason, Some(LogEnd::ClaimEnded));
        assert_eq!(String::from_utf8(out).unwrap(), "first\nlast\n");
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "warn: careful\n[4096 bytes of stdout and 12 bytes of stderr lost before this point]\n"
        );
    }

    #[test]
    fn a_line_split_across_chunks_is_reassembled_and_keepalives_are_skipped() {
        let text = stream();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut p = LogPrinter::new(&mut out, &mut err, false);
        let mut reason = None;
        // Three bytes at a time: every line is cut somewhere, including inside the JSON.
        for chunk in text.as_bytes().chunks(3) {
            if let Some(r) = p.feed(chunk).unwrap() {
                reason = Some(r);
                break;
            }
        }
        assert_eq!(reason, Some(LogEnd::ClaimEnded));
        assert_eq!(String::from_utf8(out).unwrap(), "first\nlast\n");
        assert!(
            String::from_utf8(err)
                .unwrap()
                .starts_with("warn: careful\n")
        );
    }

    #[test]
    fn timestamps_prefix_each_record_and_a_truncated_header_is_said_once() {
        let text = [
            header(777),
            record(1, LogStream::Stdout, "hello"),
            end(LogEnd::Ttl),
        ]
        .join("\n");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut p = LogPrinter::new(&mut out, &mut err, true);
        // No trailing newline: the end line is read at finish.
        assert_eq!(p.feed(text.as_bytes()).unwrap(), None);
        assert_eq!(p.finish().unwrap(), LogEnd::Ttl);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "2023-11-14T22:13:20Z hello\n"
        );
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "[777 bytes of older output dropped by the broker]\n"
        );
    }

    #[test]
    fn a_stream_cut_before_its_end_line_is_an_error_and_a_bad_line_names_its_number_only() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut p = LogPrinter::new(&mut out, &mut err, false);
        p.feed(format!("{}\n{}\n", header(0), record(1, LogStream::Stdout, "x")).as_bytes())
            .unwrap();
        let e = p.finish().unwrap_err().to_string();
        assert!(e.contains("without an end line"), "{e}");

        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut p = LogPrinter::new(&mut out, &mut err, false);
        let e = p
            .feed(format!("{}\n{{\"token\":\"eyJsecret\"}}\n", header(0)).as_bytes())
            .unwrap_err()
            .to_string();
        assert!(e.contains("log line 2"), "{e}");
        assert!(!e.contains("eyJsecret"), "the line is never echoed: {e}");
    }
}
