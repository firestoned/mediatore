// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! `mediatore sandbox logs` (ADR-0045 decision 9): the query the CLI sends and the reader of
//! the broker's NDJSON answer. The reader prints stdout records to one writer and stderr
//! records to another, so a shell can split them as it would a terminal's; a truncation or a
//! gap is one line on the error writer. Redaction happened in the VM and is best effort; the
//! CLI only prints what the broker stored.
//!
//! A record is a line, or a piece of one (`partial`, ADR-0045 decision 9 as amended
//! 2026-11-20): the guest ships the start of a line that has not ended. The reader writes a
//! piece without a newline and its continuation without a second prefix, so the pieces join
//! into the line the workload wrote, and it ends an open line before anything else is
//! printed, so the two streams never mix inside a line.
//!
//! The text is the workload's, and the store and the broker stand between the guest (which
//! neutralises control characters before it queues a line) and this terminal, so the reader
//! escapes them again ([`escape_controls`]) unless `--raw` asks for the stored text as it is.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::Write;

use mediatore_proto::{LogEnd, LogLine, LogRecord, LogStream};

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

/// Whether `c` is written out as an escape: every C0 control but tab, DEL, and the C1 range
/// (U+0080 to U+009F). That is Unicode's `Cc` category less the tab.
fn is_escaped(c: char) -> bool {
    c != '\t' && c.is_control()
}

/// `text` with every control character but the tab replaced by its visible spelling, the one
/// the guest uses: `\x1b` (backslash, `x`, two lowercase hex digits) for a C0 control or DEL,
/// `\u{9b}` for a C1 control. Everything else is kept, so text the guest already neutralised
/// comes through unchanged. Borrowed when there is nothing to do.
///
/// A record's text was chosen by the workload: an ESC starts a terminal sequence (OSC 52
/// writes the reader's clipboard), a carriage return overwrites what was printed before it,
/// and a newline would start a line that looks like a record of its own.
#[must_use]
pub fn escape_controls(text: &str) -> Cow<'_, str> {
    let Some(first) = text.find(is_escaped) else {
        return Cow::Borrowed(text);
    };
    let mut out = String::with_capacity(text.len() + 16);
    out.push_str(&text[..first]);
    for c in text[first..].chars() {
        if !is_escaped(c) {
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

/// An incremental reader of the NDJSON stream: fed chunks as they arrive, it prints each
/// complete line and reports the end line when it comes. A chunk boundary inside a line is
/// reassembled; empty keepalive lines are skipped.
pub struct LogPrinter<'a, O: Write, E: Write> {
    out: &'a mut O,
    err: &'a mut E,
    timestamps: bool,
    /// Print record text as stored, control characters included (`--raw`).
    raw: bool,
    buf: Vec<u8>,
    /// Lines seen so far, for error messages (the line itself is never echoed: it may carry
    /// what redaction missed).
    lines: usize,
    /// The stream whose last record was `partial`: its line is open, with no newline yet.
    open: Option<LogStream>,
}

impl<'a, O: Write, E: Write> LogPrinter<'a, O, E> {
    /// Print stdout records to `out`, stderr records and the gap and truncation notes to
    /// `err`; `timestamps` prefixes each record with the broker's RFC 3339 time. Control
    /// characters in a record's text are escaped ([`escape_controls`]) unless [`Self::raw`]
    /// turns that off.
    pub fn new(out: &'a mut O, err: &'a mut E, timestamps: bool) -> Self {
        Self {
            out,
            err,
            timestamps,
            raw: false,
            buf: Vec::new(),
            lines: 0,
            open: None,
        }
    }

    /// With `true`, print record text exactly as the broker stored it: for output piped to a
    /// file, not for a terminal.
    #[must_use]
    pub fn raw(mut self, raw: bool) -> Self {
        self.raw = raw;
        self
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
    /// stream was cut and the reader says so. Either way a line left open by a `partial`
    /// record is ended.
    ///
    /// # Errors
    /// A malformed last line, or a stream that ended with no end line.
    pub fn finish(&mut self) -> anyhow::Result<LogEnd> {
        let rest = std::mem::take(&mut self.buf);
        let last = self.line(&rest);
        self.close_open()?;
        if let Some(end) = last? {
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
                    self.close_open()?;
                    writeln!(
                        self.err,
                        "[{} bytes of older output dropped by the broker]",
                        h.truncated_before
                    )?;
                }
            }
            LogLine::Record(r) => self.record(&r)?,
            LogLine::Gap(g) => {
                // What was lost may be the rest of the open line: it ends here.
                self.close_open()?;
                if g.unreadable > 0 {
                    writeln!(
                        self.err,
                        "[{} bytes of output stored here could not be read and are not shown]",
                        g.unreadable
                    )?;
                } else {
                    writeln!(
                        self.err,
                        "[{} bytes of stdout and {} bytes of stderr lost before this point]",
                        g.lost_stdout, g.lost_stderr
                    )?;
                }
            }
            LogLine::End(e) => {
                self.close_open()?;
                return Ok(Some(e.reason));
            }
        }
        Ok(None)
    }

    /// Print one record. A whole line gets its prefix and a newline. A `partial` record gets
    /// no newline and is flushed, so it shows now; the record that continues it on the same
    /// stream gets no prefix, so the pieces read as the one line they were. A record of the
    /// other stream ends the open line first.
    fn record(&mut self, r: &LogRecord) -> anyhow::Result<()> {
        let continues = self.open == Some(r.stream);
        if !continues {
            self.close_open()?;
        }
        let prefix = if self.timestamps && !continues {
            format!("{} ", r.ts)
        } else {
            String::new()
        };
        let text = if self.raw {
            Cow::Borrowed(r.text.as_str())
        } else {
            escape_controls(&r.text)
        };
        let end = if r.partial { "" } else { "\n" };
        match r.stream {
            LogStream::Stdout => write!(self.out, "{prefix}{text}{end}")?,
            LogStream::Stderr => write!(self.err, "{prefix}{text}{end}")?,
        }
        if r.partial {
            // No newline came to flush a line-buffered terminal.
            match r.stream {
                LogStream::Stdout => self.out.flush()?,
                LogStream::Stderr => self.err.flush()?,
            }
            self.open = Some(r.stream);
        } else {
            self.open = None;
        }
        Ok(())
    }

    /// End the line a `partial` record left open, if there is one: a newline on its writer.
    fn close_open(&mut self) -> anyhow::Result<()> {
        match self.open.take() {
            Some(LogStream::Stdout) => writeln!(self.out)?,
            Some(LogStream::Stderr) => writeln!(self.err)?,
            None => {}
        }
        Ok(())
    }
}

/// Read a broker's answer to the end, printing as it comes; `raw` as [`LogPrinter::raw`].
///
/// # Errors
/// The body failing mid-way, a malformed line, or a stream cut before its end line.
pub async fn print_response<O: Write, E: Write>(
    mut resp: reqwest::Response,
    out: &mut O,
    err: &mut E,
    timestamps: bool,
    raw: bool,
) -> anyhow::Result<LogEnd> {
    let mut printer = LogPrinter::new(out, err, timestamps).raw(raw);
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
    use mediatore_proto::{LogEndLine, LogGap, LogHeader};

    use super::*;

    fn record(seq: u64, stream: LogStream, text: &str) -> String {
        serde_json::to_string(&LogLine::Record(LogRecord {
            seq,
            stream,
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            text: text.into(),
            partial: false,
        }))
        .unwrap()
    }

    /// A record that says its line goes on.
    fn piece(seq: u64, stream: LogStream, text: &str) -> String {
        serde_json::to_string(&LogLine::Record(LogRecord {
            seq,
            stream,
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            text: text.into(),
            partial: true,
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
                unreadable: 0,
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

    // ----- control characters in record text (red-team review 2026-11-19, A-10) -----

    /// What a workload would send to take over a terminal: a clipboard write (OSC 52, ended
    /// by BEL), a colour, a carriage return, a C1 CSI, a newline inside the record.
    const HOSTILE: &str = "\x1b]52;c;aGk=\x07\x1b[31mred\rover\u{9b}2J\nforged";
    const HOSTILE_ESCAPED: &str = "\\x1b]52;c;aGk=\\x07\\x1b[31mred\\x0dover\\u{9b}2J\\x0aforged";

    /// What is printed as it is: a tab, text outside ASCII, a redaction marker.
    const PLAIN: &str = "tab\tkept caf\u{e9} \u{65e5}\u{672c} [REDACTED]";

    fn hostile_stream() -> String {
        [
            header(0),
            record(1, LogStream::Stdout, HOSTILE),
            record(2, LogStream::Stderr, HOSTILE),
            record(3, LogStream::Stdout, PLAIN),
            end(LogEnd::ClaimEnded),
        ]
        .join("\n")
            + "\n"
    }

    #[test]
    fn escape_controls_spells_out_every_control_but_the_tab() {
        assert_eq!(escape_controls(HOSTILE), HOSTILE_ESCAPED);
        assert_eq!(
            escape_controls("\0\x08\x7f\u{80}\u{9f}"),
            "\\x00\\x08\\x7f\\u{80}\\u{9f}"
        );
        for c in (0..=0x1f_u32).chain(0x7f..=0x9f) {
            let c = char::from_u32(c).unwrap();
            let got = escape_controls(&format!("a{c}b")).into_owned();
            assert_eq!(
                got.chars().any(char::is_control),
                c == '\t',
                "U+{:04X}",
                u32::from(c)
            );
        }
        for kept in [
            "",
            "plain",
            "a\tb",
            "caf\u{e9} \u{1f980} a\u{a0}b",
            "<3>text",
            "[REDACTED]",
            HOSTILE_ESCAPED,
        ] {
            let got = escape_controls(kept);
            assert!(matches!(got, Cow::Borrowed(_)), "{kept:?} was rewritten");
            assert_eq!(got, kept);
        }
    }

    #[test]
    fn control_characters_in_a_record_are_escaped_on_both_writers() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut p = LogPrinter::new(&mut out, &mut err, false);
        assert_eq!(
            p.feed(hostile_stream().as_bytes()).unwrap(),
            Some(LogEnd::ClaimEnded)
        );
        let (out, err) = (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        );
        assert_eq!(out, format!("{HOSTILE_ESCAPED}\n{PLAIN}\n"));
        assert_eq!(err, format!("{HOSTILE_ESCAPED}\n"));
        // One line per record: nothing the workload sent starts a line of its own.
        assert_eq!(out.lines().count(), 2);
        assert!(
            !out.chars()
                .chain(err.chars())
                .any(|c| c != '\n' && c != '\t' && c.is_control())
        );
    }

    #[test]
    fn timestamps_stay_in_front_of_an_escaped_record() {
        let text = [
            record(1, LogStream::Stdout, "\rspoofed"),
            end(LogEnd::ClaimEnded),
        ]
        .join("\n");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut p = LogPrinter::new(&mut out, &mut err, true);
        p.feed(text.as_bytes()).unwrap();
        assert_eq!(p.finish().unwrap(), LogEnd::ClaimEnded);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "2023-11-14T22:13:20Z \\x0dspoofed\n"
        );
    }

    #[test]
    fn raw_prints_the_stored_text_as_it_is() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut p = LogPrinter::new(&mut out, &mut err, false).raw(true);
        assert_eq!(
            p.feed(hostile_stream().as_bytes()).unwrap(),
            Some(LogEnd::ClaimEnded)
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{HOSTILE}\n{PLAIN}\n")
        );
        assert_eq!(String::from_utf8(err).unwrap(), format!("{HOSTILE}\n"));
    }

    // ----- a line in pieces (ADR-0045 decision 9, amended 2026-11-20) -----

    /// What both writers got for `lines`, each ended by a newline, and the end reason.
    fn printed(lines: &[String], timestamps: bool, raw: bool) -> (String, String, LogEnd) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut p = LogPrinter::new(&mut out, &mut err, timestamps).raw(raw);
        let reason = p
            .feed((lines.join("\n") + "\n").as_bytes())
            .unwrap()
            .expect("an end line");
        (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
            reason,
        )
    }

    #[test]
    fn the_pieces_of_a_line_join_into_one_line_with_one_prefix() {
        let lines = [
            header(0),
            piece(1, LogStream::Stdout, "Thinking"),
            piece(2, LogStream::Stdout, "..."),
            record(3, LogStream::Stdout, " done"),
            record(4, LogStream::Stdout, "next line"),
            end(LogEnd::ClaimEnded),
        ];
        let (out, err, reason) = printed(&lines, false, false);
        assert_eq!(out, "Thinking... done\nnext line\n");
        assert!(err.is_empty(), "nothing for the error writer: {err}");
        assert_eq!(reason, LogEnd::ClaimEnded);
        // With timestamps: once, in front of the line, not in front of each piece.
        let (out, _, _) = printed(&lines, true, false);
        assert_eq!(
            out,
            "2023-11-14T22:13:20Z Thinking... done\n2023-11-14T22:13:20Z next line\n"
        );
    }

    #[test]
    fn a_record_of_the_other_stream_ends_an_open_line_first() {
        let lines = [
            piece(1, LogStream::Stdout, "half of a line"),
            record(2, LogStream::Stderr, "warn: careful"),
            record(3, LogStream::Stdout, " and its end"),
            piece(4, LogStream::Stderr, "an open error"),
            record(5, LogStream::Stdout, "out again"),
            end(LogEnd::ClaimEnded),
        ];
        let (out, err, _) = printed(&lines, true, false);
        // The open stdout line is ended before stderr prints, and what follows it on stdout
        // is a line of its own, with its own prefix.
        assert_eq!(
            out,
            "2023-11-14T22:13:20Z half of a line\n2023-11-14T22:13:20Z  and its end\n2023-11-14T22:13:20Z out again\n"
        );
        assert_eq!(
            err,
            "2023-11-14T22:13:20Z warn: careful\n2023-11-14T22:13:20Z an open error\n"
        );
    }

    #[test]
    fn a_gap_ends_an_open_line_before_its_note() {
        let lines = [
            piece(1, LogStream::Stderr, "cut off"),
            serde_json::to_string(&LogLine::Gap(LogGap {
                lost_stdout: 0,
                lost_stderr: 9,
                unreadable: 0,
            }))
            .unwrap(),
            record(7, LogStream::Stderr, "after"),
            end(LogEnd::ClaimEnded),
        ];
        let (out, err, _) = printed(&lines, false, false);
        assert!(out.is_empty(), "nothing on stdout: {out}");
        assert_eq!(
            err,
            "cut off\n[0 bytes of stdout and 9 bytes of stderr lost before this point]\nafter\n"
        );
    }

    #[test]
    fn the_end_of_the_stream_ends_an_open_line() {
        // An end line.
        let lines = [piece(1, LogStream::Stdout, "prompt> "), end(LogEnd::Client)];
        let (out, _, reason) = printed(&lines, false, false);
        assert_eq!(out, "prompt> \n");
        assert_eq!(reason, LogEnd::Client);
        // A stream cut before its end line: still an error, and the line is still ended.
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut p = LogPrinter::new(&mut out, &mut err, false);
        p.feed(format!("{}\n", piece(1, LogStream::Stderr, "cut")).as_bytes())
            .unwrap();
        assert!(p.finish().is_err(), "no end line");
        assert_eq!(String::from_utf8(err).unwrap(), "cut\n");
        assert!(out.is_empty(), "nothing on stdout");
    }

    #[test]
    fn raw_joins_pieces_the_same_way_and_escaping_applies_to_each_piece() {
        let lines = [
            piece(1, LogStream::Stdout, "\x1b[31mred"),
            record(2, LogStream::Stdout, "\rover"),
            end(LogEnd::ClaimEnded),
        ];
        let (out, _, _) = printed(&lines, false, true);
        assert_eq!(out, "\x1b[31mred\rover\n");
        let (out, _, _) = printed(&lines, false, false);
        assert_eq!(out, "\\x1b[31mred\\x0dover\n");
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
