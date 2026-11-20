// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Redaction of the workload's output before it leaves the VM (ADR-0045 decision 2).
//!
//! Best effort, not a guarantee: it removes the secrets the guest knows it placed in the jail
//! (literally, and in their base64 and percent-encoded forms) and what has the *shape* of a
//! credential (a JWT, an `Authorization` header value, a PEM private key). It cannot catch a
//! secret the workload transforms, one the guest never saw, or data that is not a credential.
//! The security argument must not rest on it; the owner-only read and the cap and TTL bound
//! the exposure (ADR-0045 decisions 4 and 5).
//!
//! The unit is a whole line, so a secret inside a line is matched however the pipe was read.
//! A caller that splits an overlong line must redact first and split after. A caller that
//! cannot hold a whole line (the reader cuts one at its raw cap) gives each cut piece to
//! [`Redactor::redact_head`], which redacts what is safe to let go and says how much of the
//! piece it held back, and the end of the line to [`Redactor::redact_line`]: a secret that
//! lies across a cut is then seen whole.

use std::fmt::Write as _;
use std::ops::Range;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

/// What a redacted span is replaced with.
pub const REDACTED: &str = "[REDACTED]";

/// Secrets shorter than this are not matched literally: a short environment value would redact
/// ordinary words and teach users to distrust the tool (ADR-0045 decision 2). The shape rules
/// still apply to them.
pub const MIN_SECRET_BYTES: usize = 8;

/// A JWT's header is base64url of `{"`, which always begins with this.
const JWT_PREFIX: &str = "eyJ";

/// Dots in a JWT: three segments.
const JWT_DOTS: usize = 2;

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";
const PEM_PRIVATE_KEY: &str = "PRIVATE KEY-----";
const AUTHORIZATION: &str = "authorization";
const AUTH_SCHEMES: [&str; 2] = ["bearer ", "basic "];

/// The least [`Redactor::redact_head`] holds back at a cut, whatever the secrets: enough for
/// what a shape rule needs before the value starts (a PEM boundary line, `Authorization`, its
/// separators and the scheme) to reach the next piece whole.
const SHAPE_HOLD_BYTES: usize = 256;

/// The longest value still running at a cut (an `Authorization` value, a run that may be a
/// JWT) that is held back whole. A longer one is replaced where it starts and dropped to its
/// end, so what is held across a cut stays bounded whatever the workload writes.
const SHAPE_RUN_MAX: usize = 16 * 1024;

/// The set of secrets to remove, and the state of a PEM block in progress.
#[derive(Debug, Default)]
pub struct Redactor {
    /// Literal forms to remove, longest first so a secret that contains another is removed whole.
    literals: Vec<String>,
    /// Inside a private key block: every line is dropped until its `END` line.
    in_pem: bool,
    /// Inside a value [`Redactor::redact_head`] replaced before its end (longer than
    /// [`SHAPE_RUN_MAX`]): the rest of the line is dropped up to the value's end.
    in_value: bool,
}

impl Redactor {
    /// An empty set: only the shape rules apply.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a secret the jail was given or the guest fetched for this claim (ADR-0045 decision
    /// 2). Under [`MIN_SECRET_BYTES`] it is ignored. Its standard base64, URL-safe base64 and
    /// percent-encoded forms are added too.
    pub fn add_secret(&mut self, value: &str) {
        if value.len() < MIN_SECRET_BYTES {
            return;
        }
        let forms = [
            value.to_owned(),
            STANDARD.encode(value),
            URL_SAFE_NO_PAD.encode(value),
            percent_encode(value),
        ];
        for form in forms {
            if form.len() >= MIN_SECRET_BYTES && !self.literals.contains(&form) {
                self.literals.push(form);
            }
        }
        self.literals.sort_by_key(|l| std::cmp::Reverse(l.len()));
    }

    /// Redact one line (no terminator), or the end of a line whose earlier pieces went to
    /// [`Redactor::redact_head`]. `None` means the line is part of a private key block and is
    /// dropped (or is the end of a value already replaced); the line that opens the block
    /// yields [`REDACTED`] alone, so a reader sees that something was removed.
    pub fn redact_line(&mut self, line: &str) -> Option<String> {
        let swallowing = self.in_value;
        let line = self.skip_value(line);
        // A value does not outlive its line.
        self.in_value = false;
        if swallowing && line.is_empty() {
            return None;
        }
        if self.in_pem {
            if is_pem_end(line) {
                self.in_pem = false;
            }
            return None;
        }
        if is_pem_begin(line) {
            // A one-line block (BEGIN and END together) does not open one.
            self.in_pem = !is_pem_end(line);
            return Some(REDACTED.to_owned());
        }
        Some(apply(line, &self.spans(line), line.len()))
    }

    /// How many bytes [`Redactor::redact_head`] holds back at least: one less than the longest
    /// literal form, so a secret that starts before a cut is whole in what is read next, and
    /// never under [`SHAPE_HOLD_BYTES`].
    #[must_use]
    pub fn hold_back(&self) -> usize {
        self.literals
            .first()
            .map_or(0, |l| l.len().saturating_sub(1))
            .max(SHAPE_HOLD_BYTES)
    }

    /// Redact a piece of a line that was cut before its end. Returns the text to let go now
    /// (`None` when there is none: all of it held back, or dropped as part of a private key
    /// block) and how many bytes of `piece` that covers. The caller keeps `piece[covered..]`,
    /// unredacted and in memory only, in front of what it reads next, and gives the end of
    /// the line to [`Redactor::redact_line`].
    ///
    /// Held back: the last [`Redactor::hold_back`] bytes, and from its start any value that
    /// lies across that point or is still running at the end of the piece. So nothing is let
    /// go that the next bytes could turn into a secret. A running value longer than
    /// [`SHAPE_RUN_MAX`] is not held: it is replaced where it starts and dropped up to its
    /// end (white space or a quote), in this piece and the ones after it.
    pub fn redact_head(&mut self, piece: &str) -> (Option<String>, usize) {
        let rest = self.skip_value(piece);
        if self.in_value {
            return (None, piece.len());
        }
        let skipped = piece.len() - rest.len();
        let hold = self.hold_back();
        let floor = floor_char_boundary(rest, rest.len().saturating_sub(hold));
        if self.in_pem {
            if is_pem_end(rest) && !pem_left_open(rest) {
                self.in_pem = false;
                return (None, piece.len());
            }
            // The END line may lie across the cut.
            return (None, skipped + floor);
        }
        if is_pem_begin(rest) {
            if !pem_left_open(rest) {
                return (Some(REDACTED.to_owned()), piece.len());
            }
            self.in_pem = true;
            return (Some(REDACTED.to_owned()), skipped + floor);
        }
        let spans = self.spans(rest);
        let mut cut = floor;
        if let Some(running) = running_value(rest, &spans) {
            cut = cut.min(running);
        }
        if let Some(across) = spans.iter().find(|s| s.start < cut && cut < s.end) {
            cut = across.start;
        }
        let mut out = apply(rest, &spans, cut);
        let mut covered = cut;
        if cut < floor && rest.len() - cut > 2 * hold + SHAPE_RUN_MAX {
            out.push_str(REDACTED);
            self.in_value = true;
            covered = rest.len();
        }
        ((!out.is_empty()).then_some(out), skipped + covered)
    }

    /// `text` without the rest of a value that [`Redactor::redact_head`] replaced before its
    /// end: from the value's end on, or nothing when the value is still running.
    fn skip_value<'a>(&mut self, text: &'a str) -> &'a str {
        if !self.in_value {
            return text;
        }
        if let Some(end) = text.find(is_value_end) {
            self.in_value = false;
            &text[end..]
        } else {
            ""
        }
    }

    /// The byte ranges of `line` to replace: every literal, every `Authorization` value and
    /// every JWT, found in the line as it was written, sorted, with overlapping ranges joined.
    fn spans(&self, line: &str) -> Vec<Range<usize>> {
        let mut spans = Vec::new();
        for literal in &self.literals {
            spans.extend(
                line.match_indices(literal.as_str())
                    .map(|(at, found)| at..at + found.len()),
            );
        }
        authorization_spans(line, &mut spans);
        jwt_spans(line, &mut spans);
        spans.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));
        let mut joined: Vec<Range<usize>> = Vec::with_capacity(spans.len());
        for s in spans {
            if let Some(last) = joined.last_mut()
                && s.start < last.end
            {
                last.end = last.end.max(s.end);
            } else {
                joined.push(s);
            }
        }
        joined
    }
}

/// `text[..upto]` with every span that ends by `upto` replaced. The spans are sorted and
/// disjoint, and none lies across `upto`.
fn apply(text: &str, spans: &[Range<usize>], upto: usize) -> String {
    let mut out = String::with_capacity(upto);
    let mut at = 0;
    for s in spans.iter().take_while(|s| s.end <= upto) {
        out.push_str(&text[at..s.start]);
        out.push_str(REDACTED);
        at = s.end;
    }
    out.push_str(&text[at..upto]);
    out
}

/// The nearest char boundary of `text` at or before `at`.
fn floor_char_boundary(text: &str, mut at: usize) -> usize {
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// Where a value that is still running at the end of a cut piece starts: a span that reaches
/// the end, or a closing run that is, or may yet become, a JWT.
fn running_value(text: &str, spans: &[Range<usize>]) -> Option<usize> {
    let span = spans
        .last()
        .filter(|s| s.end == text.len())
        .map(|s| s.start);
    // JWT characters are ASCII, so the count of chars is the count of bytes.
    let run = text.len() - text.chars().rev().take_while(|c| is_jwt_char(*c)).count();
    let tail = &text[run..];
    let jwt = (!tail.is_empty() && (tail.starts_with(JWT_PREFIX) || JWT_PREFIX.starts_with(tail)))
        .then_some(run);
    match (span, jwt) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// What ends a value: white space or a quote.
fn is_value_end(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'')
}

fn is_pem_begin(line: &str) -> bool {
    line.contains(PEM_BEGIN) && line.contains(PEM_PRIVATE_KEY)
}

fn is_pem_end(line: &str) -> bool {
    line.contains(PEM_END) && line.contains(PEM_PRIVATE_KEY)
}

/// Whether the last private key boundary in `text` is a `BEGIN`: the block it opens is not
/// closed in this text. A piece of a cut line can hold the `BEGIN` line whole and the `END`
/// line in part, which [`is_pem_end`] alone would read as closed.
fn pem_left_open(text: &str) -> bool {
    text.rfind(PEM_PRIVATE_KEY)
        .is_some_and(|key| text[..key].rfind(PEM_BEGIN) > text[..key].rfind(PEM_END))
}

/// Percent-encode everything outside RFC 3986's unreserved set.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The value after every `Authorization: Bearer|Basic ` on the line (header or JSON-ish, any
/// case): each occurrence, not the first alone.
fn authorization_spans(line: &str, spans: &mut Vec<Range<usize>>) {
    // ASCII lowercasing keeps every byte offset.
    let lower = line.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find(AUTHORIZATION) {
        let after_name = from + at + AUTHORIZATION.len();
        from = after_name;
        let rest = &lower[after_name..];
        let skipped = rest
            .find(|c: char| !matches!(c, ':' | '"' | '\'' | '=' | ' ' | '\t'))
            .unwrap_or(rest.len());
        let value_region = &rest[skipped..];
        let Some(scheme) = AUTH_SCHEMES.iter().find(|s| value_region.starts_with(**s)) else {
            continue;
        };
        let value_start = after_name + skipped + scheme.len();
        let value_len = line[value_start..]
            .find(is_value_end)
            .unwrap_or(line.len() - value_start);
        if value_len > 0 {
            spans.push(value_start..value_start + value_len);
        }
    }
}

fn is_jwt_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
}

/// Whether a run of JWT characters has a JWT's shape: `eyJ` first, two dots.
fn is_jwt(run: &str) -> bool {
    run.starts_with(JWT_PREFIX) && run.matches('.').count() == JWT_DOTS
}

/// Every run that has a JWT's shape: base64url segments, two dots, `eyJ` first.
fn jwt_spans(line: &str, spans: &mut Vec<Range<usize>>) {
    let mut start = None;
    // One char past the end closes a run that reaches it.
    for (i, c) in line
        .char_indices()
        .chain(std::iter::once((line.len(), ' ')))
    {
        match (is_jwt_char(c), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if is_jwt(&line[s..i]) {
                    spans.push(s..i);
                }
                start = None;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-phantom-value-0123456789";
    const JWT: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl";

    fn with(secret: &str) -> Redactor {
        let mut r = Redactor::new();
        r.add_secret(secret);
        r
    }

    #[test]
    fn a_known_secret_is_removed_wherever_it_appears_in_the_line() {
        let mut r = with(SECRET);
        let line = format!("token={SECRET} and again {SECRET}!");
        assert_eq!(
            r.redact_line(&line).unwrap(),
            format!("token={REDACTED} and again {REDACTED}!")
        );
    }

    #[test]
    fn its_base64_and_percent_encoded_forms_are_removed_too() {
        let mut r = with("p@ss word/value+1");
        for form in [
            STANDARD.encode("p@ss word/value+1"),
            URL_SAFE_NO_PAD.encode("p@ss word/value+1"),
            percent_encode("p@ss word/value+1"),
            "p@ss word/value+1".to_owned(),
        ] {
            let out = r.redact_line(&format!("x {form} y")).unwrap();
            assert_eq!(out, format!("x {REDACTED} y"), "form {form}");
        }
    }

    #[test]
    fn a_short_value_is_not_matched_literally() {
        let mut r = with("hello");
        assert_eq!(r.redact_line("hello world").unwrap(), "hello world");
        let mut r = with("1234567");
        assert_eq!(r.redact_line("code 1234567").unwrap(), "code 1234567");
        let mut r = with("12345678");
        assert_eq!(
            r.redact_line("code 12345678").unwrap(),
            format!("code {REDACTED}")
        );
    }

    #[test]
    fn a_secret_containing_another_is_removed_whole() {
        let mut r = Redactor::new();
        r.add_secret("abcdefgh");
        r.add_secret("abcdefgh-and-more");
        assert_eq!(
            r.redact_line("v=abcdefgh-and-more").unwrap(),
            format!("v={REDACTED}")
        );
    }

    #[test]
    fn a_jwt_is_removed_by_shape_with_no_secret_known() {
        let mut r = Redactor::new();
        assert_eq!(
            r.redact_line(&format!("got {JWT}, ok")).unwrap(),
            format!("got {REDACTED}, ok")
        );
        // Not a JWT: wrong prefix, or not three segments.
        assert_eq!(r.redact_line("abc.def.ghi").unwrap(), "abc.def.ghi");
        assert_eq!(
            r.redact_line("eyJhbGci.only-two").unwrap(),
            "eyJhbGci.only-two"
        );
        assert_eq!(r.redact_line("a.b.c.d.eyJ").unwrap(), "a.b.c.d.eyJ");
    }

    #[test]
    fn an_authorization_header_value_is_removed_in_any_case() {
        let mut r = Redactor::new();
        for (line, want) in [
            (
                "Authorization: Bearer abc123",
                format!("Authorization: Bearer {REDACTED}"),
            ),
            (
                "authorization: basic dXNlcjpwdw==",
                format!("authorization: basic {REDACTED}"),
            ),
            (
                r#"{"Authorization": "Bearer abc123", "x": 1}"#,
                format!(r#"{{"Authorization": "Bearer {REDACTED}", "x": 1}}"#),
            ),
        ] {
            assert_eq!(r.redact_line(line).unwrap(), want, "{line}");
        }
        // The word alone, or another scheme, is left.
        assert_eq!(
            r.redact_line("Authorization failed").unwrap(),
            "Authorization failed"
        );
        assert_eq!(
            r.redact_line("Authorization: Digest x").unwrap(),
            "Authorization: Digest x"
        );
    }

    /// A PEM boundary line built at run time. The source never holds a contiguous private-key
    /// header, so a push-time secret scanner has no literal to match (the body lines in these
    /// tests are not key material either).
    fn pem(edge: &str, kind: &str) -> String {
        format!("{}{edge} {kind}{}", "-----", "-----")
    }

    #[test]
    fn a_private_key_block_is_dropped_from_begin_to_end() {
        let mut r = Redactor::new();
        assert_eq!(r.redact_line("before").unwrap(), "before");
        assert_eq!(
            r.redact_line(&pem("BEGIN", "RSA PRIVATE KEY")).unwrap(),
            REDACTED
        );
        assert_eq!(r.redact_line("MIIEowIBAAKCAQEA").as_deref(), None);
        assert_eq!(r.redact_line("more+key/material==").as_deref(), None);
        assert_eq!(
            r.redact_line(&pem("END", "RSA PRIVATE KEY")).as_deref(),
            None
        );
        assert_eq!(r.redact_line("after").unwrap(), "after", "the block ended");
    }

    #[test]
    fn an_unterminated_private_key_block_drops_everything_after_it() {
        let mut r = Redactor::new();
        assert_eq!(
            r.redact_line(&pem("BEGIN", "PRIVATE KEY")).unwrap(),
            REDACTED
        );
        assert!(r.redact_line("still key").is_none());
        assert!(
            r.redact_line("and still").is_none(),
            "a partial key must not leak"
        );
    }

    #[test]
    fn a_public_certificate_is_not_a_private_key() {
        let mut r = Redactor::new();
        assert_eq!(
            r.redact_line("-----BEGIN CERTIFICATE-----").unwrap(),
            "-----BEGIN CERTIFICATE-----"
        );
    }

    #[test]
    fn ordinary_output_is_untouched() {
        let mut r = with(SECRET);
        for line in [
            "",
            "hello, world",
            "result: 42",
            "tokens used: 1234",
            "   indented",
        ] {
            assert_eq!(r.redact_line(line).unwrap(), line);
        }
    }

    #[test]
    fn adding_the_same_secret_twice_adds_nothing() {
        let mut r = with(SECRET);
        let n = r.literals.len();
        r.add_secret(SECRET);
        assert_eq!(r.literals.len(), n);
    }

    // ----- every occurrence, and a line cut before its end (red-team review 2026-11-19, G-9) -----

    #[test]
    fn every_authorization_value_on_a_line_is_removed_not_only_the_first() {
        let mut r = Redactor::new();
        assert_eq!(
            r.redact_line(
                "Authorization: Bearer abc123 then authorization: basic dXNlcjpwdw== end"
            )
            .unwrap(),
            format!("Authorization: Bearer {REDACTED} then authorization: basic {REDACTED} end")
        );
        // An occurrence with no value does not hide the one after it.
        assert_eq!(
            r.redact_line(r#"Authorization failed; sent {"Authorization": "Bearer abc123"} and Proxy-Authorization: Basic eHh4"#)
                .unwrap(),
            format!(
                r#"Authorization failed; sent {{"Authorization": "Bearer {REDACTED}"}} and Proxy-Authorization: Basic {REDACTED}"#
            )
        );
    }

    #[test]
    fn overlapping_matches_are_replaced_once() {
        let mut r = with(SECRET);
        assert_eq!(
            r.redact_line(&format!("Authorization: Bearer {SECRET} x={JWT}{SECRET}"))
                .unwrap(),
            format!("Authorization: Bearer {REDACTED} x={REDACTED}"),
            "a secret that is an Authorization value, and one that runs on from a JWT"
        );
    }

    /// A line cut at `at`: the head through `redact_head`, what it held back and the rest
    /// through `redact_line`, as the reader does. The two outputs joined.
    fn cut_at(r: &mut Redactor, line: &str, at: usize) -> String {
        let (head, covered) = r.redact_head(&line[..at]);
        assert!(covered <= at);
        let rest = format!("{}{}", &line[covered..at], &line[at..]);
        let tail = r.redact_line(&rest);
        format!("{}{}", head.unwrap_or_default(), tail.unwrap_or_default())
    }

    #[test]
    fn a_secret_across_a_cut_is_removed_wherever_the_cut_falls() {
        let line = format!("{}{SECRET} end", "x".repeat(1000));
        let want = format!("{}{REDACTED} end", "x".repeat(1000));
        for at in 990..=1000 + SECRET.len() + 2 {
            let mut r = with(SECRET);
            let whole = cut_at(&mut r, &line, at) == want;
            assert!(whole, "a cut at byte {at} let part of the secret through");
        }
    }

    #[test]
    fn what_is_held_back_at_a_cut_is_one_less_than_the_longest_literal_and_never_under_the_floor() {
        assert_eq!(Redactor::new().hold_back(), SHAPE_HOLD_BYTES);
        assert_eq!(with(SECRET).hold_back(), SHAPE_HOLD_BYTES);
        let long = "0123456789abcdef".repeat(64);
        let r = with(&long);
        let longest = r.literals.iter().map(String::len).max().unwrap();
        assert!(longest > long.len(), "the base64 form is the longest");
        assert_eq!(r.hold_back(), longest - 1);
        // An ordinary piece: all but the held-back end is let go, unchanged.
        let mut r = with(SECRET);
        let piece = "ordinary output ".repeat(100);
        let (head, covered) = r.redact_head(&piece);
        assert_eq!(covered, piece.len() - SHAPE_HOLD_BYTES);
        assert_eq!(head.as_deref(), Some(&piece[..covered]));
        // A piece shorter than what is held back: nothing is let go yet.
        assert_eq!(r.redact_head("short"), (None, 0));
    }

    #[test]
    fn a_jwt_or_an_authorization_value_across_a_cut_is_removed() {
        let pad = "x ".repeat(400);
        for (line, want) in [
            (
                format!("{pad}got {JWT} ok"),
                format!("{pad}got {REDACTED} ok"),
            ),
            (
                format!("{pad}Authorization: Bearer abc123def456 ok"),
                format!("{pad}Authorization: Bearer {REDACTED} ok"),
            ),
        ] {
            for at in pad.len()..line.len() {
                let mut r = Redactor::new();
                let whole = cut_at(&mut r, &line, at) == want;
                assert!(whole, "a cut at byte {at} let part of the value through");
            }
        }
    }

    #[test]
    fn a_cut_never_lands_inside_a_char_or_a_value_before_the_held_back_end() {
        // A value that ends well before the cut is replaced and let go; a multi-byte char at
        // the point where the held-back end starts is held whole.
        let mut r = with(SECRET);
        let piece = format!("{SECRET} {}", "\u{20ac}".repeat(300));
        assert!(!piece.is_char_boundary(piece.len() - SHAPE_HOLD_BYTES));
        let (head, covered) = r.redact_head(&piece);
        assert!(piece.is_char_boundary(covered));
        assert!(piece.len() - covered >= SHAPE_HOLD_BYTES);
        assert!(head.unwrap().starts_with(&format!("{REDACTED} ")));
    }

    #[test]
    fn a_value_too_long_to_hold_is_replaced_where_it_starts_and_dropped_to_its_end() {
        let mut r = Redactor::new();
        let giant = format!("eyJ{}", "A".repeat(2 * SHAPE_RUN_MAX));
        let piece = format!("before {giant}");
        assert_eq!(
            r.redact_head(&piece),
            (Some(format!("before {REDACTED}")), piece.len()),
            "nothing of it is held: memory stays bounded"
        );
        // The next piece is still inside the value: dropped whole.
        assert_eq!(r.redact_head(&"A".repeat(1000)), (None, 1000));
        // The value ends at white space; what follows is ordinary output again.
        assert_eq!(r.redact_line("AAAA.bbbb.cccc after").unwrap(), " after");
        assert_eq!(r.redact_line("a new line").unwrap(), "a new line");

        // A line that ends inside the value leaves nothing, and the next line is not part of it.
        let mut r = Redactor::new();
        let _ = r.redact_head(&piece);
        assert_eq!(r.redact_line("AAAA"), None);
        assert_eq!(r.redact_line("AAAA next line").unwrap(), "AAAA next line");
    }

    #[test]
    fn a_private_key_block_that_opens_or_closes_across_a_cut_is_still_dropped() {
        let begin = pem("BEGIN", "RSA PRIVATE KEY");
        let end = pem("END", "RSA PRIVATE KEY");
        let pad = "x ".repeat(400);
        // The BEGIN line cut in two: the first piece lets go ordinary output only.
        let line = format!("{pad}{begin} MIIEowIBAAKCAQEA");
        let at = pad.len() + 14;
        let mut r = Redactor::new();
        let (head, covered) = r.redact_head(&line[..at]);
        assert!(covered <= pad.len());
        assert_eq!(head.as_deref(), Some(&pad[..covered]));
        assert_eq!(r.redact_line(&line[covered..]).unwrap(), REDACTED);
        assert_eq!(r.redact_line("more+key/material=="), None);
        assert_eq!(r.redact_line(&end), None);
        assert_eq!(r.redact_line("after").unwrap(), "after");

        // The END marker cut in two inside one overlong line: nothing after BEGIN is let go
        // until a piece holds END whole.
        let body = "MIIE".repeat(200);
        let line = format!("{begin} {body} {end}");
        let at = line.len() - 9;
        let mut r = Redactor::new();
        let (head, covered) = r.redact_head(&line[..at]);
        assert_eq!(head.as_deref(), Some(REDACTED));
        assert!(
            covered < at,
            "the end of the piece is held for the END marker"
        );
        assert_eq!(r.redact_line(&line[covered..]), None);
        assert_eq!(r.redact_line("after").unwrap(), "after", "the block ended");
    }
}
