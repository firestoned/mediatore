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
//! A caller that splits an overlong line must redact first and split after.

use std::fmt::Write as _;

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

/// The set of secrets to remove, and the state of a PEM block in progress.
#[derive(Debug, Default)]
pub struct Redactor {
    /// Literal forms to remove, longest first so a secret that contains another is removed whole.
    literals: Vec<String>,
    /// Inside a private key block: every line is dropped until its `END` line.
    in_pem: bool,
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

    /// Redact one line (no terminator). `None` means the line is part of a private key block
    /// and is dropped; the line that opens the block yields [`REDACTED`] alone, so a reader
    /// sees that something was removed.
    pub fn redact_line(&mut self, line: &str) -> Option<String> {
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
        let mut out = line.to_owned();
        for literal in &self.literals {
            if out.contains(literal.as_str()) {
                out = out.replace(literal.as_str(), REDACTED);
            }
        }
        out = redact_authorization(&out);
        Some(redact_jwts(&out))
    }
}

fn is_pem_begin(line: &str) -> bool {
    line.contains(PEM_BEGIN) && line.contains(PEM_PRIVATE_KEY)
}

fn is_pem_end(line: &str) -> bool {
    line.contains(PEM_END) && line.contains(PEM_PRIVATE_KEY)
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

/// Replace the value after `Authorization: Bearer|Basic ` (header or JSON-ish, any case).
fn redact_authorization(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let Some(at) = lower.find(AUTHORIZATION) else {
        return line.to_owned();
    };
    let after_name = at + AUTHORIZATION.len();
    let rest = &lower[after_name..];
    let skipped = rest
        .find(|c: char| !matches!(c, ':' | '"' | '\'' | '=' | ' ' | '\t'))
        .unwrap_or(rest.len());
    let value_region = &lower[after_name + skipped..];
    let Some(scheme) = AUTH_SCHEMES.iter().find(|s| value_region.starts_with(**s)) else {
        return line.to_owned();
    };
    let value_start = after_name + skipped + scheme.len();
    let value_len = line[value_start..]
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\''))
        .unwrap_or(line.len() - value_start);
    if value_len == 0 {
        return line.to_owned();
    }
    format!(
        "{}{REDACTED}{}",
        &line[..value_start],
        &line[value_start + value_len..]
    )
}

fn is_jwt_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
}

/// Replace every run that has a JWT's shape: base64url segments, two dots, `eyJ` first.
fn redact_jwts(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.starts_with(JWT_PREFIX) && run.matches('.').count() == JWT_DOTS {
            out.push_str(REDACTED);
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in line.chars() {
        if is_jwt_char(c) {
            run.push(c);
            continue;
        }
        flush(&mut run, &mut out);
        out.push(c);
    }
    flush(&mut run, &mut out);
    out
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
}
