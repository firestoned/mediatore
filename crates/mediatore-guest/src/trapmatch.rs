// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The egress proxy's bait matcher (ADR-0069 decision 6): the head of a request checked whole
//! before any upstream is opened, the body streamed through a matcher that holds back what
//! could still be part of a match. Pure: no I/O, no log line.
//!
//! # What is matched
//!
//! Every bait value of at least [`MIN_PATTERN_BYTES`] bytes becomes a set of byte patterns in
//! one Aho-Corasick automaton (the `aho-corasick` crate's contiguous NFA, stepped a byte at a
//! time, so a scan is linear in the bytes scanned whatever the number of patterns):
//!
//! - **raw**, as planted;
//! - **percent-encoded**, as six kinds of client produce it, each with upper-case and with
//!   lower-case hex digits: everything but letters and digits encoded; RFC 3986's unreserved
//!   set kept (`-._~`); that set and `/` kept (a path encoder); that set and `!*'()` kept (a
//!   URI-component encoder); a form encoder (`*-._` kept, a space as `+`); and a whole-URI
//!   encoder that also keeps the reserved characters;
//! - **base64**, standard and URL-safe alphabets, at the three alignments: the value may sit
//!   at any offset inside a larger encoded text, so for each offset modulo three the pattern
//!   is the run of characters the value alone determines (the characters that also depend on
//!   a neighbouring byte, and any padding, are left out);
//! - the standard-alphabet base64 forms **percent-encoded** (unreserved set, both hex cases):
//!   an encoded blob in a form body.
//!
//! In the head ([`Matcher::in_head`]) the path, the query and every header value are also
//! percent-decoded and matched again, which covers any encoder's choice of characters there,
//! and a `Basic` credential is base64-decoded and matched.
//!
//! # What is not matched
//!
//! A value the workload transforms first (reversed, split, encrypted, encoded twice,
//! compressed without saying so, percent-encoded in a body with a mix of characters none of
//! the six sets has) is not caught. ADR-0069 decision 6 says so; the `port`, `route` and
//! `denied` traps depend on no value.
//!
//! # Nothing here prints
//!
//! No type's `Debug` shows a pattern, a held byte or a body, and a [`Hit`] names the
//! catalogue entry, never the value (decision 12).

use std::collections::{HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aho_corasick::automaton::{Automaton as _, StateID};
use aho_corasick::nfa::contiguous::NFA;
use aho_corasick::{Anchored, MatchKind};
use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{
    GeneralPurpose, GeneralPurposeConfig, STANDARD_NO_PAD, URL_SAFE_NO_PAD,
};
use bytes::{Bytes, BytesMut};
use flate2::write::{DeflateDecoder, MultiGzDecoder, ZlibDecoder};
use http_body::{Frame, SizeHint};
use mediatore_proto::trip::ProxyBait;

/// The shortest bait value, and the shortest form of one, that becomes a pattern. A shorter
/// value would match honest traffic by chance; every generated credential is far longer.
pub const MIN_PATTERN_BYTES: usize = 8;

/// A compressed body may expand to this many times the compressed bytes read so far.
pub const EXPANSION_RATIO: u64 = 64;
/// Below this much plaintext the ratio is not applied: a small, very repetitive honest body
/// (a page of padding) expands far more than [`EXPANSION_RATIO`] and costs nothing to scan.
pub const EXPANSION_FLOOR: u64 = 1024 * 1024;
/// The most plaintext one request's compressed body may expand to, whatever its size.
pub const EXPANSION_CAP: u64 = 64 * 1024 * 1024;

/// The `trap` a hit carries when a compressed body passed the expansion bound.
pub const TRAP_EXPANSION: &str = "body-expansion";
/// The `trap` a hit carries when a body is not what its `Content-Encoding` says.
pub const TRAP_UNDECODABLE: &str = "body-undecodable";
/// The `trap` every check answers with when the automaton could not be built: a matcher
/// that cannot match refuses everything rather than pass anything.
pub const TRAP_UNBUILT: &str = "matcher-not-built";

/// A `Basic` credential decoded as leniently as a server might: padding or none, and
/// trailing bits that are not zero.
const LENIENT: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_allow_trailing_bits(true)
    .with_decode_padding_mode(DecodePaddingMode::Indifferent);
const STANDARD_LENIENT: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, LENIENT);
const URL_SAFE_LENIENT: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, LENIENT);

/// A match: the catalogue entry's name, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// What a report's `trap` says.
    pub trap: String,
}

impl Hit {
    fn named(trap: &str) -> Self {
        Self {
            trap: trap.to_owned(),
        }
    }
}

/// Which characters a percent-encoder leaves alone, beside letters and digits.
#[derive(Clone, Copy)]
enum Keep {
    /// Nothing: every other byte is encoded.
    Nothing,
    /// RFC 3986's unreserved set.
    Unreserved,
    /// The unreserved set and `/`.
    Path,
    /// The unreserved set and `!*'()`.
    Component,
    /// `*-._`, and a space written as `+`.
    Form,
    /// The unreserved set, `!*'()` and the reserved characters.
    Uri,
}

impl Keep {
    const ALL: [Self; 6] = [
        Self::Nothing,
        Self::Unreserved,
        Self::Path,
        Self::Component,
        Self::Form,
        Self::Uri,
    ];

    fn keeps(self, b: u8) -> bool {
        let unreserved = matches!(b, b'-' | b'.' | b'_' | b'~');
        let marks = matches!(b, b'!' | b'*' | b'\'' | b'(' | b')');
        b.is_ascii_alphanumeric()
            || match self {
                Self::Nothing => false,
                Self::Unreserved => unreserved,
                Self::Path => unreserved || b == b'/',
                Self::Component => unreserved || marks,
                Self::Form => matches!(b, b'*' | b'-' | b'.' | b'_'),
                Self::Uri => {
                    unreserved
                        || marks
                        || matches!(
                            b,
                            b';' | b'/'
                                | b'?'
                                | b':'
                                | b'@'
                                | b'&'
                                | b'='
                                | b'+'
                                | b'$'
                                | b','
                                | b'#'
                        )
                }
            }
    }
}

/// `value` percent-encoded by an encoder that keeps `keep`, with hex digits in one case.
fn percent_encoded(value: &[u8], keep: Keep, upper: bool) -> Vec<u8> {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let digits = if upper { UPPER } else { LOWER };
    let mut out = Vec::with_capacity(value.len());
    for &b in value {
        if keep.keeps(b) {
            out.push(b);
        } else if b == b' ' && matches!(keep, Keep::Form) {
            out.push(b'+');
        } else {
            out.push(b'%');
            out.push(digits[usize::from(b >> 4)]);
            out.push(digits[usize::from(b & 0x0f)]);
        }
    }
    out
}

/// The base64 characters `value` alone determines when it sits `offset` bytes (modulo three)
/// into an encoded text: the leading characters that also carry a byte before it and the
/// trailing one that also carries a byte after it are left out.
fn base64_aligned(value: &[u8], offset: usize, engine: &GeneralPurpose) -> Vec<u8> {
    let mut padded = vec![0u8; offset];
    padded.extend_from_slice(value);
    let encoded = engine.encode(&padded).into_bytes();
    // One byte before the value reaches into two characters, two bytes into three.
    let lead = [0, 2, 3][offset];
    let whole = padded.len() * 8 / 6;
    encoded
        .get(lead..whole.min(encoded.len()))
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

/// Every form of one bait value the matcher looks for. Empty for a value under
/// [`MIN_PATTERN_BYTES`]; a form under it is left out.
fn forms_of(value: &[u8]) -> Vec<Vec<u8>> {
    if value.len() < MIN_PATTERN_BYTES {
        return Vec::new();
    }
    let mut out = vec![value.to_vec()];
    for keep in Keep::ALL {
        for upper in [true, false] {
            out.push(percent_encoded(value, keep, upper));
        }
    }
    for offset in 0..3 {
        let standard = base64_aligned(value, offset, &STANDARD_NO_PAD);
        for upper in [true, false] {
            out.push(percent_encoded(&standard, Keep::Unreserved, upper));
        }
        out.push(standard);
        out.push(base64_aligned(value, offset, &URL_SAFE_NO_PAD));
    }
    out.retain(|form| form.len() >= MIN_PATTERN_BYTES);
    out
}

/// The automaton, or why there is none.
enum Engine {
    /// No pattern: nothing matches.
    Empty,
    /// The patterns, and the bait each one belongs to.
    Built(Box<Built>),
    /// The automaton could not be built: everything matches.
    Broken,
}

struct Built {
    nfa: NFA,
    start: StateID,
    /// The bait each pattern belongs to.
    owner: Vec<usize>,
}

/// Where a scan stands in the automaton: carried from one chunk to the next.
#[derive(Clone, Copy)]
struct Cursor(Option<StateID>);

/// Every form of every bait value the proxy looks for.
pub struct Matcher {
    names: Vec<String>,
    engine: Engine,
    longest: usize,
    patterns: u32,
}

#[cfg(test)]
impl Matcher {
    /// A matcher whose automaton could not be built: what the proxy's tests of a failure to
    /// arm are handed.
    pub(crate) fn broken() -> Self {
        Self {
            names: Vec::new(),
            engine: Engine::Broken,
            longest: 0,
            patterns: 0,
        }
    }
}

impl std::fmt::Debug for Matcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the automaton: its transitions are the bait.
        f.debug_struct("Matcher")
            .field("patterns", &self.patterns)
            .field("longest", &self.longest)
            .field("built", &self.built())
            .finish_non_exhaustive()
    }
}

impl Matcher {
    /// Build the matcher from the bait the guest armed the proxy with. A value under
    /// [`MIN_PATTERN_BYTES`] adds no pattern. When the automaton cannot be built the matcher
    /// answers every check with a hit named [`TRAP_UNBUILT`] and [`Matcher::built`] is false.
    #[must_use]
    pub fn new(bait: &[ProxyBait]) -> Self {
        let mut forms: Vec<Vec<u8>> = Vec::new();
        let mut owner = Vec::new();
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for (index, entry) in bait.iter().enumerate() {
            for value in &entry.values {
                for form in forms_of(value.0.as_bytes()) {
                    if seen.insert(form.clone()) {
                        forms.push(form);
                        owner.push(index);
                    }
                }
            }
        }
        let names = bait.iter().map(|b| b.name.clone()).collect();
        let longest = forms.iter().map(Vec::len).max().unwrap_or(0);
        let patterns = u32::try_from(forms.len()).unwrap_or(u32::MAX);
        let engine = if forms.is_empty() {
            Engine::Empty
        } else {
            // Standard semantics: a match is reported at the byte that completes it, which is
            // what stepping across chunks needs.
            let built = NFA::builder()
                .match_kind(MatchKind::Standard)
                .build(&forms)
                .ok()
                .and_then(|nfa| {
                    let start = nfa.start_state(Anchored::No).ok()?;
                    Some((nfa, start))
                });
            match built {
                Some((nfa, start)) => Engine::Built(Box::new(Built { nfa, start, owner })),
                None => Engine::Broken,
            }
        };
        Self {
            names,
            engine,
            longest,
            patterns,
        }
    }

    /// Whether the automaton exists. False only when building it failed, and then every
    /// check is a hit: the guest should treat that as a failure to arm.
    #[must_use]
    pub fn built(&self) -> bool {
        !matches!(self.engine, Engine::Broken)
    }

    /// The longest pattern, in bytes: a scanner holds back at most one less.
    #[must_use]
    pub fn longest(&self) -> usize {
        self.longest
    }

    /// How many patterns the matcher holds, for the `armed` message.
    #[must_use]
    pub fn patterns(&self) -> u32 {
        self.patterns
    }

    fn cursor(&self) -> Cursor {
        match &self.engine {
            Engine::Built(built) => Cursor(Some(built.start)),
            Engine::Empty | Engine::Broken => Cursor(None),
        }
    }

    /// Step the automaton over `bytes` from `cursor`; the hit at the first byte that
    /// completes a pattern.
    fn step(&self, cursor: &mut Cursor, bytes: &[u8]) -> Option<Hit> {
        match &self.engine {
            Engine::Empty => None,
            Engine::Broken => Some(Hit::named(TRAP_UNBUILT)),
            Engine::Built(built) => {
                let Built { nfa, start, owner } = built.as_ref();
                let mut sid = cursor.0.unwrap_or(*start);
                for &b in bytes {
                    sid = nfa.next_state(Anchored::No, sid, b);
                    if nfa.is_match(sid) {
                        cursor.0 = Some(sid);
                        let pattern = nfa.match_pattern(sid, 0).as_usize();
                        let name = owner
                            .get(pattern)
                            .and_then(|bait| self.names.get(*bait))
                            .map_or(TRAP_UNBUILT, String::as_str);
                        return Some(Hit::named(name));
                    }
                }
                cursor.0 = Some(sid);
                None
            }
        }
    }

    /// A pattern anywhere in `bytes`, taken as one whole text.
    fn first(&self, bytes: &[u8]) -> Option<Hit> {
        self.step(&mut self.cursor(), bytes)
    }

    /// A pattern in `text` as sent, or in `text` percent-decoded.
    fn in_text(&self, text: &[u8]) -> Option<Hit> {
        self.first(text).or_else(|| {
            if !text.contains(&b'%') {
                return None;
            }
            let decoded: Vec<u8> = percent_encoding::percent_decode(text).collect();
            self.first(&decoded)
        })
    }

    /// Bait in the path, the query or any header: `Authorization` with a Basic pair decoded,
    /// every credential header, every other header value, every header name. The path and the
    /// query are matched as sent and percent-decoded. The method is [`Self::in_method`].
    #[must_use]
    pub fn in_head(&self, path_and_query: &str, headers: &http::HeaderMap) -> Option<Hit> {
        self.in_text(path_and_query.as_bytes())
            .or_else(|| self.in_headers(headers))
    }

    /// Bait in any header (a request's headers, or a body's trailers): each name in any case
    /// ([`Self::in_name`]), each value as sent and percent-decoded, and the pair of a `Basic`
    /// credential, in any header, base64-decoded.
    #[must_use]
    pub fn in_headers(&self, headers: &http::HeaderMap) -> Option<Hit> {
        headers
            .keys()
            .find_map(|name| self.in_name(name.as_str().as_bytes()))
            .or_else(|| {
                headers.values().find_map(|value| {
                    let bytes = value.as_bytes();
                    self.in_text(bytes)
                        .or_else(|| basic_pair(bytes).and_then(|pair| self.in_text(&pair)))
                })
            })
    }

    /// Bait in a request's method: hyper forwards an extension method as it was sent.
    #[must_use]
    pub fn in_method(&self, method: &str) -> Option<Hit> {
        self.in_name(method.as_bytes())
    }

    /// Bait in a token the proxy may forward in another case than it came in (a header name,
    /// which hyper lower-cases; a method): as it is, upper-cased and lower-cased. A value all
    /// of one case (hex, an access key id) is caught whole; a mixed-case value lower-cased is
    /// a transform, which ADR-0069 decision 6 does not catch.
    #[must_use]
    pub fn in_name(&self, name: &[u8]) -> Option<Hit> {
        self.first(name)
            .or_else(|| self.first(&name.to_ascii_uppercase()))
            .or_else(|| self.first(&name.to_ascii_lowercase()))
    }

    /// A scanner for one body.
    #[must_use]
    pub fn scanner(&self) -> Scanner<'_> {
        Scanner {
            matcher: self,
            tail: Tail::new(self),
        }
    }
}

/// The decoded `user:password` of a `Basic` credential, when `value` is one.
fn basic_pair(value: &[u8]) -> Option<Vec<u8>> {
    let value = value.trim_ascii();
    let (scheme, rest) = value.split_at_checked(5)?;
    if !scheme.eq_ignore_ascii_case(b"basic") || !rest.first().is_some_and(u8::is_ascii_whitespace)
    {
        return None;
    }
    let encoded = rest.trim_ascii();
    STANDARD_LENIENT
        .decode(encoded)
        .or_else(|_| URL_SAFE_LENIENT.decode(encoded))
        .ok()
}

/// A body's scan state: the automaton's position and the bytes not yet released.
struct Tail {
    cursor: Cursor,
    held: BytesMut,
    hit: Option<Hit>,
}

impl Tail {
    fn new(matcher: &Matcher) -> Self {
        Self {
            cursor: matcher.cursor(),
            held: BytesMut::new(),
            hit: None,
        }
    }

    fn feed(&mut self, matcher: &Matcher, chunk: &[u8]) -> Result<Bytes, Hit> {
        if let Some(hit) = &self.hit {
            return Err(hit.clone());
        }
        if let Some(hit) = matcher.step(&mut self.cursor, chunk) {
            self.hit = Some(hit.clone());
            return Err(hit);
        }
        self.held.extend_from_slice(chunk);
        let keep = matcher.longest().saturating_sub(1).min(self.held.len());
        Ok(self.held.split_to(self.held.len() - keep).freeze())
    }

    /// Everything held, whatever happened.
    fn drain(&mut self) -> Bytes {
        self.held.split().freeze()
    }
}

/// The matcher stepped across one body's chunks.
pub struct Scanner<'a> {
    matcher: &'a Matcher,
    tail: Tail,
}

impl std::fmt::Debug for Scanner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the held bytes: they are the request's body.
        f.debug_struct("Scanner")
            .field("held", &self.tail.held.len())
            .field("hit", &self.tail.hit.is_some())
            .finish_non_exhaustive()
    }
}

impl Scanner<'_> {
    /// Feed a chunk. `Ok(bytes)` are bytes that can no longer be part of a match: every byte
    /// fed so far but the last `longest() - 1`, in order.
    ///
    /// # Errors
    /// The hit, the moment a pattern completes; nothing of that chunk is released, and no
    /// byte of the completed pattern was released before it. Every later call answers the
    /// same hit.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Bytes, Hit> {
        self.tail.feed(self.matcher, chunk)
    }

    /// How many bytes are held back now: never more than `longest() - 1`.
    #[must_use]
    pub fn held(&self) -> usize {
        self.tail.held.len()
    }

    /// The held tail at a clean end of the body; nothing after a hit.
    #[must_use]
    pub fn finish(mut self) -> Bytes {
        if self.tail.hit.is_some() {
            return Bytes::new();
        }
        self.tail.drain()
    }
}

/// A request body's `Content-Encoding`, as the matcher can or cannot read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// No encoding.
    Identity,
    /// `gzip`.
    Gzip,
    /// `deflate`.
    Deflate,
    /// Anything else, and any stack of encodings: `415` under `enforce` on a matched route.
    Unsupported,
}

/// The encoding `headers` declare: `gzip` (or `x-gzip`), `deflate`, none (or `identity`), and
/// [`Encoding::Unsupported`] for any other coding, a list of codings or a second header.
#[must_use]
pub fn encoding_of(headers: &http::HeaderMap) -> Encoding {
    let mut values = headers.get_all(http::header::CONTENT_ENCODING).iter();
    let Some(first) = values.next() else {
        return Encoding::Identity;
    };
    if values.next().is_some() {
        return Encoding::Unsupported;
    }
    let coding = first.as_bytes().trim_ascii();
    if coding.is_empty() || coding.eq_ignore_ascii_case(b"identity") {
        Encoding::Identity
    } else if coding.eq_ignore_ascii_case(b"gzip") || coding.eq_ignore_ascii_case(b"x-gzip") {
        Encoding::Gzip
    } else if coding.eq_ignore_ascii_case(b"deflate") {
        Encoding::Deflate
    } else {
        Encoding::Unsupported
    }
}

/// Why a scanned body stopped.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// A bait value completed in the body.
    #[error("a trap matched in the request body")]
    Trap(Hit),
    /// A compressed body expanded past the bound, which is treated as a match.
    #[error("the request body expanded past the bound")]
    Expansion,
    /// A compressed body is not what its encoding says, which is treated as a match.
    #[error("the request body does not decode as its encoding")]
    Decode,
    /// The body was wrapped with an encoding the matcher cannot read: nothing of it was
    /// forwarded. Not a match; the caller should have answered `415`.
    #[error("the request body's encoding cannot be read")]
    Unsupported,
    /// The body itself failed.
    #[error("reading the request body: {0}")]
    Upstream(Box<dyn std::error::Error + Send + Sync>),
}

/// What a [`ScanBody`] calls, once, when a bait value completes in the body: the response may
/// already be on its way by then, so the trip is sent from here and not from the handler.
pub type HitSink = Box<dyn FnOnce(&Hit) + Send + Sync>;

/// Why a scan stopped, before it is told to anyone.
enum Stop {
    Hit(Hit),
    Expansion,
    Decode,
}

/// Where a decoder writes the plaintext: into the automaton, and nowhere else.
struct Plain {
    matcher: Arc<Matcher>,
    cursor: Cursor,
    /// Plaintext bytes seen.
    seen: u64,
    /// The most plaintext the compressed bytes read so far allow.
    allowed: u64,
    hit: Option<Hit>,
    over: bool,
}

impl std::io::Write for Plain {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.hit.is_some() || self.over {
            return Err(std::io::Error::other("the scan has stopped"));
        }
        if let Some(hit) = self.matcher.step(&mut self.cursor, buf) {
            self.hit = Some(hit);
            return Err(std::io::Error::other("a trap matched"));
        }
        self.seen = self
            .seen
            .saturating_add(u64::try_from(buf.len()).unwrap_or(u64::MAX));
        if self.seen > self.allowed {
            self.over = true;
            return Err(std::io::Error::other("past the expansion bound"));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The most plaintext a compressed body may have yielded once `read` bytes of it have come.
fn allowance(read: u64) -> u64 {
    read.saturating_mul(EXPANSION_RATIO)
        .clamp(EXPANSION_FLOOR, EXPANSION_CAP)
}

/// One of the decoders, each writing into a [`Plain`].
enum Decoder {
    Gzip(Box<MultiGzDecoder<Plain>>),
    Zlib(ZlibDecoder<Plain>),
    Raw(DeflateDecoder<Plain>),
}

impl Decoder {
    fn plain(&mut self) -> &mut Plain {
        match self {
            Self::Gzip(d) => d.get_mut(),
            Self::Zlib(d) => d.get_mut(),
            Self::Raw(d) => d.get_mut(),
        }
    }

    fn writer(&mut self) -> &mut dyn std::io::Write {
        match self {
            Self::Gzip(d) => d.as_mut(),
            Self::Zlib(d) => d,
            Self::Raw(d) => d,
        }
    }

    /// Decode `data` and push every byte of plaintext it yields into the automaton.
    fn run(&mut self, data: &[u8], allowed: u64) -> Result<(), Stop> {
        self.plain().allowed = allowed;
        let outcome = self.write_all_and_flush(data);
        let plain = self.plain();
        if let Some(hit) = plain.hit.clone() {
            return Err(Stop::Hit(hit));
        }
        if plain.over {
            return Err(Stop::Expansion);
        }
        outcome.map_err(|_| Stop::Decode)
    }

    fn write_all_and_flush(&mut self, data: &[u8]) -> std::io::Result<()> {
        let writer = self.writer();
        let mut rest = data;
        let mut stalled = false;
        while !rest.is_empty() {
            let n = writer.write(rest)?;
            if n == 0 {
                // A decoder that takes nothing after a flush has ended: what follows its end
                // is not part of the encoding.
                if stalled {
                    return Err(std::io::Error::other("bytes after the end of the stream"));
                }
                stalled = true;
                writer.flush()?;
            } else {
                stalled = false;
                rest = &rest[n..];
            }
        }
        // The decoder buffers its output: the flush is what makes "every byte of plaintext
        // these compressed bytes yield has been scanned" true before they are released.
        writer.flush()
    }
}

/// A compressed body's scan: a copy of the body is decoded into the automaton.
struct Coded {
    /// `None` until a `deflate` body's first two bytes say whether it has a zlib wrapper.
    decoder: Option<Decoder>,
    plain: Option<Plain>,
    head: Vec<u8>,
    /// Compressed bytes read.
    read: u64,
}

impl Coded {
    fn new(matcher: &Arc<Matcher>, gzip: bool) -> Self {
        let plain = Plain {
            matcher: matcher.clone(),
            cursor: matcher.cursor(),
            seen: 0,
            allowed: EXPANSION_FLOOR,
            hit: None,
            over: false,
        };
        if gzip {
            Self {
                decoder: Some(Decoder::Gzip(Box::new(MultiGzDecoder::new(plain)))),
                plain: None,
                head: Vec::new(),
                read: 0,
            }
        } else {
            Self {
                decoder: None,
                plain: Some(plain),
                head: Vec::new(),
                read: 0,
            }
        }
    }

    fn feed(&mut self, chunk: &[u8]) -> Result<(), Stop> {
        self.read = self
            .read
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        let allowed = allowance(self.read);
        if let Some(decoder) = &mut self.decoder {
            return decoder.run(chunk, allowed);
        }
        // `deflate` is a zlib stream by the RFC and a bare deflate stream from some clients:
        // the first two bytes tell them apart, and one byte alone yields no plaintext.
        self.head.extend_from_slice(chunk);
        if self.head.len() < 2 {
            return Ok(());
        }
        let Some(plain) = self.plain.take() else {
            return Err(Stop::Decode);
        };
        let zlib = self.head[0] & 0x0f == 8
            && self.head[0] >> 4 <= 7
            && ((u16::from(self.head[0]) << 8) | u16::from(self.head[1])) % 31 == 0;
        let decoder = self.decoder.insert(if zlib {
            Decoder::Zlib(ZlibDecoder::new(plain))
        } else {
            Decoder::Raw(DeflateDecoder::new(plain))
        });
        let head = std::mem::take(&mut self.head);
        decoder.run(&head, allowed)
    }
}

/// How a [`ScanBody`] reads its body.
enum Mode {
    Identity(Tail),
    Coded(Box<Coded>),
    Unsupported,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Frames are scanned before they are yielded.
    Scanning,
    /// Report-only, after a hit: frames pass as they come.
    Passing,
    /// The inner body has ended: only what is queued is left.
    Draining,
    /// Nothing more is yielded.
    Ended,
}

/// A request body wrapped in the matcher: it yields only bytes that can no longer be part of a
/// match, and an error in place of the chunk that completes one.
///
/// - **Identity:** each chunk is scanned and all but the last `longest() - 1` bytes seen are
///   yielded; the tail follows at the end of the body.
/// - **Gzip, deflate:** a copy is decoded into the matcher and the compressed chunk is yielded
///   as it came, only after every byte of plaintext it yields has been scanned. A body that
///   expands past the bound ([`EXPANSION_RATIO`], [`EXPANSION_FLOOR`], [`EXPANSION_CAP`]) or
///   does not decode is treated as a match.
/// - **Unsupported:** nothing is read and the first frame is [`ScanError::Unsupported`].
/// - **Trailers** are matched as headers and passed after the tail.
///
/// On a match the sink is called once, the frame is [`ScanError::Trap`] (or
/// [`ScanError::Expansion`], [`ScanError::Decode`]), and the body then ends: no further byte is
/// yielded, so the upstream sees an incomplete request. Under [`ScanBody::report_only`] the
/// sink is called once and the body passes whole and unchanged, scanned no further.
pub struct ScanBody<B> {
    inner: B,
    matcher: Arc<Matcher>,
    encoding: Encoding,
    on_hit: Option<HitSink>,
    report_only: bool,
    mode: Mode,
    phase: Phase,
    queued: VecDeque<Frame<Bytes>>,
}

impl<B> ScanBody<B> {
    /// Wrap `inner`, read as `encoding`, matched by `matcher`; `on_hit` is called once on a
    /// match.
    #[must_use]
    pub fn new(
        inner: B,
        matcher: Arc<Matcher>,
        encoding: Encoding,
        on_hit: Option<HitSink>,
    ) -> Self {
        let mode = match encoding {
            Encoding::Identity => Mode::Identity(Tail::new(&matcher)),
            Encoding::Gzip => Mode::Coded(Box::new(Coded::new(&matcher, true))),
            Encoding::Deflate => Mode::Coded(Box::new(Coded::new(&matcher, false))),
            Encoding::Unsupported => Mode::Unsupported,
        };
        Self {
            inner,
            matcher,
            encoding,
            on_hit,
            report_only: false,
            mode,
            phase: Phase::Scanning,
            queued: VecDeque::new(),
        }
    }

    /// The `shadow` form: a match calls the sink once and ends nothing. The body passes
    /// whole, byte for byte, and after the first match it is not scanned again. A body in an
    /// encoding the matcher cannot read passes unscanned and calls nothing.
    #[must_use]
    pub fn report_only(mut self) -> Self {
        self.report_only = true;
        if matches!(self.mode, Mode::Unsupported) {
            self.phase = Phase::Passing;
        }
        self
    }

    fn held(&self) -> usize {
        match &self.mode {
            Mode::Identity(tail) => tail.held.len(),
            Mode::Coded(_) | Mode::Unsupported => 0,
        }
    }

    /// Scan one chunk; what may be yielded for it.
    fn scan(&mut self, data: &Bytes) -> Result<Bytes, Stop> {
        match &mut self.mode {
            Mode::Identity(tail) => tail.feed(&self.matcher, data).map_err(Stop::Hit),
            Mode::Coded(coded) => coded.feed(data).map(|()| data.clone()),
            Mode::Unsupported => Err(Stop::Decode),
        }
    }

    /// The held tail, queued for the end of the body.
    fn queue_tail(&mut self) {
        if let Mode::Identity(tail) = &mut self.mode {
            let rest = tail.drain();
            if !rest.is_empty() {
                self.queued.push_back(Frame::data(rest));
            }
        }
    }

    /// Tell the sink, then either end the body with the error or, report-only, let
    /// everything withheld and `frame` pass.
    fn stopped(&mut self, stop: Stop, frame: Frame<Bytes>) -> Option<ScanError> {
        let (hit, error) = match stop {
            Stop::Hit(hit) => (hit.clone(), ScanError::Trap(hit)),
            Stop::Expansion => (Hit::named(TRAP_EXPANSION), ScanError::Expansion),
            Stop::Decode => (Hit::named(TRAP_UNDECODABLE), ScanError::Decode),
        };
        if let Some(on_hit) = self.on_hit.take() {
            on_hit(&hit);
        }
        if self.report_only {
            self.queue_tail();
            self.queued.push_back(frame);
            self.phase = Phase::Passing;
            None
        } else {
            self.queued.clear();
            self.phase = Phase::Ended;
            Some(error)
        }
    }
}

impl<B> std::fmt::Debug for ScanBody<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanBody")
            .field("encoding", &self.encoding)
            .field("patterns", &self.matcher.patterns())
            .finish_non_exhaustive()
    }
}

impl<B> http_body::Body for ScanBody<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = ScanError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, ScanError>>> {
        let this = self.get_mut();
        loop {
            if let Some(frame) = this.queued.pop_front() {
                return Poll::Ready(Some(Ok(frame)));
            }
            match this.phase {
                Phase::Ended | Phase::Draining => {
                    this.phase = Phase::Ended;
                    return Poll::Ready(None);
                }
                Phase::Scanning if matches!(this.mode, Mode::Unsupported) => {
                    // Not read, not forwarded, and not a trip: the caller owed a `415`.
                    this.phase = Phase::Ended;
                    return Poll::Ready(Some(Err(ScanError::Unsupported)));
                }
                Phase::Scanning | Phase::Passing => {}
            }
            let frame = match std::task::ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                None => {
                    if this.phase == Phase::Scanning {
                        this.queue_tail();
                    }
                    this.phase = Phase::Draining;
                    continue;
                }
                Some(Err(e)) => {
                    this.queued.clear();
                    this.phase = Phase::Ended;
                    return Poll::Ready(Some(Err(ScanError::Upstream(e.into()))));
                }
                Some(Ok(frame)) => frame,
            };
            if this.phase == Phase::Passing {
                return Poll::Ready(Some(Ok(frame)));
            }
            let stop = if let Some(data) = frame.data_ref() {
                match this.scan(data) {
                    Ok(out) if out.is_empty() => continue,
                    Ok(out) => return Poll::Ready(Some(Ok(Frame::data(out)))),
                    Err(stop) => stop,
                }
            } else if let Some(trailers) = frame.trailers_ref() {
                match this.matcher.in_headers(trailers) {
                    None => {
                        this.queue_tail();
                        this.queued.push_back(frame);
                        continue;
                    }
                    Some(hit) => Stop::Hit(hit),
                }
            } else {
                // A frame that is neither data nor trailers cannot be scanned: not forwarded.
                continue;
            };
            if let Some(error) = this.stopped(stop, frame) {
                return Poll::Ready(Some(Err(error)));
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self.phase {
            Phase::Ended => true,
            Phase::Draining => self.queued.is_empty(),
            Phase::Scanning if matches!(self.mode, Mode::Unsupported) => false,
            Phase::Scanning | Phase::Passing => {
                self.queued.is_empty() && self.held() == 0 && self.inner.is_end_stream()
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        let queued: usize = self
            .queued
            .iter()
            .filter_map(|f| f.data_ref().map(Bytes::len))
            .sum();
        let extra = u64::try_from(queued + self.held()).unwrap_or(u64::MAX);
        let inner = match self.phase {
            Phase::Ended => return SizeHint::with_exact(0),
            Phase::Draining => SizeHint::with_exact(0),
            Phase::Scanning if matches!(self.mode, Mode::Unsupported) => return SizeHint::new(),
            Phase::Scanning | Phase::Passing => self.inner.size_hint(),
        };
        // What is yielded is what came, byte for byte, unless a trap ends it early.
        let mut hint = SizeHint::new();
        hint.set_lower(inner.lower().saturating_add(extra));
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper.saturating_add(extra));
        }
        hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};
    use http_body::Body as _;
    use http_body_util::BodyExt as _;
    use mediatore_proto::Secret;
    use std::convert::Infallible;
    use std::io::Write as _;
    use std::sync::Mutex;

    /// A made-up value with every character a percent-encoder disagrees about.
    const VALUE: &str = "Zq3+vT/9xLm=Kp2w~Rt8_Yu-4.Hd";
    const PLAIN: &str = "nQ7fT2mVx9KcR4sWb8LpZ3hJ";

    // Four encoders' sets, built from the `percent-encoding` crate and not from this module.
    const EVERYTHING: &percent_encoding::AsciiSet = percent_encoding::NON_ALPHANUMERIC;
    const UNRESERVED_KEPT: percent_encoding::AsciiSet = EVERYTHING
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    const PATH_KEPT: percent_encoding::AsciiSet = UNRESERVED_KEPT.remove(b'/');
    const FORM_KEPT: percent_encoding::AsciiSet = EVERYTHING
        .remove(b'*')
        .remove(b'-')
        .remove(b'.')
        .remove(b'_');

    fn bait(entries: &[(&str, &str)]) -> Vec<ProxyBait> {
        entries
            .iter()
            .map(|(name, value)| ProxyBait {
                name: (*name).to_owned(),
                values: vec![Secret((*value).to_owned())],
            })
            .collect()
    }

    fn matcher() -> Arc<Matcher> {
        Arc::new(Matcher::new(&bait(&[("aws", VALUE), ("github", PLAIN)])))
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// Bytes that hold no pattern and plenty of near misses: every value less its last byte.
    fn clean(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 64);
        let mut i = 0u32;
        while out.len() < len {
            out.extend_from_slice(&VALUE.as_bytes()[..VALUE.len() - 1]);
            out.extend_from_slice(&PLAIN.as_bytes()[..PLAIN.len() - 1]);
            out.extend_from_slice(format!(" {i} ").as_bytes());
            i += 1;
        }
        out.truncate(len);
        out
    }

    /// Feed `chunks`; what was released before the hit, the hit, and the most held at once.
    fn feed_all(m: &Matcher, chunks: &[&[u8]]) -> (Vec<u8>, Option<Hit>, usize) {
        let mut scanner = m.scanner();
        let mut out = Vec::new();
        let mut most = 0;
        for chunk in chunks {
            match scanner.feed(chunk) {
                Ok(bytes) => out.extend_from_slice(&bytes),
                Err(hit) => return (out, Some(hit), most),
            }
            most = most.max(scanner.held());
        }
        out.extend_from_slice(&scanner.finish());
        (out, None, most)
    }

    /// A body of several frames.
    struct Chunks(VecDeque<Frame<Bytes>>);

    impl Chunks {
        fn of(chunks: &[&[u8]]) -> Self {
            Self(
                chunks
                    .iter()
                    .map(|c| Frame::data(Bytes::copy_from_slice(c)))
                    .collect(),
            )
        }
    }

    impl http_body::Body for Chunks {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Ready(self.0.pop_front().map(Ok))
        }
    }

    /// What a body yielded: its data, its trailers, the error it ended in, and how many frames
    /// came after that error.
    struct Yielded {
        data: Vec<u8>,
        trailers: Option<http::HeaderMap>,
        error: Option<ScanError>,
        after_error: usize,
    }

    async fn drain<B>(mut body: ScanBody<B>) -> Yielded
    where
        B: http_body::Body<Data = Bytes> + Unpin,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let mut y = Yielded {
            data: Vec::new(),
            trailers: None,
            error: None,
            after_error: 0,
        };
        while let Some(frame) = body.frame().await {
            if y.error.is_some() {
                y.after_error += 1;
                continue;
            }
            match frame {
                Ok(frame) => match frame.into_data() {
                    Ok(data) => y.data.extend_from_slice(&data),
                    Err(frame) => y.trailers = frame.into_trailers().ok(),
                },
                Err(e) => y.error = Some(e),
            }
        }
        assert!(body.is_end_stream(), "an ended body says it has ended");
        y
    }

    /// A sink that records the trap names it was told.
    fn sink() -> (Arc<Mutex<Vec<String>>>, Option<HitSink>) {
        let told = Arc::new(Mutex::new(Vec::new()));
        let record = told.clone();
        let on_hit: HitSink = Box::new(move |hit: &Hit| {
            record.lock().unwrap().push(hit.trap.clone());
        });
        (told, Some(on_hit))
    }

    fn gzip(plain: &[u8], level: flate2::Compression) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), level);
        enc.write_all(plain).unwrap();
        enc.finish().unwrap()
    }

    /// As much plaintext as a receiver could get out of a truncated gzip stream.
    fn gunzip_prefix(compressed: &[u8]) -> Vec<u8> {
        use std::io::Read as _;
        let mut out = Vec::new();
        let mut dec = flate2::read::MultiGzDecoder::new(compressed);
        let mut buf = [0u8; 4096];
        while let Ok(n) = dec.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    #[test]
    fn the_matcher_catches_the_raw_the_percent_encoded_and_each_base64_alignment() {
        let m = matcher();
        let caught = |text: &[u8]| m.scanner().feed(text).is_err();
        assert!(caught(format!("a={VALUE}&b=1").as_bytes()), "raw");
        // Percent-encoded by encoders this module did not write.
        for set in [EVERYTHING, &UNRESERVED_KEPT, &PATH_KEPT, &FORM_KEPT] {
            let upper = percent_encoding::utf8_percent_encode(VALUE, set).to_string();
            assert!(upper.contains('%'), "the set encodes something");
            assert!(caught(format!("k={upper};").as_bytes()), "upper-case hex");
            let lower = lower_hex(&upper);
            assert!(lower != upper, "the hex digits changed case");
            assert!(caught(format!("k={lower};").as_bytes()), "lower-case hex");
        }
        // Base64 of a text the value sits in, at each offset and with each remainder.
        for before in ["", "u", "us", "use"] {
            for after in ["", "x", "xy", "xyz"] {
                let text = format!("{before}{VALUE}{after}");
                assert!(caught(STANDARD.encode(&text).as_bytes()), "standard");
                assert!(caught(URL_SAFE.encode(&text).as_bytes()), "url-safe");
                assert!(caught(URL_SAFE_NO_PAD.encode(&text).as_bytes()), "no pad");
                let form = percent_encoding::utf8_percent_encode(
                    &STANDARD.encode(&text),
                    percent_encoding::NON_ALPHANUMERIC,
                )
                .to_string();
                assert!(caught(form.as_bytes()), "base64 in a form body");
            }
        }
        assert!(!caught(&clean(4096)), "near misses are not matches");
    }

    /// `%XX` escapes with lower-case hex digits, everything else as it was.
    fn lower_hex(encoded: &str) -> String {
        let mut out = String::with_capacity(encoded.len());
        let mut escape = 0;
        for c in encoded.chars() {
            if c == '%' {
                escape = 2;
                out.push(c);
            } else if escape > 0 {
                escape -= 1;
                out.push(c.to_ascii_lowercase());
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn a_value_split_across_any_two_chunks_is_caught() {
        let m = matcher();
        for needle in [
            VALUE.to_owned(),
            STANDARD.encode(format!("u:{VALUE}")),
            percent_encoding::utf8_percent_encode(VALUE, percent_encoding::NON_ALPHANUMERIC)
                .to_string(),
        ] {
            let body = format!("{{\"note\":\"{needle}\",\"n\":1}}").into_bytes();
            for i in 0..=body.len() {
                for j in i..=body.len() {
                    let (_, hit, _) = feed_all(&m, &[&body[..i], &body[i..j], &body[j..]]);
                    assert!(
                        hit.is_some_and(|h| h.trap == "aws"),
                        "a split hid the value"
                    );
                }
            }
            let single: Vec<&[u8]> = body.chunks(1).collect();
            assert!(feed_all(&m, &single).1.is_some(), "a byte at a time");
        }
    }

    #[test]
    fn a_complete_value_is_never_forwarded() {
        let m = matcher();
        let mut body = clean(700);
        let at = body.len();
        body.extend_from_slice(VALUE.as_bytes());
        body.extend_from_slice(&clean(300));
        for i in 0..=body.len() {
            for size in [1, 2, 3, 5, 17, 64, 1000] {
                let (head, rest) = body.split_at(i);
                let mut chunks: Vec<&[u8]> = vec![head];
                chunks.extend(rest.chunks(size));
                let (out, hit, _) = feed_all(&m, &chunks);
                assert!(hit.is_some(), "the value was missed");
                assert!(!contains(&out, VALUE.as_bytes()), "the value was released");
                // Stronger than the decision asks: no byte of the value has left.
                assert!(out.len() <= at, "a byte of the value was released");
                assert!(
                    out == body[..out.len()],
                    "what left is a prefix of what came"
                );
            }
        }
    }

    #[test]
    fn no_more_than_the_longest_pattern_less_one_is_held_back() {
        let m = matcher();
        let bound = m.longest() - 1;
        assert!(m.longest() >= VALUE.len() * 4 / 3, "the base64 forms count");
        let body = clean(5000);
        for size in [1, 2, 7, 31, bound, bound + 1, 4096] {
            let mut scanner = m.scanner();
            let mut released = 0;
            let mut fed = 0;
            for chunk in body.chunks(size) {
                released += scanner.feed(chunk).expect("clean").len();
                fed += chunk.len();
                assert!(scanner.held() <= bound, "more than the bound was held");
                assert_eq!(released + scanner.held(), fed, "a byte is unaccounted for");
                // Nothing is held that need not be: all but the bound has left.
                assert_eq!(scanner.held(), fed.min(bound));
            }
            assert_eq!(scanner.finish().len(), body.len().min(bound));
        }
    }

    #[test]
    fn a_clean_body_comes_out_byte_for_byte() {
        let m = matcher();
        let body = clean(20_000);
        for size in [1, 2, 3, 7, 64, 1000, 20_000] {
            let chunks: Vec<&[u8]> = body.chunks(size).collect();
            let (out, hit, _) = feed_all(&m, &chunks);
            assert!(hit.is_none(), "a clean body matched");
            assert!(out == body, "a clean body changed");
        }
        let (out, hit, _) = feed_all(&m, &[]);
        assert!(out.is_empty() && hit.is_none());
    }

    #[test]
    fn a_few_mebibytes_are_scanned_whole_and_the_value_at_their_end_is_caught() {
        let m = matcher();
        let mut body = clean(4 * 1024 * 1024);
        let at = body.len();
        let chunks: Vec<&[u8]> = body.chunks(16 * 1024).collect();
        let (out, hit, most) = feed_all(&m, &chunks);
        assert!(hit.is_none() && out == body, "a clean body of size changed");
        assert!(most < m.longest(), "the hold-back grew with the body");
        body.extend_from_slice(PLAIN.as_bytes());
        let chunks: Vec<&[u8]> = body.chunks(16 * 1024).collect();
        let (out, hit, _) = feed_all(&m, &chunks);
        assert!(hit.is_some_and(|h| h.trap == "github"));
        assert!(out.len() <= at && out == body[..out.len()]);
    }

    #[test]
    fn a_basic_pair_is_decoded_and_either_half_matches() {
        let m = matcher();
        let head = |value: String| {
            let mut headers = http::HeaderMap::new();
            headers.insert(http::header::AUTHORIZATION, value.parse().unwrap());
            m.in_head("/v1/x", &headers)
        };
        for pair in [format!("deploy:{VALUE}"), format!("{VALUE}:x-oauth-basic")] {
            for encoded in [
                STANDARD.encode(&pair),
                STANDARD_NO_PAD.encode(&pair),
                URL_SAFE.encode(&pair),
            ] {
                let hit = head(format!("Basic {encoded}"));
                assert!(hit.is_some_and(|h| h.trap == "aws"), "a Basic half");
                assert!(head(format!("basic   {encoded}")).is_some(), "any case");
            }
        }
        assert!(
            head(format!(
                "Basic {}",
                STANDARD.encode("deploy:hunter2-hunter2")
            ))
            .is_none()
        );
        assert!(head("Basic !!!not-base64!!!".to_owned()).is_none());
        assert!(head(format!("Bearer {PLAIN}")).is_some(), "a bearer");
        assert!(head("Bearer something-else-entirely".to_owned()).is_none());
        // The decoding itself, apart from the alignment patterns.
        assert_eq!(
            basic_pair(b"Basic dTpw").as_deref(),
            Some(b"u:p".as_slice())
        );
        assert_eq!(
            basic_pair(b" basic\tdTpwYQ== ").as_deref(),
            Some(b"u:pa".as_slice())
        );
        assert_eq!(
            basic_pair(b"BASIC dTpwYQ").as_deref(),
            Some(b"u:pa".as_slice())
        );
        assert!(basic_pair(b"Basicd dTpw").is_none());
        assert!(basic_pair(b"Bas").is_none());
    }

    #[test]
    fn bait_in_any_header_the_path_or_the_query_is_found_before_any_upstream() {
        let m = matcher();
        let none = http::HeaderMap::new();
        let every_byte = PLAIN.bytes().fold(String::new(), |mut text, b| {
            text.push('%');
            text.push_str(&hex::encode([b]));
            text
        });
        for path in [
            format!("/repos/{PLAIN}/x"),
            format!("/x?token={PLAIN}&a=1"),
            format!("/x?token={every_byte}"),
            format!("/{every_byte}/x"),
            format!("/x?blob={}", URL_SAFE_NO_PAD.encode(format!("k={PLAIN}"))),
        ] {
            let hit = m.in_head(&path, &none);
            assert!(hit.is_some_and(|h| h.trap == "github"), "the path or query");
        }
        for name in ["x-api-key", "cookie", "private-token", "x-anything-at-all"] {
            for value in [
                PLAIN.to_owned(),
                format!("session=abc; t={PLAIN}; z=1"),
                format!("t={every_byte}"),
            ] {
                let mut headers = http::HeaderMap::new();
                headers.insert("accept", "*/*".parse().unwrap());
                headers.insert(http::HeaderName::from_static(name), value.parse().unwrap());
                assert!(m.in_head("/", &headers).is_some(), "a header value");
            }
        }
        let mut headers = http::HeaderMap::new();
        headers.insert("x-api-key", "the-phantom-or-anything-else".parse().unwrap());
        headers.insert("cookie", "a=1; b=%7e%zz".parse().unwrap());
        assert!(m.in_head("/v1/messages?beta=true&x=%", &headers).is_none());
    }

    #[test]
    fn a_method_and_every_header_name_are_matched_whatever_case_hyper_gave_them() {
        // S3 of the review. hyper keeps an extension method as sent and lower-cases a name; a
        // value that is all one case (hex, an access key id) survives that whole.
        let hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let akia = "AKIAQ7TRIPWIREBAIT42";
        let m = Matcher::new(&bait(&[("jwt", hex), ("aws", akia)]));
        assert_eq!(m.in_method(akia).map(|h| h.trap), Some("aws".to_owned()));
        assert_eq!(
            m.in_method(&format!("X{akia}Y")).map(|h| h.trap),
            Some("aws".to_owned())
        );
        for method in ["GET", "POST", "PROPFIND", "M-SEARCH"] {
            assert!(m.in_method(method).is_none());
        }
        for (value, trap) in [(hex, "jwt"), (akia, "aws")] {
            for name in [value.to_owned(), format!("x-{value}-y")] {
                let mut headers = http::HeaderMap::new();
                headers.insert(
                    http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    "1".parse().unwrap(),
                );
                assert_eq!(
                    m.in_head("/", &headers).map(|h| h.trap),
                    Some(trap.to_owned()),
                    "a header name"
                );
            }
        }
        let mut headers = http::HeaderMap::new();
        headers.insert("x-request-id", "1".parse().unwrap());
        headers.insert("accept-encoding", "gzip".parse().unwrap());
        assert!(m.in_head("/", &headers).is_none());
        // A name read case-insensitively is a lookup in that name, never in a value.
        assert!(m.in_name(b"content-type").is_none());
    }

    #[tokio::test]
    async fn a_gzip_body_is_decoded_for_the_matcher_and_forwarded_as_it_came() {
        let m = matcher();
        let clean_plain = clean(50_000);
        let mut dirty_plain = clean(30_000);
        dirty_plain.extend_from_slice(VALUE.as_bytes());
        dirty_plain.extend_from_slice(&clean(30_000));
        let zlib = |plain: &[u8]| {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(plain).unwrap();
            e.finish().unwrap()
        };
        let raw = |plain: &[u8]| {
            let mut e =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(plain).unwrap();
            e.finish().unwrap()
        };
        let cases = [
            (
                Encoding::Gzip,
                gzip(&clean_plain, flate2::Compression::default()),
                gzip(&dirty_plain, flate2::Compression::default()),
            ),
            (Encoding::Deflate, zlib(&clean_plain), zlib(&dirty_plain)),
            (Encoding::Deflate, raw(&clean_plain), raw(&dirty_plain)),
        ];
        for (encoding, good, bad) in cases {
            assert!(
                !contains(&bad, VALUE.as_bytes()),
                "the fixture hides the value"
            );
            for size in [1, 5, 512, 1 << 20] {
                let chunks: Vec<&[u8]> = good.chunks(size).collect();
                let y = drain(ScanBody::new(
                    Chunks::of(&chunks),
                    m.clone(),
                    encoding,
                    None,
                ))
                .await;
                assert!(y.error.is_none(), "a clean compressed body was refused");
                assert!(
                    y.data == good,
                    "a compressed body was not forwarded as it came"
                );

                let chunks: Vec<&[u8]> = bad.chunks(size).collect();
                let (told, on_hit) = sink();
                let y = drain(ScanBody::new(
                    Chunks::of(&chunks),
                    m.clone(),
                    encoding,
                    on_hit,
                ))
                .await;
                assert!(
                    matches!(&y.error, Some(ScanError::Trap(hit)) if hit.trap == "aws"),
                    "bait in a compressed body passed"
                );
                assert_eq!(*told.lock().unwrap(), ["aws"]);
                assert!(y.data.len() < bad.len() && y.data == bad[..y.data.len()]);
            }
        }
        // A second gzip member is read too: some servers do.
        let mut two = gzip(&clean_plain, flate2::Compression::default());
        two.extend_from_slice(&gzip(VALUE.as_bytes(), flate2::Compression::default()));
        let y = drain(ScanBody::new(
            Chunks::of(&[&two]),
            m.clone(),
            Encoding::Gzip,
            None,
        ))
        .await;
        assert!(
            matches!(y.error, Some(ScanError::Trap(_))),
            "the second member"
        );
    }

    #[tokio::test]
    async fn the_gzip_chunk_that_completes_a_value_is_never_released() {
        let m = matcher();
        let mut plain = clean(300);
        plain.extend_from_slice(VALUE.as_bytes());
        plain.extend_from_slice(&clean(300));
        // Compressed, and stored: a stored block carries the plaintext as it is.
        for level in [flate2::Compression::default(), flate2::Compression::none()] {
            let body = gzip(&plain, level);
            let mut splits: Vec<Vec<&[u8]>> = (0..=body.len())
                .map(|i| vec![&body[..i], &body[i..]])
                .collect();
            splits.push(body.chunks(1).collect());
            splits.push(body.chunks(7).collect());
            for chunks in splits {
                let y = drain(ScanBody::new(
                    Chunks::of(&chunks),
                    m.clone(),
                    Encoding::Gzip,
                    None,
                ))
                .await;
                assert!(
                    matches!(y.error, Some(ScanError::Trap(_))),
                    "the value was missed"
                );
                assert_eq!(y.after_error, 0, "a frame followed the error");
                assert!(y.data == body[..y.data.len()], "what left is a prefix");
                assert!(
                    !contains(&gunzip_prefix(&y.data), VALUE.as_bytes()),
                    "the released bytes decode to the value"
                );
                assert!(
                    !contains(&y.data, VALUE.as_bytes()),
                    "the value left as stored"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_gzip_bomb_stops_at_the_expansion_bound() {
        let m = matcher();
        let bomb = gzip(&vec![0u8; 8 * 1024 * 1024], flate2::Compression::best());
        assert!(
            u64::try_from(bomb.len()).unwrap() * EXPANSION_RATIO < EXPANSION_FLOOR,
            "the fixture is under the floor"
        );
        let (told, on_hit) = sink();
        let chunks: Vec<&[u8]> = bomb.chunks(1024).collect();
        let y = drain(ScanBody::new(
            Chunks::of(&chunks),
            m.clone(),
            Encoding::Gzip,
            on_hit,
        ))
        .await;
        assert!(
            matches!(y.error, Some(ScanError::Expansion)),
            "the bomb passed"
        );
        assert_eq!(*told.lock().unwrap(), [TRAP_EXPANSION]);
        assert!(y.data.len() < bomb.len(), "the whole bomb was forwarded");
        // Under the floor a very repetitive honest body passes, whatever its ratio.
        let small = gzip(&vec![b' '; 512 * 1024], flate2::Compression::best());
        let y = drain(ScanBody::new(
            Chunks::of(&[&small]),
            m.clone(),
            Encoding::Gzip,
            None,
        ))
        .await;
        assert!(
            y.error.is_none() && y.data == small,
            "an honest body was refused"
        );
        // Past the floor the ratio holds, and never past the cap.
        assert_eq!(allowance(0), EXPANSION_FLOOR);
        assert_eq!(allowance(1024), EXPANSION_FLOOR);
        assert_eq!(allowance(65_536), 4 * 1024 * 1024);
        assert_eq!(allowance(EXPANSION_FLOOR), EXPANSION_CAP);
        assert_eq!(allowance(u64::MAX), EXPANSION_CAP);
        let big = gzip(&vec![0u8; 48 * 1024 * 1024], flate2::Compression::best());
        let allowed = allowance(u64::try_from(big.len()).unwrap());
        assert!(allowed > EXPANSION_FLOOR && allowed < 48 * 1024 * 1024);
        let y = drain(ScanBody::new(
            Chunks::of(&[&big]),
            m.clone(),
            Encoding::Gzip,
            None,
        ))
        .await;
        assert!(
            matches!(y.error, Some(ScanError::Expansion)),
            "the ratio did not hold"
        );
    }

    #[tokio::test]
    async fn a_body_that_is_not_what_its_encoding_says_is_treated_as_a_match() {
        let m = matcher();
        let good = gzip(&clean(5000), flate2::Compression::default());
        let mut trailing = good.clone();
        trailing.extend_from_slice(b"not a gzip member");
        for (encoding, body) in [
            (Encoding::Gzip, clean(500)),
            (Encoding::Gzip, trailing),
            // A final block of the reserved type, bare and behind a zlib header.
            (Encoding::Deflate, vec![0x07, 0x00, 0x00, 0x00]),
            (Encoding::Deflate, vec![0x78, 0x9c, 0x07, 0x00, 0x00, 0x00]),
        ] {
            let (told, on_hit) = sink();
            let y = drain(ScanBody::new(
                Chunks::of(&[&body]),
                m.clone(),
                encoding,
                on_hit,
            ))
            .await;
            assert!(
                matches!(y.error, Some(ScanError::Decode)),
                "an undecodable body passed"
            );
            assert_eq!(*told.lock().unwrap(), [TRAP_UNDECODABLE]);
            assert!(y.data.len() < body.len());
        }
        // A stream cut short is not one: nothing more can be derived from what came.
        let cut = &good[..good.len() - 9];
        let y = drain(ScanBody::new(
            Chunks::of(&[cut]),
            m.clone(),
            Encoding::Gzip,
            None,
        ))
        .await;
        assert!(y.error.is_none() && y.data == cut);
    }

    #[tokio::test]
    async fn an_encoding_the_proxy_cannot_decode_is_named_unsupported() {
        let of = |values: &[&str]| {
            let mut headers = http::HeaderMap::new();
            for v in values {
                headers.append(http::header::CONTENT_ENCODING, v.parse().unwrap());
            }
            encoding_of(&headers)
        };
        assert_eq!(of(&[]), Encoding::Identity);
        assert_eq!(of(&["identity"]), Encoding::Identity);
        assert_eq!(of(&[""]), Encoding::Identity);
        assert_eq!(of(&["gzip"]), Encoding::Gzip);
        assert_eq!(of(&[" GZip "]), Encoding::Gzip);
        assert_eq!(of(&["x-gzip"]), Encoding::Gzip);
        assert_eq!(of(&["deflate"]), Encoding::Deflate);
        for other in [
            &["br"][..],
            &["zstd"],
            &["compress"],
            &["gzip, gzip"],
            &["gzip, identity"],
            &["gzip", "gzip"],
            &["identity", "identity"],
            &["gzipx"],
        ] {
            assert_eq!(of(other), Encoding::Unsupported);
        }
        // Wrapped anyway: nothing is read, nothing forwarded, and it is not a trip.
        let (told, on_hit) = sink();
        let body = ScanBody::new(
            Chunks::of(&[b"anything"]),
            matcher(),
            Encoding::Unsupported,
            on_hit,
        );
        assert!(!body.is_end_stream());
        let y = drain(body).await;
        assert!(matches!(y.error, Some(ScanError::Unsupported)));
        assert!(y.data.is_empty() && told.lock().unwrap().is_empty());
        // Report-only: it passes unscanned.
        let body = ScanBody::new(
            Chunks::of(&[VALUE.as_bytes()]),
            matcher(),
            Encoding::Unsupported,
            None,
        )
        .report_only();
        let y = drain(body).await;
        assert!(y.error.is_none() && y.data == VALUE.as_bytes());
    }

    #[tokio::test]
    async fn a_hit_names_the_catalogue_entry_and_never_the_value() {
        let m = matcher();
        let mut scanner = m.scanner();
        let _ = scanner.feed(&VALUE.as_bytes()[..10]);
        let held = format!("{scanner:?}");
        let hit = scanner.feed(&VALUE.as_bytes()[10..]).unwrap_err();
        assert_eq!(hit.trap, "aws");
        assert_eq!(
            scanner.feed(b"more").unwrap_err(),
            hit,
            "the scanner stays stopped"
        );
        assert!(
            scanner.finish().is_empty(),
            "nothing is released after a hit"
        );
        let body = ScanBody::new(
            Chunks::of(&[VALUE.as_bytes()]),
            m.clone(),
            Encoding::Identity,
            None,
        );
        let wrapped = format!("{body:?}");
        let error = drain(body).await.error.expect("a trap");
        let printed = format!("{hit:?} {m:?} {held} {wrapped} {error} {error:?}");
        for secret in [VALUE, PLAIN, &VALUE[..10], &STANDARD.encode(VALUE)] {
            assert!(!printed.contains(secret), "a printed form holds bait");
        }
        assert!(printed.contains("aws"));
    }

    #[tokio::test]
    async fn after_a_hit_the_body_yields_nothing_more_and_ends_in_an_error() {
        let m = matcher();
        let before = clean(2000);
        let after = clean(2000);
        let (told, on_hit) = sink();
        let body = ScanBody::new(
            Chunks::of(&[
                &before,
                &VALUE.as_bytes()[..9],
                &VALUE.as_bytes()[9..],
                &after,
                PLAIN.as_bytes(),
            ]),
            m.clone(),
            Encoding::Identity,
            on_hit,
        );
        let y = drain(body).await;
        assert!(matches!(&y.error, Some(ScanError::Trap(hit)) if hit.trap == "aws"));
        assert_eq!(y.after_error, 0, "a frame followed the error");
        assert_eq!(*told.lock().unwrap(), ["aws"], "the sink is told once");
        assert!(y.data.len() <= before.len() && y.data == before[..y.data.len()]);
    }

    #[tokio::test]
    async fn under_report_only_a_hit_is_told_once_and_the_body_passes_whole() {
        let m = matcher();
        let plain = [
            clean(900).as_slice(),
            VALUE.as_bytes(),
            PLAIN.as_bytes(),
            &clean(900),
        ]
        .concat();
        let zipped = gzip(&plain, flate2::Compression::default());
        for (encoding, body) in [(Encoding::Identity, &plain), (Encoding::Gzip, &zipped)] {
            for size in [1, 13, 4096] {
                let chunks: Vec<&[u8]> = body.chunks(size).collect();
                let (told, on_hit) = sink();
                let wrapped =
                    ScanBody::new(Chunks::of(&chunks), m.clone(), encoding, on_hit).report_only();
                let y = drain(wrapped).await;
                assert!(y.error.is_none(), "report-only ended a body");
                assert!(y.data == *body, "report-only changed a body");
                assert_eq!(*told.lock().unwrap(), ["aws"], "told once, the first trap");
            }
        }
    }

    #[tokio::test]
    async fn trailers_are_matched_and_passed_after_the_tail() {
        let m = matcher();
        let data = clean(100);
        let with = |value: &str| {
            let mut trailers = http::HeaderMap::new();
            trailers.insert("x-checksum", value.parse().unwrap());
            let mut frames = Chunks::of(&[&data]);
            frames.0.push_back(Frame::trailers(trailers));
            frames
        };
        let y = drain(ScanBody::new(
            with("abc123"),
            m.clone(),
            Encoding::Identity,
            None,
        ))
        .await;
        assert!(
            y.error.is_none() && y.data == data,
            "the tail precedes the trailers"
        );
        assert!(y.trailers.is_some_and(|t| t["x-checksum"] == "abc123"));
        let (told, on_hit) = sink();
        let y = drain(ScanBody::new(
            with(PLAIN),
            m.clone(),
            Encoding::Identity,
            on_hit,
        ))
        .await;
        assert!(matches!(y.error, Some(ScanError::Trap(_))) && y.trailers.is_none());
        assert_eq!(*told.lock().unwrap(), ["github"]);
        let (told, on_hit) = sink();
        let wrapped = ScanBody::new(with(PLAIN), m.clone(), Encoding::Identity, on_hit);
        let y = drain(wrapped.report_only()).await;
        assert!(y.error.is_none() && y.data == data && y.trailers.is_some());
        assert_eq!(told.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_size_and_the_end_are_the_inner_bodys() {
        let m = matcher();
        let empty = ScanBody::new(
            http_body_util::Empty::<Bytes>::new(),
            m.clone(),
            Encoding::Identity,
            None,
        );
        assert!(empty.is_end_stream(), "a request with no body has none");
        assert_eq!(empty.size_hint().exact(), Some(0));
        let data = clean(1000);
        let mut body = ScanBody::new(
            http_body_util::Full::new(Bytes::from(data.clone())),
            m.clone(),
            Encoding::Identity,
            None,
        );
        assert_eq!(body.size_hint().exact(), Some(1000));
        assert!(!body.is_end_stream());
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first.len(), 1000 - (m.longest() - 1));
        assert!(!body.is_end_stream(), "the tail is still owed");
        assert_eq!(
            body.size_hint().exact(),
            Some(u64::try_from(m.longest() - 1).unwrap())
        );
        let rest = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!([first, rest].concat(), data);
        assert!(body.frame().await.is_none() && body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
    }

    #[tokio::test]
    async fn a_body_that_fails_ends_in_its_own_error_and_tells_no_one() {
        struct Failing(bool);
        impl http_body::Body for Failing {
            type Data = Bytes;
            type Error = std::io::Error;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
                if self.0 {
                    return Poll::Ready(Some(Err(std::io::Error::other("reset"))));
                }
                self.0 = true;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"some bytes")))))
            }
        }
        let (told, on_hit) = sink();
        let y = drain(ScanBody::new(
            Failing(false),
            matcher(),
            Encoding::Identity,
            on_hit,
        ))
        .await;
        assert!(matches!(y.error, Some(ScanError::Upstream(_))));
        assert!(y.data.is_empty() && told.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_value_too_short_to_match_is_no_pattern_and_no_bait_matches_nothing() {
        let none = Arc::new(Matcher::new(&[]));
        assert_eq!((none.patterns(), none.longest()), (0, 0));
        assert!(none.built());
        assert!(
            none.in_head(&format!("/{VALUE}"), &http::HeaderMap::new())
                .is_none()
        );
        let y = drain(ScanBody::new(
            Chunks::of(&[b"ab", b"cd"]),
            none.clone(),
            Encoding::Identity,
            None,
        ))
        .await;
        assert!(
            y.error.is_none() && y.data == b"abcd",
            "nothing is held with no pattern"
        );
        let short = Matcher::new(&bait(&[("short", "abc1234"), ("empty", "")]));
        assert_eq!(short.patterns(), 0);
        assert!(short.scanner().feed(b"xx abc1234 xx").is_ok());
        let floor = Matcher::new(&bait(&[("floor", "abc12345")]));
        assert!(floor.patterns() > 0);
        assert!(floor.scanner().feed(b"xx abc12345 xx").is_err());
        // One value under two names: the first named wins, and it is one set of patterns.
        let twice = Matcher::new(&bait(&[("first", PLAIN), ("second", PLAIN)]));
        assert_eq!(
            twice.patterns(),
            Matcher::new(&bait(&[("first", PLAIN)])).patterns()
        );
        assert_eq!(
            twice.scanner().feed(PLAIN.as_bytes()).unwrap_err().trap,
            "first"
        );
    }

    #[test]
    fn the_pattern_count_is_bounded_per_value() {
        // 1 raw, 12 percent forms, and per alignment 2 base64 and 2 percent-encoded base64.
        assert!(forms_of(VALUE.as_bytes()).len() <= 1 + 12 + 3 * 4);
        let one = Matcher::new(&bait(&[("aws", VALUE)]));
        assert!(one.patterns() > 3 * 2, "raw and the base64 alignments");
        // A value of letters and digits has one percent form: itself.
        let plain = Matcher::new(&bait(&[("github", PLAIN)]));
        assert!(plain.patterns() <= 1 + 3 * 2 + 3 * 2);
    }
}
