// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The audience catalog (ADR-0055 decisions 2 to 4): the definitions notaio signed as audience
//! bundles, after [`mediatore_policy::admit_audience`] verified them and moved their floor, checked
//! again here and held as one immutable snapshot that every reader resolves against.
//!
//! The kind of an audience is never read from the bundle: an audience in the platform namespace is
//! a platform audience, anywhere else a team audience, usable only from its own namespace. A
//! collision (a team audience with a platform audience's name, two audiences one namespace can see
//! on one endpoint) is refused when it is resolved, from the namespaces that see both and only
//! there, so the outcome does not depend on which bundle was read first and one team cannot take a
//! platform audience away from another.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use futures::StreamExt as _;
use jiff::Timestamp;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::runtime::WatchStreamExt as _;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, ResourceExt};
use mediatore_policy::types::{
    AudienceDefinition, Backend, CredentialFormat, CredentialSource, Placement,
};
use mediatore_policy::{AudienceBundlePayload, Envelope, Refusal, TrustedKeys, admit_audience};
use mediatore_proto::{Endpoint, EndpointRule};
use mediatore_store::ClaimStore;

/// The `ConfigMap` key notaio writes an audience bundle under (notaio ADR-0020 decision 10).
pub const AUDIENCE_KEY: &str = "audience.dsse.json";
/// Between sweeps of expired definitions out of the catalog.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// Header names an audience may never set: they frame the request or belong to the proxy. The
/// same list as notaio's `L026` (`sandboxpolicy-core`'s `RESERVED_HEADERS`).
pub const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "te",
    "upgrade",
    "trailer",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
];

/// Platform or team, derived from the namespace the definition lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceKind {
    /// In the platform namespace: visible from every namespace.
    Platform,
    /// Anywhere else: visible from its own namespace only.
    Team,
}

impl AudienceKind {
    /// For logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Team => "team",
        }
    }
}

/// One admitted definition, with what the broker parsed out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audience {
    /// The namespace it lives in.
    pub namespace: String,
    /// Its name, the audience a claim asks for.
    pub name: String,
    /// The `SandboxAudience`'s incarnation.
    pub uid: String,
    /// The bundle version it was admitted at.
    pub version: u64,
    /// The bundle's `notAfter`: past it the definition is gone.
    pub not_after: Timestamp,
    /// Platform or team.
    pub kind: AudienceKind,
    /// The definition as signed.
    pub definition: AudienceDefinition,
    /// The definition's endpoints, parsed and lowercased.
    pub endpoints: Vec<Endpoint>,
    /// The definition's rules, the widest any grant may be. Empty means every method and path.
    pub rules: Vec<EndpointRule>,
}

/// Why a verified definition was not taken into the catalog (ADR-0055 decision 4). The code is
/// notaio's lint code where there is one, so a refusal here reads against `notaio lint`.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum Inadmissible {
    /// A team audience with a backend that acts with the platform's keys.
    #[error("a team audience's backend is secret or none")]
    TeamBackend,
    /// A team audience whose credential is in `OpenBao`: the broker would read a path a team chose.
    #[error("a team audience's credential is a Secret in its own namespace, never OpenBao")]
    TeamOpenBao,
    /// A `secret` backend with nowhere to read the credential from.
    #[error("the secret backend needs a credential source")]
    NoSource,
    /// A header that is not a lowercase token or is reserved.
    #[error("header {0:?} is not a lowercase token, or is reserved")]
    Header(String),
    /// An extra header whose value is empty, not printable ASCII, or edged with whitespace
    /// (notaio ADR-0020 as amended, L026). Names the header, never the value.
    #[error(
        "the value of extra header {0:?} is empty, not printable ASCII, or edged with whitespace"
    )]
    HeaderValue(String),
    /// An endpoint that is not an exact DNS `host:port`.
    #[error("endpoint {0:?} is not an exact DNS host:port")]
    Endpoint(String),
    /// A rule the proxy cannot match.
    #[error("rule {{ method: {method:?}, path: {path:?} }}: {why}")]
    Rule {
        /// The rule's method.
        method: String,
        /// The rule's path glob.
        path: String,
        /// Why it was refused.
        why: String,
    },
    /// A zero `maxTtlSeconds`.
    #[error("maxTtlSeconds is zero")]
    NoTtl,
    /// Something this broker cannot serve yet; refused rather than served without it.
    #[error("{0} is not served by this broker yet")]
    NotBuilt(&'static str),
}

impl Inadmissible {
    /// A stable name for logs.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TeamBackend => "L022",
            Self::TeamOpenBao => "L023",
            Self::Header(_) | Self::HeaderValue(_) => "L026",
            Self::Endpoint(_) | Self::Rule { .. } => "L017",
            Self::NoSource => "NoSource",
            Self::NoTtl => "NoTtl",
            Self::NotBuilt(_) => "NotBuilt",
        }
    }
}

fn header_ok(h: &str) -> bool {
    const TCHAR_SYMBOLS: &[u8] = b"!#$%&'*+-.^_`|~";
    !h.is_empty()
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || TCHAR_SYMBOLS.contains(&b))
        && !RESERVED_HEADERS.contains(&h)
}

/// notaio's L026 for a value: non-empty, printable ASCII with inner spaces and tabs only, nothing
/// that could end the header line (no CR, no LF, no other control character).
fn header_value_ok(v: &str) -> bool {
    let edge = |c: char| c == ' ' || c == '\t';
    !v.is_empty()
        && !v.starts_with(edge)
        && !v.ends_with(edge)
        && v.bytes().all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
}

fn endpoint(s: &str) -> Result<Endpoint, Inadmissible> {
    let refuse = || Inadmissible::Endpoint(s.to_owned());
    let mut e = s.parse::<Endpoint>().map_err(|_| refuse())?;
    if e.host.contains('*') || e.host.parse::<std::net::IpAddr>().is_ok() {
        return Err(refuse());
    }
    e.host = e.host.to_ascii_lowercase();
    Ok(e)
}

fn rule(r: &mediatore_policy::types::EndpointRule) -> Result<EndpointRule, Inadmissible> {
    let refuse = |why: String| Inadmissible::Rule {
        method: r.method.clone(),
        path: r.path.clone(),
        why,
    };
    let method_ok = r.method == "*"
        || (!r.method.is_empty() && r.method.chars().all(|c| c.is_ascii_alphabetic()));
    if !method_ok || !r.path.starts_with('/') {
        return Err(refuse(
            "needs an HTTP method or `*` and an absolute path glob".into(),
        ));
    }
    // The enforcement points refuse such a request path before any rule (`path_is_canonical`),
    // so a rule spelled that way matches nothing and would only mislead a coverage check.
    if !mediatore_proto::path_is_canonical(&r.path) {
        return Err(refuse(
            "a dot segment, an empty segment or an encoded separator, which no admitted request has"
                .into(),
        ));
    }
    let out = EndpointRule {
        method: r.method.clone(),
        path: r.path.clone(),
    };
    out.validate().map_err(refuse)?;
    Ok(out)
}

/// Check a verified payload again, as ADR-0055 decision 4 has it: the consumer does not trust that
/// the producer was right. `payload` must come from [`mediatore_policy::admit_audience`], which
/// has already refused one read from another namespace than its own.
///
/// # Errors
/// The first rule the definition breaks.
pub fn audience_of(
    payload: &AudienceBundlePayload,
    platform_namespace: &str,
) -> Result<Audience, Inadmissible> {
    let content = &payload.content;
    let d = &content.definition;
    let kind = if content.audience.namespace == platform_namespace {
        AudienceKind::Platform
    } else {
        AudienceKind::Team
    };
    if kind == AudienceKind::Team {
        if !matches!(d.credential.backend, Backend::Secret | Backend::None) {
            return Err(Inadmissible::TeamBackend);
        }
        if matches!(d.credential.source, Some(CredentialSource::Openbao(_))) {
            return Err(Inadmissible::TeamOpenBao);
        }
    }
    if d.credential.backend == Backend::Secret && d.credential.source.is_none() {
        return Err(Inadmissible::NoSource);
    }
    let headers = d
        .credential
        .header
        .iter()
        .chain(d.credential.extra_headers.iter().map(|h| &h.name));
    for h in headers {
        if !header_ok(h) {
            return Err(Inadmissible::Header(h.clone()));
        }
    }
    if let Some(h) = d
        .credential
        .extra_headers
        .iter()
        .find(|h| !header_value_ok(&h.value))
    {
        return Err(Inadmissible::HeaderValue(h.name.clone()));
    }
    if d.max_ttl_seconds == 0 {
        return Err(Inadmissible::NoTtl);
    }
    if d.ca_ref.is_some() {
        return Err(Inadmissible::NotBuilt("a CA reference (caRef)"));
    }
    if d.credential.backend == Backend::Secret && d.credential.format == CredentialFormat::Basic {
        return Err(Inadmissible::NotBuilt(
            "an operator-held credential in basic format",
        ));
    }
    let mut endpoints = d
        .endpoints
        .iter()
        .map(|e| endpoint(e))
        .collect::<Result<Vec<_>, _>>()?;
    endpoints.sort();
    endpoints.dedup();
    let rules = d.rules.iter().map(rule).collect::<Result<Vec<_>, _>>()?;
    Ok(Audience {
        namespace: content.audience.namespace.clone(),
        name: content.audience.name.clone(),
        uid: content.audience.uid.clone(),
        version: payload.meta.version,
        not_after: payload.meta.not_after,
        kind,
        definition: d.clone(),
        endpoints,
        rules,
    })
}

/// Why a name does not resolve from a namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unresolved {
    /// No live definition visible from the namespace. The caller says `unknown_audience` and
    /// nothing about other namespaces.
    Unknown,
    /// A team audience in the namespace has a platform audience's name.
    Shadowed {
        /// The team audience's namespace.
        team: String,
        /// The platform namespace.
        platform: String,
    },
    /// Another audience visible from the namespace is on one of its endpoints.
    SharedEndpoint {
        /// The endpoint both declare.
        endpoint: String,
        /// The other audience, `<namespace>/<name>`.
        other: String,
    },
}

/// `(namespace, name)`.
type Key = (String, String);

/// One snapshot of every admitted definition. Immutable: a change builds the next snapshot, and a
/// reader holds the one it took for the length of its request.
#[derive(Debug, Clone, Default)]
pub struct AudienceCatalog {
    platform_namespace: String,
    audiences: BTreeMap<Key, Arc<Audience>>,
}

impl AudienceCatalog {
    /// An empty catalog whose platform audiences live in `platform_namespace`.
    #[must_use]
    pub fn new(platform_namespace: impl Into<String>) -> Self {
        Self {
            platform_namespace: platform_namespace.into(),
            audiences: BTreeMap::new(),
        }
    }

    /// The platform namespace.
    #[must_use]
    pub fn platform_namespace(&self) -> &str {
        &self.platform_namespace
    }

    /// The next snapshot, with `a` added or in place of the one it replaces.
    #[must_use]
    pub fn with(&self, a: Audience) -> Self {
        let mut next = self.clone();
        next.audiences
            .insert((a.namespace.clone(), a.name.clone()), Arc::new(a));
        next
    }

    /// The next snapshot, without `namespace`/`name`, and whether it was held.
    #[must_use]
    pub fn without(&self, namespace: &str, name: &str) -> (Self, bool) {
        let mut next = self.clone();
        let held = next
            .audiences
            .remove(&(namespace.to_owned(), name.to_owned()))
            .is_some();
        (next, held)
    }

    /// The next snapshot without the definitions expired at `now`, and their keys.
    #[must_use]
    pub fn swept(&self, now: Timestamp) -> (Self, Vec<Key>) {
        let mut next = self.clone();
        let mut gone = Vec::new();
        next.audiences.retain(|k, a| {
            let live = a.not_after > now;
            if !live {
                gone.push(k.clone());
            }
            live
        });
        (next, gone)
    }

    /// How many definitions the snapshot holds, expired ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.audiences.len()
    }

    /// No definitions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.audiences.is_empty()
    }

    fn live(&self, namespace: &str, name: &str, now: Timestamp) -> Option<&Arc<Audience>> {
        self.audiences
            .get(&(namespace.to_owned(), name.to_owned()))
            .filter(|a| a.not_after > now)
    }

    /// Every live definition, in every namespace.
    pub fn all_live(&self, now: Timestamp) -> impl Iterator<Item = &Arc<Audience>> + '_ {
        self.audiences.values().filter(move |a| a.not_after > now)
    }

    /// The live definitions a claim in `namespace` can see: every platform audience and the team
    /// audiences of `namespace`.
    pub fn visible_from<'a>(
        &'a self,
        namespace: &'a str,
        now: Timestamp,
    ) -> impl Iterator<Item = &'a Arc<Audience>> + 'a {
        self.audiences.values().filter(move |a| {
            a.not_after > now
                && (a.namespace == self.platform_namespace || a.namespace == namespace)
        })
    }

    /// The definition of `name` for a claim whose record lives in `namespace` (ADR-0055 decisions 2
    /// and 3): the team audience of that namespace or the platform audience of that name, never
    /// both, never another namespace's team audience, and never one sharing an endpoint with
    /// another audience the namespace can see.
    ///
    /// # Errors
    /// [`Unresolved`]: unknown from here, or a collision seen from here.
    pub fn resolve(
        &self,
        namespace: &str,
        name: &str,
        now: Timestamp,
    ) -> Result<&Arc<Audience>, Unresolved> {
        let platform = self.live(&self.platform_namespace, name, now);
        let team = if namespace == self.platform_namespace {
            None
        } else {
            self.live(namespace, name, now)
        };
        let found = match (team, platform) {
            (Some(_), Some(_)) => {
                return Err(Unresolved::Shadowed {
                    team: namespace.to_owned(),
                    platform: self.platform_namespace.clone(),
                });
            }
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => return Err(Unresolved::Unknown),
        };
        for other in self.visible_from(namespace, now) {
            if Arc::ptr_eq(other, found) {
                continue;
            }
            if let Some(e) = found.endpoints.iter().find(|e| other.endpoints.contains(e)) {
                return Err(Unresolved::SharedEndpoint {
                    endpoint: e.to_string(),
                    other: format!("{}/{}", other.namespace, other.name),
                });
            }
        }
        Ok(found)
    }
}

/// The shape of a definition the file and a bundle can both say, for the shadow comparison
/// (ADR-0055 decision 8). Names and values a log may carry, never a credential or a reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape {
    /// `sts`, `secret`, `delegated`, `entra-obo` or `none`.
    pub backend: &'static str,
    /// `gateway` or `proxy`.
    pub placement: &'static str,
    /// `bearer` or `basic`.
    pub format: &'static str,
    /// The header the credential is placed in, lowercase.
    pub header: String,
    /// The names of the further headers, sorted.
    pub extra_headers: Vec<String>,
    /// `host:port`, lowercase, sorted, deduplicated.
    pub endpoints: Vec<String>,
    /// `METHOD path`, sorted, deduplicated.
    pub rules: Vec<String>,
    /// The longest token lifetime, in seconds.
    pub max_ttl: i64,
}

impl Shape {
    /// A shape from its parts, normalized as [`shape_of`] normalizes a definition's.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // one argument per compared field, each named at the call
    pub fn new(
        backend: &'static str,
        placement: &'static str,
        format: &'static str,
        header: &str,
        extra_headers: impl IntoIterator<Item = String>,
        endpoints: impl IntoIterator<Item = String>,
        rules: impl IntoIterator<Item = (String, String)>,
        max_ttl: i64,
    ) -> Self {
        let sorted = |it: Vec<String>| {
            let mut v = it;
            v.sort();
            v.dedup();
            v
        };
        Self {
            backend,
            placement,
            format,
            header: header.to_ascii_lowercase(),
            extra_headers: sorted(
                extra_headers
                    .into_iter()
                    .map(|h| h.to_ascii_lowercase())
                    .collect(),
            ),
            endpoints: sorted(
                endpoints
                    .into_iter()
                    .map(|e| e.to_ascii_lowercase())
                    .collect(),
            ),
            rules: sorted(
                rules
                    .into_iter()
                    .map(|(m, p)| format!("{} {p}", m.to_ascii_uppercase()))
                    .collect(),
            ),
            max_ttl,
        }
    }
}

/// The name a backend has in the configuration and in logs.
#[must_use]
pub const fn backend_name(b: Backend) -> &'static str {
    match b {
        Backend::Sts => "sts",
        Backend::Secret => "secret",
        Backend::Delegated => "delegated",
        Backend::EntraObo => "entra-obo",
        Backend::None => "none",
    }
}

/// The shape of a signed definition.
#[must_use]
pub fn shape_of(d: &AudienceDefinition) -> Shape {
    Shape::new(
        backend_name(d.credential.backend),
        match d.credential.placement {
            Placement::Gateway => "gateway",
            Placement::Proxy => "proxy",
        },
        match d.credential.format {
            CredentialFormat::Bearer => "bearer",
            CredentialFormat::Basic => "basic",
        },
        d.credential.header.as_deref().unwrap_or("authorization"),
        d.credential.extra_headers.iter().map(|h| h.name.clone()),
        d.endpoints.iter().cloned(),
        d.rules.iter().map(|r| (r.method.clone(), r.path.clone())),
        i64::from(d.max_ttl_seconds),
    )
}

/// The fields in which `file` and `bundle` differ, in a fixed order.
#[must_use]
pub fn differences(file: &Shape, bundle: &Shape) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut check = |name, same: bool| {
        if !same {
            out.push(name);
        }
    };
    check("backend", file.backend == bundle.backend);
    check("placement", file.placement == bundle.placement);
    check("format", file.format == bundle.format);
    check("header", file.header == bundle.header);
    check("extra_headers", file.extra_headers == bundle.extra_headers);
    check("endpoints", file.endpoints == bundle.endpoints);
    check("rules", file.rules == bundle.rules);
    check("max_ttl", file.max_ttl == bundle.max_ttl);
    out
}

fn compared(file: &Shape, bundle: &Shape) -> String {
    let diff = differences(file, bundle);
    if diff.is_empty() {
        "matches the file".to_owned()
    } else {
        format!("differs from the file in: {}", diff.join(", "))
    }
}

/// The shadow comparison (ADR-0055 decision 8): for each audience of the file (by name) and each
/// live definition, one verdict. A file audience is compared with the platform definition of its
/// name; a team definition is compared with the file audience of its name if there is one, and
/// otherwise reported as one that would appear. Keys are the file's names for platform audiences
/// and `<namespace>/<name>` for team audiences.
#[must_use]
pub fn shadow_report(
    catalog: &AudienceCatalog,
    file: &BTreeMap<String, Shape>,
    now: Timestamp,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, shape) in file {
        let verdict = match catalog.live(catalog.platform_namespace(), name, now) {
            Some(a) => compared(shape, &shape_of(&a.definition)),
            None => "in the file, no platform definition".to_owned(),
        };
        out.insert(name.clone(), verdict);
    }
    for a in catalog.audiences.values().filter(|a| a.not_after > now) {
        match a.kind {
            AudienceKind::Platform => {
                if !file.contains_key(&a.name) {
                    out.insert(
                        a.name.clone(),
                        "would appear: a platform audience not in the file".to_owned(),
                    );
                }
            }
            AudienceKind::Team => {
                let verdict = match file.get(&a.name) {
                    Some(shape) => format!(
                        "a team audience of {}: {}",
                        a.namespace,
                        compared(shape, &shape_of(&a.definition))
                    ),
                    None => format!("would appear: a team audience of {}", a.namespace),
                };
                out.insert(format!("{}/{}", a.namespace, a.name), verdict);
            }
        }
    }
    out
}

/// The catalog every reader takes its snapshot from, and which namespaces have been listed.
#[derive(Debug)]
pub struct LiveCatalog {
    current: RwLock<Arc<AudienceCatalog>>,
    /// Bumped on every swap, for the credential refresh to read a new audience at once.
    changed: tokio::sync::watch::Sender<u64>,
    synced: RwLock<HashSet<String>>,
    namespaces: Vec<String>,
}

impl LiveCatalog {
    /// An empty catalog over `namespaces`, platform audiences in `platform_namespace`.
    #[must_use]
    pub fn new(platform_namespace: String, namespaces: Vec<String>) -> Self {
        Self {
            current: RwLock::new(Arc::new(AudienceCatalog::new(platform_namespace))),
            changed: tokio::sync::watch::Sender::new(0),
            synced: RwLock::new(HashSet::new()),
            namespaces,
        }
    }

    /// The current snapshot: take it once per request and resolve against it.
    #[must_use]
    pub fn snapshot(&self) -> Arc<AudienceCatalog> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The namespaces read, in the order listed.
    #[must_use]
    pub fn namespaces(&self) -> &[String] {
        &self.namespaces
    }

    /// Whether `namespace`'s first list completed.
    #[must_use]
    pub fn synced(&self, namespace: &str) -> bool {
        self.synced
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(namespace)
    }

    /// Whether every namespace read has completed its first list: until then an audience with no
    /// definition may simply not have been read.
    #[must_use]
    pub fn all_synced(&self) -> bool {
        let listed = self.synced.read().unwrap_or_else(PoisonError::into_inner);
        self.namespaces.iter().all(|n| listed.contains(n))
    }

    /// Whether a claim in `namespace` can be answered: the platform namespace and `namespace`
    /// have completed their first list, so an audience missing from the snapshot is missing, not
    /// unread. A namespace audiences are not read in holds none and is not waited for.
    #[must_use]
    pub fn ready_for(&self, namespace: &str) -> bool {
        let platform = self.snapshot().platform_namespace().to_owned();
        [platform.as_str(), namespace]
            .iter()
            .all(|n| !self.namespaces.iter().any(|w| w == n) || self.synced(n))
    }

    /// Swap in the next snapshot, built from the current one.
    fn update<T>(&self, f: impl FnOnce(&AudienceCatalog) -> (AudienceCatalog, T)) -> T {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        let (next, out) = f(&current);
        *current = Arc::new(next);
        drop(current);
        self.changed.send_modify(|n| *n = n.wrapping_add(1));
        out
    }

    /// Told of every swap.
    #[must_use]
    pub fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changed.subscribe()
    }

    fn mark_synced(&self, namespace: &str) {
        self.synced
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(namespace.to_owned());
    }
}

/// What became of one `ConfigMap` delivery.
#[derive(Debug, PartialEq, Eq)]
pub enum AudienceOutcome {
    /// Verified, the floor written, checked, in the next snapshot.
    Admitted {
        /// `<namespace>/<name>`.
        audience: String,
        /// Platform or team.
        kind: AudienceKind,
        /// The bundle's version.
        version: u64,
    },
    /// Not verified or decided against: the catalog and the floor are as they were.
    Refused {
        /// notaio's error name, or `mediatore-policy`'s.
        code: &'static str,
    },
    /// Verified, but the broker does not take the definition (decision 4): any definition held
    /// for the audience is withdrawn, since notaio has moved past it.
    Withdrawn {
        /// The rule broken.
        code: &'static str,
    },
    /// Not an audience bundle the broker reads.
    Ignored(&'static str),
}

/// The audience reflector (ADR-0055 decision 1): the trusted keys, the store the floor lives in,
/// the namespaces read and the live catalog it fills. Every replica runs it, outside the Lease.
pub struct AudienceReflector {
    store: Arc<dyn ClaimStore>,
    keys: TrustedKeys,
    live: Arc<LiveCatalog>,
    /// `(namespace, configmap)` to the audience it carries, for a delete or a relist.
    configmaps: Mutex<HashMap<(String, String), String>>,
    /// The file's audiences, under `shadow`; each verdict logged when it changes.
    shadow: Option<BTreeMap<String, Shape>>,
    reported: Mutex<BTreeMap<String, String>>,
}

impl AudienceReflector {
    /// A reflector over `namespaces` (the platform namespace and every sandbox namespace).
    #[must_use]
    pub fn new(
        store: Arc<dyn ClaimStore>,
        keys: TrustedKeys,
        platform_namespace: String,
        namespaces: Vec<String>,
    ) -> Self {
        Self {
            store,
            keys,
            live: Arc::new(LiveCatalog::new(platform_namespace, namespaces)),
            configmaps: Mutex::new(HashMap::new()),
            shadow: None,
            reported: Mutex::new(BTreeMap::new()),
        }
    }

    /// Compare every change with the file's audiences and log the verdicts (`shadow`).
    #[must_use]
    pub fn with_shadow(mut self, file: BTreeMap<String, Shape>) -> Self {
        self.shadow = Some(file);
        self
    }

    /// The live catalog the readers take snapshots from.
    #[must_use]
    pub fn live(&self) -> Arc<LiveCatalog> {
        self.live.clone()
    }

    fn platform(&self) -> String {
        self.live.snapshot().platform_namespace().to_owned()
    }

    /// A `ConfigMap` seen (added, changed, or listed at start), at the current time.
    pub async fn applied(&self, cm: &ConfigMap) -> AudienceOutcome {
        self.applied_at(cm, Timestamp::now()).await
    }

    /// [`applied`](Self::applied) with the clock injected: verify, move the floor, check, swap.
    /// Logs the outcome; never the envelope, a credential or a reference.
    pub async fn applied_at(&self, cm: &ConfigMap, now: Timestamp) -> AudienceOutcome {
        let configmap = cm.name_any();
        let namespace = cm.namespace().unwrap_or_default();
        if !self.live.namespaces.contains(&namespace) {
            return AudienceOutcome::Ignored("a namespace audiences are not read in");
        }
        let Some(text) = cm.data.as_ref().and_then(|d| d.get(AUDIENCE_KEY)) else {
            // notaio labels its policy bundles the same way: those are the policy reflector's.
            return AudienceOutcome::Ignored("no audience.dsse.json");
        };
        let Ok(envelope) = serde_json::from_str::<Envelope>(text) else {
            tracing::warn!(namespace = %namespace, configmap = %configmap, "audience bundle ignored: the envelope does not parse");
            return AudienceOutcome::Ignored("the envelope does not parse");
        };
        let payload = match admit_audience(
            self.store.as_ref(),
            &envelope,
            &namespace,
            &self.keys,
            now,
        )
        .await
        {
            Ok(p) => p,
            Err(refusal) => {
                let code = refusal.code();
                let reason = match &refusal {
                    Refusal::Bundle(e) => e.to_string(),
                    other => other.to_string(),
                };
                tracing::warn!(namespace = %namespace, configmap = %configmap, code, reason = %reason, "audience bundle refused; nothing changed");
                return AudienceOutcome::Refused { code };
            }
        };
        let name = payload.content.audience.name.clone();
        let key = (namespace.clone(), configmap.clone());
        let outcome = match audience_of(&payload, &self.platform()) {
            Ok(a) => {
                let (kind, version) = (a.kind, a.version);
                tracing::info!(
                    namespace = %namespace,
                    audience = %name,
                    kind = %kind.as_str(),
                    version,
                    not_after = %a.not_after,
                    "audience definition admitted"
                );
                self.live.update(|c| (c.with(a), ()));
                self.configmaps
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(key, name.clone());
                AudienceOutcome::Admitted {
                    audience: format!("{namespace}/{name}"),
                    kind,
                    version,
                }
            }
            Err(why) => {
                let code = why.code();
                let held = self.live.update(|c| c.without(&namespace, &name));
                tracing::warn!(
                    namespace = %namespace,
                    audience = %name,
                    code,
                    reason = %why,
                    withdrawn = held,
                    "audience definition not taken (ADR-0055 decision 4)"
                );
                self.configmaps
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&key);
                AudienceOutcome::Withdrawn { code }
            }
        };
        self.report(now);
        outcome
    }

    /// The `ConfigMap` is gone: its audience leaves the catalog (the floor stays). `true` when
    /// something was withdrawn.
    pub fn deleted(&self, cm: &ConfigMap) -> bool {
        let namespace = cm.namespace().unwrap_or_default();
        let key = (namespace.clone(), cm.name_any());
        let Some(name) = self
            .configmaps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key)
        else {
            return false;
        };
        let held = self.live.update(|c| c.without(&namespace, &name));
        if held {
            tracing::info!(namespace = %namespace, audience = %name, "audience definition withdrawn");
            self.report(Timestamp::now());
        }
        held
    }

    /// The watch on `namespace` listed everything again: an audience whose `ConfigMap` was not
    /// among `seen` was deleted while the watch was away. Marks the namespace listed.
    pub fn resynced(&self, namespace: &str, seen: &HashSet<String>) -> usize {
        let gone: Vec<String> = {
            let mut map = self
                .configmaps
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let keys: Vec<_> = map
                .keys()
                .filter(|(ns, cm)| ns == namespace && !seen.contains(cm))
                .cloned()
                .collect();
            keys.iter().filter_map(|k| map.remove(k)).collect()
        };
        let mut withdrawn = 0;
        for name in &gone {
            if self.live.update(|c| c.without(namespace, name)) {
                withdrawn += 1;
                tracing::info!(namespace, audience = %name, "audience definition gone since the last list");
            }
        }
        self.live.mark_synced(namespace);
        self.report(Timestamp::now());
        withdrawn
    }

    /// Drop the definitions past their `notAfter` at `now`; how many.
    pub fn sweep(&self, now: Timestamp) -> usize {
        let gone = self.live.update(|c| c.swept(now));
        for (ns, name) in &gone {
            tracing::info!(namespace = %ns, audience = %name, "audience definition expired");
        }
        if !gone.is_empty() {
            self.report(now);
        }
        gone.len()
    }

    /// Under `shadow`, once every namespace is listed: log each verdict that changed.
    fn report(&self, now: Timestamp) {
        let Some(file) = &self.shadow else {
            return;
        };
        if !self.live.all_synced() {
            return;
        }
        let report = shadow_report(&self.live.snapshot(), file, now);
        let mut last = self.reported.lock().unwrap_or_else(PoisonError::into_inner);
        for (audience, verdict) in &report {
            if last.get(audience) == Some(verdict) {
                continue;
            }
            if verdict == "matches the file" {
                tracing::info!(audience = %audience, verdict = %verdict, "audience shadow (ADR-0055)");
            } else {
                tracing::warn!(audience = %audience, verdict = %verdict, "audience shadow (ADR-0055)");
            }
        }
        for audience in last.keys().filter(|a| !report.contains_key(*a)) {
            tracing::info!(audience = %audience, "audience shadow: no longer in the file or the catalog");
        }
        *last = report;
    }
}

/// One watch per namespace read and the expiry sweep, until a watch ends. Every replica.
///
/// # Errors
/// When a watch or the sweep ends, which they do not on their own.
pub async fn run(client: Client, reflector: Arc<AudienceReflector>) -> anyhow::Result<()> {
    let mut watches = Vec::new();
    for ns in reflector.live.namespaces() {
        let api = Api::<ConfigMap>::namespaced(client.clone(), ns);
        let r = reflector.clone();
        let ns = ns.clone();
        watches.push(Box::pin(async move {
            let mut seen = HashSet::new();
            let mut events = watcher::watcher(
                api,
                watcher::Config::default().labels(crate::policy::BUNDLE_SELECTOR),
            )
            .default_backoff()
            .boxed();
            while let Some(event) = events.next().await {
                match event {
                    Ok(Event::Init) => seen.clear(),
                    Ok(Event::InitApply(cm)) => {
                        seen.insert(cm.name_any());
                        r.applied(&cm).await;
                    }
                    Ok(Event::InitDone) => {
                        r.resynced(&ns, &seen);
                    }
                    Ok(Event::Apply(cm)) => {
                        r.applied(&cm).await;
                    }
                    Ok(Event::Delete(cm)) => {
                        r.deleted(&cm);
                    }
                    Err(e) if crate::watch::watch_error_is_routine(&e) => {
                        tracing::debug!(namespace = %ns, error = %e, "audience watch: routine");
                    }
                    Err(e) => tracing::warn!(namespace = %ns, error = %e, "audience watch"),
                }
            }
            anyhow::bail!("the audience watch on {ns} ended")
        }));
    }
    let sweep = async {
        let mut tick = tokio::time::interval(SWEEP_EVERY);
        tick.tick().await;
        loop {
            tick.tick().await;
            reflector.sweep(Timestamp::now());
        }
    };
    tracing::info!(namespaces = ?reflector.live.namespaces(), "audience reflector running");
    tokio::select! {
        (r, _, _) = futures::future::select_all(watches) => r,
        () = sweep => anyhow::bail!("the audience sweep ended"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::SignedDuration;
    use mediatore_policy::types::{
        AudienceCredential, CredentialFormat, HeaderPair, OpenBaoSource, Placement, SecretRef,
    };
    use sandboxpolicy_bundle::{AudienceBundleContent, AudienceRef, BundleMeta};

    const PLATFORM: &str = "sandbox-platform";

    fn now() -> Timestamp {
        "2026-11-20T12:00:00Z".parse().unwrap()
    }

    fn secret_ref() -> CredentialSource {
        CredentialSource::SecretRef(SecretRef {
            name: "artifactory-token".into(),
            token_key: "token".into(),
            username_key: None,
        })
    }

    fn definition(endpoint: &str) -> AudienceDefinition {
        AudienceDefinition {
            credential: AudienceCredential {
                backend: Backend::Secret,
                placement: Placement::Gateway,
                format: CredentialFormat::Bearer,
                source: Some(secret_ref()),
                header: None,
                extra_headers: Vec::new(),
                refresh: None,
            },
            endpoints: vec![endpoint.into()],
            rules: Vec::new(),
            max_ttl_seconds: 900,
            ca_ref: None,
        }
    }

    fn payload(ns: &str, name: &str, d: AudienceDefinition) -> AudienceBundlePayload {
        AudienceBundlePayload::new(
            BundleMeta {
                version: 1,
                issued_at: now() - SignedDuration::from_mins(1),
                not_after: now() + SignedDuration::from_hours(1),
            },
            AudienceBundleContent {
                audience: AudienceRef {
                    namespace: ns.into(),
                    name: name.into(),
                    uid: format!("uid-{ns}-{name}"),
                },
                definition: d,
            },
        )
        .unwrap()
    }

    fn admitted(ns: &str, name: &str, endpoint: &str) -> Audience {
        audience_of(&payload(ns, name, definition(endpoint)), PLATFORM).unwrap()
    }

    #[test]
    fn the_kind_is_the_namespaces_never_the_bundles() {
        assert_eq!(
            admitted(PLATFORM, "anthropic", "api.anthropic.com:443").kind,
            AudienceKind::Platform
        );
        assert_eq!(
            admitted("team-a", "artifactory", "artifactory.example.com:443").kind,
            AudienceKind::Team
        );
    }

    #[test]
    fn a_team_audience_cannot_act_with_the_platforms_keys_or_read_its_openbao() {
        for backend in [Backend::Sts, Backend::Delegated, Backend::EntraObo] {
            let mut d = definition("a.example.com:443");
            d.credential.backend = backend;
            d.credential.source = None;
            let r = audience_of(&payload("team-a", "a", d.clone()), PLATFORM).unwrap_err();
            assert_eq!(r.code(), "L022", "{backend:?}");
            assert!(audience_of(&payload(PLATFORM, "a", d), PLATFORM).is_ok());
        }
        let mut d = definition("a.example.com:443");
        d.credential.source = Some(CredentialSource::Openbao(OpenBaoSource {
            mount: "secret".into(),
            path: "platform/registry".into(),
            key: "token".into(),
        }));
        let r = audience_of(&payload("team-a", "a", d.clone()), PLATFORM).unwrap_err();
        assert_eq!(r, Inadmissible::TeamOpenBao);
        assert!(audience_of(&payload(PLATFORM, "a", d), PLATFORM).is_ok());
    }

    #[test]
    fn a_secret_backend_with_no_source_is_refused() {
        let mut d = definition("a.example.com:443");
        d.credential.source = None;
        let r = audience_of(&payload(PLATFORM, "a", d), PLATFORM).unwrap_err();
        assert_eq!(r, Inadmissible::NoSource);
    }

    #[test]
    fn a_reserved_or_malformed_header_is_refused() {
        for bad in [
            "host",
            "content-length",
            "proxy-authorization",
            "X-Api-Key",
            "",
        ] {
            let mut d = definition("a.example.com:443");
            d.credential.header = Some(bad.into());
            let r = audience_of(&payload("team-a", "a", d), PLATFORM).unwrap_err();
            assert_eq!(r.code(), "L026", "{bad:?}");

            let mut d = definition("a.example.com:443");
            d.credential.extra_headers = vec![HeaderPair {
                name: bad.into(),
                value: "v".into(),
            }];
            let r = audience_of(&payload("team-a", "a", d), PLATFORM).unwrap_err();
            assert_eq!(r.code(), "L026", "{bad:?}");
        }
        let mut d = definition("a.example.com:443");
        d.credential.header = Some("x-api-key".into());
        assert!(audience_of(&payload("team-a", "a", d), PLATFORM).is_ok());
    }

    /// notaio ADR-0020 as amended 2026-11-21 (L026): an extra header's value is non-empty,
    /// printable ASCII with inner spaces and tabs only, no leading or trailing whitespace, so a
    /// CR or an LF can never split the request. Checked here too: neither side is trusted alone.
    #[test]
    fn an_extra_header_value_with_a_control_character_or_edge_whitespace_is_refused() {
        let with = |v: &str| {
            let mut d = definition("a.example.com:443");
            d.credential.extra_headers = vec![HeaderPair {
                name: "anthropic-version".into(),
                value: v.into(),
            }];
            audience_of(&payload("team-a", "a", d), PLATFORM)
        };
        for bad in [
            "",
            "2023-06-01\r\nx-injected: 1",
            "a\nb",
            "a\u{0}b",
            "a\u{7f}b",
            " leading",
            "trailing ",
            "\ttab-led",
            "caf\u{e9}",
        ] {
            let r = with(bad).unwrap_err();
            assert_eq!(r.code(), "L026", "{bad:?}");
            assert!(
                !r.to_string().contains(bad) || bad.is_empty(),
                "the value is never echoed: {r}"
            );
        }
        for good in ["2023-06-01", "oauth-2025-04-20", "a b\tc", "x"] {
            assert!(with(good).is_ok(), "{good:?}");
        }
    }

    /// A rule path the enforcement points would refuse as a request (`path_is_canonical`) can
    /// never match, and would read as inside a wider rule to a coverage check: refused at
    /// admission rather than kept as a dead rule.
    #[test]
    fn a_rule_path_with_a_dot_segment_or_an_encoded_separator_is_refused() {
        for bad in [
            "/v2/../admin/**",
            "/v2/./x",
            "/a%2fb/**",
            "/a/%2e%2e/b",
            "/a//b",
        ] {
            let mut d = definition("a.example.com:443");
            d.rules = vec![mediatore_policy::types::EndpointRule {
                method: "GET".into(),
                path: bad.into(),
            }];
            let r = audience_of(&payload("team-a", "a", d), PLATFORM).unwrap_err();
            assert_eq!(r.code(), "L017", "{bad:?}");
        }
        let mut d = definition("a.example.com:443");
        d.rules = vec![mediatore_policy::types::EndpointRule {
            method: "GET".into(),
            path: "/v2/**".into(),
        }];
        assert!(audience_of(&payload("team-a", "a", d), PLATFORM).is_ok());
    }

    #[test]
    fn an_endpoint_or_rule_the_gateway_cannot_match_is_refused() {
        for bad in ["*.example.com:443", "192.0.2.1:443", "no-port", ""] {
            let r = audience_of(&payload("team-a", "a", definition(bad)), PLATFORM).unwrap_err();
            assert_eq!(r.code(), "L017", "{bad:?}");
        }
        let mut d = definition("a.example.com:443");
        d.rules = vec![mediatore_policy::types::EndpointRule {
            method: "GET".into(),
            path: "relative".into(),
        }];
        let r = audience_of(&payload("team-a", "a", d), PLATFORM).unwrap_err();
        assert_eq!(r.code(), "L017");
        let mut d = definition("a.example.com:443");
        d.max_ttl_seconds = 0;
        assert_eq!(
            audience_of(&payload("team-a", "a", d), PLATFORM).unwrap_err(),
            Inadmissible::NoTtl
        );
    }

    #[test]
    fn what_the_broker_cannot_serve_yet_is_refused_rather_than_half_served() {
        let mut d = definition("a.example.com:443");
        d.ca_ref = Some(mediatore_policy::types::ConfigMapKeyRef {
            name: "private-ca".into(),
            key: "ca.pem".into(),
        });
        let r = audience_of(&payload("team-a", "a", d), PLATFORM).unwrap_err();
        assert_eq!(r.code(), "NotBuilt", "{r}");
        let mut d = definition("a.example.com:443");
        d.credential.format = CredentialFormat::Basic;
        let r = audience_of(&payload("team-a", "a", d), PLATFORM).unwrap_err();
        assert_eq!(r.code(), "NotBuilt", "{r}");
    }

    #[test]
    fn endpoints_are_lowercased_and_deduplicated() {
        let mut d = definition("Registry.Example.com:443");
        d.endpoints.push("registry.example.com:443".into());
        let a = audience_of(&payload("team-a", "r", d), PLATFORM).unwrap();
        assert_eq!(a.endpoints.len(), 1);
        assert_eq!(a.endpoints[0].to_string(), "registry.example.com:443");
    }

    #[test]
    fn a_team_audience_resolves_in_its_own_namespace_only() {
        let c = AudienceCatalog::new(PLATFORM).with(admitted(
            "team-a",
            "artifactory",
            "artifactory.example.com:443",
        ));
        assert_eq!(
            c.resolve("team-a", "artifactory", now()).unwrap().namespace,
            "team-a"
        );
        assert_eq!(
            c.resolve("team-b", "artifactory", now()).unwrap_err(),
            Unresolved::Unknown
        );
        assert_eq!(
            c.resolve(PLATFORM, "artifactory", now()).unwrap_err(),
            Unresolved::Unknown
        );
    }

    #[test]
    fn a_platform_audience_resolves_everywhere() {
        let c = AudienceCatalog::new(PLATFORM).with(admitted(
            PLATFORM,
            "anthropic",
            "api.anthropic.com:443",
        ));
        for ns in ["team-a", "team-b", PLATFORM] {
            assert_eq!(
                c.resolve(ns, "anthropic", now()).unwrap().kind,
                AudienceKind::Platform
            );
        }
    }

    #[test]
    fn two_teams_may_each_have_an_audience_of_one_name() {
        let c = AudienceCatalog::new(PLATFORM)
            .with(admitted("team-a", "registry", "a.example.com:443"))
            .with(admitted("team-b", "registry", "b.example.com:443"));
        assert_eq!(
            c.resolve("team-a", "registry", now()).unwrap().namespace,
            "team-a"
        );
        assert_eq!(
            c.resolve("team-b", "registry", now()).unwrap().namespace,
            "team-b"
        );
    }

    #[test]
    fn a_team_audience_with_a_platform_name_breaks_that_name_in_its_namespace_only() {
        let c = AudienceCatalog::new(PLATFORM)
            .with(admitted(PLATFORM, "anthropic", "api.anthropic.com:443"))
            .with(admitted(
                "team-a",
                "anthropic",
                "proxy.team-a.example.com:443",
            ));
        assert_eq!(
            c.resolve("team-a", "anthropic", now()).unwrap_err(),
            Unresolved::Shadowed {
                team: "team-a".into(),
                platform: PLATFORM.into()
            }
        );
        assert_eq!(
            c.resolve("team-b", "anthropic", now()).unwrap().namespace,
            PLATFORM
        );
    }

    #[test]
    fn two_audiences_one_namespace_sees_on_one_endpoint_are_both_refused_there() {
        let c = AudienceCatalog::new(PLATFORM)
            .with(admitted(PLATFORM, "registry", "registry.example.com:443"))
            .with(admitted("team-a", "mine", "registry.example.com:443"));
        for name in ["registry", "mine"] {
            assert!(
                matches!(
                    c.resolve("team-a", name, now()),
                    Err(Unresolved::SharedEndpoint { .. })
                ),
                "{name}"
            );
        }
        // Not visible from team-b, so the platform audience serves there.
        assert!(c.resolve("team-b", "registry", now()).is_ok());

        // Two platform audiences on one endpoint: refused from everywhere.
        let c = AudienceCatalog::new(PLATFORM)
            .with(admitted(PLATFORM, "one", "x.example.com:443"))
            .with(admitted(PLATFORM, "two", "x.example.com:443"));
        assert!(c.resolve("team-b", "one", now()).is_err());
        assert!(c.resolve("team-b", "two", now()).is_err());

        // Two teams on one endpoint never see each other.
        let c = AudienceCatalog::new(PLATFORM)
            .with(admitted("team-a", "r", "x.example.com:443"))
            .with(admitted("team-b", "r2", "x.example.com:443"));
        assert!(c.resolve("team-a", "r", now()).is_ok());
        assert!(c.resolve("team-b", "r2", now()).is_ok());
    }

    #[test]
    fn a_withdrawn_or_expired_definition_is_gone_from_the_next_snapshot() {
        let c = AudienceCatalog::new(PLATFORM).with(admitted(
            "team-a",
            "registry",
            "a.example.com:443",
        ));
        let (after, held) = c.without("team-a", "registry");
        assert!(held);
        assert_eq!(
            after.resolve("team-a", "registry", now()).unwrap_err(),
            Unresolved::Unknown
        );
        // The snapshot a reader already holds is unchanged.
        assert!(c.resolve("team-a", "registry", now()).is_ok());

        let later = now() + SignedDuration::from_hours(2);
        assert_eq!(
            c.resolve("team-a", "registry", later).unwrap_err(),
            Unresolved::Unknown
        );
        let (swept, gone) = c.swept(later);
        assert!(swept.is_empty());
        assert_eq!(gone, vec![("team-a".to_owned(), "registry".to_owned())]);
    }

    #[test]
    fn a_newer_definition_replaces_the_one_held() {
        let c = AudienceCatalog::new(PLATFORM).with(admitted(
            "team-a",
            "registry",
            "a.example.com:443",
        ));
        let mut next = admitted("team-a", "registry", "b.example.com:443");
        next.version = 2;
        let c = c.with(next);
        assert_eq!(c.len(), 1);
        let a = c.resolve("team-a", "registry", now()).unwrap();
        assert_eq!(
            (a.version, a.endpoints[0].to_string()),
            (2, "b.example.com:443".into())
        );
    }

    // The reflector (ADR-0055 decision 1) and the shadow comparison (decision 8).

    mod reflector {
        use std::collections::{BTreeMap, HashSet};
        use std::sync::Arc;

        use jiff::{SignedDuration, Timestamp};
        use mediatore_store::{ClaimStore, MemoryStore};
        use mediatore_testkit::policy::{
            audience_configmap, bundle_configmap, fresh_bundle, signed_audience,
        };

        use super::super::*;
        use super::{PLATFORM, definition};

        const TEAM: &str = "team-a";

        fn rig() -> (Arc<MemoryStore>, AudienceReflector) {
            let store = Arc::new(MemoryStore::default());
            let keys = signed_audience(
                Timestamp::now(),
                1,
                TEAM,
                "x",
                definition("x.example.com:443"),
            )
            .keys;
            let r = AudienceReflector::new(
                store.clone(),
                keys,
                PLATFORM.into(),
                vec![PLATFORM.into(), TEAM.into()],
            );
            (store, r)
        }

        fn cm(
            ns: &str,
            name: &str,
            version: u64,
            d: AudienceDefinition,
        ) -> k8s_openapi::api::core::v1::ConfigMap {
            let a = signed_audience(Timestamp::now(), version, ns, name, d);
            audience_configmap(ns, name, &a.envelope)
        }

        #[tokio::test]
        async fn a_bundle_in_a_watched_namespace_is_admitted_into_the_next_snapshot() {
            let (store, r) = rig();
            let before = r.live().snapshot();
            let out = r
                .applied_at(
                    &cm(TEAM, "registry", 1, definition("r.example.com:443")),
                    Timestamp::now(),
                )
                .await;
            assert_eq!(
                out,
                AudienceOutcome::Admitted {
                    audience: format!("{TEAM}/registry"),
                    kind: AudienceKind::Team,
                    version: 1
                }
            );
            let now = Timestamp::now();
            assert!(r.live().snapshot().resolve(TEAM, "registry", now).is_ok());
            // A snapshot already taken is unchanged.
            assert!(before.resolve(TEAM, "registry", now).is_err());
            assert!(
                store
                    .get_policy_floor(TEAM, "audience/registry")
                    .await
                    .unwrap()
                    .is_some()
            );
        }

        #[tokio::test]
        async fn what_is_not_an_audience_bundle_here_is_ignored() {
            let (_, r) = rig();
            let now = Timestamp::now();
            let elsewhere = cm("team-b", "registry", 1, definition("r.example.com:443"));
            assert!(matches!(
                r.applied_at(&elsewhere, now).await,
                AudienceOutcome::Ignored(_)
            ));
            // A policy bundle carries the same label; it is not ours.
            let policy = bundle_configmap(TEAM, "agent-bundle", &fresh_bundle(now, 1).envelope);
            assert!(matches!(
                r.applied_at(&policy, now).await,
                AudienceOutcome::Ignored(_)
            ));
            assert!(r.live().snapshot().is_empty());
        }

        #[tokio::test]
        async fn a_refused_bundle_changes_nothing() {
            let store = Arc::new(MemoryStore::default());
            let r = AudienceReflector::new(
                store.clone(),
                mediatore_policy::TrustedKeys::new(),
                PLATFORM.into(),
                vec![TEAM.into()],
            );
            let out = r
                .applied_at(
                    &cm(TEAM, "registry", 1, definition("r.example.com:443")),
                    Timestamp::now(),
                )
                .await;
            assert_eq!(
                out,
                AudienceOutcome::Refused {
                    code: "NoValidSignature"
                }
            );
            assert!(r.live().snapshot().is_empty());
            assert!(
                store
                    .get_policy_floor(TEAM, "audience/registry")
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        #[tokio::test]
        async fn a_newer_definition_the_broker_refuses_withdraws_the_one_held() {
            let (_, r) = rig();
            let now = Timestamp::now();
            r.applied_at(
                &cm(TEAM, "registry", 1, definition("r.example.com:443")),
                now,
            )
            .await;
            let mut d = definition("r.example.com:443");
            d.credential.backend = Backend::Sts;
            d.credential.source = None;
            let out = r.applied_at(&cm(TEAM, "registry", 2, d), now).await;
            assert_eq!(out, AudienceOutcome::Withdrawn { code: "L022" });
            assert!(r.live().snapshot().resolve(TEAM, "registry", now).is_err());
        }

        #[tokio::test]
        async fn a_deleted_or_unlisted_configmap_withdraws_its_audience() {
            let (_, r) = rig();
            let now = Timestamp::now();
            let registry = cm(TEAM, "registry", 1, definition("r.example.com:443"));
            r.applied_at(&registry, now).await;
            r.applied_at(&cm(TEAM, "other", 1, definition("o.example.com:443")), now)
                .await;
            assert!(r.deleted(&registry));
            assert!(r.live().snapshot().resolve(TEAM, "registry", now).is_err());

            assert!(!r.live().synced(TEAM));
            let seen = HashSet::new();
            assert_eq!(r.resynced(TEAM, &seen), 1);
            assert!(r.live().snapshot().is_empty());
            assert!(r.live().synced(TEAM));
            assert!(!r.live().all_synced());
            r.resynced(PLATFORM, &seen);
            assert!(r.live().all_synced());
        }

        #[tokio::test]
        async fn a_namespace_is_ready_once_it_and_the_platform_namespace_are_listed() {
            let (_, r) = rig();
            let live = r.live();
            assert!(!live.ready_for(TEAM));
            r.resynced(TEAM, &HashSet::new());
            assert!(
                !live.ready_for(TEAM),
                "the platform namespace is not listed yet"
            );
            r.resynced(PLATFORM, &HashSet::new());
            assert!(live.ready_for(TEAM));
            assert!(live.ready_for(PLATFORM));
            // A namespace audiences are not read in holds none, and is not waited for.
            assert!(live.ready_for("elsewhere"));
        }

        #[tokio::test]
        async fn an_expired_definition_is_swept() {
            let (_, r) = rig();
            let now = Timestamp::now();
            r.applied_at(
                &cm(TEAM, "registry", 1, definition("r.example.com:443")),
                now,
            )
            .await;
            assert_eq!(r.sweep(now + SignedDuration::from_hours(2)), 1);
            assert!(r.live().snapshot().is_empty());
        }

        fn file(endpoint: &str) -> Shape {
            shape_of(&definition(endpoint))
        }

        #[tokio::test]
        async fn the_shadow_report_says_what_matches_what_differs_and_what_would_appear() {
            let (_, r) = rig();
            let now = Timestamp::now();
            r.applied_at(
                &cm(PLATFORM, "same", 1, definition("s.example.com:443")),
                now,
            )
            .await;
            r.applied_at(
                &cm(PLATFORM, "moved", 1, definition("new.example.com:443")),
                now,
            )
            .await;
            r.applied_at(
                &cm(PLATFORM, "new", 1, definition("n.example.com:443")),
                now,
            )
            .await;
            r.applied_at(
                &cm(TEAM, "registry", 1, definition("r.example.com:443")),
                now,
            )
            .await;
            let file = BTreeMap::from([
                ("same".to_owned(), file("s.example.com:443")),
                ("moved".to_owned(), file("old.example.com:443")),
                ("missing".to_owned(), file("m.example.com:443")),
            ]);
            let report = shadow_report(&r.live().snapshot(), &file, now);
            assert_eq!(report["same"], "matches the file");
            assert_eq!(report["moved"], "differs from the file in: endpoints");
            assert_eq!(report["missing"], "in the file, no platform definition");
            assert_eq!(
                report["new"],
                "would appear: a platform audience not in the file"
            );
            assert_eq!(
                report[&format!("{TEAM}/registry")],
                "would appear: a team audience of team-a"
            );
        }

        #[test]
        fn every_field_the_file_and_the_definition_share_is_compared() {
            let base = definition("a.example.com:443");
            let mut other = base.clone();
            other.credential.placement = mediatore_policy::types::Placement::Proxy;
            other.credential.header = Some("x-api-key".into());
            other.max_ttl_seconds = 60;
            other.rules = vec![mediatore_policy::types::EndpointRule {
                method: "GET".into(),
                path: "/v1/**".into(),
            }];
            assert_eq!(
                differences(&shape_of(&base), &shape_of(&other)),
                vec!["placement", "header", "rules", "max_ttl"]
            );
            assert_eq!(
                differences(&shape_of(&base), &shape_of(&base)),
                Vec::<&str>::new()
            );
        }
    }
}
