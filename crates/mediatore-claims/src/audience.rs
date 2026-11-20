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

use std::collections::BTreeMap;
use std::sync::Arc;

use jiff::Timestamp;
use mediatore_policy::AudienceBundlePayload;
use mediatore_policy::types::{AudienceDefinition, Backend, CredentialSource};
use mediatore_proto::{Endpoint, EndpointRule};

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
}

impl Inadmissible {
    /// A stable name for logs.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TeamBackend => "L022",
            Self::TeamOpenBao => "L023",
            Self::Header(_) => "L026",
            Self::Endpoint(_) | Self::Rule { .. } => "L017",
            Self::NoSource => "NoSource",
            Self::NoTtl => "NoTtl",
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
    if d.max_ttl_seconds == 0 {
        return Err(Inadmissible::NoTtl);
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
}
