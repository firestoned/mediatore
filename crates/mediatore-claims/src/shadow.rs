// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The shadow comparison (ADR-0026 decision 7): every way the broker's configuration would
//! allow a sandbox more than the signed bundle of the policy it names, as findings with a
//! stable code. Pure: nothing here reads a cluster or a store, and nothing here refuses
//! anything (decision 8). The reconciler turns the findings into a `PolicyConformant`
//! condition and a log line per gap.

use std::fmt;

use mediatore_policy::BundlePayload;
use mediatore_proto::{Endpoint, EndpointRule};

use crate::sandbox::AgentSandboxSpec;

/// One audience as the broker's configuration has it: what the broker would allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audience {
    /// The audience value.
    pub name: String,
    /// The longest token the broker mints for it, in seconds.
    pub max_ttl: i64,
    /// The endpoints the broker's proxy reaches for it.
    pub egress: Vec<Endpoint>,
    /// The rules the proxy admits at those endpoints; empty admits everything.
    pub rules: Vec<EndpointRule>,
}

impl Audience {
    /// An audience with the broker's defaults (a 900 s ceiling, no endpoints, no rules).
    #[must_use]
    pub fn named(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            max_ttl: 900,
            egress: Vec::new(),
            rules: Vec::new(),
        }
    }
}

/// The finding codes of ADR-0026 decision 7. The enforcing ADR turns each into a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Code {
    /// An audience on the sandbox that the bundle does not list.
    P001,
    /// The broker's `max_ttl` for an audience above the bundle audience's `ttlSeconds`.
    P002,
    /// An `egress` endpoint of the broker's for an audience that the bundle audience does
    /// not list.
    P003,
    /// A rule of the broker's that no bundle rule covers, or no rules where the bundle has
    /// some.
    P004,
    /// The sandbox's `ttlSeconds` above the bundle's `lease.maxDurationSeconds`.
    P005,
    /// The bundle holds direct `egress[]`, which the broker has no way to provide.
    P006,
    /// No `policyRef` on the sandbox.
    P010,
    /// A `policyRef` to no verified, unexpired bundle in the cache.
    P011,
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::P001 => "P001",
            Self::P002 => "P002",
            Self::P003 => "P003",
            Self::P004 => "P004",
            Self::P005 => "P005",
            Self::P006 => "P006",
            Self::P010 => "P010",
            Self::P011 => "P011",
        })
    }
}

/// One gap: its code and what it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The code.
    pub code: Code,
    /// What the broker would allow, in one line.
    pub detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code, self.detail)
    }
}

fn finding(code: Code, detail: impl Into<String>) -> Finding {
    Finding {
        code,
        detail: detail.into(),
    }
}

/// Every gap between what `audiences` (the broker's configuration) would allow `spec` and
/// what `bundle` allows. `None` for the bundle is `P011` alone; no `policyRef` is `P010`
/// alone. Empty means conformant.
#[must_use]
pub fn compare(
    spec: &AgentSandboxSpec,
    audiences: &[Audience],
    bundle: Option<&BundlePayload>,
) -> Vec<Finding> {
    let Some(policy) = spec.policy_ref.as_ref() else {
        return vec![finding(Code::P010, "no policyRef on the sandbox")];
    };
    let Some(bundle) = bundle else {
        return vec![finding(
            Code::P011,
            format!("no verified bundle for policy {}", policy.name),
        )];
    };
    let mut out = Vec::new();
    for name in &spec.audiences {
        let Some(grant) = bundle.content.audiences.iter().find(|g| &g.name == name) else {
            out.push(finding(
                Code::P001,
                format!("audience {name} is not in the bundle"),
            ));
            continue;
        };
        // An audience the broker no longer configures has nothing the broker would allow;
        // the sandbox was refused on it, or the configuration changed since.
        let Some(configured) = audiences.iter().find(|a| &a.name == name) else {
            continue;
        };
        // An omitted `ttlSeconds` means notaio's K5.1 ceiling, which the bundle does not
        // carry in seconds: nothing to compare with.
        if let Some(ceiling) = grant.ttl_seconds
            && configured.max_ttl > i64::from(ceiling)
        {
            out.push(finding(
                Code::P002,
                format!(
                    "max_ttl {} for {name} is above the bundle's ttlSeconds {ceiling}",
                    configured.max_ttl
                ),
            ));
        }
        for endpoint in &configured.egress {
            let spelled = endpoint.to_string();
            if !grant.endpoints.contains(&spelled) {
                out.push(finding(
                    Code::P003,
                    format!("egress {spelled} for {name} is not in the bundle"),
                ));
            }
        }
        if grant.rules.is_empty() {
            // The bundle admits every method and path at this audience.
            continue;
        }
        if configured.rules.is_empty() {
            out.push(finding(
                Code::P004,
                format!(
                    "no rules for {name} where the bundle has {}",
                    grant.rules.len()
                ),
            ));
            continue;
        }
        for rule in &configured.rules {
            if !grant.rules.iter().any(|g| covers(g, rule)) {
                out.push(finding(
                    Code::P004,
                    format!(
                        "rule {} {} for {name} is covered by no bundle rule",
                        rule.method, rule.path
                    ),
                ));
            }
        }
    }
    let lease = bundle.content.lease.max_duration_seconds;
    if spec.ttl_seconds > lease {
        out.push(finding(
            Code::P005,
            format!(
                "ttlSeconds {} is above the bundle's lease.maxDurationSeconds {lease}",
                spec.ttl_seconds
            ),
        ));
    }
    if !bundle.content.egress.is_empty() {
        out.push(finding(
            Code::P006,
            format!(
                "the bundle holds {} direct egress entries the broker cannot provide",
                bundle.content.egress.len()
            ),
        ));
    }
    out
}

/// Whether every request `broker` admits, `bundle` admits too: the same or any method, and
/// a path glob that matches every path the broker's does. A covering this cannot prove is
/// `false`, and the rule is reported.
#[must_use]
pub fn covers(bundle: &mediatore_policy::types::EndpointRule, broker: &EndpointRule) -> bool {
    let method = bundle.method == "*" || bundle.method.eq_ignore_ascii_case(&broker.method);
    method && glob_covers(&segments(&bundle.path), &segments(&broker.path))
}

/// A path split into its non-empty segments, as the proxy matches them.
fn segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// Whether the glob `a` matches every path the glob `b` matches, segment-wise (`*` one
/// segment, `**` zero or more). Sound, not complete: a `*` or a literal in `a` never covers
/// a `**` in `b`, and a literal never covers a `*`, because `b` then matches paths `a` does
/// not.
fn glob_covers(a: &[&str], b: &[&str]) -> bool {
    match a.split_first() {
        None => b.is_empty(),
        Some((&"**", rest)) => (0..=b.len()).any(|skip| glob_covers(rest, &b[skip..])),
        Some((&"*", rest)) => b
            .split_first()
            .is_some_and(|(head, tail)| *head != "**" && glob_covers(rest, tail)),
        Some((lit, rest)) => b
            .split_first()
            .is_some_and(|(head, tail)| head == lit && glob_covers(rest, tail)),
    }
}

#[cfg(test)]
mod tests {
    use banlieue_api::common::LocalObjectReference;
    use chrono::Utc;
    use mediatore_policy::types::{Access, AudienceGrant, EgressRule};

    use super::*;
    use crate::sandbox::{SandboxSubject, SandboxWorkload};

    /// The conformance bundle's content: audience `internal-git` at 300 s with endpoint
    /// `git.foo.io:443` and the rule `GET /repos/**`, a 14400 s lease, no direct egress.
    fn bundle() -> BundlePayload {
        mediatore_testkit::policy::fresh_bundle(Utc::now(), 1).payload
    }

    fn spec(audiences: &[&str], policy: Option<&str>) -> AgentSandboxSpec {
        AgentSandboxSpec {
            subject: SandboxSubject {
                issuer: "https://issuer.example.com".into(),
                id: "octocat".into(),
                display: None,
            },
            pool_ref: LocalObjectReference {
                name: "pool".into(),
            },
            ttl_seconds: 3600,
            audiences: audiences.iter().map(|a| (*a).to_owned()).collect(),
            workload: SandboxWorkload {
                image: "ghcr.io/example/workload:1".into(),
                args: vec![],
            },
            policy_ref: policy.map(|name| LocalObjectReference { name: name.into() }),
        }
    }

    fn rule(method: &str, path: &str) -> EndpointRule {
        EndpointRule {
            method: method.into(),
            path: path.into(),
        }
    }

    fn bundle_rule(method: &str, path: &str) -> mediatore_policy::types::EndpointRule {
        mediatore_policy::types::EndpointRule {
            method: method.into(),
            path: path.into(),
        }
    }

    /// The broker configured exactly as the bundle allows.
    fn conformant() -> Audience {
        Audience {
            name: "internal-git".into(),
            max_ttl: 300,
            egress: vec!["git.foo.io:443".parse().unwrap()],
            rules: vec![rule("GET", "/repos/**")],
        }
    }

    fn codes(findings: &[Finding]) -> Vec<Code> {
        findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn a_broker_configured_as_the_bundle_allows_has_no_gap() {
        let findings = compare(
            &spec(&["internal-git"], Some("agent")),
            &[conformant()],
            Some(&bundle()),
        );
        assert_eq!(findings, vec![], "{findings:?}");
        // Tighter than the bundle is not a gap either.
        let tighter = Audience {
            max_ttl: 60,
            egress: vec![],
            rules: vec![rule("GET", "/repos/firestoned/*")],
            ..conformant()
        };
        assert_eq!(
            compare(
                &spec(&["internal-git"], Some("agent")),
                &[tighter],
                Some(&bundle())
            ),
            vec![]
        );
    }

    #[test]
    fn no_policy_and_no_bundle_are_reported_alone() {
        let findings = compare(
            &spec(&["internal-git"], None),
            &[conformant()],
            Some(&bundle()),
        );
        assert_eq!(codes(&findings), vec![Code::P010]);
        let findings = compare(&spec(&["nowhere"], Some("agent")), &[], None);
        assert_eq!(codes(&findings), vec![Code::P011]);
        assert!(findings[0].detail.contains("agent"));
        assert_eq!(
            findings[0].to_string(),
            format!("P011 {}", findings[0].detail)
        );
    }

    #[test]
    fn every_way_the_broker_allows_more_is_a_coded_finding() {
        let looser = Audience {
            max_ttl: 3600,
            egress: vec![
                "git.foo.io:443".parse().unwrap(),
                "mirror.foo.io:443".parse().unwrap(),
            ],
            rules: vec![rule("GET", "/repos/**"), rule("POST", "/repos/**")],
            ..conformant()
        };
        let mut sb = spec(&["internal-git", "api://elsewhere"], Some("agent"));
        sb.ttl_seconds = 86_400;
        let mut b = bundle();
        b.content.egress.push(EgressRule {
            endpoint: "pypi.org:443".into(),
            rules: vec![],
        });
        let findings = compare(&sb, &[looser], Some(&b));
        assert_eq!(
            codes(&findings),
            vec![
                Code::P002,
                Code::P003,
                Code::P004,
                Code::P001,
                Code::P005,
                Code::P006
            ],
            "{findings:?}"
        );
        let details: Vec<&str> = findings.iter().map(|f| f.detail.as_str()).collect();
        assert!(details[0].contains("3600") && details[0].contains("300"));
        assert!(details[1].contains("mirror.foo.io:443"));
        assert!(details[2].contains("POST /repos/**"));
        assert!(details[3].contains("api://elsewhere"));
        assert!(details[4].contains("86400") && details[4].contains("14400"));
        assert!(details[5].contains("1 direct egress"));
    }

    #[test]
    fn no_broker_rules_where_the_bundle_has_some_is_a_gap_and_the_reverse_is_not() {
        let open = Audience {
            rules: vec![],
            ..conformant()
        };
        let findings = compare(
            &spec(&["internal-git"], Some("agent")),
            std::slice::from_ref(&open),
            Some(&bundle()),
        );
        assert_eq!(codes(&findings), vec![Code::P004]);
        assert!(findings[0].detail.starts_with("no rules for internal-git"));
        let mut b = bundle();
        b.content.audiences[0].rules.clear();
        let with_rules = Audience {
            rules: vec![rule("DELETE", "/**")],
            ..conformant()
        };
        assert_eq!(
            compare(
                &spec(&["internal-git"], Some("agent")),
                &[with_rules],
                Some(&b)
            ),
            vec![],
            "the bundle admits everything here"
        );
        assert_eq!(
            compare(&spec(&["internal-git"], Some("agent")), &[open], Some(&b)),
            vec![]
        );
    }

    #[test]
    fn an_omitted_bundle_ttl_and_an_unconfigured_audience_compare_nothing() {
        let mut b = bundle();
        b.content.audiences[0].ttl_seconds = None;
        let long = Audience {
            max_ttl: 86_400,
            ..conformant()
        };
        assert_eq!(
            compare(&spec(&["internal-git"], Some("agent")), &[long], Some(&b)),
            vec![]
        );
        // Listed by the bundle, no longer configured by the broker: nothing to allow.
        assert_eq!(
            compare(
                &spec(&["internal-git"], Some("agent")),
                &[],
                Some(&bundle())
            ),
            vec![]
        );
        // Listed by the bundle under another grant shape still finds it.
        b.content.audiences.push(AudienceGrant {
            name: "api://other".into(),
            access: Access::Read,
            scopes: vec![],
            ttl_seconds: Some(10),
            endpoints: vec![],
            rules: vec![],
        });
        let other = Audience {
            name: "api://other".into(),
            max_ttl: 11,
            egress: vec![],
            rules: vec![],
        };
        assert_eq!(
            codes(&compare(
                &spec(&["api://other"], Some("agent")),
                &[other],
                Some(&b)
            )),
            vec![Code::P002]
        );
    }

    #[test]
    fn a_bundle_rule_covers_a_broker_rule_only_when_it_admits_every_request_the_broker_does() {
        let cases: &[(&str, &str, &str, &str, bool)] = &[
            // (bundle method, bundle path, broker method, broker path, covered)
            ("GET", "/repos/**", "GET", "/repos/**", true),
            ("*", "/repos/**", "GET", "/repos/**", true),
            ("GET", "/repos/**", "*", "/repos/**", false),
            ("get", "/repos/**", "GET", "/repos/**", true),
            ("GET", "/repos/**", "POST", "/repos/**", false),
            ("GET", "/**", "GET", "/repos/*/pulls", true),
            (
                "GET",
                "/repos/**",
                "GET",
                "/repos/firestoned/mediatore",
                true,
            ),
            ("GET", "/repos/**", "GET", "/repos", true),
            ("GET", "/repos/*", "GET", "/repos/**", false),
            ("GET", "/repos/*", "GET", "/repos/firestoned", true),
            ("GET", "/repos/firestoned", "GET", "/repos/*", false),
            ("GET", "/**/pulls", "GET", "/repos/*/pulls", true),
            ("GET", "/**/pulls", "GET", "/repos/**", false),
            ("GET", "/*/pulls", "GET", "/**/pulls", false),
            ("GET", "/repos/**", "GET", "/repos/**/pulls", true),
            ("GET", "/repos/", "GET", "/repos", true),
            ("GET", "/a/**/b", "GET", "/a/x/**/b", true),
            ("GET", "/a/**/b", "GET", "/a/**", false),
        ];
        for (bm, bp, m, p, want) in cases {
            assert_eq!(
                covers(&bundle_rule(bm, bp), &rule(m, p)),
                *want,
                "{bm} {bp} covers {m} {p}"
            );
        }
    }
}
