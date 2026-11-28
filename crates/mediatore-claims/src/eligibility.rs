// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Eligibility by group, from the signed policy bundle (ADR-0066), built in shadow only
//! (amendments of 2026-11-28): whether the requester holds one of the groups a schema v4
//! bundle's `subjects.groups` lists, recorded in one log line per request and never acted on.
//! Nothing here refuses, delays or changes an answer, and `enforce` does not start.
//!
//! The requester's groups are the validated token's, in the issuer's own spelling: the
//! broker's own decisions never add or strip a `subject_prefix` (ADR-0073 decision 4,
//! ADR-0066 decision 4), so a bundle listing `dex:team-a` does not match a Dex token's
//! `team-a`, nor the reverse. Matching is exact and case-sensitive (ADR-0046 decision 2).

use std::fmt;

use mediatore_policy::{BundlePayload, SchemaVersion};

use crate::shadow::Code;

/// The message of the one line each decision writes, so an operator greps one string.
pub const LINE: &str = "policy eligibility decision (ADR-0066, shadow): recorded, nothing refused";

/// What `policy.eligibility: enforce` is answered at start (ADR-0066, amendment 1).
pub const ENFORCE_NOT_BUILT: &str =
    "policy.eligibility: enforce is not built: ADR-0066 is built in shadow only; set off or shadow";

/// `policy.eligibility` (ADR-0066 decision 1 as amended 2026-11-28): `off` (the default)
/// reads nothing and writes nothing; `shadow` records each claim request's verdict. There is
/// no `enforce`: it does not start, and neither does any other value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EligibilityMode {
    /// Nothing is read, judged or written.
    #[default]
    Off,
    /// Every claim request is judged and the verdict logged; nothing is refused.
    Shadow,
}

impl EligibilityMode {
    /// The value as the configuration spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
        }
    }

    /// The mode a configuration value names.
    ///
    /// # Errors
    /// `enforce`, which is not built ([`ENFORCE_NOT_BUILT`]), and any value other than `off`
    /// and `shadow`: never a default in their place.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "off" => Ok(Self::Off),
            "shadow" => Ok(Self::Shadow),
            "enforce" => Err(ENFORCE_NOT_BUILT.to_owned()),
            other => Err(format!(
                "policy.eligibility: unknown value {other:?}; expected off or shadow (ADR-0066)"
            )),
        }
    }
}

impl fmt::Display for EligibilityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for EligibilityMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = String::deserialize(d)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Why a request was not judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotJudged {
    /// The request names no policy.
    NoPolicyRef,
    /// The policy named does not resolve to a verified, unexpired bundle in the namespace's
    /// sources (ADR-0054), or those sources are not read yet.
    PolicyNotResolved,
    /// The bundle is schema v3: it carries no `subjects` (`P016`).
    V3Bundle,
    /// A v4 payload without `subjects`, which notaio's verifier refuses (`Malformed`) and so
    /// never reaches the cache; read as not judged (`P016`), never as open.
    NoSubjects,
    /// The broker holds no groups for the requester: a sandbox created through the
    /// Kubernetes API (ADR-0066 decision 7).
    NoGroups,
}

impl NotJudged {
    /// The `reason` field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoPolicyRef => "no_policy_ref",
            Self::PolicyNotResolved => "policy_not_resolved",
            Self::V3Bundle => "v3_bundle",
            Self::NoSubjects => "no_subjects",
            Self::NoGroups => "no_groups",
        }
    }
}

/// The verdict on one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<'b> {
    /// The requester holds this group of the policy's list (a value of the signed bundle).
    Eligible {
        /// The first group of the bundle's list the requester holds.
        matched: &'b str,
    },
    /// The requester holds none of the policy's groups; an empty list is nobody (`P015`).
    NotEligible,
    /// Nothing was judged, and why.
    NotJudged(NotJudged),
}

impl Verdict<'_> {
    /// The `eligibility` field.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Eligible { .. } => "eligible",
            Self::NotEligible => "not_eligible",
            Self::NotJudged(_) => "not_judged",
        }
    }

    /// The finding code under ADR-0066 decision 8, `None` when there is none.
    #[must_use]
    pub const fn code(&self) -> Option<Code> {
        match self {
            Self::NotEligible => Some(Code::P015),
            Self::NotJudged(NotJudged::V3Bundle | NotJudged::NoSubjects) => Some(Code::P016),
            Self::Eligible { .. } | Self::NotJudged(_) => None,
        }
    }
}

/// Where the request reached the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// `POST /v1/claims`: the broker validated the requester's token and holds its groups.
    FrontDoor,
    /// An `AgentSandbox` created through the Kubernetes API (ADR-0066 decision 7).
    Declarative,
}

impl Path {
    /// The `path` field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FrontDoor => "front_door",
            Self::Declarative => "declarative",
        }
    }
}

/// What the request's `policyRef` came to.
#[derive(Debug, Clone, Copy)]
pub enum Lookup<'b> {
    /// The request names no policy.
    NoPolicy,
    /// The name does not resolve in the namespace's sources, or they are not read yet.
    NotResolved,
    /// The verified bundle it resolves to.
    Found(&'b BundlePayload),
}

/// Who asks, as the broker knows them: the validated token's issuer and subject, and its
/// groups when the broker holds them (`None` on the declarative path).
#[derive(Debug, Clone, Copy)]
pub struct Requester<'a> {
    /// The issuer the token validated as.
    pub issuer: &'a str,
    /// The subject, as the claim records it.
    pub subject: &'a str,
    /// The token's groups, byte for byte; `None` when the broker holds none.
    pub groups: Option<&'a [String]>,
}

/// The verdict for a requester holding `groups` (`None`: the broker holds none) under
/// `bundle`. Walks the bundle's list, which notaio bounds, against the token's groups, and
/// stops at the first match; nothing else is read.
#[must_use]
pub fn judge<'b>(bundle: &'b BundlePayload, groups: Option<&[String]>) -> Verdict<'b> {
    let subjects = match (bundle.schema_version(), bundle.content.subjects.as_ref()) {
        (Some(SchemaVersion::V4), Some(subjects)) => subjects,
        (Some(SchemaVersion::V4), None) => return Verdict::NotJudged(NotJudged::NoSubjects),
        // v3, or a schema the verifier would not have admitted: no statement to read.
        _ => return Verdict::NotJudged(NotJudged::V3Bundle),
    };
    let Some(groups) = groups else {
        return Verdict::NotJudged(NotJudged::NoGroups);
    };
    subjects
        .groups
        .iter()
        .find(|listed| groups.iter().any(|g| g == *listed))
        .map_or(Verdict::NotEligible, |matched| Verdict::Eligible {
            matched: matched.as_str(),
        })
}

/// Judge one request and write its line, under `mode`. Under `off` nothing is judged or
/// written and `None` is returned. The line carries the verdict, its code and reason, the
/// path, the namespace and the sandbox (`None` at the front door, which names it later), the
/// policy (name, namespace, bundle version), the requester's issuer and subject, the one
/// group matched and how many the policy lists: never a token, never the requester's group
/// list, never the policy's list.
pub fn record<'b>(
    mode: EligibilityMode,
    path: Path,
    namespace: &str,
    sandbox: Option<&str>,
    requester: &Requester<'_>,
    policy: Option<&str>,
    lookup: Lookup<'b>,
) -> Option<Verdict<'b>> {
    if mode == EligibilityMode::Off {
        return None;
    }
    let (verdict, bundle) = match lookup {
        Lookup::NoPolicy => (Verdict::NotJudged(NotJudged::NoPolicyRef), None),
        Lookup::NotResolved => (Verdict::NotJudged(NotJudged::PolicyNotResolved), None),
        Lookup::Found(bundle) => (judge(bundle, requester.groups), Some(bundle)),
    };
    let reason = match verdict {
        Verdict::NotJudged(why) => why.as_str(),
        Verdict::Eligible { .. } | Verdict::NotEligible => "none",
    };
    let matched_group = match verdict {
        Verdict::Eligible { matched } => matched,
        Verdict::NotEligible | Verdict::NotJudged(_) => "none",
    };
    let code = verdict
        .code()
        .map_or_else(|| "none".to_owned(), |c| c.to_string());
    let policy_namespace = bundle.map_or("none", |b| b.content.policy.namespace.as_str());
    let bundle_version = bundle.map(|b| b.meta.version);
    let policy_groups = bundle
        .and_then(|b| b.content.subjects.as_ref())
        .map(|s| s.groups.len());
    tracing::info!(
        mode = %mode,
        eligibility = verdict.as_str(),
        %code,
        reason,
        path = path.as_str(),
        %namespace,
        ?sandbox,
        policy = policy.unwrap_or("none"),
        policy_namespace,
        ?bundle_version,
        issuer = %requester.issuer,
        subject = %requester.subject,
        matched_group,
        ?policy_groups,
        "{LINE}"
    );
    Some(verdict)
}

/// One process-wide subscriber writing into a buffer per thread (the shape of the API
/// crate's): the reconciler's tests and these read what their own thread logged.
#[cfg(test)]
pub(crate) mod test_logs {
    thread_local! {
        static LOGS: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    struct ThreadLogs;

    impl std::io::Write for ThreadLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            LOGS.with(|l| l.borrow_mut().extend_from_slice(buf));
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Start capturing this thread's log lines from nothing.
    pub(crate) fn capture() {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            let _ = tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_writer(|| ThreadLogs)
                    .with_max_level(tracing::Level::TRACE)
                    .with_ansi(false)
                    .finish(),
            );
        });
        LOGS.with(|l| l.borrow_mut().clear());
    }

    /// The lines this thread wrote since [`capture`] that are eligibility decisions.
    pub(crate) fn decisions() -> Vec<String> {
        LOGS.with(|l| {
            String::from_utf8_lossy(&l.borrow())
                .lines()
                .filter(|l| l.contains(super::LINE))
                .map(str::to_owned)
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::Timestamp;

    fn v4(groups: &[&str]) -> BundlePayload {
        let content = mediatore_testkit::policy::fresh_bundle(Timestamp::now(), 1)
            .payload
            .content;
        mediatore_testkit::policy::signed_bundle_v4(Timestamp::now(), 2, content, groups).payload
    }

    fn v3() -> BundlePayload {
        mediatore_testkit::policy::fresh_bundle(Timestamp::now(), 1).payload
    }

    fn groups(g: &[&str]) -> Vec<String> {
        g.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_requester_holding_one_of_the_policys_groups_is_eligible_and_the_line_names_that_group() {
        let b = v4(&["team-a", "team-b"]);
        let held = groups(&["sandbox-users", "team-b"]);
        assert_eq!(
            judge(&b, Some(&held)),
            Verdict::Eligible { matched: "team-b" }
        );
        assert_eq!(judge(&b, Some(&held)).code(), None);
    }

    #[test]
    fn a_requester_holding_none_is_not_eligible_p015_and_an_empty_list_is_nobody() {
        let held = groups(&["team-c"]);
        let listed = v4(&["team-a", "team-b"]);
        let v = judge(&listed, Some(&held));
        assert_eq!(v, Verdict::NotEligible);
        assert_eq!(v.code(), Some(Code::P015));
        // `[]` is nobody (notaio ADR-0024 decision 1), never anyone.
        assert_eq!(judge(&v4(&[]), Some(&held)), Verdict::NotEligible);
        // A requester with no groups at all is judged, and holds none.
        assert_eq!(judge(&v4(&["team-a"]), Some(&[])), Verdict::NotEligible);
    }

    #[test]
    fn a_v3_bundle_is_not_judged_p016() {
        let old = v3();
        let v = judge(&old, Some(&groups(&["team-a"])));
        assert_eq!(v, Verdict::NotJudged(NotJudged::V3Bundle));
        assert_eq!(v.code(), Some(Code::P016));
    }

    #[test]
    fn a_v4_payload_without_subjects_is_not_judged_p016_never_open() {
        // notaio's verifier refuses it (`Malformed`), so it never reaches the cache; the
        // check still reads it as no statement, not as anyone.
        let mut b = v4(&["team-a"]);
        b.content.subjects = None;
        let v = judge(&b, Some(&groups(&["team-a"])));
        assert_eq!(v, Verdict::NotJudged(NotJudged::NoSubjects));
        assert_eq!(v.code(), Some(Code::P016));
    }

    #[test]
    fn without_the_requesters_groups_nothing_is_judged() {
        assert_eq!(
            judge(&v4(&["team-a"]), None),
            Verdict::NotJudged(NotJudged::NoGroups)
        );
    }

    #[test]
    fn the_spelling_is_the_issuers_own_no_prefix_added_or_stripped() {
        // ADR-0073 decision 4: the broker's own decisions keep the upstream spelling. A token
        // validated from an issuer with `subject_prefix: "dex:"` carries `team-a`, not
        // `dex:team-a`: the prefix is in minted tokens only.
        let held = groups(&["team-a"]);
        assert_eq!(
            judge(&v4(&["dex:team-a"]), Some(&held)),
            Verdict::NotEligible,
            "a qualified name does not match the bare group"
        );
        assert_eq!(
            judge(&v4(&["team-a"]), Some(&groups(&["dex:team-a"]))),
            Verdict::NotEligible,
            "nor the reverse"
        );
        // A connector's own prefix (GitHub's `org:team`) is part of the name.
        assert_eq!(
            judge(
                &v4(&["firestoned:sandbox-users"]),
                Some(&groups(&["sandbox-users"]))
            ),
            Verdict::NotEligible
        );
        assert_eq!(
            judge(
                &v4(&["firestoned:sandbox-users"]),
                Some(&groups(&["firestoned:sandbox-users"]))
            ),
            Verdict::Eligible {
                matched: "firestoned:sandbox-users"
            }
        );
        // Exact and case-sensitive (ADR-0046 decision 2).
        assert_eq!(judge(&v4(&["Team-A"]), Some(&held)), Verdict::NotEligible);
    }

    #[test]
    fn the_mode_is_off_or_shadow_and_enforce_does_not_start() {
        assert_eq!(EligibilityMode::default(), EligibilityMode::Off);
        assert_eq!(EligibilityMode::parse("off"), Ok(EligibilityMode::Off));
        assert_eq!(
            EligibilityMode::parse("shadow"),
            Ok(EligibilityMode::Shadow)
        );
        let refused = EligibilityMode::parse("enforce").unwrap_err();
        assert!(
            refused.contains("ADR-0066") && refused.contains("not built"),
            "{refused}"
        );
        for other in ["Shadow", "enforced", "on", ""] {
            assert!(EligibilityMode::parse(other).is_err(), "{other:?}");
        }
        let read: Result<EligibilityMode, _> = serde_json::from_str("\"enforce\"");
        assert!(read.unwrap_err().to_string().contains("ADR-0066"));
        let read: EligibilityMode = serde_json::from_str("\"shadow\"").unwrap();
        assert_eq!(read, EligibilityMode::Shadow);
    }

    fn requester(held: &[String]) -> Requester<'_> {
        Requester {
            issuer: "https://dex.home.example",
            subject: "octocat",
            groups: Some(held),
        }
    }

    #[test]
    fn under_off_nothing_is_judged_or_written() {
        test_logs::capture();
        let b = v4(&["team-a"]);
        let held = groups(&["team-b"]);
        for lookup in [Lookup::Found(&b), Lookup::NoPolicy, Lookup::NotResolved] {
            assert_eq!(
                record(
                    EligibilityMode::Off,
                    Path::FrontDoor,
                    "sandboxes",
                    None,
                    &requester(&held),
                    Some("agent"),
                    lookup,
                ),
                None
            );
        }
        assert_eq!(test_logs::decisions(), Vec::<String>::new());
    }

    #[test]
    fn each_decision_is_one_line_naming_the_matched_group_and_never_the_requesters_list() {
        test_logs::capture();
        let b = v4(&["team-a", "team-z"]);
        let held = groups(&["TOKEN-GROUP-CANARY", "team-a"]);
        let old = v3();
        let cases: [(Lookup<'_>, Option<&str>, &str); 4] = [
            (Lookup::Found(&b), Some("agent"), "eligibility=\"eligible\""),
            (Lookup::NoPolicy, None, "reason=\"no_policy_ref\""),
            (
                Lookup::NotResolved,
                Some("agent"),
                "reason=\"policy_not_resolved\"",
            ),
            (Lookup::Found(&old), Some("agent"), "reason=\"v3_bundle\""),
        ];
        for (lookup, policy, _) in cases {
            record(
                EligibilityMode::Shadow,
                Path::FrontDoor,
                "sandboxes",
                None,
                &requester(&held),
                policy,
                lookup,
            );
        }
        let not = groups(&["TOKEN-GROUP-CANARY"]);
        record(
            EligibilityMode::Shadow,
            Path::FrontDoor,
            "sandboxes",
            None,
            &requester(&not),
            Some("agent"),
            Lookup::Found(&b),
        );
        let lines = test_logs::decisions();
        assert_eq!(lines.len(), 5, "one line per decision: {lines:#?}");
        for ((_, _, want), line) in cases.iter().zip(&lines) {
            assert!(line.contains(want), "{want} in {line}");
        }
        let eligible = &lines[0];
        for needle in [
            "matched_group=\"team-a\"",
            "subject=octocat",
            "issuer=https://dex.home.example",
            "policy=\"agent\"",
            "path=\"front_door\"",
            "namespace=sandboxes",
            "policy_groups=Some(2)",
            "mode=shadow",
        ] {
            assert!(eligible.contains(needle), "{needle} in {eligible}");
        }
        let not_eligible = &lines[4];
        assert!(
            not_eligible.contains("eligibility=\"not_eligible\"")
                && not_eligible.contains("code=P015")
                && not_eligible.contains("matched_group=\"none\""),
            "{not_eligible}"
        );
        assert!(lines[3].contains("code=P016"), "{}", lines[3]);
        for line in &lines {
            assert!(
                !line.contains("TOKEN-GROUP-CANARY"),
                "the requester's group list reached a line: {line}"
            );
            assert!(
                !line.contains("team-z"),
                "the policy's list reached a line: {line}"
            );
        }
    }
}
