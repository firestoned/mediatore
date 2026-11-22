// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Whether a running claim follows its policy's current bundle (ADR-0061): only while the
//! sandbox is still inside it. One pure function, [`serve_under`], read by every answer for a
//! claim (a mint, `GET /v1/me`, the gateway's answer and credential), so they cannot disagree.

use mediatore_proto::{Endpoint, EndpointRule, FollowReason, Rendered, RenderedRoute};

use crate::shadow::rule_covers;

/// What the claim's record says the guest was handed.
#[derive(Debug, Clone, Copy)]
pub enum Render<'a> {
    /// This answer is the guest's first `200` from `GET /v1/me`: what it carries is what the
    /// guest renders, so only admission is checked.
    Rendering {
        /// The bundle version the claim was admitted under.
        admitted_version: Option<u64>,
    },
    /// The guest rendered what the record holds.
    Recorded(&'a Rendered),
    /// The guest rendered, and nothing records what: a claim from before ADR-0061.
    Unknown {
        /// The bundle version the claim was admitted under.
        admitted_version: Option<u64>,
    },
}

/// The claim's current bundle and what the claim would be given under it.
#[derive(Debug, Clone, Copy)]
pub struct Current<'a> {
    /// The bundle's version.
    pub version: u64,
    /// Its payload's content digest.
    pub digest: &'a str,
    /// Its `lease.maxDurationSeconds`.
    pub lease_max_seconds: i64,
    /// Whether the policy's name still resolves, in the namespace's sources, to the claim's
    /// policy (ADR-0054).
    pub resolves: bool,
    /// The proxy's routes the claim would be handed now.
    pub routes: &'a [RenderedRoute],
    /// The ruleset's destinations the claim would be handed now.
    pub egress: &'a [Endpoint],
}

/// Whether a claim of `ttl_seconds` that rendered as `render` is served under `current`
/// (ADR-0061 decisions 1 and 3).
///
/// # Errors
///
/// The [`FollowReason`] of the first leg that does not hold.
pub fn serve_under(
    render: Render<'_>,
    current: &Current<'_>,
    ttl_seconds: u32,
) -> Result<(), FollowReason> {
    match render {
        Render::Recorded(r) if r.bundle_version == current.version => {
            if r.bundle_digest == current.digest {
                Ok(())
            } else {
                Err(FollowReason::BundleChangedInPlace)
            }
        }
        Render::Recorded(r) => {
            admitted(current, ttl_seconds)?;
            within(r, current)
        }
        Render::Rendering { admitted_version } if admitted_version == Some(current.version) => {
            Ok(())
        }
        Render::Rendering { .. } => admitted(current, ttl_seconds),
        Render::Unknown { admitted_version } if admitted_version == Some(current.version) => Ok(()),
        Render::Unknown { .. } => Err(FollowReason::RenderedUnknown),
    }
}

/// The admission leg: the claim would be admitted under `current`.
fn admitted(current: &Current<'_>, ttl_seconds: u32) -> Result<(), FollowReason> {
    if !current.resolves {
        return Err(FollowReason::PolicyUnresolved);
    }
    if i64::from(ttl_seconds) > current.lease_max_seconds {
        return Err(FollowReason::LeaseExceeded);
    }
    Ok(())
}

/// The rendered leg: nothing the guest rendered is wider than `current` allows.
fn within(rendered: &Rendered, current: &Current<'_>) -> Result<(), FollowReason> {
    let routes_inside = rendered.routes.iter().all(|r| {
        current.routes.iter().any(|c| {
            c.audience == r.audience && c.endpoint == r.endpoint && rules_within(&r.rules, &c.rules)
        })
    });
    let egress_inside = rendered.egress.iter().all(|e| current.egress.contains(e));
    if routes_inside && egress_inside {
        Ok(())
    } else {
        Err(FollowReason::RenderedWider)
    }
}

/// Whether every request `rendered` admits, `current` admits too. An empty list admits every
/// method and path, so it is inside only an empty list.
fn rules_within(rendered: &[EndpointRule], current: &[EndpointRule]) -> bool {
    if current.is_empty() {
        return true;
    }
    !rendered.is_empty()
        && rendered
            .iter()
            .all(|r| current.iter().any(|c| rule_covers(c, r)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(host: &str, port: u16) -> Endpoint {
        Endpoint {
            host: host.to_owned(),
            port,
        }
    }

    fn rule(method: &str, path: &str) -> EndpointRule {
        EndpointRule {
            method: method.to_owned(),
            path: path.to_owned(),
        }
    }

    fn route(audience: &str, rules: Vec<EndpointRule>) -> RenderedRoute {
        RenderedRoute {
            audience: Some(audience.to_owned()),
            endpoint: ep("git.example.com", 443),
            rules,
        }
    }

    fn rendered(version: u64, routes: Vec<RenderedRoute>) -> Rendered {
        Rendered {
            bundle_version: version,
            bundle_digest: format!("sha256:v{version}"),
            routes,
            egress: vec![ep("git.example.com", 443)],
        }
    }

    struct Now {
        version: u64,
        digest: String,
        lease: i64,
        resolves: bool,
        routes: Vec<RenderedRoute>,
        egress: Vec<Endpoint>,
    }

    impl Now {
        fn at(version: u64, routes: Vec<RenderedRoute>) -> Self {
            Self {
                version,
                digest: format!("sha256:v{version}"),
                lease: 3600,
                resolves: true,
                routes,
                egress: vec![ep("git.example.com", 443)],
            }
        }

        fn current(&self) -> Current<'_> {
            Current {
                version: self.version,
                digest: &self.digest,
                lease_max_seconds: self.lease,
                resolves: self.resolves,
                routes: &self.routes,
                egress: &self.egress,
            }
        }
    }

    fn repo_read() -> Vec<EndpointRule> {
        vec![rule("GET", "/repos/**")]
    }

    #[test]
    fn the_version_the_guest_rendered_is_served() {
        let r = rendered(3, vec![route("git", repo_read())]);
        let now = Now::at(3, vec![route("git", repo_read())]);
        assert_eq!(
            serve_under(Render::Recorded(&r), &now.current(), 900),
            Ok(())
        );
    }

    #[test]
    fn a_narrowed_audience_or_lifetime_with_nothing_rendered_wider_is_served() {
        // The guest rendered a tighter rule than the new version allows: still inside.
        let r = rendered(3, vec![route("git", vec![rule("GET", "/repos/a/**")])]);
        let now = Now::at(4, vec![route("git", repo_read())]);
        assert_eq!(
            serve_under(Render::Recorded(&r), &now.current(), 900),
            Ok(())
        );
    }

    #[test]
    fn a_narrowed_rule_the_guest_rendered_wider_is_refused() {
        let r = rendered(3, vec![route("git", repo_read())]);
        let now = Now::at(4, vec![route("git", vec![rule("GET", "/repos/a/**")])]);
        assert_eq!(
            serve_under(Render::Recorded(&r), &now.current(), 900),
            Err(FollowReason::RenderedWider)
        );
    }

    #[test]
    fn a_rendered_route_with_no_rules_is_inside_only_a_route_with_none() {
        let r = rendered(3, vec![route("git", vec![])]);
        let narrowed = Now::at(4, vec![route("git", repo_read())]);
        assert_eq!(
            serve_under(Render::Recorded(&r), &narrowed.current(), 900),
            Err(FollowReason::RenderedWider)
        );
        let open = Now::at(4, vec![route("git", vec![])]);
        assert_eq!(
            serve_under(Render::Recorded(&r), &open.current(), 900),
            Ok(())
        );
    }

    #[test]
    fn a_removed_audience_the_guest_rendered_a_route_for_is_refused() {
        let r = rendered(3, vec![route("git", repo_read())]);
        let now = Now::at(4, vec![]);
        assert_eq!(
            serve_under(Render::Recorded(&r), &now.current(), 900),
            Err(FollowReason::RenderedWider)
        );
    }

    #[test]
    fn a_closed_destination_the_ruleset_still_admits_is_refused() {
        let r = rendered(3, vec![route("git", repo_read())]);
        let mut now = Now::at(4, vec![route("git", repo_read())]);
        now.egress.clear();
        assert_eq!(
            serve_under(Render::Recorded(&r), &now.current(), 900),
            Err(FollowReason::RenderedWider)
        );
    }

    #[test]
    fn a_route_moved_to_another_audience_is_not_the_same_route() {
        let r = rendered(3, vec![route("git", repo_read())]);
        let now = Now::at(4, vec![route("other", repo_read())]);
        assert_eq!(
            serve_under(Render::Recorded(&r), &now.current(), 900),
            Err(FollowReason::RenderedWider)
        );
    }

    #[test]
    fn a_lease_shortened_below_the_claims_lifetime_is_refused() {
        let r = rendered(3, vec![route("git", repo_read())]);
        let mut now = Now::at(4, vec![route("git", repo_read())]);
        now.lease = 600;
        assert_eq!(
            serve_under(Render::Recorded(&r), &now.current(), 900),
            Err(FollowReason::LeaseExceeded)
        );
        assert_eq!(
            serve_under(Render::Recorded(&r), &now.current(), 600),
            Ok(())
        );
    }

    #[test]
    fn a_policy_that_no_longer_resolves_is_refused() {
        let r = rendered(3, vec![route("git", repo_read())]);
        let mut now = Now::at(4, vec![route("git", repo_read())]);
        now.resolves = false;
        assert_eq!(
            serve_under(Render::Recorded(&r), &now.current(), 900),
            Err(FollowReason::PolicyUnresolved)
        );
    }

    #[test]
    fn the_same_version_with_another_digest_is_refused() {
        let r = rendered(3, vec![route("git", repo_read())]);
        let mut now = Now::at(3, vec![route("git", repo_read())]);
        now.digest = "sha256:other".into();
        assert_eq!(
            serve_under(Render::Recorded(&r), &now.current(), 900),
            Err(FollowReason::BundleChangedInPlace)
        );
    }

    #[test]
    fn a_claim_from_before_the_adr_is_served_until_the_version_changes() {
        let same = Now::at(3, vec![route("git", repo_read())]);
        let render = Render::Unknown {
            admitted_version: Some(3),
        };
        assert_eq!(serve_under(render, &same.current(), 900), Ok(()));
        // Never read as "rendered nothing": a later version is refused even when it widens.
        let wider = Now::at(4, vec![route("git", vec![])]);
        assert_eq!(
            serve_under(render, &wider.current(), 900),
            Err(FollowReason::RenderedUnknown)
        );
    }

    #[test]
    fn the_first_answer_checks_admission_alone() {
        let render = Render::Rendering {
            admitted_version: Some(3),
        };
        // A newer version before the guest's first answer: the guest renders from it.
        let newer = Now::at(4, vec![route("git", repo_read())]);
        assert_eq!(serve_under(render, &newer.current(), 900), Ok(()));
        let mut shorter = Now::at(4, vec![]);
        shorter.lease = 60;
        assert_eq!(
            serve_under(render, &shorter.current(), 900),
            Err(FollowReason::LeaseExceeded)
        );
    }
}
