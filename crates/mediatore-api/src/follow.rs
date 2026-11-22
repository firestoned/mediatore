// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! ADR-0061 at the answers: a running claim follows its policy's newer bundle only while it is
//! still inside it. Every answer for a claim (`GET /v1/me`, `POST /v1/token`, the gateway's
//! claim answer and its credential) passes [`gate`] first, so they cannot disagree; `GET
//! /v1/me`'s first `200` records what the guest was handed ([`record_rendered`]).

use axum::http::StatusCode;
use jiff::Timestamp;
use mediatore_claims::follow::{Current, Render, serve_under};
use mediatore_claims::policy::{EgressMode, Resolution};
use mediatore_proto::{
    Endpoint, FollowReason, FollowRefusal, Rendered, RenderedRoute, Route, error_code,
};
use mediatore_store::{ClaimRecord, modify_claim};

use crate::{ApiError, AppState, PolicyEgress, claims_bundle, handed};

/// The routes as the record keeps them: no credential placement, only what bounds a request.
pub(crate) fn rendered_routes(routes: &[Route]) -> Vec<RenderedRoute> {
    routes
        .iter()
        .map(|r| RenderedRoute {
            audience: r.audience.clone(),
            endpoint: r.endpoint.clone(),
            rules: r.rules.clone(),
        })
        .collect()
}

/// Whether `pe` refuses (decision 5): `policy.follow: enforce` under `policy.audiences:
/// enforce`. Anything else records and serves.
fn enforced(pe: &PolicyEgress) -> bool {
    pe.follow == EgressMode::Enforce && pe.audiences == EgressMode::Enforce
}

/// The refusal a claim gets under enforce (decision 4): the reason, never a rule, a host or a
/// token.
pub(crate) fn refusal(reason: FollowReason) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        error_code::POLICY_CHANGED,
        Some(format!(
            "the claim is no longer inside its policy's current bundle: {reason}"
        )),
    )
}

/// The rule's verdict for `rec` now: `None` when it is served (or there is nothing to follow:
/// no policy section, no policy on the record, no usable bundle, which the answers already
/// treat as granting nothing), else the reason and the current version.
fn verdict(
    st: &AppState,
    pe: &PolicyEgress,
    rec: &ClaimRecord,
    rendering: bool,
) -> Option<(FollowReason, u64)> {
    let uid = rec.policy_uid.as_deref()?;
    let bundle = claims_bundle(pe, rec)?;
    let version = bundle.meta.version;
    let render = match (&rec.rendered, rendering) {
        (Some(r), _) => Render::Recorded(r),
        (None, true) => Render::Rendering {
            admitted_version: rec.bundle_version,
        },
        (None, false) => Render::Unknown {
            admitted_version: rec.bundle_version,
        },
    };
    // A name a source of this replica has not listed yet is neither a pass nor a refusal of
    // the name: the uid was found and its namespace is a source, so it resolves.
    let resolves = match pe.bundles.resolve(
        &pe.sources,
        &rec.namespace,
        &bundle.content.policy.name,
        Timestamp::now(),
    ) {
        Resolution::Found(b) => b.content.policy.uid == uid,
        Resolution::NotRead => true,
        Resolution::NotFound | Resolution::Ambiguous => false,
    };
    // The routes are computed only when the rendered leg reads them.
    let compares = matches!(render, Render::Recorded(r) if r.bundle_version != version);
    let (egress, routes) = if compares {
        let (egress, routes) = handed(st, rec);
        (egress, rendered_routes(&routes))
    } else {
        (Vec::new(), Vec::new())
    };
    let current = Current {
        version,
        digest: &bundle.content_digest,
        lease_max_seconds: i64::from(bundle.content.lease.max_duration_seconds),
        resolves,
        routes: &routes,
        egress: &egress,
    };
    serve_under(render, &current, rec.ttl_seconds)
        .err()
        .map(|reason| (reason, version))
}

/// ADR-0061 decisions 1, 4 and 5 for one answer: `Ok` when the claim is served (under shadow,
/// always), the `403 policy_changed` refusal under enforce. A refusal, or its end under shadow,
/// is written on the record once, with one line, so every replica and the reconciler read it.
///
/// # Errors
///
/// [`refusal`] under enforce, for a claim the rule refuses now or refused before.
pub(crate) async fn gate(
    st: &AppState,
    rec: &ClaimRecord,
    rendering: bool,
) -> Result<(), ApiError> {
    let Some(pe) = st.policy_egress.as_ref() else {
        return Ok(());
    };
    let enforce = enforced(pe);
    // Final for the claim (decision 4), while enforce stands; setting shadow serves it again.
    if enforce && let Some(f) = rec.follow.as_ref().filter(|f| f.enforced) {
        return Err(refusal(f.reason));
    }
    let Some((reason, current_version)) = verdict(st, pe, rec, rendering) else {
        if rec.follow.is_some() {
            write_follow(st, rec, None).await;
        }
        return Ok(());
    };
    let rendered_version = rec.rendered.as_ref().map(|r| r.bundle_version);
    let same = rec.follow.as_ref().is_some_and(|f| {
        (f.reason, f.current_version, f.enforced) == (reason, current_version, enforce)
    });
    if !same {
        let policy_uid = rec.policy_uid.as_deref().unwrap_or_default();
        let admitted_version = rec.bundle_version;
        match reason {
            FollowReason::RenderedWider | FollowReason::BundleChangedInPlace => {
                tracing::warn!(claim_uid = %rec.uid, %policy_uid, ?admitted_version, ?rendered_version, current_version, %reason, enforced = enforce, "a running claim is not inside its policy's current bundle (ADR-0061)");
            }
            _ => {
                tracing::info!(claim_uid = %rec.uid, %policy_uid, ?admitted_version, ?rendered_version, current_version, %reason, enforced = enforce, "a running claim is not inside its policy's current bundle (ADR-0061)");
            }
        }
        write_follow(
            st,
            rec,
            Some(FollowRefusal {
                reason,
                rendered_version,
                current_version,
                enforced: enforce,
                at: Timestamp::now(),
            }),
        )
        .await;
    }
    if enforce {
        Err(refusal(reason))
    } else {
        Ok(())
    }
}

/// Put `next` on the record. A lost write is logged: the answer stands on the verdict it
/// computed, and the next answer writes again.
async fn write_follow(st: &AppState, rec: &ClaimRecord, next: Option<FollowRefusal>) {
    let written = modify_claim(st.store.as_ref(), rec.uid, |mut r| {
        if r.follow == next {
            return None;
        }
        r.follow.clone_from(&next);
        Some(r)
    })
    .await;
    if let Err(e) = written {
        tracing::warn!(claim_uid = %rec.uid, error = %e, "the follow verdict could not be put on the record (ADR-0061)");
    }
}

/// Decision 2: on the guest's first `200` from `GET /v1/me`, keep what it was handed, once. A
/// claim with no policy, or no usable bundle, keeps nothing. A write that fails leaves the
/// record as a claim from before the ADR, refused at the first changed version under enforce
/// (decision 6), never served as if the guest had rendered nothing.
pub(crate) async fn record_rendered(
    st: &AppState,
    rec: &ClaimRecord,
    egress: &[Endpoint],
    routes: &[Route],
) {
    let Some(pe) = st.policy_egress.as_ref() else {
        return;
    };
    if rec.policy_uid.is_none() {
        return;
    }
    let Some(bundle) = claims_bundle(pe, rec) else {
        return;
    };
    let rendered = Rendered {
        bundle_version: bundle.meta.version,
        bundle_digest: bundle.content_digest.clone(),
        routes: rendered_routes(routes),
        egress: egress.to_vec(),
    };
    let written = modify_claim(st.store.as_ref(), rec.uid, |mut r| {
        if r.rendered.is_some() {
            return None;
        }
        r.rendered = Some(rendered.clone());
        Some(r)
    })
    .await;
    match written {
        Ok(_) => {
            tracing::debug!(claim_uid = %rec.uid, bundle_version = rendered.bundle_version, routes = rendered.routes.len(), "what the guest was handed is recorded (ADR-0061)");
        }
        Err(e) => {
            tracing::warn!(claim_uid = %rec.uid, error = %e, "what the guest was handed could not be recorded (ADR-0061)");
        }
    }
}
