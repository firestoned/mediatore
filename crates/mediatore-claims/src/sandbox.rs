// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The `AgentSandbox` custom resource (ADR-0008) and its reconcile.
//!
//! An `AgentSandbox` is the record of one sandbox request. The reconciler, which runs on
//! the same leader-elected loop as the claim watcher ([`crate::watch::run`]), creates and
//! owns exactly one `VirtualMachineClaim` for it (decision 3), writes the store record
//! keyed by that claim's UID (decision 12), mirrors the claim's status plus whether the
//! claim's registration entry is set (decision 11), and holds a finalizer until the claim
//! is gone (decision 10). The claim watcher does the binding; this module never declares
//! an entry itself.
//!
//! The CRD in `deploy/base/crds/` is rendered from [`AgentSandboxSpec`] by the `crdgen`
//! binary and checked by a unit test; it is never edited by hand (decision 1).

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use banlieue_api::banlieue::{
    ClaimSelection, ClaimSubject, SelectionStrategy, VirtualMachineClaim, VirtualMachineClaimSpec,
};
use banlieue_api::common::{
    LabelSelector, LabelSelectorOperator, LabelSelectorRequirement, LocalObjectReference,
};
use jiff::Timestamp;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{DeleteParams, ObjectMeta, PostParams};
use kube::runtime::controller::Action;
use kube::{Api, Client, CustomResource, CustomResourceExt, Resource, ResourceExt};
use mediatore_policy::BundlePayload;
use mediatore_proto::{
    ClaimPhase, PoolChoice, PoolSelector, PoolSelectorOperator, RestartPolicy, Subject, Workload,
};
use mediatore_spire::{MANAGED_BY, MANAGED_BY_LABEL};
use mediatore_store::{ClaimRecord, StoreError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::{BundleCache, EgressMode, POLICY_NOT_RESOLVED, Resolution, not_resolved};
use crate::shadow;
use crate::watch::{WatchError, Watcher, claim_uid_of, phase_of};

/// The finalizer that holds an `AgentSandbox` until its claim is gone (decision 10).
pub const FINALIZER: &str = "mediatore.io/sandbox";

/// Label on the owned claim naming the sandbox's UID, beside the managed-by label the
/// watcher selects on.
pub const SANDBOX_UID_LABEL: &str = "mediatore.io/sandbox-uid";

/// Why a sandbox asking for more than `sandboxes.max_ttl_seconds` is refused: the sentence in
/// `status.reason` (ADR-0008 decision 9, amended 2026-11-26). It names the ceiling, which is
/// configuration, so the requester knows what would fit.
#[must_use]
pub fn ttl_above_maximum(max_ttl_seconds: u32) -> String {
    format!(
        "ttlSeconds is above the broker's maximum of {max_ttl_seconds} seconds (sandboxes.max_ttl_seconds)"
    )
}

/// The CRD's file name under `deploy/base/crds/` (kubebuilder convention).
pub const CRD_FILE_NAME: &str = "mediatore.io_agentsandboxes.yaml";

/// The subject a sandbox is for. Mirrors `spec.subject` on the banlieue claim, plus a
/// display name banlieue does not carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SandboxSubject {
    /// OIDC issuer URL, byte-for-byte as it appears in `iss`. Must be one of the issuers
    /// mediatore is configured with (decision 7).
    #[schemars(length(min = 1))]
    pub issuer: String,
    /// Raw subject identifier as the issuer spells it (Entra `oid`, GitHub login via Dex).
    /// Pinned to the caller at admission (decision 5).
    #[schemars(length(min = 1))]
    pub id: String,
    /// Human-readable name, informational only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// What the sandbox runs once identity is established (decision 8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SandboxWorkload {
    /// OCI reference of the rootfs the guest agent unpacks into the jail.
    #[schemars(length(min = 1))]
    pub image: String,
    /// Command and arguments to exec inside the jail.
    #[serde(default)]
    pub args: Vec<String>,
    /// What the guest does when the workload exits before the deadline (ADR-0033 decision
    /// 1): `always` (the default, restarted until the deadline), `on-failure` (an exit 0
    /// ends the claim), `never` (any exit ends the claim).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<SandboxRestart>,
    /// The requester's opt-in to output capture (ADR-0045 decision 1, amended): `true` and
    /// the guest tees, redacts and ships the workload's stdout and stderr to the broker, where
    /// the subject reads them with `GET /v1/claims/{name}/logs`. Off by default; a sandbox
    /// that opts in on a broker whose `logs` section is off is refused before any claim exists.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub logs: bool,
}

/// [`mediatore_proto::RestartPolicy`] as the resource spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxRestart {
    /// Restart whatever the status, until the deadline.
    Always,
    /// Restart a non-zero exit; an exit 0 ends the claim.
    OnFailure,
    /// Any exit ends the claim.
    Never,
}

impl From<SandboxRestart> for RestartPolicy {
    fn from(r: SandboxRestart) -> Self {
        match r {
            SandboxRestart::Always => Self::Always,
            SandboxRestart::OnFailure => Self::OnFailure,
            SandboxRestart::Never => Self::Never,
        }
    }
}

impl From<RestartPolicy> for SandboxRestart {
    fn from(r: RestartPolicy) -> Self {
        match r {
            RestartPolicy::Always => Self::Always,
            RestartPolicy::OnFailure => Self::OnFailure,
            RestartPolicy::Never => Self::Never,
        }
    }
}

/// The request mediatore already accepts on `POST /v1/claims`, as a resource (decision 7).
/// Immutable after creation: the admission policy in
/// `deploy/base/admission/agentsandbox-subject.yaml` freezes it.
#[derive(CustomResource, Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mediatore.io",
    version = "v1beta1",
    kind = "AgentSandbox",
    plural = "agentsandboxes",
    shortname = "asb",
    namespaced,
    status = "AgentSandboxStatus",
    derive = "PartialEq",
    printcolumn = r#"{"name":"Subject","type":"string","jsonPath":".spec.subject.id"}"#,
    // The pool the bound member came from, not `spec.poolRef`: a sandbox with a
    // `poolSelector` names no pool in its spec (ADR-0044 decision 5).
    printcolumn = r#"{"name":"Pool","type":"string","jsonPath":".status.poolRef.name"}"#,
    // The bound member (`status.virtualMachineRef`), mirrored from the claim.
    printcolumn = r#"{"name":"VM","type":"string","jsonPath":".status.virtualMachineRef.name"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Ready","type":"boolean","jsonPath":".status.ready"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
// The claim's own rule (banlieue ADR-0132 decision 1), restated here so a sandbox the claim
// would refuse is refused at its own admission, before a claim exists (ADR-0044 decision 1).
#[schemars(extend("x-kubernetes-validations" = [{
    "rule": "has(self.poolRef) != has(self.poolSelector)",
    "message": "a sandbox takes exactly one of poolRef or poolSelector; use poolSelector: {} for any pool in the namespace",
}]))]
pub struct AgentSandboxSpec {
    /// Who the sandbox is for.
    pub subject: SandboxSubject,
    /// The `VirtualMachinePool` to claim from, in this namespace; copied to the claim.
    /// Exactly one of this or `poolSelector` (ADR-0044 decision 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_ref: Option<LocalObjectReference>,
    /// Any `VirtualMachinePool` in this namespace whose labels match, `{}` for all of them;
    /// copied to the claim, which picks among their members (banlieue ADR-0132). Exactly one
    /// of this or `poolRef` (ADR-0044 decisions 1 and 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_selector: Option<LabelSelector>,
    /// How banlieue picks the member among the Ready ones of the matched pools (ADR-0047
    /// decision 1; banlieue ADR-0135): `strategy` is `LongestReady`, `MostAvailable` or
    /// `Spread`. Copied to the claim verbatim; absent stays absent, which is `LongestReady`,
    /// the order every sandbox had before (decision 2). Immutable with the rest of the spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<ClaimSelection>,
    /// Lifetime in seconds, counted from bind; copied to the claim, which enforces it
    /// (decision 9).
    #[schemars(range(min = 1))]
    pub ttl_seconds: u32,
    /// Downstream audiences the sandbox may request tokens for. Each must be one mediatore
    /// is configured to serve; otherwise the sandbox fails before any claim exists.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// What to run.
    pub workload: SandboxWorkload,
    /// The notaio `SandboxPolicy` this sandbox is under, in this namespace (ADR-0026
    /// decision 6). Optional while the bundle is read in shadow: a sandbox without one is
    /// reported, never refused, and naming one grants nothing yet. The claim record keeps
    /// the policy's uid and the bundle version current when the claim was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<LocalObjectReference>,
}

/// The claim's phase, mirrored (decision 11). Never derived independently.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SandboxPhase {
    /// No claim yet, or the claim is waiting for a Ready pool member.
    #[default]
    Pending,
    /// The claim is bound to a member. `ready` says whether the entry is set as well.
    Bound,
    /// The claim is releasing (TTL reached, or deleted); tokens are cut off.
    Releasing,
    /// Terminal: the request was refused, the claim failed, or the claim is gone.
    Failed,
}

impl From<SandboxPhase> for ClaimPhase {
    fn from(p: SandboxPhase) -> Self {
        match p {
            SandboxPhase::Pending => Self::Pending,
            SandboxPhase::Bound => Self::Bound,
            SandboxPhase::Releasing => Self::Releasing,
            SandboxPhase::Failed => Self::Failed,
        }
    }
}

/// What the reconciler reports: the claim's status, plus the one fact only mediatore knows.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentSandboxStatus {
    /// Mirrored from the claim.
    #[serde(default)]
    pub phase: SandboxPhase,
    /// The owned claim, set once it has been created; never cleared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<LocalObjectReference>,
    /// The claim's UID: the claim identity's key (ADR-0004, ADR-0011 decision 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_uid: Option<String>,
    /// The bound member, from the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_machine_ref: Option<LocalObjectReference>,
    /// The pool the bound member came from, from the claim (ADR-0044 decision 5): the one
    /// place a sandbox made with `spec.poolSelector` says which pool supplied its VM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_ref: Option<LocalObjectReference>,
    /// The member's addresses, from the claim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    /// From the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<Time>,
    /// From the claim: when banlieue destroys the member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Time>,
    /// The claim's registration entry is set on the SPIRE server (ADR-0006 decision 5).
    #[serde(default)]
    pub entry_set: bool,
    /// `phase == Bound && entry_set` (decision 11).
    #[serde(default)]
    pub ready: bool,
    /// The claim record (ADR-0034 decision 1): the store's part of the status, written by
    /// `KubeStore` alone and never by the reconciler's mirroring, which leaves it out of
    /// its patches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<crate::kubestore::RecordStatus>,
    /// Why the sandbox is `Failed`, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The generation this status was computed from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// `PolicyConformant` (ADR-0026 decision 7): `True` when the broker's configuration
    /// allows this sandbox nothing its policy's bundle does not, `False` with the gaps'
    /// codes in the message, `Unknown` while the bundles of this namespace have not been
    /// read yet. Absent without a `policy` section.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// The condition type the shadow comparison writes.
pub const POLICY_CONFORMANT: &str = "PolicyConformant";

/// The condition type of the follow rule (ADR-0061 decision 4).
pub const POLICY_FOLLOWED: &str = "PolicyFollowed";

/// `conditions` with `PolicyFollowed` set from the record's follow verdict (ADR-0061 decision
/// 4), which the API writes and this mirrors: `False` with the reason and both versions when
/// the rule refuses (`Refused` under enforce, `WouldRefuse` under shadow), `True` once the guest
/// rendered and the claim is inside, absent before. `lastTransitionTime` holds while the status
/// does.
#[must_use]
pub fn followed(
    conditions: Vec<Condition>,
    record: &ClaimRecord,
    generation: Option<i64>,
) -> Vec<Condition> {
    let held = conditions
        .iter()
        .find(|c| c.type_ == POLICY_FOLLOWED)
        .cloned();
    let mut out: Vec<Condition> = conditions
        .into_iter()
        .filter(|c| c.type_ != POLICY_FOLLOWED)
        .collect();
    let (status, reason, message) = match (&record.follow, &record.rendered) {
        (Some(f), _) => (
            "False",
            if f.enforced { "Refused" } else { "WouldRefuse" },
            format!(
                "{}: rendered under bundle v{}, current v{}",
                f.reason,
                f.rendered_version
                    .map_or_else(|| "unknown".to_owned(), |v| v.to_string()),
                f.current_version
            ),
        ),
        (None, Some(r)) => (
            "True",
            "Inside",
            format!(
                "inside its policy's current bundle (rendered under v{})",
                r.bundle_version
            ),
        ),
        (None, None) => return out,
    };
    let last_transition_time = held.filter(|c| c.status == status).map_or_else(
        || Time(k8s_openapi::jiff::Timestamp::now()),
        |c| c.last_transition_time,
    );
    out.push(Condition {
        type_: POLICY_FOLLOWED.into(),
        status: status.into(),
        reason: reason.into(),
        message,
        observed_generation: generation,
        last_transition_time,
    });
    out
}

/// The reason code of a sandbox failed because its `status.record` names another sandbox
/// (ADR-0057 decision 7). The code leads `status.reason`, as `delegation_required` does.
pub const RECORD_NOT_OWN: &str = "record_not_own";

impl From<&SandboxSubject> for Subject {
    fn from(s: &SandboxSubject) -> Self {
        Self {
            issuer: s.issuer.clone(),
            id: s.id.clone(),
            display: s.display.clone(),
        }
    }
}

impl From<&Subject> for SandboxSubject {
    fn from(s: &Subject) -> Self {
        Self {
            issuer: s.issuer.clone(),
            id: s.id.clone(),
            display: s.display.clone(),
        }
    }
}

impl From<&SandboxWorkload> for Workload {
    fn from(w: &SandboxWorkload) -> Self {
        Self {
            image: w.image.clone(),
            args: w.args.clone(),
            restart: w.restart.map(RestartPolicy::from).unwrap_or_default(),
            logs: w.logs,
        }
    }
}

impl From<&Workload> for SandboxWorkload {
    fn from(w: &Workload) -> Self {
        Self {
            image: w.image.clone(),
            args: w.args.clone(),
            restart: (!w.restart.is_always()).then(|| SandboxRestart::from(w.restart)),
            logs: w.logs,
        }
    }
}

/// Every CRD `deploy/base/crds/` carries, by file name (ADR-0008; ADR-0034 for the two
/// store resources).
///
/// # Errors
/// A serialisation failure, which a type change would make a unit test find first.
pub fn crd_yamls() -> Result<Vec<(&'static str, String)>, serde_saphyr::ser::Error> {
    Ok(vec![
        (CRD_FILE_NAME, crd_yaml()?),
        (
            crate::kubestore::NODE_CRD_FILE_NAME,
            render_crd(
                crate::kubestore::SandboxNode::crd(),
                "SandboxNode is one attested node mediatore knows (ADR-0034 decision 3): named by its EK hash, with its SPIRE agent identity, DMI UUID, hostname and whether it is banned.",
            )?,
        ),
        (
            crate::kubestore::FLOOR_CRD_FILE_NAME,
            render_crd(
                crate::kubestore::PolicyFloor::crd(),
                "PolicyFloor is the version floor of one notaio policy (ADR-0026 decision 5, ADR-0034 decision 3): the incarnation, the highest bundle version accepted for it and that bundle's issuedAt; moved by compare-and-set on resourceVersion.",
            )?,
        ),
    ])
}

/// One CRD as YAML, its schema's description set to `description`.
fn render_crd(
    mut crd: k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition,
    description: &str,
) -> Result<String, serde_saphyr::ser::Error> {
    let mut options = serde_saphyr::SerializerOptions::default();
    options.folded_wrap_chars = 1 << 20;
    if let Some(schema) = crd
        .spec
        .versions
        .iter_mut()
        .filter_map(|v| v.schema.as_mut())
        .find_map(|s| s.open_api_v3_schema.as_mut())
    {
        schema.description = Some(description.into());
    }
    crate::crd_formats::strip_unsupported_formats(&mut crd);
    let body = serde_saphyr::to_string_with_options(&crd, options)?;
    Ok(format!(
        "# Copyright (c) 2026 Erick Bourgeois, mediatore\n# SPDX-License-Identifier: Apache-2.0\n#\n# Generated from crates/mediatore-claims/src/kubestore.rs by `make crds` (ADR-0034\n# decision 3). Do not edit: the unit test `the_crds_in_deploy_are_what_the_types_render`\n# fails on a stale file.\n{body}"
    ))
}

/// The served name `AgentSandbox` had before ADR-0048, still served beside the type's own
/// (ADR-0049 decision 1).
pub const DEPRECATED_VERSION: &str = "v1alpha1";

/// The `AgentSandbox` CRD with both served versions (ADR-0049 decisions 1 and 2): the
/// type's own (`v1beta1`, stored) and [`DEPRECATED_VERSION`], a copy of it under the old
/// name, served, not stored, deprecated. One schema by construction, so conversion is `None`.
#[must_use]
pub fn crd()
-> k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition {
    let mut crd = AgentSandbox::crd();
    // kube-derive puts a placeholder here; the schema's own description is the type's. Set
    // before the copy, so both versions carry it.
    if let Some(schema) = crd.spec.versions[0]
        .schema
        .as_mut()
        .and_then(|s| s.open_api_v3_schema.as_mut())
    {
        schema.description = Some(
            "AgentSandbox is the record of one sandbox request (ADR-0008): mediatore creates and owns one VirtualMachineClaim for it, pins spec.subject to the caller at admission, and reports the claim's status plus whether the claim's registration entry is set."
                .into(),
        );
    }
    let mut alpha = crd.spec.versions[0].clone();
    alpha.name = DEPRECATED_VERSION.into();
    alpha.storage = false;
    alpha.deprecated = Some(true);
    alpha.deprecation_warning = Some(format!(
        "mediatore.io/{DEPRECATED_VERSION} AgentSandbox is deprecated; use {} (ADR-0049)",
        AgentSandbox::api_version(&())
    ));
    crd.spec.versions.insert(0, alpha);
    crd
}

/// The CRD as `deploy/base/crds/` carries it.
pub fn crd_yaml() -> Result<String, serde_saphyr::ser::Error> {
    let mut options = serde_saphyr::SerializerOptions::default();
    // Long descriptions stay on one line, as serde_yaml wrote them.
    options.folded_wrap_chars = 1 << 20;
    let mut crd = crd();
    crate::crd_formats::strip_unsupported_formats(&mut crd);
    let body = serde_saphyr::to_string_with_options(&crd, options)?;
    Ok(format!(
        "# Copyright (c) 2026 Erick Bourgeois, mediatore\n# SPDX-License-Identifier: Apache-2.0\n#\n# Generated from crates/mediatore-claims/src/sandbox.rs by `make crds` (ADR-0008\n# decision 1). Do not edit: the unit test `the_crd_in_deploy_is_what_the_type_renders`\n# fails on a stale file.\n{body}"
    ))
}

/// The one claim an `AgentSandbox` owns (decision 3): named after it, in its namespace,
/// labelled for the watcher, with a controller `ownerReference` back to it, and the spec
/// fields the claim carries copied over.
///
/// # Errors
/// When the sandbox has no UID (it was never persisted): no owner reference can name it.
pub fn claim_for(sb: &AgentSandbox) -> Result<VirtualMachineClaim, WatchError> {
    let mut owner = sb
        .controller_owner_ref(&())
        .ok_or_else(|| WatchError::Reconcile("sandbox has no uid".into()))?;
    // The claim cannot be garbage-collected from under a sandbox whose finalizer still
    // runs; the API server checks this against `agentsandboxes/finalizers` (RBAC).
    owner.block_owner_deletion = Some(true);
    let mut labels = BTreeMap::new();
    labels.insert(MANAGED_BY_LABEL.to_owned(), MANAGED_BY.to_owned());
    labels.insert(SANDBOX_UID_LABEL.to_owned(), owner.uid.clone());
    Ok(VirtualMachineClaim {
        metadata: ObjectMeta {
            name: Some(sb.name_any()),
            namespace: sb.namespace(),
            labels: Some(labels),
            owner_references: Some(vec![owner]),
            ..ObjectMeta::default()
        },
        spec: VirtualMachineClaimSpec {
            pool_ref: sb.spec.pool_ref.clone(),
            pool_selector: sb.spec.pool_selector.clone(),
            selection: sb.spec.selection.clone(),
            subject: ClaimSubject {
                issuer: sb.spec.subject.issuer.clone(),
                id: sb.spec.subject.id.clone(),
            },
            ttl_seconds: u64::from(sb.spec.ttl_seconds),
        },
        status: None,
    })
}

/// The sandbox's `metadata.uid` as a UUID.
#[must_use]
pub fn sandbox_uid_of(sb: &AgentSandbox) -> Option<Uuid> {
    sb.metadata
        .uid
        .as_deref()
        .and_then(|u| Uuid::parse_str(u).ok())
}

/// Which pool a spec asks for, for a log line (ADR-0044 decision 5): the name, or the
/// selector in `kubectl` spelling (`any pool` for `{}`). A spec with neither or both, which
/// the CRD's CEL rule refuses, is printed as such rather than guessed at.
#[must_use]
pub fn pool_of(spec: &AgentSandboxSpec) -> String {
    match (spec.pool_ref.as_ref(), spec.pool_selector.as_ref()) {
        (Some(r), None) => r.name.clone(),
        (None, Some(sel)) => PoolChoice::Selected(&pool_selector_of(sel)).to_string(),
        (None, None) => "<none>".into(),
        (Some(_), Some(_)) => "<both>".into(),
    }
}

/// Which strategy a spec asks for, for a log line (ADR-0047 decision 5): the value as
/// written, or `default` when absent (banlieue's `LongestReady`). Strategies are not secrets.
#[must_use]
pub fn strategy_of(spec: &AgentSandboxSpec) -> String {
    spec.selection
        .as_ref()
        .map_or_else(|| "default".to_owned(), |s| s.strategy.to_string())
}

/// banlieue's `ClaimSelection` from the request's (ADR-0047 decision 3): the same shape, the
/// same spelling.
#[must_use]
pub fn claim_selection_of(sel: &mediatore_proto::Selection) -> ClaimSelection {
    ClaimSelection {
        strategy: match sel.strategy {
            mediatore_proto::SelectionStrategy::LongestReady => SelectionStrategy::LongestReady,
            mediatore_proto::SelectionStrategy::MostAvailable => SelectionStrategy::MostAvailable,
            mediatore_proto::SelectionStrategy::Spread => SelectionStrategy::Spread,
        },
    }
}

/// The request's `Selection` from banlieue's, the other way.
#[must_use]
pub fn selection_of(sel: &ClaimSelection) -> mediatore_proto::Selection {
    mediatore_proto::Selection {
        strategy: match sel.strategy {
            SelectionStrategy::LongestReady => mediatore_proto::SelectionStrategy::LongestReady,
            SelectionStrategy::MostAvailable => mediatore_proto::SelectionStrategy::MostAvailable,
            SelectionStrategy::Spread => mediatore_proto::SelectionStrategy::Spread,
        },
    }
}

/// banlieue's `LabelSelector` from the request's (ADR-0044 decision 4): the same shape, field
/// by field.
#[must_use]
pub fn label_selector_of(sel: &PoolSelector) -> LabelSelector {
    LabelSelector {
        match_labels: sel.match_labels.clone(),
        match_expressions: sel
            .match_expressions
            .iter()
            .map(|r| LabelSelectorRequirement {
                key: r.key.clone(),
                operator: match r.operator {
                    PoolSelectorOperator::In => LabelSelectorOperator::In,
                    PoolSelectorOperator::NotIn => LabelSelectorOperator::NotIn,
                    PoolSelectorOperator::Exists => LabelSelectorOperator::Exists,
                    PoolSelectorOperator::DoesNotExist => LabelSelectorOperator::DoesNotExist,
                },
                values: r.values.clone(),
            })
            .collect(),
    }
}

/// The request's `PoolSelector` from banlieue's, the other way (for the log line and the API
/// answer).
#[must_use]
pub fn pool_selector_of(sel: &LabelSelector) -> PoolSelector {
    PoolSelector {
        match_labels: sel.match_labels.clone(),
        match_expressions: sel
            .match_expressions
            .iter()
            .map(|r| mediatore_proto::PoolSelectorRequirement {
                key: r.key.clone(),
                operator: match r.operator {
                    LabelSelectorOperator::In => PoolSelectorOperator::In,
                    LabelSelectorOperator::NotIn => PoolSelectorOperator::NotIn,
                    LabelSelectorOperator::Exists => PoolSelectorOperator::Exists,
                    LabelSelectorOperator::DoesNotExist => PoolSelectorOperator::DoesNotExist,
                },
                values: r.values.clone(),
            })
            .collect(),
    }
}

/// The store record for a sandbox whose claim has UID `claim_uid` (decision 12): the
/// request fields the sandbox API answers from, nothing bound yet; and, when the sandbox
/// names a policy with a verified `bundle`, the policy's uid and that bundle's version
/// (ADR-0026 decision 6), for the audit and for the comparison.
#[must_use]
pub fn record_for(
    sb: &AgentSandbox,
    claim_uid: Uuid,
    bundle: Option<&BundlePayload>,
) -> ClaimRecord {
    ClaimRecord {
        rendered: None,
        follow: None,
        uid: claim_uid,
        name: sb.name_any(),
        namespace: crate::kubestore::namespace_of(sb),
        subject: Subject::from(&sb.spec.subject),
        entry_id: None,
        node_id: None,
        audiences: sb.spec.audiences.clone(),
        workload: Workload::from(&sb.spec.workload),
        ttl_seconds: sb.spec.ttl_seconds,
        refresh: None,
        created_at: Timestamp::now(),
        expires_at: None,
        revoked_at: None,
        sandbox_uid: sandbox_uid_of(sb),
        policy_uid: bundle.map(|b| b.content.policy.uid.clone()),
        bundle_version: bundle.map(|b| b.meta.version),
        report: None,
        exit: None,
        delegations: std::collections::BTreeMap::new(),
        version: None,
    }
}

/// Whether `claim` is the one `sb` owns: a controller owner reference with the sandbox's
/// UID. A claim of the same name created by someone else is not ours to touch.
#[must_use]
pub fn owned_by(claim: &VirtualMachineClaim, sb: &AgentSandbox) -> bool {
    let Some(uid) = sb.uid() else {
        return false;
    };
    claim
        .owner_references()
        .iter()
        .any(|o| o.uid == uid && o.kind == AgentSandbox::kind(&()))
}

/// The status mirrored from the owned claim and the store record (decision 11).
#[must_use]
pub fn mirror_status(
    sb: &AgentSandbox,
    claim: &VirtualMachineClaim,
    record: &ClaimRecord,
) -> AgentSandboxStatus {
    let phase = if claim.metadata.deletion_timestamp.is_some() {
        SandboxPhase::Releasing
    } else {
        match phase_of(claim) {
            ClaimPhase::Pending => SandboxPhase::Pending,
            ClaimPhase::Bound => SandboxPhase::Bound,
            ClaimPhase::Releasing => SandboxPhase::Releasing,
            ClaimPhase::Failed => SandboxPhase::Failed,
        }
    };
    let st = claim.status.as_ref();
    let entry_set = record.entry_id.is_some() && record.revoked_at.is_none();
    AgentSandboxStatus {
        phase,
        claim_ref: Some(LocalObjectReference {
            name: claim.name_any(),
        }),
        claim_uid: Some(record.uid.to_string()),
        virtual_machine_ref: st.and_then(|s| s.virtual_machine_ref.clone()),
        pool_ref: st.and_then(|s| s.pool_ref.clone()),
        addresses: st
            .map(|s| s.addresses.iter().map(|a| a.address.clone()).collect())
            .unwrap_or_default(),
        bound_at: st.and_then(|s| s.bound_at.clone()),
        expires_at: st.and_then(|s| s.expires_at.clone()),
        entry_set,
        ready: phase == SandboxPhase::Bound && entry_set,
        reason: None,
        observed_generation: sb.metadata.generation,
        conditions: Vec::new(),
        record: None,
    }
}

/// What a pass got when it asked for the record of the sandbox's claim
/// ([`Watcher::record_of`]).
enum Recorded {
    /// The record: the one the store held, or the one this pass wrote.
    Record(Box<ClaimRecord>),
    /// Under `enforce`, the sandbox names a policy and a source of its namespace has not
    /// been read on this replica: nothing is written until it has (ADR-0054 decision 4).
    SourcesNotRead,
    /// Under `enforce`, the policy named does not resolve any more: no record, and the
    /// claim goes (ADR-0054 decision 4).
    PolicyNotResolved,
}

impl Watcher {
    /// Whether `policy.audiences` is `enforce` and there are bundles to enforce (ADR-0053
    /// decision 9).
    fn enforcing_audiences(&self) -> bool {
        self.cfg.audiences_mode == crate::policy::EgressMode::Enforce && self.bundles.is_some()
    }

    /// Under `enforce`, before the namespace's policy sources were listed a policy may simply not
    /// have been read yet: the sandbox is held, never failed for a policy it cannot yet be judged
    /// by (ADR-0053 decision 10). Its spec is immutable, so a failure here would be for good. Only
    /// the sandbox's own sources count (ADR-0054 decision 4): another namespace's unread source
    /// holds nothing here.
    fn awaiting_bundles(&self, sandbox: &str, namespace: &str) -> bool {
        let waiting = self.enforcing_audiences()
            && self.bundles.as_ref().is_some_and(|b| {
                !b.unread_sources(&self.cfg.policy_sources, namespace)
                    .is_empty()
            });
        if waiting {
            tracing::info!(%sandbox, %namespace, "policy bundles not all read yet; holding the sandbox (ADR-0053)");
        }
        waiting
    }

    /// ADR-0053 decision 10, the declarative path of `POST /v1/claims`'s checks: under `enforce` the
    /// sandbox names a policy that resolves to a verified, unexpired bundle granting every audience
    /// it asks for, and its lifetime fits the lease. An audience the bundle does not grant reads as
    /// one that is not configured, so a refusal tells the requester nothing about another policy.
    fn refuse_under_policy(&self, spec: &AgentSandboxSpec, namespace: &str) -> Option<String> {
        if !self.enforcing_audiences() {
            return None;
        }
        let Some(policy) = spec.policy_ref.as_ref() else {
            return Some(
                "policyRef is required: name the policy this sandbox is under (ADR-0053)".into(),
            );
        };
        // Resolved in the namespace's sources (ADR-0054), never across every watched namespace:
        // a grant comes only from a policy this namespace draws from. Unresolved reads as it
        // does under `policy.egress: enforce`, one sentence whether the name is nowhere, outside
        // the sources or held twice. Unread sources were held by `awaiting_bundles` before this.
        let resolution = self.bundles.as_ref()?.resolve(
            &self.cfg.policy_sources,
            namespace,
            &policy.name,
            Timestamp::now(),
        );
        let Resolution::Found(bundle) = resolution else {
            return Some(format!(
                "{POLICY_NOT_RESOLVED}: {}",
                not_resolved(&policy.name, namespace)
            ));
        };
        if let Some(a) = spec
            .audiences
            .iter()
            .find(|a| !self.cfg.grants(namespace, a, &bundle))
        {
            return Some(format!("audience {a} is not configured"));
        }
        if i64::from(spec.ttl_seconds) > i64::from(bundle.content.lease.max_duration_seconds) {
            return Some("ttlSeconds is above the policy's lease (ADR-0053)".into());
        }
        None
    }

    /// Why a spec is refused before any claim exists: an audience or an issuer mediatore
    /// is not configured for (decision 7; fail closed), a TTL the schema should have
    /// caught, or one above the broker's ceiling (decision 9, amended 2026-11-26).
    fn refuse(&self, spec: &AgentSandboxSpec, namespace: &str) -> Option<String> {
        if spec.ttl_seconds == 0 {
            return Some("ttlSeconds must be positive".into());
        }
        if let Some(a) = spec
            .audiences
            .iter()
            .find(|a| !self.cfg.usable(a, namespace))
        {
            // An audience this namespace may not use reads exactly as one that does not exist
            // (ADR-0053 decision 4).
            return Some(format!("audience {a} is not configured"));
        }
        if let Some(reason) = self.refuse_under_policy(spec, namespace) {
            return Some(reason);
        }
        // The broker's own ceiling (`sandboxes.max_ttl_seconds`), with or without a policy: the
        // lease checked just above only narrows it, so the bound is the smaller of the two.
        // Like every refusal here it is made before a claim exists and only then
        // (`refuse_before_the_claim`): a sandbox already bound under a higher ceiling is not
        // released when the key is lowered, it runs to the TTL it was admitted with.
        if spec.ttl_seconds > self.cfg.max_ttl_seconds {
            return Some(ttl_above_maximum(self.cfg.max_ttl_seconds));
        }
        if !self.cfg.issuers.iter().any(|i| i == &spec.subject.issuer) {
            return Some(format!("issuer {} is not configured", spec.subject.issuer));
        }
        // The requester asked for the workload's output and this broker stores none (ADR-0045
        // decision 11): a claim that ran with its output dropped would be a silent no.
        if spec.workload.logs && !self.cfg.logs_enabled {
            return Some("workload.logs: output capture is not enabled on this broker".into());
        }
        // The guest would refuse the image at bind (ADR-0021), and a gateway-era pool
        // reaches its declared registries and no other (ADR-0029): say so here.
        match spec
            .workload
            .image
            .parse::<mediatore_proto::image::ImageReference>()
        {
            Err(e) => return Some(format!("workload image {:?}: {e}", spec.workload.image)),
            Ok(image) => {
                if let Some(reason) = mediatore_proto::image::ungranted_registry(
                    self.cfg.registry_audiences.as_ref(),
                    &spec.audiences,
                    &image,
                ) {
                    return Some(reason);
                }
                // A registry the gateway places a credential for serves a claim that names its audience (ADR-0043
                // decision 1); without it the pull would be anonymous and fail later, so say so now.
                if let Some(audience) = self.cfg.placed_registries.get(&image.registry)
                    && !spec.audiences.contains(audience)
                {
                    return Some(format!(
                        "registry {} is served from your own credential: name audience {audience} and delegate it with the claim (ADR-0043)",
                        image.registry
                    ));
                }
            }
        }
        None
    }

    /// Patch the status when it differs from what the object carries.
    async fn mirror(
        &self,
        sb: &AgentSandbox,
        status: AgentSandboxStatus,
    ) -> Result<(), WatchError> {
        // The record is the store's (ADR-0034): compared and patched without it.
        let mut status = status;
        status.record = None;
        let current = sb.status.clone().map(|mut s| {
            s.record = None;
            s
        });
        if current.as_ref() == Some(&status) {
            return Ok(());
        }
        let name = sb.name_any();
        let namespace = sb.namespace().unwrap_or_default();
        tracing::debug!(sandbox = %name, %namespace, phase = ?status.phase, ready = status.ready, "sandbox status");
        self.claims
            .patch_sandbox_status(&namespace, &name, &status)
            .await
    }

    /// One pass over a sandbox. Idempotent; the finalizer, the claim, the record and the
    /// status each converge on their own.
    pub async fn reconcile_sandbox(&self, sb: &AgentSandbox) -> Result<Action, WatchError> {
        let name = sb.name_any();
        let namespace = sb.namespace().unwrap_or_default();
        if sb.metadata.deletion_timestamp.is_some() {
            return self.finalize_sandbox(sb).await;
        }
        if !sb.finalizers().iter().any(|f| f == FINALIZER) {
            // The patch raises the event that runs the next pass.
            self.claims.set_sandbox_finalizer(sb, true).await?;
            return Ok(Action::await_change());
        }
        let current = sb.status.clone().unwrap_or_default();
        if let Some(refused) = self.refuse_before_the_claim(sb, &current).await? {
            return Ok(refused);
        }
        let claim = match self.claims.get_claim(&namespace, &name).await? {
            Some(claim) if owned_by(&claim, sb) => claim,
            Some(_) => {
                let reason = format!("claim {name} exists and is not owned by this sandbox");
                tracing::warn!(sandbox = %name, %namespace, "{reason}");
                self.mirror(
                    sb,
                    AgentSandboxStatus {
                        phase: SandboxPhase::Failed,
                        reason: Some(reason),
                        observed_generation: sb.metadata.generation,
                        conditions: self.conditions(sb, &current.conditions),
                        ..current
                    },
                )
                .await?;
                return Ok(Action::await_change());
            }
            None if current.claim_ref.is_some() => {
                // Created once, gone now (expired and destroyed, or failed by the watcher):
                // a sandbox never gets a second VM.
                if current.phase != SandboxPhase::Failed {
                    tracing::info!(sandbox = %name, %namespace, "claim gone; sandbox failed, never recreated");
                }
                self.mirror(
                    sb,
                    AgentSandboxStatus {
                        phase: SandboxPhase::Failed,
                        entry_set: false,
                        ready: false,
                        reason: current.reason.clone().or_else(|| Some("claim gone".into())),
                        observed_generation: sb.metadata.generation,
                        conditions: self.conditions(sb, &current.conditions),
                        ..current
                    },
                )
                .await?;
                return Ok(Action::await_change());
            }
            None => {
                let created = self.claims.create_claim(claim_for(sb)?).await?;
                tracing::info!(sandbox = %name, %namespace, subject = %sb.spec.subject.id, pool = %pool_of(&sb.spec), strategy = %strategy_of(&sb.spec), "claim created");
                created
            }
        };
        let Some(uid) = claim_uid_of(&claim) else {
            tracing::warn!(sandbox = %name, %namespace, "owned claim without a UUID uid; held");
            return Ok(Action::await_change());
        };
        let record = match self.record_of(sb, uid).await? {
            Recorded::Record(record) => *record,
            Recorded::SourcesNotRead => return self.hold_until_read(sb, &current).await,
            Recorded::PolicyNotResolved => return self.refuse_policy(sb, &current).await,
        };
        if let Some(refused) = self
            .refuse_without_delegation(sb, &claim, &record, &current)
            .await?
        {
            return Ok(refused);
        }
        let mut status = mirror_status(sb, &claim, &record);
        status.conditions = followed(
            self.conditions(sb, &current.conditions),
            &record,
            sb.metadata.generation,
        );
        // The entry is set (on Bound) or retracted (on Releasing / Failed) by the claim
        // watcher and recorded in the store, which raises no event here: poll until the
        // status agrees with the record, or until the watcher fails the claim.
        let settling = match status.phase {
            SandboxPhase::Bound => !status.entry_set,
            SandboxPhase::Releasing | SandboxPhase::Failed => status.entry_set,
            SandboxPhase::Pending => false,
        };
        self.mirror(sb, status).await?;
        if settling {
            Ok(Action::requeue(self.cfg.requeue))
        } else {
            Ok(Action::await_change())
        }
    }

    /// The refusals that come before the claim is looked at: a record that is not the
    /// sandbox's own ([`Self::refuse_foreign_record`]), then a spec this broker does not serve
    /// ([`Self::refuse`]), then a policy that does not resolve in the namespace's sources
    /// ([`Self::refuse_unresolved_policy`], ADR-0054 decision 4). `Some` is the pass's answer.
    async fn refuse_before_the_claim(
        &self,
        sb: &AgentSandbox,
        current: &AgentSandboxStatus,
    ) -> Result<Option<Action>, WatchError> {
        if let Some(refused) = self.refuse_foreign_record(sb, current).await? {
            return Ok(Some(refused));
        }
        // Refused before any claim exists, and only then: once a claim was created the
        // request was accepted under the configuration of that moment, and a later config
        // change must not flap a bound sandbox between Failed and its mirrored status.
        if current.claim_ref.is_some() {
            return Ok(None);
        }
        let namespace = sb.namespace().unwrap_or_default();
        if self.awaiting_bundles(&sb.name_any(), &namespace) {
            return Ok(Some(Action::requeue(self.cfg.requeue)));
        }
        if self.cfg.audiences_unread(&namespace) {
            tracing::info!(sandbox = %sb.name_any(), %namespace, "audience definitions not all read yet; holding the sandbox (ADR-0055)");
            return Ok(Some(Action::requeue(self.cfg.requeue)));
        }
        let Some(reason) = self.refuse(&sb.spec, &namespace) else {
            return self.refuse_unresolved_policy(sb, current).await;
        };
        tracing::warn!(sandbox = %sb.name_any(), %namespace, %reason, "sandbox refused; no claim created");
        self.drop_session(sb).await?;
        self.mirror(
            sb,
            AgentSandboxStatus {
                phase: SandboxPhase::Failed,
                reason: Some(reason),
                observed_generation: sb.metadata.generation,
                conditions: self.conditions(sb, &current.conditions),
                ..AgentSandboxStatus::default()
            },
        )
        .await?;
        Ok(Some(Action::await_change()))
    }

    /// ADR-0057 decision 7: a sandbox whose `status.record` names another sandbox (a status
    /// carried onto this object by a restore or a copied manifest), or only half of one, has
    /// no record and gets none. The store would refuse the write with a `Conflict` on every
    /// pass, so the refusal is made here, before anything is consumed: no record is written,
    /// the parked session is not taken, the owned claim is deleted if there is one, and the
    /// sandbox is `Failed`. Settled after that: a pass that finds no claim deletes nothing
    /// and patches nothing. A record from before the ADR (neither field) and the sandbox's
    /// own are not refused.
    async fn refuse_foreign_record(
        &self,
        sb: &AgentSandbox,
        current: &AgentSandboxStatus,
    ) -> Result<Option<Action>, WatchError> {
        if !crate::kubestore::carries_foreign_record(sb) {
            return Ok(None);
        }
        let name = sb.name_any();
        let namespace = sb.namespace().unwrap_or_default();
        let reason = format!(
            "{RECORD_NOT_OWN}: status.record names another sandbox (ADR-0057 decision 7); no record is written for this one and its claim is deleted, never recreated"
        );
        // Said once: the status patch below raises the event of the next pass.
        if current.phase != SandboxPhase::Failed || current.reason.as_ref() != Some(&reason) {
            tracing::warn!(
                sandbox = %name,
                %namespace,
                sandbox_uid = sb.metadata.uid.as_deref().unwrap_or("-"),
                record_sandbox_uid = current
                    .record
                    .as_ref()
                    .and_then(|r| r.sandbox_uid.as_deref())
                    .unwrap_or("-"),
                "sandbox refused: its status.record names another sandbox; no record written, no session taken"
            );
        }
        // The claim stays named once it was seen, so that a status later rid of the foreign
        // record meets "claim gone" and never a second VM.
        let mut claim_ref = current.claim_ref.clone();
        if let Some(claim) = self.claims.get_claim(&namespace, &name).await?
            && owned_by(&claim, sb)
        {
            // One held by banlieue's finalizer is already going: deleted once.
            if claim.metadata.deletion_timestamp.is_none() {
                self.claims.delete_claim(&namespace, &name).await?;
                tracing::info!(sandbox = %name, %namespace, "claim of a sandbox whose record is not its own deleted");
            }
            if claim_ref.is_none() {
                claim_ref = Some(LocalObjectReference {
                    name: claim.name_any(),
                });
            }
        }
        self.mirror(
            sb,
            AgentSandboxStatus {
                phase: SandboxPhase::Failed,
                claim_ref,
                entry_set: false,
                ready: false,
                reason: Some(reason),
                observed_generation: sb.metadata.generation,
                conditions: self.conditions(sb, &current.conditions),
                ..current.clone()
            },
        )
        .await?;
        Ok(Some(Action::await_change()))
    }

    /// What the sandbox's `policyRef` comes to in the sources of its own namespace (ADR-0054
    /// decision 1, amending ADR-0026 decision 6): `None` when it names no policy or the broker
    /// reads no bundle. The one caller of [`BundleCache::resolve`] on the creation side; the
    /// namespace is the one the record carries, which is what the serving check compares.
    fn bundle_of(&self, sb: &AgentSandbox) -> Option<Resolution> {
        let policy = sb.spec.policy_ref.as_ref()?;
        Some(self.bundles.as_ref()?.resolve(
            &self.cfg.policy_sources,
            &crate::kubestore::namespace_of(sb),
            &policy.name,
            Timestamp::now(),
        ))
    }

    /// ADR-0054 decision 4, before any claim exists. Under `enforce` a sandbox naming a policy
    /// that does not resolve in its namespace's sources is refused (never created without a
    /// policy), and one whose sources are unread is held. Under `shadow` nothing is refused:
    /// the verdict reports it (decision 5). A sandbox that names no policy, and a broker that
    /// reads no bundle, are untouched. A sandbox whose claim already has its record was
    /// admitted by an earlier pass and is not judged again.
    async fn refuse_unresolved_policy(
        &self,
        sb: &AgentSandbox,
        current: &AgentSandboxStatus,
    ) -> Result<Option<Action>, WatchError> {
        let Some(resolution) = self.bundle_of(sb) else {
            return Ok(None);
        };
        let enforcing = self.cfg.egress_mode == EgressMode::Enforce;
        if matches!(resolution, Resolution::Found(_)) {
            return Ok(None);
        }
        if matches!(resolution, Resolution::NotFound) {
            self.say_where_the_policy_is(sb, current);
        }
        // Shadow refuses and holds nothing; the verdict carries P011, P012 or Unknown.
        if !enforcing || self.recorded_already(sb).await? {
            return Ok(None);
        }
        if matches!(resolution, Resolution::NotRead) {
            return self.hold_until_read(sb, current).await.map(Some);
        }
        self.refuse_policy(sb, current).await.map(Some)
    }

    /// Whether the sandbox's owned claim exists and its record was written: the request was
    /// admitted by a pass whose status patch never landed, and it is past the refusals that
    /// come before a claim.
    async fn recorded_already(&self, sb: &AgentSandbox) -> Result<bool, WatchError> {
        let namespace = sb.namespace().unwrap_or_default();
        let Some(claim) = self.claims.get_claim(&namespace, &sb.name_any()).await? else {
            return Ok(false);
        };
        let Some(uid) = claim_uid_of(&claim).filter(|_| owned_by(&claim, sb)) else {
            return Ok(false);
        };
        match self.reconciler.store.get_claim(uid).await {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// The operator's line of ADR-0054 decision 4: the policy named is held by a watched
    /// namespace this sandbox's namespace does not draw from. The broker's own log only (the
    /// requester's answer never says where else a name exists), in both modes, and once: a
    /// sandbox already failed for it is not said again.
    fn say_where_the_policy_is(&self, sb: &AgentSandbox, current: &AgentSandboxStatus) {
        let (Some(bundles), Some(policy)) = (self.bundles.as_ref(), sb.spec.policy_ref.as_ref())
        else {
            return;
        };
        if current.phase == SandboxPhase::Failed {
            return;
        }
        let namespace = crate::kubestore::namespace_of(sb);
        let outside = bundles.held_outside(
            &self.cfg.policy_sources,
            &namespace,
            &policy.name,
            Timestamp::now(),
        );
        if outside.is_empty() {
            return;
        }
        tracing::warn!(
            sandbox = %sb.name_any(),
            %namespace,
            policy = %policy.name,
            held_in = %outside.join(", "),
            sources = %self.cfg.policy_sources.sources_of(&namespace).join(", "),
            mode = %self.cfg.egress_mode,
            "policy held by a watched namespace outside this sandbox's sources: add a policy.sources entry for the sandbox's namespace if it is meant to draw from there (ADR-0054)"
        );
    }

    /// Hold a sandbox whose namespace's sources are unread (ADR-0054 decision 4): the verdict
    /// says `Unknown`/`BundlesNotRead`, nothing is created or written, and the pass comes
    /// back, since the first list of a namespace raises no event here.
    async fn hold_until_read(
        &self,
        sb: &AgentSandbox,
        current: &AgentSandboxStatus,
    ) -> Result<Action, WatchError> {
        self.mirror(
            sb,
            AgentSandboxStatus {
                observed_generation: sb.metadata.generation,
                conditions: self.conditions(sb, &current.conditions),
                ..current.clone()
            },
        )
        .await?;
        Ok(Action::requeue(self.cfg.requeue))
    }

    /// Refuse a sandbox whose policy does not resolve, under `enforce` (ADR-0054 decision 4):
    /// `Failed` with one reason whether the policy is nowhere, in a namespace this one does
    /// not draw from, or held twice; no record, the parked session dropped, and a claim an
    /// earlier pass created deleted before it binds a member, never recreated (the shape of
    /// [`Self::refuse_without_delegation`]). Settled after that: a pass that finds no claim
    /// deletes nothing and patches nothing.
    async fn refuse_policy(
        &self,
        sb: &AgentSandbox,
        current: &AgentSandboxStatus,
    ) -> Result<Action, WatchError> {
        let name = sb.name_any();
        let namespace = sb.namespace().unwrap_or_default();
        let policy = sb
            .spec
            .policy_ref
            .as_ref()
            .map_or("none", |p| p.name.as_str());
        let reason = format!(
            "{POLICY_NOT_RESOLVED}: {}",
            not_resolved(policy, &crate::kubestore::namespace_of(sb))
        );
        // Said once: the status patch below raises the event of the next pass.
        if current.phase != SandboxPhase::Failed || current.reason.as_ref() != Some(&reason) {
            tracing::warn!(sandbox = %name, %namespace, policy, %reason, "sandbox refused; no record written");
        }
        self.drop_session(sb).await?;
        // The claim stays named once it was seen, so that a later pass meets "claim gone"
        // and never creates a second one.
        let mut claim_ref = current.claim_ref.clone();
        if let Some(claim) = self.claims.get_claim(&namespace, &name).await?
            && owned_by(&claim, sb)
        {
            // One held by banlieue's finalizer is already going: deleted once.
            if claim.metadata.deletion_timestamp.is_none() {
                self.claims.delete_claim(&namespace, &name).await?;
                tracing::info!(sandbox = %name, %namespace, "claim of a sandbox whose policy does not resolve deleted");
            }
            if claim_ref.is_none() {
                claim_ref = Some(LocalObjectReference {
                    name: claim.name_any(),
                });
            }
        }
        self.mirror(
            sb,
            AgentSandboxStatus {
                phase: SandboxPhase::Failed,
                claim_ref,
                reason: Some(reason),
                observed_generation: sb.metadata.generation,
                conditions: self.conditions(sb, &current.conditions),
                ..AgentSandboxStatus::default()
            },
        )
        .await?;
        Ok(Action::await_change())
    }

    /// The sandbox's conditions after this pass: `previous` with `PolicyConformant` replaced
    /// by the comparison's verdict (ADR-0026 decision 7), or untouched without a `policy`
    /// section. Computed on every pass, a terminal sandbox's included: the verdict is about
    /// the spec and the bundle, not the claim. `lastTransitionTime` holds while the status
    /// does.
    fn conditions(&self, sb: &AgentSandbox, previous: &[Condition]) -> Vec<Condition> {
        let Some(bundles) = self.bundles.as_ref() else {
            return previous.to_vec();
        };
        let held = previous.iter().find(|c| c.type_ == POLICY_CONFORMANT);
        let (status, reason, message) = self.verdict(sb, bundles, held);
        let last_transition_time = held.filter(|c| c.status == status).map_or_else(
            || Time(k8s_openapi::jiff::Timestamp::now()),
            |c| c.last_transition_time.clone(),
        );
        let mut out: Vec<Condition> = previous
            .iter()
            .filter(|c| c.type_ != POLICY_CONFORMANT)
            .cloned()
            .collect();
        out.push(Condition {
            type_: POLICY_CONFORMANT.into(),
            status: status.into(),
            reason: reason.into(),
            message,
            observed_generation: sb.metadata.generation,
            last_transition_time,
        });
        out
    }

    /// The status, reason and message of `PolicyConformant` for this pass. The policy is
    /// resolved in the sandbox's sources (ADR-0054): `Unknown` only while one of those is
    /// unread, whatever the other watched namespaces are doing; `P011` for a name no source
    /// holds and `P012` for one two hold, each alone; otherwise the comparison with the
    /// bundle found. Each gap is logged when the verdict's message changes: a new bundle, a
    /// new gap, a gap closed.
    fn verdict(
        &self,
        sb: &AgentSandbox,
        bundles: &BundleCache,
        held: Option<&Condition>,
    ) -> (&'static str, &'static str, String) {
        let name = sb.name_any();
        let namespace = crate::kubestore::namespace_of(sb);
        let policy = sb
            .spec
            .policy_ref
            .as_ref()
            .map_or("none", |p| p.name.as_str());
        let resolution = self.bundle_of(sb);
        if matches!(resolution, Some(Resolution::NotRead)) {
            let unread = bundles.unread_sources(&self.cfg.policy_sources, &namespace);
            return (
                "Unknown",
                "BundlesNotRead",
                format!("no bundle has been read from {} yet", unread.join(", ")),
            );
        }
        let bundle = resolution.as_ref().and_then(Resolution::found);
        let version = bundle.map(|b| b.meta.version);
        let findings = if matches!(resolution, Some(Resolution::Ambiguous)) {
            vec![shadow::ambiguous(policy)]
        } else {
            shadow::compare_with(
                &sb.spec,
                &self.cfg.audiences_in(&namespace),
                bundle.map(Arc::as_ref),
                self.cfg.egress_mode,
            )
        };
        if findings.is_empty() {
            return (
                "True",
                "Conformant",
                format!(
                    "the broker allows nothing bundle v{} of {policy} does not",
                    version.unwrap_or_default()
                ),
            );
        }
        let message = findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        if held.map(|c| c.message.as_str()) != Some(message.as_str()) {
            for f in &findings {
                tracing::warn!(sandbox = %name, %namespace, policy, bundle_version = ?version, code = %f.code, "policy gap: {}", f.detail);
            }
        }
        ("False", "Gaps", message)
    }

    /// The record for the sandbox's claim, created on first sight. ADR-0013 decision 2:
    /// the delegated session the API parked under the sandbox's UID becomes the record's
    /// envelope, taken once.
    ///
    /// ADR-0054 decision 4: the record is written from the resolution made here. Under
    /// `enforce` a record for a sandbox that names a policy always carries its `policy_uid`:
    /// while the namespace's sources are unread nothing is written, and a name that no longer
    /// resolves (the bundle expired or was dropped since the claim was created) writes
    /// nothing either. Under `shadow` the record is written as before, without a
    /// `policy_uid` when the name does not resolve. An existing record is never rewritten.
    async fn record_of(&self, sb: &AgentSandbox, uid: Uuid) -> Result<Recorded, WatchError> {
        match self.reconciler.store.get_claim(uid).await {
            Ok(r) => Ok(Recorded::Record(Box::new(r))),
            Err(StoreError::NotFound(_)) => {
                let resolution = self.bundle_of(sb);
                if self.cfg.egress_mode == EgressMode::Enforce {
                    match &resolution {
                        Some(Resolution::NotRead) => return Ok(Recorded::SourcesNotRead),
                        Some(Resolution::NotFound | Resolution::Ambiguous) => {
                            return Ok(Recorded::PolicyNotResolved);
                        }
                        Some(Resolution::Found(_)) | None => {}
                    }
                }
                let bundle = resolution.as_ref().and_then(Resolution::found);
                let mut r = record_for(sb, uid, bundle.map(Arc::as_ref));
                if let Some(sandbox_uid) = r.sandbox_uid {
                    if let Some(session) = self.reconciler.store.take_session(sandbox_uid).await? {
                        r.refresh = Some(session.refresh);
                    }
                    // ADR-0035: the caller's delegated credentials, one per audience.
                    for d in self.reconciler.store.take_delegations(sandbox_uid).await? {
                        if let Some(audience) = d.audience {
                            r.delegations.insert(
                                audience,
                                mediatore_store::DelegatedSession {
                                    envelope: d.refresh,
                                    expires_at: d.expires_at,
                                },
                            );
                        }
                    }
                }
                let delegated = r.refresh.is_some();
                let delegations = r.delegations.len();
                self.reconciler.store.put_claim(r.clone()).await?;
                tracing::info!(
                    sandbox = %sb.name_any(),
                    namespace = %sb.namespace().unwrap_or_default(),
                    claim_uid = %uid,
                    delegated,
                    delegations,
                    policy = sb.spec.policy_ref.as_ref().map_or("none", |p| p.name.as_str()),
                    bundle_version = ?r.bundle_version,
                    "record created"
                );
                Ok(Recorded::Record(Box::new(r)))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// ADR-0035: a sandbox under a delegated audience runs on the requester's own
    /// credential and nothing else. One whose delegation never reached the record (swept
    /// after its hour, or never sent) would bind a VM to run with nothing to place: refused
    /// here, the claim deleted before a member is consumed, never recreated.
    async fn refuse_without_delegation(
        &self,
        sb: &AgentSandbox,
        claim: &VirtualMachineClaim,
        record: &ClaimRecord,
        current: &AgentSandboxStatus,
    ) -> Result<Option<Action>, WatchError> {
        let Some(audience) = self.delegation_missing(sb, record) else {
            return Ok(None);
        };
        let name = sb.name_any();
        let namespace = sb.namespace().unwrap_or_default();
        let reason = format!(
            "delegation_required: no delegated credential for {audience} reached the record (parked for over an hour before the claim could bind, or never sent)"
        );
        tracing::warn!(sandbox = %name, %namespace, claim_uid = %record.uid, %audience, "sandbox refused: its delegated credential is gone; claim deleted");
        self.reconciler.release(record.uid).await?;
        self.claims.delete_claim(&namespace, &name).await?;
        let mut status = mirror_status(sb, claim, record);
        status.phase = SandboxPhase::Failed;
        status.entry_set = false;
        status.ready = false;
        status.reason = Some(reason);
        status.conditions = self.conditions(sb, &current.conditions);
        self.mirror(sb, status).await?;
        Ok(Some(Action::await_change()))
    }

    /// The first audience of the sandbox served from a delegated credential (ADR-0035)
    /// that the record holds no delegation for.
    fn delegation_missing(&self, sb: &AgentSandbox, record: &ClaimRecord) -> Option<String> {
        let namespace = sb.namespace().unwrap_or_default();
        sb.spec
            .audiences
            .iter()
            .find(|a| self.cfg.is_delegated(a, &namespace) && !record.delegations.contains_key(*a))
            .cloned()
    }

    /// A parked session the sandbox will never consume (refused, or going away).
    async fn drop_session(&self, sb: &AgentSandbox) -> Result<(), WatchError> {
        if let Some(uid) = sandbox_uid_of(sb) {
            self.reconciler.store.delete_session(uid).await?;
        }
        Ok(())
    }

    /// Decision 10, on a sandbox being deleted: release the record (entry first), delete
    /// the claim, and drop the finalizer only on a pass that finds no claim.
    async fn finalize_sandbox(&self, sb: &AgentSandbox) -> Result<Action, WatchError> {
        let name = sb.name_any();
        let namespace = sb.namespace().unwrap_or_default();
        if !sb.finalizers().iter().any(|f| f == FINALIZER) {
            return Ok(Action::await_change());
        }
        match self.claims.get_claim(&namespace, &name).await? {
            Some(claim) if owned_by(&claim, sb) => {
                if let Some(uid) = claim_uid_of(&claim) {
                    self.reconciler.release(uid).await?;
                }
                if claim.metadata.deletion_timestamp.is_none() {
                    self.claims.delete_claim(&namespace, &name).await?;
                    tracing::info!(sandbox = %name, %namespace, "sandbox deleting: record released, claim deleted");
                }
                // The claim's own deletion event comes back through `owns`; this covers a
                // claim held by banlieue's finalizer while the member is destroyed.
                Ok(Action::requeue(self.cfg.requeue))
            }
            Some(_) | None => {
                // Nothing of ours remains, or a claim we never owned. A record written for
                // a claim that banlieue already deleted is released here, when it is this
                // sandbox's own; idempotent.
                if let Some(uid) = sb
                    .status
                    .as_ref()
                    .and_then(|s| s.claim_uid.as_deref())
                    .and_then(|u| Uuid::parse_str(u).ok())
                {
                    // The status is not proof of whose claim that is: the store finds a
                    // record by claim UID wherever its sandbox lives, so a status naming
                    // another sandbox's claim would release that one. Only a record
                    // written for this very sandbox is released here.
                    let own = sandbox_uid_of(sb);
                    match self.reconciler.store.get_claim(uid).await {
                        Ok(rec) if own.is_some() && rec.sandbox_uid == own => {
                            self.reconciler.release(uid).await?;
                        }
                        Ok(_) => {
                            tracing::warn!(sandbox = %name, %namespace, claim_uid = %uid, "sandbox status names a claim whose record is another sandbox's; not released");
                        }
                        Err(StoreError::NotFound(_)) => {}
                        Err(e) => return Err(e.into()),
                    }
                    // ADR-0034 decision 4: a sandbox that had a record keeps its finalizer
                    // for the retention window; the store's sweep releases it, with the
                    // audit line. One that was never bound goes now.
                    if crate::kubestore::record_status_of(sb).is_some() {
                        tracing::info!(sandbox = %name, %namespace, "sandbox released; held for the retention window");
                        return Ok(Action::await_change());
                    }
                }
                self.drop_session(sb).await?;
                self.claims.set_sandbox_finalizer(sb, false).await?;
                tracing::info!(sandbox = %name, %namespace, "sandbox released");
                Ok(Action::await_change())
            }
        }
    }
}

/// Why the user API could not act on a sandbox.
#[derive(Debug, thiserror::Error)]
pub enum FrontDoorError {
    /// A sandbox of that name already exists.
    #[error("conflict: {0}")]
    Conflict(String),
    /// Admission or RBAC refused the request.
    #[error("denied: {0}")]
    Denied(String),
    /// The request was malformed for the API server (schema).
    #[error("invalid: {0}")]
    Invalid(String),
    /// Anything else.
    #[error("kubernetes api: {0}")]
    Api(String),
}

/// What `POST/GET/DELETE /v1/claims` does to `AgentSandbox` resources (decision 4),
/// behind a trait so the handlers are tested without a cluster.
#[async_trait]
pub trait SandboxFrontDoor: Send + Sync + 'static {
    /// Create; a name in use is a conflict.
    async fn create(&self, sandbox: AgentSandbox) -> Result<AgentSandbox, FrontDoorError>;
    /// Fetch one, if it exists.
    async fn get(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<AgentSandbox>, FrontDoorError>;
    /// Delete; the finalizer does the rest. One already gone is success.
    async fn delete(&self, namespace: &str, name: &str) -> Result<(), FrontDoorError>;
}

/// The real thing, as the broker `ServiceAccount`.
pub struct KubeSandboxes {
    client: Client,
}

impl KubeSandboxes {
    /// Over this client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    fn api(&self, namespace: &str) -> Api<AgentSandbox> {
        Api::namespaced(self.client.clone(), namespace)
    }
}

fn front_door_error(e: kube::Error) -> FrontDoorError {
    match e {
        kube::Error::Api(ref a) if a.code == 409 => FrontDoorError::Conflict(a.message.clone()),
        kube::Error::Api(ref a) if a.code == 403 => FrontDoorError::Denied(a.message.clone()),
        kube::Error::Api(ref a) if a.code == 422 || a.code == 400 => {
            FrontDoorError::Invalid(a.message.clone())
        }
        other => FrontDoorError::Api(other.to_string()),
    }
}

#[async_trait]
impl SandboxFrontDoor for KubeSandboxes {
    async fn create(&self, sandbox: AgentSandbox) -> Result<AgentSandbox, FrontDoorError> {
        let namespace = sandbox.namespace().unwrap_or_default();
        self.api(&namespace)
            .create(&PostParams::default(), &sandbox)
            .await
            .map_err(front_door_error)
    }

    async fn get(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<AgentSandbox>, FrontDoorError> {
        self.api(namespace)
            .get_opt(name)
            .await
            .map_err(front_door_error)
    }

    async fn delete(&self, namespace: &str, name: &str) -> Result<(), FrontDoorError> {
        match self
            .api(namespace)
            .delete(name, &DeleteParams::default())
            .await
        {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(front_door_error(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use mediatore_spire::claim_entry_name;
    use mediatore_store::ClaimStore;
    use mediatore_testkit::ek::{RSA_EK_HASH, RSA_EK_PEM};
    use serde_json::json;

    use super::*;
    use crate::Reconciler;
    use crate::fakes::{FakeClaims, Rig, node, rig, rig_with};
    use crate::policy::{BundleCache, BundleReflector, Outcome};
    use crate::shadow::Audience;
    use crate::watch::WatcherConfig;

    const ISSUER: &str = "https://issuer.example.com";
    const SB_UID: &str = "9c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f";

    fn cfg() -> WatcherConfig {
        WatcherConfig {
            requeue: Duration::from_millis(5),
            audiences: vec![Audience::named("api.example")],
            issuers: vec![ISSUER.into()],
            ..WatcherConfig::default()
        }
    }

    /// The broker configured for `internal-git` exactly as the conformance bundle allows
    /// it, beside the test's own `api.example`.
    fn cfg_with_git() -> WatcherConfig {
        WatcherConfig {
            audiences: vec![
                Audience::named("api.example"),
                Audience {
                    name: "internal-git".into(),
                    max_ttl: 300,
                    egress: vec!["git.foo.io:443".parse().unwrap()],
                    rules: vec![mediatore_proto::EndpointRule {
                        method: "GET".into(),
                        path: "/repos/**".into(),
                    }],
                },
            ],
            ..cfg()
        }
    }

    fn conformant(sb: &AgentSandbox) -> &Condition {
        sb.status
            .as_ref()
            .and_then(|s| s.conditions.iter().find(|c| c.type_ == POLICY_CONFORMANT))
            .expect("a PolicyConformant condition")
    }

    fn sandbox(finalized: bool, deleting: bool) -> AgentSandbox {
        let mut sb = AgentSandbox::new(
            "sb-1",
            AgentSandboxSpec {
                subject: SandboxSubject {
                    issuer: ISSUER.into(),
                    id: "octocat".into(),
                    display: Some("The Octocat".into()),
                },
                pool_ref: Some(LocalObjectReference {
                    name: "pool".into(),
                }),
                pool_selector: None,
                selection: None,
                ttl_seconds: 600,
                audiences: vec!["api.example".into()],
                workload: SandboxWorkload {
                    image: "ghcr.io/example/workload:1".into(),
                    args: vec!["sh".into()],
                    restart: None,
                    logs: false,
                },
                policy_ref: None,
            },
        );
        sb.metadata.namespace = Some("sandboxes".into());
        sb.metadata.uid = Some(SB_UID.into());
        sb.metadata.generation = Some(1);
        if finalized {
            sb.metadata.finalizers = Some(vec![FINALIZER.into()]);
        }
        if deleting {
            sb.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH));
        }
        sb
    }

    /// Drive the sandbox through the fake until it is stable: the finalizer pass, then the
    /// claim-and-record pass. Returns the object as the fake now holds it.
    async fn settle(r: &Rig, sb: &AgentSandbox) -> AgentSandbox {
        r.claims.put_sandbox(sb.clone());
        let mut cur = sb.clone();
        for _ in 0..4 {
            r.watcher.reconcile_sandbox(&cur).await.unwrap();
            let next = r
                .claims
                .sandbox("sandboxes", "sb-1")
                .unwrap_or_else(|| cur.clone());
            if next == cur {
                break;
            }
            cur = next;
        }
        cur
    }

    fn parked_session() -> mediatore_store::SessionRecord {
        mediatore_store::SessionRecord {
            sandbox_uid: Uuid::parse_str(SB_UID).unwrap(),
            subject: Subject {
                issuer: ISSUER.into(),
                id: "octocat".into(),
                display: None,
            },
            issuer: ISSUER.into(),
            refresh: mediatore_store::Sealed {
                key_id: "k".into(),
                nonce: vec![0; 12],
                ciphertext: vec![1, 2, 3],
                format: mediatore_store::seal::FORMAT_SLOT,
            },
            created_at: Timestamp::now(),
            audience: None,
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn a_parked_session_follows_the_claim_into_the_record_once() {
        let r = rig(cfg());
        r.store.put_session(parked_session()).await.unwrap();
        settle(&r, &sandbox(false, false)).await;
        let claim = r.claims.claim("sandboxes", "sb-1").expect("claim created");
        let uid = claim_uid_of(&claim).unwrap();
        let rec = r.store.get_claim(uid).await.unwrap();
        assert_eq!(rec.sandbox_uid, Some(Uuid::parse_str(SB_UID).unwrap()));
        assert_eq!(rec.refresh, Some(parked_session().refresh));
        assert_eq!(rec.seal_binding(), Uuid::parse_str(SB_UID).unwrap());
        assert!(
            r.store
                .take_session(Uuid::parse_str(SB_UID).unwrap())
                .await
                .unwrap()
                .is_none(),
            "taken once"
        );
    }

    #[tokio::test]
    async fn a_refused_or_deleted_sandbox_drops_its_parked_session() {
        let sb_uid = Uuid::parse_str(SB_UID).unwrap();
        let r = rig(WatcherConfig {
            audiences: vec![],
            ..cfg()
        });
        r.store.put_session(parked_session()).await.unwrap();
        let cur = settle(&r, &sandbox(false, false)).await;
        assert_eq!(cur.status.unwrap().phase, SandboxPhase::Failed);
        assert!(r.store.take_session(sb_uid).await.unwrap().is_none());

        let r = rig(cfg());
        r.store.put_session(parked_session()).await.unwrap();
        let sb = sandbox(true, true);
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        assert!(r.store.take_session(sb_uid).await.unwrap().is_none());
        assert_eq!(
            r.claims
                .sandbox("sandboxes", "sb-1")
                .unwrap()
                .finalizers()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn a_sandbox_whose_delegated_credential_never_reached_its_record_is_failed_and_its_claim_deleted()
     {
        let delegated = || WatcherConfig {
            delegated_audiences: ["api.example".to_owned()].into_iter().collect(),
            ..cfg()
        };
        // Nothing parked: the delegation was swept after its hour, or never sent.
        let r = rig(delegated());
        let cur = settle(&r, &sandbox(false, false)).await;
        let status = cur.status.clone().unwrap();
        assert_eq!(status.phase, SandboxPhase::Failed);
        assert!(
            status
                .reason
                .as_deref()
                .unwrap_or_default()
                .starts_with("delegation_required"),
            "{:?}",
            status.reason
        );
        assert!(
            r.claims.claim("sandboxes", "sb-1").is_none(),
            "the claim is deleted before a member is consumed"
        );
        // Settled: a later pass keeps the refusal and creates no second claim.
        r.watcher.reconcile_sandbox(&cur).await.unwrap();
        let again = r.claims.sandbox("sandboxes", "sb-1").unwrap();
        let status = again.status.unwrap();
        assert_eq!(status.phase, SandboxPhase::Failed);
        assert!(status.reason.unwrap().starts_with("delegation_required"));
        assert!(r.claims.claim("sandboxes", "sb-1").is_none());

        // The delegation parked: the record takes it and the sandbox goes on.
        let r = rig(delegated());
        r.store
            .put_session(mediatore_store::SessionRecord {
                audience: Some("api.example".into()),
                ..parked_session()
            })
            .await
            .unwrap();
        let cur = settle(&r, &sandbox(false, false)).await;
        assert_ne!(cur.status.unwrap().phase, SandboxPhase::Failed);
        let claim = r.claims.claim("sandboxes", "sb-1").expect("claim created");
        let rec = r
            .store
            .get_claim(claim_uid_of(&claim).unwrap())
            .await
            .unwrap();
        assert!(rec.delegations.contains_key("api.example"));
    }

    const OTHER_UID: &str = "1b2c3d4e-5f60-4718-892a-3b4c5d6e7f80";

    /// A `status.record` for claim `claim_uid` naming `sandbox_uid` in `namespace`, as the
    /// store writes one.
    fn record_naming(
        claim_uid: Uuid,
        sandbox_uid: Option<&str>,
        namespace: Option<&str>,
    ) -> crate::kubestore::RecordStatus {
        serde_json::from_value(json!({
            "claimUid": claim_uid.to_string(),
            "sandboxUid": sandbox_uid,
            "namespace": namespace,
            "createdAt": "2026-10-14T10:00:00Z",
        }))
        .expect("a record status")
    }

    /// `sb-1`, finalized, with `record` on its status and nothing else: what a restore or a
    /// copied manifest leaves on a new object.
    fn sandbox_carrying(record: crate::kubestore::RecordStatus) -> AgentSandbox {
        let mut sb = sandbox(true, false);
        sb.status = Some(AgentSandboxStatus {
            record: Some(record),
            ..AgentSandboxStatus::default()
        });
        sb
    }

    /// `sb` as the fake holds it now, with `record` on its status again. The fake's status
    /// patch replaces the whole status, where the API server's merge patch keeps the record
    /// the mirror leaves out of it.
    fn held_with_record(
        r: &Rig,
        sb: &AgentSandbox,
        record: crate::kubestore::RecordStatus,
    ) -> AgentSandbox {
        let mut held = r
            .claims
            .sandbox("sandboxes", &sb.name_any())
            .expect("the sandbox is in the fake");
        held.status.get_or_insert_default().record = Some(record);
        r.claims.put_sandbox(held.clone());
        held
    }

    /// The other sandbox, `sb-2`, settled on `r` up to a bound claim with its entry set.
    /// Returns its claim's UID.
    async fn a_bound_other_sandbox(r: &Rig) -> Uuid {
        let mut other = sandbox(true, false);
        other.metadata.name = Some("sb-2".into());
        other.metadata.uid = Some(OTHER_UID.into());
        r.claims.put_sandbox(other.clone());
        r.watcher.reconcile_sandbox(&other).await.unwrap();
        r.claims.patch_claim_status(
            "sandboxes",
            "sb-2",
            &json!({ "phase": "Bound", "tpmEndorsementCertificates": [RSA_EK_PEM] }),
        );
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        let claim = r.claims.claim("sandboxes", "sb-2").expect("claim created");
        let uid = claim_uid_of(&claim).unwrap();
        r.watcher.reconcile_claim(&claim).await.unwrap();
        assert_eq!(r.entries.names(), vec![claim_entry_name(uid)]);
        uid
    }

    /// The claim `sb` owns, as banlieue holds one that was created for it.
    fn owned_claim(sb: &AgentSandbox) -> VirtualMachineClaim {
        let mut claim = claim_for(sb).unwrap();
        claim.metadata.uid = Some(Uuid::new_v4().to_string());
        claim
    }

    /// What every refusal over a record that is not the sandbox's own leaves behind.
    async fn assert_failed_over_a_foreign_record(r: &Rig, records_before: usize) {
        let st = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        assert!(!st.ready && !st.entry_set);
        assert!(
            st.reason
                .as_deref()
                .unwrap_or_default()
                .starts_with(RECORD_NOT_OWN),
            "{:?}",
            st.reason
        );
        assert_eq!(st.observed_generation, Some(1));
        assert!(
            r.claims.claim("sandboxes", "sb-1").is_none(),
            "the owned claim is deleted"
        );
        assert_eq!(
            r.store.list_claims().await.unwrap().len(),
            records_before,
            "no record is written"
        );
        let parked = r
            .store
            .take_session(Uuid::parse_str(SB_UID).unwrap())
            .await
            .unwrap()
            .is_some();
        assert!(parked, "the parked session is not taken");
    }

    #[tokio::test]
    async fn a_sandbox_whose_record_names_another_sandbox_is_failed_and_its_claim_deleted() {
        let r = rig(cfg());
        let other_claim = a_bound_other_sandbox(&r).await;
        r.store.put_session(parked_session()).await.unwrap();
        // The other sandbox's status, carried onto this object.
        let sb = sandbox_carrying(record_naming(
            other_claim,
            Some(OTHER_UID),
            Some("sandboxes"),
        ));
        r.claims.put_sandbox(sb.clone());
        r.claims.put_claim(owned_claim(&sb));

        assert_eq!(
            r.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(
            r.claims.deleted(),
            vec![("sandboxes".to_owned(), "sb-1".to_owned())]
        );
        let st = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(
            st.claim_ref.as_ref().map(|c| c.name.as_str()),
            Some("sb-1"),
            "the deleted claim stays named: never a second one"
        );
        assert_failed_over_a_foreign_record(&r, 1).await;
        // The other sandbox keeps what is its own.
        let rec = r.store.get_claim(other_claim).await.unwrap();
        assert!(
            rec.revoked_at.is_none() && rec.entry_id.is_some(),
            "the other sandbox's record is untouched"
        );
        assert_eq!(
            r.entries.names(),
            vec![claim_entry_name(other_claim)],
            "its entry is not retracted"
        );
        assert!(
            r.claims.claim("sandboxes", "sb-2").is_some(),
            "its claim is not deleted"
        );
    }

    #[tokio::test]
    async fn a_sandbox_with_a_foreign_record_and_no_claim_is_failed_and_gets_none() {
        let r = rig(cfg());
        r.store.put_session(parked_session()).await.unwrap();
        let sb = sandbox_carrying(record_naming(
            Uuid::new_v4(),
            Some(OTHER_UID),
            Some("sandboxes"),
        ));
        r.claims.put_sandbox(sb.clone());
        assert_eq!(
            r.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        assert!(r.claims.deleted().is_empty(), "no claim, nothing to delete");
        assert_failed_over_a_foreign_record(&r, 0).await;
    }

    #[tokio::test]
    async fn half_a_binding_is_a_foreign_record_too() {
        // The sandbox's own UID with no namespace, and its own namespace with no UID: a
        // missing field is never a match.
        for (sandbox_uid, namespace) in [(Some(SB_UID), None), (None, Some("sandboxes"))] {
            let r = rig(cfg());
            r.store.put_session(parked_session()).await.unwrap();
            let sb = sandbox_carrying(record_naming(Uuid::new_v4(), sandbox_uid, namespace));
            r.claims.put_sandbox(sb.clone());
            r.claims.put_claim(owned_claim(&sb));
            assert_eq!(
                r.watcher.reconcile_sandbox(&sb).await.unwrap(),
                Action::await_change()
            );
            assert_eq!(r.claims.deleted().len(), 1, "the owned claim is deleted");
            assert_failed_over_a_foreign_record(&r, 0).await;
        }
    }

    #[tokio::test]
    async fn a_record_from_before_the_binding_and_the_sandboxes_own_reconcile_as_before() {
        // The sandbox's own record, then one written before the ADR: neither field.
        for (sandbox_uid, namespace) in [(Some(SB_UID), Some("sandboxes")), (None, None)] {
            let r = rig(cfg());
            r.store.put_session(parked_session()).await.unwrap();
            let bare = sandbox(true, false);
            let claim = owned_claim(&bare);
            let uid = claim_uid_of(&claim).unwrap();
            let sb = sandbox_carrying(record_naming(uid, sandbox_uid, namespace));
            r.claims.put_sandbox(sb.clone());
            r.claims.put_claim(claim);
            assert_eq!(
                r.watcher.reconcile_sandbox(&sb).await.unwrap(),
                Action::await_change()
            );
            let st = r
                .claims
                .sandbox("sandboxes", "sb-1")
                .unwrap()
                .status
                .unwrap();
            assert_eq!(st.phase, SandboxPhase::Pending);
            assert!(st.reason.is_none(), "{:?}", st.reason);
            assert!(r.claims.deleted().is_empty(), "the claim is kept");
            assert!(r.claims.claim("sandboxes", "sb-1").is_some());
            let rec = r.store.get_claim(uid).await.unwrap();
            assert_eq!(
                rec.refresh,
                Some(parked_session().refresh),
                "the parked session follows the claim into the record"
            );
        }
    }

    #[tokio::test]
    async fn a_second_pass_over_a_sandbox_failed_for_a_foreign_record_does_nothing() {
        let r = rig(cfg());
        r.claims.hold_deleted_claims(true);
        r.store.put_session(parked_session()).await.unwrap();
        let foreign = record_naming(Uuid::new_v4(), Some(OTHER_UID), Some("sandboxes"));
        let sb = sandbox_carrying(foreign.clone());
        r.claims.put_sandbox(sb.clone());
        r.claims.put_claim(owned_claim(&sb));
        assert_eq!(
            r.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(r.claims.deleted().len(), 1);
        let patches = r.claims.patches();

        // While banlieue's finalizer holds the claim: not deleted again, nothing patched.
        let failed = held_with_record(&r, &sb, foreign);
        assert_eq!(
            r.watcher.reconcile_sandbox(&failed).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(r.claims.deleted().len(), 1, "the claim is deleted once");
        assert_eq!(r.claims.patches(), patches, "nothing is patched again");

        // The claim is gone: the same steady state, and no second claim.
        r.claims.remove_claim("sandboxes", "sb-1");
        assert_eq!(
            r.watcher.reconcile_sandbox(&failed).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(r.claims.deleted().len(), 1);
        assert_eq!(r.claims.patches(), patches);
        assert_failed_over_a_foreign_record(&r, 0).await;
    }

    #[tokio::test]
    async fn deleting_a_sandbox_failed_for_a_foreign_record_releases_nothing() {
        let r = rig(cfg());
        let other_claim = a_bound_other_sandbox(&r).await;
        let foreign = record_naming(other_claim, Some(OTHER_UID), Some("sandboxes"));
        let mut sb = sandbox_carrying(foreign.clone());
        // The whole status came along, the other sandbox's claim UID included.
        if let Some(st) = sb.status.as_mut() {
            st.claim_uid = Some(other_claim.to_string());
        }
        r.claims.put_sandbox(sb.clone());
        r.claims.put_claim(owned_claim(&sb));
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        assert_eq!(r.claims.deleted().len(), 1);

        let mut deleting = held_with_record(&r, &sb, foreign);
        assert_eq!(
            deleting.status.as_ref().map(|s| s.phase),
            Some(SandboxPhase::Failed)
        );
        deleting.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH));
        r.claims.put_sandbox(deleting.clone());
        assert_eq!(
            r.watcher.reconcile_sandbox(&deleting).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(
            r.claims.sandbox("sandboxes", "sb-1").unwrap().finalizers(),
            &Vec::<String>::new(),
            "the finalizer is dropped: no record of its own to hold it for"
        );
        let rec = r.store.get_claim(other_claim).await.unwrap();
        assert!(
            rec.revoked_at.is_none() && rec.entry_id.is_some(),
            "the other sandbox's record is not released"
        );
        assert_eq!(
            r.entries.names(),
            vec![claim_entry_name(other_claim)],
            "its entry is not retracted"
        );
        assert!(
            r.claims.claim("sandboxes", "sb-2").is_some(),
            "its claim is not deleted"
        );
        assert_eq!(r.claims.deleted().len(), 1, "no further claim deletion");
    }

    /// Every `format` in `v` (and under it) the apiserver would drop, as a path.
    fn unsupported_formats(v: &serde_json::Value, path: &str, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                if let Some(format) = m.get("format").and_then(serde_json::Value::as_str) {
                    let type_ = m.get("type").and_then(serde_json::Value::as_str);
                    if !crate::crd_formats::is_supported_format(type_, format) {
                        out.push(format!("{path}: {format}"));
                    }
                }
                for (k, child) in m {
                    unsupported_formats(child, &format!("{path}.{k}"), out);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    unsupported_formats(child, &format!("{path}[{i}]"), out);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn no_shipped_crd_carries_an_unsupported_format() {
        // The apiserver drops an unknown format and warns on apply (`unrecognized format
        // "uint64"`); schemars emits uint8..uint64 for Rust's unsigned integers.
        let mut found = Vec::new();
        for (file, rendered) in crd_yamls().unwrap() {
            let crd: k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition =
                serde_saphyr::from_str(&rendered).unwrap();
            let json = serde_json::to_value(&crd).unwrap();
            unsupported_formats(&json["spec"]["versions"], file, &mut found);
        }
        assert!(found.is_empty(), "unsupported formats: {found:#?}");
    }

    #[test]
    fn the_crds_in_deploy_are_what_the_types_render() {
        for (file, rendered) in crd_yamls().unwrap() {
            let path = format!(
                "{}/../../deploy/base/crds/{file}",
                env!("CARGO_MANIFEST_DIR")
            );
            let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
            assert_eq!(
                on_disk, rendered,
                "deploy/base/crds/{file} is stale: run `make crds`"
            );
        }
    }

    /// ADR-0046 decision 10: the broker's `ClusterRole` is the widest thing it holds (it can create
    /// sandboxes in every namespace; the namespace map narrows the user API in code, not here).
    /// A change to these rules is a trust-boundary change: it needs an ADR and a pass over
    /// `docs/security/threat-model.md` (TB-2, the row on the broker's `ServiceAccount`), not a
    /// quiet edit of this literal. A new tenant namespace needs no change here.
    #[test]
    fn the_brokers_cluster_role_is_pinned() {
        use serde_json::json;
        let path = format!("{}/../../deploy/base/rbac.yaml", env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(&path).unwrap();
        let roles: Vec<serde_json::Value> = text
            .split("\n---\n")
            .map(|d| serde_saphyr::from_str::<serde_json::Value>(d).unwrap())
            .filter(|d| d["kind"] == "ClusterRole" && d["metadata"]["name"] == "mediatore")
            .collect();
        assert_eq!(roles.len(), 1, "exactly one ClusterRole named mediatore");
        let expected = json!([
            {"apiGroups": ["mediatore.io"], "resources": ["agentsandboxes"],
             "verbs": ["get", "list", "watch", "patch", "create", "delete"]},
            {"apiGroups": ["mediatore.io"], "resources": ["agentsandboxes/status"],
             "verbs": ["patch"]},
            {"apiGroups": ["mediatore.io"], "resources": ["agentsandboxes/finalizers"],
             "verbs": ["update"]},
            {"apiGroups": ["mediatore.io"], "resources": ["sandboxnodes", "policyfloors"],
             "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]},
            {"apiGroups": ["banlieue.io"], "resources": ["virtualmachineclaims"],
             "verbs": ["get", "list", "watch", "create", "delete"]},
            {"apiGroups": ["banlieue.io"], "resources": ["virtualmachineclaims/status"],
             "verbs": ["get"]},
            {"apiGroups": ["banlieue.io"], "resources": ["virtualmachines"],
             "verbs": ["get", "list", "watch"]},
            {"apiGroups": ["spire.spiffe.io"], "resources": ["clusterstaticentries"],
             "verbs": ["get", "list", "watch", "create", "delete"]},
        ]);
        assert_eq!(
            roles[0]["rules"], expected,
            "deploy/base/rbac.yaml's ClusterRole changed: that is a trust-boundary change \
             (ADR-0046 decision 10); write the ADR and do the threat-model pass first"
        );
    }

    #[test]
    fn the_base_kustomization_lists_every_crd() {
        // A rendered CRD the base does not list is a CRD `kubectl apply -k deploy/base`
        // never installs (the kind tiers apply the directory, so only this test notices).
        let path = format!(
            "{}/../../deploy/base/kustomization.yaml",
            env!("CARGO_MANIFEST_DIR")
        );
        let kustomization = std::fs::read_to_string(&path).unwrap();
        for (file, _) in crd_yamls().unwrap() {
            assert!(
                kustomization.contains(&format!("- crds/{file}")),
                "deploy/base/kustomization.yaml does not list crds/{file}"
            );
        }
    }

    /// ADR-0049 decisions 1 and 2: the CRD serves `v1alpha1` and `v1beta1`, stores `v1beta1`,
    /// converts by `None`, and the two versions are the same schema, columns and
    /// subresources, `v1alpha1` deprecated with a warning naming `v1beta1`.
    #[test]
    fn both_versions_are_served_with_one_schema() {
        let crd = serde_json::to_value(crd()).unwrap();
        let versions = crd["spec"]["versions"].as_array().unwrap();
        let names: Vec<&str> = versions.iter().filter_map(|v| v["name"].as_str()).collect();
        assert_eq!(names, ["v1alpha1", "v1beta1"]);
        let (alpha, beta) = (&versions[0], &versions[1]);
        assert_eq!(
            (&alpha["served"], &alpha["storage"]),
            (&json!(true), &json!(false))
        );
        assert_eq!(
            (&beta["served"], &beta["storage"]),
            (&json!(true), &json!(true))
        );
        assert_eq!(alpha["deprecated"], json!(true));
        assert!(
            alpha["deprecationWarning"]
                .as_str()
                .is_some_and(|w| w.contains("mediatore.io/v1beta1")),
            "the warning names the version to move to"
        );
        assert!(beta.get("deprecated").is_none_or(|d| d == &json!(false)));
        for key in ["schema", "additionalPrinterColumns", "subresources"] {
            assert_eq!(alpha[key], beta[key], "{key} differs between the versions");
        }
        // No webhook: identical schemas convert by rewriting apiVersion alone.
        assert!(
            crd["spec"]["conversion"].is_null()
                || crd["spec"]["conversion"]["strategy"] == json!("None")
        );
        // What the broker reads and writes is the stored version.
        assert_eq!(AgentSandbox::version(&()), "v1beta1");
    }

    /// The documents of an admission file under `deploy/base/admission`.
    fn admission_docs(file: &str) -> Vec<serde_json::Value> {
        let path = format!(
            "{}/../../deploy/base/admission/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_saphyr::from_multiple(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    /// ADR-0049 decision 3: the policies on `AgentSandbox` (its subject, and who writes its
    /// status) govern every served version, named explicitly, so no version reaches the
    /// API server unpinned.
    #[test]
    fn the_admission_policy_matches_every_served_version() {
        for file in ["agentsandbox-subject.yaml", "agentsandbox-status.yaml"] {
            let docs = admission_docs(file);
            let policy = docs
                .iter()
                .find(|d| d["kind"] == "ValidatingAdmissionPolicy")
                .expect("the policy");
            let constraints = &policy["spec"]["matchConstraints"];
            assert_eq!(constraints["matchPolicy"], "Equivalent", "{file}");
            let rules = constraints["resourceRules"].as_array().unwrap();
            assert_eq!(rules.len(), 1, "{file}");
            let mut matched: Vec<&str> = rules[0]["apiVersions"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            matched.sort_unstable();
            let crd = crd();
            let mut served: Vec<&str> = crd
                .spec
                .versions
                .iter()
                .filter(|v| v.served)
                .map(|v| v.name.as_str())
                .collect();
            served.sort_unstable();
            assert_eq!(matched, served, "{file}");
        }
    }

    /// The status carries the claim record (ADR-0034), so the status subresource is the
    /// broker's alone whatever a namespace Role grants: one policy, failing closed, on
    /// every write of `agentsandboxes/status`, admitting the broker's `ServiceAccount` as
    /// the other policies spell it, and bound with `Deny`.
    #[test]
    fn the_status_policy_admits_the_broker_alone_and_denies() {
        let docs = admission_docs("agentsandbox-status.yaml");
        let policy = docs
            .iter()
            .find(|d| d["kind"] == "ValidatingAdmissionPolicy")
            .expect("the policy");
        assert_eq!(policy["spec"]["failurePolicy"], "Fail");
        assert!(
            policy["spec"]["matchConditions"].is_null(),
            "a match condition would let a request past the policy"
        );
        let rule = &policy["spec"]["matchConstraints"]["resourceRules"][0];
        assert_eq!(rule["apiGroups"], json!(["mediatore.io"]));
        assert_eq!(rule["resources"], json!(["agentsandboxes/status"]));
        assert_eq!(rule["operations"], json!(["UPDATE"]));
        let validations = policy["spec"]["validations"].as_array().unwrap();
        assert_eq!(validations.len(), 1);
        assert_eq!(
            validations[0]["expression"],
            "request.userInfo.username == 'system:serviceaccount:banlieue-system:mediatore'"
        );
        // The same spelling as the policy on the broker's entries, which carries it as
        // the first way an entry is claimed and in its sender validation (ADR-0056
        // decision 4): one name to change, in every place.
        let spelling = validations[0]["expression"].as_str().unwrap();
        let entries = admission_docs("clusterstaticentry-mediatore.yaml");
        for carried in [
            &entries[0]["spec"]["matchConditions"][0]["expression"],
            &entries[0]["spec"]["validations"][0]["expression"],
        ] {
            assert!(
                carried
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("{spelling} || ")),
                "{carried}"
            );
        }
        let binding = docs
            .iter()
            .find(|d| d["kind"] == "ValidatingAdmissionPolicyBinding")
            .expect("the binding");
        assert_eq!(binding["spec"]["policyName"], policy["metadata"]["name"]);
        assert_eq!(binding["spec"]["validationActions"], json!(["Deny"]));
        assert!(
            binding["spec"]["matchResources"].is_null(),
            "bound everywhere: a namespace left out would be ungoverned"
        );
    }

    /// The messages of the validations the entries policy carried before it claimed an entry
    /// by what it is: every one must still be there.
    const KEPT_ENTRY_VALIDATIONS: [&str; 15] = [
        "mediatore may only declare entries named mediatore-*",
        "spiffeID must be spiffe://<td>/banlieue/node/<ek-hash> or spiffe://<td>/banlieue/claim/<uuid>",
        "parentID must be a tpm agent ID: spiffe://<td>/spire/agent/tpm/<ek-hash>",
        "spiffeID and parentID must be in the same trust domain",
        "a node entry's EK hash must equal its parent agent's EK hash",
        "selectors must be unix workload selectors",
        "a node entry must select unix:uid:0",
        "a claim entry must select exactly one unix:user:sb-<12 hex> (ADR-0004)",
        "mediatore entries are never admin",
        "mediatore entries are never downstream",
        "mediatore entries never use an SVIDStore",
        "mediatore entries never federate",
        "mediatore entries carry no DNS names",
        "className is required (the controller manager ignores classless resources)",
        "x509SVIDTTL must be at most 4h",
    ];

    /// ADR-0056 decision 4: the entries policy claims an entry by what it is, whoever
    /// sends it, and says who may send one. The CEL itself is proven by an API server
    /// (the kind gateway tier's dry runs); what is held here is that the file still says
    /// it: one match condition of four ways, none of the three object tests tied to a
    /// sender, the sender validation first with the message the broker's self-check
    /// reads, every earlier validation still present, and bound with `Deny`.
    #[test]
    fn the_entries_policy_claims_an_entry_by_what_it_is_and_names_its_one_sender() {
        const BROKER: &str =
            "request.userInfo.username == 'system:serviceaccount:banlieue-system:mediatore'";
        let docs = admission_docs("clusterstaticentry-mediatore.yaml");
        let policy = docs
            .iter()
            .find(|d| d["kind"] == "ValidatingAdmissionPolicy")
            .expect("the policy");
        assert_eq!(policy["metadata"]["name"], mediatore_spire::ENTRIES_POLICY);
        assert_eq!(policy["spec"]["failurePolicy"], "Fail");
        let rule = &policy["spec"]["matchConstraints"]["resourceRules"][0];
        assert_eq!(rule["resources"], json!(["clusterstaticentries"]));
        assert_eq!(rule["operations"], json!(["CREATE", "UPDATE"]));

        let conditions = policy["spec"]["matchConditions"].as_array().unwrap();
        assert_eq!(
            conditions.len(),
            1,
            "conditions are ANDed: a second one would narrow what is claimed"
        );
        let claimed = conditions[0]["expression"].as_str().unwrap();
        let ways: Vec<&str> = claimed.split(" || ").collect();
        assert_eq!(ways.len(), 4, "{claimed}");
        assert_eq!(ways[0], BROKER, "whatever the broker sends is judged");
        assert!(
            ways[1].contains("object.metadata.name.startsWith('mediatore-')"),
            "by its name: {}",
            ways[1]
        );
        let label = mediatore_spire::MANAGED_BY_LABEL;
        let managed_by = mediatore_spire::MANAGED_BY;
        assert!(
            ways[2].contains(&format!(
                "object.metadata.labels['{label}'] == '{managed_by}'"
            )),
            "by the label the broker sets: {}",
            ways[2]
        );
        assert!(
            ways[3].contains("object.spec.spiffeID.matches('^spiffe://[^/]+/banlieue/')"),
            "by its path, in any trust domain: {}",
            ways[3]
        );
        for way in &ways[1..] {
            assert!(
                !way.contains("request."),
                "an object test tied to the request is the fail-open this replaced: {way}"
            );
        }

        let validations = policy["spec"]["validations"].as_array().unwrap();
        let sender = &validations[0];
        assert_eq!(
            sender["expression"],
            format!("{BROKER} || (request.operation == 'UPDATE' && oldObject.spec == object.spec)"),
            "the broker's ServiceAccount, or an update that declares nothing"
        );
        assert_eq!(
            sender["message"],
            mediatore_spire::ENTRIES_POLICY_SENDER_MESSAGE,
            "the broker's self-check reads this message: change both or neither"
        );
        assert_eq!(sender["reason"], "Forbidden");
        // What the policy refused before, it still refuses: every earlier validation.
        for kept in KEPT_ENTRY_VALIDATIONS {
            assert!(
                validations[1..].iter().any(|v| v["message"] == kept),
                "the validation is gone: {kept}"
            );
        }
        assert_eq!(validations.len(), 16);

        // The literal is the one string the two AgentSandbox policies carry.
        for file in ["agentsandbox-subject.yaml", "agentsandbox-status.yaml"] {
            let text = std::fs::read_to_string(format!(
                "{}/../../deploy/base/admission/{file}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            assert!(text.contains(BROKER), "{file} spells the broker otherwise");
        }

        let binding = docs
            .iter()
            .find(|d| d["kind"] == "ValidatingAdmissionPolicyBinding")
            .expect("the binding");
        assert_eq!(binding["spec"]["policyName"], policy["metadata"]["name"]);
        assert_eq!(binding["spec"]["validationActions"], json!(["Deny"]));
        assert!(
            binding["spec"]["matchResources"].is_null() && binding["spec"]["paramRef"].is_null(),
            "bound everywhere, with no parameter that could be missing"
        );
    }

    /// The gateway's entries are the platform team's and stay the gateway policy's alone:
    /// none of the shipped ones carries a sign by which the broker's policy claims an
    /// entry, and the gateway policy claims by a path the broker's shapes never have.
    #[test]
    fn the_shipped_gateway_entries_carry_none_of_the_signs_of_a_brokers_entry() {
        let path = format!(
            "{}/../../deploy/gateway/clusterstaticentries.yaml",
            env!("CARGO_MANIFEST_DIR")
        );
        let docs: Vec<serde_json::Value> =
            serde_saphyr::from_multiple(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let entries: Vec<&serde_json::Value> = docs
            .iter()
            .filter(|d| d["kind"] == "ClusterStaticEntry")
            .collect();
        assert!(!entries.is_empty(), "no gateway entry was read from {path}");
        for entry in entries {
            let name = entry["metadata"]["name"].as_str().unwrap();
            assert!(!name.starts_with("mediatore-"), "{name}");
            assert!(
                entry["metadata"]["labels"][mediatore_spire::MANAGED_BY_LABEL].is_null(),
                "{name} carries the broker's label"
            );
            let id = entry["spec"]["spiffeID"].as_str().unwrap();
            let after_td = id.strip_prefix("spiffe://").and_then(|r| r.split_once('/'));
            let Some((_, id_path)) = after_td else {
                panic!("{name}: {id} is not a SPIFFE ID with a path");
            };
            assert!(
                id_path == "gateway" || id_path.starts_with("gateway/"),
                "{name}: {id}"
            );
            assert!(!id_path.starts_with("banlieue/"), "{name}: {id}");
        }
        let gateway = admission_docs("clusterstaticentry-gateway.yaml");
        assert_eq!(
            gateway[0]["spec"]["matchConditions"][0]["expression"],
            "has(object.spec.spiffeID) && object.spec.spiffeID.matches('^spiffe://[^/]+/gateway(/.*)?$')"
        );
    }

    #[test]
    fn the_base_kustomization_lists_every_admission_policy() {
        // A policy file the base does not list is a control `kubectl apply -k deploy/base`
        // never installs.
        let root = format!("{}/../../deploy/base", env!("CARGO_MANIFEST_DIR"));
        let kustomization = std::fs::read_to_string(format!("{root}/kustomization.yaml")).unwrap();
        let mut files: Vec<String> = std::fs::read_dir(format!("{root}/admission"))
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|f| {
                std::path::Path::new(f)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml"))
            })
            .collect();
        files.sort_unstable();
        assert!(files.iter().any(|f| f == "agentsandbox-status.yaml"));
        for file in files {
            assert!(
                kustomization.contains(&format!("- admission/{file}")),
                "deploy/base/kustomization.yaml does not list admission/{file}"
            );
        }
    }

    #[test]
    fn the_schema_requires_what_the_reconciler_assumes() {
        let crd = serde_json::to_value(AgentSandbox::crd()).unwrap();
        let v = &crd["spec"]["versions"][0];
        // ADR-0048: the type's one version, served and stored. The CRD adds `v1alpha1` as a
        // copy of it at render time (ADR-0049, `both_versions_are_served_with_one_schema`).
        assert_eq!(crd["spec"]["versions"].as_array().map(Vec::len), Some(1));
        assert_eq!(v["name"], "v1beta1");
        assert_eq!((&v["served"], &v["storage"]), (&json!(true), &json!(true)));
        assert!(
            v["subresources"]["status"].is_object(),
            "status subresource"
        );
        let spec = &v["schema"]["openAPIV3Schema"]["properties"]["spec"];
        let required: Vec<&str> = spec["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        for f in ["subject", "ttlSeconds", "workload"] {
            assert!(required.contains(&f), "{f} required");
        }
        // ADR-0044 decisions 1 and 2: exactly one of poolRef and poolSelector, by CEL, so
        // neither is required on its own and neither-nor-both is never read as "any pool".
        assert!(
            !required.contains(&"poolRef"),
            "poolRef is optional beside poolSelector (ADR-0044)"
        );
        let rules = spec["x-kubernetes-validations"]
            .as_array()
            .unwrap_or_else(|| panic!("no CEL rules on spec: {spec}"));
        assert!(
            rules
                .iter()
                .any(|r| r["rule"] == "has(self.poolRef) != has(self.poolSelector)"),
            "got {rules:?}"
        );
        assert!(
            spec["properties"]["poolSelector"]["properties"]["matchLabels"].is_object(),
            "poolSelector is a LabelSelector: {spec}"
        );
        let pool = v["additionalPrinterColumns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "Pool")
            .expect("a Pool column");
        assert_eq!(
            pool["jsonPath"], ".status.poolRef.name",
            "the pool bound from, not the one asked for (ADR-0044 decision 5)"
        );
        let vm = v["additionalPrinterColumns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "VM")
            .expect("a VM column");
        assert_eq!(
            vm["jsonPath"], ".status.virtualMachineRef.name",
            "the VirtualMachine the sandbox runs on, mirrored from the claim"
        );
        assert!(
            !required.contains(&"policyRef"),
            "policyRef is optional in shadow (ADR-0026 decision 6)"
        );
        assert!(
            spec["properties"]["policyRef"]["properties"]["name"].is_object(),
            "policyRef names a SandboxPolicy"
        );
        assert_eq!(spec["properties"]["ttlSeconds"]["minimum"], 1.0);
        assert_eq!(
            spec["properties"]["subject"]["properties"]["id"]["minLength"],
            1
        );
        assert_eq!(
            spec["properties"]["workload"]["properties"]["image"]["minLength"],
            1
        );
        let phase = &v["schema"]["openAPIV3Schema"]["properties"]["status"]["properties"]["phase"];
        assert_eq!(
            phase["enum"],
            json!(["Pending", "Bound", "Releasing", "Failed"])
        );
        assert!(
            !phase["nullable"].as_bool().unwrap_or(false),
            "phase is never null"
        );
    }

    /// ADR-0046 decision 14: a create into a namespace that does not exist is the API server's
    /// 404, which is no refusal the broker names: it is `Api`, and the user API answers it with
    /// `500 internal` (`a_listed_namespace_that_does_not_exist_fails_the_create_and_parks_nothing`).
    /// ADR-0047 decision 1: `selection` is optional and its `strategy` lists exactly the
    /// strategies banlieue has, so an unknown one is refused by the API server before the
    /// reconciler runs.
    #[test]
    fn the_schema_lists_banlieues_strategies_and_no_other() {
        let crd = serde_json::to_value(AgentSandbox::crd()).unwrap();
        let spec = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"];
        let required: Vec<&str> = spec["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert!(
            !required.contains(&"selection"),
            "selection is optional (ADR-0047)"
        );
        let strategy = &spec["properties"]["selection"]["properties"]["strategy"];
        let mut values: Vec<&str> = strategy
            .get("enum")
            .and_then(|e| e.as_array())
            .map(|e| e.iter().filter_map(|v| v.as_str()).collect())
            .or_else(|| {
                strategy["oneOf"].as_array().map(|alts| {
                    alts.iter()
                        .flat_map(|a| a["enum"].as_array().into_iter().flatten())
                        .filter_map(|v| v.as_str())
                        .collect()
                })
            })
            .unwrap_or_else(|| panic!("no enum on selection.strategy: {strategy}"));
        values.sort_unstable();
        assert_eq!(values, ["LongestReady", "MostAvailable", "Spread"]);
    }

    #[test]
    fn a_404_from_the_api_server_is_the_catch_all_error() {
        let status = kube::core::Status::failure("namespaces \"team-a\" not found", "NotFound")
            .with_code(404);
        let e = front_door_error(kube::Error::Api(Box::new(status)));
        assert!(matches!(e, FrontDoorError::Api(_)), "{e:?}");
    }

    #[test]
    fn the_claim_is_owned_labelled_and_copies_the_spec() {
        let sb = sandbox(true, false);
        let claim = claim_for(&sb).unwrap();
        assert_eq!(claim.name_any(), "sb-1");
        assert_eq!(claim.namespace().as_deref(), Some("sandboxes"));
        let labels = claim.labels();
        assert_eq!(
            labels.get(MANAGED_BY_LABEL).map(String::as_str),
            Some(MANAGED_BY)
        );
        assert_eq!(
            labels.get(SANDBOX_UID_LABEL).map(String::as_str),
            Some(SB_UID)
        );
        let owner = &claim.owner_references()[0];
        assert_eq!(
            (owner.kind.as_str(), owner.api_version.as_str()),
            ("AgentSandbox", "mediatore.io/v1beta1")
        );
        assert_eq!(owner.uid, SB_UID);
        assert_eq!(
            (owner.controller, owner.block_owner_deletion),
            (Some(true), Some(true))
        );
        assert_eq!(
            claim.spec.pool_ref.as_ref().map(|r| r.name.as_str()),
            Some("pool")
        );
        assert!(claim.spec.pool_selector.is_none());
        assert_eq!(
            (
                claim.spec.subject.issuer.as_str(),
                claim.spec.subject.id.as_str()
            ),
            (ISSUER, "octocat")
        );
        assert_eq!(claim.spec.ttl_seconds, 600);
        assert!(owned_by(&claim, &sb));
        let mut other = sb.clone();
        other.metadata.uid = Some(Uuid::new_v4().to_string());
        assert!(!owned_by(&claim, &other));
        let mut unsaved = sb;
        unsaved.metadata.uid = None;
        assert!(
            claim_for(&unsaved).is_err(),
            "no uid, no owner reference, no claim"
        );
    }

    /// ADR-0044 decision 1: a selector is copied to the claim as it is, `{}` included, and
    /// the claim then names no pool; banlieue picks among the matched pools' members.
    #[test]
    fn a_selector_is_copied_to_the_claim_verbatim_and_the_claim_names_no_pool() {
        let mut sb = sandbox(true, false);
        sb.spec.pool_ref = None;
        sb.spec.pool_selector = Some(LabelSelector {
            match_labels: BTreeMap::from([(
                "sandbox.example.com/image".to_owned(),
                "agent".to_owned(),
            )]),
            match_expressions: vec![LabelSelectorRequirement {
                key: "topology.kubernetes.io/zone".into(),
                operator: LabelSelectorOperator::NotIn,
                values: vec!["c".into()],
            }],
        });
        let claim = claim_for(&sb).unwrap();
        assert!(claim.spec.pool_ref.is_none());
        assert_eq!(claim.spec.pool_selector, sb.spec.pool_selector);
        assert_eq!(
            pool_of(&sb.spec),
            "sandbox.example.com/image=agent,topology.kubernetes.io/zone notin (c)"
        );

        sb.spec.pool_selector = Some(LabelSelector::default());
        let any = claim_for(&sb).unwrap();
        assert_eq!(any.spec.pool_selector, Some(LabelSelector::default()));
        assert_eq!(pool_of(&sb.spec), "any pool");
        let json = serde_json::to_value(&any.spec).unwrap();
        assert_eq!(
            json["poolSelector"],
            json!({}),
            "kept, never dropped: {json}"
        );
        assert!(json.get("poolRef").is_none(), "got {json}");
    }

    /// The two selector shapes convert both ways without loss (ADR-0044 decision 4).
    #[test]
    fn the_request_selector_and_banlieues_are_one_shape() {
        let req = PoolSelector {
            match_labels: BTreeMap::from([("a".to_owned(), "b".to_owned())]),
            match_expressions: vec![
                mediatore_proto::PoolSelectorRequirement {
                    key: "k1".into(),
                    operator: PoolSelectorOperator::In,
                    values: vec!["x".into(), "y".into()],
                },
                mediatore_proto::PoolSelectorRequirement {
                    key: "k2".into(),
                    operator: PoolSelectorOperator::Exists,
                    values: vec![],
                },
                mediatore_proto::PoolSelectorRequirement {
                    key: "k3".into(),
                    operator: PoolSelectorOperator::DoesNotExist,
                    values: vec![],
                },
            ],
        };
        let banlieue = label_selector_of(&req);
        assert_eq!(
            serde_json::to_value(&banlieue).unwrap(),
            json!({
                "matchLabels": { "a": "b" },
                "matchExpressions": [
                    { "key": "k1", "operator": "In", "values": ["x", "y"] },
                    { "key": "k2", "operator": "Exists" },
                    { "key": "k3", "operator": "DoesNotExist" }
                ]
            })
        );
        assert_eq!(pool_selector_of(&banlieue), req);
    }

    /// ADR-0047 decisions 1 and 2: a strategy is copied to the claim as it is, and an absent
    /// one stays absent, so banlieue's own default applies and nothing written so far changes.
    #[test]
    fn a_strategy_is_copied_to_the_claim_verbatim_and_an_absent_one_stays_absent() {
        let mut sb = sandbox(true, false);
        assert!(sb.spec.selection.is_none());
        let claim = claim_for(&sb).unwrap();
        assert!(claim.spec.selection.is_none());
        let json = serde_json::to_value(&claim.spec).unwrap();
        assert!(json.get("selection").is_none(), "written as absent: {json}");
        assert_eq!(strategy_of(&sb.spec), "default");

        sb.spec.selection = Some(ClaimSelection {
            strategy: SelectionStrategy::Spread,
        });
        let claim = claim_for(&sb).unwrap();
        assert_eq!(claim.spec.selection, sb.spec.selection);
        assert_eq!(claim.spec.strategy(), SelectionStrategy::Spread);
        let json = serde_json::to_value(&claim.spec).unwrap();
        assert_eq!(
            json["selection"],
            json!({ "strategy": "Spread" }),
            "got {json}"
        );
        assert_eq!(strategy_of(&sb.spec), "Spread");
    }

    /// The request's strategy and banlieue's are one shape, both ways (ADR-0047 decision 3).
    #[test]
    fn the_request_strategy_and_banlieues_are_one_shape() {
        for (ours, theirs) in [
            (
                mediatore_proto::SelectionStrategy::LongestReady,
                SelectionStrategy::LongestReady,
            ),
            (
                mediatore_proto::SelectionStrategy::MostAvailable,
                SelectionStrategy::MostAvailable,
            ),
            (
                mediatore_proto::SelectionStrategy::Spread,
                SelectionStrategy::Spread,
            ),
        ] {
            let sel = mediatore_proto::Selection { strategy: ours };
            let claim = claim_selection_of(&sel);
            assert_eq!(claim.strategy, theirs);
            assert_eq!(selection_of(&claim), sel);
            assert_eq!(
                serde_json::to_value(&claim).unwrap(),
                serde_json::to_value(sel).unwrap(),
                "spelled the same on the claim and on the wire"
            );
        }
    }

    #[tokio::test]
    async fn a_new_sandbox_gets_a_finalizer_then_its_claim_and_record() {
        let r = rig(cfg());
        r.claims.put_sandbox(sandbox(false, false));
        let first = r
            .watcher
            .reconcile_sandbox(&sandbox(false, false))
            .await
            .unwrap();
        assert_eq!(first, Action::await_change());
        let held = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .expect("the fake saw the finalizer patch");
        assert_eq!(held.finalizers(), &[FINALIZER.to_owned()]);
        assert!(
            r.claims.claim("sandboxes", "sb-1").is_none(),
            "no claim before the finalizer"
        );

        let sb = settle(&r, &held).await;
        let claim = r.claims.claim("sandboxes", "sb-1").expect("claim created");
        assert!(owned_by(&claim, &sb));
        let uid = claim_uid_of(&claim).unwrap();
        let rec = r.store.get_claim(uid).await.unwrap();
        assert_eq!(rec.name, "sb-1");
        assert_eq!(rec.subject.id, "octocat");
        assert_eq!(rec.subject.display.as_deref(), Some("The Octocat"));
        assert_eq!(rec.audiences, vec!["api.example".to_owned()]);
        assert_eq!(rec.workload.image, "ghcr.io/example/workload:1");
        assert_eq!(rec.ttl_seconds, 600);
        assert!(rec.entry_id.is_none());
        assert!(
            rec.policy_uid.is_none() && rec.bundle_version.is_none(),
            "no policyRef, no policy on the record"
        );
        let status = sb.status.clone().unwrap();
        assert_eq!(status.phase, SandboxPhase::Pending);
        assert_eq!(status.claim_uid.as_deref(), Some(uid.to_string().as_str()));
        assert_eq!(
            status.claim_ref.as_ref().map(|c| c.name.as_str()),
            Some("sb-1")
        );
        assert!(!status.ready);
        assert_eq!(status.observed_generation, Some(1));
        // Stable: a repeated pass creates nothing and patches nothing.
        let before = r.claims.patches();
        assert_eq!(
            r.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(r.claims.patches(), before);
        assert_eq!(r.store.list_claims().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_status_mirrors_the_claim_and_turns_ready_once_the_entry_is_set() {
        let r = rig(cfg());
        let sb = settle(&r, &sandbox(false, false)).await;
        // banlieue binds the claim and mirrors the member's certificate onto it.
        r.claims.patch_claim_status(
            "sandboxes",
            "sb-1",
            &json!({ "phase": "Bound", "virtualMachineRef": { "name": "member-1" }, "poolRef": { "name": "pool" }, "tpmEndorsementCertificates": [RSA_EK_PEM],
                    "addresses": [{ "type": "InternalIP", "address": "192.0.2.10" }], "boundAt": "2026-10-14T10:00:00Z", "expiresAt": "2026-10-14T10:10:00Z" }),
        );
        // Bound, but the watcher has not declared the entry: not ready, polled.
        let action = r.watcher.reconcile_sandbox(&sb).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_millis(5)));
        let sb = r.claims.sandbox("sandboxes", "sb-1").unwrap();
        let st = sb.status.clone().unwrap();
        assert_eq!(st.phase, SandboxPhase::Bound);
        assert_eq!(
            st.virtual_machine_ref.as_ref().map(|m| m.name.as_str()),
            Some("member-1")
        );
        // The pool the member came from, from the claim's status (ADR-0044 decision 5).
        assert_eq!(st.pool_ref.as_ref().map(|p| p.name.as_str()), Some("pool"));
        assert_eq!(st.addresses, vec!["192.0.2.10".to_owned()]);
        assert!(st.bound_at.is_some() && st.expires_at.is_some());
        assert!(!st.entry_set && !st.ready);

        // The claim watcher binds it by the EK, as in production.
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        let claim = r.claims.claim("sandboxes", "sb-1").unwrap();
        r.watcher.reconcile_claim(&claim).await.unwrap();
        assert_eq!(
            r.entries.names(),
            vec![claim_entry_name(claim_uid_of(&claim).unwrap())]
        );
        let action = r.watcher.reconcile_sandbox(&sb).await.unwrap();
        assert_eq!(action, Action::await_change());
        let st = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert!(st.entry_set && st.ready, "Bound and set: ready");

        // The TTL fires: Releasing mirrors, and ready drops.
        r.claims
            .patch_claim_status("sandboxes", "sb-1", &json!({ "phase": "Releasing" }));
        let sb = r.claims.sandbox("sandboxes", "sb-1").unwrap();
        r.watcher
            .reconcile_claim(&r.claims.claim("sandboxes", "sb-1").unwrap())
            .await
            .unwrap();
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let st = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Releasing);
        assert!(!st.ready && !st.entry_set);
        assert_eq!(r.entries.names(), Vec::<String>::new());
    }

    fn scoped_cfg(namespaces: &[&str]) -> WatcherConfig {
        let rules = vec![mediatore_proto::EndpointRule {
            method: "GET".into(),
            path: "/a/**".into(),
        }];
        WatcherConfig {
            scopes: [(
                "api.example".to_owned(),
                namespaces
                    .iter()
                    .map(|n| ((*n).to_owned(), rules.clone()))
                    .collect(),
            )]
            .into_iter()
            .collect(),
            ..cfg()
        }
    }

    #[tokio::test]
    async fn a_declarative_sandbox_naming_a_scoped_audience_in_an_unlisted_namespace_is_refused() {
        // ADR-0053 decision 4: the declarative path (a sandbox created through the Kubernetes API) does not
        // go through POST /v1/claims, so the reconciler refuses it too, as it refuses an unknown audience.
        let r = rig(scoped_cfg(&["team-a"]));
        let sb = sandbox(true, false); // namespace "sandboxes"
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let st = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        assert_eq!(
            st.reason.as_deref(),
            Some("audience api.example is not configured"),
            "the same words as an audience that does not exist"
        );
        assert!(r.claims.claim("sandboxes", "sb-1").is_none(), "no claim");
    }

    #[tokio::test]
    async fn a_declarative_sandbox_in_a_listed_namespace_is_not_refused_for_its_audience() {
        let r = rig(scoped_cfg(&["sandboxes", "team-a"]));
        let sb = sandbox(true, false);
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let st = r.claims.sandbox("sandboxes", "sb-1").unwrap().status;
        assert_ne!(
            st.and_then(|s| s.reason).as_deref(),
            Some("audience api.example is not configured")
        );
        assert!(
            r.claims.claim("sandboxes", "sb-1").is_some(),
            "a claim is created"
        );
    }

    #[test]
    fn the_shadow_comparison_reads_the_rules_of_the_sandboxs_namespace() {
        let c = scoped_cfg(&["team-a"]);
        let a = c.audiences_in("team-a");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].rules[0].path, "/a/**");
        assert!(
            c.audiences_in("team-b").is_empty(),
            "not usable there, so not compared"
        );
        let open = cfg();
        assert_eq!(
            open.audiences_in("anything").len(),
            1,
            "unscoped: unchanged"
        );
    }

    #[tokio::test]
    async fn an_audience_or_issuer_outside_the_configuration_fails_the_sandbox_without_a_claim() {
        for (mutate, want) in [
            (
                Box::new(|sb: &mut AgentSandbox| sb.spec.audiences.push("api://elsewhere".into()))
                    as Box<dyn Fn(&mut AgentSandbox)>,
                "audience api://elsewhere is not configured",
            ),
            (
                Box::new(|sb: &mut AgentSandbox| {
                    sb.spec.subject.issuer = "https://other.example.com".into();
                }),
                "issuer https://other.example.com is not configured",
            ),
            (
                Box::new(|sb: &mut AgentSandbox| sb.spec.ttl_seconds = 0),
                "ttlSeconds must be positive",
            ),
        ] {
            let r = rig(cfg());
            let mut sb = sandbox(true, false);
            mutate(&mut sb);
            r.claims.put_sandbox(sb.clone());
            assert_eq!(
                r.watcher.reconcile_sandbox(&sb).await.unwrap(),
                Action::await_change()
            );
            let st = r
                .claims
                .sandbox("sandboxes", "sb-1")
                .unwrap()
                .status
                .unwrap();
            assert_eq!(st.phase, SandboxPhase::Failed, "{want}");
            assert_eq!(st.reason.as_deref(), Some(want));
            assert!(
                r.claims.claim("sandboxes", "sb-1").is_none(),
                "{want}: no claim"
            );
            assert!(
                r.store.list_claims().await.unwrap().is_empty(),
                "{want}: no record"
            );
        }
    }

    /// ADR-0045 decision 11: a sandbox that asks for its workload's output on a broker that
    /// stores none is refused before any claim exists; with `logs.enabled` the same spec is
    /// admitted.
    #[tokio::test]
    async fn a_sandbox_asking_for_its_output_is_refused_unless_the_broker_stores_it() {
        let r = rig(cfg());
        let mut sb = sandbox(true, false);
        sb.spec.workload.logs = true;
        r.claims.put_sandbox(sb.clone());
        assert_eq!(
            r.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        let st = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        assert_eq!(
            st.reason.as_deref(),
            Some("workload.logs: output capture is not enabled on this broker")
        );
        assert!(r.claims.claim("sandboxes", "sb-1").is_none(), "no claim");

        let r = rig(WatcherConfig {
            logs_enabled: true,
            ..cfg()
        });
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let held = r.claims.sandbox("sandboxes", "sb-1").unwrap();
        assert_ne!(
            held.status.as_ref().unwrap().phase,
            SandboxPhase::Failed,
            "with output storage on the opt-in is admitted: {:?}",
            held.status.as_ref().unwrap().reason
        );
        assert!(
            r.claims.claim("sandboxes", "sb-1").is_some(),
            "the claim is created"
        );
    }

    #[tokio::test]
    async fn an_image_on_a_placed_registry_needs_its_audience_named() {
        // ADR-0043 decision 1: a registry the gateway places a credential for serves a claim only when the claim names that
        // audience (and, being delegated, carries a credential for it): an image there with no audience is refused
        // before any claim exists, instead of failing the pull later as an anonymous one.
        let placed = WatcherConfig {
            audiences: vec![Audience::named("api.example"), Audience::named("registry")],
            registry_audiences: Some(
                [(
                    "registry".to_owned(),
                    ["registry.home.example".to_owned()].into_iter().collect(),
                )]
                .into_iter()
                .collect(),
            ),
            placed_registries: [("registry.home.example".to_owned(), "registry".to_owned())]
                .into_iter()
                .collect(),
            ..cfg()
        };
        let r = rig(placed.clone());
        let mut sb = sandbox(true, false);
        sb.spec.workload.image = "registry.home.example/team/image:1".into();
        r.claims.put_sandbox(sb.clone());
        assert_eq!(
            r.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        let st = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        let reason = st.reason.unwrap_or_default();
        assert!(
            reason.contains("registry.home.example") && reason.contains("not granted"),
            "{reason}"
        );
        assert!(
            r.claims.claim("sandboxes", "sb-1").is_none(),
            "no claim was created"
        );

        // Naming the audience clears this check (the delegation is checked where it always was).
        let r = rig(placed);
        let mut sb = sandbox(true, false);
        sb.spec.workload.image = "registry.home.example/team/image:1".into();
        sb.spec.audiences = vec!["registry".into()];
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let st = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert!(
            !st.reason
                .unwrap_or_default()
                .contains("name audience registry"),
            "naming it is enough for this check"
        );
    }

    #[tokio::test]
    async fn an_image_the_pool_cannot_reach_or_cannot_parse_fails_the_sandbox_without_a_claim() {
        // A gateway-era environment whose only registry audience serves the mirror (ADR-0063).
        let reachable = WatcherConfig {
            registry_audiences: Some(
                [(
                    "mirror".to_owned(),
                    ["registry.internal:5000".to_owned()].into_iter().collect(),
                )]
                .into_iter()
                .collect(),
            ),
            ..cfg()
        };
        for (cfg, image, want) in [
            (
                reachable.clone(),
                "ghcr.io/firestoned/agent:1",
                "registry ghcr.io is not granted to this sandbox: name an audience with role: registry that serves it (ADR-0063)",
            ),
            (cfg(), "not a reference!", "workload image"),
        ] {
            let r = rig(cfg);
            let mut sb = sandbox(true, false);
            sb.spec.workload.image = image.into();
            r.claims.put_sandbox(sb.clone());
            assert_eq!(
                r.watcher.reconcile_sandbox(&sb).await.unwrap(),
                Action::await_change()
            );
            let st = r
                .claims
                .sandbox("sandboxes", "sb-1")
                .unwrap()
                .status
                .unwrap();
            assert_eq!(st.phase, SandboxPhase::Failed, "{image}");
            assert!(
                st.reason.as_deref().unwrap_or("").contains(want),
                "{image}: {:?}",
                st.reason
            );
            assert!(
                r.claims.claim("sandboxes", "sb-1").is_none(),
                "{image}: no claim"
            );
        }
        // The mirror, for a sandbox that names the registry audience serving it, and any registry without gateways,
        // are fine.
        let mut granted = reachable;
        granted.audiences.push(Audience::named("mirror"));
        for (cfg, image, audiences) in [
            (
                granted,
                "registry.internal:5000/team/agent:1",
                vec!["mirror".to_string()],
            ),
            (cfg(), "ghcr.io/firestoned/agent:1", vec![]),
        ] {
            let r = rig(cfg);
            let mut sb = sandbox(true, false);
            sb.spec.workload.image = image.into();
            sb.spec.audiences.extend(audiences);
            assert_eq!(r.watcher.refuse(&sb.spec, "sandboxes"), None, "{image}");
        }
    }

    #[tokio::test]
    async fn a_config_change_after_the_claim_exists_does_not_fail_the_sandbox() {
        let r = rig(cfg());
        let sb = settle(&r, &sandbox(false, false)).await;
        let claim = r.claims.claim("sandboxes", "sb-1").unwrap();
        // The broker restarts with the audience removed from its configuration.
        let changed = rig(WatcherConfig {
            audiences: vec![],
            ..cfg()
        });
        changed.claims.put_sandbox(sb.clone());
        changed.claims.put_claim(claim);
        assert_eq!(
            changed.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        let st = changed
            .claims
            .sandbox("sandboxes", "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Pending, "mirrored, not refused");
        assert!(st.reason.is_none());
        // A new request naming that audience is refused.
        let mut fresh = sandbox(true, false);
        fresh.metadata.name = Some("sb-2".into());
        fresh.metadata.uid = Some(Uuid::new_v4().to_string());
        changed.claims.put_sandbox(fresh.clone());
        changed.watcher.reconcile_sandbox(&fresh).await.unwrap();
        assert_eq!(
            changed
                .claims
                .sandbox("sandboxes", "sb-2")
                .unwrap()
                .status
                .unwrap()
                .phase,
            SandboxPhase::Failed
        );
    }

    #[tokio::test]
    async fn a_claim_that_disappears_is_never_recreated() {
        let r = rig(cfg());
        let sb = settle(&r, &sandbox(false, false)).await;
        let uid = claim_uid_of(&r.claims.claim("sandboxes", "sb-1").unwrap()).unwrap();
        // banlieue (or the watcher's fail path) deleted it.
        r.claims.remove_claim("sandboxes", "sb-1");
        assert_eq!(
            r.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        let st = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        assert_eq!(st.reason.as_deref(), Some("claim gone"));
        assert_eq!(
            st.claim_uid.as_deref(),
            Some(uid.to_string().as_str()),
            "the old claim stays recorded"
        );
        assert!(
            r.claims.claim("sandboxes", "sb-1").is_none(),
            "no second claim"
        );
        assert_eq!(r.store.list_claims().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_record_lost_in_a_restart_is_rebuilt_from_the_resource_and_the_claim_rebound() {
        // The in-memory store is empty after a restart (threat model R-5); the sandbox and
        // its Bound claim are still in the cluster.
        let r = rig(cfg());
        let sb = settle(&r, &sandbox(false, false)).await;
        r.claims.patch_claim_status(
            "sandboxes",
            "sb-1",
            &json!({ "phase": "Bound", "tpmEndorsementCertificates": [RSA_EK_PEM] }),
        );
        let claim = r.claims.claim("sandboxes", "sb-1").unwrap();
        let uid = claim_uid_of(&claim).unwrap();
        let restarted = rig(cfg());
        restarted.claims.put_sandbox(sb.clone());
        restarted.claims.put_claim(claim.clone());
        // The node registers again (the guest retries), the reconciler rebuilds the record.
        restarted
            .store
            .put_node(node(RSA_EK_HASH, false))
            .await
            .unwrap();
        assert_eq!(
            restarted.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::requeue(Duration::from_millis(5))
        );
        let rec = restarted.store.get_claim(uid).await.unwrap();
        assert_eq!(rec.subject.id, "octocat");
        assert!(rec.entry_id.is_none());
        // The claim watcher binds it as if for the first time; the entry name is the same.
        restarted.watcher.reconcile_claim(&claim).await.unwrap();
        assert_eq!(restarted.entries.names(), vec![claim_entry_name(uid)]);
        let sb = restarted.claims.sandbox("sandboxes", "sb-1").unwrap();
        assert_eq!(
            restarted.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        assert!(
            restarted
                .claims
                .sandbox("sandboxes", "sb-1")
                .unwrap()
                .status
                .unwrap()
                .ready
        );
    }

    #[tokio::test]
    async fn a_claim_of_the_same_name_not_owned_by_the_sandbox_is_refused() {
        let r = rig(cfg());
        let sb = sandbox(true, false);
        r.claims.put_sandbox(sb.clone());
        let mut stranger = claim_for(&sb).unwrap();
        stranger.metadata.owner_references = None;
        stranger.metadata.uid = Some(Uuid::new_v4().to_string());
        r.claims.put_claim(stranger);
        assert_eq!(
            r.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        let st = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        assert!(st.reason.unwrap().contains("not owned"));
        assert!(
            r.store.list_claims().await.unwrap().is_empty(),
            "no record for a claim that is not ours"
        );
    }

    #[tokio::test]
    async fn deletion_releases_then_waits_for_the_claim_to_go() {
        let r = rig(cfg());
        r.claims.hold_deleted_claims(true);
        settle(&r, &sandbox(false, false)).await;
        r.claims.patch_claim_status(
            "sandboxes",
            "sb-1",
            &json!({ "phase": "Bound", "tpmEndorsementCertificates": [RSA_EK_PEM] }),
        );
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        let claim = r.claims.claim("sandboxes", "sb-1").unwrap();
        let uid = claim_uid_of(&claim).unwrap();
        r.watcher.reconcile_claim(&claim).await.unwrap();
        assert_eq!(r.entries.names().len(), 1);

        let mut deleting = r.claims.sandbox("sandboxes", "sb-1").unwrap();
        deleting.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH));
        r.claims.put_sandbox(deleting.clone());
        // First pass: entry retracted, record revoked, claim deleted; finalizer kept while
        // banlieue's finalizer holds the claim.
        let action = r.watcher.reconcile_sandbox(&deleting).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_millis(5)));
        assert_eq!(r.entries.names(), Vec::<String>::new(), "entry first");
        assert!(
            r.store.get_claim(uid).await.unwrap().revoked_at.is_some(),
            "then the record"
        );
        let held = r
            .claims
            .claim("sandboxes", "sb-1")
            .expect("held by banlieue's finalizer");
        assert!(held.metadata.deletion_timestamp.is_some());
        assert_eq!(
            r.claims.sandbox("sandboxes", "sb-1").unwrap().finalizers(),
            &[FINALIZER.to_owned()]
        );
        // Same again while the member is destroyed: nothing new, still waiting.
        assert_eq!(
            r.watcher.reconcile_sandbox(&deleting).await.unwrap(),
            Action::requeue(Duration::from_millis(5))
        );
        assert_eq!(r.claims.deleted().len(), 1, "the claim is deleted once");

        // The claim is gone: the finalizer goes with it.
        r.claims.remove_claim("sandboxes", "sb-1");
        assert_eq!(
            r.watcher.reconcile_sandbox(&deleting).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(
            r.claims.sandbox("sandboxes", "sb-1").unwrap().finalizers(),
            &Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn deleting_a_sandbox_whose_claim_banlieue_already_removed_releases_the_record() {
        let r = rig(cfg());
        let sb = settle(&r, &sandbox(false, false)).await;
        let uid = claim_uid_of(&r.claims.claim("sandboxes", "sb-1").unwrap()).unwrap();
        r.claims.remove_claim("sandboxes", "sb-1");
        let mut deleting = sb;
        deleting.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH));
        assert_eq!(
            r.watcher.reconcile_sandbox(&deleting).await.unwrap(),
            Action::await_change()
        );
        assert!(r.store.get_claim(uid).await.unwrap().revoked_at.is_some());
        assert_eq!(
            r.claims.sandbox("sandboxes", "sb-1").unwrap().finalizers(),
            &Vec::<String>::new()
        );
        // A sandbox that never had our finalizer is not ours to hold.
        let bare = sandbox(false, true);
        assert_eq!(
            r.watcher.reconcile_sandbox(&bare).await.unwrap(),
            Action::await_change()
        );
    }

    /// A second sandbox, `sb-2` in namespace `other`, finalized and being deleted, whose
    /// status names `claim_uid`: what a principal holding `agentsandboxes/status` in its
    /// own namespace can write.
    fn deleting_stranger(claim_uid: Uuid) -> AgentSandbox {
        let mut sb = sandbox(true, true);
        sb.metadata.name = Some("sb-2".into());
        sb.metadata.namespace = Some("other".into());
        sb.metadata.uid = Some("1b2c3d4e-5f60-4718-892a-3b4c5d6e7f80".into());
        sb.status = Some(AgentSandboxStatus {
            phase: SandboxPhase::Bound,
            claim_ref: Some(LocalObjectReference {
                name: "sb-2".into(),
            }),
            claim_uid: Some(claim_uid.to_string()),
            ..AgentSandboxStatus::default()
        });
        sb
    }

    #[tokio::test]
    async fn deleting_a_sandbox_whose_status_names_another_sandboxes_claim_releases_nothing() {
        let r = rig(cfg());
        settle(&r, &sandbox(false, false)).await;
        r.claims.patch_claim_status(
            "sandboxes",
            "sb-1",
            &json!({ "phase": "Bound", "tpmEndorsementCertificates": [RSA_EK_PEM] }),
        );
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        let claim = r.claims.claim("sandboxes", "sb-1").unwrap();
        let uid = claim_uid_of(&claim).unwrap();
        r.watcher.reconcile_claim(&claim).await.unwrap();
        assert_eq!(r.entries.names(), vec![claim_entry_name(uid)]);

        let stranger = deleting_stranger(uid);
        r.claims.put_sandbox(stranger.clone());
        assert_eq!(
            r.watcher.reconcile_sandbox(&stranger).await.unwrap(),
            Action::await_change()
        );
        let rec = r.store.get_claim(uid).await.unwrap();
        assert!(
            rec.revoked_at.is_none(),
            "the other sandbox's record is not revoked"
        );
        assert_eq!(
            r.entries.names(),
            vec![claim_entry_name(uid)],
            "its entry is not retracted"
        );
        assert!(
            r.claims.claim("sandboxes", "sb-1").is_some(),
            "its claim is not deleted"
        );
        // The forger's own sandbox, which holds no record, goes as one never bound does.
        assert_eq!(
            r.claims.sandbox("other", "sb-2").unwrap().finalizers(),
            &Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn a_record_naming_no_sandbox_is_not_released_through_a_sandboxes_status() {
        // Fail closed: a record that says nothing of its sandbox is nobody's to release
        // from a status.
        let r = rig(cfg());
        let own = sandbox(true, true);
        let uid = Uuid::new_v4();
        let mut rec = record_for(&own, uid, None);
        rec.sandbox_uid = None;
        r.store.put_claim(rec).await.unwrap();
        let mut deleting = own;
        deleting.status = Some(AgentSandboxStatus {
            claim_uid: Some(uid.to_string()),
            ..AgentSandboxStatus::default()
        });
        r.claims.put_sandbox(deleting.clone());
        r.watcher.reconcile_sandbox(&deleting).await.unwrap();
        assert!(r.store.get_claim(uid).await.unwrap().revoked_at.is_none());
    }

    /// A `status.claimRef` nobody but the broker should have written skips the refusal of
    /// `refuse`, and still gets nothing: with no owned claim behind it the sandbox is
    /// failed as one whose claim is gone, and no claim and no record are made.
    #[tokio::test]
    async fn a_forged_claim_ref_on_a_sandbox_that_would_be_refused_creates_no_claim() {
        let r = rig(WatcherConfig {
            audiences: vec![],
            ..cfg()
        });
        let mut sb = sandbox(true, false);
        sb.status = Some(AgentSandboxStatus {
            phase: SandboxPhase::Bound,
            claim_ref: Some(LocalObjectReference {
                name: "sb-1".into(),
            }),
            ..AgentSandboxStatus::default()
        });
        r.claims.put_sandbox(sb.clone());
        assert_eq!(
            r.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        let st = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        assert!(!st.ready);
        assert!(
            r.claims.claim("sandboxes", "sb-1").is_none(),
            "no claim for an audience this broker is not configured for"
        );
        assert!(r.store.list_claims().await.unwrap().is_empty());
    }

    /// A reflector over the testkit's freshly signed bundle, admitted at the real clock
    /// with the namespace's first list completed, and the sandbox in that policy's
    /// namespace naming it, asking for the bundle's audience.
    struct Admitted {
        reflector: BundleReflector,
        payload: BundlePayload,
        sb: AgentSandbox,
    }

    impl Admitted {
        fn cache(&self) -> Arc<BundleCache> {
            self.reflector.cache()
        }

        /// The same policy name signed into `namespace` as a policy of that namespace's own
        /// (another uid), admitted there, and that namespace's first list completed.
        async fn also_in(&self, namespace: &str) {
            let mut content = self.payload.content.clone();
            content.policy.namespace = namespace.to_owned();
            content.policy.uid = Uuid::new_v4().to_string();
            let fresh = mediatore_testkit::policy::signed_bundle(
                Timestamp::now(),
                self.payload.meta.version,
                content,
            );
            let cm = mediatore_testkit::policy::bundle_configmap(
                namespace,
                "agent-bundle",
                &fresh.envelope,
            );
            let outcome = self.reflector.applied(&cm).await;
            assert!(matches!(outcome, Outcome::Admitted { .. }), "{outcome:?}");
            self.reflector
                .resynced(namespace, &std::collections::HashSet::from([cm.name_any()]));
        }

        /// A later version of the bundle with `edit` applied to its content, admitted.
        async fn admit(&self, version: u64, edit: impl FnOnce(&mut BundlePayload)) {
            let mut next = self.payload.clone();
            edit(&mut next);
            let fresh =
                mediatore_testkit::policy::signed_bundle(Timestamp::now(), version, next.content);
            let policy = &fresh.payload.content.policy;
            let cm = mediatore_testkit::policy::bundle_configmap(
                &policy.namespace,
                &format!("{}-bundle", policy.name),
                &fresh.envelope,
            );
            assert_eq!(
                self.reflector.applied(&cm).await,
                Outcome::Admitted {
                    policy: format!("{}/{}", policy.namespace, policy.name),
                    version,
                }
            );
        }
    }

    async fn admitted_bundle(version: u64) -> Admitted {
        admitted_watching(version, &[], true).await
    }

    /// [`admitted_bundle`] with the reflector also reading the namespaces `beside` the
    /// policy's own (nothing in them yet), and every first list completed only when `listed`.
    async fn admitted_watching(version: u64, beside: &[&str], listed: bool) -> Admitted {
        let mediatore_testkit::policy::FreshBundle {
            keys,
            envelope,
            payload,
        } = mediatore_testkit::policy::fresh_bundle(Timestamp::now(), version);
        let policy = payload.content.policy.clone();
        let mut watched = vec![policy.namespace.clone()];
        watched.extend(beside.iter().map(|n| (*n).to_owned()));
        let reflector = BundleReflector::new(
            Arc::new(mediatore_store::MemoryStore::default()),
            keys,
            watched,
        );
        let cm = mediatore_testkit::policy::bundle_configmap(
            &policy.namespace,
            &format!("{}-bundle", policy.name),
            &envelope,
        );
        assert_eq!(
            reflector.applied(&cm).await,
            Outcome::Admitted {
                policy: format!("{}/{}", policy.namespace, policy.name),
                version,
            }
        );
        if listed {
            reflector.resynced(
                &policy.namespace,
                &std::collections::HashSet::from([cm.name_any()]),
            );
            for namespace in beside {
                reflector.resynced(namespace, &std::collections::HashSet::new());
            }
        }
        let mut sb = sandbox(true, false);
        sb.metadata.namespace = Some(policy.namespace.clone());
        sb.spec.policy_ref = Some(LocalObjectReference {
            name: policy.name.clone(),
        });
        sb.spec.audiences = vec!["internal-git".into()];
        Admitted {
            reflector,
            payload,
            sb,
        }
    }

    #[tokio::test]
    async fn a_sandbox_naming_a_policy_records_the_bundle_it_was_admitted_under() {
        let a = admitted_bundle(5).await;
        let (payload, sb) = (&a.payload, a.sb.clone());
        let namespace = sb.namespace().unwrap();
        let r = rig_with(cfg_with_git(), Some(a.cache()));
        r.claims.put_sandbox(sb.clone());
        assert_eq!(
            r.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        let claim = r.claims.claim(&namespace, "sb-1").expect("claim created");
        let rec = r
            .store
            .get_claim(claim_uid_of(&claim).unwrap())
            .await
            .unwrap();
        assert_eq!(
            rec.policy_uid.as_deref(),
            Some(payload.content.policy.uid.as_str())
        );
        assert_eq!(rec.bundle_version, Some(5));
        // Admitted as any other sandbox: naming a policy grants and refuses nothing.
        let st = r
            .claims
            .sandbox(&namespace, "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Pending);
        assert!(st.reason.is_none());
    }

    #[tokio::test]
    async fn a_sandbox_whose_policy_has_no_verified_bundle_is_admitted_with_nothing_recorded() {
        // The policy named has no bundle in the cache: no policy at all, or none that
        // verified (ADR-0026 decision 8: nothing new fails closed).
        let r = rig(cfg());
        let mut sb = sandbox(true, false);
        sb.spec.policy_ref = Some(LocalObjectReference {
            name: "unsigned".into(),
        });
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let uid = claim_uid_of(&r.claims.claim("sandboxes", "sb-1").unwrap()).unwrap();
        let rec = r.store.get_claim(uid).await.unwrap();
        assert!(rec.policy_uid.is_none() && rec.bundle_version.is_none());
        assert_eq!(
            r.claims
                .sandbox("sandboxes", "sb-1")
                .unwrap()
                .status
                .unwrap()
                .phase,
            SandboxPhase::Pending
        );
    }

    #[tokio::test]
    async fn a_bundle_admitted_after_the_record_exists_does_not_rewrite_it() {
        // The record says what was current when the claim was created (decision 6); a
        // later bundle is the comparison's business, not the record's.
        let a = admitted_bundle(5).await;
        let sb = a.sb.clone();
        let namespace = sb.namespace().unwrap();
        let r = rig_with(cfg_with_git(), Some(Arc::new(BundleCache::default())));
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let uid = claim_uid_of(&r.claims.claim(&namespace, "sb-1").unwrap()).unwrap();
        assert!(r.store.get_claim(uid).await.unwrap().policy_uid.is_none());
        // The bundle arrives; the same sandbox is reconciled again.
        let later = Rig {
            watcher: Watcher::new(
                Reconciler {
                    store: r.store.clone(),
                    spire: r.entries.clone(),
                    naming: mediatore_spire::Naming {
                        trust_domain: "sandbox.test".into(),
                    },
                },
                r.claims.clone(),
                cfg_with_git(),
            )
            .with_bundles(a.reflector.cache()),
            store: r.store.clone(),
            entries: r.entries.clone(),
            claims: r.claims.clone(),
        };
        let sb = later.claims.sandbox(&namespace, "sb-1").unwrap();
        later.watcher.reconcile_sandbox(&sb).await.unwrap();
        let rec = later.store.get_claim(uid).await.unwrap();
        assert!(
            rec.policy_uid.is_none() && rec.bundle_version.is_none(),
            "created once, never rewritten"
        );
    }

    // ----- ADR-0054: which policies a namespace may name -----

    /// `policy.egress: enforce`, the broker otherwise as the conformance bundle allows.
    /// ADR-0061 decision 4: the condition mirrors the record's follow verdict.
    #[test]
    fn policy_followed_mirrors_the_records_verdict() {
        let mut rec = test_record_for_followed();
        assert!(
            followed(vec![], &rec, Some(1)).is_empty(),
            "absent before the guest rendered"
        );
        rec.rendered = Some(mediatore_proto::Rendered {
            bundle_version: 2,
            bundle_digest: "sha256:2".into(),
            routes: vec![],
            egress: vec![],
        });
        let inside = followed(vec![], &rec, Some(1));
        assert_eq!(
            (inside[0].status.as_str(), inside[0].reason.as_str()),
            ("True", "Inside")
        );
        rec.follow = Some(mediatore_proto::FollowRefusal {
            reason: mediatore_proto::FollowReason::RenderedWider,
            rendered_version: Some(2),
            current_version: 3,
            enforced: true,
            at: jiff::Timestamp::now(),
        });
        let refused = followed(inside, &rec, Some(1));
        assert_eq!(refused.len(), 1, "replaced, not added");
        assert_eq!(
            (refused[0].status.as_str(), refused[0].reason.as_str()),
            ("False", "Refused")
        );
        assert_eq!(
            refused[0].message,
            "rendered_wider: rendered under bundle v2, current v3"
        );
        rec.follow.as_mut().unwrap().enforced = false;
        let held = refused[0].last_transition_time.clone();
        let shadow = followed(refused, &rec, Some(1));
        assert_eq!(shadow[0].reason, "WouldRefuse");
        assert_eq!(shadow[0].last_transition_time, held, "the status held");
    }

    fn test_record_for_followed() -> ClaimRecord {
        record_for(&sandbox(true, false), Uuid::new_v4(), None)
    }

    fn enforcing() -> WatcherConfig {
        WatcherConfig {
            egress_mode: EgressMode::Enforce,
            ..cfg_with_git()
        }
    }

    fn drawing(sandbox_namespace: &str, from: &[&str]) -> crate::policy::PolicySources {
        crate::policy::PolicySources::new(BTreeMap::from([(
            sandbox_namespace.to_owned(),
            from.iter().map(|n| (*n).to_owned()).collect(),
        )]))
    }

    fn status_of(r: &Rig, namespace: &str) -> AgentSandboxStatus {
        r.claims
            .sandbox(namespace, "sb-1")
            .expect("the sandbox")
            .status
            .expect("a status")
    }

    async fn session_is_parked(r: &Rig) -> bool {
        r.store
            .take_session(Uuid::parse_str(SB_UID).unwrap())
            .await
            .unwrap()
            .is_some()
    }

    /// The sentence a requester reads, for `policy` named from `namespace`.
    fn not_resolved_reason(policy: &str, namespace: &str) -> String {
        format!(
            "policy_not_resolved: no verified bundle for policy {policy} in the namespaces {namespace} draws its policies from"
        )
    }

    #[tokio::test]
    async fn a_sandbox_in_the_pools_namespace_finds_its_policy_through_a_sources_entry() {
        // The shape of the live run of 2026-11-05: the pool and its sandboxes in one
        // namespace, notaio's bundles in another. Since ADR-0054 the operator says so
        // (`policy.sources`); the watched list alone no longer does.
        let a = admitted_bundle(3).await;
        let mut sb = a.sb.clone();
        sb.metadata.namespace = Some("pool-ns".into());
        let r = rig_with(
            WatcherConfig {
                policy_sources: drawing("pool-ns", &["conformance"]),
                ..enforcing()
            },
            Some(a.cache()),
        );
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let st = status_of(&r, "pool-ns");
        assert_eq!(st.phase, SandboxPhase::Pending, "{:?}", st.reason);
        let claim = r.claims.claim("pool-ns", "sb-1").expect("claim created");
        let rec = r
            .store
            .get_claim(claim_uid_of(&claim).unwrap())
            .await
            .unwrap();
        assert_eq!(rec.bundle_version, Some(3));
        assert_eq!(
            rec.policy_uid.as_deref(),
            Some(a.payload.content.policy.uid.as_str())
        );
        assert_eq!(rec.namespace, "pool-ns");
    }

    #[tokio::test]
    async fn under_enforce_a_policy_ref_that_does_not_resolve_is_refused_before_any_claim_exists() {
        // The policy is real and verified, in a watched namespace this sandbox's namespace
        // does not draw from.
        let a = admitted_watching(1, &["team-a"], true).await;
        let policy = a.payload.content.policy.name.clone();
        let mut sb = a.sb.clone();
        sb.metadata.namespace = Some("team-a".into());
        let r = rig_with(enforcing(), Some(a.cache()));
        r.store.put_session(parked_session()).await.unwrap();
        r.claims.put_sandbox(sb.clone());
        assert_eq!(
            r.watcher.reconcile_sandbox(&sb).await.unwrap(),
            Action::await_change()
        );
        let st = status_of(&r, "team-a");
        assert_eq!(st.phase, SandboxPhase::Failed);
        assert_eq!(
            st.reason.as_deref(),
            Some(not_resolved_reason(&policy, "team-a").as_str())
        );
        assert!(st.claim_ref.is_none() && st.claim_uid.is_none());
        assert_eq!(st.observed_generation, Some(1));
        let held = r.claims.sandbox("team-a", "sb-1").unwrap();
        let c = conformant(&held);
        assert_eq!((c.status.as_str(), c.reason.as_str()), ("False", "Gaps"));
        assert!(c.message.starts_with("P011"), "{}", c.message);
        assert!(
            r.claims.claim("team-a", "sb-1").is_none(),
            "no claim is created"
        );
        assert!(
            r.store.list_claims().await.unwrap().is_empty(),
            "no record is written"
        );
        assert!(
            !session_is_parked(&r).await,
            "the parked session is dropped, as for every other refusal"
        );
        // Settled: another pass creates nothing and patches nothing.
        let before = r.claims.patches();
        r.watcher.reconcile_sandbox(&held).await.unwrap();
        assert_eq!(r.claims.patches(), before);
        assert!(r.claims.claim("team-a", "sb-1").is_none());
    }

    #[tokio::test]
    async fn the_refusal_is_the_same_for_a_policy_elsewhere_and_a_policy_nowhere() {
        let a = admitted_watching(1, &["team-a"], true).await;
        let mut sb = a.sb.clone();
        sb.metadata.namespace = Some("team-a".into());
        // Elsewhere: the cache holds the policy, in `conformance`. Nowhere: the same watched
        // namespaces, read, holding nothing.
        let empty = BundleReflector::new(
            Arc::new(mediatore_store::MemoryStore::default()),
            mediatore_testkit::policy::fresh_bundle(Timestamp::now(), 1).keys,
            vec!["conformance".into(), "team-a".into()],
        );
        for namespace in ["conformance", "team-a"] {
            empty.resynced(namespace, &std::collections::HashSet::new());
        }
        let mut answers = Vec::new();
        for cache in [a.cache(), empty.cache()] {
            let r = rig_with(enforcing(), Some(cache));
            r.claims.put_sandbox(sb.clone());
            r.watcher.reconcile_sandbox(&sb).await.unwrap();
            let held = r.claims.sandbox("team-a", "sb-1").unwrap();
            let c = conformant(&held);
            let st = held.status.clone().unwrap();
            assert!(r.claims.claim("team-a", "sb-1").is_none());
            answers.push((
                st.phase,
                st.reason.unwrap_or_default(),
                c.status.clone(),
                c.reason.clone(),
                c.message.clone(),
            ));
        }
        assert_eq!(answers[0], answers[1]);
        assert_eq!(answers[0].0, SandboxPhase::Failed);
        assert!(
            !answers[0].1.contains("conformance") && !answers[0].4.contains("conformance"),
            "the answer does not say where else the name exists"
        );
    }

    #[tokio::test]
    async fn under_enforce_an_ambiguous_policy_ref_is_refused_with_p012() {
        let a = admitted_watching(1, &["team-b"], true).await;
        a.also_in("team-b").await;
        let policy = a.payload.content.policy.name.clone();
        let mut sb = a.sb.clone();
        sb.metadata.namespace = Some("infra".into());
        for listed in [["conformance", "team-b"], ["team-b", "conformance"]] {
            let r = rig_with(
                WatcherConfig {
                    policy_sources: drawing("infra", &listed),
                    ..enforcing()
                },
                Some(a.cache()),
            );
            r.claims.put_sandbox(sb.clone());
            r.watcher.reconcile_sandbox(&sb).await.unwrap();
            let st = status_of(&r, "infra");
            assert_eq!(st.phase, SandboxPhase::Failed, "{listed:?}");
            assert_eq!(
                st.reason.as_deref(),
                Some(not_resolved_reason(&policy, "infra").as_str()),
                "{listed:?}"
            );
            let held = r.claims.sandbox("infra", "sb-1").unwrap();
            let c = conformant(&held);
            assert_eq!((c.status.as_str(), c.reason.as_str()), ("False", "Gaps"));
            assert!(c.message.starts_with("P012"), "{listed:?}: {}", c.message);
            assert!(r.claims.claim("infra", "sb-1").is_none(), "{listed:?}");
            assert!(
                r.store.list_claims().await.unwrap().is_empty(),
                "{listed:?}: no record is written"
            );
        }
        // Each namespace on its own still runs under its own policy of that name.
        let r = rig_with(enforcing(), Some(a.cache()));
        r.claims.put_sandbox(a.sb.clone());
        r.watcher.reconcile_sandbox(&a.sb).await.unwrap();
        assert_eq!(status_of(&r, "conformance").phase, SandboxPhase::Pending);
    }

    #[tokio::test]
    async fn under_shadow_the_same_sandbox_is_created_and_reports_p011() {
        let a = admitted_watching(1, &["team-a"], true).await;
        let mut sb = a.sb.clone();
        sb.metadata.namespace = Some("team-a".into());
        let r = rig_with(cfg_with_git(), Some(a.cache()));
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let st = status_of(&r, "team-a");
        assert_eq!(st.phase, SandboxPhase::Pending);
        assert!(st.reason.is_none(), "shadow refuses nothing");
        let held = r.claims.sandbox("team-a", "sb-1").unwrap();
        let c = conformant(&held);
        assert_eq!((c.status.as_str(), c.reason.as_str()), ("False", "Gaps"));
        assert!(c.message.starts_with("P011"), "{}", c.message);
        // Created as before, and its record names no policy: nothing for a later switch to
        // enforce to start serving (decision 5).
        let claim = r.claims.claim("team-a", "sb-1").expect("claim created");
        let rec = r
            .store
            .get_claim(claim_uid_of(&claim).unwrap())
            .await
            .unwrap();
        assert!(rec.policy_uid.is_none() && rec.bundle_version.is_none());

        // The ambiguous name under shadow: created too, reported as P012.
        let a = admitted_watching(1, &["team-b"], true).await;
        a.also_in("team-b").await;
        let mut sb = a.sb.clone();
        sb.metadata.namespace = Some("infra".into());
        let r = rig_with(
            WatcherConfig {
                policy_sources: drawing("infra", &["conformance", "team-b"]),
                ..cfg_with_git()
            },
            Some(a.cache()),
        );
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        assert_eq!(status_of(&r, "infra").phase, SandboxPhase::Pending);
        let held = r.claims.sandbox("infra", "sb-1").unwrap();
        assert!(conformant(&held).message.starts_with("P012"));
        let claim = r.claims.claim("infra", "sb-1").expect("claim created");
        let rec = r
            .store
            .get_claim(claim_uid_of(&claim).unwrap())
            .await
            .unwrap();
        assert!(rec.policy_uid.is_none(), "never the first of the two");
    }

    #[tokio::test]
    async fn under_enforce_a_sandbox_is_held_while_its_sources_are_unread_and_no_claim_is_created()
    {
        // The bundle is already cached; the namespace's first list has not completed.
        let a = admitted_watching(1, &["team-b"], false).await;
        let r = rig_with(enforcing(), Some(a.cache()));
        r.store.put_session(parked_session()).await.unwrap();
        r.claims.put_sandbox(a.sb.clone());
        assert_eq!(
            r.watcher.reconcile_sandbox(&a.sb).await.unwrap(),
            Action::requeue(Duration::from_millis(5)),
            "held, and asked again: a first list raises no event"
        );
        let held = r.claims.sandbox("conformance", "sb-1").unwrap();
        let c = conformant(&held);
        assert_eq!(
            (c.status.as_str(), c.reason.as_str()),
            ("Unknown", "BundlesNotRead")
        );
        assert!(
            c.message.contains("conformance") && !c.message.contains("team-b"),
            "only this namespace's sources are waited for: {}",
            c.message
        );
        let st = held.status.clone().unwrap();
        assert_eq!(st.phase, SandboxPhase::Pending);
        assert!(st.reason.is_none() && st.claim_ref.is_none());
        assert!(r.claims.claim("conformance", "sb-1").is_none());
        assert!(
            r.store.list_claims().await.unwrap().is_empty(),
            "no record is written while the sources are unread"
        );
        // Its own namespace listed (team-b still is not): admitted, with the policy recorded
        // and the session it parked.
        a.reflector.resynced(
            "conformance",
            &std::collections::HashSet::from([format!("{}-bundle", a.payload.content.policy.name)]),
        );
        assert_eq!(
            r.watcher.reconcile_sandbox(&held).await.unwrap(),
            Action::await_change()
        );
        let claim = r.claims.claim("conformance", "sb-1").expect("claim");
        let rec = r
            .store
            .get_claim(claim_uid_of(&claim).unwrap())
            .await
            .unwrap();
        assert_eq!(
            rec.policy_uid.as_deref(),
            Some(a.payload.content.policy.uid.as_str())
        );
        assert_eq!(rec.refresh, Some(parked_session().refresh));
    }

    #[tokio::test]
    async fn under_enforce_a_record_for_a_sandbox_naming_a_policy_always_carries_its_uid() {
        let a = admitted_bundle(4).await;
        let r = rig_with(enforcing(), Some(a.cache()));
        r.claims.put_sandbox(a.sb.clone());
        r.watcher.reconcile_sandbox(&a.sb).await.unwrap();
        let records = r.store.list_claims().await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].policy_uid.as_deref(),
            Some(a.payload.content.policy.uid.as_str())
        );
        assert_eq!(records[0].bundle_version, Some(4));
        // Every way the name fails to resolve writes no record at all, never one without
        // the uid: elsewhere, nowhere, and unread.
        let elsewhere = admitted_watching(1, &["team-a"], true).await;
        let mut away = elsewhere.sb.clone();
        away.metadata.namespace = Some("team-a".into());
        let mut unsigned = a.sb.clone();
        unsigned.spec.policy_ref = Some(LocalObjectReference {
            name: "unsigned".into(),
        });
        let unread = admitted_watching(1, &[], false).await;
        for (what, cache, sb) in [
            ("elsewhere", elsewhere.cache(), away),
            ("nowhere", a.cache(), unsigned),
            ("unread", unread.cache(), unread.sb.clone()),
        ] {
            let r = rig_with(enforcing(), Some(cache));
            r.claims.put_sandbox(sb.clone());
            r.watcher.reconcile_sandbox(&sb).await.unwrap();
            assert!(
                r.store.list_claims().await.unwrap().is_empty(),
                "{what}: no record without the policy's uid"
            );
        }
    }

    #[tokio::test]
    async fn a_bundle_gone_between_admission_and_the_record_refuses_the_sandbox_and_deletes_the_claim()
     {
        // With the status naming the claim (the pass that created it landed its patch) and
        // without (it did not): the claim exists, its record was never written, and the
        // bundle has expired since.
        for status_landed in [true, false] {
            let a = admitted_bundle(1).await;
            let policy = a.payload.content.policy.name.clone();
            let mut sb = a.sb.clone();
            if status_landed {
                sb.status = Some(AgentSandboxStatus {
                    claim_ref: Some(LocalObjectReference {
                        name: "sb-1".into(),
                    }),
                    ..AgentSandboxStatus::default()
                });
            }
            let r = rig_with(enforcing(), Some(a.cache()));
            r.store.put_session(parked_session()).await.unwrap();
            r.claims.put_sandbox(sb.clone());
            r.claims.put_claim(owned_claim(&sb));
            assert_eq!(
                a.reflector
                    .sweep(Timestamp::now() + jiff::SignedDuration::from_hours(2)),
                1,
                "the bundle expired"
            );

            assert_eq!(
                r.watcher.reconcile_sandbox(&sb).await.unwrap(),
                Action::await_change(),
                "status_landed={status_landed}"
            );
            let st = status_of(&r, "conformance");
            assert_eq!(st.phase, SandboxPhase::Failed, "{status_landed}");
            assert_eq!(
                st.reason.as_deref(),
                Some(not_resolved_reason(&policy, "conformance").as_str()),
                "status_landed={status_landed}"
            );
            assert!(
                r.claims.claim("conformance", "sb-1").is_none(),
                "status_landed={status_landed}: the claim is deleted"
            );
            assert!(
                r.store.list_claims().await.unwrap().is_empty(),
                "status_landed={status_landed}: no record is written"
            );
            assert!(!session_is_parked(&r).await, "{status_landed}");
            // Never recreated: the claim stays named, and the next pass meets "claim gone".
            assert!(st.claim_ref.is_some(), "status_landed={status_landed}");
            let held = r.claims.sandbox("conformance", "sb-1").unwrap();
            r.watcher.reconcile_sandbox(&held).await.unwrap();
            assert!(r.claims.claim("conformance", "sb-1").is_none());
            let st = status_of(&r, "conformance");
            assert_eq!(st.phase, SandboxPhase::Failed);
            assert!(
                st.reason
                    .as_deref()
                    .unwrap_or_default()
                    .starts_with("policy_not_resolved"),
                "the reason outlives the claim"
            );
        }
    }

    #[tokio::test]
    async fn a_claim_whose_record_exists_is_not_judged_again_when_its_policy_goes() {
        // Admitted and recorded; the status patch never landed; the bundle then expires. The
        // request was accepted under the bundle of that moment: nothing is deleted here, and
        // what the record may still reach is the serving check's (decision 6).
        let a = admitted_bundle(1).await;
        let r = rig_with(enforcing(), Some(a.cache()));
        r.claims.put_sandbox(a.sb.clone());
        r.watcher.reconcile_sandbox(&a.sb).await.unwrap();
        assert_eq!(r.store.list_claims().await.unwrap().len(), 1);
        a.reflector
            .sweep(Timestamp::now() + jiff::SignedDuration::from_hours(2));
        // The object as it was before the pass that created the claim: no status.
        r.watcher.reconcile_sandbox(&a.sb).await.unwrap();
        assert!(r.claims.claim("conformance", "sb-1").is_some());
        assert_eq!(r.store.list_claims().await.unwrap().len(), 1);
        assert_eq!(status_of(&r, "conformance").phase, SandboxPhase::Pending);
    }

    #[tokio::test]
    async fn a_sandbox_without_a_policy_ref_is_created_as_before() {
        let a = admitted_bundle(1).await;
        // Enforcing, with the namespace read and with it unread: no policy named, nothing to
        // resolve, nothing to wait for.
        let unread = Arc::new(BundleCache::watching(vec!["conformance".into()]));
        for (what, cache) in [("read", a.cache()), ("unread", unread)] {
            let mut sb = a.sb.clone();
            sb.spec.policy_ref = None;
            let r = rig_with(enforcing(), Some(cache));
            r.claims.put_sandbox(sb.clone());
            assert_eq!(
                r.watcher.reconcile_sandbox(&sb).await.unwrap(),
                Action::await_change(),
                "{what}"
            );
            let st = status_of(&r, "conformance");
            assert_eq!(st.phase, SandboxPhase::Pending, "{what}");
            assert!(st.reason.is_none(), "{what}");
            let held = r.claims.sandbox("conformance", "sb-1").unwrap();
            assert!(
                conformant(&held).message.starts_with("P010"),
                "{what}: {}",
                conformant(&held).message
            );
            let claim = r.claims.claim("conformance", "sb-1").expect("claim");
            let rec = r
                .store
                .get_claim(claim_uid_of(&claim).unwrap())
                .await
                .unwrap();
            assert!(
                rec.policy_uid.is_none() && rec.bundle_version.is_none(),
                "{what}"
            );
        }
    }

    #[tokio::test]
    async fn a_conformant_sandbox_reports_policy_conformant_true() {
        let a = admitted_bundle(1).await;
        let r = rig_with(cfg_with_git(), Some(a.cache()));
        r.claims.put_sandbox(a.sb.clone());
        r.watcher.reconcile_sandbox(&a.sb).await.unwrap();
        let sb = r.claims.sandbox("conformance", "sb-1").unwrap();
        let c = conformant(&sb);
        assert_eq!(
            (c.status.as_str(), c.reason.as_str()),
            ("True", "Conformant")
        );
        assert!(
            c.message.contains("v1") && c.message.contains("agent"),
            "{}",
            c.message
        );
        assert_eq!(c.observed_generation, Some(1));
        assert_eq!(sb.status.as_ref().unwrap().phase, SandboxPhase::Pending);
        // Held across a pass with nothing new: no patch, the same transition time.
        let before = r.claims.patches();
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        assert_eq!(r.claims.patches(), before);
    }

    #[tokio::test]
    async fn a_gap_reports_false_with_its_codes_and_refuses_nothing() {
        let a = admitted_bundle(1).await;
        // The broker mints 900 s tokens for internal-git (the bundle says 300) and the
        // sandbox also asks for an audience the bundle does not list.
        let mut sb = a.sb.clone();
        sb.spec.audiences.push("api.example".into());
        let r = rig_with(
            WatcherConfig {
                audiences: vec![
                    Audience::named("api.example"),
                    Audience::named("internal-git"),
                ],
                ..cfg()
            },
            Some(a.cache()),
        );
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let held = r.claims.sandbox("conformance", "sb-1").unwrap();
        let c = conformant(&held);
        assert_eq!((c.status.as_str(), c.reason.as_str()), ("False", "Gaps"));
        assert!(c.message.contains("P002 max_ttl 900"), "{}", c.message);
        assert!(
            c.message.contains("P001 audience api.example"),
            "{}",
            c.message
        );
        // Admitted exactly as today (decision 8).
        assert_eq!(held.status.as_ref().unwrap().phase, SandboxPhase::Pending);
        assert!(held.status.as_ref().unwrap().reason.is_none());
        assert!(r.claims.claim("conformance", "sb-1").is_some());
        assert_eq!(r.store.list_claims().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn no_policy_ref_and_no_bundle_report_their_codes() {
        let a = admitted_bundle(1).await;
        for (edit, code) in [
            (
                Box::new(|sb: &mut AgentSandbox| sb.spec.policy_ref = None)
                    as Box<dyn Fn(&mut AgentSandbox)>,
                "P010",
            ),
            (
                Box::new(|sb: &mut AgentSandbox| {
                    sb.spec.policy_ref = Some(LocalObjectReference {
                        name: "unsigned".into(),
                    });
                }),
                "P011",
            ),
        ] {
            let mut sb = a.sb.clone();
            edit(&mut sb);
            let r = rig_with(cfg_with_git(), Some(a.cache()));
            r.claims.put_sandbox(sb.clone());
            r.watcher.reconcile_sandbox(&sb).await.unwrap();
            let held = r.claims.sandbox("conformance", "sb-1").unwrap();
            let c = conformant(&held);
            assert_eq!(c.status, "False", "{code}");
            assert!(c.message.starts_with(code), "{code}: {}", c.message);
            assert_eq!(held.status.as_ref().unwrap().phase, SandboxPhase::Pending);
        }
    }

    #[tokio::test]
    async fn unknown_until_the_namespace_was_listed_and_absent_without_a_policy_section() {
        let a = admitted_bundle(1).await;
        // The sandbox's own namespace is watched and its first list has not completed.
        let unread = Arc::new(BundleCache::watching(vec!["conformance".into()]));
        let r = rig_with(cfg_with_git(), Some(unread));
        r.claims.put_sandbox(a.sb.clone());
        r.watcher.reconcile_sandbox(&a.sb).await.unwrap();
        let held = r.claims.sandbox("conformance", "sb-1").unwrap();
        let c = conformant(&held);
        assert_eq!(
            (c.status.as_str(), c.reason.as_str()),
            ("Unknown", "BundlesNotRead")
        );
        assert!(c.message.contains("conformance"), "{}", c.message);
        // Shadow holds nothing: the sandbox is created as before (ADR-0054 decision 5).
        assert!(r.claims.claim("conformance", "sb-1").is_some());

        let r = rig(cfg_with_git());
        r.claims.put_sandbox(a.sb.clone());
        r.watcher.reconcile_sandbox(&a.sb).await.unwrap();
        let held = r.claims.sandbox("conformance", "sb-1").unwrap();
        assert_eq!(
            held.status.as_ref().unwrap().conditions.len(),
            0,
            "no policy section, no condition"
        );
        assert_eq!(held.status.as_ref().unwrap().phase, SandboxPhase::Pending);
    }

    /// A sandbox that ended (refused, its claim gone, its claim not its own) still carries
    /// the verdict, recomputed on every pass like a live one: the condition is absent only
    /// without a `policy` section (ADR-0026 decision 7).
    #[tokio::test]
    async fn a_terminal_sandbox_still_carries_the_policy_verdict() {
        let a = admitted_bundle(1).await;

        // Refused before any claim: the audience is not configured, and it is not in the
        // bundle either.
        let r = rig_with(cfg_with_git(), Some(a.cache()));
        let mut refused = a.sb.clone();
        refused.spec.audiences = vec!["nowhere".into()];
        r.claims.put_sandbox(refused.clone());
        r.watcher.reconcile_sandbox(&refused).await.unwrap();
        let held = r.claims.sandbox("conformance", "sb-1").unwrap();
        assert_eq!(held.status.as_ref().unwrap().phase, SandboxPhase::Failed);
        let c = conformant(&held);
        assert_eq!(c.status, "False");
        assert!(c.message.starts_with("P001"), "{}", c.message);

        // Its claim gone: the verdict follows a newer bundle even then.
        let r = rig_with(cfg_with_git(), Some(a.cache()));
        r.claims.put_sandbox(a.sb.clone());
        r.watcher.reconcile_sandbox(&a.sb).await.unwrap();
        let cur = r.claims.sandbox("conformance", "sb-1").unwrap();
        assert_eq!(conformant(&cur).status, "True");
        r.claims.remove_claim("conformance", "sb-1");
        a.admit(2, |b| b.content.lease.max_duration_seconds = 60)
            .await;
        r.watcher.reconcile_sandbox(&cur).await.unwrap();
        let held = r.claims.sandbox("conformance", "sb-1").unwrap();
        let st = held.status.as_ref().unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        assert_eq!(st.reason.as_deref(), Some("claim gone"));
        let c = conformant(&held);
        assert_eq!(c.status, "False");
        assert!(c.message.starts_with("P005"), "{}", c.message);

        // A claim of its name it does not own.
        let r = rig_with(cfg_with_git(), Some(a.cache()));
        r.claims.put_sandbox(a.sb.clone());
        let mut stranger = claim_for(&a.sb).unwrap();
        stranger.metadata.owner_references = None;
        stranger.metadata.uid = Some(Uuid::new_v4().to_string());
        r.claims.put_claim(stranger);
        r.watcher.reconcile_sandbox(&a.sb).await.unwrap();
        let held = r.claims.sandbox("conformance", "sb-1").unwrap();
        assert_eq!(held.status.as_ref().unwrap().phase, SandboxPhase::Failed);
        assert_eq!(conformant(&held).status, "False");
    }

    #[tokio::test]
    async fn a_new_bundle_changes_the_verdict_and_the_transition_time_moves_only_with_the_status() {
        let a = admitted_bundle(1).await;
        let r = rig_with(cfg_with_git(), Some(a.cache()));
        r.claims.put_sandbox(a.sb.clone());
        r.watcher.reconcile_sandbox(&a.sb).await.unwrap();
        let first = conformant(&r.claims.sandbox("conformance", "sb-1").unwrap()).clone();
        assert_eq!(first.status, "True");

        // v2 shortens the lease below the sandbox's ttlSeconds: a gap appears, and the
        // cache announces the policy so the controller compares its sandboxes again.
        let mut changes = a.cache().subscribe();
        a.admit(2, |b| b.content.lease.max_duration_seconds = 60)
            .await;
        assert_eq!(
            changes.try_recv().unwrap(),
            ("conformance".to_owned(), "agent".to_owned())
        );
        let sb = r.claims.sandbox("conformance", "sb-1").unwrap();
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let second = conformant(&r.claims.sandbox("conformance", "sb-1").unwrap()).clone();
        assert_eq!(second.status, "False");
        assert!(
            second.message.contains("P005 ttlSeconds 600"),
            "{}",
            second.message
        );
        assert!(second.last_transition_time >= first.last_transition_time);

        // v3 adds another gap: False still, so the transition time holds; the message moves.
        a.admit(3, |b| {
            b.content.lease.max_duration_seconds = 60;
            b.content.audiences[0].ttl_seconds = Some(10);
        })
        .await;
        let sb = r.claims.sandbox("conformance", "sb-1").unwrap();
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let third = conformant(&r.claims.sandbox("conformance", "sb-1").unwrap()).clone();
        assert_eq!(third.status, "False");
        assert_eq!(third.last_transition_time, second.last_transition_time);
        assert!(third.message.contains("P002") && third.message.contains("P005"));

        // v4 is conformant again.
        a.admit(4, |_| {}).await;
        let sb = r.claims.sandbox("conformance", "sb-1").unwrap();
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let fourth = conformant(&r.claims.sandbox("conformance", "sb-1").unwrap()).clone();
        assert_eq!(fourth.status, "True");
        assert!(fourth.message.contains("v4"), "{}", fourth.message);
        // The record still says what was current at admission.
        let uid = claim_uid_of(&r.claims.claim("conformance", "sb-1").unwrap()).unwrap();
        assert_eq!(
            r.store.get_claim(uid).await.unwrap().bundle_version,
            Some(1)
        );
    }

    #[test]
    fn an_empty_fake_knows_no_sandbox() {
        let fake = FakeClaims::default();
        assert!(fake.sandbox("x", "y").is_none());
    }

    fn enforcing_cfg() -> WatcherConfig {
        WatcherConfig {
            audiences_mode: crate::policy::EgressMode::Enforce,
            ..cfg_with_git()
        }
    }

    #[tokio::test]
    async fn under_enforce_a_conformant_sandbox_is_admitted_and_its_record_carries_the_policy() {
        let a = admitted_bundle(5).await;
        let sb = a.sb.clone();
        let namespace = sb.namespace().unwrap();
        let r = rig_with(enforcing_cfg(), Some(a.cache()));
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let claim = r
            .claims
            .claim(&namespace, "sb-1")
            .expect("a claim is created");
        let rec = r
            .store
            .get_claim(claim_uid_of(&claim).unwrap())
            .await
            .unwrap();
        assert_eq!(
            rec.policy_uid.as_deref(),
            Some(a.payload.content.policy.uid.as_str())
        );
    }

    #[tokio::test]
    async fn under_enforce_a_sandbox_without_a_policy_ref_is_refused_without_a_claim() {
        let a = admitted_bundle(5).await;
        let mut sb = a.sb.clone();
        sb.spec.policy_ref = None;
        let namespace = sb.namespace().unwrap();
        let r = rig_with(enforcing_cfg(), Some(a.cache()));
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let st = r
            .claims
            .sandbox(&namespace, "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        assert!(st.reason.unwrap().contains("policyRef is required"));
        assert!(r.claims.claim(&namespace, "sb-1").is_none());
    }

    #[tokio::test]
    async fn under_enforce_a_policy_with_no_verified_bundle_is_refused() {
        let a = admitted_bundle(5).await;
        let mut sb = a.sb.clone();
        sb.spec.policy_ref = Some(LocalObjectReference {
            name: "no-such-policy".into(),
        });
        let namespace = sb.namespace().unwrap();
        let r = rig_with(enforcing_cfg(), Some(a.cache()));
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let st = r
            .claims
            .sandbox(&namespace, "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        assert!(st.reason.unwrap().contains("no verified bundle"));
        assert!(r.claims.claim(&namespace, "sb-1").is_none());
    }

    /// ADR-0053's enforce and ADR-0054 together: the grants come only from a policy in the
    /// sandbox namespace's sources. The same policy, named from `team-b`, is refused while
    /// `team-b` draws from itself alone (the reason of a policy nowhere, naming no other
    /// namespace) and admitted once a `policy.sources` entry maps it to the policy's namespace.
    #[tokio::test]
    async fn under_enforce_a_policy_outside_the_namespaces_sources_grants_nothing() {
        let a = admitted_bundle(5).await;
        let policy_ns = a.sb.namespace().unwrap();
        let mut sb = a.sb.clone();
        sb.metadata.namespace = Some("team-b".into());

        let r = rig_with(enforcing_cfg(), Some(a.cache()));
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let st = r.claims.sandbox("team-b", "sb-1").unwrap().status.unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        let reason = st.reason.unwrap();
        assert!(reason.contains("no verified bundle"), "{reason}");
        assert!(
            !reason.contains(&policy_ns),
            "the reason never says where else the name is held"
        );
        assert!(r.claims.claim("team-b", "sb-1").is_none());

        let mapped = WatcherConfig {
            policy_sources: crate::policy::PolicySources::new(BTreeMap::from([(
                "team-b".to_owned(),
                vec![policy_ns.clone()],
            )])),
            ..enforcing_cfg()
        };
        let r = rig_with(mapped, Some(a.cache()));
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let claim = r
            .claims
            .claim("team-b", "sb-1")
            .expect("admitted through the sources entry");
        let rec = r
            .store
            .get_claim(claim_uid_of(&claim).unwrap())
            .await
            .unwrap();
        assert_eq!(
            rec.policy_uid.as_deref(),
            Some(a.payload.content.policy.uid.as_str())
        );
    }

    #[tokio::test]
    async fn before_the_bundles_are_read_an_enforcing_watcher_holds_the_sandbox_and_does_not_fail_it()
     {
        // An unsynced cache: the policy may simply not have been read yet. The spec is immutable, so a
        // failure now would be for good.
        let a = admitted_bundle(5).await;
        let sb = a.sb.clone();
        let namespace = sb.namespace().unwrap();
        let unsynced = Arc::new(BundleCache::watching(vec![namespace.clone()]));
        let r = rig_with(enforcing_cfg(), Some(unsynced));
        r.claims.put_sandbox(sb.clone());
        let action = r.watcher.reconcile_sandbox(&sb).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_millis(5)));
        let phase = r
            .claims
            .sandbox(&namespace, "sb-1")
            .and_then(|s| s.status)
            .map(|s| s.phase);
        assert_ne!(phase, Some(SandboxPhase::Failed));
        assert!(
            r.claims.claim(&namespace, "sb-1").is_none(),
            "nothing is created yet"
        );
    }

    #[tokio::test]
    async fn under_enforce_an_audience_the_bundle_does_not_grant_reads_as_not_configured() {
        let a = admitted_bundle(5).await;
        let mut sb = a.sb.clone();
        sb.spec.audiences = vec!["internal-git".into(), "api.example".into()];
        let namespace = sb.namespace().unwrap();
        let r = rig_with(enforcing_cfg(), Some(a.cache()));
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let st = r
            .claims
            .sandbox(&namespace, "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        assert_eq!(
            st.reason.as_deref(),
            Some("audience api.example is not configured")
        );
    }

    #[tokio::test]
    async fn under_enforce_a_ttl_above_the_policys_lease_is_refused() {
        let a = admitted_bundle(5).await;
        let lease = a.payload.content.lease.max_duration_seconds;
        let mut sb = a.sb.clone();
        sb.spec.ttl_seconds = lease + 1;
        let namespace = sb.namespace().unwrap();
        let r = rig_with(enforcing_cfg(), Some(a.cache()));
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        let st = r
            .claims
            .sandbox(&namespace, "sb-1")
            .unwrap()
            .status
            .unwrap();
        assert_eq!(st.phase, SandboxPhase::Failed);
        assert!(st.reason.unwrap().contains("above the policy's lease"));
    }

    /// The status a pass leaves on `sb` under `cfg`, and whether a claim or a record exists.
    async fn reconciled(
        cfg: WatcherConfig,
        bundles: Option<Arc<BundleCache>>,
        sb: &AgentSandbox,
    ) -> (AgentSandboxStatus, bool) {
        let namespace = sb.namespace().unwrap();
        let r = rig_with(cfg, bundles);
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(sb).await.unwrap();
        let status = r
            .claims
            .sandbox(&namespace, "sb-1")
            .and_then(|s| s.status)
            .unwrap_or_default();
        let anything = r.claims.claim(&namespace, "sb-1").is_some()
            || !r.store.list_claims().await.unwrap().is_empty();
        (status, anything)
    }

    #[test]
    fn the_watchers_ceiling_defaults_to_one_day() {
        assert_eq!(WatcherConfig::default().max_ttl_seconds, 86_400);
        assert_eq!(mediatore_proto::DEFAULT_MAX_TTL_SECONDS, 86_400);
    }

    /// ADR-0008 decision 9, amended 2026-11-26: a sandbox with no policy is bounded by the
    /// broker's ceiling. At the ceiling it is admitted; one second above it is `Failed` with
    /// the reason, and no claim and no record exist.
    #[tokio::test]
    async fn a_ttl_at_the_ceiling_is_admitted_and_one_second_above_fails_without_a_claim() {
        let ceiling = cfg().max_ttl_seconds;
        assert_eq!(ceiling, 86_400, "the default");
        let mut sb = sandbox(true, false);
        sb.spec.ttl_seconds = ceiling;
        let (status, anything) = reconciled(cfg(), None, &sb).await;
        assert_ne!(status.phase, SandboxPhase::Failed);
        assert!(anything, "a claim is created at the ceiling");

        sb.spec.ttl_seconds = ceiling + 1;
        let (status, anything) = reconciled(cfg(), None, &sb).await;
        assert_eq!(status.phase, SandboxPhase::Failed);
        assert_eq!(
            status.reason.as_deref(),
            Some(
                "ttlSeconds is above the broker's maximum of 86400 seconds (sandboxes.max_ttl_seconds)"
            )
        );
        assert!(!anything, "no claim and no record above the ceiling");

        // The key raised: the same request is admitted.
        let raised = WatcherConfig {
            max_ttl_seconds: ceiling + 1,
            ..cfg()
        };
        let (status, anything) = reconciled(raised, None, &sb).await;
        assert_ne!(status.phase, SandboxPhase::Failed);
        assert!(anything, "a claim is created under the raised ceiling");
    }

    /// The effective bound is the smaller of the policy's lease and the ceiling, whichever
    /// that is.
    #[tokio::test]
    async fn under_enforce_the_smaller_of_the_lease_and_the_ceiling_bounds_a_sandbox() {
        let a = admitted_bundle(5).await;
        let lease = a.payload.content.lease.max_duration_seconds;
        assert!(lease > 2, "the conformance lease leaves room below it");

        // The ceiling above the lease: the lease still wins.
        let wide = WatcherConfig {
            max_ttl_seconds: lease + 10,
            ..enforcing_cfg()
        };
        let mut sb = a.sb.clone();
        sb.spec.ttl_seconds = lease + 1;
        let (status, anything) = reconciled(wide, Some(a.cache()), &sb).await;
        assert_eq!(status.phase, SandboxPhase::Failed);
        assert_eq!(
            status.reason.as_deref(),
            Some("ttlSeconds is above the policy's lease (ADR-0053)")
        );
        assert!(!anything, "no claim above the lease");

        // The ceiling below the lease: the ceiling wins, for a TTL the lease would admit.
        let narrow = WatcherConfig {
            max_ttl_seconds: lease - 2,
            ..enforcing_cfg()
        };
        sb.spec.ttl_seconds = lease - 1;
        let (status, anything) = reconciled(narrow.clone(), Some(a.cache()), &sb).await;
        assert_eq!(status.phase, SandboxPhase::Failed);
        assert_eq!(
            status.reason,
            Some(ttl_above_maximum(lease - 2)),
            "the ceiling, not the lease"
        );
        assert!(!anything, "no claim above the ceiling");

        // Inside both, it is admitted.
        sb.spec.ttl_seconds = lease - 2;
        let (status, anything) = reconciled(narrow, Some(a.cache()), &sb).await;
        assert_ne!(status.phase, SandboxPhase::Failed);
        assert!(anything, "a claim is created inside both bounds");
    }

    /// No retroactive release: a sandbox whose claim exists is not judged again when the
    /// ceiling is lowered under it.
    #[tokio::test]
    async fn a_sandbox_already_claimed_is_not_failed_when_the_ceiling_is_lowered() {
        let r = rig(cfg());
        let settled = settle(&r, &sandbox(true, false)).await;
        let claimed = settled
            .status
            .as_ref()
            .is_some_and(|s| s.claim_ref.is_some());
        assert!(claimed, "the sandbox has its claim");
        // The same store and API, read by a broker restarted with a ceiling below the TTL.
        let lowered = Watcher::new(
            Reconciler {
                store: r.store.clone(),
                spire: r.entries.clone(),
                naming: mediatore_spire::Naming {
                    trust_domain: "sandbox.test".into(),
                },
            },
            r.claims.clone(),
            WatcherConfig {
                max_ttl_seconds: settled.spec.ttl_seconds - 1,
                ..cfg()
            },
        );
        lowered.reconcile_sandbox(&settled).await.unwrap();
        let status = r
            .claims
            .sandbox("sandboxes", "sb-1")
            .and_then(|s| s.status)
            .expect("the status is still there");
        assert_ne!(status.phase, SandboxPhase::Failed);
        assert_ne!(
            status.reason,
            Some(ttl_above_maximum(settled.spec.ttl_seconds - 1)),
            "nothing is refused after the fact"
        );
        assert!(
            r.claims.claim("sandboxes", "sb-1").is_some(),
            "the claim is left alone"
        );
    }

    #[tokio::test]
    async fn without_enforce_none_of_this_applies_a_sandbox_with_no_policy_is_served_as_before() {
        let a = admitted_bundle(5).await;
        let mut sb = a.sb.clone();
        sb.spec.policy_ref = None;
        let namespace = sb.namespace().unwrap();
        let r = rig_with(cfg_with_git(), Some(a.cache()));
        r.claims.put_sandbox(sb.clone());
        r.watcher.reconcile_sandbox(&sb).await.unwrap();
        assert!(
            r.claims.claim(&namespace, "sb-1").is_some(),
            "shadow refuses nothing"
        );
    }
}
