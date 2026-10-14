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

use async_trait::async_trait;
use banlieue_api::banlieue::{ClaimSubject, VirtualMachineClaim, VirtualMachineClaimSpec};
use banlieue_api::common::LocalObjectReference;
use chrono::{DateTime, Utc};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::api::{DeleteParams, ObjectMeta, PostParams};
use kube::runtime::controller::Action;
use kube::{Api, Client, CustomResource, CustomResourceExt, Resource, ResourceExt};
use mediatore_proto::{ClaimPhase, Subject, Workload};
use mediatore_spire::{MANAGED_BY, MANAGED_BY_LABEL};
use mediatore_store::{ClaimRecord, StoreError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::watch::{WatchError, Watcher, claim_uid_of, phase_of};

/// The finalizer that holds an `AgentSandbox` until its claim is gone (decision 10).
pub const FINALIZER: &str = "mediatore.io/sandbox";

/// Label on the owned claim naming the sandbox's UID, beside the managed-by label the
/// watcher selects on.
pub const SANDBOX_UID_LABEL: &str = "mediatore.io/sandbox-uid";

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
    /// OCI reference of the rootfs `mediatore-guest` unpacks into the jail.
    #[schemars(length(min = 1))]
    pub image: String,
    /// Command and arguments to exec inside the jail.
    #[serde(default)]
    pub args: Vec<String>,
}

/// The request mediatore already accepts on `POST /v1/claims`, as a resource (decision 7).
/// Immutable after creation: the admission policy in
/// `deploy/base/admission/agentsandbox-subject.yaml` freezes it.
#[derive(CustomResource, Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mediatore.io",
    version = "v1alpha1",
    kind = "AgentSandbox",
    plural = "agentsandboxes",
    shortname = "asb",
    namespaced,
    status = "AgentSandboxStatus",
    derive = "PartialEq",
    printcolumn = r#"{"name":"Subject","type":"string","jsonPath":".spec.subject.id"}"#,
    printcolumn = r#"{"name":"Pool","type":"string","jsonPath":".spec.poolRef.name"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Ready","type":"boolean","jsonPath":".status.ready"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct AgentSandboxSpec {
    /// Who the sandbox is for.
    pub subject: SandboxSubject,
    /// The `VirtualMachinePool` to claim from, in this namespace; copied to the claim.
    pub pool_ref: LocalObjectReference,
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
    /// Why the sandbox is `Failed`, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The generation this status was computed from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

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
        }
    }
}

impl From<&Workload> for SandboxWorkload {
    fn from(w: &Workload) -> Self {
        Self {
            image: w.image.clone(),
            args: w.args.clone(),
        }
    }
}

/// `chrono` for a Kubernetes timestamp (the wire types use `chrono`).
#[must_use]
pub fn chrono_of(t: &Time) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(
        t.0.as_second(),
        u32::try_from(t.0.subsec_nanosecond()).ok()?,
    )
}

/// The CRD as `deploy/base/crds/` carries it.
pub fn crd_yaml() -> Result<String, serde_saphyr::ser::Error> {
    let mut options = serde_saphyr::SerializerOptions::default();
    // Long descriptions stay on one line, as serde_yaml wrote them.
    options.folded_wrap_chars = 1 << 20;
    let mut crd = AgentSandbox::crd();
    // kube-derive puts a placeholder here; the schema's own description is the type's.
    if let Some(schema) = crd
        .spec
        .versions
        .iter_mut()
        .filter_map(|v| v.schema.as_mut())
        .find_map(|s| s.open_api_v3_schema.as_mut())
    {
        schema.description = Some(
            "AgentSandbox is the record of one sandbox request (ADR-0008): mediatore creates and owns one VirtualMachineClaim for it, pins spec.subject to the caller at admission, and reports the claim's status plus whether the claim's registration entry is set."
                .into(),
        );
    }
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
            subject: ClaimSubject {
                issuer: sb.spec.subject.issuer.clone(),
                id: sb.spec.subject.id.clone(),
            },
            ttl_seconds: u64::from(sb.spec.ttl_seconds),
        },
        status: None,
    })
}

/// The store record for a sandbox whose claim has UID `claim_uid` (decision 12): the
/// request fields the sandbox API answers from, nothing bound yet.
#[must_use]
pub fn record_for(sb: &AgentSandbox, claim_uid: Uuid) -> ClaimRecord {
    ClaimRecord {
        uid: claim_uid,
        name: sb.name_any(),
        subject: Subject::from(&sb.spec.subject),
        entry_id: None,
        node_id: None,
        audiences: sb.spec.audiences.clone(),
        workload: Workload::from(&sb.spec.workload),
        ttl_seconds: sb.spec.ttl_seconds,
        refresh: None,
        created_at: Utc::now(),
        expires_at: None,
        revoked_at: None,
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
        addresses: st
            .map(|s| s.addresses.iter().map(|a| a.address.clone()).collect())
            .unwrap_or_default(),
        bound_at: st.and_then(|s| s.bound_at.clone()),
        expires_at: st.and_then(|s| s.expires_at.clone()),
        entry_set,
        ready: phase == SandboxPhase::Bound && entry_set,
        reason: None,
        observed_generation: sb.metadata.generation,
    }
}

impl Watcher {
    /// Why a spec is refused before any claim exists: an audience or an issuer mediatore
    /// is not configured for (decision 7; fail closed), or a TTL the schema should have
    /// caught.
    fn refuse(&self, spec: &AgentSandboxSpec) -> Option<String> {
        if spec.ttl_seconds == 0 {
            return Some("ttlSeconds must be positive".into());
        }
        if let Some(a) = spec
            .audiences
            .iter()
            .find(|a| !self.cfg.audiences.contains(a))
        {
            return Some(format!("audience {a} is not configured"));
        }
        if !self.cfg.issuers.iter().any(|i| i == &spec.subject.issuer) {
            return Some(format!("issuer {} is not configured", spec.subject.issuer));
        }
        None
    }

    /// Patch the status when it differs from what the object carries.
    async fn mirror(
        &self,
        sb: &AgentSandbox,
        status: AgentSandboxStatus,
    ) -> Result<(), WatchError> {
        if sb.status.as_ref() == Some(&status) {
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
        // Refused before any claim exists, and only then: once a claim was created the
        // request was accepted under the configuration of that moment, and a later config
        // change must not flap a bound sandbox between Failed and its mirrored status.
        if current.claim_ref.is_none()
            && let Some(reason) = self.refuse(&sb.spec)
        {
            tracing::warn!(sandbox = %name, %namespace, %reason, "sandbox refused; no claim created");
            self.mirror(
                sb,
                AgentSandboxStatus {
                    phase: SandboxPhase::Failed,
                    reason: Some(reason),
                    observed_generation: sb.metadata.generation,
                    ..AgentSandboxStatus::default()
                },
            )
            .await?;
            return Ok(Action::await_change());
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
                        reason: Some("claim gone".into()),
                        observed_generation: sb.metadata.generation,
                        ..current
                    },
                )
                .await?;
                return Ok(Action::await_change());
            }
            None => {
                let created = self.claims.create_claim(claim_for(sb)?).await?;
                tracing::info!(sandbox = %name, %namespace, subject = %sb.spec.subject.id, pool = %sb.spec.pool_ref.name, "claim created");
                created
            }
        };
        let Some(uid) = claim_uid_of(&claim) else {
            tracing::warn!(sandbox = %name, %namespace, "owned claim without a UUID uid; held");
            return Ok(Action::await_change());
        };
        let record = match self.reconciler.store.get_claim(uid).await {
            Ok(r) => r,
            Err(StoreError::NotFound(_)) => {
                let r = record_for(sb, uid);
                self.reconciler.store.put_claim(r.clone()).await?;
                tracing::info!(sandbox = %name, %namespace, claim_uid = %uid, "record created");
                r
            }
            Err(e) => return Err(e.into()),
        };
        let status = mirror_status(sb, &claim, &record);
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
                // a claim that banlieue already deleted is released here; idempotent.
                if let Some(uid) = sb
                    .status
                    .as_ref()
                    .and_then(|s| s.claim_uid.as_deref())
                    .and_then(|u| Uuid::parse_str(u).ok())
                {
                    self.reconciler.release(uid).await?;
                }
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
    use crate::fakes::{FakeClaims, Rig, node, rig};
    use crate::watch::WatcherConfig;

    const ISSUER: &str = "https://issuer.example.com";
    const SB_UID: &str = "9c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f";

    fn cfg() -> WatcherConfig {
        WatcherConfig {
            requeue: Duration::from_millis(5),
            audiences: vec!["api.example".into()],
            issuers: vec![ISSUER.into()],
            ..WatcherConfig::default()
        }
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
                pool_ref: LocalObjectReference {
                    name: "pool".into(),
                },
                ttl_seconds: 600,
                audiences: vec!["api.example".into()],
                workload: SandboxWorkload {
                    image: "ghcr.io/example/workload:1".into(),
                    args: vec!["sh".into()],
                },
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

    #[test]
    fn the_crd_in_deploy_is_what_the_type_renders() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/base/crds/",
            "mediatore.io_agentsandboxes.yaml"
        );
        let on_disk = std::fs::read_to_string(path).unwrap_or_default();
        assert_eq!(
            on_disk,
            crd_yaml().unwrap(),
            "deploy/base/crds is stale: run `make crds`"
        );
    }

    #[test]
    fn the_schema_requires_what_the_reconciler_assumes() {
        let crd = serde_json::to_value(AgentSandbox::crd()).unwrap();
        let v = &crd["spec"]["versions"][0];
        assert_eq!(v["name"], "v1alpha1");
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
        for f in ["subject", "poolRef", "ttlSeconds", "workload"] {
            assert!(required.contains(&f), "{f} required");
        }
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
            ("AgentSandbox", "mediatore.io/v1alpha1")
        );
        assert_eq!(owner.uid, SB_UID);
        assert_eq!(
            (owner.controller, owner.block_owner_deletion),
            (Some(true), Some(true))
        );
        assert_eq!(claim.spec.pool_ref.name, "pool");
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
            &json!({ "phase": "Bound", "virtualMachineRef": { "name": "member-1" }, "tpmEndorsementCertificates": [RSA_EK_PEM],
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

    #[test]
    fn timestamps_convert_to_chrono() {
        let t = Time(k8s_openapi::jiff::Timestamp::from_second(1_800_000_000).unwrap());
        assert_eq!(chrono_of(&t).unwrap().timestamp(), 1_800_000_000);
        let fake = FakeClaims::default();
        assert!(fake.sandbox("x", "y").is_none());
    }
}
