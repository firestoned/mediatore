// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The Kubernetes API as the broker's store (ADR-0034): the `AgentSandbox` is the claim
//! record (its `status.record`, written here and nowhere else), the sealed session is a
//! Secret owned by the sandbox, attested nodes are `SandboxNode` resources and the notaio
//! version floors `PolicyFloor` resources. The record is where the sandbox is; the Secrets,
//! nodes and floors are in the broker's own namespace. No database.
//!
//! What the store finds, it finds by label: the claim's UID (`mediatore.io/claim-uid`) and
//! a digest of the bound node's SPIFFE ID (`mediatore.io/node`, a label value being too
//! short for the ID itself). Writes to the record are merge patches of `status.record`
//! alone, so they compose with the reconciler's mirroring of the rest of the status from
//! any replica. The compare-and-set the floors need is the resource's `resourceVersion`.
//!
//! Retention (decision 4): a record that ended stays on its resource, finalizer held, until
//! [`ClaimStore::sweep`] runs past the retention window; the sweep logs the audit line,
//! deletes the resource if nobody has, and releases the finalizer.

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use jiff::Timestamp;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference, Time};
use kube::api::{DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::{Api, Client, CustomResource, Resource, ResourceExt};
use mediatore_proto::{
    ClaimReport, LOG_SEGMENT_BYTES, LogBatch, LogEntry, LogGap, Provider, Subject, Workload,
    WorkloadExit,
};
use mediatore_store::seal::Sealed;
use mediatore_store::{
    ClaimRecord, ClaimStore, DelegatedSession, LogAppend, LogChunk, LogLimits, LogStore,
    NodeRecord, SessionRecord, StoreError,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::sandbox::{AgentSandbox, FINALIZER, sandbox_uid_of};

/// The label carrying the claim's UID on an `AgentSandbox` with a record.
pub const CLAIM_UID_LABEL: &str = "mediatore.io/claim-uid";
/// The label carrying a digest of the bound node's SPIFFE ID (see [`node_label`]).
pub const NODE_LABEL: &str = "mediatore.io/node";
/// The label carrying the sandbox UID on its session Secret.
pub const SANDBOX_UID_LABEL: &str = "mediatore.io/sandbox-uid";
/// The label saying whether a session Secret is still parked or has become the record's.
pub const SESSION_LABEL: &str = "mediatore.io/session";
/// The label naming the audience a delegated credential's Secret is for (ADR-0035); absent
/// on the issuer's session Secret.
pub const AUDIENCE_LABEL: &str = "mediatore.io/audience";
/// The label carrying a node's DMI UUID on its `SandboxNode`.
pub const DMI_LABEL: &str = "mediatore.io/dmi-uuid";
/// The label marking a Secret as one segment of a claim's output ring (ADR-0045 decision 6);
/// its value is [`LOGS_SEGMENT`]. The segment also carries [`CLAIM_UID_LABEL`] and, when the
/// record has one, [`SANDBOX_UID_LABEL`].
pub const LOGS_LABEL: &str = "mediatore.io/logs";
/// The one value of [`LOGS_LABEL`].
pub const LOGS_SEGMENT: &str = "segment";
/// Annotation on a segment: its number in the ring.
const SEGMENT_ANNOTATION: &str = "mediatore.io/segment";
/// Annotation on a segment: the lowest record `seq` in it (absent when it holds no record).
const FIRST_SEQ_ANNOTATION: &str = "mediatore.io/first-seq";
/// Annotation on a segment: the highest record `seq` in it.
const LAST_SEQ_ANNOTATION: &str = "mediatore.io/last-seq";
/// Annotation on a segment: record text bytes in it.
const BYTES_ANNOTATION: &str = "mediatore.io/bytes";
/// Annotation on a segment: record text bytes the ring had dropped from its front when the
/// segment was last written. The newest segment's value is the ring's truth; an older
/// segment's is what it was then and may be stale.
const TRUNCATED_ANNOTATION: &str = "mediatore.io/truncated-before";
/// The data key holding a segment's entries, NDJSON, one [`LogEntry`] per line.
const ENTRIES_KEY: &str = "entries";
/// How many times a conflicting segment write is retried before it is an error.
const SEGMENT_WRITE_ATTEMPTS: usize = 3;
/// How many location hints [`KubeStore`] keeps before it forgets them all: a forgotten hint
/// costs one list, never an answer.
const LOCATED_MAX: usize = 4096;
/// The rendered CRD files (`make crds`).
pub const NODE_CRD_FILE_NAME: &str = "mediatore.io_sandboxnodes.yaml";
/// See [`NODE_CRD_FILE_NAME`].
pub const FLOOR_CRD_FILE_NAME: &str = "mediatore.io_policyfloors.yaml";

/// What the claim record keeps beyond the spec and the mirrored status (ADR-0034 decision
/// 1): the store's part of `AgentSandbox.status`, written by [`KubeStore`] alone. The
/// request fields are the spec's; the sealed refresh envelope is the sandbox's Secret.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecordStatus {
    /// The claim's UID (banlieue's `VirtualMachineClaim`), the key of the record.
    pub claim_uid: String,
    /// When the record was created.
    pub created_at: Time,
    /// The bind deadline, once bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Time>,
    /// Set on release or revocation; a revoked claim never issues again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<Time>,
    /// The SPIRE registration entry, once created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    /// The bound node's SPIFFE ID, once known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// The notaio policy's incarnation the record was created under (ADR-0026 decision 6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_uid: Option<String>,
    /// The bundle version then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<u64>,
    /// Whether a sealed refresh envelope is held for the claim (in the sandbox's Secret).
    #[serde(default)]
    pub refresh: bool,
    /// The caller's delegated credentials (ADR-0035), one Secret each: the audience and
    /// when the bearer dies; the envelopes are the Secrets'.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegations: Vec<DelegationStatus>,
    /// The guest's report (ADR-0029 decision 5), as `ClaimReport` serialises.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "preserve_arbitrary")]
    pub report: Option<serde_json::Value>,
    /// The workload's exit (ADR-0033 decision 2), as `WorkloadExit` serialises.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "preserve_arbitrary")]
    pub exit: Option<serde_json::Value>,
}

/// One delegated credential on the record (ADR-0035): which audience, until when.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DelegationStatus {
    /// The audience the credential is for.
    pub audience: String,
    /// When the bearer dies, if the caller said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Time>,
}

/// A free-form object in the CRD schema: the wire types own their shape.
fn preserve_arbitrary(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": true
    })
}

/// An attested node mediatore knows (ADR-0034 decision 3), named by its EK hash.
#[derive(CustomResource, Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mediatore.io",
    version = "v1alpha1",
    kind = "SandboxNode",
    plural = "sandboxnodes",
    shortname = "sbn",
    namespaced,
    derive = "PartialEq",
    printcolumn = r#"{"name":"Hostname","type":"string","jsonPath":".spec.hostname"}"#,
    printcolumn = r#"{"name":"Provider","type":"string","jsonPath":".spec.provider"}"#,
    printcolumn = r#"{"name":"Banned","type":"boolean","jsonPath":".spec.banned"}"#,
    printcolumn = r#"{"name":"Registered","type":"date","jsonPath":".spec.registeredAt"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct SandboxNodeSpec {
    /// The EK public-key hash, also the resource's name.
    pub ek_hash: String,
    /// The SPIRE agent's SPIFFE ID.
    pub node_id: String,
    /// The guest's DMI UUID, matched against banlieue's `providerID`; also a label.
    pub dmi_uuid: String,
    /// Informational.
    pub hostname: String,
    /// Informational.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// A banned node is never bound again, even if still Ready.
    #[serde(default)]
    pub banned: bool,
    /// First registration time.
    pub registered_at: Time,
}

/// The version floor of one notaio policy (ADR-0026 decision 5, ADR-0034 decision 3),
/// named `<policy namespace>.<policy name>`; moved by compare-and-set on `resourceVersion`.
#[derive(CustomResource, Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mediatore.io",
    version = "v1alpha1",
    kind = "PolicyFloor",
    plural = "policyfloors",
    shortname = "pfl",
    namespaced,
    derive = "PartialEq",
    printcolumn = r#"{"name":"Policy","type":"string","jsonPath":".spec.policyName"}"#,
    printcolumn = r#"{"name":"Namespace","type":"string","jsonPath":".spec.policyNamespace"}"#,
    printcolumn = r#"{"name":"Version","type":"integer","jsonPath":".spec.version"}"#,
    printcolumn = r#"{"name":"Issued","type":"string","jsonPath":".spec.issuedAt"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct PolicyFloorSpec {
    /// The policy's namespace.
    pub policy_namespace: String,
    /// The policy's name.
    pub policy_name: String,
    /// The incarnation: the `SandboxPolicy`'s `uid`.
    pub uid: String,
    /// The highest bundle version accepted for that incarnation.
    pub version: u64,
    /// `issuedAt` of the bundle the floor was last moved by, RFC 3339 to the nanosecond
    /// (a Kubernetes `Time` keeps seconds only).
    pub issued_at: String,
}

/// The store over the API server, as the broker's `ServiceAccount`: the record on the
/// `AgentSandbox` wherever the sandbox lives (the controller watches every namespace),
/// everything else in the broker's own namespace.
pub struct KubeStore {
    client: Client,
    /// The broker's own namespace, the client's default (the `ServiceAccount`'s in a pod):
    /// the session Secrets, `SandboxNode` and `PolicyFloor` live here, where the RBAC of
    /// `deploy/base` reaches and which exists before any sandbox does.
    home: String,
    /// Where the sandbox of a claim was last found, `(namespace, name)` by claim UID: a
    /// hint, never state. It only chooses which read is tried first; what it names is read
    /// from the API server and checked again on every use (see
    /// [`KubeStore::sandbox_of_claim`]), and a hint that no longer holds is dropped for the
    /// label list, which decides. Per replica, lost on restart, bounded by [`LOCATED_MAX`].
    located: std::sync::Mutex<HashMap<Uuid, (String, String)>>,
}

impl KubeStore {
    /// Over `client`, keeping what is not a sandbox in the client's default namespace.
    pub fn new(client: Client) -> Self {
        let home = client.default_namespace().to_owned();
        Self {
            client,
            home,
            located: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The broker's own namespace, where the Secrets, nodes and floors are kept.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.home
    }

    /// Every namespace: the lookups are by label and by UID, the controller's scope.
    fn all_sandboxes(&self) -> Api<AgentSandbox> {
        Api::all(self.client.clone())
    }

    /// The namespace `sb` lives in, for the writes to it.
    fn sandboxes_of(&self, sb: &AgentSandbox) -> Api<AgentSandbox> {
        match sb.namespace() {
            Some(ns) => Api::namespaced(self.client.clone(), &ns),
            None => Api::all(self.client.clone()),
        }
    }

    /// One namespace, for a read by name.
    fn sandboxes_in(&self, namespace: &str) -> Api<AgentSandbox> {
        Api::namespaced(self.client.clone(), namespace)
    }

    /// The location hint for claim `uid`, if one is kept. The lock is never held across an
    /// await: the hint is copied out.
    fn hint_of(&self, uid: Uuid) -> Option<(String, String)> {
        self.located.lock().ok()?.get(&uid).cloned()
    }

    /// Keep where the sandbox of claim `uid` was found.
    fn remember(&self, uid: Uuid, sb: &AgentSandbox) {
        let (Some(namespace), Some(name)) = (sb.namespace(), sb.metadata.name.clone()) else {
            return;
        };
        if let Ok(mut located) = self.located.lock() {
            if located.len() >= LOCATED_MAX && !located.contains_key(&uid) {
                located.clear();
            }
            located.insert(uid, (namespace, name));
        }
    }

    /// Drop the hint for claim `uid`.
    fn forget(&self, uid: Uuid) {
        if let Ok(mut located) = self.located.lock() {
            located.remove(&uid);
        }
    }

    /// The sandbox a new record is for: by its UID when the record carries one, else by
    /// name, in whichever namespace it lives.
    ///
    /// A record with a sandbox UID names its sandbox too, so one read by name in the
    /// record's namespace is tried first and taken only when the object there has that UID;
    /// anything else (no such object, another UID) is left to the list over every namespace.
    async fn sandbox_for(&self, rec: &ClaimRecord) -> Result<AgentSandbox, StoreError> {
        let uid = rec.sandbox_uid.map(|u| u.to_string());
        if let Some(uid) = &uid
            && !rec.name.is_empty()
            && !rec.namespace.is_empty()
            && let Some(sb) = self
                .sandboxes_in(&rec.namespace)
                .get_opt(&rec.name)
                .await
                .map_err(|e| backend(&e))?
            && sb.metadata.uid.as_deref() == Some(uid.as_str())
        {
            return Ok(sb);
        }
        let list = self
            .all_sandboxes()
            .list(&ListParams::default())
            .await
            .map_err(|e| backend(&e))?;
        list.items
            .into_iter()
            .find(|sb| match &uid {
                Some(uid) => sb.metadata.uid.as_deref() == Some(uid.as_str()),
                None => sb.name_any() == rec.name,
            })
            .ok_or_else(|| StoreError::NotFound(rec.name.clone()))
    }

    fn secrets(&self) -> Api<Secret> {
        Api::namespaced(self.client.clone(), &self.home)
    }

    fn nodes(&self) -> Api<SandboxNode> {
        Api::namespaced(self.client.clone(), &self.home)
    }

    fn floors(&self) -> Api<PolicyFloor> {
        Api::namespaced(self.client.clone(), &self.home)
    }

    /// The sandbox carrying the record of claim `uid`, by its label.
    ///
    /// Where the sandbox was found last time is tried first, as one read by name; the object
    /// read is taken only when it passes the list's own two tests, the label and the record
    /// ([`carries_claim`]). A sandbox that is gone, relabelled or replaced by another of the
    /// same name fails them, the hint is dropped and the label list over every namespace
    /// decides, as it always did.
    ///
    /// The read by name answers what the list would because at most one sandbox carries a
    /// given claim UID: the UID is that of the one `VirtualMachineClaim` a sandbox owns
    /// (`claim_for`: named after the sandbox, in its namespace, controlled by it), the API
    /// server gives no two objects the same UID, and [`ClaimStore::put_claim`] refuses both
    /// a sandbox that already has a record and a UID that already has a sandbox. The hint
    /// itself only ever comes from the list's answer.
    async fn sandbox_of_claim(&self, uid: Uuid) -> Result<AgentSandbox, StoreError> {
        if let Some((namespace, name)) = self.hint_of(uid) {
            let hinted = self
                .sandboxes_in(&namespace)
                .get_opt(&name)
                .await
                .map_err(|e| backend(&e))?;
            if let Some(sb) = hinted
                && carries_claim(&sb, uid)
            {
                return Ok(sb);
            }
            self.forget(uid);
        }
        let list = self
            .all_sandboxes()
            .list(&ListParams::default().labels(&format!("{CLAIM_UID_LABEL}={uid}")))
            .await
            .map_err(|e| backend(&e))?;
        let sb = list
            .items
            .into_iter()
            .find(|sb| record_status_of(sb).is_some_and(|r| r.claim_uid == uid.to_string()))
            .ok_or_else(|| StoreError::NotFound(uid.to_string()))?;
        self.remember(uid, &sb);
        Ok(sb)
    }

    /// The record on `sb`, with its envelope from the session Secret.
    async fn record_of(&self, sb: &AgentSandbox) -> Result<ClaimRecord, StoreError> {
        let Some(status) = record_status_of(sb) else {
            return Err(StoreError::NotFound(sb.name_any()));
        };
        let mut rec = record_from(sb, status)?;
        if status.refresh
            && let Some(sandbox_uid) = rec.sandbox_uid
            && let Some(secret) = self
                .secrets()
                .get_opt(&session_name(sandbox_uid))
                .await
                .map_err(|e| backend(&e))?
        {
            rec.refresh = envelope_of(&secret);
        }
        if let Some(sandbox_uid) = rec.sandbox_uid {
            for d in &status.delegations {
                let Some(secret) = self
                    .secrets()
                    .get_opt(&delegation_name(sandbox_uid, &d.audience))
                    .await
                    .map_err(|e| backend(&e))?
                else {
                    continue;
                };
                if let Some(envelope) = envelope_of(&secret) {
                    rec.delegations.insert(
                        d.audience.clone(),
                        DelegatedSession {
                            envelope,
                            expires_at: d.expires_at.as_ref().map(|t| t.0),
                        },
                    );
                }
            }
        }
        Ok(rec)
    }

    /// Write `status.record` for `sb` from `rec`, and the labels the lookups need.
    ///
    /// A patch that would set nothing is not sent: the labels patch when `sb`, as read,
    /// already carries every label it would set with the same value, the status patch when
    /// `sb`'s `status.record` already equals the one it would write. The accepted
    /// difference: a writer whose copy equals what it just read no longer re-sends a no-op
    /// patch.
    async fn write_record(&self, sb: &AgentSandbox, rec: &ClaimRecord) -> Result<(), StoreError> {
        let name = sb.name_any();
        let name = name.as_str();
        let mut labels: BTreeMap<&str, String> = BTreeMap::new();
        labels.insert(CLAIM_UID_LABEL, rec.uid.to_string());
        if let Some(node) = &rec.node_id {
            labels.insert(NODE_LABEL, node_label(node));
        }
        let carried = sb.labels();
        if !labels.iter().all(|(k, v)| carried.get(*k) == Some(v)) {
            self.sandboxes_of(sb)
                .patch(
                    name,
                    &PatchParams::default(),
                    &Patch::Merge(serde_json::json!({ "metadata": { "labels": labels } })),
                )
                .await
                .map_err(|e| backend(&e))?;
        }
        let record = record_status_from(rec);
        if record_status_of(sb) != Some(&record) {
            self.sandboxes_of(sb)
                .patch_status(
                    name,
                    &PatchParams::default(),
                    &Patch::Merge(serde_json::json!({ "status": { "record": record } })),
                )
                .await
                .map_err(|e| backend(&e))?;
        }
        Ok(())
    }

    /// Put `rec.refresh` and every delegation where the record keeps them: the sandbox's
    /// session Secrets, written as the record's own (`claimed`) and owned by the sandbox;
    /// an envelope gone from the record (revoked) deletes its Secret (ADR-0043 decision 4).
    async fn write_envelope(&self, sb: &AgentSandbox, rec: &ClaimRecord) -> Result<(), StoreError> {
        let Some(sandbox_uid) = rec.sandbox_uid else {
            return Ok(());
        };
        self.write_one_envelope(sb, rec, sandbox_uid, None, rec.refresh.as_ref(), None)
            .await?;
        // The delegations the record carries, then the Secrets of any it no longer does.
        for (audience, d) in &rec.delegations {
            self.write_one_envelope(
                sb,
                rec,
                sandbox_uid,
                Some(audience),
                Some(&d.envelope),
                d.expires_at,
            )
            .await?;
        }
        let held = self
            .secrets()
            .list(&ListParams::default().labels(&format!(
                "{SANDBOX_UID_LABEL}={sandbox_uid},{AUDIENCE_LABEL}"
            )))
            .await
            .map_err(|e| backend(&e))?;
        for secret in &held.items {
            let Some(audience) = secret
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(AUDIENCE_LABEL))
                .cloned()
            else {
                continue;
            };
            if !rec.delegations.contains_key(&audience) {
                self.write_one_envelope(sb, rec, sandbox_uid, Some(&audience), None, None)
                    .await?;
            }
        }
        Ok(())
    }

    /// One Secret: the issuer's session (`audience` `None`) or a delegation's.
    async fn write_one_envelope(
        &self,
        sb: &AgentSandbox,
        rec: &ClaimRecord,
        sandbox_uid: Uuid,
        audience: Option<&str>,
        sealed: Option<&Sealed>,
        expires_at: Option<Timestamp>,
    ) -> Result<(), StoreError> {
        let name = match audience {
            Some(a) => delegation_name(sandbox_uid, a),
            None => session_name(sandbox_uid),
        };
        let api = self.secrets();
        let existing = api.get_opt(&name).await.map_err(|e| backend(&e))?;
        match (envelope_write(sealed.is_some(), existing.is_some()), sealed) {
            (EnvelopeWrite::Replace, Some(sealed)) => {
                let owners = owner_refs(&self.home, sb);
                // Everything the patch would set, already there on the Secret just read: the
                // envelope, the `claimed` label and (when the sandbox owns it) the owner
                // references. Then the patch is not sent, the same accepted difference as
                // `write_record`'s; any one of them differing sends the whole patch.
                let unchanged = existing.as_ref().is_some_and(|held| {
                    envelope_of(held).as_ref() == Some(sealed)
                        && held.labels().get(SESSION_LABEL).map(String::as_str) == Some("claimed")
                        && owners
                            .as_ref()
                            .is_none_or(|o| held.metadata.owner_references.as_ref() == Some(o))
                });
                if !unchanged {
                    let mut metadata =
                        serde_json::json!({ "labels": { SESSION_LABEL: "claimed" } });
                    if let Some(owners) = owners {
                        metadata["ownerReferences"] = serde_json::json!(owners);
                    }
                    let patch = serde_json::json!({
                        "metadata": metadata,
                        "data": envelope_data(sealed),
                    });
                    api.patch(&name, &PatchParams::default(), &Patch::Merge(patch))
                        .await
                        .map_err(|e| backend(&e))?;
                }
            }
            (EnvelopeWrite::Create, Some(sealed)) => {
                let mut secret = session_secret(
                    &SessionRecord {
                        sandbox_uid,
                        subject: rec.subject.clone(),
                        issuer: String::new(),
                        refresh: sealed.clone(),
                        created_at: rec.created_at,
                        audience: audience.map(str::to_owned),
                        expires_at,
                    },
                    "claimed",
                );
                secret.metadata.owner_references = owner_refs(&self.home, sb);
                api.create(&PostParams::default(), &secret)
                    .await
                    .map_err(|e| backend(&e))?;
            }
            (EnvelopeWrite::Delete, _) => {
                // Deleted, not emptied: the Secret is not a marker (the released claim is on the AgentSandbox's status
                // record), and a stored envelope must not outlive its claim.
                match api.delete(&name, &DeleteParams::default()).await {
                    Ok(_) => {}
                    Err(e) if is_not_found(&e) => {}
                    Err(e) => return Err(backend(&e)),
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Every Secret kept for a sandbox, in any state: the issuer's session and each
    /// delegation, in the broker's home namespace whichever namespace the sandbox is in.
    async fn delete_secrets_of(&self, sandbox_uid: Uuid) -> Result<(), StoreError> {
        let held = self
            .secrets()
            .list(&ListParams::default().labels(&format!("{SANDBOX_UID_LABEL}={sandbox_uid}")))
            .await
            .map_err(|e| backend(&e))?;
        for secret in &held.items {
            match self
                .secrets()
                .delete(&secret.name_any(), &DeleteParams::default())
                .await
            {
                Ok(_) => {}
                Err(e) if is_not_found(&e) => {}
                Err(e) => return Err(backend(&e)),
            }
        }
        // The session by name too, for one written before the label existed.
        match self
            .secrets()
            .delete(&session_name(sandbox_uid), &DeleteParams::default())
            .await
        {
            Ok(_) => {}
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(backend(&e)),
        }
        Ok(())
    }

    /// The claim's segments, oldest first (ADR-0045 decision 6). A Secret under the label
    /// that is not a well-formed segment is skipped.
    async fn segments_of(&self, claim_uid: Uuid) -> Result<Vec<LogSegment>, StoreError> {
        let list = self
            .secrets()
            .list(&ListParams::default().labels(&format!(
                "{LOGS_LABEL}={LOGS_SEGMENT},{CLAIM_UID_LABEL}={claim_uid}"
            )))
            .await
            .map_err(|e| backend(&e))?;
        let mut segments: Vec<LogSegment> = list.items.iter().filter_map(segment_of).collect();
        segments.sort_by_key(|s| s.number);
        Ok(segments)
    }

    /// What `read_logs` answers after cursor `since` when the ring holds nothing newer, from
    /// the segments' metadata alone (no entry is downloaded); `None` when there is something
    /// newer or when the metadata cannot say, and the full read then answers.
    ///
    /// The annotations are written with the entries, in the one object, by
    /// [`segment_secret`], and `seq` rises strictly through the ring (the batch's shape and
    /// the append's filter), so the last `seq` of the newest segment holding a record is the
    /// ring's highest. With that at or below the cursor the full read returns no entry, the
    /// newest segment's `truncated_before` and that `seq`; an empty ring is the default
    /// chunk. A Secret under the label whose annotations are missing or unreadable is not
    /// guessed at: the full read decides what it is.
    async fn idle_chunk(
        &self,
        claim_uid: Uuid,
        since: u64,
    ) -> Result<Option<LogChunk>, StoreError> {
        let list = self
            .secrets()
            .list_metadata(&ListParams::default().labels(&format!(
                "{LOGS_LABEL}={LOGS_SEGMENT},{CLAIM_UID_LABEL}={claim_uid}"
            )))
            .await
            .map_err(|e| backend(&e))?;
        let mut heads = Vec::with_capacity(list.items.len());
        for item in &list.items {
            let Some(head) = segment_head_of(&item.metadata) else {
                return Ok(None);
            };
            heads.push(head);
        }
        heads.sort_by_key(|h| h.number);
        let Some(newest) = heads.last() else {
            return Ok(Some(LogChunk::default()));
        };
        if heads.iter().any(|h| h.last_seq.is_some_and(|l| l > since)) {
            return Ok(None);
        }
        Ok(Some(LogChunk {
            truncated_before: newest.truncated_before,
            entries: Vec::new(),
            last_seq: heads.iter().rev().find_map(|h| h.last_seq),
        }))
    }

    /// Delete the named segments of a claim; one already gone is fine.
    async fn delete_segments(&self, claim_uid: Uuid, numbers: &[u32]) -> Result<(), StoreError> {
        for n in numbers {
            match self
                .secrets()
                .delete(&logs_segment_name(claim_uid, *n), &DeleteParams::default())
                .await
            {
                Ok(_) => {}
                Err(e) if is_not_found(&e) => {}
                Err(e) => return Err(backend(&e)),
            }
        }
        Ok(())
    }

    /// One attempt at appending `batch` (ADR-0045 decisions 4, 6 and 8): read the ring,
    /// keep the records above its highest `seq`, pack, write the changed segments (a replace
    /// on the open one by `resourceVersion`, creates for new ones), then drop the oldest
    /// whole segments beyond the cap. `Err(Conflict)` when another replica wrote in between;
    /// the caller reads again and retries.
    async fn try_append(
        &self,
        rec: &ClaimRecord,
        batch: &LogBatch,
        limits: &LogLimits,
    ) -> Result<LogAppend, StoreError> {
        let mut segments = self.segments_of(rec.uid).await?;
        let highest = segments.iter().rev().find_map(LogSegment::last_seq);
        let new: Vec<&mediatore_proto::LogRecord> = batch
            .records
            .iter()
            .filter(|r| highest.is_none_or(|h| r.seq > h))
            .collect();
        let ignored = batch.records.len() - new.len();
        if new.is_empty() {
            return Ok(LogAppend { stored: 0, ignored });
        }
        let mut entries = Vec::with_capacity(new.len() + 1);
        if batch.dropped_stdout > 0 || batch.dropped_stderr > 0 {
            entries.push(LogEntry::Gap(LogGap {
                lost_stdout: batch.dropped_stdout,
                lost_stderr: batch.dropped_stderr,
            }));
        }
        entries.extend(new.iter().map(|r| LogEntry::Record((*r).clone())));
        let changed = pack(&segments, entries);
        // The ring as it will be: the unchanged older segments, then the changed ones.
        let first_changed = changed[0].number;
        segments.retain(|s| s.number < first_changed);
        segments.extend(changed.iter().cloned());
        let (gone, dropped) = trim(&segments, limits.max_bytes);
        let truncated_before = segments.last().map_or(0, |s| s.truncated_before) + dropped;
        // The owner: the sandbox, when it is in the broker's namespace (the session rule).
        // A record elsewhere is not looked up at all: its namespace is its sandbox's own
        // (`record_from`), and `owner_refs` is `None` for any sandbox outside `home`.
        let owners = if rec.sandbox_uid.is_some() && rec.namespace == self.home {
            match self.sandbox_for(rec).await {
                Ok(sb) => owner_refs(&self.home, &sb),
                Err(StoreError::NotFound(_)) => None,
                Err(e) => return Err(e),
            }
        } else {
            None
        };
        let api = self.secrets();
        for seg in &changed {
            let mut seg = seg.clone();
            seg.truncated_before = truncated_before;
            let secret = segment_secret(rec, &seg, owners.clone());
            let name = secret.name_any();
            let result = if seg.resource_version.is_some() {
                api.replace(&name, &PostParams::default(), &secret).await
            } else {
                api.create(&PostParams::default(), &secret).await
            };
            match result {
                Ok(_) => {}
                Err(e) if is_conflict(&e) => return Err(StoreError::Conflict(name)),
                Err(e) => return Err(backend(&e)),
            }
        }
        if !gone.is_empty() {
            tracing::info!(
                claim_uid = %rec.uid,
                segments = gone.len(),
                bytes = dropped,
                truncated_before,
                "output ring over its cap; oldest segments dropped (ADR-0045 decision 4)"
            );
            self.delete_segments(rec.uid, &gone).await?;
        }
        tracing::debug!(
            claim_uid = %rec.uid,
            records = new.len(),
            ignored,
            bytes = new.iter().map(|r| r.text.len()).sum::<usize>(),
            segments = changed.len(),
            "output appended"
        );
        Ok(LogAppend {
            stored: new.len(),
            ignored,
        })
    }

    /// Every sandbox carrying a record.
    async fn sandboxes_with_records(&self) -> Result<Vec<AgentSandbox>, StoreError> {
        Ok(self
            .all_sandboxes()
            .list(&ListParams::default().labels(CLAIM_UID_LABEL))
            .await
            .map_err(|e| backend(&e))?
            .items)
    }
}

/// The record's part of the status, if the sandbox has one.
#[must_use]
pub fn record_status_of(sb: &AgentSandbox) -> Option<&RecordStatus> {
    sb.status.as_ref()?.record.as_ref()
}

/// Whether `sb` is the sandbox of claim `uid` as the label lookup means it: it carries the
/// claim's label with that value, and its record is that claim's.
fn carries_claim(sb: &AgentSandbox, uid: Uuid) -> bool {
    let uid = uid.to_string();
    sb.labels().get(CLAIM_UID_LABEL) == Some(&uid)
        && record_status_of(sb).is_some_and(|r| r.claim_uid == uid)
}

/// The record on `sb` as its status alone gives it: no envelope is read, so `refresh` and
/// `delegations` are empty. For the callers that read neither (the sweeps).
fn head_of(sb: &AgentSandbox) -> Result<ClaimRecord, StoreError> {
    let Some(status) = record_status_of(sb) else {
        return Err(StoreError::NotFound(sb.name_any()));
    };
    record_from(sb, status)
}

/// The label value for a node's SPIFFE ID: the first 32 hex characters of its SHA-256,
/// since a label value holds 63 characters and the ID does not fit.
#[must_use]
pub fn node_label(node_id: &str) -> String {
    hex::encode(Sha256::digest(node_id.as_bytes()))[..32].to_owned()
}

/// The issuer's session Secret's name for a sandbox.
#[must_use]
pub fn session_name(sandbox_uid: Uuid) -> String {
    format!("mediatore-session-{sandbox_uid}")
}

/// A delegated credential's Secret name for a sandbox (ADR-0035): the audience as the
/// first 16 hex characters of its SHA-256, since an audience name need not be a valid
/// object name; the label carries the name itself.
#[must_use]
pub fn delegation_name(sandbox_uid: Uuid, audience: &str) -> String {
    let digest = hex::encode(Sha256::digest(audience.as_bytes()));
    format!("mediatore-session-{sandbox_uid}-{}", &digest[..16])
}

/// A segment Secret's name: the claim's UID and the segment's number in the ring.
#[must_use]
pub fn logs_segment_name(claim_uid: Uuid, segment: u32) -> String {
    format!("mediatore-logs-{claim_uid}-{segment:06}")
}

/// One segment of a claim's output ring (ADR-0045 decision 6), as read from or about to be
/// written to its Secret.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LogSegment {
    /// Its number in the ring: higher is newer, the highest is the open one.
    number: u32,
    entries: Vec<LogEntry>,
    /// Record text bytes in `entries`.
    bytes: usize,
    /// The ring's cumulative front drops when this segment was last written.
    truncated_before: u64,
    /// The Secret's `resourceVersion`, for the compare-and-set of a replace; `None` for a
    /// segment not yet created.
    resource_version: Option<String>,
}

impl LogSegment {
    fn empty(number: u32, truncated_before: u64) -> Self {
        Self {
            number,
            entries: Vec::new(),
            bytes: 0,
            truncated_before,
            resource_version: None,
        }
    }

    fn first_seq(&self) -> Option<u64> {
        self.entries.iter().find_map(LogEntry::seq)
    }

    fn last_seq(&self) -> Option<u64> {
        self.entries.iter().rev().find_map(LogEntry::seq)
    }

    fn push(&mut self, entry: LogEntry) {
        self.bytes += entry.text_bytes();
        self.entries.push(entry);
    }
}

/// The segment a Secret holds; `None` for a Secret that is not a well-formed segment (it is
/// then left alone by reads and found again by the sweep's label listing).
fn segment_of(secret: &Secret) -> Option<LogSegment> {
    let ann = secret.metadata.annotations.as_ref()?;
    let number: u32 = ann.get(SEGMENT_ANNOTATION)?.parse().ok()?;
    let truncated_before: u64 = ann
        .get(TRUNCATED_ANNOTATION)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let text = secret
        .data
        .as_ref()
        .and_then(|d| d.get(ENTRIES_KEY))
        .map(|b| String::from_utf8_lossy(&b.0).into_owned())
        .unwrap_or_default();
    let mut seg = LogSegment::empty(number, truncated_before);
    seg.resource_version
        .clone_from(&secret.metadata.resource_version);
    for line in text.lines().filter(|l| !l.is_empty()) {
        let entry: LogEntry = serde_json::from_str(line).ok()?;
        seg.push(entry);
    }
    Some(seg)
}

/// The Secret for a segment: labelled by the claim and the sandbox, owned by the sandbox
/// when it shares the broker's namespace (the session Secret's rule), its entries as NDJSON.
fn segment_secret(
    rec: &ClaimRecord,
    seg: &LogSegment,
    owners: Option<Vec<OwnerReference>>,
) -> Secret {
    let mut text = String::new();
    for e in &seg.entries {
        if let Ok(line) = serde_json::to_string(e) {
            text.push_str(&line);
            text.push('\n');
        }
    }
    let mut labels = BTreeMap::from([
        (LOGS_LABEL.to_owned(), LOGS_SEGMENT.to_owned()),
        (CLAIM_UID_LABEL.to_owned(), rec.uid.to_string()),
    ]);
    if let Some(sandbox_uid) = rec.sandbox_uid {
        labels.insert(SANDBOX_UID_LABEL.to_owned(), sandbox_uid.to_string());
    }
    let mut annotations = BTreeMap::from([
        (SEGMENT_ANNOTATION.to_owned(), seg.number.to_string()),
        (BYTES_ANNOTATION.to_owned(), seg.bytes.to_string()),
        (
            TRUNCATED_ANNOTATION.to_owned(),
            seg.truncated_before.to_string(),
        ),
    ]);
    if let Some(f) = seg.first_seq() {
        annotations.insert(FIRST_SEQ_ANNOTATION.to_owned(), f.to_string());
    }
    if let Some(l) = seg.last_seq() {
        annotations.insert(LAST_SEQ_ANNOTATION.to_owned(), l.to_string());
    }
    let mut secret = Secret::default();
    secret.metadata.name = Some(logs_segment_name(rec.uid, seg.number));
    secret.metadata.labels = Some(labels);
    secret.metadata.annotations = Some(annotations);
    secret.metadata.owner_references = owners;
    secret
        .metadata
        .resource_version
        .clone_from(&seg.resource_version);
    secret.type_ = Some("Opaque".into());
    secret.data = Some(BTreeMap::from([(
        ENTRIES_KEY.to_owned(),
        ByteString(text.into_bytes()),
    )]));
    secret
}

/// Pack `entries` into the ring: the open segment (the last of `segments`, or a first one)
/// takes them up to [`LOG_SEGMENT_BYTES`] of record text, then a new segment is opened for
/// the rest, as often as needed. Returns the segments that changed or were created, oldest
/// first; `truncated_before` is copied from the newest segment so every written one carries
/// the ring's current count.
fn pack(segments: &[LogSegment], entries: Vec<LogEntry>) -> Vec<LogSegment> {
    let truncated_before = segments.last().map_or(0, |s| s.truncated_before);
    let mut open = segments
        .last()
        .cloned()
        .unwrap_or_else(|| LogSegment::empty(0, 0));
    open.truncated_before = truncated_before;
    let mut out = Vec::new();
    for e in entries {
        if open.bytes > 0 && open.bytes + e.text_bytes() > LOG_SEGMENT_BYTES {
            let next = LogSegment::empty(open.number + 1, truncated_before);
            out.push(std::mem::replace(&mut open, next));
        }
        open.push(e);
    }
    out.push(open);
    out
}

/// Which of `segments` (oldest first, the newest last) the ring drops so the whole stays
/// within `max_bytes`: whole segments from the front, never the newest. Returns their
/// numbers and the record text bytes they held, which join `truncated_before`.
fn trim(segments: &[LogSegment], max_bytes: usize) -> (Vec<u32>, u64) {
    let mut total: usize = segments.iter().map(|s| s.bytes).sum();
    let mut gone = Vec::new();
    let mut dropped: u64 = 0;
    for s in segments.iter().take(segments.len().saturating_sub(1)) {
        if total <= max_bytes {
            break;
        }
        total -= s.bytes;
        dropped += s.bytes as u64;
        gone.push(s.number);
    }
    (gone, dropped)
}

/// The cursor rule of `LogStore::read_logs`: everything, or the records after `since` with
/// the gaps immediately before the first of them. The same rule as the memory ring's.
fn after_cursor(entries: Vec<LogEntry>, since: Option<u64>) -> Vec<LogEntry> {
    let Some(since) = since else {
        return entries;
    };
    let Some(mut start) = entries
        .iter()
        .position(|e| e.seq().is_some_and(|s| s > since))
    else {
        return Vec::new();
    };
    while start > 0 && entries[start - 1].seq().is_none() {
        start -= 1;
    }
    entries.into_iter().skip(start).collect()
}

/// The claim UID a segment Secret is labelled with, from its metadata.
fn claim_uid_of_segment(meta: &ObjectMeta) -> Option<Uuid> {
    meta.labels
        .as_ref()?
        .get(CLAIM_UID_LABEL)
        .and_then(|v| Uuid::parse_str(v).ok())
}

/// What a segment's annotations say of it, without its entries.
struct SegmentHead {
    /// Its number in the ring.
    number: u32,
    /// The ring's cumulative front drops when it was last written.
    truncated_before: u64,
    /// The highest record `seq` in it; `None` when it holds no record.
    last_seq: Option<u64>,
}

/// The head of a segment from its metadata; `None` when an annotation [`segment_secret`]
/// always writes is missing or does not parse, or when the two `seq` annotations disagree
/// on whether the segment holds a record.
fn segment_head_of(meta: &ObjectMeta) -> Option<SegmentHead> {
    let ann = meta.annotations.as_ref()?;
    let number: u32 = ann.get(SEGMENT_ANNOTATION)?.parse().ok()?;
    let truncated_before: u64 = ann.get(TRUNCATED_ANNOTATION)?.parse().ok()?;
    let last_seq: Option<u64> = match ann.get(LAST_SEQ_ANNOTATION) {
        Some(v) => Some(v.parse().ok()?),
        None => None,
    };
    if ann.contains_key(FIRST_SEQ_ANNOTATION) != last_seq.is_some() {
        return None;
    }
    Some(SegmentHead {
        number,
        truncated_before,
        last_seq,
    })
}

fn backend(e: &kube::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn is_conflict(e: &kube::Error) -> bool {
    matches!(e, kube::Error::Api(a) if a.code == 409)
}

fn is_not_found(e: &kube::Error) -> bool {
    matches!(e, kube::Error::Api(a) if a.code == 404)
}

fn time_of(t: Timestamp) -> Time {
    Time(t)
}

fn record_status_from(rec: &ClaimRecord) -> RecordStatus {
    RecordStatus {
        claim_uid: rec.uid.to_string(),
        created_at: time_of(rec.created_at),
        expires_at: rec.expires_at.map(time_of),
        revoked_at: rec.revoked_at.map(time_of),
        entry_id: rec.entry_id.clone(),
        node_id: rec.node_id.clone(),
        policy_uid: rec.policy_uid.clone(),
        bundle_version: rec.bundle_version,
        refresh: rec.refresh.is_some(),
        delegations: rec
            .delegations
            .iter()
            .map(|(audience, d)| DelegationStatus {
                audience: audience.clone(),
                expires_at: d.expires_at.map(time_of),
            })
            .collect(),
        report: rec
            .report
            .as_ref()
            .and_then(|r| serde_json::to_value(r).ok()),
        exit: rec.exit.as_ref().and_then(|x| serde_json::to_value(x).ok()),
    }
}

/// The namespace a sandbox lives in (ADR-0046 decision 9): the resource's own is the truth.
pub(crate) fn namespace_of(sb: &AgentSandbox) -> String {
    sb.namespace()
        .unwrap_or_else(|| mediatore_store::FALLBACK_NAMESPACE.to_owned())
}

/// The record a sandbox and its `status.record` describe, without the envelope.
fn record_from(sb: &AgentSandbox, status: &RecordStatus) -> Result<ClaimRecord, StoreError> {
    let uid = Uuid::parse_str(&status.claim_uid)
        .map_err(|e| StoreError::Backend(format!("status.record.claimUid: {e}")))?;
    let created_at = status.created_at.0;
    Ok(ClaimRecord {
        uid,
        name: sb.name_any(),
        namespace: namespace_of(sb),
        subject: Subject::from(&sb.spec.subject),
        entry_id: status.entry_id.clone(),
        node_id: status.node_id.clone(),
        audiences: sb.spec.audiences.clone(),
        workload: Workload::from(&sb.spec.workload),
        ttl_seconds: sb.spec.ttl_seconds,
        refresh: None,
        created_at,
        expires_at: status.expires_at.as_ref().map(|t| t.0),
        revoked_at: status.revoked_at.as_ref().map(|t| t.0),
        sandbox_uid: sandbox_uid_of(sb),
        policy_uid: status.policy_uid.clone(),
        bundle_version: status.bundle_version,
        report: status
            .report
            .clone()
            .and_then(|v| serde_json::from_value::<ClaimReport>(v).ok()),
        exit: status
            .exit
            .clone()
            .and_then(|v| serde_json::from_value::<WorkloadExit>(v).ok()),
        delegations: BTreeMap::new(),
    })
}

/// The owner reference a session Secret in `home` carries: its sandbox, when the sandbox
/// is in `home` too. An owner reference cannot cross a namespace (the API server treats
/// it as absent and collects the dependent), so a sandbox elsewhere owns nothing and the
/// retention sweep deletes the Secret with it.
fn owner_refs(home: &str, sb: &AgentSandbox) -> Option<Vec<OwnerReference>> {
    (sb.namespace().as_deref() == Some(home)).then(|| vec![owner_of(sb)])
}

fn owner_of(sb: &AgentSandbox) -> OwnerReference {
    OwnerReference {
        // From the type, so the version cannot drift from the derive (ADR-0048 decision 3).
        api_version: AgentSandbox::api_version(&()).into_owned(),
        kind: "AgentSandbox".into(),
        name: sb.name_any(),
        uid: sb.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(false),
    }
}

/// What `write_one_envelope` does with one envelope Secret, from whether the record carries an envelope and whether a
/// Secret exists (ADR-0043 decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvelopeWrite {
    /// The record carries it and the Secret exists: replace its data.
    Replace,
    /// The record carries it and no Secret exists: create one.
    Create,
    /// The record no longer carries it (a released claim) and a Secret exists: delete the object, so no empty
    /// marker outlives the claim.
    Delete,
    /// Neither: nothing to do.
    Nothing,
}

fn envelope_write(carried: bool, exists: bool) -> EnvelopeWrite {
    match (carried, exists) {
        (true, true) => EnvelopeWrite::Replace,
        (true, false) => EnvelopeWrite::Create,
        (false, true) => EnvelopeWrite::Delete,
        (false, false) => EnvelopeWrite::Nothing,
    }
}

fn envelope_data(sealed: &Sealed) -> serde_json::Value {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    serde_json::json!({
        "key_id": b64.encode(sealed.key_id.as_bytes()),
        "nonce": b64.encode(&sealed.nonce),
        "ciphertext": b64.encode(&sealed.ciphertext),
    })
}

fn envelope_of(secret: &Secret) -> Option<Sealed> {
    let data = secret.data.as_ref()?;
    let key_id = String::from_utf8(data.get("key_id")?.0.clone()).ok()?;
    Some(Sealed {
        key_id,
        nonce: data.get("nonce")?.0.clone(),
        ciphertext: data.get("ciphertext")?.0.clone(),
    })
}

/// The Secret a parked or claimed session is kept in: the issuer's (`rec.audience` `None`)
/// or a delegation's, in the `state` its label says.
fn session_secret(rec: &SessionRecord, state: &str) -> Secret {
    let sandbox_uid = rec.sandbox_uid;
    let (subject, issuer, sealed, created_at) = (
        &rec.subject,
        rec.issuer.as_str(),
        &rec.refresh,
        rec.created_at,
    );
    let (audience, expires_at) = (rec.audience.as_deref(), rec.expires_at);
    let mut data = BTreeMap::new();
    if let Some(e) = expires_at {
        data.insert(
            "expires_at".to_owned(),
            ByteString(e.to_string().into_bytes()),
        );
    }
    data.insert(
        "subject".to_owned(),
        ByteString(serde_json::to_vec(subject).unwrap_or_default()),
    );
    data.insert("issuer".to_owned(), ByteString(issuer.as_bytes().to_vec()));
    data.insert(
        "created_at".to_owned(),
        ByteString(created_at.to_string().into_bytes()),
    );
    data.insert(
        "key_id".to_owned(),
        ByteString(sealed.key_id.as_bytes().to_vec()),
    );
    data.insert("nonce".to_owned(), ByteString(sealed.nonce.clone()));
    data.insert(
        "ciphertext".to_owned(),
        ByteString(sealed.ciphertext.clone()),
    );
    let mut secret = Secret::default();
    let mut labels = BTreeMap::from([
        (SANDBOX_UID_LABEL.to_owned(), sandbox_uid.to_string()),
        (SESSION_LABEL.to_owned(), state.to_owned()),
    ]);
    secret.metadata.name = Some(match audience {
        Some(a) => {
            labels.insert(AUDIENCE_LABEL.to_owned(), a.to_owned());
            delegation_name(sandbox_uid, a)
        }
        None => session_name(sandbox_uid),
    });
    secret.metadata.labels = Some(labels);
    secret.type_ = Some("Opaque".into());
    secret.data = Some(data);
    secret
}

fn session_of(secret: &Secret) -> Option<SessionRecord> {
    let data = secret.data.as_ref()?;
    let text = |k: &str| {
        data.get(k)
            .map(|b| String::from_utf8_lossy(&b.0).into_owned())
    };
    let sandbox_uid = secret
        .metadata
        .labels
        .as_ref()?
        .get(SANDBOX_UID_LABEL)
        .and_then(|u| Uuid::parse_str(u).ok())?;
    Some(SessionRecord {
        sandbox_uid,
        subject: serde_json::from_str(&text("subject")?).ok()?,
        issuer: text("issuer")?,
        refresh: envelope_of(secret)?,
        created_at: text("created_at")?.parse().ok()?,
        audience: secret
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(AUDIENCE_LABEL))
            .cloned(),
        expires_at: text("expires_at").and_then(|t| t.parse().ok()),
    })
}

fn node_record_of(n: &SandboxNode) -> Result<NodeRecord, StoreError> {
    Ok(NodeRecord {
        ek_hash: n.spec.ek_hash.clone(),
        node_id: n.spec.node_id.clone(),
        dmi_uuid: Uuid::parse_str(&n.spec.dmi_uuid)
            .map_err(|e| StoreError::Backend(format!("sandboxnode dmiUuid: {e}")))?,
        hostname: n.spec.hostname.clone(),
        provider: n.spec.provider.as_deref().and_then(|p| {
            serde_json::from_value::<Provider>(serde_json::Value::String(p.into())).ok()
        }),
        banned: n.spec.banned,
        registered_at: n.spec.registered_at.0,
    })
}

fn sandbox_node_of(rec: &NodeRecord) -> SandboxNode {
    let provider = rec
        .provider
        .as_ref()
        .and_then(|p| serde_json::to_value(p).ok())
        .and_then(|v| v.as_str().map(ToOwned::to_owned));
    let mut node = SandboxNode::new(
        &rec.ek_hash,
        SandboxNodeSpec {
            ek_hash: rec.ek_hash.clone(),
            node_id: rec.node_id.clone(),
            dmi_uuid: rec.dmi_uuid.to_string(),
            hostname: rec.hostname.clone(),
            provider,
            banned: rec.banned,
            registered_at: time_of(rec.registered_at),
        },
    );
    node.metadata.labels = Some(BTreeMap::from([(
        DMI_LABEL.to_owned(),
        rec.dmi_uuid.to_string(),
    )]));
    node
}

/// The `PolicyFloor` name for a policy.
#[must_use]
pub fn floor_name(namespace: &str, name: &str) -> String {
    format!("{namespace}.{name}")
}

fn floor_of(f: &PolicyFloor) -> Result<mediatore_store::PolicyFloor, StoreError> {
    Ok(mediatore_store::PolicyFloor {
        namespace: f.spec.policy_namespace.clone(),
        name: f.spec.policy_name.clone(),
        uid: f.spec.uid.clone(),
        version: f.spec.version,
        issued_at: f
            .spec
            .issued_at
            .parse()
            .map_err(|e| StoreError::Backend(format!("policyfloor issuedAt: {e}")))?,
    })
}

fn floor_spec_of(f: &mediatore_store::PolicyFloor) -> PolicyFloorSpec {
    PolicyFloorSpec {
        policy_namespace: f.namespace.clone(),
        policy_name: f.name.clone(),
        uid: f.uid.clone(),
        version: f.version,
        issued_at: format!("{:.9}", f.issued_at),
    }
}

#[async_trait]
impl LogStore for KubeStore {
    async fn append_logs(
        &self,
        rec: &ClaimRecord,
        batch: &LogBatch,
        limits: &LogLimits,
    ) -> Result<LogAppend, StoreError> {
        let mut last = StoreError::Conflict(rec.uid.to_string());
        for _ in 0..SEGMENT_WRITE_ATTEMPTS {
            match self.try_append(rec, batch, limits).await {
                Err(StoreError::Conflict(name)) => {
                    tracing::debug!(claim_uid = %rec.uid, segment = %name, "segment write conflicted; reading the ring again");
                    last = StoreError::Conflict(name);
                }
                other => return other,
            }
        }
        Err(last)
    }

    async fn read_logs(&self, claim_uid: Uuid, since: Option<u64>) -> Result<LogChunk, StoreError> {
        // A follower's poll usually finds nothing new: the segments' metadata says so
        // without the ring being downloaded.
        if let Some(since) = since
            && let Some(chunk) = self.idle_chunk(claim_uid, since).await?
        {
            return Ok(chunk);
        }
        let segments = self.segments_of(claim_uid).await?;
        let Some(newest) = segments.last() else {
            return Ok(LogChunk::default());
        };
        let truncated_before = newest.truncated_before;
        let last_seq = segments.iter().rev().find_map(LogSegment::last_seq);
        let entries: Vec<LogEntry> = segments.into_iter().flat_map(|s| s.entries).collect();
        Ok(LogChunk {
            truncated_before,
            entries: after_cursor(entries, since),
            last_seq,
        })
    }

    async fn delete_logs(&self, claim_uid: Uuid) -> Result<(), StoreError> {
        let list = self
            .secrets()
            .list(&ListParams::default().labels(&format!(
                "{LOGS_LABEL}={LOGS_SEGMENT},{CLAIM_UID_LABEL}={claim_uid}"
            )))
            .await
            .map_err(|e| backend(&e))?;
        for secret in &list.items {
            match self
                .secrets()
                .delete(&secret.name_any(), &DeleteParams::default())
                .await
            {
                Ok(_) => {}
                Err(e) if is_not_found(&e) => {}
                Err(e) => return Err(backend(&e)),
            }
        }
        Ok(())
    }

    async fn sweep_logs(&self, before: Timestamp) -> Result<usize, StoreError> {
        // The labels are all that is read of the segments: their metadata, not their entries.
        let list = self
            .secrets()
            .list_metadata(&ListParams::default().labels(&format!("{LOGS_LABEL}={LOGS_SEGMENT}")))
            .await
            .map_err(|e| backend(&e))?;
        let claims: std::collections::BTreeSet<Uuid> = list
            .items
            .iter()
            .filter_map(|s| claim_uid_of_segment(&s.metadata))
            .collect();
        let mut swept = 0;
        for claim_uid in claims {
            // When the claim ended is on the status: no envelope is read for it.
            let head = self
                .sandbox_of_claim(claim_uid)
                .await
                .and_then(|sb| head_of(&sb));
            let gone = match head {
                // The record is gone: an orphan ring (ADR-0045 decision 7).
                Err(StoreError::NotFound(_)) => true,
                Err(e) => return Err(e),
                Ok(rec) => rec.ended_at().is_some_and(|e| e < before),
            };
            if !gone {
                continue;
            }
            tracing::info!(%claim_uid, "stored output swept (ADR-0045 decision 7)");
            self.delete_logs(claim_uid).await?;
            swept += 1;
        }
        Ok(swept)
    }
}

#[async_trait]
impl ClaimStore for KubeStore {
    async fn put_claim(&self, rec: ClaimRecord) -> Result<(), StoreError> {
        let sb = self.sandbox_for(&rec).await?;
        if record_status_of(&sb).is_some() {
            return Err(StoreError::Conflict(rec.uid.to_string()));
        }
        if self.sandbox_of_claim(rec.uid).await.is_ok() {
            return Err(StoreError::Conflict(rec.uid.to_string()));
        }
        self.write_envelope(&sb, &rec).await?;
        self.write_record(&sb, &rec).await
    }

    async fn get_claim(&self, uid: Uuid) -> Result<ClaimRecord, StoreError> {
        let sb = self.sandbox_of_claim(uid).await?;
        self.record_of(&sb).await
    }

    async fn get_claim_by_name(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<ClaimRecord, StoreError> {
        // By name in that namespace only: one read of the one object that name can be there,
        // taken when it carries the claim label, as the listing of recorded sandboxes
        // required. No object, or one without the label, is not found.
        if namespace.is_empty() || name.is_empty() {
            return Err(StoreError::NotFound(name.to_owned()));
        }
        let sb = self
            .sandboxes_in(namespace)
            .get_opt(name)
            .await
            .map_err(|e| backend(&e))?
            .filter(|sb| sb.labels().contains_key(CLAIM_UID_LABEL))
            .ok_or_else(|| StoreError::NotFound(name.to_owned()))?;
        self.record_of(&sb).await
    }

    async fn update_claim(&self, rec: ClaimRecord) -> Result<(), StoreError> {
        let sb = self.sandbox_of_claim(rec.uid).await?;
        self.write_envelope(&sb, &rec).await?;
        self.write_record(&sb, &rec).await
    }

    async fn revoke_claim(&self, uid: Uuid, at: Timestamp) -> Result<(), StoreError> {
        let sb = self.sandbox_of_claim(uid).await?;
        let mut rec = self.record_of(&sb).await?;
        rec.revoked_at.get_or_insert(at);
        rec.refresh = None;
        rec.delegations.clear();
        self.write_envelope(&sb, &rec).await?;
        self.write_record(&sb, &rec).await
    }

    async fn get_claim_by_node(&self, node_id: &str) -> Result<ClaimRecord, StoreError> {
        let now = Timestamp::now();
        let list = self
            .all_sandboxes()
            .list(&ListParams::default().labels(&format!("{NODE_LABEL}={}", node_label(node_id))))
            .await
            .map_err(|e| backend(&e))?;
        let mut live: Vec<ClaimRecord> = Vec::new();
        for sb in &list.items {
            if let Ok(rec) = self.record_of(sb).await
                && rec.node_id.as_deref() == Some(node_id)
                && rec.is_live(now)
            {
                live.push(rec);
            }
        }
        live.into_iter()
            .max_by_key(|c| c.created_at)
            .ok_or_else(|| StoreError::NotFound(node_id.to_owned()))
    }

    async fn list_claims(&self) -> Result<Vec<ClaimRecord>, StoreError> {
        let mut out = Vec::new();
        for sb in self.sandboxes_with_records().await? {
            if let Ok(rec) = self.record_of(&sb).await {
                out.push(rec);
            }
        }
        Ok(out)
    }

    async fn put_node(&self, rec: NodeRecord) -> Result<(), StoreError> {
        let api = self.nodes();
        if let Some(existing) = api.get_opt(&rec.ek_hash).await.map_err(|e| backend(&e))? {
            if existing.spec.dmi_uuid != rec.dmi_uuid.to_string() {
                return Err(StoreError::Conflict(format!(
                    "ek_hash {} already registered for dmi {}",
                    rec.ek_hash, existing.spec.dmi_uuid
                )));
            }
            return Ok(());
        }
        match api
            .create(&PostParams::default(), &sandbox_node_of(&rec))
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if is_conflict(&e) => {
                // Registered by another replica between the get and the create: same check.
                let existing = api.get(&rec.ek_hash).await.map_err(|e| backend(&e))?;
                if existing.spec.dmi_uuid == rec.dmi_uuid.to_string() {
                    Ok(())
                } else {
                    Err(StoreError::Conflict(format!(
                        "ek_hash {} already registered for dmi {}",
                        rec.ek_hash, existing.spec.dmi_uuid
                    )))
                }
            }
            Err(e) => Err(backend(&e)),
        }
    }

    async fn get_node(&self, ek_hash: &str) -> Result<NodeRecord, StoreError> {
        let node = self
            .nodes()
            .get_opt(ek_hash)
            .await
            .map_err(|e| backend(&e))?
            .ok_or_else(|| StoreError::NotFound(ek_hash.to_owned()))?;
        node_record_of(&node)
    }

    async fn get_node_by_dmi(&self, dmi_uuid: Uuid) -> Result<NodeRecord, StoreError> {
        let list = self
            .nodes()
            .list(&ListParams::default().labels(&format!("{DMI_LABEL}={dmi_uuid}")))
            .await
            .map_err(|e| backend(&e))?;
        list.items
            .iter()
            .find(|n| n.spec.dmi_uuid == dmi_uuid.to_string())
            .map(node_record_of)
            .transpose()?
            .ok_or_else(|| StoreError::NotFound(dmi_uuid.to_string()))
    }

    async fn ban_node(&self, ek_hash: &str) -> Result<(), StoreError> {
        match self
            .nodes()
            .patch(
                ek_hash,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({ "spec": { "banned": true } })),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if is_not_found(&e) => Err(StoreError::NotFound(ek_hash.to_owned())),
            Err(e) => Err(backend(&e)),
        }
    }

    async fn list_nodes(&self) -> Result<Vec<NodeRecord>, StoreError> {
        self.nodes()
            .list(&ListParams::default())
            .await
            .map_err(|e| backend(&e))?
            .items
            .iter()
            .map(node_record_of)
            .collect()
    }

    async fn delete_node(&self, ek_hash: &str) -> Result<(), StoreError> {
        match self.nodes().delete(ek_hash, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(backend(&e)),
        }
    }

    async fn sweep(&self, before: Timestamp) -> Result<usize, StoreError> {
        let mut swept = 0;
        for sb in self.sandboxes_with_records().await? {
            // From the status alone: the sweep reads neither the envelope nor a delegation,
            // it deletes their Secrets by label.
            let Ok(rec) = head_of(&sb) else {
                continue;
            };
            if rec.ended_at().is_none_or(|e| e >= before) {
                continue;
            }
            let name = sb.name_any();
            tracing::info!(
                sandbox = %name,
                claim_uid = %rec.uid,
                subject = %rec.subject.id,
                node_id = rec.node_id.as_deref().unwrap_or("-"),
                created_at = %rec.created_at,
                expires_at = ?rec.expires_at,
                revoked_at = ?rec.revoked_at,
                report = rec.report.is_some(),
                exit = ?rec.exit.as_ref().map(|x| (x.exit.code, x.exit.signal, x.exit.restarts)),
                "claim swept after its retention (ADR-0034 decision 4): the audit line"
            );
            // The session and every delegation go with the sandbox: by owner reference when
            // they share the namespace, by this delete otherwise (ADR-0046 decision 9).
            if let Some(sandbox_uid) = rec.sandbox_uid {
                self.delete_secrets_of(sandbox_uid).await?;
            }
            // The output ring too (ADR-0045 decision 7): by the claim's label, so a segment
            // written for a record without a sandbox UID goes as well.
            self.delete_logs(rec.uid).await?;
            if sb.metadata.deletion_timestamp.is_none()
                && let Err(e) = self
                    .sandboxes_of(&sb)
                    .delete(&name, &DeleteParams::default())
                    .await
                && !is_not_found(&e)
            {
                return Err(backend(&e));
            }
            let finalizers: Vec<String> = sb
                .finalizers()
                .iter()
                .filter(|f| *f != FINALIZER)
                .cloned()
                .collect();
            match self
                .sandboxes_of(&sb)
                .patch(
                    &name,
                    &PatchParams::default(),
                    &Patch::Merge(serde_json::json!({ "metadata": { "finalizers": finalizers } })),
                )
                .await
            {
                Ok(_) => {}
                Err(e) if is_not_found(&e) => {}
                Err(e) => return Err(backend(&e)),
            }
            // The sandbox is going: where it was is no longer worth trying first.
            self.forget(rec.uid);
            swept += 1;
        }
        Ok(swept)
    }

    async fn put_session(&self, rec: SessionRecord) -> Result<(), StoreError> {
        let secret = session_secret(&rec, "parked");
        match self.secrets().create(&PostParams::default(), &secret).await {
            Ok(_) => Ok(()),
            Err(e) if is_conflict(&e) => Err(StoreError::Conflict(rec.sandbox_uid.to_string())),
            Err(e) => Err(backend(&e)),
        }
    }

    async fn take_session(&self, sandbox_uid: Uuid) -> Result<Option<SessionRecord>, StoreError> {
        let name = session_name(sandbox_uid);
        let Some(secret) = self
            .secrets()
            .get_opt(&name)
            .await
            .map_err(|e| backend(&e))?
        else {
            return Ok(None);
        };
        let parked = secret
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(SESSION_LABEL))
            .is_some_and(|s| s == "parked");
        if !parked {
            return Ok(None);
        }
        let Some(session) = session_of(&secret) else {
            return Ok(None);
        };
        // Taken: the record's envelope from here on (put_claim writes it as claimed).
        self.secrets()
            .patch(
                &name,
                &PatchParams::default(),
                &Patch::Merge(
                    serde_json::json!({ "metadata": { "labels": { SESSION_LABEL: "claimed" } } }),
                ),
            )
            .await
            .map_err(|e| backend(&e))?;
        Ok(Some(session))
    }

    async fn take_delegations(&self, sandbox_uid: Uuid) -> Result<Vec<SessionRecord>, StoreError> {
        let list = self
            .secrets()
            .list(&ListParams::default().labels(&format!(
                "{SANDBOX_UID_LABEL}={sandbox_uid},{SESSION_LABEL}=parked,{AUDIENCE_LABEL}"
            )))
            .await
            .map_err(|e| backend(&e))?;
        let mut out = Vec::new();
        for secret in &list.items {
            let Some(session) = session_of(secret) else {
                continue;
            };
            self.secrets()
                .patch(
                    &secret.name_any(),
                    &PatchParams::default(),
                    &Patch::Merge(
                        serde_json::json!({ "metadata": { "labels": { SESSION_LABEL: "claimed" } } }),
                    ),
                )
                .await
                .map_err(|e| backend(&e))?;
            out.push(session);
        }
        out.sort_by(|a, b| a.audience.cmp(&b.audience));
        Ok(out)
    }

    async fn delete_session(&self, sandbox_uid: Uuid) -> Result<(), StoreError> {
        // Every parked Secret of the sandbox, the issuer's and the delegations; a claimed
        // one is the record's and goes with the record, not here.
        let list = self
            .secrets()
            .list(&ListParams::default().labels(&format!(
                "{SANDBOX_UID_LABEL}={sandbox_uid},{SESSION_LABEL}=parked"
            )))
            .await
            .map_err(|e| backend(&e))?;
        for secret in &list.items {
            match self
                .secrets()
                .delete(&secret.name_any(), &DeleteParams::default())
                .await
            {
                Ok(_) => {}
                Err(e) if is_not_found(&e) => {}
                Err(e) => return Err(backend(&e)),
            }
        }
        Ok(())
    }

    async fn sweep_sessions(&self, before: Timestamp) -> Result<usize, StoreError> {
        let now = Timestamp::now();
        // Every session Secret in one list, parked or claimed; the label's value says which
        // rule applies, and a value that is neither is left alone.
        let list = self
            .secrets()
            .list(&ListParams::default().labels(SESSION_LABEL))
            .await
            .map_err(|e| backend(&e))?;
        let mut swept = 0;
        for secret in &list.items {
            let state = secret.labels().get(SESSION_LABEL).map(String::as_str);
            let Some(session) = session_of(secret) else {
                continue;
            };
            let expired = session.expires_at.is_some_and(|e| e <= now);
            let due = match state {
                // Old (the grace period) or expired (ADR-0043 decision 4); the same rule as the in-memory store.
                Some("parked") => session.created_at < before || expired,
                // A bound claim's envelopes (relabelled `claimed` when the record took them) go when they expire,
                // not at the claim's end: no secret is stored past its expiry (the operator's rule, ADR-0043
                // decision 4). The record reads each envelope by name and skips a missing one, so the delegation
                // is simply gone from it. The age rule does not apply: a long claim's envelope is old and still
                // wanted.
                Some("claimed") => expired,
                _ => false,
            };
            if !due {
                continue;
            }
            match self
                .secrets()
                .delete(&secret.name_any(), &DeleteParams::default())
                .await
            {
                Ok(_) => swept += 1,
                Err(e) if is_not_found(&e) => {}
                Err(e) => return Err(backend(&e)),
            }
        }
        Ok(swept)
    }

    async fn get_policy_floor(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<mediatore_store::PolicyFloor>, StoreError> {
        self.floors()
            .get_opt(&floor_name(namespace, name))
            .await
            .map_err(|e| backend(&e))?
            .as_ref()
            .map(floor_of)
            .transpose()
    }

    async fn advance_policy_floor(
        &self,
        held: Option<&mediatore_store::PolicyFloor>,
        next: mediatore_store::PolicyFloor,
    ) -> Result<(), StoreError> {
        if let Some(h) = held
            && (h.namespace != next.namespace || h.name != next.name)
        {
            return Err(StoreError::Conflict(format!(
                "held floor names {}/{}, next names {}/{}",
                h.namespace, h.name, next.namespace, next.name
            )));
        }
        let name = floor_name(&next.namespace, &next.name);
        let api = self.floors();
        let current = api.get_opt(&name).await.map_err(|e| backend(&e))?;
        match (held, current) {
            (None, None) => {
                let floor = PolicyFloor::new(&name, floor_spec_of(&next));
                match api.create(&PostParams::default(), &floor).await {
                    Ok(_) => Ok(()),
                    Err(e) if is_conflict(&e) => Err(StoreError::Conflict(name)),
                    Err(e) => Err(backend(&e)),
                }
            }
            (Some(h), Some(mut current)) => {
                let stored = floor_of(&current)?;
                if stored != *h {
                    return Err(StoreError::Conflict(name));
                }
                current.spec = floor_spec_of(&next);
                match api.replace(&name, &PostParams::default(), &current).await {
                    Ok(_) => Ok(()),
                    Err(e) if is_conflict(&e) => Err(StoreError::Conflict(name)),
                    Err(e) => Err(backend(&e)),
                }
            }
            // Decided from no floor while one exists, or from a floor that is gone.
            _ => Err(StoreError::Conflict(name)),
        }
    }

    async fn ping(&self) -> Result<(), StoreError> {
        self.all_sandboxes()
            .list(&ListParams::default().limit(1))
            .await
            .map(|_| ())
            .map_err(|e| backend(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_released_claims_envelope_secret_is_deleted_not_blanked() {
        // ADR-0043 decision 4: when the record no longer carries an envelope (the claim was released) its Secret is
        // deleted, not emptied and left as a marker; the released claim is on the `AgentSandbox` status record.
        assert_eq!(envelope_write(true, true), EnvelopeWrite::Replace);
        assert_eq!(envelope_write(true, false), EnvelopeWrite::Create);
        assert_eq!(envelope_write(false, true), EnvelopeWrite::Delete);
        assert_eq!(envelope_write(false, false), EnvelopeWrite::Nothing);
    }

    #[test]
    fn a_session_is_owned_by_its_sandbox_only_within_the_brokers_namespace() {
        let mut sb = AgentSandbox::new(
            "sb",
            crate::sandbox::AgentSandboxSpec {
                subject: crate::sandbox::SandboxSubject {
                    issuer: "https://idp.example".into(),
                    id: "octocat".into(),
                    display: None,
                },
                pool_ref: Some(banlieue_api::common::LocalObjectReference {
                    name: "pool-a".into(),
                }),
                pool_selector: None,
                selection: None,
                ttl_seconds: 600,
                audiences: vec![],
                workload: crate::sandbox::SandboxWorkload {
                    image: "registry.internal:5000/x:1".into(),
                    args: vec!["/bin/x".into()],
                    restart: None,
                    logs: false,
                },
                policy_ref: None,
            },
        );
        sb.metadata.uid = Some("u-1".into());
        sb.metadata.namespace = Some("banlieue-system".into());
        let owners = owner_refs("banlieue-system", &sb).expect("same namespace: owned");
        assert_eq!(owners[0].kind, "AgentSandbox");
        assert_eq!(owners[0].uid, "u-1");
        assert!(
            owner_refs("sandboxes", &sb).is_none(),
            "a reference across namespaces would be collected"
        );
    }

    /// A fake Kubernetes API for the store's tests: sandboxes in a tenant namespace, Secrets
    /// in the broker's home namespace, every request recorded. It answers as the API server
    /// does where the store depends on it: a read by name honours the namespace and the name
    /// and is a 404 for an unknown one, a list honours its namespace and label selector, a
    /// merge patch is applied (the status only through the status subresource), a delete
    /// waits on finalizers, and a metadata-only list carries no data.
    mod fake {
        use super::*;
        use http::{Request, Response};
        use http_body_util::BodyExt as _;
        use kube::client::Body;
        use std::sync::{Arc, Mutex};

        pub const HOME: &str = "infra";
        pub const TENANT: &str = "team-a";

        #[derive(Default)]
        pub struct State {
            pub sandboxes: Vec<serde_json::Value>,
            pub secrets: Vec<serde_json::Value>,
            /// Every request, in order: the verb and the path.
            pub log: Vec<(String, String)>,
            /// The paths of the lists that asked for metadata only.
            pub metadata_lists: Vec<String>,
        }

        pub fn store(state: &Arc<Mutex<State>>) -> KubeStore {
            let (svc, mut handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
            let state = Arc::clone(state);
            tokio::spawn(async move {
                while let Some((req, send)) = handle.next_request().await {
                    let method = req.method().as_str().to_owned();
                    let path = req.uri().path().to_owned();
                    let query = req
                        .uri()
                        .query()
                        .unwrap_or("")
                        .replace("%3D", "=")
                        .replace("%2C", ",")
                        .replace("%2F", "/");
                    // What `Api::list_metadata` asks for (a `PartialObjectMetadataList`).
                    let partial = req
                        .headers()
                        .get(http::header::ACCEPT)
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|a| a.contains("as=PartialObjectMetadataList"));
                    let sent: serde_json::Value = req
                        .into_body()
                        .collect()
                        .await
                        .ok()
                        .and_then(|b| serde_json::from_slice(&b.to_bytes()).ok())
                        .unwrap_or(serde_json::Value::Null);
                    let call = Call {
                        method: &method,
                        path: &path,
                        query: &query,
                        partial,
                    };
                    let (code, body) = answer(&mut state.lock().unwrap(), &call, sent);
                    {
                        let mut st = state.lock().unwrap();
                        if partial {
                            st.metadata_lists.push(path.clone());
                        }
                        st.log.push((method, path));
                    }
                    send.send_response(
                        Response::builder()
                            .status(code)
                            .header("content-type", "application/json")
                            .body(Body::from(serde_json::to_vec(&body).unwrap()))
                            .unwrap(),
                    );
                }
            });
            KubeStore::new(Client::new(svc, HOME))
        }

        /// One request, as `answer` reads it.
        struct Call<'a> {
            method: &'a str,
            path: &'a str,
            query: &'a str,
            partial: bool,
        }

        fn matches(object: &serde_json::Value, selector: &str) -> bool {
            selector
                .split(',')
                .filter(|c| !c.is_empty())
                .all(|c| match c.split_once('=') {
                    Some((k, v)) => object["metadata"]["labels"][k] == v,
                    None => object["metadata"]["labels"].get(c).is_some(),
                })
        }

        fn status(code: u16, reason: &str, message: &str) -> (u16, serde_json::Value) {
            (
                code,
                serde_json::json!({"apiVersion": "v1", "kind": "Status", "status": "Failure",
                    "reason": reason, "code": code, "message": message, "metadata": {}}),
            )
        }

        fn conflict(what: &str) -> (u16, serde_json::Value) {
            status(409, "Conflict", what)
        }

        fn not_found() -> (u16, serde_json::Value) {
            status(404, "NotFound", "not found")
        }

        /// A JSON merge patch (RFC 7396): objects merge, `null` removes, anything else
        /// replaces.
        fn merge(target: &mut serde_json::Value, patch: &serde_json::Value) {
            let Some(patch) = patch.as_object() else {
                *target = patch.clone();
                return;
            };
            if !target.is_object() {
                *target = serde_json::json!({});
            }
            if let Some(map) = target.as_object_mut() {
                for (k, v) in patch {
                    if v.is_null() {
                        map.remove(k);
                    } else {
                        merge(map.entry(k.clone()).or_insert(serde_json::Value::Null), v);
                    }
                }
            }
        }

        fn answer(
            st: &mut State,
            call: &Call<'_>,
            sent: serde_json::Value,
        ) -> (u16, serde_json::Value) {
            let selector = call
                .query
                .split('&')
                .find_map(|p| p.strip_prefix("labelSelector="))
                .unwrap_or("");
            if call.path.contains("/agentsandboxes") {
                answer_sandbox(st, call, selector, &sent)
            } else {
                answer_secret(st, call, selector, sent)
            }
        }

        /// `AgentSandbox`: every namespace or one for a list, one namespace and one name for
        /// anything else, `/status` for the status subresource.
        fn answer_sandbox(
            st: &mut State,
            call: &Call<'_>,
            selector: &str,
            sent: &serde_json::Value,
        ) -> (u16, serde_json::Value) {
            let (head, tail) = call
                .path
                .split_once("/agentsandboxes")
                .unwrap_or((call.path, ""));
            let ns = head.split_once("/namespaces/").map(|(_, ns)| ns);
            let tail = tail.trim_start_matches('/');
            let (name, subresource) = match tail.strip_suffix("/status") {
                Some(name) => (name, true),
                None => (tail, false),
            };
            let in_ns =
                |s: &serde_json::Value| ns.is_none_or(|ns| s["metadata"]["namespace"] == ns);
            if name.is_empty() {
                if call.method != "GET" {
                    return status(500, "InternalError", "unexpected request on the collection");
                }
                let items: Vec<&serde_json::Value> = st
                    .sandboxes
                    .iter()
                    .filter(|s| in_ns(s) && matches(s, selector))
                    .collect();
                return (
                    200,
                    serde_json::json!({"apiVersion": "mediatore.io/v1beta1",
                        "kind": "AgentSandboxList", "metadata": {"resourceVersion": "1"},
                        "items": items}),
                );
            }
            // A named sandbox is read in its namespace; there is no such route without one.
            let found = ns.and_then(|_| {
                st.sandboxes
                    .iter()
                    .position(|s| in_ns(s) && s["metadata"]["name"] == name)
            });
            let Some(i) = found else {
                return not_found();
            };
            match call.method {
                "GET" => (200, st.sandboxes[i].clone()),
                "PATCH" => {
                    // The status moves through its subresource alone, and nothing else does.
                    if subresource {
                        merge(&mut st.sandboxes[i]["status"], &sent["status"]);
                    } else {
                        let mut patch = sent.clone();
                        if let Some(map) = patch.as_object_mut() {
                            map.remove("status");
                        }
                        merge(&mut st.sandboxes[i], &patch);
                    }
                    let sb = st.sandboxes[i].clone();
                    let released = sb["metadata"]["finalizers"]
                        .as_array()
                        .is_none_or(Vec::is_empty);
                    if released && !sb["metadata"]["deletionTimestamp"].is_null() {
                        st.sandboxes.remove(i);
                    }
                    (200, sb)
                }
                "DELETE" => {
                    // Held by a finalizer: marked, and gone when the last one is released.
                    let finalized = st.sandboxes[i]["metadata"]["finalizers"]
                        .as_array()
                        .is_some_and(|f| !f.is_empty());
                    if finalized {
                        st.sandboxes[i]["metadata"]["deletionTimestamp"] =
                            "2026-01-02T00:00:00Z".into();
                        (200, st.sandboxes[i].clone())
                    } else {
                        (200, st.sandboxes.remove(i))
                    }
                }
                _ => status(500, "InternalError", "unexpected request on a sandbox"),
            }
        }

        /// What a metadata-only list returns of an object: its metadata, no data.
        fn partial_of(object: &serde_json::Value) -> serde_json::Value {
            serde_json::json!({"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata",
                "metadata": object["metadata"]})
        }

        /// Apply a merge patch to a stored Secret and return it as it then is.
        fn patch_secret(
            held: &mut serde_json::Value,
            patch: &serde_json::Value,
        ) -> serde_json::Value {
            let mut secret = held.clone();
            merge(&mut secret, patch);
            if secret != *held {
                let current = secret["metadata"]["resourceVersion"]
                    .as_str()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                secret["metadata"]["resourceVersion"] = (current + 1).to_string().into();
                held.clone_from(&secret);
            }
            secret
        }

        fn answer_secret(
            st: &mut State,
            call: &Call<'_>,
            selector: &str,
            sent: serde_json::Value,
        ) -> (u16, serde_json::Value) {
            let (method, path) = (call.method, call.path);
            let rest = path.strip_prefix("/api/v1/namespaces/").unwrap_or("");
            let (ns, rest) = rest.split_once("/secrets").unwrap_or(("", ""));
            let name = rest.trim_start_matches('/');
            let at = |s: &serde_json::Value| {
                s["metadata"]["namespace"] == ns
                    && (name.is_empty() || s["metadata"]["name"] == name)
            };
            match (method, name.is_empty()) {
                // Create: the name from the body, one per name, resourceVersion 1.
                ("POST", true) => {
                    let mut secret = sent;
                    secret["apiVersion"] = "v1".into();
                    secret["kind"] = "Secret".into();
                    secret["metadata"]["namespace"] = ns.into();
                    let new_name = secret["metadata"]["name"].clone();
                    if st.secrets.iter().any(|s| {
                        s["metadata"]["namespace"] == ns && s["metadata"]["name"] == new_name
                    }) {
                        return conflict("already exists");
                    }
                    secret["metadata"]["resourceVersion"] = "1".into();
                    st.secrets.push(secret.clone());
                    (201, secret)
                }
                // Replace: compare-and-set on resourceVersion, then bump it.
                ("PUT", false) => {
                    let Some(i) = st.secrets.iter().position(at) else {
                        return not_found();
                    };
                    let current = st.secrets[i]["metadata"]["resourceVersion"].clone();
                    if sent["metadata"]["resourceVersion"] != current {
                        return conflict("the object has been modified");
                    }
                    let next: u64 = current.as_str().and_then(|v| v.parse().ok()).unwrap_or(0) + 1;
                    let mut secret = sent;
                    secret["apiVersion"] = "v1".into();
                    secret["kind"] = "Secret".into();
                    secret["metadata"]["namespace"] = ns.into();
                    secret["metadata"]["resourceVersion"] = next.to_string().into();
                    st.secrets[i] = secret.clone();
                    (200, secret)
                }
                // A merge patch; one that changes nothing leaves the resourceVersion alone.
                ("PATCH", false) => {
                    let Some(i) = st.secrets.iter().position(at) else {
                        return not_found();
                    };
                    (200, patch_secret(&mut st.secrets[i], &sent))
                }
                ("GET", true) => {
                    let found = st.secrets.iter().filter(|s| at(s) && matches(s, selector));
                    if call.partial {
                        let items: Vec<serde_json::Value> = found.map(partial_of).collect();
                        (
                            200,
                            serde_json::json!({"apiVersion": "meta.k8s.io/v1",
                                "kind": "PartialObjectMetadataList",
                                "metadata": {"resourceVersion": "1"}, "items": items}),
                        )
                    } else {
                        let items: Vec<&serde_json::Value> = found.collect();
                        (
                            200,
                            serde_json::json!({"apiVersion": "v1", "kind": "SecretList",
                                "metadata": {"resourceVersion": "1"}, "items": items}),
                        )
                    }
                }
                ("GET" | "DELETE", false) => {
                    let Some(i) = st.secrets.iter().position(at) else {
                        return not_found();
                    };
                    let found = if method == "DELETE" {
                        st.secrets.remove(i)
                    } else {
                        st.secrets[i].clone()
                    };
                    (200, found)
                }
                _ => status(500, "InternalError", "unexpected request on a Secret"),
            }
        }

        /// A session Secret in the home namespace, as the API server would hold it: the
        /// issuer's (`audience` `None`) or a delegation's, in the `state` its label says.
        pub fn session(
            sandbox: Uuid,
            audience: Option<&str>,
            state: &str,
            created_at: Timestamp,
            expires_at: Option<Timestamp>,
        ) -> serde_json::Value {
            let mut v = serde_json::to_value(session_secret(
                &SessionRecord {
                    sandbox_uid: sandbox,
                    subject: Subject {
                        issuer: "https://idp.example".into(),
                        id: "octocat".into(),
                        display: None,
                    },
                    issuer: String::new(),
                    refresh: Sealed {
                        key_id: "k1".into(),
                        nonce: vec![1],
                        ciphertext: vec![2],
                    },
                    created_at,
                    audience: audience.map(str::to_owned),
                    expires_at,
                },
                state,
            ))
            .unwrap();
            v["apiVersion"] = "v1".into();
            v["kind"] = "Secret".into();
            v["metadata"]["namespace"] = HOME.into();
            v["metadata"]["resourceVersion"] = "1".into();
            v
        }

        fn home_secret(sandbox: Uuid, audience: Option<&str>) -> serde_json::Value {
            session(sandbox, audience, "claimed", Timestamp::now(), None)
        }

        /// The UID of the one seeded sandbox.
        pub fn sandbox_uid(st: &State) -> Uuid {
            Uuid::parse_str(st.sandboxes[0]["metadata"]["uid"].as_str().unwrap()).unwrap()
        }

        /// How many requests listed sandboxes (a GET on the collection, in every namespace
        /// or in one).
        pub fn sandbox_lists(st: &State) -> usize {
            st.log
                .iter()
                .filter(|(m, p)| m == "GET" && p.ends_with("/agentsandboxes"))
                .count()
        }

        /// How many requests read one sandbox by name.
        pub fn sandbox_gets(st: &State) -> usize {
            st.log
                .iter()
                .filter(|(m, p)| {
                    m == "GET" && p.contains("/agentsandboxes/") && !p.ends_with("/status")
                })
                .count()
        }

        /// How many requests listed Secrets, in full or as metadata.
        pub fn secret_lists(st: &State) -> usize {
            st.log
                .iter()
                .filter(|(m, p)| m == "GET" && p.ends_with("/secrets"))
                .count()
        }

        /// How many requests read one Secret by name.
        pub fn secret_gets(st: &State) -> usize {
            st.log
                .iter()
                .filter(|(m, p)| m == "GET" && p.contains("/secrets/"))
                .count()
        }

        /// The paths that were patched, in order.
        pub fn patched(st: &State) -> Vec<&str> {
            st.log
                .iter()
                .filter(|(m, _)| m == "PATCH")
                .map(|(_, p)| p.as_str())
                .collect()
        }

        /// A sandbox in the tenant namespace with a record, its session Secret and one
        /// delegation Secret in the home namespace.
        pub fn seed(revoked: bool) -> (Arc<Mutex<State>>, Uuid) {
            let claim = Uuid::new_v4();
            let sandbox = Uuid::new_v4();
            let mut sb = serde_json::to_value(AgentSandbox::new(
                "sb-1",
                crate::sandbox::AgentSandboxSpec {
                    subject: crate::sandbox::SandboxSubject {
                        issuer: "https://idp.example".into(),
                        id: "octocat".into(),
                        display: None,
                    },
                    pool_ref: Some(banlieue_api::common::LocalObjectReference {
                        name: "pool-a".into(),
                    }),
                    pool_selector: None,
                    selection: None,
                    ttl_seconds: 600,
                    audiences: vec![],
                    workload: crate::sandbox::SandboxWorkload {
                        image: "registry.internal:5000/x:1".into(),
                        args: vec!["/bin/x".into()],
                        restart: None,
                        logs: false,
                    },
                    policy_ref: None,
                },
            ))
            .unwrap();
            sb["metadata"] = serde_json::json!({
                "name": "sb-1", "namespace": TENANT, "uid": sandbox.to_string(),
                "labels": { CLAIM_UID_LABEL: claim.to_string() },
                "finalizers": [FINALIZER],
            });
            let mut record = serde_json::json!({
                "claimUid": claim.to_string(),
                "createdAt": "2026-01-01T00:00:00Z",
                "refresh": true,
                "delegations": [{ "audience": "api.example" }],
            });
            if revoked {
                record["revokedAt"] = "2026-01-01T01:00:00Z".into();
            }
            sb["status"] = serde_json::json!({ "record": record });
            let st = State {
                sandboxes: vec![sb],
                secrets: vec![
                    home_secret(sandbox, None),
                    home_secret(sandbox, Some("api.example")),
                ],
                ..State::default()
            };
            (Arc::new(Mutex::new(st)), claim)
        }

        /// The names alone: a failure message never prints a Secret's data.
        pub fn secret_names(st: &State) -> Vec<&str> {
            st.secrets
                .iter()
                .filter_map(|s| s["metadata"]["name"].as_str())
                .collect()
        }

        pub fn assert_only_home_secrets(st: &State) {
            for (m, p) in &st.log {
                if p.contains("/secrets") {
                    assert!(
                        p.starts_with(&format!("/api/v1/namespaces/{HOME}/secrets")),
                        "{m} {p}: a Secret outside the broker's namespace"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn releasing_a_claim_in_a_tenant_namespace_deletes_its_session_and_delegation_secrets() {
        let (state, claim) = fake::seed(false);
        assert_eq!(state.lock().unwrap().secrets.len(), 2);
        let store = fake::store(&state);
        store.revoke_claim(claim, Timestamp::now()).await.unwrap();
        let st = state.lock().unwrap();
        assert!(st.secrets.is_empty(), "left: {:?}", fake::secret_names(&st));
        fake::assert_only_home_secrets(&st);
    }

    #[tokio::test]
    async fn the_sweep_removes_a_tenant_sandboxs_secrets_when_the_release_was_missed() {
        let (state, _claim) = fake::seed(true);
        let store = fake::store(&state);
        let swept = store.sweep(Timestamp::now()).await.unwrap();
        assert_eq!(swept, 1);
        let st = state.lock().unwrap();
        assert!(st.secrets.is_empty(), "left: {:?}", fake::secret_names(&st));
        fake::assert_only_home_secrets(&st);
    }

    #[tokio::test]
    async fn a_lookup_by_name_reads_only_its_namespace() {
        let (state, claim) = fake::seed(false);
        // The same name in another namespace, the record of another claim.
        let other = Uuid::new_v4();
        {
            let mut st = state.lock().unwrap();
            let mut twin = st.sandboxes[0].clone();
            twin["metadata"]["namespace"] = "team-c".into();
            twin["metadata"]["uid"] = Uuid::new_v4().to_string().into();
            twin["metadata"]["labels"][CLAIM_UID_LABEL] = other.to_string().into();
            twin["status"]["record"]["claimUid"] = other.to_string().into();
            twin["status"]["record"]["refresh"] = false.into();
            twin["status"]["record"]["delegations"] = serde_json::json!([]);
            st.sandboxes.push(twin);
        }
        let store = fake::store(&state);
        assert!(matches!(
            store.get_claim_by_name("team-b", "sb-1").await,
            Err(StoreError::NotFound(_))
        ));
        let rec = store.get_claim_by_name(fake::TENANT, "sb-1").await.unwrap();
        assert_eq!(rec.namespace, fake::TENANT);
        assert!(rec.uid == claim, "the tenant's record, not its namesake's");
        let rec = store.get_claim_by_name("team-c", "sb-1").await.unwrap();
        assert_eq!(rec.namespace, "team-c");
        assert!(
            rec.uid == other,
            "the namesake's record in its own namespace"
        );
        let st = state.lock().unwrap();
        assert_eq!(
            fake::sandbox_lists(&st),
            0,
            "a lookup by name lists nothing"
        );
        assert_eq!(fake::sandbox_gets(&st), 3, "one read by name per lookup");
    }

    #[tokio::test]
    async fn a_lookup_by_name_wants_the_claim_label_and_a_record() {
        // What the listing of recorded sandboxes required: no label, not found.
        let (state, _claim) = fake::seed(false);
        state.lock().unwrap().sandboxes[0]["metadata"]["labels"] = serde_json::json!({});
        let store = fake::store(&state);
        assert!(matches!(
            store.get_claim_by_name(fake::TENANT, "sb-1").await,
            Err(StoreError::NotFound(_))
        ));
        // The label without a record: not found either.
        let (state, _claim) = fake::seed(false);
        state.lock().unwrap().sandboxes[0]["status"] = serde_json::json!({});
        let store = fake::store(&state);
        assert!(matches!(
            store.get_claim_by_name(fake::TENANT, "sb-1").await,
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.get_claim_by_name(fake::TENANT, "").await,
            Err(StoreError::NotFound(_))
        ));
    }

    /// The seeded sandbox before any record: no label, no status, no Secret.
    fn unrecorded(state: &std::sync::Mutex<fake::State>) {
        let mut st = state.lock().unwrap();
        st.sandboxes[0]["metadata"]["labels"] = serde_json::json!({});
        st.sandboxes[0]["status"] = serde_json::json!({});
        st.secrets.clear();
    }

    #[tokio::test]
    async fn a_new_record_finds_its_sandbox_by_name_and_checks_the_uid() {
        let (state, _seeded) = fake::seed(false);
        unrecorded(&state);
        let sandbox = fake::sandbox_uid(&state.lock().unwrap());
        let store = fake::store(&state);
        let claim = Uuid::new_v4();
        let mut rec = test_record(claim);
        rec.name = "sb-1".into();
        rec.namespace = fake::TENANT.into();
        rec.sandbox_uid = Some(sandbox);
        store.put_claim(rec.clone()).await.unwrap();
        {
            let st = state.lock().unwrap();
            assert_eq!(fake::sandbox_gets(&st), 1, "the sandbox, by name");
            assert_eq!(
                fake::sandbox_lists(&st),
                1,
                "only the check that no sandbox carries the claim yet"
            );
            assert_eq!(fake::patched(&st).len(), 2, "the labels and the status");
        }
        let back = store.get_claim(claim).await.unwrap();
        assert_eq!(back.name, "sb-1");
        assert!(back.sandbox_uid == Some(sandbox), "the record's sandbox");
        assert!(matches!(
            store.put_claim(rec).await,
            Err(StoreError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn a_new_record_under_another_name_is_still_found_by_uid_and_a_wrong_uid_never_is() {
        let (state, _seeded) = fake::seed(false);
        unrecorded(&state);
        let sandbox = fake::sandbox_uid(&state.lock().unwrap());
        let store = fake::store(&state);
        // The name is taken by a sandbox of another UID: not that one.
        let mut stranger = test_record(Uuid::new_v4());
        stranger.name = "sb-1".into();
        stranger.namespace = fake::TENANT.into();
        stranger.sandbox_uid = Some(Uuid::new_v4());
        assert!(matches!(
            store.put_claim(stranger).await,
            Err(StoreError::NotFound(_))
        ));
        assert!(
            state.lock().unwrap().sandboxes[0]["status"]["record"].is_null(),
            "nothing was written to the sandbox of that name"
        );
        // The record names its sandbox wrongly: the list over every namespace finds the UID.
        let claim = Uuid::new_v4();
        let mut rec = test_record(claim);
        rec.name = "renamed".into();
        rec.namespace = "elsewhere".into();
        rec.sandbox_uid = Some(sandbox);
        store.put_claim(rec).await.unwrap();
        assert_eq!(store.get_claim(claim).await.unwrap().name, "sb-1");
    }

    #[tokio::test]
    async fn a_second_read_of_a_claim_reads_its_sandbox_by_name_and_lists_nothing() {
        let (state, claim) = fake::seed(false);
        let store = fake::store(&state);
        let first = store.get_claim(claim).await.unwrap();
        {
            let st = state.lock().unwrap();
            assert_eq!(fake::sandbox_lists(&st), 1, "found by its label once");
            assert_eq!(fake::sandbox_gets(&st), 0);
        }
        let second = store.get_claim(claim).await.unwrap();
        assert!(first.uid == second.uid && first.name == second.name);
        assert!(first.refresh == second.refresh, "the same envelope");
        let st = state.lock().unwrap();
        assert_eq!(fake::sandbox_lists(&st), 1, "no second list");
        assert_eq!(fake::sandbox_gets(&st), 1, "one read by name");
    }

    #[tokio::test]
    async fn a_hint_whose_sandbox_is_gone_or_relabelled_falls_back_to_the_list() {
        // Deleted: the list says not found.
        let (state, claim) = fake::seed(false);
        let store = fake::store(&state);
        store.get_claim(claim).await.unwrap();
        state.lock().unwrap().sandboxes.clear();
        assert!(matches!(
            store.get_claim(claim).await,
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(fake::sandbox_lists(&state.lock().unwrap()), 2);

        // The label removed: not found, as the selector would have it.
        let (state, claim) = fake::seed(false);
        let store = fake::store(&state);
        store.get_claim(claim).await.unwrap();
        state.lock().unwrap().sandboxes[0]["metadata"]["labels"] = serde_json::json!({});
        assert!(matches!(
            store.get_claim(claim).await,
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(fake::sandbox_lists(&state.lock().unwrap()), 2);

        // The name now another claim's sandbox, the claim on a sandbox elsewhere: the list
        // returns that one.
        let (state, claim) = fake::seed(false);
        let store = fake::store(&state);
        store.get_claim(claim).await.unwrap();
        {
            let mut st = state.lock().unwrap();
            let mut moved = st.sandboxes[0].clone();
            moved["metadata"]["name"] = "sb-2".into();
            moved["metadata"]["namespace"] = "team-c".into();
            let other = Uuid::new_v4().to_string();
            st.sandboxes[0]["metadata"]["labels"][CLAIM_UID_LABEL] = other.clone().into();
            st.sandboxes[0]["status"]["record"]["claimUid"] = other.into();
            st.sandboxes.push(moved);
        }
        let rec = store.get_claim(claim).await.unwrap();
        assert_eq!(rec.name, "sb-2");
        assert_eq!(rec.namespace, "team-c");
        assert_eq!(fake::sandbox_lists(&state.lock().unwrap()), 2);
        // And the new place is the hint from here on.
        store.get_claim(claim).await.unwrap();
        assert_eq!(fake::sandbox_lists(&state.lock().unwrap()), 2);
    }

    #[tokio::test]
    async fn an_update_that_changes_nothing_patches_nothing() {
        let (state, claim) = fake::seed(false);
        let store = fake::store(&state);
        let rec = store.get_claim(claim).await.unwrap();
        assert!(rec.refresh.is_some() && rec.delegations.len() == 1);
        store.update_claim(rec).await.unwrap();
        let st = state.lock().unwrap();
        assert_eq!(
            fake::patched(&st).len(),
            0,
            "neither the labels, the status nor a Secret"
        );
        assert_eq!(st.secrets.len(), 2);
    }

    #[tokio::test]
    async fn an_update_with_a_new_envelope_patches_the_session_secret_alone() {
        let (state, claim) = fake::seed(false);
        let sandbox = fake::sandbox_uid(&state.lock().unwrap());
        let store = fake::store(&state);
        let mut rec = store.get_claim(claim).await.unwrap();
        let rotated = Sealed {
            key_id: "k1".into(),
            nonce: vec![3],
            ciphertext: vec![4],
        };
        rec.refresh = Some(rotated.clone());
        store.update_claim(rec).await.unwrap();
        {
            let st = state.lock().unwrap();
            let patched = fake::patched(&st);
            assert_eq!(patched.len(), 1, "one patch");
            assert!(
                patched[0].ends_with(&format!("/secrets/{}", session_name(sandbox))),
                "the issuer's session Secret"
            );
        }
        let back = store.get_claim(claim).await.unwrap();
        assert!(back.refresh == Some(rotated), "the new envelope is stored");
        assert_eq!(back.delegations.len(), 1, "the delegation is untouched");
    }

    #[tokio::test]
    async fn an_update_that_changes_the_record_patches_the_status_and_a_new_node_the_labels() {
        let (state, claim) = fake::seed(false);
        let store = fake::store(&state);
        let mut rec = store.get_claim(claim).await.unwrap();
        rec.entry_id = Some("entry-1".into());
        store.update_claim(rec.clone()).await.unwrap();
        {
            let st = state.lock().unwrap();
            let patched = fake::patched(&st);
            assert_eq!(patched.len(), 1);
            assert!(patched[0].ends_with("/agentsandboxes/sb-1/status"));
        }
        let node = "spiffe://sandbox.test/spire/agent/tpm/aaaa";
        rec.node_id = Some(node.into());
        store.update_claim(rec).await.unwrap();
        let st = state.lock().unwrap();
        let patched = fake::patched(&st);
        assert_eq!(patched.len(), 3, "the labels, then the status");
        assert!(patched[1].ends_with("/agentsandboxes/sb-1"));
        assert_eq!(
            st.sandboxes[0]["metadata"]["labels"][NODE_LABEL],
            node_label(node)
        );
        assert_eq!(st.sandboxes[0]["status"]["record"]["entryId"], "entry-1");
        assert_eq!(st.sandboxes[0]["status"]["record"]["nodeId"], node);
    }

    #[tokio::test]
    async fn the_sweeps_read_no_envelope_and_the_log_sweep_lists_metadata_only() {
        let (state, claim) = fake::seed(true);
        let store = fake::store(&state);
        let rec = store.get_claim(claim).await.unwrap();
        let limits = LogLimits {
            max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
        };
        store
            .append_logs(&rec, &log_batch(1, 1, "ended"), &limits)
            .await
            .unwrap();
        {
            let mut st = state.lock().unwrap();
            st.log.clear();
            st.metadata_lists.clear();
        }
        // The revoked record ended in 2026: nothing before the dawn of time, all of it now.
        assert_eq!(store.sweep_logs(Timestamp::MIN).await.unwrap(), 0);
        {
            let st = state.lock().unwrap();
            assert_eq!(fake::secret_gets(&st), 0, "no Secret is read by name");
            assert_eq!(st.metadata_lists.len(), 1, "the segments, as metadata only");
            assert_eq!(fake::secret_lists(&st), 1, "and nothing else is listed");
        }
        assert_eq!(store.sweep_logs(Timestamp::now()).await.unwrap(), 1);
        assert_eq!(fake::secret_gets(&state.lock().unwrap()), 0);
        // The audit sweep: the same record, its Secrets deleted by label, none read.
        assert_eq!(store.sweep(Timestamp::now()).await.unwrap(), 1);
        let st = state.lock().unwrap();
        assert_eq!(fake::secret_gets(&st), 0, "no envelope is read to sweep");
        assert!(st.secrets.is_empty(), "its Secrets are deleted");
        assert!(st.sandboxes.is_empty(), "deleted, its finalizer released");
    }

    #[tokio::test]
    async fn a_swept_claim_is_not_found_again() {
        let (state, claim) = fake::seed(true);
        let store = fake::store(&state);
        store.get_claim(claim).await.unwrap();
        assert_eq!(store.sweep(Timestamp::now()).await.unwrap(), 1);
        let before = fake::sandbox_gets(&state.lock().unwrap());
        assert!(matches!(
            store.get_claim(claim).await,
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(
            fake::sandbox_gets(&state.lock().unwrap()),
            before,
            "the hint went with the sandbox: the list answers"
        );
    }

    #[tokio::test]
    async fn the_session_sweep_lists_once_and_keeps_each_states_rule() {
        let (state, _claim) = fake::seed(false);
        let now = Timestamp::now();
        let ago = |seconds: i64| Timestamp::from_second(now.as_second() - seconds).unwrap();
        let later = Timestamp::from_second(now.as_second() + 3600).unwrap();
        let (old_parked, fresh_parked, expired_parked) =
            (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let (expired_claimed, live_claimed, odd) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        {
            let mut st = state.lock().unwrap();
            st.secrets
                .push(fake::session(old_parked, None, "parked", ago(7200), None));
            st.secrets
                .push(fake::session(fresh_parked, None, "parked", ago(60), None));
            st.secrets.push(fake::session(
                expired_parked,
                Some("api.example"),
                "parked",
                ago(60),
                Some(ago(1)),
            ));
            st.secrets.push(fake::session(
                expired_claimed,
                Some("api.example"),
                "claimed",
                ago(7200),
                Some(ago(1)),
            ));
            st.secrets.push(fake::session(
                live_claimed,
                Some("api.example"),
                "claimed",
                ago(7200),
                Some(later),
            ));
            // Neither parked nor claimed: left alone, whatever its age and expiry.
            st.secrets.push(fake::session(
                odd,
                Some("api.example"),
                "other",
                ago(7200),
                Some(ago(1)),
            ));
        }
        let store = fake::store(&state);
        assert_eq!(store.sweep_sessions(ago(3600)).await.unwrap(), 3);
        let st = state.lock().unwrap();
        assert_eq!(fake::secret_lists(&st), 1, "one list for both states");
        let names = fake::secret_names(&st);
        let gone = [
            session_name(old_parked),
            delegation_name(expired_parked, "api.example"),
            delegation_name(expired_claimed, "api.example"),
        ];
        let kept = [
            session_name(fresh_parked),
            delegation_name(live_claimed, "api.example"),
            delegation_name(odd, "api.example"),
        ];
        assert!(gone.iter().all(|n| !names.contains(&n.as_str())));
        assert!(kept.iter().all(|n| names.contains(&n.as_str())));
        assert_eq!(
            st.secrets.len(),
            5,
            "the seeded claim's two old envelopes without an expiry stay too"
        );
    }

    #[test]
    fn the_node_label_fits_a_label_value_and_differs_per_node() {
        let a = node_label("spiffe://sandbox.test/spire/agent/tpm/aaaa");
        let b = node_label("spiffe://sandbox.test/spire/agent/tpm/bbbb");
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one record literal with every field, kept whole"
    )]
    fn a_record_round_trips_through_the_status_and_the_secret_shapes() {
        let uid = Uuid::new_v4();
        let sandbox_uid = Uuid::new_v4();
        let mut sb = AgentSandbox::new(
            "sandbox-abc",
            crate::sandbox::AgentSandboxSpec {
                subject: crate::sandbox::SandboxSubject {
                    issuer: "https://idp.example".into(),
                    id: "octocat".into(),
                    display: None,
                },
                pool_ref: Some(banlieue_api::common::LocalObjectReference {
                    name: "pool-a".into(),
                }),
                pool_selector: None,
                selection: None,
                ttl_seconds: 600,
                audiences: vec!["a".into()],
                workload: crate::sandbox::SandboxWorkload {
                    image: "registry.internal:5000/x:1".into(),
                    args: vec!["/bin/x".into()],
                    restart: Some(crate::sandbox::SandboxRestart::Never),
                    logs: false,
                },
                policy_ref: None,
            },
        );
        sb.metadata.uid = Some(sandbox_uid.to_string());
        let sealed = Sealed {
            key_id: "k1".into(),
            nonce: vec![1, 2, 3],
            ciphertext: vec![9, 9, 9, 9],
        };
        let rec = ClaimRecord {
            uid,
            name: "sandbox-abc".into(),
            namespace: "sandboxes".into(),
            subject: Subject::from(&sb.spec.subject),
            entry_id: Some("entry-1".into()),
            node_id: Some("spiffe://sandbox.test/spire/agent/tpm/aaaa".into()),
            audiences: vec!["a".into()],
            workload: Workload::from(&sb.spec.workload),
            ttl_seconds: 600,
            refresh: Some(sealed.clone()),
            created_at: Timestamp::from_second(1_700_000_000).unwrap(),
            expires_at: Some(Timestamp::from_second(1_700_000_600).unwrap()),
            revoked_at: None,
            sandbox_uid: Some(sandbox_uid),
            policy_uid: Some("p-uid".into()),
            bundle_version: Some(4),
            report: None,
            exit: Some(WorkloadExit {
                exited_at: Timestamp::from_second(1_700_000_100).unwrap(),
                exit: mediatore_proto::GuestExit {
                    code: Some(0),
                    signal: None,
                    restarts: 1,
                },
            }),
            delegations: BTreeMap::new(),
        };
        let status = record_status_from(&rec);
        assert_eq!(status.claim_uid, uid.to_string());
        assert!(status.refresh);
        let back = record_from(&sb, &status).unwrap();
        assert_eq!(back.uid, uid);
        assert_eq!(back.entry_id, rec.entry_id);
        assert_eq!(back.node_id, rec.node_id);
        assert_eq!(back.expires_at, rec.expires_at);
        assert_eq!(back.sandbox_uid, Some(sandbox_uid));
        assert_eq!(back.workload.restart, mediatore_proto::RestartPolicy::Never);
        assert_eq!(back.exit, rec.exit);
        assert_eq!(back.policy_uid.as_deref(), Some("p-uid"));
        assert!(
            back.refresh.is_none(),
            "the envelope is the Secret's, not the status's"
        );

        let secret = session_secret(
            &SessionRecord {
                sandbox_uid,
                subject: rec.subject.clone(),
                issuer: "https://idp.example".into(),
                refresh: sealed.clone(),
                created_at: rec.created_at,
                audience: None,
                expires_at: None,
            },
            "parked",
        );
        assert_eq!(
            secret.metadata.name.as_deref(),
            Some(session_name(sandbox_uid).as_str())
        );
        assert_eq!(envelope_of(&secret), Some(sealed));
        let session = session_of(&secret).unwrap();
        assert_eq!(session.sandbox_uid, sandbox_uid);
        assert_eq!(session.issuer, "https://idp.example");
        assert_eq!(session.created_at, rec.created_at);
        assert!(
            !serde_json::to_string(&status)
                .unwrap()
                .contains("ciphertext"),
            "nothing of the envelope on the status"
        );
    }

    #[test]
    fn nodes_and_floors_round_trip_through_their_resources() {
        let node = NodeRecord {
            ek_hash: "ab".repeat(32),
            node_id: "spiffe://sandbox.test/spire/agent/tpm/abab".into(),
            dmi_uuid: Uuid::new_v4(),
            hostname: "member-01".into(),
            provider: Some(Provider::Libvirt),
            banned: false,
            registered_at: Timestamp::from_second(1_700_000_000).unwrap(),
        };
        let res = sandbox_node_of(&node);
        assert_eq!(res.metadata.name.as_deref(), Some(node.ek_hash.as_str()));
        assert_eq!(res.spec.provider.as_deref(), Some("libvirt"));
        assert_eq!(
            res.metadata.labels.as_ref().unwrap()[DMI_LABEL],
            node.dmi_uuid.to_string()
        );
        let back = node_record_of(&res).unwrap();
        assert_eq!(back.ek_hash, node.ek_hash);
        assert_eq!(back.dmi_uuid, node.dmi_uuid);
        assert_eq!(back.provider, Some(Provider::Libvirt));
        assert_eq!(back.registered_at, node.registered_at);

        let floor = mediatore_store::PolicyFloor {
            namespace: "sandboxes".into(),
            name: "agents".into(),
            uid: "u-1".into(),
            version: 7,
            issued_at: Timestamp::new(1_700_000_000, 123_456_789).unwrap(),
        };
        let spec = floor_spec_of(&floor);
        assert!(
            spec.issued_at.ends_with(".123456789Z"),
            "{}",
            spec.issued_at
        );
        let res = PolicyFloor::new(&floor_name("sandboxes", "agents"), spec);
        assert_eq!(res.metadata.name.as_deref(), Some("sandboxes.agents"));
        assert_eq!(floor_of(&res).unwrap(), floor);
    }

    #[test]
    fn a_floor_written_by_an_earlier_broker_still_reads() {
        // Every broker so far wrote `issuedAt` as RFC 3339 with nine fraction digits and a `Z`;
        // a resource left by one of them reads back to the same instant.
        let res = PolicyFloor::new(
            &floor_name("sandboxes", "agents"),
            PolicyFloorSpec {
                policy_namespace: "sandboxes".into(),
                policy_name: "agents".into(),
                uid: "u-1".into(),
                version: 7,
                issued_at: "2026-11-15T16:46:49.123456789Z".into(),
            },
        );
        assert_eq!(
            floor_of(&res).unwrap().issued_at,
            Timestamp::new(1_794_761_209, 123_456_789).unwrap()
        );
        let res = PolicyFloor::new(
            &floor_name("sandboxes", "agents"),
            PolicyFloorSpec {
                policy_namespace: "sandboxes".into(),
                policy_name: "agents".into(),
                uid: "u-1".into(),
                version: 7,
                issued_at: "not a time".into(),
            },
        );
        assert!(floor_of(&res).is_err());
    }

    #[test]
    fn a_session_written_by_an_earlier_broker_still_reads() {
        // Earlier brokers wrote `created_at` and `expires_at` as RFC 3339 with a `+00:00` offset
        // and the fraction as it came; a Secret left by one of them reads back to the same
        // instants.
        let sandbox_uid = Uuid::new_v4();
        let mut secret = session_secret(
            &SessionRecord {
                sandbox_uid,
                subject: Subject {
                    issuer: "https://idp.example".into(),
                    id: "octocat".into(),
                    display: None,
                },
                issuer: "https://idp.example".into(),
                refresh: Sealed {
                    key_id: "k1".into(),
                    nonce: vec![1, 2, 3],
                    ciphertext: vec![9, 9, 9, 9],
                },
                created_at: Timestamp::from_second(1_700_000_000).unwrap(),
                audience: Some("anthropic".into()),
                expires_at: None,
            },
            "parked",
        );
        let data = secret.data.as_mut().unwrap();
        data.insert(
            "created_at".into(),
            ByteString(b"2026-11-15T16:46:49.123456789+00:00".to_vec()),
        );
        data.insert(
            "expires_at".into(),
            ByteString(b"2026-11-15T17:46:49+00:00".to_vec()),
        );
        let back = session_of(&secret).unwrap();
        assert_eq!(back.sandbox_uid, sandbox_uid);
        assert_eq!(back.audience.as_deref(), Some("anthropic"));
        assert_eq!(
            back.created_at,
            Timestamp::new(1_794_761_209, 123_456_789).unwrap()
        );
        assert_eq!(
            back.expires_at,
            Some(Timestamp::from_second(1_794_764_809).unwrap())
        );
        secret
            .data
            .as_mut()
            .unwrap()
            .insert("created_at".into(), ByteString(b"yesterday".to_vec()));
        assert!(
            session_of(&secret).is_none(),
            "an unreadable instant is refused"
        );
    }

    // ---------- the output ring (ADR-0045 decision 6) ----------

    fn log_record(seq: u64, text: &str) -> mediatore_proto::LogRecord {
        mediatore_proto::LogRecord {
            seq,
            stream: mediatore_proto::LogStream::Stdout,
            ts: Timestamp::from_second(1_700_000_000 + i64::try_from(seq).unwrap()).unwrap(),
            text: text.into(),
        }
    }

    fn log_batch(from: u64, to: u64, text: &str) -> LogBatch {
        LogBatch {
            records: (from..=to).map(|seq| log_record(seq, text)).collect(),
            ..LogBatch::default()
        }
    }

    fn seqs(entries: &[LogEntry]) -> Vec<u64> {
        entries.iter().filter_map(LogEntry::seq).collect()
    }

    /// A record with the fields the ring reads: its UID, no sandbox yet.
    fn test_record(uid: Uuid) -> ClaimRecord {
        ClaimRecord {
            uid,
            name: "sandbox-abc".into(),
            namespace: "sandboxes".into(),
            subject: Subject {
                issuer: "https://idp.example".into(),
                id: "octocat".into(),
                display: None,
            },
            entry_id: None,
            node_id: None,
            audiences: vec![],
            workload: Workload {
                image: "registry.internal:5000/x:1".into(),
                args: vec![],
                restart: mediatore_proto::RestartPolicy::Never,
                logs: true,
            },
            ttl_seconds: 600,
            refresh: None,
            created_at: Timestamp::from_second(1_700_000_000).unwrap(),
            expires_at: None,
            revoked_at: None,
            sandbox_uid: None,
            policy_uid: None,
            bundle_version: None,
            report: None,
            exit: None,
            delegations: BTreeMap::new(),
        }
    }

    fn segment_with(number: u32, records: &[(u64, usize)]) -> LogSegment {
        let mut seg = LogSegment::empty(number, 0);
        for (seq, len) in records {
            seg.push(LogEntry::Record(log_record(*seq, &"x".repeat(*len))));
        }
        seg
    }

    #[test]
    fn a_segments_name_carries_the_claim_and_a_zero_padded_number() {
        let uid = Uuid::parse_str("7f9c24e8-3b12-4c3d-9e2a-1a2b3c4d5e6f").unwrap();
        assert_eq!(
            logs_segment_name(uid, 7),
            "mediatore-logs-7f9c24e8-3b12-4c3d-9e2a-1a2b3c4d5e6f-000007"
        );
        assert!(
            logs_segment_name(uid, 7) < logs_segment_name(uid, 10),
            "names sort as numbers"
        );
        assert!(
            logs_segment_name(uid, 0).len() <= 63,
            "a Secret name within a DNS label"
        );
    }

    #[test]
    fn a_segment_round_trips_through_its_secret_with_the_labels_the_sweep_finds_it_by() {
        let uid = Uuid::new_v4();
        let sandbox_uid = Uuid::new_v4();
        let mut rec = test_record(uid);
        rec.sandbox_uid = Some(sandbox_uid);
        let mut seg = LogSegment::empty(3, 4096);
        seg.push(LogEntry::Gap(LogGap {
            lost_stdout: 10,
            lost_stderr: 0,
        }));
        seg.push(LogEntry::Record(log_record(41, "first")));
        seg.push(LogEntry::Record(log_record(42, "second")));
        seg.resource_version = Some("12".into());
        let owner = OwnerReference {
            api_version: "mediatore.io/v1beta1".into(),
            kind: "AgentSandbox".into(),
            name: "sb".into(),
            uid: sandbox_uid.to_string(),
            controller: Some(true),
            block_owner_deletion: Some(false),
        };
        let secret = segment_secret(&rec, &seg, Some(vec![owner.clone()]));
        assert_eq!(secret.name_any(), logs_segment_name(uid, 3));
        let labels = secret.labels();
        assert_eq!(
            labels.get(LOGS_LABEL).map(String::as_str),
            Some(LOGS_SEGMENT)
        );
        assert_eq!(labels.get(CLAIM_UID_LABEL), Some(&uid.to_string()));
        assert_eq!(
            labels.get(SANDBOX_UID_LABEL),
            Some(&sandbox_uid.to_string())
        );
        let ann = secret.annotations();
        assert_eq!(ann.get(SEGMENT_ANNOTATION).map(String::as_str), Some("3"));
        assert_eq!(
            ann.get(FIRST_SEQ_ANNOTATION).map(String::as_str),
            Some("41")
        );
        assert_eq!(ann.get(LAST_SEQ_ANNOTATION).map(String::as_str), Some("42"));
        assert_eq!(ann.get(BYTES_ANNOTATION).map(String::as_str), Some("11"));
        assert_eq!(
            ann.get(TRUNCATED_ANNOTATION).map(String::as_str),
            Some("4096")
        );
        assert_eq!(secret.metadata.owner_references, Some(vec![owner]));
        assert_eq!(secret.type_.as_deref(), Some("Opaque"));
        let text = String::from_utf8(secret.data.as_ref().unwrap()[ENTRIES_KEY].0.clone()).unwrap();
        assert_eq!(text.lines().count(), 3, "one entry per line: {text}");
        assert!(!text.contains('\u{2014}'));
        assert_eq!(segment_of(&secret), Some(seg));
        // A record without a sandbox UID labels no sandbox and owns nothing.
        rec.sandbox_uid = None;
        let secret = segment_secret(&rec, &LogSegment::empty(0, 0), None);
        assert!(!secret.labels().contains_key(SANDBOX_UID_LABEL));
        assert_eq!(secret.annotations().get(FIRST_SEQ_ANNOTATION), None);
        assert_eq!(segment_of(&secret).map(|s| s.bytes), Some(0));
        // Not a segment: a session Secret.
        assert_eq!(segment_of(&Secret::default()), None);
    }

    #[test]
    fn packing_fills_the_open_segment_then_rolls_to_new_ones_numbered_on() {
        let kib = 1024;
        let open = segment_with(4, &[(1, 60 * kib)]);
        let older = segment_with(3, &[(0, LOG_SEGMENT_BYTES)]);
        let entries: Vec<LogEntry> = (2..=6)
            .map(|seq| LogEntry::Record(log_record(seq, &"y".repeat(30 * kib))))
            .collect();
        let changed = pack(&[older, open], entries);
        let numbers: Vec<u32> = changed.iter().map(|s| s.number).collect();
        assert_eq!(numbers, vec![4, 5, 6, 7], "the open one and three new");
        assert_eq!(
            seqs(&changed[0].entries),
            vec![1],
            "60 KiB + 30 KiB is over a segment"
        );
        assert_eq!(seqs(&changed[1].entries), vec![2, 3]);
        assert_eq!(seqs(&changed[2].entries), vec![4, 5]);
        assert_eq!(seqs(&changed[3].entries), vec![6]);
        for s in &changed {
            assert!(
                s.bytes <= LOG_SEGMENT_BYTES,
                "segment {} holds {}",
                s.number,
                s.bytes
            );
        }
        // An empty ring starts at 0; a gap weighs nothing and never rolls a segment.
        let changed = pack(
            &[],
            vec![
                LogEntry::Gap(LogGap::default()),
                LogEntry::Record(log_record(1, "a")),
            ],
        );
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].number, 0);
        assert_eq!(changed[0].entries.len(), 2);
        // A record larger than what is left opens a new segment, never splits.
        let open = segment_with(0, &[(1, LOG_SEGMENT_BYTES - 1)]);
        let changed = pack(&[open], vec![LogEntry::Record(log_record(2, "ab"))]);
        assert_eq!(changed.len(), 2);
        assert_eq!(seqs(&changed[1].entries), vec![2]);
        // The newest segment's count is what every written one carries.
        let mut open = segment_with(2, &[(1, 10)]);
        open.truncated_before = 999;
        let changed = pack(
            &[segment_with(1, &[(0, 10)]), open],
            vec![LogEntry::Record(log_record(2, "z"))],
        );
        assert!(changed.iter().all(|s| s.truncated_before == 999));
    }

    #[test]
    fn the_ring_trims_whole_segments_from_the_front_and_never_the_newest() {
        let segments = vec![
            segment_with(0, &[(1, 100)]),
            segment_with(1, &[(2, 200)]),
            segment_with(2, &[(3, 300)]),
        ];
        assert_eq!(trim(&segments, 600), (vec![], 0), "within the cap: nothing");
        assert_eq!(trim(&segments, 599), (vec![0], 100));
        assert_eq!(trim(&segments, 499), (vec![0, 1], 300));
        assert_eq!(
            trim(&segments, 10),
            (vec![0, 1], 300),
            "the newest stays whatever the cap"
        );
        assert_eq!(trim(&segments[2..], 10), (vec![], 0));
        assert_eq!(trim(&[], 10), (vec![], 0));
    }

    #[test]
    fn the_cursor_rule_matches_the_memory_rings() {
        let gap = LogEntry::Gap(LogGap {
            lost_stdout: 1,
            lost_stderr: 0,
        });
        let entries = vec![
            LogEntry::Record(log_record(1, "a")),
            gap.clone(),
            LogEntry::Record(log_record(2, "b")),
            LogEntry::Record(log_record(3, "c")),
        ];
        assert_eq!(after_cursor(entries.clone(), None), entries);
        assert_eq!(
            after_cursor(entries.clone(), Some(1)),
            entries[1..].to_vec()
        );
        assert_eq!(
            after_cursor(entries.clone(), Some(2)),
            entries[3..].to_vec()
        );
        assert_eq!(after_cursor(entries.clone(), Some(3)), vec![]);
        assert_eq!(
            after_cursor(vec![gap], Some(0)),
            vec![],
            "a gap with nothing after it is not sent"
        );
    }

    #[tokio::test]
    async fn output_appended_through_the_api_server_reads_back_and_a_replay_is_ignored() {
        let (state, claim) = fake::seed(false);
        let store = fake::store(&state);
        let rec = store.get_claim(claim).await.unwrap();
        let limits = LogLimits {
            max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
        };
        let done = store
            .append_logs(&rec, &log_batch(1, 2, "hello"), &limits)
            .await
            .unwrap();
        assert_eq!(
            done,
            LogAppend {
                stored: 2,
                ignored: 0
            }
        );
        let mut lossy = log_batch(2, 4, "world");
        lossy.dropped_stdout = 64;
        let done = store.append_logs(&rec, &lossy, &limits).await.unwrap();
        assert_eq!(
            done,
            LogAppend {
                stored: 2,
                ignored: 1
            }
        );
        let chunk = store.read_logs(claim, None).await.unwrap();
        assert_eq!(seqs(&chunk.entries), vec![1, 2, 3, 4]);
        assert!(matches!(
            chunk.entries[2],
            LogEntry::Gap(LogGap {
                lost_stdout: 64,
                ..
            })
        ));
        assert_eq!(chunk.last_seq, Some(4));
        assert_eq!(chunk.truncated_before, 0);
        let chunk = store.read_logs(claim, Some(2)).await.unwrap();
        assert_eq!(seqs(&chunk.entries), vec![3, 4]);
        assert!(matches!(chunk.entries[0], LogEntry::Gap(_)));
        {
            let st = state.lock().unwrap();
            let segments: Vec<&serde_json::Value> = st
                .secrets
                .iter()
                .filter(|s| s["metadata"]["labels"][LOGS_LABEL] == LOGS_SEGMENT)
                .collect();
            assert_eq!(segments.len(), 1, "a few lines fit one segment");
            assert_eq!(
                segments[0]["metadata"]["resourceVersion"], "2",
                "created once, replaced once, by resourceVersion"
            );
            assert_eq!(
                segments[0]["metadata"]["labels"][CLAIM_UID_LABEL],
                claim.to_string()
            );
            assert_eq!(
                segments[0]["metadata"]["ownerReferences"],
                serde_json::Value::Null,
                "the sandbox lives in the tenant namespace: nothing across namespaces owns the segment"
            );
            fake::assert_only_home_secrets(&st);
        }
        store.delete_logs(claim).await.unwrap();
        assert_eq!(
            store.read_logs(claim, None).await.unwrap().entries,
            Vec::new()
        );
        store.delete_logs(claim).await.unwrap();
    }

    #[tokio::test]
    async fn the_secret_ring_rolls_segments_and_drops_the_oldest_beyond_the_cap() {
        let (state, claim) = fake::seed(false);
        let store = fake::store(&state);
        let rec = store.get_claim(claim).await.unwrap();
        let limits = LogLimits {
            max_bytes: 2 * LOG_SEGMENT_BYTES,
        };
        let kib = "k".repeat(1024);
        let per = u64::try_from(LOG_SEGMENT_BYTES / 1024).unwrap();
        for i in 0..3u64 {
            let from = i * per + 1;
            store
                .append_logs(&rec, &log_batch(from, from + per - 1, &kib), &limits)
                .await
                .unwrap();
        }
        let chunk = store.read_logs(claim, None).await.unwrap();
        assert_eq!(
            chunk.truncated_before,
            u64::try_from(LOG_SEGMENT_BYTES).unwrap()
        );
        assert_eq!(seqs(&chunk.entries).first().copied(), Some(per + 1));
        assert_eq!(chunk.last_seq, Some(3 * per));
        let st = state.lock().unwrap();
        let names: Vec<String> = st
            .secrets
            .iter()
            .filter(|s| s["metadata"]["labels"][LOGS_LABEL] == LOGS_SEGMENT)
            .map(|s| s["metadata"]["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            names,
            vec![logs_segment_name(claim, 1), logs_segment_name(claim, 2)],
            "segment 0 went"
        );
        assert!(
            st.log
                .iter()
                .any(|(m, p)| m == "DELETE" && p.ends_with(&logs_segment_name(claim, 0))),
            "deleted through the API: {:?}",
            st.log
        );
    }

    #[tokio::test]
    async fn output_of_a_sandbox_beside_the_broker_is_owned_by_it_after_one_read_by_name() {
        let (state, claim) = fake::seed(false);
        state.lock().unwrap().sandboxes[0]["metadata"]["namespace"] = fake::HOME.into();
        let sandbox = fake::sandbox_uid(&state.lock().unwrap());
        let store = fake::store(&state);
        let rec = store.get_claim(claim).await.unwrap();
        assert_eq!(rec.namespace, fake::HOME);
        let limits = LogLimits {
            max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
        };
        store
            .append_logs(&rec, &log_batch(1, 2, "hello"), &limits)
            .await
            .unwrap();
        let st = state.lock().unwrap();
        assert_eq!(
            fake::sandbox_lists(&st),
            1,
            "the claim's lookup; the append lists no sandbox"
        );
        assert_eq!(fake::sandbox_gets(&st), 1, "the owner, by name");
        let segment = st
            .secrets
            .iter()
            .find(|s| s["metadata"]["labels"][LOGS_LABEL] == LOGS_SEGMENT)
            .expect("a segment");
        assert!(
            segment["metadata"]["ownerReferences"][0]["uid"] == sandbox.to_string(),
            "owned by the sandbox in the broker's namespace"
        );
        assert_eq!(
            segment["metadata"]["ownerReferences"][0]["kind"],
            "AgentSandbox"
        );
    }

    #[tokio::test]
    async fn output_of_a_sandbox_elsewhere_looks_no_sandbox_up() {
        let (state, claim) = fake::seed(false);
        let store = fake::store(&state);
        let rec = store.get_claim(claim).await.unwrap();
        assert_eq!(rec.namespace, fake::TENANT);
        let limits = LogLimits {
            max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
        };
        state.lock().unwrap().log.clear();
        store
            .append_logs(&rec, &log_batch(1, 2, "hello"), &limits)
            .await
            .unwrap();
        let st = state.lock().unwrap();
        let sandbox_requests = st
            .log
            .iter()
            .filter(|(_, p)| p.contains("/agentsandboxes"))
            .count();
        assert_eq!(
            sandbox_requests, 0,
            "nothing across namespaces owns a segment: no sandbox is read for it"
        );
    }

    #[tokio::test]
    async fn an_idle_followers_poll_lists_segment_metadata_and_downloads_nothing() {
        let (state, claim) = fake::seed(false);
        let store = fake::store(&state);
        let rec = store.get_claim(claim).await.unwrap();
        let limits = LogLimits {
            max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
        };
        store
            .append_logs(&rec, &log_batch(1, 3, "line"), &limits)
            .await
            .unwrap();
        let nothing_new = LogChunk {
            truncated_before: 0,
            entries: Vec::new(),
            last_seq: Some(3),
        };
        let clear = || {
            let mut st = state.lock().unwrap();
            st.log.clear();
            st.metadata_lists.clear();
        };
        // At the cursor, and with a cursor past the ring: nothing new, one metadata list.
        for since in [3, 9] {
            clear();
            assert_eq!(
                store.read_logs(claim, Some(since)).await.unwrap(),
                nothing_new
            );
            let st = state.lock().unwrap();
            assert_eq!(st.log.len(), 1, "one request");
            assert_eq!(st.metadata_lists.len(), 1, "for metadata only");
        }
        // A claim with no ring: the default chunk, from the same one list.
        clear();
        assert_eq!(
            store.read_logs(Uuid::new_v4(), Some(0)).await.unwrap(),
            LogChunk::default()
        );
        assert_eq!(state.lock().unwrap().log.len(), 1);
        // Something new: the metadata says so and the ring is read.
        clear();
        let chunk = store.read_logs(claim, Some(2)).await.unwrap();
        assert_eq!(seqs(&chunk.entries), vec![3]);
        assert_eq!(state.lock().unwrap().log.len(), 2);
        // A segment whose annotations do not say: the full read answers, not a guess.
        {
            let mut st = state.lock().unwrap();
            let segment = st
                .secrets
                .iter_mut()
                .find(|s| s["metadata"]["labels"][LOGS_LABEL] == LOGS_SEGMENT)
                .expect("a segment");
            segment["metadata"]["annotations"]
                .as_object_mut()
                .unwrap()
                .remove(TRUNCATED_ANNOTATION);
        }
        clear();
        assert_eq!(store.read_logs(claim, Some(3)).await.unwrap(), nothing_new);
        let st = state.lock().unwrap();
        assert_eq!(st.log.len(), 2, "the metadata, then the ring itself");
        assert_eq!(st.metadata_lists.len(), 1);
    }

    #[tokio::test]
    async fn a_poll_after_a_cursor_answers_what_the_full_read_and_the_cursor_rule_give() {
        // A ring with a gap in it, in one segment.
        let (state, claim) = fake::seed(false);
        let store = fake::store(&state);
        let rec = store.get_claim(claim).await.unwrap();
        let limits = LogLimits {
            max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
        };
        store
            .append_logs(&rec, &log_batch(1, 2, "hello"), &limits)
            .await
            .unwrap();
        let mut lossy = log_batch(3, 4, "world");
        lossy.dropped_stdout = 64;
        store.append_logs(&rec, &lossy, &limits).await.unwrap();
        let full = store.read_logs(claim, None).await.unwrap();
        assert_eq!(seqs(&full.entries), vec![1, 2, 3, 4]);
        for since in 0..=5u64 {
            let want = LogChunk {
                truncated_before: full.truncated_before,
                entries: after_cursor(full.entries.clone(), Some(since)),
                last_seq: full.last_seq,
            };
            assert_eq!(
                store.read_logs(claim, Some(since)).await.unwrap(),
                want,
                "since {since}"
            );
        }

        // A ring that rolled and dropped its oldest segment: `truncated_before` is the
        // newest segment's, on the idle path as on the full one.
        let (state, claim) = fake::seed(false);
        let store = fake::store(&state);
        let rec = store.get_claim(claim).await.unwrap();
        let limits = LogLimits {
            max_bytes: 2 * LOG_SEGMENT_BYTES,
        };
        let kib = "k".repeat(1024);
        let per = u64::try_from(LOG_SEGMENT_BYTES / 1024).unwrap();
        for i in 0..3u64 {
            let from = i * per + 1;
            store
                .append_logs(&rec, &log_batch(from, from + per - 1, &kib), &limits)
                .await
                .unwrap();
        }
        let full = store.read_logs(claim, None).await.unwrap();
        assert_eq!(
            full.truncated_before,
            u64::try_from(LOG_SEGMENT_BYTES).unwrap()
        );
        for since in [0, per, 2 * per, 3 * per - 1, 3 * per, 3 * per + 1] {
            let got = store.read_logs(claim, Some(since)).await.unwrap();
            assert_eq!(got.truncated_before, full.truncated_before);
            assert_eq!(got.last_seq, full.last_seq);
            assert!(
                got.entries == after_cursor(full.entries.clone(), Some(since)),
                "the entries after {since}"
            );
        }
        state.lock().unwrap().metadata_lists.clear();
        let idle = store.read_logs(claim, Some(3 * per)).await.unwrap();
        assert_eq!(idle.entries.len(), 0);
        assert_eq!(state.lock().unwrap().metadata_lists.len(), 1);
    }

    #[tokio::test]
    async fn the_log_sweep_removes_orphan_and_ended_rings_and_the_audit_sweep_takes_the_ring_along()
    {
        // An orphan ring: a claim no sandbox carries.
        let (state, claim) = fake::seed(true);
        let store = fake::store(&state);
        let rec = store.get_claim(claim).await.unwrap();
        let limits = LogLimits {
            max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
        };
        store
            .append_logs(&rec, &log_batch(1, 1, "ended"), &limits)
            .await
            .unwrap();
        let mut orphan = rec.clone();
        orphan.uid = Uuid::new_v4();
        orphan.sandbox_uid = None;
        store
            .append_logs(&orphan, &log_batch(1, 1, "orphan"), &limits)
            .await
            .unwrap();
        // Nothing has ended before the dawn of time: only the orphan goes.
        assert_eq!(store.sweep_logs(Timestamp::MIN).await.unwrap(), 1);
        assert_eq!(
            store.read_logs(orphan.uid, None).await.unwrap().entries,
            Vec::new()
        );
        assert_eq!(
            seqs(&store.read_logs(claim, None).await.unwrap().entries),
            vec![1]
        );
        // The revoked record ended in 2026; now is after that.
        assert_eq!(store.sweep_logs(Timestamp::now()).await.unwrap(), 1);
        assert_eq!(
            store.read_logs(claim, None).await.unwrap().entries,
            Vec::new()
        );
        assert_eq!(store.sweep_logs(Timestamp::now()).await.unwrap(), 0);

        // The audit sweep of a claim takes its segments with the session Secrets.
        store
            .append_logs(&rec, &log_batch(2, 2, "late"), &limits)
            .await
            .unwrap();
        assert_eq!(store.sweep(Timestamp::now()).await.unwrap(), 1);
        let st = state.lock().unwrap();
        assert!(st.secrets.is_empty(), "left: {:?}", fake::secret_names(&st));
        fake::assert_only_home_secrets(&st);
    }
}
