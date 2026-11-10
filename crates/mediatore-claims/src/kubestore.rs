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

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{OwnerReference, Time};
use kube::api::{DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::{Api, Client, CustomResource, ResourceExt};
use mediatore_proto::{ClaimReport, Provider, Subject, Workload, WorkloadExit};
use mediatore_store::seal::Sealed;
use mediatore_store::{
    ClaimRecord, ClaimStore, DelegatedSession, NodeRecord, SessionRecord, StoreError,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::sandbox::{AgentSandbox, FINALIZER, chrono_of, sandbox_uid_of};

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
}

impl KubeStore {
    /// Over `client`, keeping what is not a sandbox in the client's default namespace.
    pub fn new(client: Client) -> Self {
        let home = client.default_namespace().to_owned();
        Self { client, home }
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

    /// The sandbox a new record is for: by its UID when the record carries one, else by
    /// name, in whichever namespace it lives.
    async fn sandbox_for(&self, rec: &ClaimRecord) -> Result<AgentSandbox, StoreError> {
        let list = self
            .all_sandboxes()
            .list(&ListParams::default())
            .await
            .map_err(|e| backend(&e))?;
        let uid = rec.sandbox_uid.map(|u| u.to_string());
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
    async fn sandbox_of_claim(&self, uid: Uuid) -> Result<AgentSandbox, StoreError> {
        let list = self
            .all_sandboxes()
            .list(&ListParams::default().labels(&format!("{CLAIM_UID_LABEL}={uid}")))
            .await
            .map_err(|e| backend(&e))?;
        list.items
            .into_iter()
            .find(|sb| record_status_of(sb).is_some_and(|r| r.claim_uid == uid.to_string()))
            .ok_or_else(|| StoreError::NotFound(uid.to_string()))
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
                            expires_at: d.expires_at.as_ref().and_then(chrono_of),
                        },
                    );
                }
            }
        }
        Ok(rec)
    }

    /// Write `status.record` for `sb` from `rec`, and the labels the lookups need.
    async fn write_record(&self, sb: &AgentSandbox, rec: &ClaimRecord) -> Result<(), StoreError> {
        let name = sb.name_any();
        let name = name.as_str();
        let mut labels = serde_json::Map::new();
        labels.insert(CLAIM_UID_LABEL.into(), rec.uid.to_string().into());
        if let Some(node) = &rec.node_id {
            labels.insert(NODE_LABEL.into(), node_label(node).into());
        }
        self.sandboxes_of(sb)
            .patch(
                name,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({ "metadata": { "labels": labels } })),
            )
            .await
            .map_err(|e| backend(&e))?;
        let record = record_status_from(rec);
        self.sandboxes_of(sb)
            .patch_status(
                name,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({ "status": { "record": record } })),
            )
            .await
            .map_err(|e| backend(&e))?;
        Ok(())
    }

    /// Put `rec.refresh` and every delegation where the record keeps them: the sandbox's
    /// session Secrets, written as the record's own (`claimed`) and owned by the sandbox;
    /// an envelope gone from the record (revoked) empties its Secret.
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
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), StoreError> {
        let name = match audience {
            Some(a) => delegation_name(sandbox_uid, a),
            None => session_name(sandbox_uid),
        };
        let api = self.secrets();
        match (sealed, api.get_opt(&name).await.map_err(|e| backend(&e))?) {
            (Some(sealed), Some(_)) => {
                let mut metadata = serde_json::json!({ "labels": { SESSION_LABEL: "claimed" } });
                if let Some(owners) = owner_refs(&self.home, sb) {
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
            (Some(sealed), None) => {
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
            (None, Some(_)) => {
                // Dropped (revoked): the envelope's keys go, the Secret stays as the marker.
                let patch = serde_json::json!({
                    "data": { "key_id": null, "nonce": null, "ciphertext": null }
                });
                api.patch(&name, &PatchParams::default(), &Patch::Merge(patch))
                    .await
                    .map_err(|e| backend(&e))?;
            }
            (None, None) => {}
        }
        Ok(())
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

fn backend(e: &kube::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn is_conflict(e: &kube::Error) -> bool {
    matches!(e, kube::Error::Api(a) if a.code == 409)
}

fn is_not_found(e: &kube::Error) -> bool {
    matches!(e, kube::Error::Api(a) if a.code == 404)
}

fn time_of(t: DateTime<Utc>) -> Time {
    let nanos = i128::from(t.timestamp()) * 1_000_000_000 + i128::from(t.timestamp_subsec_nanos());
    Time(
        k8s_openapi::jiff::Timestamp::from_nanosecond(nanos)
            .unwrap_or(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
    )
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

/// The record a sandbox and its `status.record` describe, without the envelope.
fn record_from(sb: &AgentSandbox, status: &RecordStatus) -> Result<ClaimRecord, StoreError> {
    let uid = Uuid::parse_str(&status.claim_uid)
        .map_err(|e| StoreError::Backend(format!("status.record.claimUid: {e}")))?;
    let created_at = chrono_of(&status.created_at)
        .ok_or_else(|| StoreError::Backend("status.record.createdAt out of range".into()))?;
    Ok(ClaimRecord {
        uid,
        name: sb.name_any(),
        subject: Subject::from(&sb.spec.subject),
        entry_id: status.entry_id.clone(),
        node_id: status.node_id.clone(),
        audiences: sb.spec.audiences.clone(),
        workload: Workload::from(&sb.spec.workload),
        ttl_seconds: sb.spec.ttl_seconds,
        refresh: None,
        created_at,
        expires_at: status.expires_at.as_ref().and_then(chrono_of),
        revoked_at: status.revoked_at.as_ref().and_then(chrono_of),
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
        api_version: "mediatore.io/v1alpha1".into(),
        kind: "AgentSandbox".into(),
        name: sb.name_any(),
        uid: sb.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(false),
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
            ByteString(e.to_rfc3339().into_bytes()),
        );
    }
    data.insert(
        "subject".to_owned(),
        ByteString(serde_json::to_vec(subject).unwrap_or_default()),
    );
    data.insert("issuer".to_owned(), ByteString(issuer.as_bytes().to_vec()));
    data.insert(
        "created_at".to_owned(),
        ByteString(created_at.to_rfc3339().into_bytes()),
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
        created_at: DateTime::parse_from_rfc3339(&text("created_at")?)
            .ok()?
            .with_timezone(&Utc),
        audience: secret
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(AUDIENCE_LABEL))
            .cloned(),
        expires_at: text("expires_at")
            .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
            .map(|t| t.with_timezone(&Utc)),
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
        registered_at: chrono_of(&n.spec.registered_at)
            .ok_or_else(|| StoreError::Backend("sandboxnode registeredAt out of range".into()))?,
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
        issued_at: DateTime::parse_from_rfc3339(&f.spec.issued_at)
            .map_err(|e| StoreError::Backend(format!("policyfloor issuedAt: {e}")))?
            .with_timezone(&Utc),
    })
}

fn floor_spec_of(f: &mediatore_store::PolicyFloor) -> PolicyFloorSpec {
    PolicyFloorSpec {
        policy_namespace: f.namespace.clone(),
        policy_name: f.name.clone(),
        uid: f.uid.clone(),
        version: f.version,
        issued_at: f
            .issued_at
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
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

    async fn get_claim_by_name(&self, name: &str) -> Result<ClaimRecord, StoreError> {
        // By name across namespaces: the newest sandbox of that name carrying a record.
        let sb = self
            .sandboxes_with_records()
            .await?
            .into_iter()
            .filter(|sb| sb.name_any() == name)
            .max_by_key(|sb| sb.metadata.creation_timestamp.clone().map(|t| t.0))
            .ok_or_else(|| StoreError::NotFound(name.to_owned()))?;
        self.record_of(&sb).await
    }

    async fn update_claim(&self, rec: ClaimRecord) -> Result<(), StoreError> {
        let sb = self.sandbox_of_claim(rec.uid).await?;
        self.write_envelope(&sb, &rec).await?;
        self.write_record(&sb, &rec).await
    }

    async fn revoke_claim(&self, uid: Uuid, at: DateTime<Utc>) -> Result<(), StoreError> {
        let sb = self.sandbox_of_claim(uid).await?;
        let mut rec = self.record_of(&sb).await?;
        rec.revoked_at.get_or_insert(at);
        rec.refresh = None;
        rec.delegations.clear();
        self.write_envelope(&sb, &rec).await?;
        self.write_record(&sb, &rec).await
    }

    async fn get_claim_by_node(&self, node_id: &str) -> Result<ClaimRecord, StoreError> {
        let now = Utc::now();
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

    async fn sweep(&self, before: DateTime<Utc>) -> Result<usize, StoreError> {
        let mut swept = 0;
        for sb in self.sandboxes_with_records().await? {
            let Ok(rec) = self.record_of(&sb).await else {
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
            // The session goes with the sandbox: by owner reference when they share the
            // namespace, by this delete otherwise.
            if let Some(sandbox_uid) = rec.sandbox_uid
                && let Err(e) = self
                    .secrets()
                    .delete(&session_name(sandbox_uid), &DeleteParams::default())
                    .await
                && !is_not_found(&e)
            {
                return Err(backend(&e));
            }
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

    async fn sweep_sessions(&self, before: DateTime<Utc>) -> Result<usize, StoreError> {
        let list = self
            .secrets()
            .list(&ListParams::default().labels(&format!("{SESSION_LABEL}=parked")))
            .await
            .map_err(|e| backend(&e))?;
        let mut swept = 0;
        for secret in &list.items {
            let Some(session) = session_of(secret) else {
                continue;
            };
            if session.created_at >= before {
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
    fn a_session_is_owned_by_its_sandbox_only_within_the_brokers_namespace() {
        let mut sb = AgentSandbox::new(
            "sb",
            crate::sandbox::AgentSandboxSpec {
                subject: crate::sandbox::SandboxSubject {
                    issuer: "https://idp.example".into(),
                    id: "octocat".into(),
                    display: None,
                },
                pool_ref: banlieue_api::common::LocalObjectReference {
                    name: "pool-a".into(),
                },
                ttl_seconds: 600,
                audiences: vec![],
                workload: crate::sandbox::SandboxWorkload {
                    image: "registry.internal:5000/x:1".into(),
                    args: vec!["/bin/x".into()],
                    restart: None,
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

    #[test]
    fn the_node_label_fits_a_label_value_and_differs_per_node() {
        let a = node_label("spiffe://sandbox.test/spire/agent/tpm/aaaa");
        let b = node_label("spiffe://sandbox.test/spire/agent/tpm/bbbb");
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
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
                pool_ref: banlieue_api::common::LocalObjectReference {
                    name: "pool-a".into(),
                },
                ttl_seconds: 600,
                audiences: vec!["a".into()],
                workload: crate::sandbox::SandboxWorkload {
                    image: "registry.internal:5000/x:1".into(),
                    args: vec!["/bin/x".into()],
                    restart: Some(crate::sandbox::SandboxRestart::Never),
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
            subject: Subject::from(&sb.spec.subject),
            entry_id: Some("entry-1".into()),
            node_id: Some("spiffe://sandbox.test/spire/agent/tpm/aaaa".into()),
            audiences: vec!["a".into()],
            workload: Workload::from(&sb.spec.workload),
            ttl_seconds: 600,
            refresh: Some(sealed.clone()),
            created_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            expires_at: Some(DateTime::from_timestamp(1_700_000_600, 0).unwrap()),
            revoked_at: None,
            sandbox_uid: Some(sandbox_uid),
            policy_uid: Some("p-uid".into()),
            bundle_version: Some(4),
            report: None,
            exit: Some(WorkloadExit {
                exited_at: DateTime::from_timestamp(1_700_000_100, 0).unwrap(),
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
            registered_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
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
            issued_at: DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap(),
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
}
