// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! SPIRE registration entries, declared rather than pushed (ADR-0006).
//!
//! mediatore creates exactly two kinds of registration entry:
//! * a node bootstrap entry `spiffe://<td>/banlieue/node/<ek-hash>` for the in-guest agent
//!   (selectors `unix:uid:0` + `unix:path:/usr/bin/mediatore`, ADR-0014), and
//! * a claim entry `spiffe://<td>/banlieue/claim/<uid>` for the jailed workload
//!   (selector `unix:user:<sandbox user>`).
//!
//! Both are parented to the node's tpm agent ID, which is computable from the EK hash.
//! [`KubeEntryManager`] writes them as `ClusterStaticEntry` resources through the Kubernetes
//! API and waits for the SPIRE Controller Manager to report them set; mediatore never holds
//! a SPIRE admin identity. [`MemoryEntries`] is the fake for `dev_mode` and tests, and it
//! validates inputs exactly as the real one does.

pub mod kube;
pub mod x509pop;

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use mediatore_proto::ek::is_ek_hash;
use uuid::Uuid;

pub use crate::kube::{
    ClusterStaticEntry, ClusterStaticEntrySpec, EntriesConfig, KubeEntryManager, MAX_CLAIM_SVID_TTL,
};

/// Label every mediatore-declared entry carries; the orphan sweep selects on it.
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
/// Value of [`MANAGED_BY_LABEL`].
pub const MANAGED_BY: &str = "mediatore";
/// Label naming the entry kind: `node` or `claim`.
pub const KIND_LABEL: &str = "mediatore.io/kind";
/// Label carrying the claim UID on a claim entry.
pub const CLAIM_UID_LABEL: &str = "mediatore.io/claim-uid";
/// Name of the `ValidatingAdmissionPolicy` that bounds what may be declared as one of the
/// broker's entries (`deploy/base/admission/clusterstaticentry-mediatore.yaml`). The API
/// server names it in every denial it issues, which is how [`EntryManager::self_check`]
/// tells this policy's refusal from any other.
pub const ENTRIES_POLICY: &str = "mediatore-clusterstaticentry";
/// The message of that policy's sender validation, word for word (a test in
/// `mediatore-claims` holds the file to it): an entry that is the broker's by its name, its
/// label or its path was sent by a principal the policy does not take for the broker.
/// Read by [`EntryManager::self_check`], so a broker whose `ServiceAccount` the policy
/// does not name learns it at start and not at its first bind.
pub const ENTRIES_POLICY_SENDER_MESSAGE: &str = "an entry named mediatore-*, labelled app.kubernetes.io/managed-by=mediatore or under /banlieue/ is the broker's alone to declare, and this request is not from the broker's ServiceAccount as this policy spells it";
/// Path of the one mediatore binary on a pool member, pinned by the node entry's `unix:path`
/// selector (ADR-0014). The jail mounts the same file, so `unix:uid:0` is the selector that
/// tells the guest role from a jailed workload.
pub const GUEST_AGENT_PATH: &str = mediatore_proto::AGENT_BINARY_PATH;

/// Trust domain plus the path prefixes we own.
#[derive(Debug, Clone)]
pub struct Naming {
    /// e.g. `sandbox.example`
    pub trust_domain: String,
}

impl Naming {
    /// `spiffe://<td>/spire/agent/tpm/<ek-hash>`: the ID the TPM attestor gives the SPIRE
    /// agent on the VM, used as the parent of every entry on that node.
    #[must_use]
    pub fn agent_id(&self, ek_hash: &str) -> String {
        format!("spiffe://{}/spire/agent/tpm/{ek_hash}", self.trust_domain)
    }

    /// `spiffe://<td>/banlieue/node/<ek-hash>`
    #[must_use]
    pub fn node_id(&self, ek_hash: &str) -> String {
        format!("spiffe://{}/banlieue/node/{ek_hash}", self.trust_domain)
    }

    /// Parse the EK hash out of a peer's node SPIFFE ID, if it is one of ours.
    #[must_use]
    pub fn node_ek_from(&self, spiffe_id: &str) -> Option<String> {
        let prefix = format!("spiffe://{}/banlieue/node/", self.trust_domain);
        spiffe_id
            .strip_prefix(&prefix)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
    }

    /// `spiffe://<td>/banlieue/claim/<uid>`
    #[must_use]
    pub fn claim_id(&self, uid: Uuid) -> String {
        format!("spiffe://{}/banlieue/claim/{uid}", self.trust_domain)
    }

    /// `spiffe://<td>/mediatore`
    #[must_use]
    pub fn broker_id(&self) -> String {
        format!("spiffe://{}/mediatore", self.trust_domain)
    }

    /// Parse a claim UID out of a peer SPIFFE ID, if it is one of ours.
    #[must_use]
    pub fn claim_uid_from(&self, spiffe_id: &str) -> Option<Uuid> {
        let prefix = format!("spiffe://{}/banlieue/claim/", self.trust_domain);
        spiffe_id
            .strip_prefix(&prefix)
            .and_then(|s| Uuid::parse_str(s).ok())
    }

    /// `spiffe://<td>/gateway`: the one identity every egress gateway of the environment
    /// holds (ADR-0028 decision 2). The platform team registers it; the broker never mints
    /// it, a gateway not being a claim.
    #[must_use]
    pub fn gateway_id(&self) -> String {
        format!("spiffe://{}/gateway", self.trust_domain)
    }

    /// Whether a peer SPIFFE ID is the gateway identity: exactly it, nothing under it.
    #[must_use]
    pub fn is_gateway(&self, spiffe_id: &str) -> bool {
        spiffe_id == self.gateway_id()
    }

    /// `spiffe://<td>/gateway/authorizer`: the identity of a gateway's authorizer
    /// (`mediatore gateway`), as a client of the broker (ADR-0053 decision 1). The
    /// listeners keep [`Self::gateway_id`]; the two never stand in for each other.
    #[must_use]
    pub fn gateway_authorizer_id(&self) -> String {
        format!("spiffe://{}/gateway/authorizer", self.trust_domain)
    }

    /// Whether a peer SPIFFE ID is the gateway authorizer's: exactly it, never a prefix,
    /// so it is disjoint from [`Self::is_gateway`] by construction.
    #[must_use]
    pub fn is_gateway_authorizer(&self, spiffe_id: &str) -> bool {
        spiffe_id == self.gateway_authorizer_id()
    }
}

/// `mediatore-node-<ek-hash>`: deterministic, so "ensure" is a create that tolerates 409.
#[must_use]
pub fn node_entry_name(ek_hash: &str) -> String {
    format!("mediatore-node-{ek_hash}")
}

/// `mediatore-claim-<uid>`.
#[must_use]
pub fn claim_entry_name(claim_uid: Uuid) -> String {
    format!("mediatore-claim-{claim_uid}")
}

/// Which of the two shapes an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// In-guest agent identity for a node.
    Node,
    /// Jailed-workload identity for a claim.
    Claim,
}

impl EntryKind {
    /// The `mediatore.io/kind` label value.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Claim => "claim",
        }
    }
}

/// A declared entry, as mediatore tracks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRef {
    /// Resource name (`mediatore-node-…` or `mediatore-claim-…`).
    pub name: String,
    /// Shape.
    pub kind: EntryKind,
    /// The claim a claim entry belongs to.
    pub claim_uid: Option<Uuid>,
    /// The SPIFFE ID the entry is parented to (`spec.parentID`): for a node entry of a TPM
    /// guest, `spiffe://<td>/spire/agent/tpm/<ek hash>`, the same hash its name carries. What
    /// tells a TPM node entry from an x509pop one (ADR-0049), whose name is also a hash.
    pub parent_id: Option<String>,
}

/// Errors from declaring or retracting entries.
#[derive(Debug, thiserror::Error)]
pub enum SpireError {
    /// The API server could not be reached or answered unexpectedly.
    #[error("api: {0}")]
    Api(String),
    /// Admission refused the declaration (the policy in `deploy/base/admission`).
    #[error("refused at admission: {0}")]
    Denied(String),
    /// Another entry with the same parent and selectors already exists; the claim must fail.
    #[error("entry {0} is masked by another entry")]
    Masked(String),
    /// The controller manager did not set the entry within the ready timeout.
    #[error("entry {0} was not set within the ready timeout")]
    Timeout(String),
    /// Input that would never pass admission; refused before any request.
    #[error("invalid input: {0}")]
    Invalid(String),
    /// The entries admission self-check last failed, so nothing is declared until one
    /// passes (ADR-0056 decision 5). Refused before any request.
    #[error(
        "no entry is declared while the entries admission policy is unproven (ADR-0056 decision 5): {0}"
    )]
    Unproven(String),
    /// Not wired yet.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

/// Why [`EntryManager::self_check`] did not prove that the entries admission policy binds
/// the identity the manager declares under (ADR-0056 decision 5). Every variant is a
/// reason not to start: none is a degraded mode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelfCheckError {
    /// The API server admitted a dry-run create of an entry the policy must refuse: the
    /// policy is absent, unbound, or does not match what this identity sends.
    #[error(
        "the entries admission policy is not in force for this identity: the API server admitted a dry-run create of the forbidden ClusterStaticEntry {0}. Apply deploy/base/admission/clusterstaticentry-mediatore.yaml (policy and binding) before the broker starts"
    )]
    Admitted(String),
    /// The policy refused the probe by its sender validation: it is in force, and it does
    /// not take this identity for the broker, so it would refuse every real entry too.
    #[error(
        "the entries admission policy is in force but does not name this identity as the broker: every entry the broker declares would be refused. Set the key `broker` of the ConfigMap mediatore-agentsandbox-subject-policy (deploy/base/admission/agentsandbox-subject.yaml) to the username the broker runs as. The API server said: {0}"
    )]
    NotTheBroker(String),
    /// The policy is bound and could not be evaluated: its parameter (the `ConfigMap` that
    /// names the broker) is absent, or lacks the key the expressions read. Nothing was
    /// judged, so nothing is proven, and every real entry would be refused the same way.
    #[error(
        "the entries admission policy is bound but cannot be evaluated: its parameter is missing or incomplete, so every entry the broker declares would be refused. Restore the ConfigMap mediatore-agentsandbox-subject-policy with its key `broker` in the namespace the bindings' paramRef names (deploy/base/admission/agentsandbox-subject.yaml). The API server said: {0}"
    )]
    Parameter(String),
    /// Authorization refused the create before admission judged it. That proves nothing
    /// about the policy, and a broker without the verb is a different fault.
    #[error(
        "this identity may not create clusterstaticentries (RBAC, deploy/base/rbac.yaml), so the entries admission policy was never asked: {0}"
    )]
    Rbac(String),
    /// The API server refused the probe, and not through the entries policy (the CRD's
    /// schema, a missing CRD, an expired credential, another admission plugin).
    #[error(
        "the dry-run create of a forbidden ClusterStaticEntry was refused, but not by the entries admission policy (HTTP {code}), which proves nothing about it: {message}"
    )]
    Refused {
        /// The HTTP status code of the answer.
        code: u16,
        /// The API server's message.
        message: String,
    },
    /// No answer from the API server.
    #[error("the API server did not answer the entries admission self-check: {0}")]
    Unreachable(String),
    /// The manager has no way to ask. The trait's default, so a new manager fails closed.
    #[error("this entry manager cannot prove that the entries admission policy is in force")]
    Unsupported,
}

/// Refuse anything that is not the attestor's hash shape; the admission policy would too.
pub fn validate_ek_hash(ek_hash: &str) -> Result<(), SpireError> {
    if is_ek_hash(ek_hash) {
        Ok(())
    } else {
        Err(SpireError::Invalid(
            "ek hash must be 64 lowercase hex characters".into(),
        ))
    }
}

/// Refuse a user that is not `sb-` plus 12 lowercase hex (ADR-0004), as admission would.
pub fn validate_unix_user(user: &str) -> Result<(), SpireError> {
    let ok = user.strip_prefix("sb-").is_some_and(|h| {
        h.len() == 12
            && h.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    });
    if ok {
        Ok(())
    } else {
        Err(SpireError::Invalid(
            "unix user must be sb- followed by 12 lowercase hex characters".into(),
        ))
    }
}

/// A Go duration as SPIRE and its controller manager write them (`15m`, `900s`, `1h30m`):
/// whole hours, minutes and seconds in that order, each optional, at least one. What
/// `spire.entries.claim_svid_ttl` is parsed from.
///
/// # Errors
/// Anything else, including an empty string, a fraction, a unit SPIRE would accept but a
/// TTL never needs (`ms`, `us`, `ns`), or zero.
pub fn parse_go_duration(s: &str) -> Result<Duration, String> {
    let mut rest = s.trim();
    if rest.is_empty() {
        return Err("empty duration".into());
    }
    let mut secs: u64 = 0;
    let mut seen: u8 = 0;
    for (unit, factor, rank) in [("h", 3600u64, 1u8), ("m", 60, 2), ("s", 1, 3)] {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() || !rest[digits.len()..].starts_with(unit) {
            continue;
        }
        let n: u64 = digits
            .parse()
            .map_err(|_| format!("{s:?}: {digits} is too large"))?;
        secs = secs
            .checked_add(
                n.checked_mul(factor)
                    .ok_or_else(|| format!("{s:?} is too large"))?,
            )
            .ok_or_else(|| format!("{s:?} is too large"))?;
        rest = &rest[digits.len() + unit.len()..];
        seen = rank;
    }
    if !rest.is_empty() || seen == 0 {
        return Err(format!(
            "{s:?} is not a duration of hours, minutes and seconds (like 15m or 900s)"
        ));
    }
    if secs == 0 {
        return Err(format!("{s:?} is zero"));
    }
    Ok(Duration::from_secs(secs))
}

/// Registration entry operations mediatore needs. Every method returns the entry's resource
/// name; a declaration only succeeds once the entry is set on the SPIRE server.
#[async_trait]
pub trait EntryManager: Send + Sync + 'static {
    /// Declare (or find) the node bootstrap entry for a VM whose EK hash is known.
    async fn ensure_node_entry(&self, ek_hash: &str) -> Result<String, SpireError>;
    /// Declare the claim entry under the node's agent. Idempotent on the name. `claim_ttl`
    /// is the time the claim has left: the entry's SVID TTL never exceeds it (ADR-0027
    /// decision 7).
    async fn create_claim_entry(
        &self,
        ek_hash: &str,
        claim_uid: Uuid,
        unix_user: &str,
        claim_ttl: Duration,
    ) -> Result<String, SpireError>;
    /// Retract an entry by name; a missing entry is success.
    async fn delete_entry(&self, name: &str) -> Result<(), SpireError>;
    /// Every entry mediatore has declared, for the orphan sweep.
    async fn list_entries(&self) -> Result<Vec<EntryRef>, SpireError>;
    /// Prove, before the broker serves, that the entries admission policy binds the
    /// identity this manager declares under (ADR-0056 decision 5): ask for something the
    /// policy must refuse, persisting nothing, and succeed only on its refusal.
    ///
    /// # Errors
    /// [`SelfCheckError`]: the forbidden entry was admitted, the refusal was not the
    /// policy's, or there was no answer. The default refuses ([`SelfCheckError::Unsupported`]):
    /// a manager that cannot ask has proven nothing.
    async fn self_check(&self) -> Result<(), SelfCheckError> {
        Err(SelfCheckError::Unsupported)
    }
}

/// In-memory entries for `dev_mode` and tests. Validates like [`KubeEntryManager`] and
/// remembers what was declared, so a test can assert that release really retracted the
/// entry.
#[derive(Debug, Default)]
pub struct MemoryEntries {
    entries: Mutex<BTreeMap<String, EntryRef>>,
    /// What the self-check answers when a test has taken the policy away; `None` is a
    /// server that enforces it.
    self_check_fault: Mutex<Option<SelfCheckError>>,
}

impl MemoryEntries {
    /// Answer the self-check from now on as an API server would once the policy no longer
    /// binds the broker (`Some`), or as one that enforces it again (`None`). It changes the
    /// answer to the probe only: the fake still declares nothing but the two shapes, so it
    /// is never more permissive than the real thing, only less trusted.
    ///
    /// # Panics
    /// If the lock is poisoned (a test already failed).
    pub fn answer_self_check_with(&self, fault: Option<SelfCheckError>) {
        *self.self_check_fault.lock().unwrap() = fault;
    }

    /// Names currently declared, in order.
    ///
    /// # Panics
    /// If the lock is poisoned (a test already failed).
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.entries.lock().unwrap().keys().cloned().collect()
    }
}

/// The TPM agent ID the memory fake parents its entries to: the shape the Kubernetes entries
/// carry, under a trust domain that cannot be a real one.
fn memory_agent_id(ek_hash: &str) -> String {
    format!("spiffe://memory.invalid/spire/agent/tpm/{ek_hash}")
}

#[async_trait]
impl EntryManager for MemoryEntries {
    async fn ensure_node_entry(&self, ek_hash: &str) -> Result<String, SpireError> {
        validate_ek_hash(ek_hash)?;
        let name = node_entry_name(ek_hash);
        self.entries.lock().unwrap().insert(
            name.clone(),
            EntryRef {
                name: name.clone(),
                kind: EntryKind::Node,
                claim_uid: None,
                parent_id: Some(memory_agent_id(ek_hash)),
            },
        );
        tracing::info!(name, "memory: node entry declared");
        Ok(name)
    }

    async fn create_claim_entry(
        &self,
        ek_hash: &str,
        claim_uid: Uuid,
        unix_user: &str,
        _claim_ttl: Duration,
    ) -> Result<String, SpireError> {
        validate_ek_hash(ek_hash)?;
        validate_unix_user(unix_user)?;
        let name = claim_entry_name(claim_uid);
        self.entries.lock().unwrap().insert(
            name.clone(),
            EntryRef {
                name: name.clone(),
                kind: EntryKind::Claim,
                claim_uid: Some(claim_uid),
                parent_id: Some(memory_agent_id(ek_hash)),
            },
        );
        tracing::info!(name, %claim_uid, unix_user, "memory: claim entry declared");
        Ok(name)
    }

    async fn delete_entry(&self, name: &str) -> Result<(), SpireError> {
        let removed = self.entries.lock().unwrap().remove(name).is_some();
        tracing::info!(name, removed, "memory: entry retracted");
        Ok(())
    }

    async fn list_entries(&self) -> Result<Vec<EntryRef>, SpireError> {
        Ok(self.entries.lock().unwrap().values().cloned().collect())
    }

    /// As a compliant API server answers: the forbidden entry is refused by the policy, so
    /// the check passes. This fake only ever declares the two shapes, through validation
    /// that refuses what admission would, and it cannot be told to admit anything else.
    async fn self_check(&self) -> Result<(), SelfCheckError> {
        if let Some(fault) = self.self_check_fault.lock().unwrap().clone() {
            return Err(fault);
        }
        tracing::debug!("memory: entries admission self-check answered as the policy would");
        Ok(())
    }
}

/// An entry manager that declares nothing it has not proven it may: the gate behind which
/// the broker keeps its manager (ADR-0056 decision 5 and open question 7).
///
/// It starts unproven. [`EntryManager::self_check`] asks the inner manager and remembers
/// the answer; while the last answer was a failure, `ensure_node_entry` and
/// `create_claim_entry` ask once more before each declaration and refuse with
/// [`SpireError::Unproven`] unless that passes, so a broker that knows its bound is gone
/// stops declaring, and starts again as soon as the policy answers, without waiting for
/// the next resync. Retracting and listing are never gated: releasing a claim removes an
/// entry, and that must work whatever the policy's state. Nothing here releases anything.
pub struct Gated {
    inner: std::sync::Arc<dyn EntryManager>,
    proven: std::sync::atomic::AtomicBool,
}

impl Gated {
    /// Over `inner`, unproven until a self-check passes.
    #[must_use]
    pub fn new(inner: std::sync::Arc<dyn EntryManager>) -> Self {
        Self {
            inner,
            proven: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Whether the last self-check passed.
    #[must_use]
    pub fn is_proven(&self) -> bool {
        self.proven.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Pass when proven; otherwise ask again, and refuse unless the policy answers now.
    async fn proven_or_refused(&self) -> Result<(), SpireError> {
        if self.is_proven() {
            return Ok(());
        }
        self.self_check()
            .await
            .map_err(|e| SpireError::Unproven(e.to_string()))
    }
}

#[async_trait]
impl EntryManager for Gated {
    async fn ensure_node_entry(&self, ek_hash: &str) -> Result<String, SpireError> {
        self.proven_or_refused().await?;
        self.inner.ensure_node_entry(ek_hash).await
    }

    async fn create_claim_entry(
        &self,
        ek_hash: &str,
        claim_uid: Uuid,
        unix_user: &str,
        claim_ttl: Duration,
    ) -> Result<String, SpireError> {
        self.proven_or_refused().await?;
        self.inner
            .create_claim_entry(ek_hash, claim_uid, unix_user, claim_ttl)
            .await
    }

    async fn delete_entry(&self, name: &str) -> Result<(), SpireError> {
        self.inner.delete_entry(name).await
    }

    async fn list_entries(&self) -> Result<Vec<EntryRef>, SpireError> {
        self.inner.list_entries().await
    }

    async fn self_check(&self) -> Result<(), SelfCheckError> {
        let answer = self.inner.self_check().await;
        self.proven
            .store(answer.is_ok(), std::sync::atomic::Ordering::SeqCst);
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EK: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";

    #[test]
    fn claim_uid_roundtrip() {
        let n = Naming {
            trust_domain: "sandbox.test".into(),
        };
        let uid = Uuid::new_v4();
        assert_eq!(n.claim_uid_from(&n.claim_id(uid)), Some(uid));
        assert_eq!(n.claim_uid_from("spiffe://sandbox.test/mediatore"), None);
        assert_eq!(
            n.claim_uid_from("spiffe://other.test/banlieue/claim/x"),
            None
        );
    }

    #[test]
    fn node_ek_roundtrip() {
        let n = Naming {
            trust_domain: "sandbox.test".into(),
        };
        assert_eq!(n.node_ek_from(&n.node_id(EK)), Some(EK.to_owned()));
        assert_eq!(n.node_ek_from(&n.agent_id(EK)), None);
        assert_eq!(n.node_ek_from("spiffe://sandbox.test/banlieue/node/"), None);
        assert_eq!(
            n.node_ek_from(&format!("spiffe://other.test/banlieue/node/{EK}")),
            None
        );
    }

    #[test]
    fn the_gateway_identity_is_exactly_one_id_and_nothing_near_it() {
        let n = Naming {
            trust_domain: "sandbox.test".into(),
        };
        assert_eq!(n.gateway_id(), "spiffe://sandbox.test/gateway");
        assert!(n.is_gateway("spiffe://sandbox.test/gateway"));
        assert!(!n.is_gateway("spiffe://sandbox.test/gateway/"));
        assert!(!n.is_gateway("spiffe://sandbox.test/gateway/1"));
        assert!(!n.is_gateway("spiffe://sandbox.test/gatewayx"));
        assert!(!n.is_gateway("spiffe://other.test/gateway"));
        assert!(!n.is_gateway(&n.broker_id()));
        assert!(n.claim_uid_from(&n.gateway_id()).is_none());
        assert!(n.node_ek_from(&n.gateway_id()).is_none());
    }

    #[test]
    fn the_authorizer_identity_is_exactly_one_id_and_is_not_the_gateway_identity() {
        // ADR-0053 decision 1: two exact names, disjoint in both directions. No matcher
        // is a prefix test, so `/gateway` does not take in what sits under it.
        let n = Naming {
            trust_domain: "sandbox.test".into(),
        };
        let authorizer = n.gateway_authorizer_id();
        assert_eq!(authorizer, "spiffe://sandbox.test/gateway/authorizer");
        assert!(n.is_gateway_authorizer(&authorizer));
        assert!(!n.is_gateway(&authorizer));
        assert!(!n.is_gateway_authorizer(&n.gateway_id()));
        assert!(n.is_gateway(&n.gateway_id()));
        for near in [
            "spiffe://sandbox.test/gateway/authorizer/",
            "spiffe://sandbox.test/gateway/authorizer/1",
            "spiffe://sandbox.test/gateway/authorizerx",
            "spiffe://sandbox.test/gateway/",
            "spiffe://sandbox.test/gateway-authorizer",
            "spiffe://sandbox.test/authorizer",
            "spiffe://other.test/gateway/authorizer",
        ] {
            assert!(!n.is_gateway_authorizer(near), "{near}");
            assert!(!n.is_gateway(near), "{near}");
        }
        assert!(!n.is_gateway_authorizer(&n.broker_id()));
        assert!(n.claim_uid_from(&authorizer).is_none());
        assert!(n.node_ek_from(&authorizer).is_none());
    }

    #[test]
    fn input_validation_matches_admission() {
        assert!(validate_ek_hash(EK).is_ok());
        assert!(validate_ek_hash("3f9a").is_err());
        assert!(validate_ek_hash(&EK.to_uppercase()).is_err());
        assert!(validate_unix_user("sb-0123456789ab").is_ok());
        assert!(validate_unix_user("sb-0123456789AB").is_err());
        assert!(validate_unix_user("root").is_err());
        assert!(validate_unix_user("sb-0123").is_err());
    }

    #[tokio::test]
    async fn memory_fake_declares_and_retracts() {
        let m = MemoryEntries::default();
        let uid = Uuid::new_v4();
        let node = m.ensure_node_entry(EK).await.unwrap();
        let claim = m
            .create_claim_entry(EK, uid, "sb-0123456789ab", Duration::from_hours(1))
            .await
            .unwrap();
        assert_eq!(node, node_entry_name(EK));
        assert_eq!(claim, claim_entry_name(uid));
        let listed = m.list_entries().await.unwrap();
        assert_eq!(listed.len(), 2);
        assert!(
            listed
                .iter()
                .any(|e| e.kind == EntryKind::Claim && e.claim_uid == Some(uid))
        );
        m.delete_entry(&claim).await.unwrap();
        m.delete_entry("never-declared").await.unwrap();
        assert_eq!(m.names(), vec![node]);
    }

    #[tokio::test]
    async fn memory_fake_is_no_more_permissive_than_the_real_thing() {
        let m = MemoryEntries::default();
        assert!(matches!(
            m.ensure_node_entry("3f9a").await,
            Err(SpireError::Invalid(_))
        ));
        assert!(matches!(
            m.create_claim_entry(EK, Uuid::new_v4(), "root", Duration::from_hours(1))
                .await,
            Err(SpireError::Invalid(_))
        ));
        assert_eq!(m.names(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn memory_fake_answers_the_self_check_as_a_compliant_server_would() {
        // ADR-0056 decision 5: under dev_mode there is no API server, and the fake stands
        // for one that enforces the policy. It declares nothing while answering.
        let m = MemoryEntries::default();
        assert_eq!(m.self_check().await, Ok(()));
        assert_eq!(m.names(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_gate_declares_nothing_while_unproven_and_always_retracts() {
        // ADR-0056 decision 5, open question 7: a broker that knows its bound is gone stops
        // declaring. It never stops retracting, and it releases nothing on its own.
        let inner = std::sync::Arc::new(MemoryEntries::default());
        let gated = Gated::new(inner.clone());
        assert!(!gated.is_proven(), "unproven until a self-check has passed");
        gated.self_check().await.unwrap();
        assert!(gated.is_proven());
        let node = gated.ensure_node_entry(EK).await.unwrap();
        let claim = Uuid::new_v4();
        let entry = gated
            .create_claim_entry(EK, claim, "sb-0123456789ab", Duration::from_hours(1))
            .await
            .unwrap();

        // The policy stops answering for this identity.
        inner.answer_self_check_with(Some(SelfCheckError::Admitted(
            "mediatore-selfcheck-0".into(),
        )));
        assert!(gated.self_check().await.is_err());
        assert!(!gated.is_proven());
        let other = "a".repeat(64);
        let refused = gated.ensure_node_entry(&other).await.unwrap_err();
        assert!(matches!(refused, SpireError::Unproven(_)), "{refused:?}");
        assert!(refused.to_string().contains("unproven"), "{refused}");
        assert!(matches!(
            gated
                .create_claim_entry(
                    EK,
                    Uuid::new_v4(),
                    "sb-0123456789ab",
                    Duration::from_hours(1)
                )
                .await,
            Err(SpireError::Unproven(_))
        ));
        assert_eq!(
            inner.names(),
            vec![entry.clone(), node.clone()],
            "what was declared stays declared: the gate releases nothing"
        );
        // Listing and retracting are not declarations.
        assert_eq!(gated.list_entries().await.unwrap().len(), 2);
        gated.delete_entry(&entry).await.unwrap();
        assert_eq!(inner.names(), vec![node.clone()]);

        // The policy answers again: the next declaration asks, passes and goes through,
        // without waiting for anyone else to run the check.
        inner.answer_self_check_with(None);
        gated.ensure_node_entry(&other).await.unwrap();
        assert!(gated.is_proven());
        assert_eq!(inner.names().len(), 2);
    }

    #[tokio::test]
    async fn a_gate_never_checked_asks_before_its_first_declaration() {
        // Fail closed from construction: no declaration reaches the inner manager before
        // the policy has been proven once.
        let inner = std::sync::Arc::new(MemoryEntries::default());
        inner.answer_self_check_with(Some(SelfCheckError::Unreachable("connect".into())));
        let gated = Gated::new(inner.clone());
        assert!(matches!(
            gated.ensure_node_entry(EK).await,
            Err(SpireError::Unproven(_))
        ));
        assert_eq!(inner.names(), Vec::<String>::new());
    }

    /// A manager that implements only what the trait requires.
    struct NoSelfCheck;

    #[async_trait]
    impl EntryManager for NoSelfCheck {
        async fn ensure_node_entry(&self, _ek_hash: &str) -> Result<String, SpireError> {
            Err(SpireError::NotImplemented("ensure_node_entry"))
        }

        async fn create_claim_entry(
            &self,
            _ek_hash: &str,
            _claim_uid: Uuid,
            _unix_user: &str,
            _claim_ttl: Duration,
        ) -> Result<String, SpireError> {
            Err(SpireError::NotImplemented("create_claim_entry"))
        }

        async fn delete_entry(&self, _name: &str) -> Result<(), SpireError> {
            Err(SpireError::NotImplemented("delete_entry"))
        }

        async fn list_entries(&self) -> Result<Vec<EntryRef>, SpireError> {
            Err(SpireError::NotImplemented("list_entries"))
        }
    }

    #[tokio::test]
    async fn a_manager_that_cannot_ask_fails_the_self_check_closed() {
        assert_eq!(
            NoSelfCheck.self_check().await,
            Err(SelfCheckError::Unsupported),
            "the default must refuse: a manager that proves nothing does not start a broker"
        );
    }

    #[test]
    fn every_self_check_error_says_which_fault_it_is() {
        // The operator reads one line at start; each fault names its own remedy and none
        // reads like another.
        let admitted = SelfCheckError::Admitted("mediatore-selfcheck-x".into()).to_string();
        assert!(
            admitted.contains("not in force for this identity"),
            "{admitted}"
        );
        assert!(
            admitted.contains("clusterstaticentry-mediatore.yaml"),
            "{admitted}"
        );
        let renamed = SelfCheckError::NotTheBroker("denied".into()).to_string();
        assert!(renamed.contains("does not name this identity"), "{renamed}");
        assert!(renamed.contains("key `broker`"), "{renamed}");
        let unparameterised = SelfCheckError::Parameter("no params found".into()).to_string();
        assert!(
            unparameterised.contains("cannot be evaluated"),
            "{unparameterised}"
        );
        assert!(
            unparameterised.contains("mediatore-agentsandbox-subject-policy"),
            "{unparameterised}"
        );
        assert!(
            !unparameterised.contains("not in force"),
            "{unparameterised}"
        );
        let rbac = SelfCheckError::Rbac("cannot create".into()).to_string();
        assert!(rbac.contains("RBAC"), "{rbac}");
        assert!(!rbac.contains("not in force"), "{rbac}");
        let refused = SelfCheckError::Refused {
            code: 422,
            message: "schema".into(),
        }
        .to_string();
        assert!(refused.contains("HTTP 422"), "{refused}");
        let silent = SelfCheckError::Unreachable("connect".into()).to_string();
        assert!(silent.contains("did not answer"), "{silent}");
        assert!(!silent.contains("not in force"), "{silent}");
    }

    #[test]
    fn go_durations_of_hours_minutes_and_seconds_parse_and_nothing_else_does() {
        for (text, secs) in [
            ("15m", 900),
            ("900s", 900),
            ("1h", 3600),
            ("1h30m", 5400),
            ("1h30m15s", 5415),
            (" 2m ", 120),
            ("4h", 14400),
        ] {
            assert_eq!(
                parse_go_duration(text).unwrap(),
                Duration::from_secs(secs),
                "{text}"
            );
        }
        for bad in [
            "", "0", "0s", "15", "m", "1.5h", "30m1h", "15min", "100ms", "-1h", "1h1h",
        ] {
            assert!(parse_go_duration(bad).is_err(), "{bad:?} parsed");
        }
    }
}
