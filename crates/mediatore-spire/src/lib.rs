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
    /// Not wired yet.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
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
}

/// In-memory entries for `dev_mode` and tests. Validates like [`KubeEntryManager`] and
/// remembers what was declared, so a test can assert that release really retracted the
/// entry.
#[derive(Debug, Default)]
pub struct MemoryEntries {
    entries: Mutex<BTreeMap<String, EntryRef>>,
}

impl MemoryEntries {
    /// Names currently declared, in order.
    ///
    /// # Panics
    /// If the lock is poisoned (a test already failed).
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.entries.lock().unwrap().keys().cloned().collect()
    }
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
