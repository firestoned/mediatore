//! Wire contract between the mediatore server, the in-guest agent (`mediatore-guest`)
//! and the workload-side CLI (`sandbox-token`).
//!
//! Every type here is versioned together with [`API_VERSION`]. Breaking changes to any of
//! them are a new API version, never a silent edit.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Path prefix all endpoints live under.
pub const API_VERSION: &str = "v1";

/// Length of the hex suffix in a derived sandbox username (`sb-` + this many hex chars).
pub const USERNAME_HASH_LEN: usize = 12;

/// Which hypervisor a node runs on. Recorded for audit; identity does not depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// `VMware vSphere` (vTPM, EK certificate issued by the VMCA).
    Vsphere,
    /// Cloud Hypervisor with `swtpm` on a socket.
    CloudHypervisor,
    /// libvirt/KVM with `swtpm` emulator backend.
    Libvirt,
}

/// `POST /v1/nodes`, sent by the in-guest agent at boot over the node SVID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistration {
    /// SHA-256 of the TPM endorsement public key, as the SPIRE TPM attestor computes it.
    pub ek_hash: String,
    /// `/sys/class/dmi/id/product_uuid` inside the guest.
    pub dmi_uuid: Uuid,
    /// Guest hostname, informational.
    pub hostname: String,
    /// Hypervisor, if the guest can tell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
}

/// Response to a node registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistered {
    /// The node's SPIFFE ID as SPIRE reports it.
    pub node_id: String,
}

/// The subject a claim was handed to. Mirrors `spec.subject` on the banlieue claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// OIDC issuer URL, byte-for-byte as it appears in `iss`.
    pub issuer: String,
    /// Raw subject identifier: Entra `oid`, or the GitHub login via Dex.
    pub id: String,
    /// Human-readable name (UPN, e-mail, or login), informational only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

impl Subject {
    /// Derive the deterministic, valid Linux username for this subject:
    /// `sb-` followed by the first [`USERNAME_HASH_LEN`] hex characters of
    /// `sha256(issuer || "|" || id)`.
    #[must_use]
    pub fn sandbox_username(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.issuer.as_bytes());
        h.update(b"|");
        h.update(self.id.as_bytes());
        let digest = hex::encode(h.finalize());
        format!("sb-{}", &digest[..USERNAME_HASH_LEN])
    }
}

/// What the sandbox should run once identity is established.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Workload {
    /// OCI reference of the rootfs to unpack into `/mnt/sandbox`.
    pub image: String,
    /// Command and arguments to exec inside the jail.
    #[serde(default)]
    pub args: Vec<String>,
}

/// `POST /v1/claims` body, sent by a user or agent with an `IdP` bearer token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// `spec.poolRef` on the banlieue claim.
    pub pool_ref: String,
    /// `spec.ttlSeconds` on the banlieue claim; a deadline counted from bind.
    pub ttl_seconds: u32,
    /// Downstream audiences the sandbox may request tokens for. Must be a subset of
    /// what mediatore is configured to serve.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// What to run.
    pub workload: Workload,
}

/// Claim lifecycle as mirrored from banlieue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimPhase {
    /// Waiting for a Ready pool member.
    Pending,
    /// Bound to a member; identity entry created.
    Bound,
    /// TTL reached or deleted; member being destroyed.
    Releasing,
    /// Terminal; never rebound.
    Failed,
}

/// `POST /v1/claims` and `GET /v1/claims/{name}` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimResponse {
    /// Kubernetes object name.
    pub name: String,
    /// Kubernetes object UID once persisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<Uuid>,
    /// Current phase.
    pub phase: ClaimPhase,
    /// Deadline, once bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Guest addresses, once known.
    #[serde(default)]
    pub addresses: Vec<String>,
}

/// `GET /v1/me`, answered to the in-guest agent over the node SVID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Me {
    /// Kubernetes UID of the claim bound to this node.
    pub claim_uid: Uuid,
    /// Who the sandbox is for.
    pub subject: Subject,
    /// Deadline after which the guest tears the jail down regardless.
    pub expires_at: DateTime<Utc>,
    /// What to run.
    pub workload: Workload,
}

/// `POST /v1/token` body, sent by the jailed workload over its claim SVID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    /// Exactly one downstream audience.
    pub audience: String,
}

/// `POST /v1/token` response. Never contains a refresh token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The bearer token for `audience`.
    pub access_token: String,
    /// Always `Bearer`.
    pub token_type: String,
    /// Absolute expiry; the workload must not cache past this.
    pub expires_at: DateTime<Utc>,
    /// Echo of the requested audience.
    pub audience: String,
    /// Who the token acts for.
    pub subject: Subject,
}

/// Error body for every non-2xx response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Stable machine-readable code (`unauthorized`, `unknown_audience`, ...).
    pub error: String,
    /// Human-readable detail, safe to show to a caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_is_deterministic_and_valid() {
        let s = Subject {
            issuer: "https://dex.home.example".into(),
            id: "octocat".into(),
            display: None,
        };
        let a = s.sandbox_username();
        let b = s.sandbox_username();
        assert_eq!(a, b);
        assert_eq!(a.len(), 3 + USERNAME_HASH_LEN);
        assert!(a.starts_with("sb-"));
        assert!(a[3..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn username_changes_with_issuer() {
        let mk = |iss: &str| Subject {
            issuer: iss.into(),
            id: "octocat".into(),
            display: None,
        };
        assert_ne!(
            mk("https://a").sandbox_username(),
            mk("https://b").sandbox_username()
        );
    }

    #[test]
    fn claim_request_roundtrips() {
        let req = ClaimRequest {
            pool_ref: "pool-a".into(),
            ttl_seconds: 3600,
            audiences: vec!["grafana.home.example".into()],
            workload: Workload {
                image: "registry/sandbox:latest".into(),
                args: vec![],
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ClaimRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pool_ref, "pool-a");
    }
}
