// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Wire contract between the broker (`mediatore serve`), the in-guest agent (`mediatore guest`)
//! and the workload-side client (`mediatore token`).
//!
//! Every type here is versioned together with [`API_VERSION`]. Breaking changes to any of
//! them are a new API version, never a silent edit.

pub mod cert;
pub mod ek;
pub mod image;
pub mod tls;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Path prefix all endpoints live under.
pub const API_VERSION: &str = "v1";

/// Where the one mediatore binary lives on a pool member (ADR-0014). The node entry's
/// `unix:path` selector pins it, and the guest role bind-mounts this exact path, never the
/// path it happens to run from, into the jail at the same place.
pub const AGENT_BINARY_PATH: &str = "/usr/bin/mediatore";

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

/// A destination the jailed workload may reach: a host (a name or an address) and a TCP
/// port. Declared per audience in the broker's config, returned by `GET /v1/me` for the
/// claim's audiences, admitted by the guest's ruleset for the sandbox uid (ADR-0020).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    /// Host name or IP address, without brackets.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl std::str::FromStr for Endpoint {
    type Err = String;

    /// `host:port`, with an IPv6 address in brackets (`[2001:db8::1]:443`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("{s:?}: expected host:port"))?;
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty() || (host.contains(':') && !s.starts_with('[')) {
            return Err(format!(
                "{s:?}: expected host:port, an IPv6 address in brackets"
            ));
        }
        let port: u16 = port
            .parse()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("{s:?}: the port must be 1 to 65535"))?;
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// A credential in a request body: serialises as the plain string, never prints.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
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
    /// The caller's upstream refresh token, delegated to mediatore so it can refresh the
    /// session before every issue (ADR-0013). Required for an issuer configured with a
    /// `session`, refused for any other. Sealed before it is stored; never returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Secret>,
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
    /// The claim's UID, once the claim exists: the key of the claim's SPIFFE identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<Uuid>,
    /// Current phase.
    pub phase: ClaimPhase,
    /// `Bound` and the claim's registration entry is set: the sandbox can fetch its SVID
    /// (ADR-0008 decision 11).
    #[serde(default)]
    pub ready: bool,
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
    /// Where the workload may connect, beyond the broker: the `egress` of every audience
    /// on the claim, sorted and deduplicated (ADR-0020). Empty with an old broker or an
    /// audience that declares none; the jail then reaches the broker only.
    #[serde(default)]
    pub egress: Vec<Endpoint>,
    /// The operator's credential for the registry `workload.image` names, when one is
    /// configured (ADR-0022); absent, the pull is anonymous. Used by the guest for one
    /// pull, kept nowhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_credential: Option<RegistryCredential>,
}

/// The operator's pull credential for one registry, handed to the guest for the registry
/// its claim's image names (ADR-0022). The password prints as `[redacted]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryCredential {
    /// The registry host as the API reaches it (`registry-1.docker.io` for Docker Hub).
    pub host: String,
    /// The login at that registry.
    pub username: String,
    /// The password or token.
    pub password: Secret,
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
    fn an_endpoint_is_host_and_port_with_ipv6_in_brackets() {
        let e: Endpoint = "grafana.home.example:443".parse().unwrap();
        assert_eq!((e.host.as_str(), e.port), ("grafana.home.example", 443));
        assert_eq!(e.to_string(), "grafana.home.example:443");
        let e: Endpoint = "[2001:db8::1]:8443".parse().unwrap();
        assert_eq!((e.host.as_str(), e.port), ("2001:db8::1", 8443));
        assert_eq!(e.to_string(), "[2001:db8::1]:8443");
        let e: Endpoint = "192.0.2.10:80".parse().unwrap();
        assert_eq!((e.host.as_str(), e.port), ("192.0.2.10", 80));
    }

    #[test]
    fn a_malformed_endpoint_is_refused() {
        for bad in [
            "grafana.home.example",
            ":443",
            "grafana.home.example:0",
            "grafana.home.example:65536",
            "grafana.home.example:https",
            "2001:db8::1:443",
            "[2001:db8::1]:",
        ] {
            assert!(bad.parse::<Endpoint>().is_err(), "{bad} parsed");
        }
    }

    #[test]
    fn me_without_egress_deserialises_as_an_empty_list() {
        let me: Me = serde_json::from_value(serde_json::json!({
            "claim_uid": "00000000-0000-0000-0000-000000000001",
            "subject": { "issuer": "https://dex.home.example", "id": "octocat" },
            "expires_at": "2026-01-01T00:00:00Z",
            "workload": { "image": "registry.internal:5000/sandbox:latest" }
        }))
        .unwrap();
        assert_eq!(me.egress, Vec::<Endpoint>::new());
    }

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
            refresh_token: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ClaimRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pool_ref, "pool-a");
    }
}
