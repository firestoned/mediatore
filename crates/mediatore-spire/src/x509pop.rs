// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The x509pop node attestation path for a guest with no vTPM (ADR-0049), as pure functions.

use std::collections::BTreeSet;

use mediatore_proto::x509pop::{CommonNameError, single_common_name};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::Encode as _;
use x509_cert::ext::pkix::BasicConstraints;

use crate::kube::ClusterStaticEntrySpec;
use crate::{
    GUEST_AGENT_PATH, Naming, SpireError, node_entry_name, validate_ek_hash, validate_node_key,
};

/// Longest common name accepted (X.509 `ub-common-name`).
pub use mediatore_proto::x509pop::MAX_COMMON_NAME_LEN;

/// How a node's agent attests, chosen explicitly by the caller, never guessed from which
/// data happens to be present (ADR-0049).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeAttestation {
    /// A guest with a vTPM: the tpm attestor, agent ID from the EK hash (ADR-0018).
    Tpm {
        /// Hex SHA-256 of the EK public key.
        ek_hash: String,
    },
    /// A guest without one: the x509pop attestor, agent ID from the host CA's and the
    /// guest's common names (ADR-0049).
    X509pop {
        /// Common name of the host's signing CA.
        issuer_cn: String,
        /// Common name of the guest certificate: the machine's UID.
        subject_cn: String,
    },
}

impl From<&mediatore_proto::Attestation> for NodeAttestation {
    /// What a node's registration says (ADR-0049 decision 8), as the attestation the watcher
    /// also builds: the two then derive the key and the agent ID with the same functions.
    /// Nothing is validated here; [`node_key`] and [`agent_id_for`] do that.
    fn from(wire: &mediatore_proto::Attestation) -> Self {
        match wire {
            mediatore_proto::Attestation::Tpm { ek_hash } => Self::Tpm {
                ek_hash: ek_hash.clone(),
            },
            mediatore_proto::Attestation::X509pop {
                issuer_cn,
                subject_cn,
            } => Self::X509pop {
                issuer_cn: issuer_cn.clone(),
                subject_cn: subject_cn.clone(),
            },
        }
    }
}

/// What banlieue publishes for an x509pop guest: the administrator-asserted host CA
/// (`Provider.spec.attestation.hostCa`) and the machine's `status.attestationSubject`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509popInput {
    /// PEM of the host's signing CA certificate: exactly one.
    pub host_ca_pem: String,
    /// The subject common name the host's signer will set.
    pub attestation_subject: String,
}

/// Path prefix the x509pop attestor gives its agents under the trust domain.
const X509POP_AGENT_PREFIX: &str = "spire/agent/x509pop";

/// Path prefix the tpm attestor gives its agents under the trust domain.
const TPM_AGENT_PREFIX: &str = "spire/agent/tpm";

/// Refuse a common name that is not a SPIFFE path segment: non-empty, at most
/// [`MAX_COMMON_NAME_LEN`] bytes, letters, digits, dots, dashes and underscores only, and
/// neither `.` nor `..` (SPIFFE forbids those segments). The rule itself is
/// [`mediatore_proto::x509pop::validate_common_name`], which the guest applies to its own
/// leaf, so the two sides cannot drift.
pub fn validate_common_name(cn: &str) -> Result<(), SpireError> {
    mediatore_proto::x509pop::validate_common_name(cn)
        .map_err(|e| SpireError::Invalid(e.to_string()))
}

/// `spiffe://<td>/spire/agent/x509pop/<issuer CN>/<subject CN>`: the ID the SPIRE server's
/// `agent_path_template` `/x509pop/{{ .Issuer.CommonName }}/{{ .Subject.CommonName }}` gives
/// the agent (ADR-0049 decision 2). Both names are validated first.
pub fn x509pop_agent_id(td: &str, issuer: &str, subject: &str) -> Result<String, SpireError> {
    if td.is_empty() {
        return Err(SpireError::Invalid("trust domain is empty".into()));
    }
    validate_common_name(issuer)?;
    validate_common_name(subject)?;
    Ok(format!(
        "spiffe://{td}/{X509POP_AGENT_PREFIX}/{issuer}/{subject}"
    ))
}

/// The one common name of a certificate's subject; zero or several is refused, because
/// the server's template reads one and a second would make the ID ambiguous.
fn common_name_of(cert: &Certificate) -> Result<String, SpireError> {
    single_common_name(cert.tbs_certificate().subject()).map_err(|e| match e {
        CommonNameError::Count(n) => SpireError::Invalid(format!(
            "a CA certificate must have exactly one common name, found {n}"
        )),
        other => SpireError::Invalid(other.to_string()),
    })
}

/// Refuse a certificate that is not a host CA in the sense ADR-0049 decision 2 needs:
/// `basicConstraints` with `cA` true and a path length of zero. The server names an agent
/// after its leaf's *immediate* issuer (ADR-0050's prototype table), so a CA free to sign
/// another CA could sign one that carries a different host's common name, and its leaves
/// would attest under that host's name. With a path length of zero the server's own chain
/// validation refuses such a chain, and the name a leaf attests under is the bundle CA's.
/// `cn` is only for the message.
fn refuse_unconfined_ca(cert: &Certificate, cn: &str) -> Result<(), SpireError> {
    match cert.tbs_certificate().get_extension::<BasicConstraints>() {
        Ok(Some((_, bc))) if bc.ca && bc.path_len_constraint == Some(0) => Ok(()),
        Ok(Some((_, bc))) if bc.ca => Err(SpireError::Invalid(format!(
            "CA {cn:?} may sign further CAs; its path length constraint must be 0"
        ))),
        Ok(_) => Err(SpireError::Invalid(format!(
            "certificate {cn:?} is not a CA (basicConstraints with cA true is required)"
        ))),
        Err(e) => Err(SpireError::Invalid(format!(
            "certificate {cn:?}: basicConstraints does not parse: {e}"
        ))),
    }
}

fn parse_certs(pem: &str) -> Result<Vec<Certificate>, SpireError> {
    let certs = Certificate::load_pem_chain(pem.as_bytes())
        .map_err(|e| SpireError::Invalid(format!("CA bundle: {e}")))?;
    if certs.is_empty() {
        return Err(SpireError::Invalid("CA bundle holds no certificate".into()));
    }
    Ok(certs)
}

/// Common names of every CA in a PEM bundle, in order (ADR-0049 decision 2).
pub fn ca_bundle_common_names(pem: &str) -> Result<Vec<String>, SpireError> {
    parse_certs(pem)?.iter().map(common_name_of).collect()
}

/// Refuse a bundle in which two CAs share a common name, any name that cannot be an
/// agent-ID segment, or any member that is not a CA with a path length of zero
/// ([`refuse_unconfined_ca`]). The agent ID is issuer-qualified, so a duplicate, or a CA
/// that can make another CA under any name, removes the confinement (ADR-0049 decision 2).
/// The error names the certificate.
pub fn refuse_duplicate_common_names(pem: &str) -> Result<(), SpireError> {
    let mut seen = BTreeSet::new();
    for cert in parse_certs(pem)? {
        let cn = common_name_of(&cert)?;
        validate_common_name(&cn)?;
        refuse_unconfined_ca(&cert, &cn)?;
        if !seen.insert(cn.clone()) {
            return Err(SpireError::Invalid(format!(
                "two CAs in the bundle share the common name {cn:?}; every CA needs a unique one"
            )));
        }
    }
    Ok(())
}

/// Common name of a host's signing CA: the PEM must hold exactly one certificate
/// (`Provider.spec.attestation.hostCa` is a single certificate), and it must be a CA with
/// a path length of zero ([`refuse_unconfined_ca`]): no node entry is rendered under the
/// name of a CA that could hand that name's standing to another.
pub fn host_ca_common_name(pem: &str) -> Result<String, SpireError> {
    let certs = parse_certs(pem)?;
    match <[Certificate; 1]>::try_from(certs) {
        Ok([cert]) => {
            let cn = common_name_of(&cert)?;
            refuse_unconfined_ca(&cert, &cn)?;
            Ok(cn)
        }
        Err(all) => Err(SpireError::Invalid(format!(
            "host CA must be exactly one certificate, found {}",
            all.len()
        ))),
    }
}

impl X509popInput {
    /// The explicit x509pop attestation this input describes; both names are validated.
    pub fn attestation(&self) -> Result<NodeAttestation, SpireError> {
        let issuer_cn = host_ca_common_name(&self.host_ca_pem)?;
        validate_common_name(&issuer_cn)?;
        validate_common_name(&self.attestation_subject)?;
        Ok(NodeAttestation::X509pop {
            issuer_cn,
            subject_cn: self.attestation_subject.clone(),
        })
    }
}

/// The agent ID the attestation gives the in-guest SPIRE agent: the parent of its node entry.
pub fn agent_id_for(naming: &Naming, att: &NodeAttestation) -> Result<String, SpireError> {
    match att {
        NodeAttestation::Tpm { ek_hash } => {
            validate_ek_hash(ek_hash)?;
            Ok(naming.agent_id(ek_hash))
        }
        NodeAttestation::X509pop {
            issuer_cn,
            subject_cn,
        } => x509pop_agent_id(&naming.trust_domain, issuer_cn, subject_cn),
    }
}

/// The 64 lowercase hex key the node's SPIFFE ID and entry name derive from, so the ADR-0006
/// shapes and the admission policy stay as they are. A TPM node's is its EK hash. An x509pop
/// node has no EK: its key is the hex SHA-256 of its agent ID.
///
/// ADR-0049 decision 7 records this rule, and decision 8 what rests on it: the broker's node
/// registration derives the key from the attestation the guest sends with this function and
/// requires the peer's SPIFFE ID to be `banlieue/node/<that key>`, so the names a guest sends
/// must hash to the ID SPIRE issued it under the entry the watcher declared, with this same
/// function, for exactly those names. One function on both sides; a different rule is a
/// change here and nowhere else.
pub fn node_key(naming: &Naming, att: &NodeAttestation) -> Result<String, SpireError> {
    match att {
        NodeAttestation::Tpm { ek_hash } => {
            validate_ek_hash(ek_hash)?;
            Ok(ek_hash.clone())
        }
        NodeAttestation::X509pop { .. } => {
            let id = agent_id_for(naming, att)?;
            Ok(hex::encode(Sha256::digest(id.as_bytes())))
        }
    }
}

/// A node as an entry is parented to it: its key (what names its record, its node entry and
/// its SPIFFE ID) and the agent ID SPIRE gave its agent. Built from an attestation
/// ([`Self::of`]) or from a stored record ([`Self::stored`]); the agent ID is never
/// recomputed from the key, because only a TPM node's can be (ADR-0049 decision 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    /// The node key: 64 lowercase hex. A TPM node's EK hash, an x509pop node's
    /// [`node_key`].
    pub key: String,
    /// The SPIRE agent's SPIFFE ID, the parent of every entry on the node.
    pub agent_id: String,
}

impl NodeIdentity {
    /// The identity an attestation gives, with the one pair of functions the watcher and
    /// the broker share.
    ///
    /// # Errors
    /// The attestation is invalid: nothing is derived from it.
    pub fn of(naming: &Naming, att: &NodeAttestation) -> Result<Self, SpireError> {
        Ok(Self {
            key: node_key(naming, att)?,
            agent_id: agent_id_for(naming, att)?,
        })
    }

    /// The identity a stored node record carries (`NodeRecord.ek_hash` is the key,
    /// `NodeRecord.node_id` the agent ID). Not validated here: [`Self::validate`] is, by
    /// every entry manager, before anything is declared under it.
    #[must_use]
    pub fn stored(key: &str, agent_id: &str) -> Self {
        Self {
            key: key.to_owned(),
            agent_id: agent_id.to_owned(),
        }
    }

    /// Refuse an identity an entry must not be parented to. The agent ID must be, in
    /// `trust_domain`, `spire/agent/tpm/<64 hex>` or `spire/agent/x509pop/<cn>/<cn>` and
    /// nothing else (no third segment, no other attestor, no other trust domain), and the
    /// key must be the one that agent ID gives: the hash itself for a TPM agent, the
    /// SHA-256 of the ID for an x509pop one. `trust_domain` of `None` accepts any single
    /// trust domain (the in-memory fake built without one).
    ///
    /// # Errors
    /// [`SpireError::Invalid`], naming the rule broken and never the whole identity.
    pub fn validate(&self, trust_domain: Option<&str>) -> Result<(), SpireError> {
        validate_node_key(&self.key)?;
        let invalid = |why: &str| SpireError::Invalid(format!("agent ID: {why}"));
        let rest = self
            .agent_id
            .strip_prefix("spiffe://")
            .ok_or_else(|| invalid("not a SPIFFE ID"))?;
        let (td, path) = rest
            .split_once('/')
            .ok_or_else(|| invalid("no path after the trust domain"))?;
        if td.is_empty() || trust_domain.is_some_and(|want| want != td) {
            return Err(invalid("not in this trust domain"));
        }
        if let Some(hash) = path
            .strip_prefix(TPM_AGENT_PREFIX)
            .and_then(|p| p.strip_prefix('/'))
        {
            validate_ek_hash(hash)?;
            if hash != self.key {
                return Err(invalid("a tpm agent's hash is not the node key"));
            }
            return Ok(());
        }
        let Some(names) = path
            .strip_prefix(X509POP_AGENT_PREFIX)
            .and_then(|p| p.strip_prefix('/'))
        else {
            return Err(invalid(
                "neither spire/agent/tpm/<hash> nor spire/agent/x509pop/<issuer>/<subject>",
            ));
        };
        let mut segments = names.split('/');
        let (Some(issuer), Some(subject), None) =
            (segments.next(), segments.next(), segments.next())
        else {
            return Err(invalid(
                "an x509pop agent ID has exactly an issuer and a subject segment",
            ));
        };
        validate_common_name(issuer)?;
        validate_common_name(subject)?;
        if hex::encode(Sha256::digest(self.agent_id.as_bytes())) != self.key {
            return Err(invalid(
                "the node key is not the SHA-256 of this x509pop agent ID",
            ));
        }
        Ok(())
    }
}

/// Whether a SPIFFE ID is under the x509pop attestor's agent path (in any trust domain).
/// Only the path is read: a pass that must leave every x509pop node alone asks this, and
/// errs towards leaving one alone.
#[must_use]
pub fn is_x509pop_agent_id(agent_id: &str) -> bool {
    agent_id
        .strip_prefix("spiffe://")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(_, path)| path.starts_with(&format!("{X509POP_AGENT_PREFIX}/")))
}

/// Every certificate of a PEM as its one common name and the hex SHA-256 of its DER: what
/// tells two assertions of one host CA (the same certificate twice) from two CAs under one
/// name. Nothing about the certificates is checked beyond their having one common name.
///
/// # Errors
/// The PEM holds no certificate, one does not parse, or one has no single common name.
pub fn certificate_identities(pem: &str) -> Result<Vec<(String, String)>, SpireError> {
    parse_certs(pem)?
        .iter()
        .map(|cert| {
            let der = cert
                .to_der()
                .map_err(|e| SpireError::Invalid(format!("certificate: {e}")))?;
            Ok((common_name_of(cert)?, hex::encode(Sha256::digest(der))))
        })
        .collect()
}

/// The node key of the node whose agent has this SPIFFE ID, when the ID is one of the two
/// agent shapes (in any one trust domain): the hash a tpm agent's ID ends with, or the
/// SHA-256 of an x509pop agent's whole ID. `None` for anything else. The inverse of
/// [`agent_id_for`] as far as [`node_key`] needs it: what lets a pass that holds only agent
/// IDs (a claim's `node_id`, an entry's parent) name the nodes they belong to.
#[must_use]
pub fn node_key_of_agent_id(agent_id: &str) -> Option<String> {
    let (_, path) = agent_id.strip_prefix("spiffe://")?.split_once('/')?;
    let tpm_hash = path
        .strip_prefix(TPM_AGENT_PREFIX)
        .and_then(|p| p.strip_prefix('/'));
    let key = match tpm_hash {
        Some(hash) => hash.to_owned(),
        None if path.starts_with(X509POP_AGENT_PREFIX) => {
            hex::encode(Sha256::digest(agent_id.as_bytes()))
        }
        None => return None,
    };
    NodeIdentity::stored(&key, agent_id)
        .validate(None)
        .is_ok()
        .then_some(key)
}

/// The node bootstrap entry for an attestation, in the ADR-0006 shape: its resource name and
/// spec, parented to the attestation's agent ID. Nothing is rendered for an invalid input.
pub fn node_entry_spec(
    naming: &Naming,
    att: &NodeAttestation,
    class_name: &str,
) -> Result<(String, ClusterStaticEntrySpec), SpireError> {
    let key = node_key(naming, att)?;
    let spec = ClusterStaticEntrySpec {
        spiffe_id: naming.node_id(&key),
        parent_id: agent_id_for(naming, att)?,
        selectors: vec!["unix:uid:0".into(), format!("unix:path:{GUEST_AGENT_PATH}")],
        class_name: Some(class_name.to_owned()),
        x509_svid_ttl: None,
        hint: Some("node".into()),
    };
    Ok((node_entry_name(&key), spec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    const TD: &str = "sandbox.test";

    /// A host CA as ADR-0049 decision 2 needs it: a CA that may sign no further CA.
    fn ca_pem(cn: &str) -> String {
        cert_pem(cn, IsCa::Ca(BasicConstraints::Constrained(0)))
    }

    /// A self-signed certificate named `cn` with the given `basicConstraints`.
    fn cert_pem(cn: &str, is_ca: IsCa) -> String {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        p.distinguished_name = dn;
        p.is_ca = is_ca;
        let key = KeyPair::generate().unwrap();
        p.self_signed(&key).unwrap().pem()
    }

    /// The shapes that are not a host CA: one that may sign further CAs (no path length,
    /// or one above zero), and a certificate that is no CA at all (the extension saying so,
    /// or absent).
    fn not_host_cas(cn: &str) -> [String; 4] {
        [
            cert_pem(cn, IsCa::Ca(BasicConstraints::Unconstrained)),
            cert_pem(cn, IsCa::Ca(BasicConstraints::Constrained(1))),
            cert_pem(cn, IsCa::ExplicitNoCa),
            cert_pem(cn, IsCa::NoCa),
        ]
    }

    #[test]
    fn a_bundle_ca_that_may_sign_further_cas_or_is_no_ca_is_refused() {
        // ADR-0049 decision 2 rests on a CA minting IDs under its own name alone. The
        // server names an agent after its leaf's immediate issuer, so a CA free to sign a
        // CA could sign one carrying another host's name.
        for refused in not_host_cas("host-b") {
            let pem = format!("{}{refused}", ca_pem("host-a"));
            let err = refuse_duplicate_common_names(&pem).unwrap_err().to_string();
            assert!(err.contains("host-b"), "the refusal names the CA: {err}");
        }
        refuse_duplicate_common_names(&bundle(&["host-a", "host-b"])).unwrap();
    }

    #[test]
    fn a_host_ca_that_may_sign_further_cas_or_is_no_ca_gives_no_attestation() {
        for refused in not_host_cas("host-a") {
            assert!(host_ca_common_name(&refused).is_err());
            let input = X509popInput {
                host_ca_pem: refused,
                attestation_subject: "vm-1".into(),
            };
            assert!(
                input.attestation().is_err(),
                "no node entry for such a host"
            );
        }
        assert_eq!(host_ca_common_name(&ca_pem("host-a")).unwrap(), "host-a");
    }

    fn bundle(cns: &[&str]) -> String {
        cns.iter().map(|c| ca_pem(c)).collect()
    }

    #[test]
    fn agent_id_is_issuer_then_subject_under_the_x509pop_prefix() {
        assert_eq!(
            x509pop_agent_id(TD, "host-a.ca", "3f2a_b.c-1").unwrap(),
            "spiffe://sandbox.test/spire/agent/x509pop/host-a.ca/3f2a_b.c-1"
        );
    }

    #[test]
    fn a_common_name_outside_the_path_segment_alphabet_is_refused() {
        for bad in [
            "", "a/b", "a b", "a:b", "a@b", "a%2fb", "a\u{e9}", "a\nb", "a?b", "a#b", ".", "..",
            "*",
        ] {
            assert!(validate_common_name(bad).is_err(), "{bad:?} accepted");
            assert!(x509pop_agent_id(TD, bad, "ok").is_err(), "issuer {bad:?}");
            assert!(x509pop_agent_id(TD, "ok", bad).is_err(), "subject {bad:?}");
        }
    }

    #[test]
    fn the_length_limit_is_inclusive() {
        let at = "a".repeat(MAX_COMMON_NAME_LEN);
        let over = "a".repeat(MAX_COMMON_NAME_LEN + 1);
        assert!(validate_common_name(&at).is_ok());
        assert!(validate_common_name(&over).is_err());
    }

    #[test]
    fn an_empty_trust_domain_is_refused() {
        assert!(x509pop_agent_id("", "a", "b").is_err());
    }

    #[test]
    fn bundle_common_names_are_listed_in_order() {
        let names = ca_bundle_common_names(&bundle(&["host-a", "host-b", "host-c"])).unwrap();
        assert_eq!(names, ["host-a", "host-b", "host-c"]);
    }

    #[test]
    fn garbage_and_an_empty_bundle_are_errors() {
        assert!(ca_bundle_common_names("not a pem").is_err());
        assert!(ca_bundle_common_names("").is_err());
        assert!(
            ca_bundle_common_names(
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
            )
            .is_err()
        );
    }

    #[test]
    fn a_ca_with_no_common_name_is_refused() {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        // rcgen's default subject carries a common name; an empty one is the case under test.
        p.distinguished_name = DistinguishedName::new();
        let key = KeyPair::generate().unwrap();
        let pem = p.self_signed(&key).unwrap().pem();
        assert!(ca_bundle_common_names(&pem).is_err());
    }

    #[test]
    fn unique_names_pass() {
        refuse_duplicate_common_names(&bundle(&["host-a", "host-b"])).unwrap();
    }

    #[test]
    fn a_duplicate_is_refused_and_named() {
        let err = refuse_duplicate_common_names(&bundle(&["host-a", "host-b", "host-a"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("host-a"), "{err}");
        assert!(!err.contains("host-b"), "{err}");
    }

    #[test]
    fn two_different_keys_with_one_name_is_still_a_duplicate() {
        // The confinement is by name, not by key: same CN, different CA, no confinement.
        assert!(refuse_duplicate_common_names(&bundle(&["same", "same"])).is_err());
    }

    #[test]
    fn a_bundle_member_that_cannot_be_an_agent_id_segment_is_refused() {
        assert!(refuse_duplicate_common_names(&bundle(&["host a"])).is_err());
    }

    fn naming() -> Naming {
        Naming {
            trust_domain: TD.into(),
        }
    }

    const EK: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";

    fn x509() -> NodeAttestation {
        NodeAttestation::X509pop {
            issuer_cn: "host-a".into(),
            subject_cn: "uid-1".into(),
        }
    }

    #[test]
    fn host_ca_common_name_takes_exactly_one_certificate() {
        assert_eq!(host_ca_common_name(&ca_pem("host-a")).unwrap(), "host-a");
        assert!(host_ca_common_name(&bundle(&["a", "b"])).is_err());
        assert!(host_ca_common_name("").is_err());
    }

    #[test]
    fn input_becomes_an_x509pop_attestation() {
        let input = X509popInput {
            host_ca_pem: ca_pem("host-a"),
            attestation_subject: "uid-1".into(),
        };
        assert_eq!(input.attestation().unwrap(), x509());
        let bad = X509popInput {
            host_ca_pem: ca_pem("host-a"),
            attestation_subject: "a/b".into(),
        };
        assert!(bad.attestation().is_err());
    }

    #[test]
    fn tpm_entry_keeps_the_adr_0006_shape() {
        let (name, spec) = node_entry_spec(
            &naming(),
            &NodeAttestation::Tpm { ek_hash: EK.into() },
            "cls",
        )
        .unwrap();
        assert_eq!(name, crate::node_entry_name(EK));
        assert_eq!(spec.spiffe_id, naming().node_id(EK));
        assert_eq!(spec.parent_id, naming().agent_id(EK));
        assert_eq!(
            spec.selectors,
            [
                "unix:uid:0".to_owned(),
                format!("unix:path:{}", crate::GUEST_AGENT_PATH)
            ]
        );
        assert_eq!(spec.class_name.as_deref(), Some("cls"));
        assert_eq!(spec.hint.as_deref(), Some("node"));
        assert_eq!(spec.x509_svid_ttl, None);
    }

    #[test]
    fn x509pop_entry_is_parented_to_the_x509pop_agent() {
        let (name, spec) = node_entry_spec(&naming(), &x509(), "cls").unwrap();
        let key = node_key(&naming(), &x509()).unwrap();
        assert_eq!(
            spec.parent_id,
            "spiffe://sandbox.test/spire/agent/x509pop/host-a/uid-1"
        );
        assert_eq!(spec.spiffe_id, naming().node_id(&key));
        assert_eq!(name, crate::node_entry_name(&key));
        assert_eq!(spec.selectors.len(), 2);
        assert_eq!(spec.hint.as_deref(), Some("node"));
    }

    #[test]
    fn node_key_has_the_admission_shape_and_is_deterministic() {
        let k = node_key(&naming(), &x509()).unwrap();
        assert!(mediatore_proto::ek::is_ek_hash(&k));
        assert_eq!(k, node_key(&naming(), &x509()).unwrap());
        let other = NodeAttestation::X509pop {
            issuer_cn: "host-b".into(),
            subject_cn: "uid-1".into(),
        };
        assert_ne!(k, node_key(&naming(), &other).unwrap());
        assert_eq!(
            node_key(&naming(), &NodeAttestation::Tpm { ek_hash: EK.into() }).unwrap(),
            EK
        );
    }

    #[test]
    fn invalid_attestations_render_nothing() {
        let bad_tpm = NodeAttestation::Tpm {
            ek_hash: "3f9a".into(),
        };
        assert!(node_entry_spec(&naming(), &bad_tpm, "c").is_err());
        let bad_x = NodeAttestation::X509pop {
            issuer_cn: "a b".into(),
            subject_cn: "ok".into(),
        };
        assert!(node_entry_spec(&naming(), &bad_x, "c").is_err());
        assert!(agent_id_for(&naming(), &bad_x).is_err());
    }

    #[test]
    fn a_wire_attestation_becomes_the_same_attestation_the_watcher_builds() {
        let wire = mediatore_proto::Attestation::X509pop {
            issuer_cn: "host-a".into(),
            subject_cn: "uid-1".into(),
        };
        assert_eq!(NodeAttestation::from(&wire), x509());
        let wire = mediatore_proto::Attestation::Tpm { ek_hash: EK.into() };
        assert_eq!(
            NodeAttestation::from(&wire),
            NodeAttestation::Tpm { ek_hash: EK.into() }
        );
    }

    #[test]
    fn an_identity_from_an_attestation_validates_and_carries_both_derivations() {
        let tpm =
            NodeIdentity::of(&naming(), &NodeAttestation::Tpm { ek_hash: EK.into() }).unwrap();
        assert_eq!(tpm.key, EK);
        assert_eq!(tpm.agent_id, naming().agent_id(EK));
        assert!(!is_x509pop_agent_id(&tpm.agent_id));
        tpm.validate(Some(TD)).unwrap();
        tpm.validate(None).unwrap();
        let x = NodeIdentity::of(&naming(), &x509()).unwrap();
        assert_eq!(x.key, node_key(&naming(), &x509()).unwrap());
        assert_eq!(
            x.agent_id,
            "spiffe://sandbox.test/spire/agent/x509pop/host-a/uid-1"
        );
        assert!(is_x509pop_agent_id(&x.agent_id));
        x.validate(Some(TD)).unwrap();
        x.validate(None).unwrap();
        assert!(
            NodeIdentity::of(
                &naming(),
                &NodeAttestation::Tpm {
                    ek_hash: "3f9a".into()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn an_identity_whose_agent_id_is_not_one_of_the_two_shapes_is_refused() {
        let x = NodeIdentity::of(&naming(), &x509()).unwrap();
        let key_of = |id: &str| hex::encode(Sha256::digest(id.as_bytes()));
        let refused = |key: &str, agent_id: &str| {
            NodeIdentity::stored(key, agent_id)
                .validate(Some(TD))
                .is_err()
        };
        // Another trust domain, for both shapes.
        assert!(refused(
            EK,
            &format!("spiffe://other.test/spire/agent/tpm/{EK}")
        ));
        let foreign = "spiffe://other.test/spire/agent/x509pop/host-a/uid-1";
        assert!(refused(&key_of(foreign), foreign));
        // A tpm agent whose hash is not the key, or not a hash.
        assert!(refused(&"ab".repeat(32), &naming().agent_id(EK)));
        assert!(refused(EK, "spiffe://sandbox.test/spire/agent/tpm/3f9a"));
        // An x509pop agent with one segment, three, an empty one, a bad character.
        for path in [
            "host-a",
            "host-a/uid-1/extra",
            "host-a/",
            "/uid-1",
            "host a/uid-1",
            "host-a/uid:1",
            "../uid-1",
        ] {
            let id = format!("spiffe://sandbox.test/spire/agent/x509pop/{path}");
            assert!(
                refused(&key_of(&id), &id),
                "a malformed x509pop path was accepted"
            );
        }
        // The key is not the hash of the agent ID.
        assert!(refused(EK, &x.agent_id));
        // Another attestor, the server, a node ID, not a SPIFFE ID, and a key that is no key.
        for id in [
            "spiffe://sandbox.test/spire/agent/join_token/abc",
            "spiffe://sandbox.test/spire/server",
            "spiffe://sandbox.test/spire/agent/tpm",
            "spiffe://sandbox.test",
            "https://sandbox.test/spire/agent/x509pop/host-a/uid-1",
            "",
        ] {
            assert!(
                refused(&key_of(id), id),
                "an ID that is no agent's was accepted"
            );
            assert!(refused(EK, id), "an ID that is no agent's was accepted");
        }
        assert!(refused(&naming().node_id(EK), &naming().node_id(EK)));
        assert!(refused("ek1", &naming().agent_id("ek1")));
        // Without a trust domain to hold it to, the shape and the key still decide.
        assert!(
            NodeIdentity::stored(&key_of(foreign), foreign)
                .validate(None)
                .is_ok()
        );
        assert!(
            NodeIdentity::stored(EK, &x.agent_id)
                .validate(None)
                .is_err()
        );
        assert!(
            NodeIdentity::stored(EK, "spiffe:///spire/agent/tpm/x")
                .validate(None)
                .is_err()
        );
    }

    #[test]
    fn the_node_key_of_an_agent_id_is_the_one_its_attestation_gives() {
        for att in [NodeAttestation::Tpm { ek_hash: EK.into() }, x509()] {
            let id = NodeIdentity::of(&naming(), &att).unwrap();
            assert_eq!(node_key_of_agent_id(&id.agent_id), Some(id.key));
        }
        for not_an_agent in [
            "spiffe://sandbox.test/spire/agent/tpm/3f9a",
            "spiffe://sandbox.test/spire/agent/x509pop/host-a",
            "spiffe://sandbox.test/spire/agent/x509pop/host-a/uid-1/extra",
            "spiffe://sandbox.test/spire/agent/join_token/abc",
            "spiffe://sandbox.test/spire/server",
            "spiffe://sandbox.test/banlieue/node/abc",
            "node-a",
            "",
        ] {
            assert_eq!(node_key_of_agent_id(not_an_agent), None);
        }
    }

    #[test]
    fn a_certificate_is_told_from_another_of_the_same_name_by_its_fingerprint() {
        let a = ca_pem("host-a");
        let again = ca_pem("host-a");
        let ids = certificate_identities(&format!("{a}{again}{a}")).unwrap();
        assert_eq!(ids.len(), 3);
        assert!(ids.iter().all(|(cn, _)| cn == "host-a"));
        assert_eq!(
            ids[0].1, ids[2].1,
            "the same certificate, the same fingerprint"
        );
        assert_ne!(
            ids[0].1, ids[1].1,
            "another key under the name, another one"
        );
        assert!(certificate_identities("").is_err());
        assert!(certificate_identities("not a pem").is_err());
    }

    #[test]
    fn only_an_id_under_the_x509pop_agent_path_is_an_x509pop_agents() {
        assert!(is_x509pop_agent_id(
            "spiffe://sandbox.test/spire/agent/x509pop/host-a/uid-1"
        ));
        for other in [
            "spiffe://sandbox.test/spire/agent/tpm/abc",
            "spiffe://sandbox.test/spire/agent/x509pop",
            "spiffe://sandbox.test/banlieue/node/x509pop/a/b",
            "spire/agent/x509pop/a/b",
            "",
        ] {
            assert!(!is_x509pop_agent_id(other));
        }
    }
}
