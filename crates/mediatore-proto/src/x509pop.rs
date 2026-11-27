// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The names an `x509pop` node attests under (ADR-0049 decisions 2 and 8): the common name
//! of a certificate's subject and of its issuer, and the alphabet both must stay in.
//!
//! One place for both sides. The broker's watcher reads a host CA's subject common name to
//! declare a node entry, the guest reads its own leaf's issuer and subject common names to
//! say which node it is, and the two must agree byte for byte or the names the guest sends
//! do not hash to the identity SPIRE issued it.

use x509_cert::Certificate;
use x509_cert::der::asn1::{PrintableStringRef, Utf8StringRef};
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::name::Name;

/// `id-at-commonName` (2.5.4.3).
const COMMON_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// Longest common name accepted (X.509 `ub-common-name`).
pub const MAX_COMMON_NAME_LEN: usize = 64;

/// Why a common name, or the certificate it was read from, cannot name an `x509pop` agent.
/// No variant carries certificate bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommonNameError {
    /// Empty, or longer than [`MAX_COMMON_NAME_LEN`].
    #[error("common name must be 1 to {MAX_COMMON_NAME_LEN} characters")]
    Length,
    /// `.` or `..`, which SPIFFE forbids as a path segment.
    #[error("common name must not be . or ..")]
    Dots,
    /// A character outside the path-segment alphabet.
    #[error("common name may hold only letters, digits, dots, dashes and underscores")]
    Alphabet,
    /// The name's common name attribute is not a UTF-8 or printable string.
    #[error("common name is not text: {0}")]
    NotText(String),
    /// Zero common names, or more than one: the server's template reads one, and a second
    /// would make the agent ID ambiguous.
    #[error("exactly one common name is required, found {0}")]
    Count(usize),
    /// The PEM holds no certificate, or does not parse.
    #[error("certificate: {0}")]
    Parse(String),
}

/// Refuse a common name that is not a SPIFFE path segment: non-empty, at most
/// [`MAX_COMMON_NAME_LEN`] bytes, letters, digits, dots, dashes and underscores only, and
/// neither `.` nor `..` (SPIFFE forbids those segments).
///
/// # Errors
/// [`CommonNameError::Length`], [`CommonNameError::Dots`] or [`CommonNameError::Alphabet`].
pub fn validate_common_name(cn: &str) -> Result<(), CommonNameError> {
    if cn.is_empty() || cn.len() > MAX_COMMON_NAME_LEN {
        return Err(CommonNameError::Length);
    }
    if cn == "." || cn == ".." {
        return Err(CommonNameError::Dots);
    }
    let allowed = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_');
    if !cn.bytes().all(allowed) {
        return Err(CommonNameError::Alphabet);
    }
    Ok(())
}

/// The one common name of a distinguished name; zero or several is refused. Not validated
/// against the alphabet: the caller decides what an unusable name means.
///
/// # Errors
/// [`CommonNameError::Count`] or [`CommonNameError::NotText`].
pub fn single_common_name(name: &Name) -> Result<String, CommonNameError> {
    let mut found = Vec::new();
    for atv in name.iter() {
        if atv.oid != COMMON_NAME_OID {
            continue;
        }
        let text = atv
            .value
            .decode_as::<Utf8StringRef<'_>>()
            .map(|v| v.as_str().to_owned())
            .or_else(|_| {
                atv.value
                    .decode_as::<PrintableStringRef<'_>>()
                    .map(|v| v.as_str().to_owned())
            })
            .map_err(|e| CommonNameError::NotText(e.to_string()))?;
        found.push(text);
    }
    match <[String; 1]>::try_from(found) {
        Ok([cn]) => Ok(cn),
        Err(all) => Err(CommonNameError::Count(all.len())),
    }
}

/// The issuer and subject common names of a leaf certificate, as the SPIRE server's
/// `agent_path_template` reads them (`.Issuer.CommonName`, `.Subject.CommonName`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafNames {
    /// Common name of the leaf's immediate issuer: the host's signing CA.
    pub issuer_cn: String,
    /// Common name of the leaf's subject: what the host's signer set.
    pub subject_cn: String,
}

/// The names of the **first** certificate in `pem`: the file `mediatore node-cert` writes is
/// the leaf followed by its chain (ADR-0049 decision 6), and the agent attests with the
/// leaf. Each side must carry exactly one common name, inside the alphabet.
///
/// # Errors
/// [`CommonNameError`]: no certificate, an unparsable one, or a name that cannot be a
/// segment of the agent ID.
pub fn leaf_common_names(pem: &[u8]) -> Result<LeafNames, CommonNameError> {
    let certs =
        Certificate::load_pem_chain(pem).map_err(|e| CommonNameError::Parse(e.to_string()))?;
    let leaf = certs
        .first()
        .ok_or_else(|| CommonNameError::Parse("no certificate in the file".into()))?;
    let tbs = leaf.tbs_certificate();
    let issuer_cn = single_common_name(tbs.issuer())?;
    validate_common_name(&issuer_cn)?;
    let subject_cn = single_common_name(tbs.subject())?;
    validate_common_name(&subject_cn)?;
    Ok(LeafNames {
        issuer_cn,
        subject_cn,
    })
}

#[cfg(test)]
mod tests {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    };

    use super::*;

    fn named(cns: &[&str]) -> CertificateParams {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = DistinguishedName::new();
        for cn in cns {
            dn.push(DnType::CommonName, *cn);
        }
        p.distinguished_name = dn;
        p
    }

    /// A leaf with the subject common names `subject`, signed by a CA named `issuer`, and
    /// that CA: both as PEM.
    fn leaf_and_ca(issuer: &str, subject: &[&str]) -> (String, String) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = named(&[issuer]);
        ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let ca_pem = ca.clone().self_signed(&ca_key).unwrap().pem();
        let signer = Issuer::new(ca, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = named(subject).signed_by(&leaf_key, &signer).unwrap().pem();
        (leaf, ca_pem)
    }

    #[test]
    fn the_leafs_issuer_and_subject_common_names_are_read_from_the_first_certificate() {
        let (leaf, ca) = leaf_and_ca("hv-01", &["3f0c2a"]);
        let want = LeafNames {
            issuer_cn: "hv-01".into(),
            subject_cn: "3f0c2a".into(),
        };
        assert_eq!(leaf_common_names(leaf.as_bytes()).unwrap(), want);
        // The leaf followed by its chain, as node-cert writes it: the leaf is what counts.
        let bundle = format!("{leaf}{ca}");
        assert_eq!(leaf_common_names(bundle.as_bytes()).unwrap(), want);
        // The chain first is another certificate's names: the CA is its own issuer.
        let reversed = format!("{ca}{leaf}");
        assert_eq!(
            leaf_common_names(reversed.as_bytes()).unwrap().subject_cn,
            "hv-01"
        );
    }

    #[test]
    fn a_leaf_with_no_common_name_is_refused_and_so_is_a_name_with_two() {
        let (none, _) = leaf_and_ca("hv-01", &[]);
        assert_eq!(
            leaf_common_names(none.as_bytes()),
            Err(CommonNameError::Count(0))
        );
        // rcgen keeps one attribute per type, so the two-name case is a name built directly.
        let two: Name = "CN=a,CN=b".parse().unwrap();
        assert_eq!(single_common_name(&two), Err(CommonNameError::Count(2)));
        let one: Name = "O=example,CN=a".parse().unwrap();
        assert_eq!(single_common_name(&one).as_deref(), Ok("a"));
    }

    #[test]
    fn a_name_outside_the_alphabet_on_either_side_is_refused() {
        let (bad_subject, _) = leaf_and_ca("hv-01", &["a/b"]);
        assert_eq!(
            leaf_common_names(bad_subject.as_bytes()),
            Err(CommonNameError::Alphabet)
        );
        let (bad_issuer, _) = leaf_and_ca("hv 01", &["vm-1"]);
        assert_eq!(
            leaf_common_names(bad_issuer.as_bytes()),
            Err(CommonNameError::Alphabet)
        );
    }

    #[test]
    fn an_empty_file_and_garbage_are_parse_errors() {
        for bad in [
            "",
            "not a pem",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        ] {
            assert!(
                matches!(
                    leaf_common_names(bad.as_bytes()),
                    Err(CommonNameError::Parse(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_alphabet_the_length_and_the_dot_segments() {
        for ok in ["a", "hv-01", "host_a.ca", &"a".repeat(MAX_COMMON_NAME_LEN)] {
            assert_eq!(validate_common_name(ok), Ok(()), "{ok}");
        }
        assert_eq!(validate_common_name(""), Err(CommonNameError::Length));
        assert_eq!(
            validate_common_name(&"a".repeat(MAX_COMMON_NAME_LEN + 1)),
            Err(CommonNameError::Length)
        );
        assert_eq!(validate_common_name("."), Err(CommonNameError::Dots));
        assert_eq!(validate_common_name(".."), Err(CommonNameError::Dots));
        for bad in ["a/b", "a b", "a:b", "a\u{e9}", "a\nb", "*"] {
            assert_eq!(
                validate_common_name(bad),
                Err(CommonNameError::Alphabet),
                "{bad:?}"
            );
        }
    }
}
