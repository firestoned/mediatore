// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! From a vTPM endorsement-key certificate to the hash the SPIRE tpm attestor puts in the
//! agent ID (ADR-0006 decision 4).
//!
//! `bloomberg/spire-tpm-plugin` names an attested agent
//! `spiffe://<td>/spire/agent/tpm/<hex sha256 of the EK public key in PKIX DER>`; the
//! PKIX DER of a public key is the certificate's `SubjectPublicKeyInfo`. `mediatore-guest`
//! computes the same value with `openssl pkey -pubin -outform der | sha256sum`, and
//! banlieue publishes the certificate on `VirtualMachine.status.tpmEndorsementCertificates`
//! (banlieue ADR-0045), so the broker can name a node's agent before it attests.

use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::{DecodePem, Encode};

/// `rsaEncryption`: the EK the guest creates (`tpm2_createek -G rsa`) and the one a TPM
/// carries at NV index `0x01c00002`.
const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";

/// Why a certificate did not yield an EK hash.
#[derive(Debug, thiserror::Error)]
pub enum EkError {
    /// Not a PEM-encoded X.509 certificate.
    #[error("ek certificate: {0}")]
    Parse(String),
    /// None of the published certificates carries an RSA public key.
    #[error("no RSA endorsement-key certificate among {0} published")]
    NoRsaCertificate(usize),
}

/// True for the hash shape the attestor produces and the admission policy accepts: exactly
/// 64 lowercase hex characters.
#[must_use]
pub fn is_ek_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Hex SHA-256 of the certificate's `SubjectPublicKeyInfo` DER.
pub fn ek_hash_from_pem(pem: &str) -> Result<String, EkError> {
    let cert = Certificate::from_pem(pem.as_bytes()).map_err(|e| EkError::Parse(e.to_string()))?;
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| EkError::Parse(e.to_string()))?;
    Ok(hex::encode(Sha256::digest(spki)))
}

/// The agent-ID hash for a VM from everything banlieue published for it: the first
/// certificate whose key is RSA, matching the EK the guest attests with. A certificate that
/// does not parse is an error even if another one would do, because a corrupt status is not
/// something to guess around.
pub fn ek_hash_from_pems<S: AsRef<str>>(pems: &[S]) -> Result<String, EkError> {
    for pem in pems {
        let cert = Certificate::from_pem(pem.as_ref().as_bytes())
            .map_err(|e| EkError::Parse(e.to_string()))?;
        let spki = cert.tbs_certificate().subject_public_key_info();
        if spki.algorithm.oid.to_string() == RSA_ENCRYPTION_OID {
            let der = spki.to_der().map_err(|e| EkError::Parse(e.to_string()))?;
            return Ok(hex::encode(Sha256::digest(der)));
        }
    }
    Err(EkError::NoRsaCertificate(pems.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway self-signed certificates generated with openssl for this test. The expected
    // hashes come from the guest's exact pipeline on the same files:
    //   openssl x509 -in <pem> -pubkey -noout | openssl pkey -pubin -outform der | sha256sum
    const RSA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIUc1LZdJY2wxbquwgnAWadY8bLBZkwDQYJKoZIhvcNAQEL
BQAwJTEjMCEGA1UEAwwaYmFubGlldWUtZWstcHJvYmU6dGVzdC1yc2EwHhcNMjYx
MDEyMDg1NDUyWhcNMzYxMDA5MDg1NDUyWjAlMSMwIQYDVQQDDBpiYW5saWV1ZS1l
ay1wcm9iZTp0ZXN0LXJzYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AIJ8QlviTjX4SiU2hPOG0RYmSQaXAN9sLHuKlQ7KI6g3DEG+qpHoEt75u7Yt+W0c
tPNIJ//+14E6PXlQRVcC8yOVcxX0Gs0pim44CGQVEtIWXJ//sgiY9Sa64ZJ7iiKv
wZXIMHrpgjNANA3jk9m4yNLhTsqhibPKAqLYnlS+bKXiZa6fG46wE+R2rak3B8GB
9lRZ/0JClYdy2q/gfZ5t0bfutUCHdOycErBDodUACLjKN1cERxyF0EFHuI1QcsPl
rtuCBuO97et36hhR1uckdfIVw6tta/E3tjBz92X0zKk0Cd9Wt8ZXfYzyPXA2J2q0
LqUGXM+8gz+WJl2bHL3Nb8kCAwEAAaNTMFEwHQYDVR0OBBYEFFHIqZWt35p1rFkC
N/uRZ/uaNFhuMB8GA1UdIwQYMBaAFFHIqZWt35p1rFkCN/uRZ/uaNFhuMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEEWRy7q8v1i+5C8N+SnRPEf
gusVTvKEF4ZWaiIwqVcSvXLOdsL/fczL08Kxxh607du+L+VXj1sTgszj0VclH+lT
hErz04WbstUkk6zYNKramByijTzgMGaF8KIHdA5ES1yOJGqMDgXYOr4f067pKPYC
HcxKBwr/OD4n8rHkbnFb+ewr3cDRKawW9P8j7m/ZaCBd/gvK5VWc1wzZU4/LfNVG
YBrfxo85qxRvJtmEk9mIC3mYhhovOizbIsIzR5vRNrXoTM7WImz6X/Yf6eNLKvjz
lIAMzxQTSBKBz/W/dLdog/AKmdZMAGaUs9RUtV7trtK+nNkTgzuFHsz7Tbs8fWk=
-----END CERTIFICATE-----
";
    const RSA_HASH: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";

    const EC_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBnTCCAUOgAwIBAgIUCs6HcIgOQKl6IEMw3ygn8dLOUy0wCgYIKoZIzj0EAwIw
JDEiMCAGA1UEAwwZYmFubGlldWUtZWstcHJvYmU6dGVzdC1lYzAeFw0yNjEwMTIw
ODU0NTJaFw0zNjEwMDkwODU0NTJaMCQxIjAgBgNVBAMMGWJhbmxpZXVlLWVrLXBy
b2JlOnRlc3QtZWMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARZKLnB0v0Jt4Lb
NsvVE9rPeMuFY2OaNHjmE1A+fdq7uoJV65hhlKsx/vsCOmc426BxFzkMdwBpcOTr
BYBkf7SRo1MwUTAdBgNVHQ4EFgQU1yJVMLWP8kczcOkMZesDs5xbX5EwHwYDVR0j
BBgwFoAU1yJVMLWP8kczcOkMZesDs5xbX5EwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAgNIADBFAiEAtYXkF2NmepozsUbHGnpk7hD/YilFOgvlVLZbP2AWnJwC
IGr5jehpaR8RO6lR0tMn/zrjf/58sUIwrO0lkfUAJyQb
-----END CERTIFICATE-----
";
    const EC_HASH: &str = "dd8171d6e403c1e5215766fda87734ffdfd6fd18539cbd83d236140e029c1f5b";

    #[test]
    fn rsa_certificate_hashes_like_the_guest_and_the_attestor() {
        assert_eq!(ek_hash_from_pem(RSA_PEM).unwrap(), RSA_HASH);
    }

    #[test]
    fn ec_certificate_hashes_its_spki_too() {
        assert_eq!(ek_hash_from_pem(EC_PEM).unwrap(), EC_HASH);
    }

    #[test]
    fn hashes_have_the_admission_policy_shape() {
        assert!(is_ek_hash(RSA_HASH));
        assert!(is_ek_hash(EC_HASH));
        assert!(!is_ek_hash(&RSA_HASH[..63]));
        assert!(!is_ek_hash(&RSA_HASH.to_uppercase()));
        assert!(!is_ek_hash("3f9a"));
        assert!(!is_ek_hash(""));
    }

    #[test]
    fn garbage_is_an_error_not_a_hash() {
        assert!(matches!(
            ek_hash_from_pem("not a cert"),
            Err(EkError::Parse(_))
        ));
        assert!(matches!(
            ek_hash_from_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
            Err(EkError::Parse(_))
        ));
    }

    #[test]
    fn published_list_picks_the_rsa_ek() {
        assert_eq!(ek_hash_from_pems(&[EC_PEM, RSA_PEM]).unwrap(), RSA_HASH);
        assert_eq!(ek_hash_from_pems(&[RSA_PEM]).unwrap(), RSA_HASH);
    }

    #[test]
    fn published_list_without_rsa_fails_closed() {
        assert!(matches!(
            ek_hash_from_pems(&[EC_PEM]),
            Err(EkError::NoRsaCertificate(1))
        ));
        let none: [&str; 0] = [];
        assert!(matches!(
            ek_hash_from_pems(&none),
            Err(EkError::NoRsaCertificate(0))
        ));
    }

    #[test]
    fn a_corrupt_certificate_in_the_list_is_not_skipped() {
        assert!(matches!(
            ek_hash_from_pems(&["garbage", RSA_PEM]),
            Err(EkError::Parse(_))
        ));
    }
}
