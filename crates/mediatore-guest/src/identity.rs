// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! What the guest knows about itself.

use std::path::Path;

use anyhow::Context as _;
use mediatore_proto::x509pop::{LeafNames, leaf_common_names};
use uuid::Uuid;

use crate::nodecert::CERT_FILE;

/// DMI system UUID as the hypervisor set it (`--platform uuid=` on Cloud Hypervisor,
/// `<uuid>` on libvirt, `config.uuid` on vSphere).
pub fn dmi_uuid() -> anyhow::Result<Uuid> {
    let raw = std::fs::read_to_string("/sys/class/dmi/id/product_uuid")?;
    Ok(Uuid::parse_str(raw.trim())?)
}

/// Hostname from the kernel.
pub fn hostname() -> anyhow::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/hostname")?
        .trim()
        .to_owned())
}

/// SHA-256 of the EK public key, computed the same way the SPIRE TPM attestor does.
///
/// Reads the EK via `tpm2_createek`/`tpm2_readpublic` for now; the `tss-esapi` path replaces
/// the shell-out once the encoding used by the attestor plugin is confirmed (Part 3.2 of the
/// runbook).
pub async fn ek_hash(tpm: &Path) -> anyhow::Result<String> {
    let out = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "tpm2_createek -T device:{tpm} -c /run/mediatore-guest/ek.ctx -G rsa -u /run/mediatore-guest/ek.pub >/dev/null && \
             tpm2_readpublic -T device:{tpm} -c /run/mediatore-guest/ek.ctx -f pem -o /dev/stdout | \
             openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1",
            tpm = tpm.display()
        ))
        .output()
        .await?;
    anyhow::ensure!(
        out.status.success(),
        "ek hash: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

/// The names this node attested under with `x509pop` (ADR-0049 decision 8): the issuer and
/// subject common names of the leaf `mediatore node-cert` wrote to `dir` (the first
/// certificate of [`CERT_FILE`]; the chain follows it). The SPIRE server named the agent
/// from these two, so they are what the broker is told.
///
/// # Errors
/// The file is missing or unreadable, holds no certificate, or its leaf has no single
/// common name inside the path-segment alphabet on either side. Each is a reason not to
/// start: the guest never guesses its names, and never falls back to a TPM.
pub fn x509pop_names(dir: &Path) -> anyhow::Result<LeafNames> {
    let path = dir.join(CERT_FILE);
    let pem = std::fs::read(&path).with_context(|| {
        format!(
            "x509pop node attestation: cannot read the node certificate {} (`mediatore node-cert fetch` writes it before the agent starts)",
            path.display()
        )
    })?;
    // The error names the rule broken, never the certificate.
    leaf_common_names(&pem).map_err(|e| {
        anyhow::anyhow!(
            "x509pop node attestation: the node certificate {} is unusable: {e}",
            path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use mediatore_testkit::x509pop::HostCa;

    use super::*;

    #[test]
    fn the_names_are_those_of_the_leaf_node_cert_wrote_whatever_follows_it() {
        let dir = tempfile::tempdir().unwrap();
        let ca = HostCa::new("hv-01");
        let leaf = ca.leaf_pem("3f0c2a1e-7b1d-4e0a-9c55-0a1b2c3d4e5f");
        let want = LeafNames {
            issuer_cn: "hv-01".into(),
            subject_cn: "3f0c2a1e-7b1d-4e0a-9c55-0a1b2c3d4e5f".into(),
        };
        std::fs::write(dir.path().join(CERT_FILE), &leaf).unwrap();
        assert_eq!(x509pop_names(dir.path()).unwrap(), want);
        // The leaf followed by its chain: the leaf is still what the agent attests with.
        std::fs::write(dir.path().join(CERT_FILE), format!("{leaf}{}", ca.pem())).unwrap();
        assert_eq!(x509pop_names(dir.path()).unwrap(), want);
    }

    #[test]
    fn a_missing_file_an_unparsable_one_and_a_bad_name_are_each_an_error_that_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let missing = x509pop_names(dir.path()).unwrap_err().to_string();
        assert!(
            missing.contains("cannot read the node certificate") && missing.contains("cert.pem"),
            "a missing file is named"
        );
        let cert = dir.path().join(CERT_FILE);
        for garbage in ["", "not a certificate"] {
            std::fs::write(&cert, garbage).unwrap();
            let err = x509pop_names(dir.path()).unwrap_err().to_string();
            assert!(
                err.contains("unusable"),
                "an unparsable file is said to be unusable"
            );
        }
        // A subject the server's template could not render into one path segment, and an
        // issuer whose name is outside the alphabet.
        for (issuer, subject) in [("hv-01", "a/b"), ("hv 01", "vm-1"), ("hv-01", "..")] {
            std::fs::write(&cert, HostCa::new(issuer).leaf_pem(subject)).unwrap();
            let err = x509pop_names(dir.path()).unwrap_err().to_string();
            assert!(
                err.contains("unusable") && err.contains("common name"),
                "a bad name on either side is said to be unusable"
            );
            assert!(!err.contains("BEGIN CERTIFICATE"), "no certificate body");
        }
    }
}
