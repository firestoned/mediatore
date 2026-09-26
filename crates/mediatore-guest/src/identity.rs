//! What the guest knows about itself.

use std::path::Path;

use uuid::Uuid;

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
