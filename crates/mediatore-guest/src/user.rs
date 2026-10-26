// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Per-subject Linux user.

use mediatore_proto::Subject;

/// Create the sandbox user for `subject`. Idempotent: an existing user of that name is kept.
pub async fn ensure(subject: &Subject) -> anyhow::Result<String> {
    let name = subject.sandbox_username();
    let exists = tokio::process::Command::new("id")
        .arg(&name)
        .output()
        .await?
        .status
        .success();
    if exists {
        return Ok(name);
    }
    let gecos = subject
        .display
        .clone()
        .unwrap_or_else(|| subject.id.clone());
    let status = tokio::process::Command::new("useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "--comment",
            &gecos,
            "--user-group",
            &name,
        ])
        .status()
        .await?;
    anyhow::ensure!(status.success(), "useradd {name} failed: {status}");
    tracing::info!(user = %name, "sandbox user created");
    Ok(name)
}

/// The uid of `name`, what the ruleset keys on (ADR-0020).
///
/// # Errors
/// No such user, or `id` unavailable.
pub async fn uid(name: &str) -> anyhow::Result<u32> {
    id("-u", name).await
}

/// The primary gid of `name`, what `work/` is owned by (ADR-0021).
///
/// # Errors
/// No such user, or `id` unavailable.
pub async fn gid(name: &str) -> anyhow::Result<u32> {
    id("-g", name).await
}

async fn id(flag: &str, name: &str) -> anyhow::Result<u32> {
    let out = tokio::process::Command::new("id")
        .args([flag, name])
        .output()
        .await?;
    anyhow::ensure!(
        out.status.success(),
        "id {flag} {name} failed: {}",
        out.status
    );
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("id {flag} {name} printed {:?}: {e}", text.trim()))
}

/// Remove the sandbox user and its group. Idempotent.
pub async fn remove(name: &str) -> anyhow::Result<()> {
    let status = tokio::process::Command::new("userdel")
        .arg("--force")
        .arg(name)
        .status()
        .await?;
    if !status.success() {
        tracing::warn!(user = name, %status, "userdel did not succeed (already gone?)");
    }
    Ok(())
}
