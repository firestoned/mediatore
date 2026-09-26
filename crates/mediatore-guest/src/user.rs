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
