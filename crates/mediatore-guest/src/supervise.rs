// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Jail supervision: run the workload until the claim's deadline, restart on crash,
//! tear everything down at the end.

use std::path::Path;

use chrono::{DateTime, Utc};

use crate::jail::JailSpec;
use crate::{net, sandboxfs, user};

/// Seconds to wait before restarting a crashed workload.
const RESTART_DELAY_SECS: u64 = 2;

/// Run `nsjail` with the spec's arguments until `expires_at`, restarting on exit.
///
/// Returns when the deadline passes; the running child is killed first. An error spawning
/// the jail is returned immediately: a sandbox that cannot start must not linger half-built.
pub async fn run(spec: &JailSpec, expires_at: DateTime<Utc>) -> anyhow::Result<()> {
    loop {
        let remaining = expires_at - Utc::now();
        let Ok(remaining) = remaining.to_std() else {
            tracing::info!("claim deadline reached");
            return Ok(());
        };

        let mut child = tokio::process::Command::new("nsjail")
            .args(spec.to_args())
            .spawn()?;
        tracing::info!(pid = child.id(), user = %spec.user, "jail started");

        tokio::select! {
            status = child.wait() => {
                let status = status?;
                tracing::warn!(%status, "workload exited before the deadline; restarting");
                tokio::time::sleep(std::time::Duration::from_secs(RESTART_DELAY_SECS)).await;
            }
            () = tokio::time::sleep(remaining) => {
                tracing::info!("claim deadline reached; stopping the jail");
                child.start_kill()?;
                let _ = child.wait().await;
                return Ok(());
            }
        }
    }
}

/// Best-effort teardown: drop the ruleset, unmount the sandbox tmpfs (ADR-0021), wipe
/// whatever is left under the root when there was no mount, and remove the user. Failures
/// are logged, never fatal; the VM is about to be destroyed anyway.
pub async fn teardown(sandbox_root: &Path, username: &str) {
    net::unload().await;
    match sandboxfs::is_mounted(sandbox_root) {
        Ok(true) => sandboxfs::unmount(sandbox_root).await,
        Ok(false) => {}
        Err(e) => tracing::warn!(error = %e, "could not read the mount table"),
    }
    if !sandboxfs::is_mounted(sandbox_root).unwrap_or(false) {
        for name in ["work", "layers", "rootfs"] {
            let dir = sandbox_root.join(name);
            if let Err(e) = tokio::fs::remove_dir_all(&dir).await
                && e.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(dir = %dir.display(), error = %e, "could not wipe sandbox dir");
            }
        }
    }
    if let Err(e) = user::remove(username).await {
        tracing::warn!(user = username, error = %e, "could not remove sandbox user");
    }
    tracing::info!(user = username, "teardown complete");
}
