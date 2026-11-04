// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The guest's report (ADR-0029 decision 5): once the image is pulled and the tables are
//! loaded, and before the workload starts, the guest tells the broker what it found, over
//! the node SVID: the manifest digest, the hash of the sandbox uid's ruleset as loaded,
//! and the host table as `nft` lists it, hashed, or its absence. The record then says which
//! bytes and which rules ran, and a later `nft list table` can be compared. One attempt,
//! bounded: the report is the record's, not the jail's gate, so a broker that cannot be
//! reached at that moment is said at `warn` and the claim goes on; its record shows no
//! report, which the subject sees.

use std::time::Duration;

use mediatore_proto::{GuestReport, HostTable};
use reqwest::Method;
use sha2::{Digest, Sha256};

use crate::client::SandboxClient;

/// The host table's name (`image/host-table`).
pub const HOST_TABLE: &str = "mediatore_host";
/// How long the report may take.
const SEND_TIMEOUT: Duration = Duration::from_secs(15);

/// The host table as loaded: `nft -s list table inet mediatore_host` hashed (`-s` leaves
/// out the counters, so the hash is of the rules), `Missing` when `nft` finds none and the
/// environment has gateways (`expected`), `NotLoaded` when none is expected either.
pub async fn host_table(expected: bool) -> HostTable {
    let out = tokio::process::Command::new(crate::net::NFT)
        .args(["-s", "list", "table", "inet", HOST_TABLE])
        .output()
        .await;
    classify(out.map(|o| (o.status.success(), o.stdout)), expected)
}

/// [`host_table`] without the process: what `nft` said, to what is reported.
#[must_use]
pub fn classify(nft: std::io::Result<(bool, Vec<u8>)>, expected: bool) -> HostTable {
    match nft {
        Ok((true, stdout)) if !stdout.is_empty() => HostTable::Loaded {
            sha256: hex::encode(Sha256::digest(&stdout)),
        },
        _ if expected => HostTable::Missing,
        _ => HostTable::NotLoaded,
    }
}

/// `POST /v1/me/report`, once.
///
/// # Errors
/// The broker unreachable within the bound, or refusing the report.
pub async fn send(client: &SandboxClient, report: &GuestReport) -> anyhow::Result<()> {
    let resp = tokio::time::timeout(
        SEND_TIMEOUT,
        client.send(Method::POST, "/v1/me/report", Some(report)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("no answer within {}s", SEND_TIMEOUT.as_secs()))??;
    anyhow::ensure!(
        resp.status().is_success(),
        "the broker refused the report: {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_table_is_hashed_when_listed_and_its_absence_named_by_what_was_expected() {
        let text = b"table inet mediatore_host {\n  chain input {\n    type filter hook input priority filter; policy drop;\n  }\n}\n".to_vec();
        let want = hex::encode(Sha256::digest(&text));
        assert_eq!(
            classify(Ok((true, text.clone())), true),
            HostTable::Loaded {
                sha256: want.clone()
            }
        );
        assert_eq!(
            classify(Ok((true, text)), false),
            HostTable::Loaded { sha256: want },
            "a table loaded where none was expected is still reported as loaded"
        );
        // nft exits non-zero when the table does not exist, and says nothing on stdout.
        assert_eq!(classify(Ok((false, Vec::new())), true), HostTable::Missing);
        assert_eq!(
            classify(Ok((false, Vec::new())), false),
            HostTable::NotLoaded
        );
        assert_eq!(
            classify(Ok((true, Vec::new())), true),
            HostTable::Missing,
            "an empty listing is no table"
        );
        let no_nft = Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(
            classify(no_nft, true),
            HostTable::Missing,
            "no nft at all is a missing table where one was expected"
        );
    }

    #[test]
    fn a_report_of_a_loaded_table_validates_and_a_bad_hash_does_not() {
        let good = GuestReport {
            image_digest: format!("sha256:{}", "ab".repeat(32)),
            sandbox_ruleset_sha256: "cd".repeat(32),
            host_table: HostTable::Loaded {
                sha256: "ef".repeat(32),
            },
        };
        assert_eq!(good.validate(), Ok(()));
        let mut bad = good.clone();
        bad.image_digest = "ab".repeat(32);
        assert!(bad.validate().is_err(), "no sha256: prefix");
        let mut bad = good.clone();
        bad.host_table = HostTable::Loaded {
            sha256: "EF".repeat(32),
        };
        assert!(bad.validate().is_err(), "upper-case hex");
        let mut bad = good;
        bad.sandbox_ruleset_sha256 = "cd".repeat(31);
        assert!(bad.validate().is_err(), "too short");
    }
}
