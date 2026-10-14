// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The SQLite store on a file (ADR-0012 decision 5): what a reopened database still knows.
//! Files live under cargo's per-target temporary directory, never the system one.

use chrono::{Duration, Utc};
use mediatore_proto::{Provider, Subject, Workload};
use mediatore_store::sql::{Engine, SqlStore};
use mediatore_store::{ClaimRecord, ClaimStore, NodeRecord};
use uuid::Uuid;

fn claim(uid: Uuid) -> ClaimRecord {
    ClaimRecord {
        uid,
        name: format!("sandbox-{}", &uid.to_string()[..8]),
        subject: Subject {
            issuer: "https://issuer.example.com".into(),
            id: "octocat".into(),
            display: None,
        },
        entry_id: None,
        node_id: None,
        audiences: vec!["e2e".into()],
        workload: Workload {
            image: "registry.internal:5000/sandbox:e2e".into(),
            args: vec!["sh".into()],
        },
        ttl_seconds: 600,
        refresh: None,
        created_at: Utc::now(),
        expires_at: None,
        revoked_at: None,
        sandbox_uid: None,
    }
}

fn node(ek: &str) -> NodeRecord {
    NodeRecord {
        ek_hash: ek.into(),
        node_id: format!("spiffe://sandbox.test/spire/agent/tpm/{ek}"),
        dmi_uuid: Uuid::new_v4(),
        hostname: "member-01".into(),
        provider: Some(Provider::Libvirt),
        banned: false,
        registered_at: Utc::now(),
    }
}

/// A fresh directory under `CARGO_TARGET_TMPDIR`, which cargo owns.
fn fresh_dir() -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("mediatore-store-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn a_reopened_file_keeps_revocations_nodes_and_entries() {
    let dir = fresh_dir();
    let url = format!("sqlite://{}/store.db?mode=rwc", dir.display());
    let uid = Uuid::new_v4();
    let node = node("ek1");
    {
        let s = SqlStore::connect(&url, 2).await.unwrap();
        assert_eq!(s.engine(), Engine::Sqlite);
        let mut rec = claim(uid);
        rec.entry_id = Some("mediatore-claim-x".into());
        rec.node_id = Some(node.node_id.clone());
        rec.expires_at = Some(Utc::now() + Duration::hours(1));
        s.put_claim(rec).await.unwrap();
        s.put_node(node.clone()).await.unwrap();
        let other = claim(Uuid::new_v4());
        s.put_claim(other.clone()).await.unwrap();
        s.revoke_claim(other.uid, Utc::now()).await.unwrap();
    }
    let s = SqlStore::connect(&url, 2).await.unwrap();
    let rec = s.get_claim(uid).await.unwrap();
    assert_eq!(rec.entry_id.as_deref(), Some("mediatore-claim-x"));
    assert_eq!(s.get_claim_by_node(&node.node_id).await.unwrap().uid, uid);
    assert_eq!(s.get_node("ek1").await.unwrap().dmi_uuid, node.dmi_uuid);
    let revoked = s
        .list_claims()
        .await
        .unwrap()
        .into_iter()
        .filter(|c| c.revoked_at.is_some())
        .count();
    assert_eq!(revoked, 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn the_migration_runs_once_and_a_second_connect_is_fine() {
    let dir = fresh_dir();
    let url = format!("sqlite://{}/store.db?mode=rwc", dir.display());
    SqlStore::connect(&url, 1).await.unwrap();
    SqlStore::connect(&url, 1).await.unwrap();
    std::fs::remove_dir_all(&dir).ok();
}
