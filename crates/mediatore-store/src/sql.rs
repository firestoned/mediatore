// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The shipped store: one query set over sqlx's `Any` driver, on SQLite or PostgreSQL by
//! URL (ADR-0012 decisions 1 and 2).
//!
//! The portable subset: text, integer and byte columns; UUIDs as text; timestamps as
//! microseconds since the epoch; subject, audiences, workload and provider as JSON text.
//! Placeholders are `$1`, `$2`, in ascending order, each used once: PostgreSQL binds them by
//! number and SQLite by order of first appearance, which then agree. The DDL differs by
//! column type, so each engine has its own migration set, embedded here and applied by
//! [`SqlStore::connect`].

use std::borrow::Cow;
use std::str::FromStr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::any::{AnyConnectOptions, AnyPoolOptions, AnyRow};
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::{AnyPool, ConnectOptions, Row, SqlSafeStr};
use uuid::Uuid;

use crate::seal::Sealed;
use crate::{ClaimAudit, ClaimRecord, ClaimStore, NodeRecord, SessionRecord, StoreError};

/// Which engine a URL names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// `sqlite:` URLs.
    Sqlite,
    /// `postgres:` and `postgresql:` URLs.
    Postgres,
}

impl Engine {
    /// The engine behind `url`, or `None` for a scheme the store does not support.
    #[must_use]
    pub fn of(url: &str) -> Option<Self> {
        let scheme = url.split(':').next()?.to_ascii_lowercase();
        match scheme.as_str() {
            "sqlite" => Some(Self::Sqlite),
            "postgres" | "postgresql" => Some(Self::Postgres),
            _ => None,
        }
    }

    fn migrator(self) -> Migrator {
        let steps: [(i64, &'static str, &'static str); 2] = match self {
            Self::Sqlite => [
                (
                    1,
                    "init",
                    include_str!("../migrations/sqlite/0001_init.sql"),
                ),
                (
                    2,
                    "sessions",
                    include_str!("../migrations/sqlite/0002_sessions.sql"),
                ),
            ],
            Self::Postgres => [
                (
                    1,
                    "init",
                    include_str!("../migrations/postgres/0001_init.sql"),
                ),
                (
                    2,
                    "sessions",
                    include_str!("../migrations/postgres/0002_sessions.sql"),
                ),
            ],
        };
        Migrator {
            migrations: Cow::Owned(
                steps
                    .into_iter()
                    .map(|(version, name, sql)| {
                        Migration::new(
                            version,
                            Cow::Borrowed(name),
                            MigrationType::Simple,
                            sql.into_sql_str(),
                            false,
                        )
                    })
                    .collect(),
            ),
            ..Migrator::DEFAULT
        }
    }
}

/// True for a SQLite URL that lives in memory, which is as lossy as `MemoryStore` and
/// which every pool connection would see as a different database.
#[must_use]
pub fn is_memory_sqlite(url: &str) -> bool {
    Engine::of(url) == Some(Engine::Sqlite)
        && (url.contains(":memory:") || url.contains("mode=memory"))
}

/// What of a URL may be logged: the scheme and, for PostgreSQL, the host.
#[must_use]
pub fn redacted(url: &str) -> String {
    match Engine::of(url) {
        Some(Engine::Sqlite) => "sqlite".into(),
        Some(Engine::Postgres) => {
            let host = url
                .split_once('@')
                .map_or("", |(_, rest)| rest)
                .split(['/', '?'])
                .next()
                .unwrap_or("");
            if host.is_empty() {
                "postgres".into()
            } else {
                format!("postgres://{host}")
            }
        }
        None => "unsupported".into(),
    }
}

/// The sqlx-backed [`ClaimStore`].
pub struct SqlStore {
    pool: AnyPool,
    engine: Engine,
}

fn backend(e: impl std::fmt::Display) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn micros(t: DateTime<Utc>) -> i64 {
    t.timestamp_micros()
}

fn from_micros(v: i64) -> Result<DateTime<Utc>, StoreError> {
    DateTime::from_timestamp_micros(v).ok_or_else(|| backend(format!("timestamp {v} out of range")))
}

fn opt_micros(v: Option<i64>) -> Result<Option<DateTime<Utc>>, StoreError> {
    v.map(from_micros).transpose()
}

fn json<T: serde::Serialize>(v: &T) -> Result<String, StoreError> {
    serde_json::to_string(v).map_err(backend)
}

fn unjson<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, StoreError> {
    serde_json::from_str(s).map_err(backend)
}

fn uuid(s: &str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(s).map_err(backend)
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.is_unique_violation())
}

const CLAIM_COLUMNS: &str = "uid, name, subject, entry_id, node_id, audiences, workload, ttl_seconds, \
     refresh_key_id, refresh_nonce, refresh_ciphertext, created_at, expires_at, revoked_at, \
     sandbox_uid";

/// The three columns of a [`Sealed`] envelope, or three `NULL`s.
fn sealed_columns(s: Option<&Sealed>) -> (Option<String>, Option<Vec<u8>>, Option<Vec<u8>>) {
    match s {
        Some(s) => (
            Some(s.key_id.clone()),
            Some(s.nonce.clone()),
            Some(s.ciphertext.clone()),
        ),
        None => (None, None, None),
    }
}

const SESSION_COLUMNS: &str =
    "sandbox_uid, subject, issuer, refresh_key_id, refresh_nonce, refresh_ciphertext, created_at";

fn session_of(row: &AnyRow) -> Result<SessionRecord, StoreError> {
    let sandbox_uid: String = row.try_get("sandbox_uid").map_err(backend)?;
    let subject: String = row.try_get("subject").map_err(backend)?;
    Ok(SessionRecord {
        sandbox_uid: uuid(&sandbox_uid)?,
        subject: unjson(&subject)?,
        issuer: row.try_get("issuer").map_err(backend)?,
        refresh: Sealed {
            key_id: row.try_get("refresh_key_id").map_err(backend)?,
            nonce: row.try_get("refresh_nonce").map_err(backend)?,
            ciphertext: row.try_get("refresh_ciphertext").map_err(backend)?,
        },
        created_at: from_micros(row.try_get("created_at").map_err(backend)?)?,
    })
}

fn claim_of(row: &AnyRow) -> Result<ClaimRecord, StoreError> {
    let uid: String = row.try_get("uid").map_err(backend)?;
    let subject: String = row.try_get("subject").map_err(backend)?;
    let audiences: String = row.try_get("audiences").map_err(backend)?;
    let workload: String = row.try_get("workload").map_err(backend)?;
    let ttl: i64 = row.try_get("ttl_seconds").map_err(backend)?;
    let key_id: Option<String> = row.try_get("refresh_key_id").map_err(backend)?;
    let nonce: Option<Vec<u8>> = row.try_get("refresh_nonce").map_err(backend)?;
    let ciphertext: Option<Vec<u8>> = row.try_get("refresh_ciphertext").map_err(backend)?;
    let refresh = match (key_id, nonce, ciphertext) {
        (Some(key_id), Some(nonce), Some(ciphertext)) => Some(Sealed {
            key_id,
            nonce,
            ciphertext,
        }),
        _ => None,
    };
    Ok(ClaimRecord {
        uid: uuid(&uid)?,
        name: row.try_get("name").map_err(backend)?,
        subject: unjson(&subject)?,
        entry_id: row.try_get("entry_id").map_err(backend)?,
        node_id: row.try_get("node_id").map_err(backend)?,
        audiences: unjson(&audiences)?,
        workload: unjson(&workload)?,
        ttl_seconds: u32::try_from(ttl).map_err(backend)?,
        refresh,
        created_at: from_micros(row.try_get("created_at").map_err(backend)?)?,
        expires_at: opt_micros(row.try_get("expires_at").map_err(backend)?)?,
        revoked_at: opt_micros(row.try_get("revoked_at").map_err(backend)?)?,
        sandbox_uid: row
            .try_get::<Option<String>, _>("sandbox_uid")
            .map_err(backend)?
            .as_deref()
            .map(uuid)
            .transpose()?,
    })
}

const NODE_COLUMNS: &str = "ek_hash, node_id, dmi_uuid, hostname, provider, banned, registered_at";

fn node_of(row: &AnyRow) -> Result<NodeRecord, StoreError> {
    let dmi: String = row.try_get("dmi_uuid").map_err(backend)?;
    let provider: Option<String> = row.try_get("provider").map_err(backend)?;
    let banned: i64 = row.try_get("banned").map_err(backend)?;
    Ok(NodeRecord {
        ek_hash: row.try_get("ek_hash").map_err(backend)?,
        node_id: row.try_get("node_id").map_err(backend)?,
        dmi_uuid: uuid(&dmi)?,
        hostname: row.try_get("hostname").map_err(backend)?,
        provider: provider.as_deref().map(unjson).transpose()?,
        banned: banned != 0,
        registered_at: from_micros(row.try_get("registered_at").map_err(backend)?)?,
    })
}

impl SqlStore {
    /// Connect to `url`, apply the migrations and return the store. A memory SQLite URL
    /// gets one connection whatever `max_connections` says (each connection would otherwise
    /// be its own database); a file SQLite runs in WAL mode with a busy timeout.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, StoreError> {
        let engine = Engine::of(url)
            .ok_or_else(|| StoreError::Backend("unsupported store url scheme".into()))?;
        sqlx::any::install_default_drivers();
        let options = AnyConnectOptions::from_str(url)
            .map_err(backend)?
            .disable_statement_logging();
        let memory = is_memory_sqlite(url);
        let mut pool =
            AnyPoolOptions::new().max_connections(if memory { 1 } else { max_connections.max(1) });
        if engine == Engine::Sqlite {
            pool = pool.after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::query("PRAGMA busy_timeout = 5000")
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query("PRAGMA journal_mode = WAL")
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query("PRAGMA synchronous = NORMAL")
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            });
        }
        let pool = pool.connect_with(options).await.map_err(backend)?;
        engine.migrator().run(&pool).await.map_err(backend)?;
        Ok(Self { pool, engine })
    }

    /// Which engine this store runs on.
    #[must_use]
    pub fn engine(&self) -> Engine {
        self.engine
    }
}

#[async_trait]
impl ClaimStore for SqlStore {
    async fn put_claim(&self, rec: ClaimRecord) -> Result<(), StoreError> {
        let (key_id, nonce, ciphertext) = sealed_columns(rec.refresh.as_ref());
        let sql = format!(
            "INSERT INTO claims ({CLAIM_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"
        );
        let result = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(rec.uid.to_string())
            .bind(&rec.name)
            .bind(json(&rec.subject)?)
            .bind(&rec.entry_id)
            .bind(&rec.node_id)
            .bind(json(&rec.audiences)?)
            .bind(json(&rec.workload)?)
            .bind(i64::from(rec.ttl_seconds))
            .bind(key_id)
            .bind(nonce)
            .bind(ciphertext)
            .bind(micros(rec.created_at))
            .bind(rec.expires_at.map(micros))
            .bind(rec.revoked_at.map(micros))
            .bind(rec.sandbox_uid.map(|u| u.to_string()))
            .execute(&self.pool)
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) if is_unique_violation(&e) => Err(StoreError::Conflict(rec.uid.to_string())),
            Err(e) => Err(backend(e)),
        }
    }

    async fn get_claim(&self, uid: Uuid) -> Result<ClaimRecord, StoreError> {
        let sql = format!("SELECT {CLAIM_COLUMNS} FROM claims WHERE uid = $1");
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(uid.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound(uid.to_string()))
            .and_then(|r| claim_of(&r))
    }

    async fn get_claim_by_name(&self, name: &str) -> Result<ClaimRecord, StoreError> {
        let sql = format!(
            "SELECT {CLAIM_COLUMNS} FROM claims WHERE name = $1 ORDER BY created_at DESC LIMIT 1"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound(name.to_owned()))
            .and_then(|r| claim_of(&r))
    }

    async fn update_claim(&self, rec: ClaimRecord) -> Result<(), StoreError> {
        let (key_id, nonce, ciphertext) = sealed_columns(rec.refresh.as_ref());
        let done = sqlx::query(
            "UPDATE claims SET name = $1, subject = $2, entry_id = $3, node_id = $4, audiences = $5, \
             workload = $6, ttl_seconds = $7, refresh_key_id = $8, refresh_nonce = $9, \
             refresh_ciphertext = $10, created_at = $11, expires_at = $12, revoked_at = $13, \
             sandbox_uid = $14 WHERE uid = $15",
        )
        .bind(&rec.name)
        .bind(json(&rec.subject)?)
        .bind(&rec.entry_id)
        .bind(&rec.node_id)
        .bind(json(&rec.audiences)?)
        .bind(json(&rec.workload)?)
        .bind(i64::from(rec.ttl_seconds))
        .bind(key_id)
        .bind(nonce)
        .bind(ciphertext)
        .bind(micros(rec.created_at))
        .bind(rec.expires_at.map(micros))
        .bind(rec.revoked_at.map(micros))
        .bind(rec.sandbox_uid.map(|u| u.to_string()))
        .bind(rec.uid.to_string())
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound(rec.uid.to_string()));
        }
        Ok(())
    }

    async fn revoke_claim(&self, uid: Uuid, at: DateTime<Utc>) -> Result<(), StoreError> {
        let done = sqlx::query(
            "UPDATE claims SET revoked_at = COALESCE(revoked_at, $1), refresh_key_id = NULL, \
             refresh_nonce = NULL, refresh_ciphertext = NULL WHERE uid = $2",
        )
        .bind(micros(at))
        .bind(uid.to_string())
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound(uid.to_string()));
        }
        Ok(())
    }

    async fn get_claim_by_node(&self, node_id: &str) -> Result<ClaimRecord, StoreError> {
        let sql = format!(
            "SELECT {CLAIM_COLUMNS} FROM claims WHERE node_id = $1 AND revoked_at IS NULL \
             AND (expires_at IS NULL OR expires_at > $2) ORDER BY created_at DESC LIMIT 1"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(node_id)
            .bind(micros(Utc::now()))
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound(node_id.to_owned()))
            .and_then(|r| claim_of(&r))
    }

    async fn list_claims(&self) -> Result<Vec<ClaimRecord>, StoreError> {
        let sql = format!("SELECT {CLAIM_COLUMNS} FROM claims ORDER BY created_at");
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?
            .iter()
            .map(claim_of)
            .collect()
    }

    async fn put_node(&self, rec: NodeRecord) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let existing = sqlx::query("SELECT dmi_uuid FROM nodes WHERE ek_hash = $1")
            .bind(&rec.ek_hash)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?;
        if let Some(row) = existing {
            let dmi: String = row.try_get("dmi_uuid").map_err(backend)?;
            if uuid(&dmi)? != rec.dmi_uuid {
                // Same TPM, different VM: cloned TPM state. Refuse loudly.
                return Err(StoreError::Conflict(format!(
                    "ek_hash {} already registered for dmi {dmi}",
                    rec.ek_hash
                )));
            }
            return Ok(());
        }
        let sql = format!("INSERT INTO nodes ({NODE_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7)");
        let result = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(&rec.ek_hash)
            .bind(&rec.node_id)
            .bind(rec.dmi_uuid.to_string())
            .bind(&rec.hostname)
            .bind(rec.provider.as_ref().map(json).transpose()?)
            .bind(i64::from(rec.banned))
            .bind(micros(rec.registered_at))
            .execute(&mut *tx)
            .await;
        match result {
            Ok(_) => {}
            // Two registrations racing: the row that won is the record; re-read it.
            Err(e) if is_unique_violation(&e) => {
                drop(tx);
                return Box::pin(self.put_node(rec)).await;
            }
            Err(e) => return Err(backend(e)),
        }
        tx.commit().await.map_err(backend)
    }

    async fn get_node(&self, ek_hash: &str) -> Result<NodeRecord, StoreError> {
        let sql = format!("SELECT {NODE_COLUMNS} FROM nodes WHERE ek_hash = $1");
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(ek_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound(ek_hash.to_owned()))
            .and_then(|r| node_of(&r))
    }

    async fn get_node_by_dmi(&self, dmi_uuid: Uuid) -> Result<NodeRecord, StoreError> {
        let sql = format!(
            "SELECT {NODE_COLUMNS} FROM nodes WHERE dmi_uuid = $1 ORDER BY registered_at LIMIT 1"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(dmi_uuid.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound(dmi_uuid.to_string()))
            .and_then(|r| node_of(&r))
    }

    async fn ban_node(&self, ek_hash: &str) -> Result<(), StoreError> {
        let done = sqlx::query("UPDATE nodes SET banned = 1 WHERE ek_hash = $1")
            .bind(ek_hash)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound(ek_hash.to_owned()));
        }
        Ok(())
    }

    async fn list_nodes(&self) -> Result<Vec<NodeRecord>, StoreError> {
        let sql = format!("SELECT {NODE_COLUMNS} FROM nodes ORDER BY registered_at");
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?
            .iter()
            .map(node_of)
            .collect()
    }

    async fn sweep(&self, before: DateTime<Utc>) -> Result<usize, StoreError> {
        let swept_at = Utc::now();
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let sql = format!(
            "SELECT {CLAIM_COLUMNS} FROM claims WHERE COALESCE(revoked_at, expires_at) < $1"
        );
        let ended: Vec<ClaimRecord> = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(micros(before))
            .fetch_all(&mut *tx)
            .await
            .map_err(backend)?
            .iter()
            .map(claim_of)
            .collect::<Result<_, _>>()?;
        for c in &ended {
            sqlx::query(
                "INSERT INTO claim_audit (uid, name, subject, node_id, created_at, expires_at, revoked_at, swept_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(c.uid.to_string())
            .bind(&c.name)
            .bind(json(&c.subject)?)
            .bind(&c.node_id)
            .bind(micros(c.created_at))
            .bind(c.expires_at.map(micros))
            .bind(c.revoked_at.map(micros))
            .bind(micros(swept_at))
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
            sqlx::query("DELETE FROM claims WHERE uid = $1")
                .bind(c.uid.to_string())
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
        }
        tx.commit().await.map_err(backend)?;
        Ok(ended.len())
    }

    async fn list_audit(&self) -> Result<Vec<ClaimAudit>, StoreError> {
        let rows = sqlx::query(
            "SELECT uid, name, subject, node_id, created_at, expires_at, revoked_at, swept_at \
             FROM claim_audit ORDER BY swept_at, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(|row| {
                let uid: String = row.try_get("uid").map_err(backend)?;
                let subject: String = row.try_get("subject").map_err(backend)?;
                Ok(ClaimAudit {
                    uid: uuid(&uid)?,
                    name: row.try_get("name").map_err(backend)?,
                    subject: unjson(&subject)?,
                    node_id: row.try_get("node_id").map_err(backend)?,
                    created_at: from_micros(row.try_get("created_at").map_err(backend)?)?,
                    expires_at: opt_micros(row.try_get("expires_at").map_err(backend)?)?,
                    revoked_at: opt_micros(row.try_get("revoked_at").map_err(backend)?)?,
                    swept_at: from_micros(row.try_get("swept_at").map_err(backend)?)?,
                })
            })
            .collect()
    }

    async fn put_session(&self, rec: SessionRecord) -> Result<(), StoreError> {
        let sql =
            format!("INSERT INTO sessions ({SESSION_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7)");
        let result = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(rec.sandbox_uid.to_string())
            .bind(json(&rec.subject)?)
            .bind(&rec.issuer)
            .bind(&rec.refresh.key_id)
            .bind(&rec.refresh.nonce)
            .bind(&rec.refresh.ciphertext)
            .bind(micros(rec.created_at))
            .execute(&self.pool)
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) if is_unique_violation(&e) => {
                Err(StoreError::Conflict(rec.sandbox_uid.to_string()))
            }
            Err(e) => Err(backend(e)),
        }
    }

    async fn take_session(&self, sandbox_uid: Uuid) -> Result<Option<SessionRecord>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let sql = format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE sandbox_uid = $1");
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(sandbox_uid.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let session = session_of(&row)?;
        sqlx::query("DELETE FROM sessions WHERE sandbox_uid = $1")
            .bind(sandbox_uid.to_string())
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(Some(session))
    }

    async fn delete_session(&self, sandbox_uid: Uuid) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM sessions WHERE sandbox_uid = $1")
            .bind(sandbox_uid.to_string())
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(backend)
    }

    async fn sweep_sessions(&self, before: DateTime<Utc>) -> Result<usize, StoreError> {
        let done = sqlx::query("DELETE FROM sessions WHERE created_at < $1")
            .bind(micros(before))
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        usize::try_from(done.rows_affected()).map_err(backend)
    }

    async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::conformance::suite!(
        sqlite,
        SqlStore::connect("sqlite::memory:", 4).await.unwrap()
    );

    /// The same suite against a live PostgreSQL (`make kind-e2e-store`), which refuses to
    /// run without its fixture rather than pass vacuously. The cases share one database
    /// and each empties it first, so they run with `--test-threads=1`.
    mod postgres {
        use super::*;

        async fn live() -> SqlStore {
            let url = std::env::var("MEDIATORE_LIVE_STORE_URL").unwrap_or_else(|_| {
                panic!("MEDIATORE_LIVE_STORE_URL is unset: this test needs a live PostgreSQL")
            });
            assert_eq!(
                Engine::of(&url),
                Some(Engine::Postgres),
                "not a postgres url"
            );
            let store = SqlStore::connect(&url, 4).await.unwrap();
            // Each case assumes an empty store, as the in-memory runs get one.
            for t in ["claim_audit", "claims", "nodes", "sessions"] {
                sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {t}")))
                    .execute(&store.pool)
                    .await
                    .unwrap();
            }
            store
        }

        macro_rules! live_cases {
            ($($name:ident),* $(,)?) => {
                $(
                    #[tokio::test]
                    #[ignore = "needs MEDIATORE_LIVE_STORE_URL"]
                    async fn $name() {
                        let store = live().await;
                        crate::conformance::$name(&store).await;
                    }
                )*
            };
        }

        live_cases!(
            a_claim_round_trips_every_field,
            a_second_put_of_the_same_uid_is_a_conflict,
            update_replaces_and_needs_an_existing_row,
            revoke_is_idempotent_and_drops_the_refresh_envelope,
            revoke_of_an_unknown_claim_is_not_found,
            claim_by_node_finds_only_the_newest_live_claim,
            a_node_round_trips_and_registers_once,
            duplicate_ek_with_another_dmi_is_a_conflict,
            ban_marks_the_node_and_needs_an_existing_row,
            a_sweep_moves_ended_claims_into_the_audit_table,
            a_session_is_taken_once_deleted_on_demand_and_swept_when_stale,
            ping_answers,
        );
    }

    #[tokio::test]
    async fn an_unsupported_scheme_is_refused() {
        let Err(err) = SqlStore::connect("mysql://nope", 1).await else {
            panic!("connected to an unsupported engine")
        };
        assert!(err.to_string().contains("unsupported"), "{err}");
    }

    #[test]
    fn engines_memory_urls_and_redaction() {
        assert_eq!(Engine::of("sqlite::memory:"), Some(Engine::Sqlite));
        assert_eq!(
            Engine::of("sqlite:///var/lib/mediatore/store.db"),
            Some(Engine::Sqlite)
        );
        assert_eq!(
            Engine::of("postgres://u:p@db.home.example:5432/mediatore?sslmode=verify-full"),
            Some(Engine::Postgres)
        );
        assert_eq!(Engine::of("postgresql://u:p@db/m"), Some(Engine::Postgres));
        assert_eq!(Engine::of("mysql://x"), None);
        assert!(is_memory_sqlite("sqlite::memory:"));
        assert!(is_memory_sqlite("sqlite:file:x?mode=memory&cache=shared"));
        assert!(!is_memory_sqlite("sqlite:///tmp/x.db"));
        assert_eq!(
            redacted("postgres://user:hunter2@db.home.example:5432/mediatore?sslmode=verify-full"),
            "postgres://db.home.example:5432"
        );
        assert_eq!(redacted("postgres://db/m"), "postgres");
        assert_eq!(redacted("sqlite:///x?mode=rwc"), "sqlite");
        assert!(!redacted("postgres://user:hunter2@db/m").contains("hunter2"));
    }
}
