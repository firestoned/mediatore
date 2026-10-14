-- Copyright (c) 2026 Erick Bourgeois, mediatore
-- SPDX-License-Identifier: Apache-2.0
--
-- ADR-0012: the claim store on PostgreSQL. Timestamps are microseconds since the epoch;
-- subject, audiences, workload and provider are JSON text; refresh material is the sealed
-- envelope (key id, nonce, ciphertext) or NULL. The SQLite set differs only in types.

CREATE TABLE claims (
    uid                TEXT   NOT NULL PRIMARY KEY,
    name               TEXT   NOT NULL,
    subject            TEXT   NOT NULL,
    entry_id           TEXT,
    node_id            TEXT,
    audiences          TEXT   NOT NULL,
    workload           TEXT   NOT NULL,
    ttl_seconds        BIGINT NOT NULL,
    refresh_key_id     TEXT,
    refresh_nonce      BYTEA,
    refresh_ciphertext BYTEA,
    created_at         BIGINT NOT NULL,
    expires_at         BIGINT,
    revoked_at         BIGINT
);
CREATE INDEX claims_name ON claims (name);
CREATE INDEX claims_node ON claims (node_id);

CREATE TABLE nodes (
    ek_hash       TEXT   NOT NULL PRIMARY KEY,
    node_id       TEXT   NOT NULL,
    dmi_uuid      TEXT   NOT NULL,
    hostname      TEXT   NOT NULL,
    provider      TEXT,
    banned        BIGINT NOT NULL,
    registered_at BIGINT NOT NULL
);
CREATE INDEX nodes_dmi ON nodes (dmi_uuid);

CREATE TABLE claim_audit (
    id         BIGSERIAL PRIMARY KEY,
    uid        TEXT   NOT NULL,
    name       TEXT   NOT NULL,
    subject    TEXT   NOT NULL,
    node_id    TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT,
    revoked_at BIGINT,
    swept_at   BIGINT NOT NULL
);
CREATE INDEX claim_audit_uid ON claim_audit (uid);
