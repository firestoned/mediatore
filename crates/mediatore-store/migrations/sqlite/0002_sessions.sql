-- Copyright (c) 2026 Erick Bourgeois, mediatore
-- SPDX-License-Identifier: Apache-2.0
--
-- ADR-0013: the AgentSandbox UID a record came from (the associated data of its refresh
-- envelope), and the sessions a delegated refresh token waits in between the API call
-- and the record.

ALTER TABLE claims ADD COLUMN sandbox_uid TEXT;

CREATE TABLE sessions (
    sandbox_uid        TEXT    NOT NULL PRIMARY KEY,
    subject            TEXT    NOT NULL,
    issuer             TEXT    NOT NULL,
    refresh_key_id     TEXT    NOT NULL,
    refresh_nonce      BLOB    NOT NULL,
    refresh_ciphertext BLOB    NOT NULL,
    created_at         INTEGER NOT NULL
);
