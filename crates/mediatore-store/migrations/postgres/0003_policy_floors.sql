-- Copyright (c) 2026 Erick Bourgeois, mediatore
-- SPDX-License-Identifier: Apache-2.0
--
-- ADR-0026 decision 5: the version floor of each notaio policy, so a bundle older than one
-- already accepted is refused after a restart too. `issued_at` is RFC 3339 text with
-- nanoseconds, not microseconds like the other timestamps: the floor orders incarnations of
-- a policy by it, and the writer's compare-and-set matches it exactly.

CREATE TABLE policy_floors (
    namespace TEXT   NOT NULL,
    name      TEXT   NOT NULL,
    uid       TEXT   NOT NULL,
    version   BIGINT NOT NULL,
    issued_at TEXT   NOT NULL,
    PRIMARY KEY (namespace, name)
);
