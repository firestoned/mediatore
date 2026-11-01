-- Copyright (c) 2026 Erick Bourgeois, mediatore
-- SPDX-License-Identifier: Apache-2.0
--
-- ADR-0026 decision 6: the notaio policy a sandbox named, as the record saw it when the claim
-- was created: the policy's uid (its incarnation) and the version of the verified bundle in
-- the cache at that moment. Both NULL for a sandbox that named no policy, or whose policy had
-- no verified bundle then.

ALTER TABLE claims ADD COLUMN policy_uid TEXT;
ALTER TABLE claims ADD COLUMN bundle_version INTEGER;
