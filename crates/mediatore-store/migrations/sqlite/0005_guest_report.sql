-- Copyright (c) 2026 Erick Bourgeois, mediatore
-- SPDX-License-Identifier: Apache-2.0
--
-- ADR-0029 decision 5: what the guest found loaded and pulled when it started the claim's
-- workload, as JSON (reported_at, image_digest, sandbox_ruleset_sha256, host_table). NULL
-- until the guest reports; kept with the audit row when the claim is swept.

ALTER TABLE claims ADD COLUMN report TEXT;
ALTER TABLE claim_audit ADD COLUMN report TEXT;
