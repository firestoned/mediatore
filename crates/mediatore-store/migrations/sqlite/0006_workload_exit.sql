-- Copyright (c) 2026 Erick Bourgeois, mediatore
-- SPDX-License-Identifier: Apache-2.0
--
-- ADR-0033 decision 2: how the workload ended when its restart policy ended the claim, as
-- JSON (exited_at, code, signal, restarts). NULL for a claim that ran to its deadline or
-- was released by its subject; kept with the audit row when the claim is swept.

ALTER TABLE claims ADD COLUMN exit TEXT;
ALTER TABLE claim_audit ADD COLUMN exit TEXT;
