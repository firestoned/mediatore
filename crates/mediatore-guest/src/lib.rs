// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The VM side of the one `mediatore` binary (ADR-0014): the `guest` role, which turns a
//! bound banlieue claim into a jailed, identity-bearing workload, and the `token` role,
//! which the workload runs inside that jail to trade its claim SVID for an audience-scoped
//! token. Both reach the broker through the same [`client::SandboxClient`].
//! The `jail-exec` role sits between the two: what `nsjail` execs as the sandbox user, it
//! applies Landlock to itself and execs the workload (ADR-0024). The `egress-proxy` role is
//! the jail's only way out since ADR-0025: a second process as the sandbox user outside the
//! jail that swaps the workload's phantom token for the audience's real one; inside the jail
//! the `token` role has no socket and no route any more.
//!
//! Transport: SPIFFE mTLS with the SVID from the Workload API, verifying the broker as
//! exactly `spiffe://<td>/mediatore` (ADR-0007 decision 5). With the `dev` cargo feature
//! only, `--dev-spiffe-id` sends the identity as a header to a loopback `dev_mode` server
//! instead; release builds have no such path.

pub mod client;
pub mod confine;
pub mod egress;
pub mod guest;
mod identity;
pub mod image;
pub mod jail;
pub mod net;
pub mod ready;
pub mod sandboxfs;
mod supervise;
pub mod token;
mod user;
