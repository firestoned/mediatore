// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The VM side of the one `mediatore` binary (ADR-0014): the `guest` role, which turns a
//! bound banlieue claim into a jailed, identity-bearing workload, and the `token` role,
//! which the workload runs inside that jail to trade its claim SVID for an audience-scoped
//! token. Both reach the broker through the same [`client::SandboxClient`].
//!
//! Transport: SPIFFE mTLS with the SVID from the Workload API, verifying the broker as
//! exactly `spiffe://<td>/mediatore` (ADR-0007 decision 5). With the `dev` cargo feature
//! only, `--dev-spiffe-id` sends the identity as a header to a loopback `dev_mode` server
//! instead; release builds have no such path.

pub mod client;
pub mod guest;
mod identity;
pub mod jail;
mod supervise;
pub mod token;
mod user;
