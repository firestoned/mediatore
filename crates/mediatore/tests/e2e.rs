// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The hermetic end-to-end suites as one test binary: each file beside this one is a module.
//! A new suite is a new file here and a `mod` line below (`autotests` is off in `Cargo.toml`,
//! so a file that is not named here is not compiled). Run one suite with
//! `cargo test -p mediatore --test e2e e2e_dev::`.

mod e2e_dev;
mod e2e_egress;
mod e2e_entra;
mod e2e_forward;
mod e2e_gateway;
mod e2e_issuers;
mod e2e_mtls;
mod e2e_sandbox;
mod e2e_session;
mod egress_upstream_tls;
mod transit_sealer;
