// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! SPIFFE mTLS for mediatore, on rustls (ADR-0007).
//!
//! The sandbox listener and the guest clients authenticate each other with X.509 SVIDs. This
//! crate holds the two verifiers (the client certificate on the server side, the server
//! certificate on the client side), the configs built from them, and the accept loop that
//! hands axum a request extension carrying the verified peer SPIFFE ID.
//!
//! Material arrives through [`MaterialSource`]: the Workload API in production
//! ([`WorkloadApiSource`], the `spiffe` crate's `X509Source`, kept in memory and rotated by
//! the agent), or a test CA in the e2e suite (`mediatore-testkit`). The verification path is
//! the same whichever source feeds it; only the certificates differ, which is what lets the
//! hermetic suite exercise the production path with no SPIRE.
//!
//! A peer certificate must satisfy, in this order (the checks `spiffe-rustls` makes):
//!
//! 1. leaf constraints: not a CA, `digitalSignature` set, neither `keyCertSign` nor
//!    `cRLSign`, and exactly one URI SAN that is a SPIFFE ID with a non-empty path;
//! 2. the SPIFFE ID's trust domain is the local one (no federation);
//! 3. the chain verifies to the trust domain's bundle (rustls and webpki, with the
//!    `clientAuth` or `serverAuth` extended key usage the side requires, and validity now);
//! 4. the authorizer accepts the SPIFFE ID.
//!
//! A failure closes the handshake before a byte of HTTP is parsed. TLS 1.3 only, session
//! resumption off (a resumed handshake would skip the verifier).
//!
//! Both ends of this leg are ours, so its cryptography is pinned rather than negotiated
//! ([`sandbox_provider`]): key exchange is X25519MLKEM768 and nothing else, the record
//! protection is AES-256-GCM with SHA-384. A peer that offers only classical groups does
//! not complete the handshake. Signatures stay whatever the SVIDs carry (ECDSA from SPIRE
//! today); the verifiers already accept ML-DSA certificates, so the path is ready for the
//! day SPIRE issues them (threat model R-8).

mod client;
mod material;
mod provider;
mod server;
mod verify;

pub use client::{client_config, server_verifier};
pub use material::{Material, MaterialSource, WorkloadApiSource, endpoint};
pub use provider::sandbox_provider;
pub use server::{PeerSpiffeId, TlsConfigs, serve};
pub use spiffe::{SpiffeId, TrustDomain};
pub use verify::{Authorizer, PeerError, exact, leaf_spiffe_id};

/// Errors building or sourcing TLS material.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The source has no usable SVID or bundle right now.
    #[error("tls material: {0}")]
    Material(String),
    /// A rustls config could not be built from the material.
    #[error("tls config: {0}")]
    Config(String),
    /// The Workload API could not be reached or stopped delivering.
    #[error("workload api: {0}")]
    WorkloadApi(String),
}
