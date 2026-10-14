// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Refresh material never reaches the store in the clear (ADR-0012 decision 3).
//!
//! A [`Sealed`] envelope is the only form a `ClaimRecord` accepts: the id of the key that
//! sealed it, a fresh 96-bit nonce and the AES-256-GCM ciphertext, with the claim UID as
//! associated data so an envelope copied onto another claim's row does not open. A
//! [`Sealer`] turns plaintext into an envelope and back. [`LocalKeySealer`] holds a 32-byte
//! key read from a file (a Secret volume): the homelab shape, where the broker holds the
//! wrapping key. The work shape, `OpenBao` transit, implements the same trait and lands with
//! the first plaintext to seal (roadmap 04).

use std::path::Path;

use async_trait::async_trait;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Length of the nonce, in bytes.
const NONCE_LEN: usize = 12;
/// Length of a local key, in bytes.
pub const KEY_LEN: usize = 32;

/// Sealed refresh material. Has no constructor that takes plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// Which key sealed it; the unsealer refuses an envelope under a key it does not hold.
    pub key_id: String,
    /// Fresh per envelope.
    pub nonce: Vec<u8>,
    /// AES-256-GCM output, tag included.
    pub ciphertext: Vec<u8>,
}

/// What can go wrong sealing or unsealing.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The envelope names a key this sealer does not hold.
    #[error("sealed under key {0}, which this sealer does not hold")]
    UnknownKey(String),
    /// The envelope did not authenticate: wrong claim, wrong key, or tampered.
    #[error("envelope did not open")]
    Rejected,
    /// The key material is unusable.
    #[error("key: {0}")]
    Key(String),
}

/// Seals and unseals refresh material bound to a claim.
#[async_trait]
pub trait Sealer: Send + Sync + 'static {
    /// The id envelopes sealed here carry.
    fn key_id(&self) -> &str;
    /// Seal `plaintext` for `claim_uid`.
    async fn seal(&self, claim_uid: Uuid, plaintext: &[u8]) -> Result<Sealed, SealError>;
    /// Open `sealed`, which must have been sealed for `claim_uid` under a key this sealer holds.
    async fn unseal(&self, claim_uid: Uuid, sealed: &Sealed) -> Result<Vec<u8>, SealError>;
}

/// AES-256-GCM under one key held in memory.
pub struct LocalKeySealer {
    key: LessSafeKey,
    key_id: String,
    rng: SystemRandom,
}

impl LocalKeySealer {
    /// A sealer over `key`. The key id is the first 16 hex characters of the key's SHA-256,
    /// so a rotated key is told apart and the key itself is never written anywhere.
    #[must_use]
    pub fn new(key: [u8; KEY_LEN]) -> Self {
        let key_id = hex::encode(&Sha256::digest(key)[..8]);
        // Infallible: the algorithm's key length is KEY_LEN by construction.
        let unbound = UnboundKey::new(&AES_256_GCM, &key)
            .unwrap_or_else(|_| unreachable!("AES-256-GCM takes {KEY_LEN} bytes"));
        Self {
            key: LessSafeKey::new(unbound),
            key_id,
            rng: SystemRandom::new(),
        }
    }

    /// A sealer over the key in `path`: exactly 32 raw bytes, or 64 hex characters (with
    /// surrounding whitespace allowed). Anything else is refused.
    pub fn from_file(path: &Path) -> Result<Self, SealError> {
        let raw =
            std::fs::read(path).map_err(|e| SealError::Key(format!("{}: {e}", path.display())))?;
        Self::from_bytes(&raw)
    }

    /// See [`Self::from_file`].
    pub fn from_bytes(raw: &[u8]) -> Result<Self, SealError> {
        let key: [u8; KEY_LEN] = if let Ok(exact) = <[u8; KEY_LEN]>::try_from(raw) {
            exact
        } else {
            let text = std::str::from_utf8(raw)
                .map_err(|_| {
                    SealError::Key(format!(
                        "expected {KEY_LEN} raw bytes or {} hex characters",
                        KEY_LEN * 2
                    ))
                })?
                .trim();
            let decoded = hex::decode(text).map_err(|_| {
                SealError::Key(format!(
                    "expected {KEY_LEN} raw bytes or {} hex characters",
                    KEY_LEN * 2
                ))
            })?;
            decoded
                .try_into()
                .map_err(|_| SealError::Key(format!("expected {} hex characters", KEY_LEN * 2)))?
        };
        Ok(Self::new(key))
    }
}

fn aad(claim_uid: Uuid) -> [u8; 16] {
    *claim_uid.as_bytes()
}

#[async_trait]
impl Sealer for LocalKeySealer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn seal(&self, claim_uid: Uuid, plaintext: &[u8]) -> Result<Sealed, SealError> {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce)
            .map_err(|_| SealError::Key("no randomness".into()))?;
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(claim_uid)),
                &mut buf,
            )
            .map_err(|_| SealError::Rejected)?;
        Ok(Sealed {
            key_id: self.key_id.clone(),
            nonce: nonce.to_vec(),
            ciphertext: buf,
        })
    }

    async fn unseal(&self, claim_uid: Uuid, sealed: &Sealed) -> Result<Vec<u8>, SealError> {
        if sealed.key_id != self.key_id {
            return Err(SealError::UnknownKey(sealed.key_id.clone()));
        }
        let nonce: [u8; NONCE_LEN] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| SealError::Rejected)?;
        let mut buf = sealed.ciphertext.clone();
        let opened = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(claim_uid)),
                &mut buf,
            )
            .map_err(|_| SealError::Rejected)?;
        Ok(opened.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealer(byte: u8) -> LocalKeySealer {
        LocalKeySealer::new([byte; KEY_LEN])
    }

    #[tokio::test]
    async fn an_envelope_opens_only_for_its_claim_under_its_key() {
        let uid = Uuid::new_v4();
        let s = sealer(1);
        let env = s.seal(uid, b"refresh").await.unwrap();
        assert_eq!(env.key_id, s.key_id());
        assert_eq!(env.nonce.len(), NONCE_LEN);
        assert_ne!(env.ciphertext, b"refresh");
        assert_eq!(s.unseal(uid, &env).await.unwrap(), b"refresh");

        assert!(matches!(
            s.unseal(Uuid::new_v4(), &env).await,
            Err(SealError::Rejected)
        ));
        assert!(matches!(
            sealer(2).unseal(uid, &env).await,
            Err(SealError::UnknownKey(_))
        ));
        let mut forged = env.clone();
        forged.key_id = sealer(2).key_id().to_owned();
        assert!(matches!(
            sealer(2).unseal(uid, &forged).await,
            Err(SealError::Rejected)
        ));
        let mut tampered = env.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(matches!(
            s.unseal(uid, &tampered).await,
            Err(SealError::Rejected)
        ));
    }

    #[tokio::test]
    async fn every_envelope_has_its_own_nonce() {
        let uid = Uuid::new_v4();
        let s = sealer(1);
        let a = s.seal(uid, b"x").await.unwrap();
        let b = s.seal(uid, b"x").await.unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn a_key_file_is_raw_or_hex_and_nothing_else() {
        let raw = LocalKeySealer::from_bytes(&[9u8; KEY_LEN]).unwrap();
        let hex =
            LocalKeySealer::from_bytes(format!("{}\n", "09".repeat(KEY_LEN)).as_bytes()).unwrap();
        assert_eq!(raw.key_id(), hex.key_id());
        assert_ne!(raw.key_id(), sealer(1).key_id());
        for bad in [
            &b"short"[..],
            &[0u8; 31],
            &[0u8; 33],
            "zz".repeat(32).as_bytes(),
        ] {
            assert!(matches!(
                LocalKeySealer::from_bytes(bad),
                Err(SealError::Key(_))
            ));
        }
    }
}
