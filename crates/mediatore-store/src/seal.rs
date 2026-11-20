// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Refresh material never reaches the store in the clear (ADR-0012 decision 3).
//!
//! A [`Sealed`] envelope is the only form a `ClaimRecord` accepts: the id of the key that
//! sealed it, a fresh 96-bit nonce and the AES-256-GCM ciphertext, with the binding UID and
//! the envelope's slot as associated data (ADR-0057 decision 9), so an envelope copied onto
//! another claim's row, or presented as another audience's of the same claim, does not open. A
//! [`Sealer`] turns plaintext into an envelope and back. [`LocalKeySealer`] holds a 32-byte
//! key read from a file (a Secret volume): the homelab shape, where the broker holds the
//! wrapping key. [`TransitSealer`] is the work shape (ADR-0015): `OpenBao`'s transit engine
//! holds a derived key, the same binding bytes are the derivation context, and the broker
//! holds only a short-lived `OpenBao` token it obtained with its `ServiceAccount`.

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

/// The envelope format of ADR-0013: a session envelope bound to the bare binding UID. What
/// an envelope stored with no marker is. Still read (ADR-0057 decision 10), never sealed
/// again. Also what an envelope that is not a session's carries (a batch of output), whose
/// context does not depend on the marker.
pub const FORMAT_BARE_UID: u8 = 1;
/// The envelope format of ADR-0057 decision 9: a session envelope bound to a label, the
/// binding UID and its [`Slot`].
pub const FORMAT_SLOT: u8 = 2;
/// The label a format 2 session context starts with.
const SESSION_CONTEXT: &[u8] = b"mediatore-session\0";

fn format_bare_uid() -> u8 {
    FORMAT_BARE_UID
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
fn is_bare_uid(format: &u8) -> bool {
    *format == FORMAT_BARE_UID
}

/// Sealed refresh material. Has no constructor that takes plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// Which key sealed it; the unsealer refuses an envelope under a key it does not hold.
    pub key_id: String,
    /// Fresh per envelope.
    pub nonce: Vec<u8>,
    /// AES-256-GCM output, tag included.
    pub ciphertext: Vec<u8>,
    /// Which context a session envelope was sealed under (ADR-0057 decision 10):
    /// [`FORMAT_BARE_UID`] when absent, [`FORMAT_SLOT`] for everything sealed since. In clear,
    /// and proves nothing: it chooses the context an envelope is opened under, and an
    /// envelope opens only under the one it was sealed with.
    #[serde(default = "format_bare_uid", skip_serializing_if = "is_bare_uid")]
    pub format: u8,
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
    /// The sealer's backend did not answer: an outage, not a refusal. The caller keeps the
    /// envelope and tries again later; nothing is revoked on it.
    #[error("sealer unavailable: {0}")]
    Unavailable(String),
    /// A caller asked for a format 1 session envelope to be sealed. Nothing seals one again
    /// (ADR-0057 decision 10): a broker bug, never a stored envelope's fault.
    #[error("format 1 session envelopes are read, never sealed (ADR-0057 decision 10)")]
    RetiredFormat,
}

/// Which of a sandbox's session envelopes one is (ADR-0057 decision 9). Part of the binding,
/// so an envelope of one slot never opens as another's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot<'a> {
    /// The issuer's session (ADR-0013): the refresh token.
    Issuer,
    /// A delegated credential for this audience (ADR-0035).
    Delegation(&'a str),
}

/// What an envelope is for. The purpose is part of the binding, so an envelope sealed for one
/// purpose never opens as another, whatever the claim and the key (ADR-0052 decision 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealPurpose<'a> {
    /// Session material as ADR-0013 sealed it (format 1): bound to the bare binding UID. For
    /// opening what is already stored; a sealer refuses to seal under it.
    SessionFormat1,
    /// Session material (ADR-0013, ADR-0035) since ADR-0057 (format 2): bound to a label, the
    /// binding UID and the slot.
    Session(Slot<'a>),
    /// A batch of a workload's stored output (ADR-0052): bound to a label and the claim UID.
    Logs,
}

impl SealPurpose<'_> {
    /// The binding bytes for `claim_uid`: the AEAD's associated data locally, the derivation
    /// context at transit. For a format 2 session: the label, the 16 bytes of the UID, then
    /// `0x00` for the issuer's slot or `0x01` and the audience for a delegation's. The UID has
    /// a fixed length and the audience is last, so no two inputs give the same bytes.
    #[must_use]
    pub fn context(self, claim_uid: Uuid) -> Vec<u8> {
        match self {
            Self::SessionFormat1 => claim_uid.as_bytes().to_vec(),
            Self::Session(slot) => {
                let mut ctx = SESSION_CONTEXT.to_vec();
                ctx.extend_from_slice(claim_uid.as_bytes());
                match slot {
                    Slot::Issuer => ctx.push(0x00),
                    Slot::Delegation(audience) => {
                        ctx.push(0x01);
                        ctx.extend_from_slice(audience.as_bytes());
                    }
                }
                ctx
            }
            Self::Logs => {
                let mut ctx = b"mediatore-logs\0".to_vec();
                ctx.extend_from_slice(claim_uid.as_bytes());
                ctx
            }
        }
    }

    /// The marker an envelope sealed for this purpose carries.
    #[must_use]
    pub fn format(self) -> u8 {
        match self {
            Self::Session(_) => FORMAT_SLOT,
            Self::SessionFormat1 | Self::Logs => FORMAT_BARE_UID,
        }
    }

    /// Whether anything may still be sealed for this purpose: everything but format 1.
    fn sealable(self) -> Result<(), SealError> {
        match self {
            Self::SessionFormat1 => Err(SealError::RetiredFormat),
            Self::Session(_) | Self::Logs => Ok(()),
        }
    }
}

/// Seals and unseals material bound to a claim and a purpose.
#[async_trait]
pub trait Sealer: Send + Sync + 'static {
    /// The id envelopes sealed here carry.
    fn key_id(&self) -> &str;
    /// Seal `plaintext` for `claim_uid` and `purpose`; the envelope carries
    /// [`SealPurpose::format`]. [`SealPurpose::SessionFormat1`] is refused with
    /// [`SealError::RetiredFormat`].
    async fn seal_with(
        &self,
        purpose: SealPurpose<'_>,
        claim_uid: Uuid,
        plaintext: &[u8],
    ) -> Result<Sealed, SealError>;
    /// Open `sealed`, which must have been sealed for `claim_uid` and `purpose` under a key
    /// this sealer holds.
    async fn unseal_with(
        &self,
        purpose: SealPurpose<'_>,
        claim_uid: Uuid,
        sealed: &Sealed,
    ) -> Result<Vec<u8>, SealError>;
    /// Seal session material for `binding` and `slot`: always format 2. There is no helper
    /// that seals format 1 (ADR-0057 decision 10).
    async fn seal_session(
        &self,
        slot: Slot<'_>,
        binding: Uuid,
        plaintext: &[u8],
    ) -> Result<Sealed, SealError> {
        self.seal_with(SealPurpose::Session(slot), binding, plaintext)
            .await
    }
    /// Open session material stored for `binding` and `slot`, under the context its format
    /// marker names: the bare UID for a format 1 envelope (which knew no slot), the slot's for
    /// format 2. The marker is in clear and only chooses: an envelope relabelled either way
    /// is opened under a context it was not sealed with, and does not open. A marker this
    /// broker does not know is [`SealError::Rejected`].
    async fn unseal_session(
        &self,
        slot: Slot<'_>,
        binding: Uuid,
        sealed: &Sealed,
    ) -> Result<Vec<u8>, SealError> {
        let purpose = match sealed.format {
            FORMAT_BARE_UID => SealPurpose::SessionFormat1,
            FORMAT_SLOT => SealPurpose::Session(slot),
            _ => return Err(SealError::Rejected),
        };
        self.unseal_with(purpose, binding, sealed).await
    }
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

#[async_trait]
impl Sealer for LocalKeySealer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn seal_with(
        &self,
        purpose: SealPurpose<'_>,
        claim_uid: Uuid,
        plaintext: &[u8],
    ) -> Result<Sealed, SealError> {
        purpose.sealable()?;
        let mut nonce = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce)
            .map_err(|_| SealError::Key("no randomness".into()))?;
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(purpose.context(claim_uid)),
                &mut buf,
            )
            .map_err(|_| SealError::Rejected)?;
        Ok(Sealed {
            key_id: self.key_id.clone(),
            nonce: nonce.to_vec(),
            ciphertext: buf,
            format: purpose.format(),
        })
    }

    async fn unseal_with(
        &self,
        purpose: SealPurpose<'_>,
        claim_uid: Uuid,
        sealed: &Sealed,
    ) -> Result<Vec<u8>, SealError> {
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
                Aad::from(purpose.context(claim_uid)),
                &mut buf,
            )
            .map_err(|_| SealError::Rejected)?;
        Ok(opened.to_vec())
    }
}

pub use mediatore_openbao::TransitConfig;

/// Envelopes sealed by `OpenBao` transit under a derived key, the binding bytes
/// ([`SealPurpose::context`]) as context.
pub struct TransitSealer {
    client: mediatore_openbao::Client,
    key: String,
    key_id: String,
}

impl std::fmt::Debug for TransitSealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitSealer")
            .field("client", &self.client)
            .field("key", &self.key)
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl From<mediatore_openbao::Error> for SealError {
    fn from(e: mediatore_openbao::Error) -> Self {
        use mediatore_openbao::Error;
        match e {
            Error::Unavailable(why) => SealError::Unavailable(why),
            Error::Denied(why) | Error::Config(why) => SealError::Key(why),
            // A 400 is OpenBao refusing the operation: a bad context, a tampered or
            // retired ciphertext, a missing key. Nothing to retry.
            Error::Rejected(_) => SealError::Rejected,
        }
    }
}

impl TransitSealer {
    /// Connect to `OpenBao`: build the client over `ca_file`, log in, and seal and unseal
    /// probes under a random binding, so a wrong URL, CA, role, policy, mount, key, a key
    /// created without derivation or one that does not bind the slot fails here, not at the
    /// first claim.
    pub async fn connect(cfg: &TransitConfig) -> Result<Self, SealError> {
        let client = mediatore_openbao::Client::connect(cfg).await?;
        let sealer = Self {
            key_id: format!("transit:{}/{}", client.mount(), cfg.key),
            client,
            key: cfg.key.clone(),
        };
        let probe = Uuid::new_v4();
        sealer.probe_sessions(probe).await?;
        sealer.probe_output(probe).await?;
        Ok(sealer)
    }

    /// The session contexts (ADR-0057 decision 9): a delegation's envelope round-trips, holds
    /// for its own binding only, and opens under no other audience, not as the issuer's
    /// session and not as a format 1 envelope; the issuer's round-trips and is no
    /// delegation's.
    async fn probe_sessions(&self, probe: Uuid) -> Result<(), SealError> {
        let slot = Slot::Delegation("probe-a");
        let envelope = self.seal_session(slot, probe, b"probe").await?;
        if self.unseal_session(slot, probe, &envelope).await? != b"probe" {
            return Err(SealError::Key("transit probe did not round-trip".into()));
        }
        if self
            .unseal_session(slot, Uuid::new_v4(), &envelope)
            .await
            .is_ok()
        {
            return Err(SealError::Key(format!(
                "transit key {} is not derived: the binding would not hold",
                self.key_id
            )));
        }
        let mut relabelled = envelope.clone();
        relabelled.format = FORMAT_BARE_UID;
        let other = Slot::Delegation("probe-b");
        if self.unseal_session(other, probe, &envelope).await.is_ok()
            || self
                .unseal_session(Slot::Issuer, probe, &envelope)
                .await
                .is_ok()
            || self.unseal_session(slot, probe, &relabelled).await.is_ok()
        {
            return Err(SealError::Key(format!(
                "transit key {} does not bind the slot: an audience's envelope would open as another's",
                self.key_id
            )));
        }
        let session = self.seal_session(Slot::Issuer, probe, b"probe").await?;
        if self.unseal_session(Slot::Issuer, probe, &session).await? != b"probe" {
            return Err(SealError::Key(
                "transit probe did not round-trip for the issuer's slot".into(),
            ));
        }
        if self.unseal_session(slot, probe, &session).await.is_ok() {
            return Err(SealError::Key(format!(
                "transit key {} does not bind the slot: the issuer's session would open as a delegation",
                self.key_id
            )));
        }
        Ok(())
    }

    /// The output's context (ADR-0052 decision 2): it round-trips, holds for its own claim
    /// only, and does not open as a session envelope of either format.
    async fn probe_output(&self, probe: Uuid) -> Result<(), SealError> {
        let blob = self.seal_with(SealPurpose::Logs, probe, b"probe").await?;
        if self.unseal_with(SealPurpose::Logs, probe, &blob).await? != b"probe" {
            return Err(SealError::Key(
                "transit probe did not round-trip for the output's context".into(),
            ));
        }
        if self
            .unseal_with(SealPurpose::Logs, Uuid::new_v4(), &blob)
            .await
            .is_ok()
            || self
                .unseal_with(SealPurpose::SessionFormat1, probe, &blob)
                .await
                .is_ok()
            || self
                .unseal_with(SealPurpose::Session(Slot::Issuer), probe, &blob)
                .await
                .is_ok()
        {
            return Err(SealError::Key(format!(
                "transit key {} does not bind the output's context",
                self.key_id
            )));
        }
        Ok(())
    }

    async fn call(
        &self,
        op: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, SealError> {
        Ok(self.client.call(op, &self.key, body).await?)
    }
}

#[async_trait]
impl Sealer for TransitSealer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn seal_with(
        &self,
        purpose: SealPurpose<'_>,
        claim_uid: Uuid,
        plaintext: &[u8],
    ) -> Result<Sealed, SealError> {
        use base64::Engine as _;
        purpose.sealable()?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let reply = self
            .call(
                "encrypt",
                serde_json::json!({
                    "plaintext": b64.encode(plaintext),
                    "context": b64.encode(purpose.context(claim_uid)),
                }),
            )
            .await?;
        let ciphertext = reply
            .get("data")
            .and_then(|d| d.get("ciphertext"))
            .and_then(|c| c.as_str())
            .ok_or_else(|| SealError::Unavailable("encrypt: no ciphertext in reply".into()))?;
        Ok(Sealed {
            key_id: self.key_id.clone(),
            nonce: Vec::new(),
            ciphertext: ciphertext.as_bytes().to_vec(),
            format: purpose.format(),
        })
    }

    async fn unseal_with(
        &self,
        purpose: SealPurpose<'_>,
        claim_uid: Uuid,
        sealed: &Sealed,
    ) -> Result<Vec<u8>, SealError> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        if sealed.key_id != self.key_id {
            return Err(SealError::UnknownKey(sealed.key_id.clone()));
        }
        let ciphertext =
            std::str::from_utf8(&sealed.ciphertext).map_err(|_| SealError::Rejected)?;
        let reply = self
            .call(
                "decrypt",
                serde_json::json!({
                    "ciphertext": ciphertext,
                    "context": b64.encode(purpose.context(claim_uid)),
                }),
            )
            .await?;
        let plaintext = reply
            .get("data")
            .and_then(|d| d.get("plaintext"))
            .and_then(|p| p.as_str())
            .ok_or_else(|| SealError::Unavailable("decrypt: no plaintext in reply".into()))?;
        b64.decode(plaintext).map_err(|_| SealError::Rejected)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl LocalKeySealer {
    /// A session envelope as a broker before ADR-0057 stored it: the bare binding UID as
    /// associated data, marked format 1. For the tests that prove such an envelope still
    /// opens; behind `test-support`, so no shipped binary can seal one.
    ///
    /// # Panics
    ///
    /// If there is no randomness or the AEAD refuses; this is test scaffolding.
    #[must_use]
    pub fn seal_format_1(&self, binding: Uuid, plaintext: &[u8]) -> Sealed {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce).expect("randomness");
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(SealPurpose::SessionFormat1.context(binding)),
                &mut buf,
            )
            .expect("seal");
        Sealed {
            key_id: self.key_id.clone(),
            nonce: nonce.to_vec(),
            ciphertext: buf,
            format: FORMAT_BARE_UID,
        }
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
        let env = s.seal_session(Slot::Issuer, uid, b"refresh").await.unwrap();
        assert_eq!(env.key_id, s.key_id());
        assert_eq!(env.nonce.len(), NONCE_LEN);
        assert_eq!(env.format, FORMAT_SLOT, "everything sealed now is format 2");
        assert_ne!(env.ciphertext, b"refresh");
        assert_eq!(
            s.unseal_session(Slot::Issuer, uid, &env).await.unwrap(),
            b"refresh"
        );

        assert!(matches!(
            s.unseal_session(Slot::Issuer, Uuid::new_v4(), &env).await,
            Err(SealError::Rejected)
        ));
        assert!(matches!(
            sealer(2).unseal_session(Slot::Issuer, uid, &env).await,
            Err(SealError::UnknownKey(_))
        ));
        let mut forged = env.clone();
        forged.key_id = sealer(2).key_id().to_owned();
        assert!(matches!(
            sealer(2).unseal_session(Slot::Issuer, uid, &forged).await,
            Err(SealError::Rejected)
        ));
        let mut tampered = env.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(matches!(
            s.unseal_session(Slot::Issuer, uid, &tampered).await,
            Err(SealError::Rejected)
        ));
    }

    #[tokio::test]
    async fn every_envelope_has_its_own_nonce() {
        let uid = Uuid::new_v4();
        let s = sealer(1);
        let a = s.seal_session(Slot::Issuer, uid, b"x").await.unwrap();
        let b = s.seal_session(Slot::Issuer, uid, b"x").await.unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn the_format_2_context_is_the_label_the_uid_and_the_slot() {
        let uid = Uuid::from_bytes([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ]);
        // The bytes, pinned: what the local sealer authenticates and what transit derives by.
        let mut issuer = b"mediatore-session\0".to_vec();
        issuer.extend_from_slice(&[
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ]);
        let mut delegation = issuer.clone();
        issuer.push(0x00);
        delegation.push(0x01);
        delegation.extend_from_slice(b"api.example");
        assert_eq!(SealPurpose::Session(Slot::Issuer).context(uid), issuer);
        assert_eq!(issuer.len(), 18 + 16 + 1);
        assert_eq!(
            SealPurpose::Session(Slot::Delegation("api.example")).context(uid),
            delegation
        );
        // Format 1 stays the bare UID, so what is stored still opens; the output's is its own.
        assert_eq!(
            SealPurpose::SessionFormat1.context(uid),
            uid.as_bytes().to_vec()
        );
        let logs = SealPurpose::Logs.context(uid);
        assert!(logs.starts_with(b"mediatore-logs\0"));
        assert!(logs.ends_with(uid.as_bytes()));
        assert_eq!(SealPurpose::Session(Slot::Issuer).format(), FORMAT_SLOT);
        assert_eq!(SealPurpose::SessionFormat1.format(), FORMAT_BARE_UID);
        assert_eq!(SealPurpose::Logs.format(), FORMAT_BARE_UID);
    }

    #[tokio::test]
    async fn a_delegation_opens_only_for_its_audience_and_never_as_the_issuers_session() {
        let uid = Uuid::new_v4();
        let s = sealer(1);
        let github = s
            .seal_session(Slot::Delegation("github"), uid, b"gh")
            .await
            .unwrap();
        assert_eq!(
            s.unseal_session(Slot::Delegation("github"), uid, &github)
                .await
                .unwrap(),
            b"gh"
        );
        // Another audience of the same sandbox, the issuer's slot, another sandbox: refused.
        assert!(matches!(
            s.unseal_session(Slot::Delegation("anthropic"), uid, &github)
                .await,
            Err(SealError::Rejected)
        ));
        assert!(matches!(
            s.unseal_session(Slot::Issuer, uid, &github).await,
            Err(SealError::Rejected)
        ));
        assert!(matches!(
            s.unseal_session(Slot::Delegation("github"), Uuid::new_v4(), &github)
                .await,
            Err(SealError::Rejected)
        ));
        // And the reverse: the issuer's session is no delegation's.
        let session = s.seal_session(Slot::Issuer, uid, b"refresh").await.unwrap();
        assert!(matches!(
            s.unseal_session(Slot::Delegation("github"), uid, &session)
                .await,
            Err(SealError::Rejected)
        ));
        assert!(matches!(
            s.unseal_session(Slot::Delegation(""), uid, &session).await,
            Err(SealError::Rejected)
        ));
    }

    #[test]
    fn no_two_slots_of_any_spelling_share_a_context() {
        let uid = Uuid::new_v4();
        // Audiences chosen to collide if the encoding were ambiguous: empty, a NUL, the
        // issuer's tag byte, a prefix of another, the label itself.
        let audiences = [
            "",
            "\0",
            "\u{1}",
            "a",
            "ab",
            "a\0b",
            "mediatore-session",
            "github",
            "GitHub",
        ];
        let mut seen: Vec<Vec<u8>> = vec![
            SealPurpose::Session(Slot::Issuer).context(uid),
            SealPurpose::SessionFormat1.context(uid),
            SealPurpose::Logs.context(uid),
        ];
        for a in audiences {
            seen.push(SealPurpose::Session(Slot::Delegation(a)).context(uid));
        }
        let total = seen.len();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), total, "two slots share a context");
        // The audience cannot reach into the UID: the UID is fixed-length and comes first.
        let other = Uuid::new_v4();
        assert_ne!(
            SealPurpose::Session(Slot::Delegation("a")).context(uid),
            SealPurpose::Session(Slot::Delegation("a")).context(other)
        );
    }

    #[tokio::test]
    async fn a_format_1_envelope_still_opens_under_the_bare_uid_and_a_relabelled_one_does_not() {
        let uid = Uuid::new_v4();
        let s = sealer(1);
        // What a broker before ADR-0057 stored: no slot in the binding, no marker.
        let old = s.seal_format_1(uid, b"refresh");
        assert_eq!(old.format, FORMAT_BARE_UID);
        // It knew no slot, so it opens for whichever slot its Secret is read as.
        assert_eq!(
            s.unseal_session(Slot::Issuer, uid, &old).await.unwrap(),
            b"refresh"
        );
        assert_eq!(
            s.unseal_session(Slot::Delegation("github"), uid, &old)
                .await
                .unwrap(),
            b"refresh"
        );
        assert!(matches!(
            s.unseal_session(Slot::Issuer, Uuid::new_v4(), &old).await,
            Err(SealError::Rejected)
        ));
        // The marker proves nothing: a 1 marked 2, or a 2 marked 1, does not open.
        let mut old_marked_new = old.clone();
        old_marked_new.format = FORMAT_SLOT;
        assert!(matches!(
            s.unseal_session(Slot::Issuer, uid, &old_marked_new).await,
            Err(SealError::Rejected)
        ));
        let new = s.seal_session(Slot::Issuer, uid, b"refresh").await.unwrap();
        let mut new_marked_old = new.clone();
        new_marked_old.format = FORMAT_BARE_UID;
        assert!(matches!(
            s.unseal_session(Slot::Issuer, uid, &new_marked_old).await,
            Err(SealError::Rejected)
        ));
        // A marker this broker does not know is refused before any key is used.
        let mut unknown = new.clone();
        unknown.format = 3;
        assert!(matches!(
            s.unseal_session(Slot::Issuer, uid, &unknown).await,
            Err(SealError::Rejected)
        ));
        // Nothing seals format 1 again.
        assert!(matches!(
            s.seal_with(SealPurpose::SessionFormat1, uid, b"x").await,
            Err(SealError::RetiredFormat)
        ));
    }

    #[test]
    fn the_format_marker_is_absent_for_1_and_written_for_2() {
        let old = Sealed {
            key_id: "k".into(),
            nonce: vec![1],
            ciphertext: vec![2],
            format: FORMAT_BARE_UID,
        };
        let v = serde_json::to_value(&old).unwrap();
        assert!(v.get("format").is_none(), "format 1 is the absent marker");
        assert_eq!(serde_json::from_value::<Sealed>(v).unwrap(), old);
        let new = Sealed {
            format: FORMAT_SLOT,
            ..old
        };
        let v = serde_json::to_value(&new).unwrap();
        assert_eq!(v["format"], 2);
        assert_eq!(serde_json::from_value::<Sealed>(v).unwrap(), new);
    }

    #[tokio::test]
    async fn an_output_blob_opens_under_no_session_slot() {
        let uid = Uuid::new_v4();
        let s = sealer(1);
        let blob = s
            .seal_with(SealPurpose::Logs, uid, b"output")
            .await
            .unwrap();
        assert_eq!(
            s.unseal_with(SealPurpose::Logs, uid, &blob).await.unwrap(),
            b"output"
        );
        // The same claim and key, every session context, whatever the marker says: refused.
        for format in [FORMAT_BARE_UID, FORMAT_SLOT] {
            let mut marked = blob.clone();
            marked.format = format;
            for slot in [Slot::Issuer, Slot::Delegation(""), Slot::Delegation("logs")] {
                assert!(matches!(
                    s.unseal_session(slot, uid, &marked).await,
                    Err(SealError::Rejected)
                ));
            }
        }
        // And no session envelope opens as output.
        let session = s.seal_session(Slot::Issuer, uid, b"refresh").await.unwrap();
        assert!(matches!(
            s.unseal_with(SealPurpose::Logs, uid, &session).await,
            Err(SealError::Rejected)
        ));
        let old = s.seal_format_1(uid, b"refresh");
        assert!(matches!(
            s.unseal_with(SealPurpose::Logs, uid, &old).await,
            Err(SealError::Rejected)
        ));
        // And a blob stays bound to its claim.
        assert!(matches!(
            s.unseal_with(SealPurpose::Logs, Uuid::new_v4(), &blob)
                .await,
            Err(SealError::Rejected)
        ));
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
