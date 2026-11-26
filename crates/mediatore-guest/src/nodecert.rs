// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The `node-cert` role (ADR-0049 Decisions 5 and 6, amended 2026-11-24): the certificate a
//! guest with no vTPM attests with, through SPIRE's `x509pop` node attestor.
//!
//! The guest makes an EC P-256 key, sends only a CSR to its own host on vsock port 1025, and
//! writes what comes back (the leaf, then the host CA's chain, possibly empty) as one file
//! beside the key
//! for the agent to read. The host's signer (banlieue ADR-0146, `banlieue-attestation-ca`)
//! takes only the public key, chooses the subject (the VM's UID) and the lifetime, and
//! answers one request per connection.
//!
//! Two modes, two units: `fetch` is the oneshot the agent's unit requires (no certificate, no
//! agent), `renew` runs beside the agent and fetches again with the same key at half the
//! remaining life. Both run as the agent's own user, with no capability. Nothing here logs
//! the key, the CSR or a certificate body.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PublicKeyData};
use x509_cert::Certificate;
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{Encode, EncodePem};

/// The host's CID on any vsock (the hypervisor).
pub use crate::ready::VSOCK_HOST_CID;

/// The port the host's per-guest signer listens on (banlieue ADR-0137 Decision 6, ADR-0146
/// Decision 2); the install report's is 1024.
pub const VSOCK_SIGNER_PORT: u32 = 1025;
/// Where the key and the certificate live: the agent's runtime directory, on `tmpfs`.
pub const DEFAULT_DIR: &str = "/run/spire/x509pop";
/// The private key, PKCS#8 PEM, `0600`. The agent's `private_key_path`.
pub const KEY_FILE: &str = "key.pem";
/// The leaf followed by the host CA's chain (none for a self-signed host CA). The agent's
/// `certificate_path`, which takes "the identity certificate followed by any intermediate
/// certificates"; no separate `intermediates_path`.
pub const CERT_FILE: &str = "cert.pem";
/// The largest reply accepted: a leaf and a chain of a few intermediates fit many times over.
pub const MAX_REPLY_BYTES: usize = 65_536;
/// How far ahead of the guest's clock a fresh certificate's `notBefore` may be. The signer
/// stamps the host's time and does not backdate, so a guest a little behind is normal.
pub const CLOCK_SKEW: Duration = Duration::from_secs(300);
/// The CSR's subject. Never used: the signer sets the subject itself (Decision 3).
const CSR_COMMON_NAME: &str = "mediatore-node-cert";
/// Connect, write and read bound on one request.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// The first retry's delay; each later one doubles, up to [`BACKOFF_MAX`].
pub const BACKOFF_FIRST: Duration = Duration::from_secs(2);
/// The longest delay between attempts.
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// `fetch` gives up after this many attempts and exits non-zero: the agent does not start.
pub const DEFAULT_FETCH_ATTEMPTS: u32 = 10;
/// The directory's mode: only the agent's user reads the key.
const DIR_MODE: u32 = 0o700;
/// The key's mode.
const KEY_MODE: u32 = 0o600;
/// The certificates' mode: public material.
const CERT_MODE: u32 = 0o644;
/// Permission bits other than the owner's.
const GROUP_WORLD_BITS: u32 = 0o077;
/// The temporary-file suffix, renamed over the real name once written.
const TMP_SUFFIX: &str = ".tmp";

/// `mediatore node-cert`.
#[derive(Args, Debug)]
pub struct NodeCertArgs {
    /// What to do.
    #[command(subcommand)]
    pub mode: Mode,
    /// The directory holding the key and the certificate.
    #[arg(long, env = "MEDIATORE_NODE_CERT_DIR", default_value = DEFAULT_DIR, global = true)]
    pub dir: PathBuf,
}

/// `fetch` or `renew`.
#[derive(Subcommand, Debug)]
pub enum Mode {
    /// Obtain a certificate before the agent starts; exit non-zero without one.
    Fetch {
        /// Attempts before giving up.
        #[arg(long, default_value_t = DEFAULT_FETCH_ATTEMPTS)]
        attempts: u32,
    },
    /// Beside the agent: fetch again, with the same key, at half the remaining life.
    Renew,
}

/// Why a reply was not accepted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplyError {
    /// No bytes: the signer refuses a request by closing without a reply.
    #[error("the host refused the request (no reply)")]
    Empty,
    /// More than [`MAX_REPLY_BYTES`].
    #[error("the reply is larger than {MAX_REPLY_BYTES} bytes")]
    TooLarge,
    /// Not a sequence of PEM `CERTIFICATE` blocks.
    #[error("the reply is not PEM certificates")]
    NotCertificates,
    /// The leaf certifies a key that is not this guest's.
    #[error("the certificate is not for this guest's key")]
    NotOurKey,
    /// `notBefore` is further ahead than [`CLOCK_SKEW`].
    #[error("the certificate is not valid yet")]
    NotYetValid,
    /// `notAfter` has passed.
    #[error("the certificate has expired")]
    Expired,
}

/// Why `node-cert` failed.
#[derive(Debug, thiserror::Error)]
pub enum NodeCertError {
    /// The reply was refused.
    #[error(transparent)]
    Reply(#[from] ReplyError),
    /// The vsock exchange or a file.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Key or CSR generation, or a key file that does not parse.
    #[error("key: {0}")]
    Key(String),
    /// The key file is readable by more than its owner.
    #[error("{0} is readable by group or others; refusing it")]
    KeyMode(PathBuf),
    /// A file the mode needs is absent or unreadable.
    #[error("{0}")]
    Missing(String),
}

/// A certificate the guest accepted: the leaf and the chain above it, in reply order.
#[derive(Debug)]
pub struct Issued {
    leaf: Certificate,
    chain: Vec<Certificate>,
}

impl Issued {
    /// `notAfter`, as a duration since the Unix epoch.
    #[must_use]
    pub fn not_after(&self) -> Duration {
        self.leaf
            .tbs_certificate()
            .validity()
            .not_after
            .to_unix_duration()
    }

    /// The serial number, hex: logged in place of the certificate.
    #[must_use]
    pub fn serial_hex(&self) -> String {
        hex::encode(self.leaf.tbs_certificate().serial_number().as_bytes())
    }

    /// The issuer, RFC 4514: logged in place of the certificate.
    #[must_use]
    pub fn issuer(&self) -> String {
        self.leaf.tbs_certificate().issuer().to_string()
    }

    /// The number of chain certificates the host sent.
    #[must_use]
    pub fn chain_len(&self) -> usize {
        self.chain.len()
    }

    /// The leaf, PEM.
    ///
    /// # Errors
    /// Re-encoding failed (it was parsed from DER, so it does not in practice).
    pub fn leaf_pem(&self) -> Result<String, ReplyError> {
        self.leaf
            .to_pem(LineEnding::LF)
            .map_err(|_| ReplyError::NotCertificates)
    }

    /// The chain, PEM, concatenated; empty for a self-signed host CA.
    ///
    /// # Errors
    /// As [`Issued::leaf_pem`].
    pub fn chain_pem(&self) -> Result<String, ReplyError> {
        self.chain
            .iter()
            .map(|c| c.to_pem(LineEnding::LF))
            .collect::<Result<String, _>>()
            .map_err(|_| ReplyError::NotCertificates)
    }

    /// The leaf followed by the chain: what the agent's `certificate_path` holds. One file,
    /// never a separate `intermediates_path`, which SPIRE refuses when it holds no
    /// certificate, as it would for every self-signed host CA.
    ///
    /// # Errors
    /// As [`Issued::leaf_pem`].
    pub fn bundle_pem(&self) -> Result<String, ReplyError> {
        Ok(self.leaf_pem()? + &self.chain_pem()?)
    }
}

/// A new EC P-256 key (Decision 3: the one key type the signer accepts).
///
/// # Errors
/// The crypto provider failed to generate one.
pub fn new_key() -> Result<KeyPair, NodeCertError> {
    KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| NodeCertError::Key(e.to_string()))
}

/// The CSR for `key`, PEM. Its subject is a placeholder the signer ignores.
///
/// # Errors
/// Signing the request failed.
pub fn csr_pem(key: &KeyPair) -> Result<String, NodeCertError> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CSR_COMMON_NAME);
    params.distinguished_name = dn;
    params
        .serialize_request(key)
        .and_then(|csr| csr.pem())
        .map_err(|e| NodeCertError::Key(e.to_string()))
}

/// Accept or refuse the host's reply: bounded, PEM certificates only, the leaf for `key`,
/// valid at `now` (a duration since the Unix epoch, allowing [`CLOCK_SKEW`] on `notBefore`).
///
/// The subject is not checked: the guest does not name itself (Decision 3), and the server's
/// chain verification and the declared node entry are the checks that count.
///
/// # Errors
/// [`ReplyError`] says which check failed.
pub fn parse_reply(reply: &[u8], key: &KeyPair, now: Duration) -> Result<Issued, ReplyError> {
    if reply.is_empty() {
        return Err(ReplyError::Empty);
    }
    if reply.len() > MAX_REPLY_BYTES {
        return Err(ReplyError::TooLarge);
    }
    let mut certs = Certificate::load_pem_chain(reply).map_err(|_| ReplyError::NotCertificates)?;
    if certs.is_empty() {
        return Err(ReplyError::NotCertificates);
    }
    let leaf = certs.remove(0);
    let tbs = leaf.tbs_certificate();
    let spki = tbs
        .subject_public_key_info()
        .to_der()
        .map_err(|_| ReplyError::NotCertificates)?;
    if spki != key.subject_public_key_info() {
        return Err(ReplyError::NotOurKey);
    }
    let validity = tbs.validity();
    if validity.not_before.to_unix_duration() > now + CLOCK_SKEW {
        return Err(ReplyError::NotYetValid);
    }
    if validity.not_after.to_unix_duration() <= now {
        return Err(ReplyError::Expired);
    }
    Ok(Issued { leaf, chain: certs })
}

/// How long to wait before renewing a certificate that expires at `not_after`: half of what
/// remains at `now`, zero when it has already passed.
#[must_use]
pub fn renew_after(not_after: Duration, now: Duration) -> Duration {
    not_after.saturating_sub(now) / 2
}

/// The delay before attempt `attempt + 1`: [`BACKOFF_FIRST`] doubling, capped at
/// [`BACKOFF_MAX`]. Spaced so the first minute stays under the host signer's per-guest rate
/// limit.
#[must_use]
pub fn backoff(attempt: u32) -> Duration {
    BACKOFF_FIRST
        .checked_mul(1_u32.checked_shl(attempt).unwrap_or(u32::MAX))
        .map_or(BACKOFF_MAX, |d| d.min(BACKOFF_MAX))
}

/// A stream whose write half can be closed alone: the signer reads the CSR to EOF.
pub trait HalfClose: Read + Write {
    /// Close the write half.
    ///
    /// # Errors
    /// The socket refused the shutdown.
    fn close_write(&self) -> io::Result<()>;
}

impl HalfClose for std::os::unix::net::UnixStream {
    fn close_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

#[cfg(target_os = "linux")]
impl HalfClose for socket2::Socket {
    fn close_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

/// One request: write the CSR, half-close, read the reply up to [`MAX_REPLY_BYTES`] (one
/// more byte is read to tell a reply at the cap from one over it).
///
/// # Errors
/// The stream failed, or the reply is over the cap.
pub fn exchange<S: HalfClose>(mut stream: S, csr: &str) -> Result<Vec<u8>, NodeCertError> {
    stream.write_all(csr.as_bytes())?;
    stream.flush()?;
    stream.close_write()?;
    let mut reply = Vec::new();
    let cap = u64::try_from(MAX_REPLY_BYTES).unwrap_or(u64::MAX) + 1;
    stream.take(cap).read_to_end(&mut reply)?;
    if reply.len() > MAX_REPLY_BYTES {
        return Err(ReplyError::TooLarge.into());
    }
    Ok(reply)
}

/// A connected, time-bounded stream to the host's signer.
#[cfg(target_os = "linux")]
fn connect() -> io::Result<socket2::Socket> {
    let addr = socket2::SockAddr::vsock(VSOCK_HOST_CID, VSOCK_SIGNER_PORT);
    let s = socket2::Socket::new(socket2::Domain::VSOCK, socket2::Type::STREAM, None)?;
    s.connect_timeout(&addr, IO_TIMEOUT)?;
    s.set_read_timeout(Some(IO_TIMEOUT))?;
    s.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(s)
}

/// vsock is a Linux socket family: elsewhere the role fails closed.
#[cfg(not(target_os = "linux"))]
fn connect() -> io::Result<std::os::unix::net::UnixStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "node-cert needs vsock, which is Linux only",
    ))
}

/// The key in `dir`, created `0600` (and the directory `0700`) when absent. A key file
/// readable by group or others is refused, not repaired.
///
/// # Errors
/// The directory or file could not be made or read, the mode is too open, or the file does
/// not hold a key.
pub fn load_or_create_key(dir: &Path) -> Result<KeyPair, NodeCertError> {
    DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(dir)?;
    let path = dir.join(KEY_FILE);
    match fs::metadata(&path) {
        Ok(_) => load_key(&path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = new_key()?;
            write_atomic(&path, key.serialize_pem().as_bytes(), KEY_MODE)?;
            Ok(key)
        }
        Err(e) => Err(e.into()),
    }
}

/// The key at `path`, refused when readable by more than its owner.
fn load_key(path: &Path) -> Result<KeyPair, NodeCertError> {
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & GROUP_WORLD_BITS != 0 {
        return Err(NodeCertError::KeyMode(path.to_path_buf()));
    }
    let pem = fs::read_to_string(path)?;
    KeyPair::from_pem(&pem).map_err(|e| NodeCertError::Key(e.to_string()))
}

/// Write the leaf and the chain into `dir` as one file ([`Issued::bundle_pem`]), by rename, so
/// the agent never reads a leaf without its chain.
///
/// # Errors
/// The file could not be written or renamed.
pub fn store(dir: &Path, issued: &Issued) -> Result<(), NodeCertError> {
    write_atomic(
        &dir.join(CERT_FILE),
        issued.bundle_pem()?.as_bytes(),
        CERT_MODE,
    )?;
    Ok(())
}

/// Write `bytes` to a temporary name beside `path` with `mode`, sync, then rename over `path`.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(TMP_SUFFIX);
    let tmp = PathBuf::from(tmp_name);
    // A leftover from an interrupted run would make `create_new` fail; it holds nothing the
    // next write does not replace.
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

/// The current time as a duration since the Unix epoch.
fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// One request to the host and the reply checked; nothing is written.
async fn request(key: &KeyPair) -> Result<Issued, NodeCertError> {
    let csr = csr_pem(key)?;
    let reply = tokio::task::spawn_blocking(move || exchange(connect()?, &csr))
        .await
        .map_err(|e| NodeCertError::Io(io::Error::other(e)))??;
    Ok(parse_reply(&reply, key, now())?)
}

/// Request until one succeeds, `attempts` at most (`None`: without end), backing off between.
async fn request_with_backoff(
    dir: &Path,
    key: &KeyPair,
    attempts: Option<u32>,
) -> Result<Issued, NodeCertError> {
    let mut attempt = 0_u32;
    loop {
        match request(key).await {
            Ok(issued) => {
                store(dir, &issued)?;
                tracing::info!(
                    serial = %issued.serial_hex(),
                    issuer = %issued.issuer(),
                    chain = issued.chain_len(),
                    not_after = issued.not_after().as_secs(),
                    "node certificate written"
                );
                return Ok(issued);
            }
            Err(e) => {
                attempt = attempt.saturating_add(1);
                if attempts.is_some_and(|max| attempt >= max) {
                    tracing::error!(error = %e, attempt, "no node certificate; giving up");
                    return Err(e);
                }
                let wait = backoff(attempt - 1);
                tracing::warn!(error = %e, attempt, retry_in_secs = wait.as_secs(), "node certificate request failed");
                tokio::time::sleep(wait).await;
            }
        }
    }
}

/// The `not_after` of the leaf on disk.
fn leaf_not_after(dir: &Path) -> Result<Duration, NodeCertError> {
    let pem = fs::read(dir.join(CERT_FILE))
        .map_err(|e| NodeCertError::Missing(format!("{CERT_FILE}: {e}")))?;
    let leaf = Certificate::load_pem_chain(&pem)
        .ok()
        .and_then(|mut c| (!c.is_empty()).then(|| c.remove(0)))
        .ok_or_else(|| NodeCertError::Missing(format!("{CERT_FILE} holds no certificate")))?;
    Ok(leaf
        .tbs_certificate()
        .validity()
        .not_after
        .to_unix_duration())
}

/// Run the role.
///
/// # Errors
/// `fetch`: no certificate within the attempts. `renew`: no key or no leaf on disk to renew.
pub async fn run(args: NodeCertArgs) -> Result<(), NodeCertError> {
    match args.mode {
        Mode::Fetch { attempts } => {
            let key = load_or_create_key(&args.dir)?;
            request_with_backoff(&args.dir, &key, Some(attempts.max(1)))
                .await
                .map(|_| ())
        }
        Mode::Renew => {
            let key = load_key(&args.dir.join(KEY_FILE))?;
            loop {
                let wait = renew_after(leaf_not_after(&args.dir)?, now());
                tracing::info!(
                    renew_in_secs = wait.as_secs(),
                    "next node certificate renewal"
                );
                tokio::time::sleep(wait).await;
                // Without end: a renewal that keeps failing leaves the current files, and the
                // agent ends itself one SVID lifetime after they expire (fail closed).
                request_with_backoff(&args.dir, &key, None).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, IsCa, Issuer, KeyUsagePurpose};
    use std::os::unix::net::UnixStream;
    use std::thread;

    /// The host's rate limit (banlieue-attestation-ca `DEFAULT_MAX_REQUESTS` per minute).
    const HOST_MAX_REQUESTS: usize = 6;
    const HOST_WINDOW: Duration = Duration::from_secs(60);
    const HOUR: Duration = Duration::from_hours(1);

    /// `n` less `d`, checked: the test clock is far from the epoch.
    fn before(n: Duration, d: Duration) -> Duration {
        n.checked_sub(d).unwrap()
    }

    fn unix_now() -> Duration {
        now()
    }

    fn at(d: Duration) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(i64::try_from(d.as_secs()).unwrap()).unwrap()
    }

    /// A host CA, as the signer holds one.
    fn ca(cn: &str) -> (CertificateParams, KeyPair) {
        let key = new_key().unwrap();
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        (p, key)
    }

    /// What the signer issues for `guest_key`: subject the UID it chose, CA:FALSE,
    /// digitalSignature, valid from `from` to `to`.
    fn leaf_for(
        guest_key: &KeyPair,
        ca: &(CertificateParams, KeyPair),
        from: Duration,
        to: Duration,
    ) -> String {
        let mut p = CertificateParams::default();
        p.distinguished_name
            .push(DnType::CommonName, "0b6f9f0e-2c64-4c61-9f43-0a1b2c3d4e5f");
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.not_before = at(from);
        p.not_after = at(to);
        let issuer = Issuer::new(ca.0.clone(), &ca.1);
        p.signed_by(guest_key, &issuer).unwrap().pem()
    }

    fn valid_leaf(guest_key: &KeyPair) -> String {
        let n = unix_now();
        leaf_for(guest_key, &ca("host-a"), before(n, HOUR), n + HOUR)
    }

    #[test]
    fn the_csr_carries_the_guests_p256_key() {
        use x509_cert::der::DecodePem;
        let key = new_key().unwrap();
        let csr = x509_cert::request::CertReq::from_pem(csr_pem(&key).unwrap()).unwrap();
        assert_eq!(
            csr.info.public_key.to_der().unwrap(),
            key.subject_public_key_info()
        );
        let curve: x509_cert::der::asn1::ObjectIdentifier = csr
            .info
            .public_key
            .algorithm
            .parameters
            .as_ref()
            .unwrap()
            .decode_as()
            .unwrap();
        assert_eq!(
            curve.to_string(),
            "1.2.840.10045.3.1.7",
            "P-256 is the one curve the signer accepts"
        );
    }

    #[test]
    fn the_csr_holds_no_private_key() {
        let key = new_key().unwrap();
        let csr = csr_pem(&key).unwrap();
        assert!(csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(!csr.contains("PRIVATE KEY"));
    }

    #[test]
    fn a_leaf_alone_is_accepted() {
        let key = new_key().unwrap();
        let issued = parse_reply(valid_leaf(&key).as_bytes(), &key, unix_now()).unwrap();
        assert_eq!(issued.chain_len(), 0);
        assert_eq!(issued.chain_pem().unwrap(), "");
        assert!(issued.issuer().contains("host-a"));
    }

    #[test]
    fn a_leaf_and_the_host_cas_chain_are_split() {
        let key = new_key().unwrap();
        let host = ca("host-a");
        let host_cert = host.0.self_signed(&host.1).unwrap().pem();
        let n = unix_now();
        let reply = format!(
            "{}{host_cert}",
            leaf_for(&key, &host, before(n, HOUR), n + HOUR)
        );
        let issued = parse_reply(reply.as_bytes(), &key, n).unwrap();
        assert_eq!(issued.chain_len(), 1);
        assert_eq!(issued.chain_pem().unwrap(), host_cert);
        assert!(
            issued
                .leaf_pem()
                .unwrap()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );

        // Stored as one file, leaf first: the agent's certificate_path.
        let dir = tempfile::tempdir().unwrap();
        store(dir.path(), &issued).unwrap();
        let written = fs::read(dir.path().join(CERT_FILE)).unwrap();
        let certs = Certificate::load_pem_chain(&written).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(
            certs[0].to_pem(LineEnding::LF).unwrap(),
            issued.leaf_pem().unwrap()
        );
        assert_eq!(leaf_not_after(dir.path()).unwrap(), issued.not_after());
    }

    #[test]
    fn a_certificate_for_another_key_is_refused() {
        let ours = new_key().unwrap();
        let theirs = new_key().unwrap();
        assert_eq!(
            parse_reply(valid_leaf(&theirs).as_bytes(), &ours, unix_now()).unwrap_err(),
            ReplyError::NotOurKey
        );
    }

    #[test]
    fn an_expired_certificate_is_refused() {
        let key = new_key().unwrap();
        let n = unix_now();
        let leaf = leaf_for(&key, &ca("host-a"), before(n, HOUR * 2), before(n, HOUR));
        assert_eq!(
            parse_reply(leaf.as_bytes(), &key, n).unwrap_err(),
            ReplyError::Expired
        );
    }

    #[test]
    fn a_host_clock_ahead_within_the_skew_is_tolerated_and_beyond_it_refused() {
        let key = new_key().unwrap();
        let n = unix_now();
        let host = ca("host-a");
        let near = leaf_for(&key, &host, n + CLOCK_SKEW / 2, n + HOUR);
        assert!(parse_reply(near.as_bytes(), &key, n).is_ok());
        let far = leaf_for(&key, &host, n + CLOCK_SKEW + HOUR, n + HOUR + HOUR);
        assert_eq!(
            parse_reply(far.as_bytes(), &key, n).unwrap_err(),
            ReplyError::NotYetValid
        );
    }

    #[test]
    fn an_empty_reply_is_the_hosts_refusal() {
        let key = new_key().unwrap();
        assert_eq!(
            parse_reply(b"", &key, unix_now()).unwrap_err(),
            ReplyError::Empty
        );
    }

    #[test]
    fn junk_and_a_private_key_are_not_certificates() {
        let key = new_key().unwrap();
        for reply in [
            b"not pem at all".to_vec(),
            key.serialize_pem().into_bytes(),
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_vec(),
        ] {
            assert_eq!(
                parse_reply(&reply, &key, unix_now()).unwrap_err(),
                ReplyError::NotCertificates
            );
        }
    }

    #[test]
    fn an_oversized_reply_is_refused_before_parsing() {
        let key = new_key().unwrap();
        let reply = vec![b'A'; MAX_REPLY_BYTES + 1];
        assert_eq!(
            parse_reply(&reply, &key, unix_now()).unwrap_err(),
            ReplyError::TooLarge
        );
    }

    #[test]
    fn renewal_is_at_half_the_remaining_life_and_immediate_when_expired() {
        let n = unix_now();
        assert_eq!(renew_after(n + HOUR, n), HOUR / 2);
        assert_eq!(renew_after(n, n), Duration::ZERO);
        assert_eq!(renew_after(before(n, HOUR), n), Duration::ZERO);
    }

    #[test]
    fn backoff_doubles_from_the_first_delay_and_is_capped() {
        assert_eq!(backoff(0), BACKOFF_FIRST);
        assert_eq!(backoff(1), BACKOFF_FIRST * 2);
        assert_eq!(backoff(2), BACKOFF_FIRST * 4);
        assert_eq!(backoff(10), BACKOFF_MAX);
        assert_eq!(backoff(u32::MAX), BACKOFF_MAX);
    }

    #[test]
    fn retries_stay_under_the_hosts_rate_limit_in_any_window() {
        // The attempt times: 0, then each after the previous one's backoff.
        let mut t = Duration::ZERO;
        let mut times = vec![t];
        for attempt in 0..40 {
            t += backoff(attempt);
            times.push(t);
        }
        for (i, start) in times.iter().enumerate() {
            let in_window = times[i..]
                .iter()
                .take_while(|&&x| x < *start + HOST_WINDOW)
                .count();
            assert!(
                in_window < HOST_MAX_REQUESTS,
                "{in_window} attempts within a window from {start:?}"
            );
        }
    }

    #[test]
    fn the_exchange_half_closes_and_reads_the_whole_reply() {
        let (guest, host) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let mut host = host;
            let mut csr = String::new();
            // Returns only at EOF: the guest must half-close.
            host.read_to_string(&mut csr).unwrap();
            host.write_all(b"REPLY").unwrap();
            csr
        });
        let reply = exchange(guest, "CSR").unwrap();
        assert_eq!(server.join().unwrap(), "CSR");
        assert_eq!(reply, b"REPLY");
    }

    #[test]
    fn the_exchange_refuses_a_reply_over_the_cap() {
        let (guest, host) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let mut host = host;
            let mut sink = Vec::new();
            host.read_to_end(&mut sink).unwrap();
            // The guest stops reading at the cap and drops the stream: a broken pipe here is
            // the guest doing its job.
            let _ = host.write_all(&vec![b'A'; MAX_REPLY_BYTES + 2]);
        });
        let err = exchange(guest, "CSR").unwrap_err();
        server.join().unwrap();
        assert!(matches!(err, NodeCertError::Reply(ReplyError::TooLarge)));
    }

    #[test]
    fn the_key_is_created_once_owner_only_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("x509pop");
        let first = load_or_create_key(&d).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&d), DIR_MODE);
        assert_eq!(mode(&d.join(KEY_FILE)), KEY_MODE);
        let second = load_or_create_key(&d).unwrap();
        assert_eq!(
            first.subject_public_key_info(),
            second.subject_public_key_info(),
            "renewal reuses the key"
        );
    }

    #[test]
    fn a_key_readable_by_others_is_refused_not_repaired() {
        let dir = tempfile::tempdir().unwrap();
        load_or_create_key(dir.path()).unwrap();
        let key = dir.path().join(KEY_FILE);
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_or_create_key(dir.path()).unwrap_err(),
            NodeCertError::KeyMode(_)
        ));
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o644,
            "left as found"
        );
    }

    #[test]
    fn store_writes_a_lone_leaf_and_no_empty_chain_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_key(dir.path()).unwrap();
        let issued = parse_reply(valid_leaf(&key).as_bytes(), &key, unix_now()).unwrap();
        store(dir.path(), &issued).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join(CERT_FILE)).unwrap(),
            issued.leaf_pem().unwrap()
        );
        // SPIRE refuses an intermediates file with no certificate in it.
        assert!(!dir.path().join("chain.pem").exists());
        assert_eq!(leaf_not_after(dir.path()).unwrap(), issued.not_after());
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(TMP_SUFFIX))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn renew_without_a_leaf_on_disk_says_so() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            leaf_not_after(dir.path()).unwrap_err(),
            NodeCertError::Missing(_)
        ));
    }
}
