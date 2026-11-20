// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Upstream identity providers.
//!
//! Three responsibilities:
//! 1. Validate the bearer token a caller presents to `POST /v1/claims` (issuer, audience,
//!    signature via JWKS, expiry, and the per-issuer authorisation gate).
//! 2. For an issuer with a `session`, refresh the delegated upstream session before every
//!    issue and validate the ID token it returns the same way (ADR-0013).
//! 3. For an Entra issuer (ADR-0016), exchange the caller's access token On-Behalf-Of at
//!    claim creation for a refresh token, and before every issue refresh that session for
//!    the audience's resource, authenticating as the broker with a client assertion
//!    ([`assertion::ClientAssertion`]).

pub mod assertion;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use assertion::{ClientAssertion, EntraConfig};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use mediatore_proto::{Secret, Subject};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// How long a fetched JWKS may be served from cache before it is re-fetched.
const JWKS_CACHE_TTL_SECS: u64 = 300;

/// The least time between two fetches of one issuer's keys while a previously fetched set is
/// held. A `kid` the held set does not have is answered from that set, with no fetch, until
/// this long after the last fetch began; and after a fetch that failed, the next one waits
/// this long. An unauthenticated caller choosing `kid` values cannot ask the issuer more often.
const JWKS_REFETCH_INTERVAL_SECS: u64 = 30;

/// How old a key set may get while the issuer cannot be asked for a newer one. Past the cache
/// TTL a set is served only when its re-fetch failed, and never past this: then validation
/// fails with the outage.
const JWKS_MAX_STALE_SECS: u64 = 3600;

/// How long a connection to an issuer may take to open. An issuer that does not answer is an
/// outage ([`IdpError::Upstream`]), never a request that waits for ever.
const IDP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one call to an issuer may take from the request to the last byte of the answer.
/// Every call here is a small request with a small answer (discovery, the JWKS, one token
/// grant); none is a stream. It also bounds how long the per-issuer fetch gate is held.
const IDP_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Clock skew allowed between the issuer and the broker, in seconds, on both `exp` and `nbf`:
/// a token is accepted up to this long after it expired and up to this long before it becomes
/// valid. Stated here on purpose, so it does not move with the library's default.
const CLOCK_SKEW_LEEWAY_SECS: u64 = 60;

/// The registered claims a token must carry to be looked at. Without `aud` in this list the
/// library skips the audience check for a token that has no `aud` at all, and the same holds
/// for `iss`.
const REQUIRED_CLAIMS: &[&str] = &["exp", "aud", "iss"];

/// Which exchange mechanism serves an issuer, or mints for an audience.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// Entra ID On-Behalf-Of: mediatore is a confidential client with a certificate credential.
    EntraObo,
    /// mediatore signs its own tokens (see `mediatore-sts`); upstream is only for login.
    Sts,
    /// Nothing is minted: an audience the workload reaches through the egress proxy without
    /// a credential, its endpoints, rules and CA still the route's (ADR-0025 decision 8).
    /// Never an issuer's backend; the configuration refuses it there.
    None,
    /// The caller's own credential for the audience, delegated with the claim, sealed per
    /// audience and placed by the proxy (ADR-0035). Never an issuer's backend; the
    /// configuration refuses it there.
    Delegated,
    /// An operator-held credential for the audience, read from `secret_file` at start and
    /// placed by the proxy in the header the audience names (ADR-0032). Never an issuer's.
    Secret,
}

/// The delegated upstream session an issuer requires (ADR-0013): the caller hands over
/// the refresh token it got as `client_id` (a public client, no secret), and mediatore
/// refreshes it before every issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// The OAuth client the refresh token was issued to; `mediatore login` uses
    /// mediatore's own public client, so this is normally the issuer's `client_id`.
    pub client_id: String,
    /// A file holding the client's secret, for an issuer whose token endpoint wants one
    /// even from a public client (Google's installed-app clients, ADR-0017). Not a
    /// credential anyone relies on; read at startup (`Validator::with_session_secret`).
    #[serde(default)]
    pub client_secret_file: Option<std::path::PathBuf>,
}

/// One trusted issuer, from config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    /// `iss` value, byte-for-byte.
    pub url: String,
    /// Exchange mechanism.
    pub backend: Backend,
    /// Our client id at this issuer; also the required `aud`.
    pub client_id: String,
    /// Claim carrying the subject id: `oid` for Entra, `preferred_username` for Dex.
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
    /// Alias for `required_groups` with one entry (ADR-0046 decision 1). Exactly one of
    /// `required_group`, `required_groups` and `allow_any_authenticated: true` is set;
    /// [`IssuerConfig::gate`] enforces it.
    #[serde(default)]
    pub required_group: Option<String>,
    /// Groups of which the token must carry at least one (Dex `groups`, Entra
    /// `groups`/`roles`), matched exactly (ADR-0046 decisions 1 and 2). `None` is absent;
    /// `Some(vec![])` is an empty list, which is refused.
    #[serde(default)]
    pub required_groups: Option<Vec<String>>,
    /// The explicit "no group gate": any authenticated person of this issuer may log in
    /// (ADR-0046 decision 19). `false` counts as absent.
    #[serde(default)]
    pub allow_any_authenticated: bool,
    /// The claim that carries the groups, when it is not `groups` or `roles`: Auth0 puts
    /// them under a namespaced claim such as `https://example.com/groups` (ADR-0017).
    /// When set, only that claim is read.
    #[serde(default)]
    pub groups_claim: Option<String>,
    /// Set when claims from this issuer must delegate a refresh token (ADR-0013).
    #[serde(default)]
    pub session: Option<SessionConfig>,
    /// Set for an Entra issuer (`backend: entra-obo`, ADR-0016): the broker's credential
    /// for the On-Behalf-Of exchange and the refreshes. Exclusive with `session`: the
    /// Entra session comes from the exchange, not from the caller.
    #[serde(default)]
    pub entra: Option<EntraConfig>,
    /// A PEM file with the CA certificates that sign this issuer's TLS certificate, for an
    /// issuer on a private PKI. When set, discovery, JWKS and token requests to this issuer
    /// trust exactly those certificates and not the public roots. Read at startup
    /// (`Validator::with_issuer_ca`); a missing or empty file stops the process.
    #[serde(default)]
    pub ca_file: Option<std::path::PathBuf>,
}

fn default_subject_claim() -> String {
    "oid".to_owned()
}

/// The login gate of one issuer, resolved and validated (ADR-0046 decisions 1, 18, 19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// The token must carry at least one of these groups, exactly. Built from
    /// `required_groups`, or from `required_group` as a one-element list.
    Groups(Vec<String>),
    /// No group gate, written down as `allow_any_authenticated: true`.
    AnyAuthenticated,
}

impl std::fmt::Display for Gate {
    /// `required_groups (<values>)`, `required_group (<value>)` for a single entry, or
    /// `none (explicit)`. Values are configuration, never token content.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AnyAuthenticated => f.write_str("none (explicit)"),
            Self::Groups(g) => write!(f, "required_groups ({})", g.join(", ")),
        }
    }
}

/// A gate configuration the broker refuses to start with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("issuer {issuer}: {reason}")]
pub struct GateError {
    issuer: String,
    reason: String,
}

impl IssuerConfig {
    /// Resolve and validate this issuer's gate: exactly one of `required_group`,
    /// `required_groups`, `allow_any_authenticated: true`; no empty list, blank,
    /// whitespace-padded or duplicate entry. The error names the issuer url and the keys.
    ///
    /// # Errors
    /// [`GateError`] for any of the refused shapes.
    pub fn gate(&self) -> Result<Gate, GateError> {
        let err = |reason: &str| GateError {
            issuer: self.url.clone(),
            reason: reason.to_owned(),
        };
        let set = usize::from(self.required_group.is_some())
            + usize::from(self.required_groups.is_some())
            + usize::from(self.allow_any_authenticated);
        match set {
            0 => {
                return Err(err(
                    "no login gate: set one of required_group, required_groups, or \
                     allow_any_authenticated: true",
                ));
            }
            1 => {}
            _ => {
                return Err(err(
                    "more than one of required_group, required_groups, allow_any_authenticated \
                     is set; set exactly one",
                ));
            }
        }
        if self.allow_any_authenticated {
            return Ok(Gate::AnyAuthenticated);
        }
        let (key, list) = match (&self.required_group, &self.required_groups) {
            (Some(one), _) => ("required_group", vec![one.clone()]),
            (_, Some(many)) => ("required_groups", many.clone()),
            (None, None) => unreachable!("exactly one key is set"),
        };
        if list.is_empty() {
            return Err(err(
                "required_groups is empty; an empty list is not a gate (use \
                 allow_any_authenticated: true for none)",
            ));
        }
        for (i, g) in list.iter().enumerate() {
            if g.trim().is_empty() {
                return Err(err(&format!("{key} has an empty or blank entry")));
            }
            if g.trim() != g {
                return Err(err(&format!(
                    "{key} has an entry with leading or trailing whitespace"
                )));
            }
            if list[..i].contains(g) {
                return Err(err(&format!("{key} has a duplicate entry")));
            }
        }
        Ok(Gate::Groups(list))
    }
}

impl IssuerConfig {
    /// The gate form for the startup log (ADR-0046 decision 18): `required_groups (<values>)`,
    /// `required_group (<value>)` for the alias, or `none (explicit)`. Values are
    /// configuration, never token content.
    ///
    /// # Errors
    /// [`GateError`] when the gate is invalid, as [`Self::gate`].
    pub fn gate_form(&self) -> Result<String, GateError> {
        let gate = self.gate()?;
        Ok(match (&gate, &self.required_group) {
            (Gate::Groups(g), Some(_)) => format!("required_group ({})", g.join(", ")),
            _ => gate.to_string(),
        })
    }
}

/// Whether the token's groups and the listed groups share a value. Exact, case-sensitive,
/// no prefix stripping: `org:ADMIN` and `ADMIN` are different groups (ADR-0046 decision 2).
/// The one function behind the issuer gate and the namespace check.
#[must_use]
pub fn groups_intersect(token_groups: &[String], listed: &[String]) -> bool {
    token_groups.iter().any(|g| listed.contains(g))
}

/// Errors from validation or exchange.
#[derive(Debug, thiserror::Error)]
pub enum IdpError {
    /// The token's `iss` is not configured.
    #[error("unknown issuer")]
    UnknownIssuer,
    /// Audience, signature, expiry or claim shape failed.
    #[error("invalid token: {0}")]
    Invalid(String),
    /// The subject is authenticated but not allowed (group gate).
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// Upstream HTTP failure.
    #[error("upstream: {0}")]
    Upstream(String),
    /// The issuer refused to refresh or exchange the session (`invalid_grant`, or Entra's
    /// `interaction_required` and `consent_required`): revoked upstream, the user is gone,
    /// or a policy now needs the user. A revocation, not an outage.
    #[error("session revoked upstream: {0}")]
    SessionRevoked(String),
    /// The broker's own credential at the issuer is unusable: a key or certificate file,
    /// the transit key, the federated token. The broker's fault, never the caller's.
    #[error("client credential: {0}")]
    Credential(String),
    /// Feature not wired yet.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

/// What a successful validation yields.
#[derive(Debug, Clone)]
pub struct Validated {
    /// Subject as it will be written to the claim.
    pub subject: Subject,
    /// Issuer config the token matched.
    pub issuer: IssuerConfig,
    /// Groups carried in the token, if any.
    pub groups: Vec<String>,
    /// Token expiry, informational.
    pub expires_at: Timestamp,
}

/// Unverified `iss` peek, used to pick the issuer config before verifying the signature.
fn peek_issuer(token: &str) -> Result<String, IdpError> {
    let mut parts = token.split('.');
    let (_h, payload) = (
        parts.next(),
        parts
            .next()
            .ok_or_else(|| IdpError::Invalid("not a JWT".into()))?,
    );
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| IdpError::Invalid(e.to_string()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| IdpError::Invalid(e.to_string()))?;
    v.get("iss")
        .and_then(|s| s.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| IdpError::Invalid("missing iss".into()))
}

/// Refuse an endpoint the discovery document names over plain HTTP when the issuer itself is
/// HTTPS: an `https` issuer never sends the broker to fetch keys or post a grant in clear.
/// An `http` issuer (`dev_mode` only, the configuration refuses it otherwise) is left alone.
fn require_https_endpoint(issuer_url: &str, what: &str, endpoint: &str) -> Result<(), IdpError> {
    if issuer_url.starts_with("https://") && !endpoint.starts_with("https://") {
        return Err(IdpError::Upstream(format!(
            "discovery document's {what} is not https for an https issuer"
        )));
    }
    Ok(())
}

/// What the discovery document told us, with the JWKS, and when. Shared behind an `Arc`: a
/// validation borrows the key it needs, nothing is copied per request.
struct CachedIssuer {
    set: JwkSet,
    token_endpoint: Option<String>,
    /// When the fetch that produced this began: a caller that must see a set newer than its
    /// own question (a `kid` miss) compares against this, never against the end of the fetch.
    started_at: Instant,
    /// When the fetch ended, what the cache TTL counts from.
    fetched_at: Instant,
}

impl CachedIssuer {
    /// Within [`JWKS_CACHE_TTL_SECS`] of its fetch.
    fn is_fresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.fetched_at).as_secs() < JWKS_CACHE_TTL_SECS
    }

    /// Within [`JWKS_MAX_STALE_SECS`] of its fetch: it may still stand in for a fetch that
    /// failed or that the refetch interval does not allow yet.
    fn within_max_stale(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.fetched_at).as_secs() < JWKS_MAX_STALE_SECS
    }

    /// The key that signed `kid`; with no `kid`, the set's first key.
    fn key(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(k) => self.set.find(k),
            None => self.set.keys.first(),
        }
    }
}

/// One issuer's fetch gate: discovery and the JWKS are fetched by one caller at a time, the
/// others wait and take what it brought back. Holds the last fetch's failure, so the callers
/// that waited through a failed fetch share its error and do not queue to repeat it one by
/// one against an issuer that is down.
#[derive(Default)]
struct FetchGate {
    /// When the last fetch failed and with what, `None` after a success.
    failed: Option<(Instant, String)>,
    /// When the last fetch began, whatever came of it; what the refetch interval counts from.
    last_attempt: Option<Instant>,
}

impl FetchGate {
    /// Whether the last fetch began less than [`JWKS_REFETCH_INTERVAL_SECS`] ago.
    fn fetched_within_interval(&self, now: Instant) -> bool {
        self.last_attempt.is_some_and(|at| {
            now.saturating_duration_since(at).as_secs() < JWKS_REFETCH_INTERVAL_SECS
        })
    }
}

/// The monotonic clock the key cache reads: the process clock, which a test moves ahead
/// instead of sleeping. Clones share the offset, as clones of a [`Validator`] share the cache.
#[derive(Clone, Default)]
struct Clock {
    /// Seconds added to the process clock; never set outside tests.
    ahead_secs: Arc<std::sync::atomic::AtomicU64>,
}

impl Clock {
    fn now(&self) -> Instant {
        Instant::now()
            + Duration::from_secs(self.ahead_secs.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Move the clock ahead by `by`, whole seconds.
    #[cfg(test)]
    fn advance(&self, by: Duration) {
        self.ahead_secs
            .fetch_add(by.as_secs(), std::sync::atomic::Ordering::Relaxed);
    }
}

/// What a refresh yields (ADR-0013 decision 4).
#[derive(Debug, Clone)]
pub struct Refreshed {
    /// The fresh ID token, validated exactly like a login token.
    pub validated: Validated,
    /// The refresh token to keep: the rotated one, or the one just used when the issuer
    /// does not rotate.
    pub refresh_token: String,
}

/// What an Entra refresh yields (ADR-0016 decision 2).
#[derive(Debug)]
pub struct EntraRefreshed {
    /// The refresh token to keep: the rotated one, or the one just used.
    pub refresh_token: Secret,
    /// The access token for the resource asked for.
    pub access_token: Secret,
    /// When that access token expires, from Entra's `expires_in`.
    pub expires_at: Timestamp,
    /// Set when the resource was mediatore itself: the access token validated exactly
    /// like a login (signature, issuer, audience, the group gate, the subject).
    pub validated: Option<Validated>,
}

/// The errors Entra answers a refusal with. Everything else is an outage or the broker's
/// own misconfiguration, and revokes nothing.
const REFUSALS: &[&str] = &["invalid_grant", "interaction_required", "consent_required"];

/// Validates upstream tokens against a configured set of issuers.
#[derive(Clone)]
pub struct Validator {
    issuers: Vec<IssuerConfig>,
    http: reqwest::Client,
    /// Per-issuer clients over a private CA (`IssuerConfig::ca_file`), keyed by issuer URL.
    pinned: HashMap<String, reqwest::Client>,
    /// Per-issuer client assertions (`IssuerConfig::entra`), keyed by issuer URL.
    assertions: HashMap<String, Arc<ClientAssertion>>,
    /// Per-issuer client secrets for the refresh grant (`SessionConfig::client_secret_file`).
    session_secrets: HashMap<String, Secret>,
    jwks: Arc<RwLock<HashMap<String, Arc<CachedIssuer>>>>,
    /// One fetch gate per configured issuer, keyed by issuer URL; fixed at construction.
    fetch_gates: Arc<HashMap<String, tokio::sync::Mutex<FetchGate>>>,
    /// What the key cache's TTL, refetch interval and maximum staleness are measured with.
    clock: Clock,
}

impl std::fmt::Debug for Validator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Validator")
            .field("issuers", &self.issuers)
            .finish_non_exhaustive()
    }
}

/// Signing algorithm implied by a JWK's parameters.
fn algorithm_of(jwk: &Jwk) -> Result<Algorithm, IdpError> {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(p) => match p.curve {
            EllipticCurve::P256 => Ok(Algorithm::ES256),
            EllipticCurve::P384 => Ok(Algorithm::ES384),
            ref other => Err(IdpError::Invalid(format!("unsupported curve {other:?}"))),
        },
        AlgorithmParameters::RSA(_) => Ok(Algorithm::RS256),
        other => Err(IdpError::Invalid(format!("unsupported key type {other:?}"))),
    }
}

/// The refusal for a token signed by a key the issuer does not publish.
fn no_key_for(kid: Option<&str>) -> IdpError {
    IdpError::Invalid(format!("no key for kid {kid:?}"))
}

/// String values of a JSON array claim, e.g. `groups` or `roles`.
fn string_array(claims: &serde_json::Value, key: &str) -> Vec<String> {
    claims
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

impl Validator {
    /// Build from config.
    ///
    /// # Panics
    /// If `reqwest` cannot build a client over the workspace TLS config, which would be a
    /// broken build rather than a runtime condition.
    #[must_use]
    pub fn new(issuers: Vec<IssuerConfig>) -> Self {
        Self::with_timeouts(issuers, IDP_CONNECT_TIMEOUT, IDP_REQUEST_TIMEOUT)
    }

    /// [`Self::new`] with the timeouts given, so a test need not wait out the real ones.
    fn with_timeouts(issuers: Vec<IssuerConfig>, connect: Duration, request: Duration) -> Self {
        let fetch_gates: HashMap<String, tokio::sync::Mutex<FetchGate>> = issuers
            .iter()
            .map(|i| (i.url.clone(), tokio::sync::Mutex::default()))
            .collect();
        Self {
            issuers,
            http: reqwest::Client::builder()
                .tls_backend_preconfigured(mediatore_proto::tls::https_client_config())
                .connect_timeout(connect)
                .timeout(request)
                .build()
                .expect("reqwest client over the workspace TLS config"),
            pinned: HashMap::new(),
            assertions: HashMap::new(),
            session_secrets: HashMap::new(),
            jwks: Arc::new(RwLock::new(HashMap::new())),
            fetch_gates: Arc::new(fetch_gates),
            clock: Clock::default(),
        }
    }

    /// Send `secret` as `client_secret` on every refresh at the issuer at `url`
    /// (ADR-0017): what Google's token endpoint wants from an installed-app client.
    #[must_use]
    pub fn with_session_secret(mut self, url: &str, secret: Secret) -> Self {
        self.session_secrets.insert(url.to_owned(), secret);
        self
    }

    /// Authenticate as the broker at the issuer at `url` with `assertion` (ADR-0016).
    #[must_use]
    pub fn with_client_assertion(mut self, url: &str, assertion: ClientAssertion) -> Self {
        self.assertions.insert(url.to_owned(), Arc::new(assertion));
        self
    }

    /// Trust exactly the CA certificates in `pem` for the issuer at `url` (its
    /// `ca_file`), instead of the public roots. Fails closed on a PEM with no certificate.
    pub fn with_issuer_ca(mut self, url: &str, pem: &[u8]) -> Result<Self, IdpError> {
        let cfg = mediatore_proto::tls::https_client_config_with_ca(pem)
            .map_err(|e| IdpError::Upstream(format!("{url}: {e}")))?;
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(cfg)
            .connect_timeout(IDP_CONNECT_TIMEOUT)
            .timeout(IDP_REQUEST_TIMEOUT)
            .build()
            .map_err(|e| IdpError::Upstream(e.to_string()))?;
        self.pinned.insert(url.to_owned(), client);
        Ok(self)
    }

    /// The HTTP client for an issuer: the pinned one when it has a `ca_file`.
    fn http_for(&self, issuer_url: &str) -> &reqwest::Client {
        self.pinned.get(issuer_url).unwrap_or(&self.http)
    }

    /// Find the issuer config for a token without trusting anything in it yet.
    pub fn issuer_for(&self, token: &str) -> Result<&IssuerConfig, IdpError> {
        let iss = peek_issuer(token)?;
        self.issuers
            .iter()
            .find(|i| i.url == iss)
            .ok_or(IdpError::UnknownIssuer)
    }

    /// The issuer's token endpoint, from the same discovery document as the JWKS.
    async fn token_endpoint_for(&self, issuer_url: &str) -> Result<String, IdpError> {
        self.discover(issuer_url, false)
            .await?
            .token_endpoint
            .clone()
            .ok_or_else(|| IdpError::Upstream("discovery document has no token_endpoint".into()))
    }

    /// What the cache holds for the issuer, fresh or not.
    async fn cached(&self, issuer_url: &str) -> Option<Arc<CachedIssuer>> {
        self.jwks.read().await.get(issuer_url).cloned()
    }

    /// The JWKS and the token endpoint, from cache unless stale or `force` is set.
    ///
    /// One caller per issuer fetches at a time (the issuer's [`FetchGate`]); a caller that
    /// waited takes what the fetch it waited for brought back when that answers its question:
    /// any fetch that began after it asked, or, unforced, any set still within the TTL.
    ///
    /// What changed from "a forced caller (a `kid` miss) always leaves with a set whose fetch
    /// began after it asked; nothing delays or skips a forced fetch": that guarantee let anyone
    /// who could send a bearer naming a configured `iss` and a made-up `kid` have the issuer
    /// asked once per request. It now holds only outside [`JWKS_REFETCH_INTERVAL_SECS`]:
    ///
    /// * While a set is held that is no older than [`JWKS_MAX_STALE_SECS`], no fetch begins
    ///   within the interval of the last one. A caller inside it, forced or not, is answered
    ///   from the held set: for a `kid` miss that is "no key for this kid". A key the issuer
    ///   rotated in is picked up by the first miss after the interval, so it is refused for at
    ///   most the interval.
    /// * A fetch that fails leaves the held set in place. An unforced caller (the cache TTL ran
    ///   out) is served that set, said at `warn`, and the issuer is asked again after the
    ///   interval, until the set is older than the maximum staleness; from then on the outage
    ///   is the caller's, as it always was with nothing cached. A forced caller whose own fetch
    ///   failed is told of the outage: the held set does not have its key.
    /// * With no set to serve nothing is rate limited: every caller that arrives after a
    ///   failed fetch tries again, and those that waited through it share its error.
    async fn discover(&self, issuer_url: &str, force: bool) -> Result<Arc<CachedIssuer>, IdpError> {
        let asked = self.clock.now();
        if !force
            && let Some(cached) = self.cached(issuer_url).await
            && cached.is_fresh(asked)
        {
            return Ok(cached);
        }
        let Some(gate) = self.fetch_gates.get(issuer_url) else {
            // Not a configured issuer: `validate` refuses those before it gets here, and a
            // caller that hands in its own `IssuerConfig` fetches for itself, as before.
            return self.fetch(issuer_url).await;
        };
        let mut gate = gate.lock().await;
        let now = self.clock.now();
        let cached = self.cached(issuer_url).await;
        if let Some(cached) = &cached
            && (cached.started_at >= asked || (!force && cached.is_fresh(now)))
        {
            return Ok(cached.clone());
        }
        // The held set, while it may stand in for a fetch.
        let previous = cached.filter(|c| c.within_max_stale(now));
        if let Some(previous) = &previous
            && gate.fetched_within_interval(now)
        {
            return Ok(previous.clone());
        }
        if let Some((at, why)) = &gate.failed
            && *at >= asked
        {
            // The fetch this caller waited for failed: its outage is this caller's too.
            return Err(IdpError::Upstream(why.clone()));
        }
        gate.last_attempt = Some(now);
        match self.fetch(issuer_url).await {
            Ok(fetched) => {
                gate.failed = None;
                Ok(fetched)
            }
            Err(e) => {
                let why = match &e {
                    IdpError::Upstream(why) => why.clone(),
                    other => other.to_string(),
                };
                gate.failed = Some((self.clock.now(), why.clone()));
                let Some(previous) = previous else {
                    return Err(e);
                };
                tracing::warn!(
                    issuer = issuer_url,
                    error = %why,
                    retry_after_secs = JWKS_REFETCH_INTERVAL_SECS,
                    "the issuer's keys could not be re-fetched; the previous set stays in use"
                );
                if force { Err(e) } else { Ok(previous) }
            }
        }
    }

    /// Fetch the discovery document and the JWKS it names, and cache them.
    async fn fetch(&self, issuer_url: &str) -> Result<Arc<CachedIssuer>, IdpError> {
        let started_at = self.clock.now();
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let discovery: serde_json::Value = self
            .http_for(issuer_url)
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| IdpError::Upstream(format!("discovery: {e}")))?
            .error_for_status()
            .map_err(|e| IdpError::Upstream(format!("discovery: {e}")))?
            .json()
            .await
            .map_err(|e| IdpError::Upstream(format!("discovery: {e}")))?;
        let jwks_uri = discovery
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdpError::Upstream("discovery document has no jwks_uri".into()))?;
        require_https_endpoint(issuer_url, "jwks_uri", jwks_uri)?;
        let token_endpoint = discovery
            .get("token_endpoint")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        if let Some(endpoint) = &token_endpoint {
            require_https_endpoint(issuer_url, "token_endpoint", endpoint)?;
        }

        let set: JwkSet = self
            .http_for(issuer_url)
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| IdpError::Upstream(format!("jwks: {e}")))?
            .error_for_status()
            .map_err(|e| IdpError::Upstream(format!("jwks: {e}")))?
            .json()
            .await
            .map_err(|e| IdpError::Upstream(format!("jwks: {e}")))?;

        tracing::debug!(issuer = issuer_url, keys = set.keys.len(), "jwks fetched");
        let cached = Arc::new(CachedIssuer {
            set,
            token_endpoint,
            started_at,
            fetched_at: self.clock.now(),
        });
        self.jwks
            .write()
            .await
            .insert(issuer_url.to_owned(), cached.clone());
        Ok(cached)
    }

    /// The issuer's keys with the one that signed `kid` among them, re-fetching the JWKS on a
    /// miss (key rotation) when the refetch interval allows it, see [`Self::discover`]. The
    /// caller borrows the key with [`CachedIssuer::key`].
    async fn key_for(
        &self,
        issuer_url: &str,
        kid: Option<&str>,
    ) -> Result<Arc<CachedIssuer>, IdpError> {
        let cached = self.discover(issuer_url, false).await?;
        if cached.key(kid).is_some() {
            return Ok(cached);
        }
        let cached = self.discover(issuer_url, true).await?;
        if cached.key(kid).is_some() {
            Ok(cached)
        } else {
            Err(no_key_for(kid))
        }
    }

    /// Full validation: signature via the issuer's JWKS, `iss` and `aud` present with
    /// `aud` == `client_id`, `exp` present and not passed, `nbf` not in the future when the
    /// token carries one (both within `CLOCK_SKEW_LEEWAY_SECS`), subject claim present,
    /// group gate satisfied.
    pub async fn validate(&self, token: &str) -> Result<Validated, IdpError> {
        let issuer = self.issuer_for(token)?.clone();
        self.validate_as(&issuer, token).await
    }

    /// The configured issuer named `url`, for a record that remembers which one it is.
    pub fn issuer_named(&self, url: &str) -> Option<&IssuerConfig> {
        self.issuers.iter().find(|i| i.url == url)
    }

    /// Refresh a delegated session (ADR-0013 decision 4): the `refresh_token` grant at the
    /// issuer's token endpoint as the session's client, then the returned ID token
    /// validated exactly like a login token. `invalid_grant` is [`IdpError::SessionRevoked`];
    /// any other failure is [`IdpError::Upstream`] and revokes nothing.
    pub async fn refresh(
        &self,
        issuer: &IssuerConfig,
        refresh_token: &str,
    ) -> Result<Refreshed, IdpError> {
        let session = issuer
            .session
            .as_ref()
            .ok_or(IdpError::NotImplemented("issuer takes no session"))?;
        let endpoint = self.token_endpoint_for(&issuer.url).await?;
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", session.client_id.as_str()),
        ];
        if let Some(secret) = self.session_secrets.get(&issuer.url) {
            form.push(("client_secret", secret.0.as_str()));
        }
        let resp = self
            .http_for(&issuer.url)
            .post(&endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| IdpError::Upstream(format!("refresh: {e}")))?;
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| IdpError::Upstream(format!("refresh: {e}")))?;
        if !status.is_success() {
            let code = body
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if status.is_client_error() && code == "invalid_grant" {
                return Err(IdpError::SessionRevoked(code));
            }
            return Err(IdpError::Upstream(format!("refresh: {status} {code}")));
        }
        let id_token = body
            .get("id_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdpError::Upstream("refresh: no id_token in the response".into()))?;
        let validated = self.validate_as(issuer, id_token).await?;
        let refresh_token = body
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .unwrap_or(refresh_token)
            .to_owned();
        Ok(Refreshed {
            validated,
            refresh_token,
        })
    }

    /// The client assertion for an Entra issuer, signed now for its token endpoint.
    async fn client_assertion(
        &self,
        issuer: &IssuerConfig,
        endpoint: &str,
    ) -> Result<String, IdpError> {
        let assertion = self.assertions.get(&issuer.url).ok_or_else(|| {
            IdpError::Credential(format!("issuer {} has no client assertion", issuer.url))
        })?;
        assertion.assert(&issuer.client_id, endpoint).await
    }

    /// One call to the token endpoint. A 4xx with one of Entra's refusal codes is
    /// [`IdpError::SessionRevoked`]; anything else that is not a success is
    /// [`IdpError::Upstream`].
    async fn post_token(
        &self,
        issuer: &IssuerConfig,
        endpoint: &str,
        what: &str,
        form: &[(&str, &str)],
    ) -> Result<serde_json::Value, IdpError> {
        let resp = self
            .http_for(&issuer.url)
            .post(endpoint)
            .form(form)
            .send()
            .await
            .map_err(|e| IdpError::Upstream(format!("{what}: {e}")))?;
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| IdpError::Upstream(format!("{what}: {e}")))?;
        if !status.is_success() {
            let code = body
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if status.is_client_error() && REFUSALS.contains(&code.as_str()) {
                return Err(IdpError::SessionRevoked(code));
            }
            return Err(IdpError::Upstream(format!("{what}: {status} {code}")));
        }
        Ok(body)
    }

    /// The On-Behalf-Of exchange (ADR-0016 decision 1): the caller's access token for
    /// mediatore becomes a refresh token issued to mediatore for that user, good for every
    /// resource the user consented to. `resource` is the first audience the claim names
    /// that Entra serves, or mediatore's own client id. Nothing else from the response is
    /// kept.
    pub async fn exchange(
        &self,
        issuer: &IssuerConfig,
        access_token: &str,
        resource: &str,
    ) -> Result<Secret, IdpError> {
        if issuer.entra.is_none() {
            return Err(IdpError::NotImplemented("issuer is not Entra"));
        }
        let endpoint = self.token_endpoint_for(&issuer.url).await?;
        let assertion = self.client_assertion(issuer, &endpoint).await?;
        let scope = format!("offline_access {resource}/.default");
        let form = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("client_id", issuer.client_id.as_str()),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", assertion.as_str()),
            ("assertion", access_token),
            ("scope", scope.as_str()),
            ("requested_token_use", "on_behalf_of"),
        ];
        let body = self
            .post_token(issuer, &endpoint, "exchange", &form)
            .await?;
        body.get("refresh_token")
            .and_then(|v| v.as_str())
            .map(|t| Secret(t.to_owned()))
            .ok_or_else(|| IdpError::Upstream("exchange: no refresh_token in the response".into()))
    }

    /// Refresh an Entra session for `resource` (ADR-0016 decision 2): the `refresh_token`
    /// grant with the client assertion and `scope=offline_access <resource>/.default`
    /// (`offline_access` so a rotated refresh token comes back, as MSAL asks on every
    /// request). When the resource is mediatore itself the access token is validated like
    /// a login and returned with its claims; for any other resource it is handed back
    /// unread.
    pub async fn refresh_entra(
        &self,
        issuer: &IssuerConfig,
        refresh_token: &str,
        resource: &str,
    ) -> Result<EntraRefreshed, IdpError> {
        if issuer.entra.is_none() {
            return Err(IdpError::NotImplemented("issuer is not Entra"));
        }
        let endpoint = self.token_endpoint_for(&issuer.url).await?;
        let assertion = self.client_assertion(issuer, &endpoint).await?;
        let scope = format!("offline_access {resource}/.default");
        let form = [
            ("grant_type", "refresh_token"),
            ("client_id", issuer.client_id.as_str()),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", assertion.as_str()),
            ("refresh_token", refresh_token),
            ("scope", scope.as_str()),
        ];
        let body = self.post_token(issuer, &endpoint, "refresh", &form).await?;
        let access_token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdpError::Upstream("refresh: no access_token in the response".into()))?
            .to_owned();
        let expires_in = body
            .get("expires_in")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| IdpError::Upstream("refresh: no expires_in in the response".into()))?;
        let validated = if resource == issuer.client_id {
            Some(self.validate_as(issuer, &access_token).await?)
        } else {
            None
        };
        let refresh_token = body
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .unwrap_or(refresh_token)
            .to_owned();
        Ok(EntraRefreshed {
            refresh_token: Secret(refresh_token),
            access_token: Secret(access_token),
            expires_at: Timestamp::now() + jiff::SignedDuration::from_secs(expires_in),
            validated,
        })
    }

    /// [`Self::validate`] against one known issuer.
    async fn validate_as(&self, issuer: &IssuerConfig, token: &str) -> Result<Validated, IdpError> {
        tracing::debug!(issuer = %issuer.url, backend = ?issuer.backend, "validating upstream token");

        let header =
            jsonwebtoken::decode_header(token).map_err(|e| IdpError::Invalid(e.to_string()))?;
        let kid = header.kid.as_deref();
        let keys = self.key_for(&issuer.url, kid).await?;
        let jwk = keys.key(kid).ok_or_else(|| no_key_for(kid))?;
        let key = DecodingKey::from_jwk(jwk).map_err(|e| IdpError::Invalid(e.to_string()))?;

        let mut validation = Validation::new(algorithm_of(jwk)?);
        validation.set_audience(&[&issuer.client_id]);
        validation.set_issuer(&[&issuer.url]);
        validation.set_required_spec_claims(REQUIRED_CLAIMS);
        validation.validate_nbf = true;
        validation.leeway = CLOCK_SKEW_LEEWAY_SECS;
        let data = jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation)
            .map_err(|e| IdpError::Invalid(e.to_string()))?;
        let claims = data.claims;

        let id = claims
            .get(&issuer.subject_claim)
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdpError::Invalid(format!("missing claim {}", issuer.subject_claim)))?
            .to_owned();
        // An address the issuer has not verified is whatever its holder typed: as the subject
        // it would let one account take another's name (ADR-0017).
        if issuer.subject_claim == "email"
            && claims
                .get("email_verified")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
        {
            return Err(IdpError::Invalid("email is not verified".into()));
        }

        let groups = if let Some(claim) = &issuer.groups_claim {
            string_array(&claims, claim)
        } else {
            let mut groups = string_array(&claims, "groups");
            groups.extend(string_array(&claims, "roles"));
            groups
        };
        // A gate the configuration load should have refused is still refused here: fail closed.
        match issuer
            .gate()
            .map_err(|e| IdpError::Credential(e.to_string()))?
        {
            Gate::AnyAuthenticated => {}
            Gate::Groups(listed) => {
                if !groups_intersect(&groups, &listed) {
                    return Err(IdpError::Forbidden("not in a required group".into()));
                }
            }
        }

        let display = ["upn", "email", "name"]
            .iter()
            .find_map(|k| claims.get(*k).and_then(|v| v.as_str()))
            .map(ToOwned::to_owned);
        let expires_at = claims
            .get("exp")
            .and_then(serde_json::Value::as_i64)
            .and_then(|ts| Timestamp::from_second(ts).ok())
            .ok_or_else(|| IdpError::Invalid("missing exp".into()))?;

        Ok(Validated {
            subject: Subject {
                issuer: issuer.url.clone(),
                id,
                display,
            },
            issuer: issuer.clone(),
            groups,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_pinned_issuer_ca_is_read_at_construction_and_an_empty_one_is_refused() {
        let v = Validator::new(vec![]);
        let err = v
            .with_issuer_ca("https://dex.home.example", b"")
            .unwrap_err();
        assert!(err.to_string().contains("no certificate"), "{err}");
        let v = Validator::new(vec![])
            .with_issuer_ca(
                "https://dex.home.example",
                mediatore_testkit::fixture_ca_pem().as_bytes(),
            )
            .unwrap();
        assert!(v.pinned.contains_key("https://dex.home.example"));
        assert!(std::ptr::eq(
            v.http_for("https://other.example"),
            std::ptr::from_ref(&v.http)
        ));
    }

    use mediatore_testkit::FakeIdp;

    use super::*;

    fn issuer_config(idp: &FakeIdp) -> IssuerConfig {
        IssuerConfig {
            url: idp.issuer.clone(),
            backend: Backend::Sts,
            client_id: "mediatore".into(),
            subject_claim: "preferred_username".into(),
            required_group: Some("firestoned:sandbox-users".into()),
            required_groups: None,
            allow_any_authenticated: false,
            session: Some(SessionConfig {
                client_id: "mediatore".into(),
                client_secret_file: None,
            }),
            ca_file: None,
            entra: None,
            groups_claim: None,
        }
    }

    #[tokio::test]
    async fn a_refresh_validates_the_fresh_id_token_rotates_and_sees_revocation() {
        let idp = FakeIdp::start().await;
        idp.set_groups("octocat", &["firestoned:sandbox-users"]);
        let v = Validator::new(vec![issuer_config(&idp)]);
        let (_, refresh_token) = idp.session("octocat", "mediatore");

        let first = v
            .refresh(&issuer_config(&idp), &refresh_token)
            .await
            .unwrap();
        assert_eq!(first.validated.subject.id, "octocat");
        assert_ne!(first.refresh_token, refresh_token, "rotated");
        assert!(
            matches!(
                v.refresh(&issuer_config(&idp), &refresh_token).await,
                Err(IdpError::SessionRevoked(_))
            ),
            "the old token is dead after rotation"
        );

        // The group gate runs on the fresh token: removal from the group is a refusal.
        // The issuer rotated before we looked, so that session is spent either way.
        idp.set_groups("octocat", &["firestoned:other"]);
        assert!(matches!(
            v.refresh(&issuer_config(&idp), &first.refresh_token).await,
            Err(IdpError::Forbidden(_))
        ));
        idp.set_groups("octocat", &["firestoned:sandbox-users"]);
        let (_, again) = idp.session("octocat", "mediatore");
        let second = v.refresh(&issuer_config(&idp), &again).await.unwrap();

        idp.revoke("octocat");
        assert!(matches!(
            v.refresh(&issuer_config(&idp), &second.refresh_token).await,
            Err(IdpError::SessionRevoked(_))
        ));
        assert_eq!(idp.refreshes(), 3);
    }

    #[tokio::test]
    async fn an_issuer_outage_is_not_a_revocation() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let (_, refresh_token) = idp.session("octocat", "mediatore");
        idp.set_down(true);
        assert!(matches!(
            v.refresh(&issuer_config(&idp), &refresh_token).await,
            Err(IdpError::Upstream(_))
        ));
        idp.set_down(false);
        v.refresh(&issuer_config(&idp), &refresh_token)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_issuer_without_a_session_cannot_refresh() {
        let idp = FakeIdp::start().await;
        let mut cfg = issuer_config(&idp);
        cfg.session = None;
        let v = Validator::new(vec![cfg.clone()]);
        assert!(matches!(
            v.refresh(&cfg, "whatever").await,
            Err(IdpError::NotImplemented(_))
        ));
    }

    #[tokio::test]
    async fn valid_token_yields_subject_and_groups() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let token = idp.token(serde_json::json!({
            "aud": "mediatore",
            "preferred_username": "octocat",
            "email": "octocat@example.com",
            "groups": ["firestoned:sandbox-users", "firestoned:dev"],
        }));
        let out = v.validate(&token).await.unwrap();
        assert_eq!(out.subject.id, "octocat");
        assert_eq!(out.subject.issuer, idp.issuer);
        assert_eq!(out.subject.display.as_deref(), Some("octocat@example.com"));
        assert!(out.groups.contains(&"firestoned:dev".to_owned()));
    }

    #[tokio::test]
    async fn wrong_audience_is_invalid() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let token = idp.token(serde_json::json!({
            "aud": "kubernetes",
            "preferred_username": "octocat",
            "groups": ["firestoned:sandbox-users"],
        }));
        assert!(matches!(
            v.validate(&token).await,
            Err(IdpError::Invalid(_))
        ));
    }

    fn gate_cfg(extra: &serde_json::Value) -> IssuerConfig {
        let mut v = serde_json::json!({
            "url": "https://idp.example.com",
            "backend": "sts",
            "client_id": "mediatore",
            "subject_claim": "preferred_username",
        });
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(v).unwrap()
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    async fn login_with(
        cfg_extra: serde_json::Value,
        groups: &[&str],
    ) -> Result<Validated, IdpError> {
        let idp = FakeIdp::start().await;
        let mut cfg = issuer_config(&idp);
        cfg.required_group = None;
        cfg.required_groups = None;
        cfg.allow_any_authenticated = false;
        let extra = cfg_extra.as_object().unwrap();
        if let Some(g) = extra.get("required_groups") {
            cfg.required_groups = Some(serde_json::from_value(g.clone()).unwrap());
        }
        if let Some(g) = extra.get("required_group") {
            cfg.required_group = Some(g.as_str().unwrap().to_owned());
        }
        if let Some(g) = extra.get("allow_any_authenticated") {
            cfg.allow_any_authenticated = g.as_bool().unwrap();
        }
        let v = Validator::new(vec![cfg]);
        let token = idp.token(serde_json::json!({
            "aud": "mediatore",
            "preferred_username": "octocat",
            "groups": groups,
        }));
        v.validate(&token).await
    }

    #[tokio::test]
    async fn required_groups_admits_any_one_of_them() {
        let list = serde_json::json!({"required_groups": ["example-org:APP_EXAMPLE_ADMIN", "APP_EXAMPLE_ADMIN"]});
        for g in ["example-org:APP_EXAMPLE_ADMIN", "APP_EXAMPLE_ADMIN"] {
            let ok = login_with(list.clone(), &[g]).await.unwrap();
            assert_eq!(ok.groups, strs(&[g]));
        }
    }

    #[tokio::test]
    async fn required_groups_refuses_a_token_with_none_of_them() {
        let list = serde_json::json!({"required_groups": ["example-org:APP_EXAMPLE_ADMIN", "APP_EXAMPLE_ADMIN"]});
        let err = login_with(list, &["APP_EXAMPLE_TEAM_A_USER"])
            .await
            .unwrap_err();
        let IdpError::Forbidden(msg) = err else {
            panic!("expected forbidden")
        };
        assert!(
            !msg.contains("APP_EXAMPLE_ADMIN"),
            "the message must not name the values: {msg}"
        );
    }

    #[tokio::test]
    async fn required_group_alone_behaves_as_before() {
        let one = serde_json::json!({"required_group": "example-org:APP_EXAMPLE_ADMIN"});
        assert!(
            login_with(one.clone(), &["example-org:APP_EXAMPLE_ADMIN"])
                .await
                .is_ok()
        );
        assert!(matches!(
            login_with(one, &["APP_EXAMPLE_TEAM_A_USER"]).await,
            Err(IdpError::Forbidden(_))
        ));
    }

    #[test]
    fn an_issuer_with_both_required_group_keys_refuses_to_start() {
        let cfg = gate_cfg(&serde_json::json!({"required_group": "a", "required_groups": ["b"]}));
        let e = cfg.gate().unwrap_err().to_string();
        assert!(
            e.contains("https://idp.example.com")
                && e.contains("required_group")
                && e.contains("required_groups"),
            "{e}"
        );
    }

    #[test]
    fn an_empty_required_groups_refuses_to_start() {
        let e = gate_cfg(&serde_json::json!({"required_groups": []}))
            .gate()
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("https://idp.example.com") && e.contains("required_groups"),
            "{e}"
        );
        for bad in [
            serde_json::json!([""]),
            serde_json::json!(["  "]),
            serde_json::json!([" a"]),
            serde_json::json!(["a "]),
            serde_json::json!(["a", "a"]),
        ] {
            assert!(
                gate_cfg(&serde_json::json!({"required_groups": bad}))
                    .gate()
                    .is_err()
            );
        }
        assert!(
            gate_cfg(&serde_json::json!({"required_group": " a"}))
                .gate()
                .is_err()
        );
        assert!(
            gate_cfg(&serde_json::json!({"required_group": ""}))
                .gate()
                .is_err()
        );
    }

    #[test]
    fn group_matching_is_exact_and_case_sensitive() {
        let held = strs(&["example-org:APP_EXAMPLE_ADMIN"]);
        assert!(groups_intersect(
            &held,
            &strs(&["example-org:APP_EXAMPLE_ADMIN"])
        ));
        assert!(!groups_intersect(
            &held,
            &strs(&["example-org:app_example_admin"])
        ));
        assert!(!groups_intersect(
            &held,
            &strs(&["Example-Org:APP_EXAMPLE_ADMIN"])
        ));
        assert!(!groups_intersect(&[], &strs(&["x"])));
        assert!(!groups_intersect(&held, &[]));
    }

    #[test]
    fn a_prefixed_group_does_not_match_the_bare_name() {
        assert!(!groups_intersect(
            &strs(&["example-org:APP_EXAMPLE_ADMIN"]),
            &strs(&["APP_EXAMPLE_ADMIN"])
        ));
    }

    #[test]
    fn a_bare_group_does_not_match_the_prefixed_name() {
        assert!(!groups_intersect(
            &strs(&["APP_EXAMPLE_ADMIN"]),
            &strs(&["example-org:APP_EXAMPLE_ADMIN"])
        ));
    }

    #[tokio::test]
    async fn a_service_id_with_a_bare_group_passes_when_both_spellings_are_listed() {
        let both = serde_json::json!({"required_groups": ["example-org:APP_EXAMPLE_ADMIN", "APP_EXAMPLE_ADMIN"]});
        assert!(login_with(both, &["APP_EXAMPLE_ADMIN"]).await.is_ok());
        let prefixed = serde_json::json!({"required_group": "example-org:APP_EXAMPLE_ADMIN"});
        assert!(matches!(
            login_with(prefixed, &["APP_EXAMPLE_ADMIN"]).await,
            Err(IdpError::Forbidden(_))
        ));
    }

    #[test]
    fn an_issuer_with_no_gate_key_refuses_to_start() {
        let e = gate_cfg(&serde_json::json!({}))
            .gate()
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("https://idp.example.com")
                && e.contains("required_group")
                && e.contains("required_groups")
                && e.contains("allow_any_authenticated"),
            "{e}"
        );
    }

    #[tokio::test]
    async fn an_issuer_with_allow_any_authenticated_admits_a_token_with_no_groups() {
        let ok = login_with(serde_json::json!({"allow_any_authenticated": true}), &[])
            .await
            .unwrap();
        assert_eq!(ok.groups, Vec::<String>::new());
        let cfg = gate_cfg(&serde_json::json!({"allow_any_authenticated": true}));
        assert_eq!(cfg.gate().unwrap(), Gate::AnyAuthenticated);
        assert_eq!(cfg.gate().unwrap().to_string(), "none (explicit)");
    }

    #[test]
    fn allow_any_authenticated_with_required_groups_refuses_to_start() {
        assert!(
            gate_cfg(
                &serde_json::json!({"allow_any_authenticated": true, "required_groups": ["a"]})
            )
            .gate()
            .is_err()
        );
        assert!(
            gate_cfg(&serde_json::json!({"allow_any_authenticated": true, "required_group": "a"}))
                .gate()
                .is_err()
        );
    }

    #[test]
    fn allow_any_authenticated_false_is_not_a_gate() {
        assert!(
            gate_cfg(&serde_json::json!({"allow_any_authenticated": false}))
                .gate()
                .is_err()
        );
        let g =
            gate_cfg(&serde_json::json!({"allow_any_authenticated": false, "required_group": "a"}))
                .gate()
                .unwrap();
        assert_eq!(g, Gate::Groups(strs(&["a"])));
        let alias = gate_cfg(&serde_json::json!({"required_group": "a"}));
        assert_eq!(alias.gate_form().unwrap(), "required_group (a)");
        let g = gate_cfg(&serde_json::json!({"required_groups": ["a", "b"]}))
            .gate()
            .unwrap();
        assert_eq!(g.to_string(), "required_groups (a, b)");
    }

    #[test]
    fn an_issuer_with_an_unknown_key_refuses_to_start() {
        let v =
            serde_json::json!({"url": "u", "backend": "sts", "client_id": "c", "allow_any": true});
        assert!(serde_json::from_value::<IssuerConfig>(v).is_err());
    }

    #[test]
    fn a_misspelled_required_groups_refuses_to_start() {
        let v = serde_json::json!({"url": "u", "backend": "sts", "client_id": "c", "required_group": ["a"]});
        assert!(serde_json::from_value::<IssuerConfig>(v).is_err());
        let v = serde_json::json!({"url": "u", "backend": "sts", "client_id": "c", "requiredgroups": ["a"]});
        assert!(serde_json::from_value::<IssuerConfig>(v).is_err());
    }

    #[test]
    fn an_entra_or_session_block_with_an_unknown_key_refuses_to_start() {
        let base = serde_json::json!({"url": "u", "backend": "sts", "client_id": "c", "allow_any_authenticated": true});
        let mut with_session = base.clone();
        with_session["session"] = serde_json::json!({"client_id": "c", "client_sekret_file": "/x"});
        assert!(serde_json::from_value::<IssuerConfig>(with_session).is_err());
        let mut with_entra = base.clone();
        with_entra["entra"] = serde_json::json!({"key_file": "/k", "key_fil": "/k"});
        assert!(serde_json::from_value::<IssuerConfig>(with_entra).is_err());
        let mut ok = base;
        ok["session"] = serde_json::json!({"client_id": "c"});
        assert!(serde_json::from_value::<IssuerConfig>(ok).is_ok());
    }

    #[tokio::test]
    async fn missing_required_group_is_forbidden() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let token = idp.token(serde_json::json!({
            "aud": "mediatore",
            "preferred_username": "octocat",
            "groups": ["firestoned:other"],
        }));
        assert!(matches!(
            v.validate(&token).await,
            Err(IdpError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn unknown_issuer_is_rejected_before_any_fetch() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![]);
        let token = idp.token(serde_json::json!({ "aud": "mediatore" }));
        assert!(matches!(
            v.validate(&token).await,
            Err(IdpError::UnknownIssuer)
        ));
    }

    #[tokio::test]
    async fn expired_token_is_invalid() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let token = idp.token(serde_json::json!({
            "aud": "mediatore",
            "preferred_username": "octocat",
            "groups": ["firestoned:sandbox-users"],
            "exp": jiff::Timestamp::now().as_second() - 3600,
        }));
        assert!(matches!(
            v.validate(&token).await,
            Err(IdpError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn a_token_with_no_audience_is_invalid() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        // Correctly signed, the right issuer, the right group: only `aud` is absent.
        let token = idp.token(serde_json::json!({
            "preferred_username": "octocat",
            "groups": ["firestoned:sandbox-users"],
        }));
        assert!(matches!(
            v.validate(&token).await,
            Err(IdpError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn an_email_subject_needs_the_issuer_to_have_verified_it() {
        let idp = FakeIdp::start().await;
        let mut by_email = issuer_config(&idp);
        by_email.subject_claim = "email".into();
        let v = Validator::new(vec![by_email]);
        let login = |verified: Option<bool>| {
            let mut claims = serde_json::json!({
                "aud": "mediatore",
                "email": "octocat@example.com",
                "preferred_username": "octocat",
                "groups": ["firestoned:sandbox-users"],
            });
            if let Some(v) = verified {
                claims["email_verified"] = v.into();
            }
            idp.token(claims)
        };
        let out = v.validate(&login(Some(true))).await.unwrap();
        assert_eq!(out.subject.id, "octocat@example.com");
        for unverified in [Some(false), None] {
            assert!(matches!(
                v.validate(&login(unverified)).await,
                Err(IdpError::Invalid(_))
            ));
        }
        // A subject that is not the address does not ask for the flag.
        let v = Validator::new(vec![issuer_config(&idp)]);
        assert!(v.validate(&login(None)).await.is_ok());
    }

    #[tokio::test]
    async fn a_token_not_yet_valid_is_invalid_and_one_within_the_leeway_is_not() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let starting_in = |secs: i64| {
            idp.token(serde_json::json!({
                "aud": "mediatore",
                "preferred_username": "octocat",
                "groups": ["firestoned:sandbox-users"],
                "nbf": jiff::Timestamp::now().as_second() + secs,
                "exp": jiff::Timestamp::now().as_second() + 7200,
            }))
        };
        assert!(matches!(
            v.validate(&starting_in(3600)).await,
            Err(IdpError::Invalid(_))
        ));
        let skew = i64::try_from(CLOCK_SKEW_LEEWAY_SECS).unwrap();
        let out = v.validate(&starting_in(skew / 2)).await.unwrap();
        assert_eq!(out.subject.id, "octocat");
    }

    #[test]
    fn an_https_issuer_is_not_sent_to_a_plain_http_endpoint() {
        let https = "https://idp.example.com";
        for what in ["jwks_uri", "token_endpoint"] {
            let plain = "http://idp.example.com/x";
            let err = require_https_endpoint(https, what, plain).unwrap_err();
            assert!(
                matches!(&err, IdpError::Upstream(why) if why.contains(what)),
                "{err}"
            );
            assert!(require_https_endpoint(https, what, "https://idp.example.com/x").is_ok());
            // Not a URL with a scheme at all: refused with the rest.
            assert!(require_https_endpoint(https, what, "idp.example.com/x").is_err());
            // The dev-mode issuer over plain HTTP keeps its plain HTTP endpoints.
            let dev = "http://127.0.0.1:5556";
            assert!(require_https_endpoint(dev, what, "http://127.0.0.1:5556/x").is_ok());
        }
    }

    #[tokio::test]
    async fn garbage_is_invalid() {
        let v = Validator::new(vec![]);
        assert!(v.validate("not-a-jwt").await.is_err());
    }

    /// An Entra-shaped issuer: `entra-obo`, the fixed certificate registered, `oid`.
    const ENTRA_CLIENT: &str = "00001111-aaaa-2222-bbbb-3333cccc4444";

    async fn entra(idp: &FakeIdp) -> (IssuerConfig, Validator) {
        let dir = mediatore_testkit::tempdir();
        let (key, cert) = mediatore_testkit::entra::write_client_credential(&dir);
        idp.register_client_certificate(
            ENTRA_CLIENT,
            &mediatore_testkit::entra::client_credential().certificate_pem,
        );
        let cfg = EntraConfig {
            certificate_file: Some(cert),
            key_file: Some(key),
            ..Default::default()
        };
        let issuer = IssuerConfig {
            url: idp.issuer.clone(),
            backend: Backend::EntraObo,
            client_id: ENTRA_CLIENT.into(),
            subject_claim: "oid".into(),
            required_group: Some("firestoned:sandbox-users".into()),
            required_groups: None,
            allow_any_authenticated: false,
            session: None,
            ca_file: None,
            entra: Some(cfg.clone()),
            groups_claim: None,
        };
        let assertion = ClientAssertion::build(&cfg).await.unwrap();
        let v = Validator::new(vec![issuer.clone()]).with_client_assertion(&idp.issuer, assertion);
        (issuer, v)
    }

    #[tokio::test]
    async fn the_exchange_yields_a_session_good_for_mediatore_and_for_the_audience() {
        let idp = FakeIdp::start().await;
        let (issuer, v) = entra(&idp).await;
        let bearer = idp.access_token("octocat", ENTRA_CLIENT);
        let session = v
            .exchange(&issuer, &bearer, "api://trading-data")
            .await
            .unwrap();
        assert_eq!(idp.exchanges(), 1);
        assert!(idp.is_live(&session.0));
        assert!(
            !format!("{session:?}").contains(&session.0),
            "the refresh token has a redacting Debug"
        );

        // For mediatore itself: validated like a login, groups included.
        let own = v
            .refresh_entra(&issuer, &session.0, ENTRA_CLIENT)
            .await
            .unwrap();
        let validated = own.validated.unwrap();
        assert_eq!(validated.subject.id, "octocat");
        assert_eq!(validated.groups, vec!["firestoned:sandbox-users"]);
        assert_ne!(own.refresh_token.0, session.0, "rotated");
        assert!(!idp.is_live(&session.0));
        assert!(own.expires_at > Timestamp::now() + jiff::SignedDuration::from_mins(55));

        // For the audience: Entra's token, unread.
        let downstream = v
            .refresh_entra(&issuer, &own.refresh_token.0, "api://trading-data")
            .await
            .unwrap();
        assert!(downstream.validated.is_none());
        assert!(downstream.access_token.0.starts_with("at-"));
        assert_eq!(
            idp.refresh_scopes(),
            vec![
                format!("offline_access {ENTRA_CLIENT}/.default"),
                "offline_access api://trading-data/.default".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn entra_refusals_are_revocations_and_everything_else_is_an_outage() {
        let idp = FakeIdp::start().await;
        let (issuer, v) = entra(&idp).await;
        let bearer = idp.access_token("octocat", ENTRA_CLIENT);
        let session = v
            .exchange(&issuer, &bearer, "api://trading-data")
            .await
            .unwrap();
        idp.set_interaction_required("octocat", true);
        assert!(matches!(
            v.refresh_entra(&issuer, &session.0, ENTRA_CLIENT).await,
            Err(IdpError::SessionRevoked(ref c)) if c == "interaction_required"
        ));
        assert!(matches!(
            v.exchange(&issuer, &bearer, "api://trading-data").await,
            Err(IdpError::SessionRevoked(_))
        ));
        idp.set_interaction_required("octocat", false);
        // The fake spends a refresh token on any grant, refused or not (Entra keeps it);
        // a fresh session for what follows.
        let (_, session) = idp.session("octocat", ENTRA_CLIENT);
        idp.set_down(true);
        assert!(matches!(
            v.refresh_entra(&issuer, &session, ENTRA_CLIENT).await,
            Err(IdpError::Upstream(_))
        ));
        idp.set_down(false);
        // A fresh token that left the group fails the gate on the self refresh only.
        idp.set_groups("octocat", &["firestoned:other"]);
        assert!(
            v.refresh_entra(&issuer, &session, "api://trading-data")
                .await
                .is_ok()
        );
        let (_, again) = idp.session("octocat", ENTRA_CLIENT);
        assert!(matches!(
            v.refresh_entra(&issuer, &again, ENTRA_CLIENT).await,
            Err(IdpError::Forbidden(_))
        ));
        // The exchange needs an access token for mediatore: an ID token for another app
        // does not validate at the login and would not exchange either.
        let foreign = idp.token(serde_json::json!({ "aud": "another-app", "oid": "octocat" }));
        assert!(matches!(
            v.exchange(&issuer, &foreign, "api://trading-data").await,
            Err(IdpError::SessionRevoked(ref c)) if c == "invalid_grant"
        ));
    }

    #[tokio::test]
    async fn an_issuer_without_entra_cannot_exchange_and_one_without_an_assertion_is_a_credential_error()
     {
        let idp = FakeIdp::start().await;
        let dex = issuer_config(&idp);
        let v = Validator::new(vec![dex.clone()]);
        assert!(matches!(
            v.exchange(&dex, "t", "r").await,
            Err(IdpError::NotImplemented(_))
        ));
        assert!(matches!(
            v.refresh_entra(&dex, "t", "r").await,
            Err(IdpError::NotImplemented(_))
        ));
        let mut entra = dex.clone();
        entra.backend = Backend::EntraObo;
        entra.session = None;
        entra.entra = Some(EntraConfig::default());
        let v = Validator::new(vec![entra.clone()]);
        assert!(matches!(
            v.exchange(&entra, "t", "r").await,
            Err(IdpError::Credential(_))
        ));
    }

    // ----- the discovery and JWKS cache: one fetch for many callers, bounded by a timeout -----

    fn login_token(idp: &FakeIdp) -> String {
        idp.token(serde_json::json!({
            "aud": "mediatore",
            "preferred_username": "octocat",
            "groups": ["firestoned:sandbox-users"],
        }))
    }

    /// `token` with its header replaced by one naming `kid`: a token signed by a key the
    /// issuer does not publish, as far as the key lookup can tell.
    fn with_kid(token: &str, kid: &str) -> String {
        let header = URL_SAFE_NO_PAD
            .encode(serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": kid }).to_string());
        let rest = token.split_once('.').expect("a JWT has a header").1;
        format!("{header}.{rest}")
    }

    #[tokio::test]
    async fn concurrent_validations_on_a_cold_cache_fetch_the_keys_once() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let token = login_token(&idp);
        let callers: Vec<_> = (0..16)
            .map(|_| {
                let (v, token) = (v.clone(), token.clone());
                tokio::spawn(async move { v.validate(&token).await.map(|out| out.subject.id) })
            })
            .collect();
        for caller in callers {
            assert_eq!(caller.await.unwrap().unwrap(), "octocat");
        }
        assert_eq!(idp.discovery_fetches(), 1, "one discovery for all of them");
        assert_eq!(idp.jwks_fetches(), 1, "one JWKS fetch for all of them");
        // And a warm cache fetches nothing.
        v.validate(&token).await.unwrap();
        assert_eq!((idp.discovery_fetches(), idp.jwks_fetches()), (1, 1));
    }

    /// One second past the refetch interval.
    fn past_the_interval() -> Duration {
        Duration::from_secs(JWKS_REFETCH_INTERVAL_SECS + 1)
    }

    #[tokio::test]
    async fn many_unknown_kids_refetch_the_keys_once_an_interval_and_are_refused_every_time() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let token = login_token(&idp);
        // A cold cache: the fetch, the miss, and no second fetch inside the interval.
        assert!(matches!(
            v.validate(&with_kid(&token, "made-up-0")).await,
            Err(IdpError::Invalid(_))
        ));
        assert_eq!((idp.discovery_fetches(), idp.jwks_fetches()), (1, 1));
        // A warm cache: any number of made-up kids ask the issuer nothing.
        for i in 1..20 {
            assert!(matches!(
                v.validate(&with_kid(&token, &format!("made-up-{i}"))).await,
                Err(IdpError::Invalid(_))
            ));
        }
        assert_eq!((idp.discovery_fetches(), idp.jwks_fetches()), (1, 1));
        // Past the interval the first miss asks once, and the rest are answered from that.
        v.clock.advance(past_the_interval());
        for i in 20..40 {
            assert!(matches!(
                v.validate(&with_kid(&token, &format!("made-up-{i}"))).await,
                Err(IdpError::Invalid(_))
            ));
        }
        assert_eq!((idp.discovery_fetches(), idp.jwks_fetches()), (2, 2));
        // The published key is served from what the last fetch brought back.
        v.validate(&token).await.unwrap();
        assert_eq!((idp.discovery_fetches(), idp.jwks_fetches()), (2, 2));
    }

    /// What a [`StubIssuer`] answers with.
    struct StubState {
        /// The JWKS document it publishes.
        jwks: serde_json::Value,
        /// Answer `503` to discovery and to the JWKS.
        failing: bool,
        /// How many times discovery was asked for, answered or refused: one per fetch.
        discoveries: usize,
    }

    /// An issuer that is discovery and a JWKS and nothing else, whose published keys a test
    /// replaces and which a test takes down: the two things the test kit's fake issuer does
    /// not do. Each connection serves one request and is closed, so taking it down is seen by
    /// the very next fetch.
    struct StubIssuer {
        url: String,
        state: Arc<std::sync::Mutex<StubState>>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for StubIssuer {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    /// The status line and body for one request to a [`StubIssuer`].
    fn stub_answer(
        state: &std::sync::Mutex<StubState>,
        issuer: &str,
        path: &str,
    ) -> (&'static str, String) {
        let mut st = state.lock().unwrap();
        let body = match path {
            "/.well-known/openid-configuration" => {
                st.discoveries += 1;
                serde_json::json!({
                    "issuer": issuer,
                    "jwks_uri": format!("{issuer}/jwks"),
                    "token_endpoint": format!("{issuer}/token"),
                })
            }
            "/jwks" => st.jwks.clone(),
            _ => return ("404 Not Found", "{}".to_owned()),
        };
        if st.failing {
            ("503 Service Unavailable", "{}".to_owned())
        } else {
            ("200 OK", body.to_string())
        }
    }

    impl StubIssuer {
        async fn start(jwks: serde_json::Value) -> Self {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let state = Arc::new(std::sync::Mutex::new(StubState {
                jwks,
                failing: false,
                discoveries: 0,
            }));
            let (served, issuer) = (state.clone(), url.clone());
            let task = tokio::spawn(async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    let (served, issuer) = (served.clone(), issuer.clone());
                    tokio::spawn(async move {
                        let mut request = Vec::new();
                        let mut chunk = [0u8; 1024];
                        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                            match socket.read(&mut chunk).await {
                                Ok(n) if n > 0 => request.extend_from_slice(&chunk[..n]),
                                _ => return,
                            }
                        }
                        let request = String::from_utf8_lossy(&request).into_owned();
                        let path = request.split_whitespace().nth(1).unwrap_or_default();
                        let (status, body) = stub_answer(&served, &issuer, path);
                        let reply = format!(
                            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = socket.write_all(reply.as_bytes()).await;
                        let _ = socket.shutdown().await;
                    });
                }
            });
            Self {
                url,
                state,
                server: task,
            }
        }

        fn set_failing(&self, failing: bool) {
            self.state.lock().unwrap().failing = failing;
        }

        fn publish(&self, jwks: serde_json::Value) {
            self.state.lock().unwrap().jwks = jwks;
        }

        fn discoveries(&self) -> usize {
            self.state.lock().unwrap().discoveries
        }

        /// This issuer as the configuration names it: no group gate.
        fn config(&self) -> IssuerConfig {
            let mut cfg = gate_cfg(&serde_json::json!({ "allow_any_authenticated": true }));
            cfg.url.clone_from(&self.url);
            cfg
        }

        /// A login token of this issuer, signed with the test kit's issuer key.
        fn token(&self) -> String {
            mediatore_testkit::mint(
                &self.url,
                serde_json::json!({ "aud": "mediatore", "preferred_username": "octocat" }),
            )
        }
    }

    /// The JWKS document the test kit's fake issuer publishes (the public half of the key
    /// [`mediatore_testkit::mint`] signs with), its key renamed to `kid` when one is given.
    async fn test_jwks(kid: Option<&str>) -> serde_json::Value {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let set = v.discover(&idp.issuer, false).await.unwrap().set.clone();
        let mut jwks = serde_json::to_value(&set).unwrap();
        if let Some(kid) = kid {
            jwks["keys"][0]["kid"] = serde_json::json!(kid);
        }
        jwks
    }

    #[tokio::test]
    async fn a_failing_issuer_after_a_good_fetch_still_validates_with_the_cached_keys() {
        let issuer = StubIssuer::start(test_jwks(None).await).await;
        let v = Validator::new(vec![issuer.config()]);
        let token = issuer.token();
        v.validate(&token).await.unwrap();
        assert_eq!(issuer.discoveries(), 1);

        // The issuer goes away and the cache TTL runs out: the re-fetch fails, the keys
        // already held go on validating.
        issuer.set_failing(true);
        v.clock
            .advance(Duration::from_secs(JWKS_CACHE_TTL_SECS + 1));
        assert_eq!(v.validate(&token).await.unwrap().subject.id, "octocat");
        assert_eq!(issuer.discoveries(), 2, "the re-fetch was tried");
        // Inside the interval the failing issuer is left alone.
        for _ in 0..5 {
            v.validate(&token).await.unwrap();
        }
        assert_eq!(issuer.discoveries(), 2);
        // Past it, it is asked again, once, and the held keys still serve.
        v.clock.advance(past_the_interval());
        v.validate(&token).await.unwrap();
        v.validate(&token).await.unwrap();
        assert_eq!(issuer.discoveries(), 3);

        // Back up: the next try past the interval takes a fresh set, and that one is cached.
        issuer.set_failing(false);
        v.clock.advance(past_the_interval());
        v.validate(&token).await.unwrap();
        v.validate(&token).await.unwrap();
        assert_eq!(issuer.discoveries(), 4);
    }

    #[tokio::test]
    async fn an_unknown_kid_while_the_issuer_is_down_is_an_outage_once_and_the_cached_keys_still_serve()
     {
        let issuer = StubIssuer::start(test_jwks(None).await).await;
        let v = Validator::new(vec![issuer.config()]);
        let token = issuer.token();
        v.validate(&token).await.unwrap();
        issuer.set_failing(true);
        v.clock.advance(past_the_interval());
        // The cache is within its TTL; the miss is what asks, and the issuer does not answer.
        assert!(matches!(
            v.validate(&with_kid(&token, "rotated-in-elsewhere")).await,
            Err(IdpError::Upstream(_))
        ));
        assert_eq!(issuer.discoveries(), 2);
        // The next misses are inside the interval: refused from the held set, nothing asked.
        assert!(matches!(
            v.validate(&with_kid(&token, "rotated-in-elsewhere")).await,
            Err(IdpError::Invalid(_))
        ));
        v.validate(&token).await.unwrap();
        assert_eq!(issuer.discoveries(), 2);
    }

    #[tokio::test]
    async fn a_rotated_in_key_is_accepted_by_the_first_validation_after_the_interval() {
        // The issuer publishes its key under another name: the token's kid is unknown.
        let issuer = StubIssuer::start(test_jwks(Some("retired")).await).await;
        let v = Validator::new(vec![issuer.config()]);
        let token = issuer.token();
        assert!(matches!(
            v.validate(&token).await,
            Err(IdpError::Invalid(_))
        ));
        assert_eq!(issuer.discoveries(), 1);

        // The key is rotated in. Inside the interval the held set still answers.
        issuer.publish(test_jwks(None).await);
        assert!(matches!(
            v.validate(&token).await,
            Err(IdpError::Invalid(_))
        ));
        assert_eq!(issuer.discoveries(), 1, "no fetch inside the interval");

        // Past it, the first miss fetches and the token validates on that same call.
        v.clock.advance(past_the_interval());
        assert_eq!(v.validate(&token).await.unwrap().subject.id, "octocat");
        assert_eq!(issuer.discoveries(), 2);
    }

    #[tokio::test]
    async fn a_key_set_past_the_maximum_staleness_is_not_served() {
        let issuer = StubIssuer::start(test_jwks(None).await).await;
        let v = Validator::new(vec![issuer.config()]);
        let token = issuer.token();
        v.validate(&token).await.unwrap();
        issuer.set_failing(true);

        // Just inside the maximum: stale, the re-fetch fails, the held keys serve.
        let margin = past_the_interval().as_secs();
        v.clock
            .advance(Duration::from_secs(JWKS_MAX_STALE_SECS - margin));
        v.validate(&token).await.unwrap();
        assert_eq!(issuer.discoveries(), 2);

        // Past it: the outage is the caller's, and every caller asks, as with a cold cache.
        v.clock.advance(Duration::from_secs(margin + 1));
        for asked in 3..=4 {
            assert!(matches!(
                v.validate(&token).await,
                Err(IdpError::Upstream(_))
            ));
            assert_eq!(issuer.discoveries(), asked);
        }

        // And the issuer coming back is seen at once.
        issuer.set_failing(false);
        v.validate(&token).await.unwrap();
    }

    #[tokio::test]
    async fn an_issuer_that_never_answers_is_an_outage_within_the_timeout_and_asked_once() {
        // Accepts every connection and never answers: up at the socket, away above it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = accepted.clone();
        let held = tokio::spawn(async move {
            let mut sockets = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                sockets.push(socket);
            }
        });
        let mut cfg = gate_cfg(&serde_json::json!({ "allow_any_authenticated": true }));
        cfg.url.clone_from(&issuer);
        let v = Validator::with_timeouts(
            vec![cfg],
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let token = mediatore_testkit::mint(
            &issuer,
            serde_json::json!({ "aud": "mediatore", "preferred_username": "octocat" }),
        );
        let started = Instant::now();
        let callers: Vec<_> = (0..8)
            .map(|_| {
                let (v, token) = (v.clone(), token.clone());
                tokio::spawn(async move { v.validate(&token).await.map(|out| out.subject.id) })
            })
            .collect();
        for caller in callers {
            assert!(
                matches!(caller.await.unwrap(), Err(IdpError::Upstream(_))),
                "an issuer that does not answer is an outage, never a refusal"
            );
        }
        let waited = started.elapsed();
        held.abort();
        assert!(
            waited < Duration::from_secs(5),
            "the callers that waited share the failed fetch, they do not repeat it in turn"
        );
        assert_eq!(
            accepted.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one fetch was tried for all of them"
        );
    }
}
