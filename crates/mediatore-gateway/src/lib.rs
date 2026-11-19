// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The egress gateway's authorizer, `mediatore gateway` (ADR-0028 decision 4): Envoy's
//! external authorization service on the gateway VM. Envoy has already required a client
//! certificate and validated it against the trust bundle; for each `CONNECT` it asks this
//! process, over gRPC, whether the caller may reach the authority. The answer
//! comes from a bounded cache of one allowlist per claim UID, filled from the broker's
//! gateway-only route over SPIFFE mTLS with the gateway SVID ([`broker`]).
//!
//! What the check carries, set by Envoy from the downstream connection and never read from
//! the client (`headers_to_add` overrides anything the client sent, and nothing but Envoy
//! reaches this listener): the peer's URI SAN, the request method and the authority
//! ([`serve`]). What this process decides ([`Authorizer::authorize`]):
//!
//! - the peer must be a claim identity of this trust domain, `spiffe://<td>/banlieue/claim/<uid>`;
//! - the method must be `CONNECT` and the authority `host:port` (decision 3: one shape);
//! - the authority must be in the claim's allowlist, exactly;
//! - the allowlist is the broker's answer, fresh for a bound, served stale for a further
//!   bound when the broker is unreachable, never past the claim's deadline, dropped when
//!   the broker answers `404` (released, expired, pending, unknown);
//! - the broker unreachable and nothing cached, or the broker refusing the gateway's own
//!   identity, is a deny.
//!
//! Every decision is one log line keyed by claim UID; never a token, never a body.
//!
//! # Gateway-placed credentials (ADR-0040)
//!
//! A second kind of question, on a second socket for a second Envoy (`envoy-inject`):
//! [`Authorizer::authorize_inject`]. The peer must again be a claim; the request is an
//! ordinary HTTP request (never `CONNECT`) whose authority must be the exact `host:port` of
//! one of the claim's gateway-placed routes and whose method and path must be admitted by
//! that route's rules. Only then is the credential obtained from the broker
//! ([`broker::Credentials`], `POST /v1/gateway/claims/{uid}/credential`), kept in memory for
//! at most the lesser of a minute and its expiry less a margin, and never past the claim's
//! deadline, and answered as the headers Envoy must set on the upstream request. The
//! credential is a [`Secret`] throughout: it is in no log line, no refusal and no `Debug`.

#![forbid(unsafe_code)]

pub mod broker;
pub mod serve;

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use jiff::Timestamp;
use mediatore_proto::{ClaimEgress, Endpoint, HeaderPair, InjectRoute, Secret};
use mediatore_spire::Naming;
use uuid::Uuid;

use crate::broker::{Allowlists, Answer, AskError, CredentialAnswer, Credentials};

/// How many claims [`Authorizer::sweep`] asks the broker about at once. Each ask is its own mutual TLS
/// connection with its own timeout, so one at a time lets a long list of claims, or a broker that answers
/// nothing, stretch a sweep past `sweep_every`, and with it the time a released claim's credential stays in
/// memory (ADR-0040 decision 5). Bounded, so a sweep is never a burst of connections at the broker.
const SWEEP_CONCURRENCY: usize = 8;

/// The cache's bounds.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// How long an answer is used without asking the broker again.
    pub fresh_for: Duration,
    /// How long past `fresh_for` an answer still stands in when the broker is unreachable.
    /// Past this, an outage is a deny.
    pub stale_for: Duration,
    /// How many claims the cache holds; past it, the least recently used entry goes. The
    /// credential cache is bounded by the same number of entries.
    pub max_claims: usize,
    /// The most a gateway-placed credential is kept (ADR-0040 decision 5): 60 seconds.
    pub credential_for: Duration,
    /// How long before its expiry a credential stops being kept (ADR-0040 decision 5): 30
    /// seconds. Past that margin the credential is used for the request that fetched it and
    /// not kept.
    pub credential_margin: Duration,
    /// How often the sweep asks the broker about every claim that holds a kept credential, so a released
    /// claim's credential leaves memory within this long of the release without a request for it (ADR-0040
    /// decision 5): 10 seconds.
    pub sweep_every: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            fresh_for: Duration::from_secs(30),
            stale_for: Duration::from_secs(300),
            max_claims: 4096,
            credential_for: Duration::from_secs(60),
            credential_margin: Duration::from_secs(30),
            sweep_every: Duration::from_secs(10),
        }
    }
}

/// Why a check was refused. Stable names, logged and returned in the deny body; nothing
/// in them names a destination the caller did not already name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The peer is not a claim identity of this trust domain.
    NotAClaim,
    /// The method is not `CONNECT`.
    NotConnect,
    /// The authority is not `host:port`.
    BadAuthority,
    /// The claim's allowlist does not name the authority.
    NotAllowed,
    /// The broker says the claim is gone: released, expired, pending or unknown.
    ClaimGone,
    /// The broker is unreachable and nothing cached stands in.
    BrokerUnreachable,
    /// The broker refused the gateway's own identity.
    BrokerRefused,
    /// An inject question that cannot be one: a `CONNECT`, or this authorizer has no
    /// credential source.
    NotInject,
    /// The broker would not place the credential (`403`), answered for another audience than
    /// the one asked, or answered one that has already expired.
    CredentialRefused,
}

impl Refusal {
    /// The stable name.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotAClaim => "not_a_claim",
            Self::NotConnect => "not_connect",
            Self::BadAuthority => "bad_authority",
            Self::NotAllowed => "not_allowed",
            Self::ClaimGone => "claim_gone",
            Self::BrokerUnreachable => "broker_unreachable",
            Self::BrokerRefused => "broker_refused",
            Self::NotInject => "not_inject",
            Self::CredentialRefused => "credential_refused",
        }
    }
}

/// Where the allowlist a decision used came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// A fresh entry.
    Cache,
    /// The broker, asked now.
    Broker,
    /// A stale entry, the broker being unreachable.
    Stale,
    /// No allowlist was consulted.
    None,
}

/// One check's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The claim, once the peer parsed as one.
    pub claim_uid: Option<Uuid>,
    /// `Ok(())` to allow; the refusal otherwise.
    pub verdict: Result<(), Refusal>,
    /// Where the allowlist came from.
    pub served: Served,
}

impl Decision {
    fn refuse(claim_uid: Option<Uuid>, why: Refusal, served: Served) -> Self {
        Self {
            claim_uid,
            verdict: Err(why),
            served,
        }
    }
}

/// What Envoy must do to the upstream request when an inject check is allowed. Holds the
/// credential, so it prints it as `[redacted]` and is never logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectAllow {
    /// The request header the credential goes in, lowercase.
    pub header: String,
    /// The whole header value.
    pub value: Secret,
    /// Public headers set beside it (`anthropic-version`).
    pub extra_headers: Vec<HeaderPair>,
    /// Credential-bearing headers a client could have sent, removed from the request. Never
    /// the route's own header and never an extra header: those are set by overwrite, which
    /// replaces a client's copy, so no ordering of Envoy's removals and additions can strip
    /// the credential this answer adds.
    pub remove_headers: Vec<String>,
}

/// One inject check's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectDecision {
    /// The claim, once the peer parsed as one.
    pub claim_uid: Option<Uuid>,
    /// The audience of the matched route, once there was one.
    pub audience: Option<String>,
    /// The authority as the request carried it, for the decision line.
    pub host: String,
    /// What to do to the request, or the refusal.
    pub verdict: Result<InjectAllow, Refusal>,
}

/// One claim's cached answer.
struct Entry {
    egress: BTreeSet<Endpoint>,
    inject: Arc<Vec<InjectRoute>>,
    expires_at: Timestamp,
    fetched_at: Instant,
    used_at: Instant,
}

impl Entry {
    fn allows(&self, authority: &Endpoint) -> bool {
        self.egress.contains(authority)
    }
}

#[derive(Default)]
struct Cache {
    entries: HashMap<Uuid, Entry>,
}

impl Cache {
    /// Insert, evicting the least recently used entry past the bound.
    fn put(&mut self, uid: Uuid, entry: Entry, max: usize) {
        self.entries.insert(uid, entry);
        while self.entries.len() > max.max(1) {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.used_at)
                .map(|(k, _)| *k)
                .expect("non-empty");
            self.entries.remove(&oldest);
        }
    }
}

/// A claim and an audience: what one credential is for.
type CredentialKey = (Uuid, String);

/// A credential as the authorizer holds it. Kept in memory only.
#[derive(Clone)]
struct HeldCredential {
    header: String,
    value: Secret,
    extra_headers: Vec<HeaderPair>,
}

struct CredentialEntry {
    held: HeldCredential,
    /// Past this instant the entry is not served: the least of the cache bound, the
    /// credential's expiry less the margin, and the claim's deadline.
    valid_until: Instant,
    used_at: Instant,
}

/// The authorizer: the cache, its bounds, and where answers come from.
pub struct Authorizer {
    naming: Naming,
    source: Arc<dyn Allowlists>,
    creds: Option<Arc<dyn Credentials>>,
    cfg: CacheConfig,
    cache: std::sync::Mutex<Cache>,
    credentials: std::sync::Mutex<HashMap<CredentialKey, CredentialEntry>>,
    /// One ask in flight per claim: checks arriving together for the same claim share it.
    asking: std::sync::Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>,
    /// The same for a claim's credential, per audience.
    cred_asking: std::sync::Mutex<HashMap<CredentialKey, Arc<tokio::sync::Mutex<()>>>>,
}

impl Authorizer {
    /// An authorizer for `trust_domain`'s claims, answering from `source` within `cfg`.
    /// Without [`Self::with_credentials`] every inject check is refused.
    #[must_use]
    pub fn new(trust_domain: &str, source: Arc<dyn Allowlists>, cfg: CacheConfig) -> Self {
        Self {
            naming: Naming {
                trust_domain: trust_domain.to_owned(),
            },
            source,
            creds: None,
            cfg,
            cache: std::sync::Mutex::new(Cache::default()),
            credentials: std::sync::Mutex::new(HashMap::new()),
            asking: std::sync::Mutex::new(HashMap::new()),
            cred_asking: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Where gateway-placed credentials come from (ADR-0040 decision 2).
    #[must_use]
    pub fn with_credentials(mut self, creds: Arc<dyn Credentials>) -> Self {
        self.creds = Some(creds);
        self
    }

    /// The decision for one check, as the module documentation lays it out.
    pub async fn authorize(&self, peer: &str, method: &str, authority: &str) -> Decision {
        let Some(uid) = self.naming.claim_uid_from(peer) else {
            return Decision::refuse(None, Refusal::NotAClaim, Served::None);
        };
        if !method.eq_ignore_ascii_case("CONNECT") {
            return Decision::refuse(Some(uid), Refusal::NotConnect, Served::None);
        }
        let Ok(authority) = authority.parse::<Endpoint>().map(normalised) else {
            return Decision::refuse(Some(uid), Refusal::BadAuthority, Served::None);
        };
        let (allowed, served) = self.entry_view(uid, |e| e.allows(&authority)).await;
        Decision {
            claim_uid: Some(uid),
            verdict: allowed.and_then(|ok| ok.then_some(()).ok_or(Refusal::NotAllowed)),
            served,
        }
    }

    /// The decision for one inject check (ADR-0040 decision 4): `method`, `host` (as the
    /// request carried it, with its port if it had one) and `path` (with its query, which is
    /// not part of what the rules match) are what Envoy saw; `peer` is the verified
    /// certificate's URI SAN.
    pub async fn authorize_inject(
        &self,
        peer: &str,
        method: &str,
        host: &str,
        path: &str,
    ) -> InjectDecision {
        let refuse = |claim_uid, audience, why| InjectDecision {
            claim_uid,
            audience,
            host: host.to_owned(),
            verdict: Err(why),
        };
        let Some(uid) = self.naming.claim_uid_from(peer) else {
            return refuse(None, None, Refusal::NotAClaim);
        };
        if method.eq_ignore_ascii_case("CONNECT") || self.creds.is_none() {
            return refuse(Some(uid), None, Refusal::NotInject);
        }
        let Some((name, port)) = split_host_port(host) else {
            return refuse(Some(uid), None, Refusal::BadAuthority);
        };
        let (routes, _) = self.entry_view(uid, |e| e.inject.clone()).await;
        let routes = match routes {
            Ok(r) => r,
            Err(why) => return refuse(Some(uid), None, why),
        };
        let Some(route) = routes.iter().find(|r| r.matches_authority(&name, port)) else {
            return refuse(Some(uid), None, Refusal::NotAllowed);
        };
        let audience = Some(route.audience.clone());
        let path = path.split(['?', '#']).next().unwrap_or_default();
        if !route.admits(method, path) {
            return refuse(Some(uid), audience, Refusal::NotAllowed);
        }
        match self.credential_for(uid, &route.audience).await {
            Ok(held) => {
                let own: BTreeSet<String> = std::iter::once(route.header.to_ascii_lowercase())
                    .chain(
                        held.extra_headers
                            .iter()
                            .map(|h| h.name.to_ascii_lowercase()),
                    )
                    .collect();
                InjectDecision {
                    claim_uid: Some(uid),
                    audience,
                    host: host.to_owned(),
                    verdict: Ok(InjectAllow {
                        header: held.header,
                        value: held.value,
                        extra_headers: held.extra_headers,
                        remove_headers: route
                            .client_headers_to_strip()
                            .into_iter()
                            .filter(|h| !own.contains(h))
                            .collect(),
                    }),
                }
            }
            Err(why) => refuse(Some(uid), audience, why),
        }
    }

    /// `read` applied to the claim's entry: the fresh one, or the broker's answer now (one ask
    /// per claim at a time; whoever waited reads what the ask left), or the stale one when the
    /// broker is unreachable. The verdict and where the entry came from.
    async fn entry_view<T>(
        &self,
        uid: Uuid,
        read: impl Fn(&Entry) -> T,
    ) -> (Result<T, Refusal>, Served) {
        if let Some(v) = self.fresh_with(uid, Timestamp::now(), Instant::now(), &read) {
            return (Ok(v), Served::Cache);
        }
        let ask_lock = self.asking_lock(uid);
        let held = ask_lock.lock().await;
        let out = self.ask_view(uid, &read).await;
        drop(held);
        drop(ask_lock);
        lock(&self.asking).retain(|_, l| Arc::strong_count(l) > 1);
        out
    }

    /// Under the claim's ask lock: a fresh entry a parallel check just filled, or the
    /// broker's answer now.
    async fn ask_view<T>(
        &self,
        uid: Uuid,
        read: &impl Fn(&Entry) -> T,
    ) -> (Result<T, Refusal>, Served) {
        if let Some(v) = self.fresh_with(uid, Timestamp::now(), Instant::now(), read) {
            return (Ok(v), Served::Cache);
        }
        match self.source.ask(uid).await {
            Ok(Answer::Found(answer)) => {
                if !self.admit(uid, answer, Instant::now()) {
                    return (Err(Refusal::NotAllowed), Served::Broker);
                }
                let seen = lock(&self.cache).entries.get(&uid).map(read);
                (seen.ok_or(Refusal::NotAllowed), Served::Broker)
            }
            Ok(Answer::Gone) => {
                self.forget_claim(uid);
                (Err(Refusal::ClaimGone), Served::Broker)
            }
            Err(AskError::Refused(status)) => {
                tracing::error!(claim_uid = %uid, status, "the broker refused the gateway identity");
                (Err(Refusal::BrokerRefused), Served::None)
            }
            Err(AskError::Unreachable(why)) => {
                if let Some(v) = self.stale_with(uid, Timestamp::now(), Instant::now(), read) {
                    tracing::warn!(claim_uid = %uid, error = %why, "broker unreachable; serving the stale allowlist");
                    (Ok(v), Served::Stale)
                } else {
                    tracing::warn!(claim_uid = %uid, error = %why, "broker unreachable and nothing cached; denied");
                    (Err(Refusal::BrokerUnreachable), Served::None)
                }
            }
        }
    }

    fn asking_lock(&self, uid: Uuid) -> Arc<tokio::sync::Mutex<()>> {
        lock(&self.asking).entry(uid).or_default().clone()
    }

    /// `read` on the fresh entry, if there is one: within `fresh_for` and before the claim's
    /// deadline. Marks the entry used. An entry past its deadline goes, and its credentials
    /// with it.
    fn fresh_with<T>(
        &self,
        uid: Uuid,
        now: Timestamp,
        tick: Instant,
        read: impl FnOnce(&Entry) -> T,
    ) -> Option<T> {
        let mut cache = lock(&self.cache);
        let entry = cache.entries.get_mut(&uid)?;
        if entry.expires_at <= now {
            cache.entries.remove(&uid);
            drop(cache);
            self.forget_credentials(uid);
            return None;
        }
        if tick.duration_since(entry.fetched_at) >= self.cfg.fresh_for {
            return None;
        }
        entry.used_at = tick;
        Some(read(entry))
    }

    /// `read` on the stale entry, if one stands in: within `fresh_for + stale_for` and
    /// before the claim's deadline.
    fn stale_with<T>(
        &self,
        uid: Uuid,
        now: Timestamp,
        tick: Instant,
        read: impl FnOnce(&Entry) -> T,
    ) -> Option<T> {
        let mut cache = lock(&self.cache);
        let entry = cache.entries.get_mut(&uid)?;
        if entry.expires_at <= now {
            cache.entries.remove(&uid);
            drop(cache);
            self.forget_credentials(uid);
            return None;
        }
        if tick.duration_since(entry.fetched_at) >= self.cfg.fresh_for + self.cfg.stale_for {
            cache.entries.remove(&uid);
            return None;
        }
        entry.used_at = tick;
        Some(read(entry))
    }

    /// Keep the broker's answer; `false` when it is already past its deadline, in which
    /// case nothing is kept.
    fn admit(&self, uid: Uuid, answer: ClaimEgress, tick: Instant) -> bool {
        if answer.expires_at <= Timestamp::now() {
            lock(&self.cache).entries.remove(&uid);
            self.forget_credentials(uid);
            return false;
        }
        let entry = Entry {
            egress: answer.egress.into_iter().map(normalised).collect(),
            inject: Arc::new(answer.inject.into_iter().map(normalised_route).collect()),
            expires_at: answer.expires_at,
            fetched_at: tick,
            used_at: tick,
        };
        lock(&self.cache).put(uid, entry, self.cfg.max_claims);
        true
    }

    /// The broker said the claim is gone: nothing of it is kept.
    fn forget_claim(&self, uid: Uuid) {
        lock(&self.cache).entries.remove(&uid);
        self.forget_credentials(uid);
    }

    fn forget_credentials(&self, uid: Uuid) {
        lock(&self.credentials).retain(|(claim, _), _| *claim != uid);
    }

    /// The claim's credential for `audience`: the kept one, or the broker's now (one ask per
    /// claim and audience at a time).
    async fn credential_for(&self, uid: Uuid, audience: &str) -> Result<HeldCredential, Refusal> {
        let key: CredentialKey = (uid, audience.to_owned());
        if let Some(held) = self.credential_fresh(&key, Instant::now()) {
            return Ok(held);
        }
        let ask_lock = lock(&self.cred_asking)
            .entry(key.clone())
            .or_default()
            .clone();
        let held = ask_lock.lock().await;
        let out = self.ask_credential(&key).await;
        drop(held);
        drop(ask_lock);
        lock(&self.cred_asking).retain(|_, l| Arc::strong_count(l) > 1);
        out
    }

    fn credential_fresh(&self, key: &CredentialKey, tick: Instant) -> Option<HeldCredential> {
        let mut kept = lock(&self.credentials);
        let entry = kept.get_mut(key)?;
        if tick >= entry.valid_until {
            kept.remove(key);
            return None;
        }
        entry.used_at = tick;
        Some(entry.held.clone())
    }

    async fn ask_credential(&self, key: &CredentialKey) -> Result<HeldCredential, Refusal> {
        if let Some(held) = self.credential_fresh(key, Instant::now()) {
            return Ok(held);
        }
        let (uid, audience) = (key.0, key.1.as_str());
        let Some(creds) = self.creds.as_ref() else {
            return Err(Refusal::NotInject);
        };
        match creds.credential(uid, audience).await {
            Ok(CredentialAnswer::Found(cred)) => {
                if cred.audience != audience || cred.expires_at <= Timestamp::now() {
                    tracing::warn!(claim_uid = %uid, audience, "the broker's credential answer was for another audience or already expired; denied");
                    return Err(Refusal::CredentialRefused);
                }
                // Envoy's header add drops an empty value without an error: an empty credential would reach the
                // upstream as no credential, silently. Refuse it here.
                if cred.value.0.is_empty() || cred.header.is_empty() {
                    tracing::warn!(claim_uid = %uid, audience, "the broker's credential answer had an empty header or value; denied");
                    return Err(Refusal::CredentialRefused);
                }
                Ok(self.keep_credential(key, cred))
            }
            Ok(CredentialAnswer::Gone) => {
                self.forget_claim(uid);
                Err(Refusal::ClaimGone)
            }
            Err(AskError::Refused(401)) => {
                tracing::error!(claim_uid = %uid, status = 401, "the broker refused the gateway identity");
                Err(Refusal::BrokerRefused)
            }
            Err(AskError::Refused(status)) => {
                tracing::warn!(claim_uid = %uid, audience, status, "the broker would not place the credential");
                Err(Refusal::CredentialRefused)
            }
            Err(AskError::Unreachable(why)) => {
                tracing::warn!(claim_uid = %uid, audience, error = %why, "broker unreachable and no credential kept; denied");
                Err(Refusal::BrokerUnreachable)
            }
        }
    }

    /// Keep the credential for its bound and hand it back: at most `credential_for`, at most
    /// its expiry less `credential_margin`, at most until the claim's deadline. A zero bound
    /// keeps nothing, and the credential still serves the request that fetched it.
    fn keep_credential(
        &self,
        key: &CredentialKey,
        cred: mediatore_proto::GatewayCredential,
    ) -> HeldCredential {
        let now = Timestamp::now();
        let tick = Instant::now();
        let left =
            |at: Timestamp| Duration::try_from(at.duration_since(now)).unwrap_or(Duration::ZERO);
        let mut bound = left(cred.expires_at)
            .saturating_sub(self.cfg.credential_margin)
            .min(self.cfg.credential_for);
        if let Some(deadline) = lock(&self.cache).entries.get(&key.0).map(|e| e.expires_at) {
            bound = bound.min(left(deadline));
        }
        let held = HeldCredential {
            header: cred.header,
            value: cred.value,
            extra_headers: cred.extra_headers,
        };
        if !bound.is_zero() {
            let mut kept = lock(&self.credentials);
            kept.retain(|_, e| e.valid_until > tick);
            kept.insert(
                key.clone(),
                CredentialEntry {
                    held: held.clone(),
                    valid_until: tick + bound,
                    used_at: tick,
                },
            );
            while kept.len() > self.cfg.max_claims.max(1) {
                let oldest = kept
                    .iter()
                    .min_by_key(|(_, e)| e.used_at)
                    .map(|(k, _)| k.clone())
                    .expect("non-empty");
                kept.remove(&oldest);
            }
        }
        held
    }

    /// Drop what a released claim left in memory (ADR-0040 decision 5). A credential lives for its claim and not
    /// past it, and a request is not needed to notice the release: every credential past its own bound goes, then
    /// the broker is asked about each claim that still holds one, and a claim the broker no longer knows is
    /// forgotten with its routes and credentials. A broker that cannot be reached or refuses is not a release: what
    /// is kept stays until its own bound, as a check would serve it. At most `SWEEP_CONCURRENCY` claims are
    /// asked about at once. Returns how many claims were forgotten.
    pub async fn sweep(&self) -> usize {
        let tick = Instant::now();
        lock(&self.credentials).retain(|_, e| e.valid_until > tick);
        let claims: std::collections::BTreeSet<Uuid> = lock(&self.credentials)
            .keys()
            .map(|(uid, _)| *uid)
            .collect();
        let forgotten = AtomicUsize::new(0);
        let forgotten_ref = &forgotten;
        // Each claim's ask and its outcome stand alone: nothing is shared between two claims but the tables' own
        // short locks, which are never held across the ask.
        futures::stream::iter(claims)
            .for_each_concurrent(SWEEP_CONCURRENCY, |uid| async move {
                match self.source.ask(uid).await {
                    Ok(Answer::Gone) => {
                        self.forget_claim(uid);
                        forgotten_ref.fetch_add(1, Ordering::Relaxed);
                        tracing::info!(claim_uid = %uid, "claim released; its routes and credentials are gone from memory");
                    }
                    Ok(Answer::Found(answer)) => {
                        self.admit(uid, answer, Instant::now());
                    }
                    Err(_) => {}
                }
            })
            .await;
        forgotten.into_inner()
    }

    /// Run [`Self::sweep`] every `sweep_every` until the task is dropped.
    pub fn spawn_sweeper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut every = tokio::time::interval(this.cfg.sweep_every);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            every.tick().await;
            loop {
                every.tick().await;
                this.sweep().await;
            }
        })
    }

    /// How many claims the cache holds now.
    #[must_use]
    pub fn cached(&self) -> usize {
        lock(&self.cache).entries.len()
    }

    /// How many credentials are kept now.
    #[must_use]
    pub fn cached_credentials(&self) -> usize {
        lock(&self.credentials).len()
    }
}

/// The lock, poisoned or not: a check that panicked mid-update left nothing the next
/// check does not recompute, so the data is taken as it is.
fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Host names compare case-insensitively; addresses are left alone.
fn normalised(mut e: Endpoint) -> Endpoint {
    e.host = e.host.to_ascii_lowercase();
    e
}

fn normalised_route(mut r: InjectRoute) -> InjectRoute {
    r.endpoint = normalised(r.endpoint);
    r.header = r.header.to_ascii_lowercase();
    r
}

/// A request's authority: the host and the port when there is one. An IPv6 address is in
/// brackets, a port is 1 to 65535, and anything else is not an authority.
fn split_host_port(authority: &str) -> Option<(String, Option<u16>)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        match after {
            "" => (host, None),
            _ => (host, Some(after.strip_prefix(':')?)),
        }
    } else {
        match authority.split_once(':') {
            None => (authority, None),
            Some((host, port)) if !port.contains(':') => (host, Some(port)),
            Some(_) => return None,
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        None => None,
        Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p != 0)?),
    };
    Some((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TD: &str = "sandbox.test";

    /// Answers scripted per ask, counting them.
    struct Scripted {
        answers: std::sync::Mutex<Vec<Result<Answer, AskError>>>,
        asks: AtomicUsize,
        delay: Duration,
    }

    impl Scripted {
        fn new(answers: Vec<Result<Answer, AskError>>) -> Arc<Self> {
            Arc::new(Self {
                answers: std::sync::Mutex::new(answers),
                asks: AtomicUsize::new(0),
                delay: Duration::ZERO,
            })
        }
    }

    #[async_trait::async_trait]
    impl Allowlists for Scripted {
        async fn ask(&self, _: Uuid) -> Result<Answer, AskError> {
            self.asks.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            let mut answers = self.answers.lock().unwrap();
            if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers[0].clone()
            }
        }
    }

    fn found(egress: &[&str], ttl_secs: i64) -> Answer {
        Answer::Found(ClaimEgress {
            claim_uid: Uuid::nil(),
            expires_at: Timestamp::now() + jiff::SignedDuration::from_secs(ttl_secs),
            egress: egress.iter().map(|e| e.parse().unwrap()).collect(),
            inject: Vec::new(),
        })
    }

    fn unreachable() -> Result<Answer, AskError> {
        Err(AskError::Unreachable("connection refused".into()))
    }

    fn claim(uid: Uuid) -> String {
        format!("spiffe://{TD}/banlieue/claim/{uid}")
    }

    fn cfg(fresh: u64, stale: u64, max: usize) -> CacheConfig {
        CacheConfig {
            fresh_for: Duration::from_millis(fresh),
            stale_for: Duration::from_millis(stale),
            max_claims: max,
            ..CacheConfig::default()
        }
    }

    #[tokio::test]
    async fn the_peer_the_method_and_the_authority_are_checked_before_anyone_is_asked() {
        let src = Scripted::new(vec![Ok(found(&["api.home.example:443"], 600))]);
        let a = Authorizer::new(TD, src.clone(), CacheConfig::default());
        let uid = Uuid::new_v4();
        for (peer, method, authority, why) in [
            (
                format!("spiffe://{TD}/banlieue/node/abc"),
                "CONNECT",
                "api.home.example:443",
                Refusal::NotAClaim,
            ),
            (
                format!("spiffe://other.test/banlieue/claim/{uid}"),
                "CONNECT",
                "api.home.example:443",
                Refusal::NotAClaim,
            ),
            (
                format!("spiffe://{TD}/gateway"),
                "CONNECT",
                "api.home.example:443",
                Refusal::NotAClaim,
            ),
            (
                claim(uid),
                "GET",
                "api.home.example:443",
                Refusal::NotConnect,
            ),
            (
                claim(uid),
                "CONNECT",
                "api.home.example",
                Refusal::BadAuthority,
            ),
            (claim(uid), "CONNECT", "", Refusal::BadAuthority),
        ] {
            let d = a.authorize(&peer, method, authority).await;
            assert_eq!(d.verdict, Err(why), "{peer} {method} {authority}");
            assert_eq!(d.served, Served::None);
        }
        assert_eq!(
            src.asks.load(Ordering::SeqCst),
            0,
            "nothing reached the broker"
        );
    }

    #[tokio::test]
    async fn an_allowlist_is_fetched_once_within_the_fresh_bound_and_compared_exactly() {
        let src = Scripted::new(vec![Ok(found(
            &["API.Home.Example:443", "192.0.2.10:8443"],
            600,
        ))]);
        let a = Authorizer::new(TD, src.clone(), cfg(10_000, 0, 16));
        let uid = Uuid::new_v4();
        let first = a
            .authorize(&claim(uid), "connect", "api.home.example:443")
            .await;
        assert_eq!(first.verdict, Ok(()));
        assert_eq!(first.served, Served::Broker);
        assert_eq!(first.claim_uid, Some(uid));
        for (authority, want) in [
            ("api.home.example:443", Ok(())),
            ("192.0.2.10:8443", Ok(())),
            ("api.home.example:8443", Err(Refusal::NotAllowed)),
            ("other.home.example:443", Err(Refusal::NotAllowed)),
            ("[2001:db8::1]:443", Err(Refusal::NotAllowed)),
        ] {
            let d = a.authorize(&claim(uid), "CONNECT", authority).await;
            assert_eq!(d.verdict, want, "{authority}");
            assert_eq!(d.served, Served::Cache, "{authority}");
        }
        assert_eq!(src.asks.load(Ordering::SeqCst), 1, "one ask for the claim");
        assert_eq!(a.cached(), 1);
    }

    #[tokio::test]
    async fn past_the_fresh_bound_the_broker_is_asked_again_and_a_gone_claim_is_dropped() {
        let src = Scripted::new(vec![
            Ok(found(&["api.home.example:443"], 600)),
            Ok(Answer::Gone),
            Ok(found(&["api.home.example:443"], 600)),
        ]);
        let a = Authorizer::new(TD, src.clone(), cfg(20, 0, 16));
        let uid = Uuid::new_v4();
        assert_eq!(
            a.authorize(&claim(uid), "CONNECT", "api.home.example:443")
                .await
                .verdict,
            Ok(())
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        let d = a
            .authorize(&claim(uid), "CONNECT", "api.home.example:443")
            .await;
        assert_eq!(d.verdict, Err(Refusal::ClaimGone));
        assert_eq!(d.served, Served::Broker);
        assert_eq!(a.cached(), 0, "a gone claim leaves nothing behind");
        // Asked again on the next check, not remembered as gone.
        let d = a
            .authorize(&claim(uid), "CONNECT", "api.home.example:443")
            .await;
        assert_eq!(d.verdict, Ok(()));
        assert_eq!(src.asks.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn an_outage_serves_the_stale_allowlist_within_its_bound_then_denies() {
        let src = Scripted::new(vec![
            Ok(found(&["api.home.example:443"], 600)),
            unreachable(),
        ]);
        let a = Authorizer::new(TD, src.clone(), cfg(20, 40, 16));
        let uid = Uuid::new_v4();
        assert_eq!(
            a.authorize(&claim(uid), "CONNECT", "api.home.example:443")
                .await
                .verdict,
            Ok(())
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        // Past fresh, within stale: the broker is asked, fails, the old answer stands in.
        let d = a
            .authorize(&claim(uid), "CONNECT", "api.home.example:443")
            .await;
        assert_eq!(d.verdict, Ok(()));
        assert_eq!(d.served, Served::Stale);
        let d = a
            .authorize(&claim(uid), "CONNECT", "other.home.example:443")
            .await;
        assert_eq!(
            d.verdict,
            Err(Refusal::NotAllowed),
            "stale is still the allowlist"
        );
        assert_eq!(d.served, Served::Stale);
        tokio::time::sleep(Duration::from_millis(40)).await;
        // Past fresh + stale: the outage is a deny, and the entry is gone.
        let d = a
            .authorize(&claim(uid), "CONNECT", "api.home.example:443")
            .await;
        assert_eq!(d.verdict, Err(Refusal::BrokerUnreachable));
        assert_eq!(a.cached(), 0);
        // A claim never seen during an outage is a deny from the start.
        let d = a
            .authorize(&claim(Uuid::new_v4()), "CONNECT", "api.home.example:443")
            .await;
        assert_eq!(d.verdict, Err(Refusal::BrokerUnreachable));
        assert_eq!(d.served, Served::None);
    }

    #[tokio::test]
    async fn the_broker_refusing_the_gateway_is_a_deny_whatever_is_cached() {
        let src = Scripted::new(vec![
            Ok(found(&["api.home.example:443"], 600)),
            Err(AskError::Refused(403)),
        ]);
        let a = Authorizer::new(TD, src, cfg(20, 10_000, 16));
        let uid = Uuid::new_v4();
        assert_eq!(
            a.authorize(&claim(uid), "CONNECT", "api.home.example:443")
                .await
                .verdict,
            Ok(())
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        let d = a
            .authorize(&claim(uid), "CONNECT", "api.home.example:443")
            .await;
        assert_eq!(d.verdict, Err(Refusal::BrokerRefused));
    }

    #[tokio::test]
    async fn no_answer_outlives_the_claims_deadline() {
        let src = Scripted::new(vec![Ok(found(&["api.home.example:443"], 1)), unreachable()]);
        let a = Authorizer::new(TD, src.clone(), cfg(10_000, 10_000, 16));
        let uid = Uuid::new_v4();
        assert_eq!(
            a.authorize(&claim(uid), "CONNECT", "api.home.example:443")
                .await
                .verdict,
            Ok(())
        );
        tokio::time::sleep(Duration::from_millis(1100)).await;
        // Fresh and stale bounds are wide open; the deadline is what ends it.
        let d = a
            .authorize(&claim(uid), "CONNECT", "api.home.example:443")
            .await;
        assert_eq!(d.verdict, Err(Refusal::BrokerUnreachable));
        assert_eq!(src.asks.load(Ordering::SeqCst), 2);
        // An answer already past its deadline is not kept either.
        let src = Scripted::new(vec![Ok(found(&["api.home.example:443"], -1))]);
        let a = Authorizer::new(TD, src, cfg(10_000, 10_000, 16));
        let d = a
            .authorize(&claim(uid), "CONNECT", "api.home.example:443")
            .await;
        assert_eq!(d.verdict, Err(Refusal::NotAllowed));
        assert_eq!(a.cached(), 0);
    }

    #[tokio::test]
    async fn the_cache_is_bounded_by_least_recent_use() {
        let src = Scripted::new(vec![Ok(found(&["api.home.example:443"], 600))]);
        let a = Authorizer::new(TD, src.clone(), cfg(10_000, 0, 2));
        let (one, two, three) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        a.authorize(&claim(one), "CONNECT", "api.home.example:443")
            .await;
        a.authorize(&claim(two), "CONNECT", "api.home.example:443")
            .await;
        // `one` is used again, so `two` is the least recent when `three` arrives.
        a.authorize(&claim(one), "CONNECT", "api.home.example:443")
            .await;
        a.authorize(&claim(three), "CONNECT", "api.home.example:443")
            .await;
        assert_eq!(a.cached(), 2);
        assert_eq!(src.asks.load(Ordering::SeqCst), 3);
        assert_eq!(
            a.authorize(&claim(one), "CONNECT", "api.home.example:443")
                .await
                .served,
            Served::Cache
        );
        assert_eq!(
            a.authorize(&claim(two), "CONNECT", "api.home.example:443")
                .await
                .served,
            Served::Broker
        );
    }

    // ----- gateway-placed credentials (ADR-0040 decisions 4 and 5) ---------------------------------------------

    use mediatore_proto::{
        EndpointRule, GatewayCredential, HeaderPair, InjectRoute, Secret, Subject,
    };

    const SECRET: &str = "sk-ant-oat01-NEVER-LOG-THIS";

    /// Credential answers scripted per ask, counting them.
    struct ScriptedCreds {
        answers: std::sync::Mutex<Vec<Result<CredentialAnswer, AskError>>>,
        asks: AtomicUsize,
        delay: Duration,
    }

    impl ScriptedCreds {
        fn new(answers: Vec<Result<CredentialAnswer, AskError>>) -> Arc<Self> {
            Arc::new(Self {
                answers: std::sync::Mutex::new(answers),
                asks: AtomicUsize::new(0),
                delay: Duration::ZERO,
            })
        }
    }

    #[async_trait::async_trait]
    impl Credentials for ScriptedCreds {
        async fn credential(&self, _: Uuid, _: &str) -> Result<CredentialAnswer, AskError> {
            self.asks.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            let mut answers = self.answers.lock().unwrap();
            if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers[0].clone()
            }
        }
    }

    fn cred_unreachable() -> Result<CredentialAnswer, AskError> {
        Err(AskError::Unreachable("connection refused".into()))
    }

    fn route(header: &str) -> InjectRoute {
        InjectRoute {
            audience: "anthropic".into(),
            endpoint: "api.anthropic.example:443".parse().unwrap(),
            rules: vec![EndpointRule {
                method: "POST".into(),
                path: "/v1/messages".into(),
            }],
            header: header.into(),
            extra_headers: vec![HeaderPair {
                name: "anthropic-version".into(),
                value: "2023-06-01".into(),
            }],
        }
    }

    fn found_inject(routes: Vec<InjectRoute>, ttl_secs: i64) -> Answer {
        Answer::Found(ClaimEgress {
            claim_uid: Uuid::nil(),
            expires_at: Timestamp::now() + jiff::SignedDuration::from_secs(ttl_secs),
            egress: routes.iter().map(|r| r.endpoint.clone()).collect(),
            inject: routes,
        })
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "scripted next to `cred_unreachable()` in vectors of one Result type"
    )]
    fn credential(header: &str, ttl_secs: i64) -> Result<CredentialAnswer, AskError> {
        Ok(CredentialAnswer::Found(GatewayCredential {
            audience: "anthropic".into(),
            subject: Subject {
                issuer: "https://login.example.test".into(),
                id: "octocat".into(),
                display: None,
            },
            header: header.into(),
            value: Secret(SECRET.into()),
            extra_headers: vec![HeaderPair {
                name: "anthropic-version".into(),
                value: "2023-06-01".into(),
            }],
            expires_at: Timestamp::now() + jiff::SignedDuration::from_secs(ttl_secs),
        }))
    }

    /// An authorizer for one route, with credentials from `creds`.
    fn injector(
        header: &str,
        creds: Arc<ScriptedCreds>,
        cfg: CacheConfig,
    ) -> (Authorizer, Arc<Scripted>) {
        let src = Scripted::new(vec![Ok(found_inject(vec![route(header)], 600))]);
        (
            Authorizer::new(TD, src.clone(), cfg).with_credentials(creds),
            src,
        )
    }

    async fn inject(a: &Authorizer, uid: Uuid) -> InjectDecision {
        a.authorize_inject(&claim(uid), "POST", "api.anthropic.example", "/v1/messages")
            .await
    }

    #[tokio::test]
    async fn an_inject_check_places_the_routes_header_and_removes_the_other_credential_headers() {
        for (header, removed) in [
            ("x-api-key", vec!["authorization"]),
            ("authorization", vec!["x-api-key"]),
            ("x-custom-key", vec!["authorization", "x-api-key"]),
        ] {
            let creds = ScriptedCreds::new(vec![credential(header, 200)]);
            let (a, _) = injector(header, creds, CacheConfig::default());
            let d = inject(&a, Uuid::new_v4()).await;
            let allow = d.verdict.expect("allowed");
            assert_eq!(allow.header, header);
            assert_eq!(allow.value, Secret(SECRET.into()));
            assert_eq!(allow.extra_headers.len(), 1);
            assert_eq!(allow.extra_headers[0].name, "anthropic-version");
            assert_eq!(d.audience.as_deref(), Some("anthropic"));
            assert_eq!(
                allow.remove_headers, removed,
                "the route's own header is placed by overwrite and never in the removal list, so the order of Envoy's removals and additions cannot strip it"
            );
        }
    }

    #[tokio::test]
    async fn an_inject_check_is_refused_for_anything_but_a_claim_a_matching_authority_and_a_rule() {
        let creds = ScriptedCreds::new(vec![credential("x-api-key", 200)]);
        let (a, _) = injector("x-api-key", creds.clone(), CacheConfig::default());
        let uid = Uuid::new_v4();
        let ok = |m: &str, h: &str, p: &str| (claim(uid), m.to_owned(), h.to_owned(), p.to_owned());
        for (peer, method, host, path, why) in [
            // not a claim identity
            (
                format!("spiffe://{TD}/gateway"),
                "POST",
                "api.anthropic.example",
                "/v1/messages",
                Refusal::NotAClaim,
            ),
            (
                String::new(),
                "POST",
                "api.anthropic.example",
                "/v1/messages",
                Refusal::NotAClaim,
            ),
            // a tunnel question has no business on the inject socket
            (
                claim(uid),
                "CONNECT",
                "api.anthropic.example:443",
                "",
                Refusal::NotInject,
            ),
            // the authority is exact: another host, another port, a bad shape
            (
                claim(uid),
                "POST",
                "other.anthropic.example",
                "/v1/messages",
                Refusal::NotAllowed,
            ),
            (
                claim(uid),
                "POST",
                "api.anthropic.example:8443",
                "/v1/messages",
                Refusal::NotAllowed,
            ),
            (
                claim(uid),
                "POST",
                "",
                "/v1/messages",
                Refusal::BadAuthority,
            ),
            // the rules: a method and a path nobody named
            (
                claim(uid),
                "GET",
                "api.anthropic.example",
                "/v1/messages",
                Refusal::NotAllowed,
            ),
            (
                claim(uid),
                "POST",
                "api.anthropic.example",
                "/v1/models",
                Refusal::NotAllowed,
            ),
            (
                claim(uid),
                "POST",
                "api.anthropic.example",
                "/v1/messages/../models",
                Refusal::NotAllowed,
            ),
        ] {
            let d = a.authorize_inject(&peer, method, host, path).await;
            assert_eq!(
                d.verdict.map(|_| ()),
                Err(why),
                "{peer} {method} {host} {path}"
            );
        }
        let _ = ok;
        assert_eq!(
            creds.asks.load(Ordering::SeqCst),
            0,
            "no refused check reached the credential route"
        );
    }

    #[tokio::test]
    async fn the_host_compares_without_case_a_missing_port_is_443_and_the_query_is_not_the_path() {
        let creds = ScriptedCreds::new(vec![credential("x-api-key", 200)]);
        let (a, _) = injector("x-api-key", creds, CacheConfig::default());
        let uid = Uuid::new_v4();
        for (host, path) in [
            ("API.Anthropic.Example", "/v1/messages"),
            ("api.anthropic.example:443", "/v1/messages"),
            (
                "api.anthropic.example",
                "/v1/messages?beta=true&x=/v1/models",
            ),
            ("api.anthropic.example", "/v1/messages//"),
        ] {
            let d = a.authorize_inject(&claim(uid), "post", host, path).await;
            assert!(
                d.verdict.is_ok(),
                "{host} {path}: {:?}",
                d.verdict.map(|_| ())
            );
        }
    }

    #[tokio::test]
    async fn an_authorizer_without_credentials_refuses_every_inject_check() {
        let src = Scripted::new(vec![Ok(found_inject(vec![route("x-api-key")], 600))]);
        let a = Authorizer::new(TD, src.clone(), CacheConfig::default());
        let d = inject(&a, Uuid::new_v4()).await;
        assert_eq!(d.verdict.map(|_| ()), Err(Refusal::NotInject));
        assert_eq!(src.asks.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_credential_is_fetched_once_within_its_bound_and_asked_again_after_it() {
        let creds = ScriptedCreds::new(vec![credential("x-api-key", 200)]);
        let cfg = CacheConfig {
            credential_for: Duration::from_millis(150),
            credential_margin: Duration::ZERO,
            ..CacheConfig::default()
        };
        let (a, _) = injector("x-api-key", creds.clone(), cfg);
        let uid = Uuid::new_v4();
        for _ in 0..3 {
            assert!(inject(&a, uid).await.verdict.is_ok());
        }
        assert_eq!(
            creds.asks.load(Ordering::SeqCst),
            1,
            "three checks, one ask"
        );
        assert_eq!(a.cached_credentials(), 1);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(inject(&a, uid).await.verdict.is_ok());
        assert_eq!(
            creds.asks.load(Ordering::SeqCst),
            2,
            "past the bound it is asked again"
        );
    }

    #[tokio::test]
    async fn the_bound_is_the_credentials_expiry_less_the_margin_and_a_near_expiry_is_not_kept() {
        // 40 s left and a 30 s margin leave a 10 s bound; 20 s left leaves none, so nothing is kept.
        let creds = ScriptedCreds::new(vec![credential("x-api-key", 20)]);
        let (a, _) = injector("x-api-key", creds.clone(), CacheConfig::default());
        let uid = Uuid::new_v4();
        assert!(
            inject(&a, uid).await.verdict.is_ok(),
            "still served: the broker said it is good"
        );
        assert!(inject(&a, uid).await.verdict.is_ok());
        assert_eq!(creds.asks.load(Ordering::SeqCst), 2, "no bound, no cache");
        assert_eq!(a.cached_credentials(), 0);
        let creds = ScriptedCreds::new(vec![credential("x-api-key", 40)]);
        let (a, _) = injector("x-api-key", creds.clone(), CacheConfig::default());
        assert!(inject(&a, uid).await.verdict.is_ok());
        assert!(inject(&a, uid).await.verdict.is_ok());
        assert_eq!(creds.asks.load(Ordering::SeqCst), 1);
        assert_eq!(a.cached_credentials(), 1);
    }

    /// An authorizer for one route whose broker answers `answers` in turn (the last repeats), after one allowed check
    /// has kept a credential for `uid`.
    async fn kept_one(
        answers: Vec<Result<Answer, AskError>>,
        cfg: CacheConfig,
    ) -> (Authorizer, Arc<Scripted>, Uuid) {
        let src = Scripted::new(answers);
        let creds = ScriptedCreds::new(vec![credential("x-api-key", 200)]);
        let a = Authorizer::new(TD, src.clone(), cfg).with_credentials(creds);
        let uid = Uuid::new_v4();
        assert!(
            inject(&a, uid).await.verdict.is_ok(),
            "the first check is allowed"
        );
        assert_eq!(a.cached_credentials(), 1, "and keeps the credential");
        (a, src, uid)
    }

    #[tokio::test]
    async fn a_sweep_forgets_a_released_claims_credential_without_any_request_for_it() {
        // ADR-0040 decision 5: a credential lives for its claim and not past it. A request is not needed to notice the
        // release: the sweep asks the broker about every claim that holds one.
        let (a, src, _) = kept_one(
            vec![
                Ok(found_inject(vec![route("x-api-key")], 600)),
                Ok(Answer::Gone),
            ],
            CacheConfig::default(),
        )
        .await;
        assert_eq!(a.sweep().await, 1, "one claim forgotten");
        assert_eq!(
            a.cached_credentials(),
            0,
            "its credential is gone from memory"
        );
        assert_eq!(a.cached(), 0, "and its routes");
        assert_eq!(
            src.asks.load(Ordering::SeqCst),
            2,
            "one ask for the check, one for the sweep"
        );
    }

    #[tokio::test]
    async fn a_sweep_keeps_a_live_claims_credential() {
        let (a, _, _) = kept_one(
            vec![Ok(found_inject(vec![route("x-api-key")], 600))],
            CacheConfig::default(),
        )
        .await;
        assert_eq!(a.sweep().await, 0);
        assert_eq!(
            a.cached_credentials(),
            1,
            "the claim is live, its credential stays"
        );
        assert_eq!(a.cached(), 1);
    }

    #[tokio::test]
    async fn a_sweep_in_a_broker_outage_keeps_a_credential_only_to_its_own_bound() {
        let (a, _, _) = kept_one(
            vec![
                Ok(found_inject(vec![route("x-api-key")], 600)),
                Err(AskError::Unreachable("connection refused".into())),
            ],
            CacheConfig::default(),
        )
        .await;
        assert_eq!(a.sweep().await, 0, "an outage is not a release");
        assert_eq!(
            a.cached_credentials(),
            1,
            "kept until its own bound, as a check would serve it"
        );
    }

    #[tokio::test]
    async fn a_sweep_drops_a_credential_past_its_bound_with_no_ask_and_no_request() {
        let cfg = CacheConfig {
            credential_for: Duration::from_millis(20),
            credential_margin: Duration::ZERO,
            ..CacheConfig::default()
        };
        let (a, src, _) =
            kept_one(vec![Ok(found_inject(vec![route("x-api-key")], 600))], cfg).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(a.sweep().await, 0);
        assert_eq!(
            a.cached_credentials(),
            0,
            "an expired credential does not sit in memory"
        );
        assert_eq!(
            src.asks.load(Ordering::SeqCst),
            1,
            "nothing left to ask about, so the broker is not asked"
        );
    }

    /// Every claim is live. Counts the asks in flight, the most there ever were at once, and which claims were
    /// asked about.
    struct Gauged {
        in_flight: AtomicUsize,
        peak: AtomicUsize,
        asked: std::sync::Mutex<Vec<Uuid>>,
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl Allowlists for Gauged {
        async fn ask(&self, uid: Uuid) -> Result<Answer, AskError> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            self.asked.lock().unwrap().push(uid);
            tokio::time::sleep(self.delay).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(found_inject(vec![route("x-api-key")], 600))
        }
    }

    #[tokio::test]
    async fn a_sweep_asks_about_every_claim_and_never_more_than_its_bound_at_once() {
        // ADR-0040 decision 5: a released claim's credential is gone within `sweep_every`, which one slow ask per
        // claim in turn would not hold to. The asks overlap, up to a bound and never past it.
        let src = Arc::new(Gauged {
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            asked: std::sync::Mutex::new(Vec::new()),
            delay: Duration::from_millis(10),
        });
        let creds = ScriptedCreds::new(vec![credential("x-api-key", 200)]);
        let a = Authorizer::new(TD, src.clone(), CacheConfig::default()).with_credentials(creds);
        let claims: BTreeSet<Uuid> = (0..SWEEP_CONCURRENCY * 2 + 3)
            .map(|_| Uuid::new_v4())
            .collect();
        for uid in &claims {
            assert!(
                inject(&a, *uid).await.verdict.is_ok(),
                "each claim's first check is allowed"
            );
        }
        assert_eq!(a.cached_credentials(), claims.len());
        assert_eq!(
            src.peak.load(Ordering::SeqCst),
            1,
            "the checks came one at a time"
        );
        src.asked.lock().unwrap().clear();

        assert_eq!(a.sweep().await, 0, "every claim is live");

        let asked = src.asked.lock().unwrap().clone();
        assert_eq!(asked.len(), claims.len(), "one ask per claim");
        assert!(
            asked.into_iter().collect::<BTreeSet<Uuid>>() == claims,
            "every claim that holds a credential was asked about"
        );
        assert_eq!(
            src.peak.load(Ordering::SeqCst),
            SWEEP_CONCURRENCY,
            "the asks overlap up to the bound and never past it"
        );
        assert_eq!(src.in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(a.cached_credentials(), claims.len(), "and nothing was lost");
    }

    #[tokio::test]
    async fn an_empty_credential_value_or_header_is_refused_and_kept_nowhere() {
        // Envoy's header add drops an empty value without an error, so an empty credential would reach the
        // upstream as no credential at all, silently. The authorizer says no instead.
        for (what, blank_value, blank_header) in [("value", true, false), ("header", false, true)] {
            let Ok(CredentialAnswer::Found(mut c)) = credential("x-api-key", 200) else {
                unreachable!()
            };
            if blank_value {
                c.value = Secret(String::new());
            }
            if blank_header {
                c.header = String::new();
            }
            let creds = ScriptedCreds::new(vec![Ok(CredentialAnswer::Found(c))]);
            let (a, _) = injector("x-api-key", creds, CacheConfig::default());
            let d = inject(&a, Uuid::new_v4()).await;
            assert_eq!(
                d.verdict.map(|_| ()),
                Err(Refusal::CredentialRefused),
                "an empty {what}"
            );
            assert_eq!(a.cached_credentials(), 0, "an empty {what} is kept nowhere");
        }
    }

    #[tokio::test]
    async fn an_expired_or_misaddressed_credential_is_refused_and_kept_nowhere() {
        let creds = ScriptedCreds::new(vec![credential("x-api-key", -1)]);
        let (a, _) = injector("x-api-key", creds, CacheConfig::default());
        let d = inject(&a, Uuid::new_v4()).await;
        assert_eq!(d.verdict.map(|_| ()), Err(Refusal::CredentialRefused));
        assert_eq!(a.cached_credentials(), 0);
        let Ok(CredentialAnswer::Found(mut other)) = credential("x-api-key", 200) else {
            unreachable!()
        };
        other.audience = "someone-else".into();
        let creds = ScriptedCreds::new(vec![Ok(CredentialAnswer::Found(other))]);
        let (a, _) = injector("x-api-key", creds, CacheConfig::default());
        let d = inject(&a, Uuid::new_v4()).await;
        assert_eq!(
            d.verdict.map(|_| ()),
            Err(Refusal::CredentialRefused),
            "the broker answered for another audience than the one asked"
        );
        assert_eq!(a.cached_credentials(), 0);
    }

    #[tokio::test]
    async fn the_credential_routes_answers_map_to_stable_refusals() {
        for (answer, want) in [
            (Ok(CredentialAnswer::Gone), Refusal::ClaimGone),
            (Err(AskError::Refused(403)), Refusal::CredentialRefused),
            (Err(AskError::Refused(401)), Refusal::BrokerRefused),
            (cred_unreachable(), Refusal::BrokerUnreachable),
        ] {
            let creds = ScriptedCreds::new(vec![answer]);
            let (a, _) = injector("x-api-key", creds, CacheConfig::default());
            let d = inject(&a, Uuid::new_v4()).await;
            assert_eq!(d.verdict.map(|_| ()), Err(want));
            assert_eq!(a.cached_credentials(), 0);
        }
    }

    #[tokio::test]
    async fn a_404_for_the_claim_drops_its_credentials_and_its_routes() {
        let creds = ScriptedCreds::new(vec![
            credential("x-api-key", 200),
            Ok(CredentialAnswer::Gone),
        ]);
        let cfg = CacheConfig {
            credential_for: Duration::from_millis(40),
            credential_margin: Duration::ZERO,
            ..CacheConfig::default()
        };
        let (a, _) = injector("x-api-key", creds, cfg);
        let uid = Uuid::new_v4();
        assert!(inject(&a, uid).await.verdict.is_ok());
        assert_eq!((a.cached(), a.cached_credentials()), (1, 1));
        tokio::time::sleep(Duration::from_millis(60)).await;
        let d = inject(&a, uid).await;
        assert_eq!(d.verdict.map(|_| ()), Err(Refusal::ClaimGone));
        assert_eq!(
            (a.cached(), a.cached_credentials()),
            (0, 0),
            "nothing of the claim is left"
        );
    }

    #[tokio::test]
    async fn the_egress_route_saying_gone_drops_the_claims_credentials_too() {
        let creds = ScriptedCreds::new(vec![credential("x-api-key", 200)]);
        let src = Scripted::new(vec![
            Ok(found_inject(vec![route("x-api-key")], 600)),
            Ok(Answer::Gone),
        ]);
        let a = Authorizer::new(TD, src, cfg(20, 0, 16)).with_credentials(creds);
        let uid = Uuid::new_v4();
        assert!(inject(&a, uid).await.verdict.is_ok());
        assert_eq!(a.cached_credentials(), 1);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let d = inject(&a, uid).await;
        assert_eq!(d.verdict.map(|_| ()), Err(Refusal::ClaimGone));
        assert_eq!(a.cached_credentials(), 0);
    }

    #[tokio::test]
    async fn a_cached_credential_serves_through_a_broker_outage_until_its_bound_then_denies() {
        let creds = ScriptedCreds::new(vec![credential("x-api-key", 200), cred_unreachable()]);
        let cfg = CacheConfig {
            credential_for: Duration::from_millis(120),
            credential_margin: Duration::ZERO,
            ..CacheConfig::default()
        };
        let (a, _) = injector("x-api-key", creds.clone(), cfg);
        let uid = Uuid::new_v4();
        assert!(inject(&a, uid).await.verdict.is_ok());
        assert!(
            inject(&a, uid).await.verdict.is_ok(),
            "the outage is not noticed within the bound"
        );
        assert_eq!(creds.asks.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(150)).await;
        let d = inject(&a, uid).await;
        assert_eq!(
            d.verdict.map(|_| ()),
            Err(Refusal::BrokerUnreachable),
            "past the bound an outage is a deny"
        );
        assert_eq!(a.cached_credentials(), 0);
        let creds = ScriptedCreds::new(vec![cred_unreachable()]);
        let (a, _) = injector("x-api-key", creds, CacheConfig::default());
        let d = inject(&a, Uuid::new_v4()).await;
        assert_eq!(
            d.verdict.map(|_| ()),
            Err(Refusal::BrokerUnreachable),
            "nothing cached, a deny"
        );
    }

    #[tokio::test]
    async fn no_credential_outlives_the_claims_deadline() {
        let creds = ScriptedCreds::new(vec![credential("x-api-key", 300)]);
        let src = Scripted::new(vec![
            Ok(found_inject(vec![route("x-api-key")], 1)),
            unreachable(),
        ]);
        let a = Authorizer::new(TD, src, cfg(10_000, 10_000, 16)).with_credentials(creds.clone());
        let uid = Uuid::new_v4();
        assert!(inject(&a, uid).await.verdict.is_ok());
        assert_eq!(a.cached_credentials(), 1);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let d = inject(&a, uid).await;
        assert!(
            d.verdict.is_err(),
            "the claim's deadline passed; the broker is unreachable"
        );
        assert_eq!(
            a.cached_credentials(),
            0,
            "the credential went with the claim"
        );
        assert_eq!(creds.asks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn checks_arriving_together_share_one_credential_ask() {
        let creds = Arc::new(ScriptedCreds {
            answers: std::sync::Mutex::new(vec![credential("x-api-key", 200)]),
            asks: AtomicUsize::new(0),
            delay: Duration::from_millis(50),
        });
        let (a, _) = injector("x-api-key", creds.clone(), CacheConfig::default());
        let a = Arc::new(a);
        let uid = Uuid::new_v4();
        let checks: Vec<_> = (0..8)
            .map(|_| {
                let a = a.clone();
                tokio::spawn(async move { inject(&a, uid).await })
            })
            .collect();
        for c in checks {
            assert!(c.await.unwrap().verdict.is_ok());
        }
        assert_eq!(
            creds.asks.load(Ordering::SeqCst),
            1,
            "one ask for eight checks"
        );
        assert!(lock(&a.cred_asking).is_empty(), "no lock left behind");
    }

    #[tokio::test]
    async fn the_credential_cache_is_bounded_by_least_recent_use() {
        let creds = ScriptedCreds::new(vec![credential("x-api-key", 200)]);
        let (a, _) = injector("x-api-key", creds.clone(), cfg(10_000, 0, 2));
        let (one, two, three) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        for uid in [one, two, one, three] {
            assert!(inject(&a, uid).await.verdict.is_ok());
        }
        assert_eq!(a.cached_credentials(), 2);
        assert_eq!(creds.asks.load(Ordering::SeqCst), 3);
        assert!(inject(&a, one).await.verdict.is_ok());
        assert_eq!(creds.asks.load(Ordering::SeqCst), 3, "`one` was kept");
        assert!(inject(&a, two).await.verdict.is_ok());
        assert_eq!(
            creds.asks.load(Ordering::SeqCst),
            4,
            "`two` was the least recent and went"
        );
    }

    #[tokio::test]
    async fn the_credential_never_shows_in_a_debug_print_of_a_decision() {
        let creds = ScriptedCreds::new(vec![credential("x-api-key", 200)]);
        let (a, _) = injector("x-api-key", creds, CacheConfig::default());
        let d = inject(&a, Uuid::new_v4()).await;
        let printed = format!("{d:?}");
        assert!(!printed.contains(SECRET), "{printed}");
        assert!(printed.contains("[redacted]"), "{printed}");
    }

    #[tokio::test]
    async fn checks_arriving_together_for_one_claim_share_one_ask() {
        let src = Arc::new(Scripted {
            answers: std::sync::Mutex::new(vec![Ok(found(&["api.home.example:443"], 600))]),
            asks: AtomicUsize::new(0),
            delay: Duration::from_millis(50),
        });
        let a = Arc::new(Authorizer::new(TD, src.clone(), cfg(10_000, 0, 16)));
        let uid = Uuid::new_v4();
        let checks: Vec<_> = (0..8)
            .map(|_| {
                let a = a.clone();
                tokio::spawn(async move {
                    a.authorize(&claim(uid), "CONNECT", "api.home.example:443")
                        .await
                })
            })
            .collect();
        for c in checks {
            assert_eq!(c.await.unwrap().verdict, Ok(()));
        }
        assert_eq!(
            src.asks.load(Ordering::SeqCst),
            1,
            "one ask for eight checks"
        );
        assert!(lock(&a.asking).is_empty(), "no lock left behind");
    }
}
