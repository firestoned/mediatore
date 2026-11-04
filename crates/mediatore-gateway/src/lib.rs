// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The egress gateway's authorizer, `mediatore gateway` (ADR-0028 decision 4): Envoy's
//! external authorization service on the gateway VM. Envoy has already required a client
//! certificate and validated it against the trust bundle; for each `CONNECT` it asks this
//! process, over HTTP on loopback, whether the caller may reach the authority. The answer
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

#![forbid(unsafe_code)]

pub mod broker;
pub mod serve;

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use mediatore_proto::{ClaimEgress, Endpoint};
use mediatore_spire::Naming;
use uuid::Uuid;

use crate::broker::{Allowlists, Answer, AskError};

/// The cache's bounds.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// How long an answer is used without asking the broker again.
    pub fresh_for: Duration,
    /// How long past `fresh_for` an answer still stands in when the broker is unreachable.
    /// Past this, an outage is a deny.
    pub stale_for: Duration,
    /// How many claims the cache holds; past it, the least recently used entry goes.
    pub max_claims: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            fresh_for: Duration::from_secs(30),
            stale_for: Duration::from_secs(300),
            max_claims: 4096,
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

/// One claim's cached answer.
struct Entry {
    egress: BTreeSet<Endpoint>,
    expires_at: DateTime<Utc>,
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

/// The authorizer: the cache, its bounds, and where answers come from.
pub struct Authorizer {
    naming: Naming,
    source: Arc<dyn Allowlists>,
    cfg: CacheConfig,
    cache: std::sync::Mutex<Cache>,
    /// One ask in flight per claim: checks arriving together for the same claim share it.
    asking: std::sync::Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>,
}

impl Authorizer {
    /// An authorizer for `trust_domain`'s claims, answering from `source` within `cfg`.
    #[must_use]
    pub fn new(trust_domain: &str, source: Arc<dyn Allowlists>, cfg: CacheConfig) -> Self {
        Self {
            naming: Naming {
                trust_domain: trust_domain.to_owned(),
            },
            source,
            cfg,
            cache: std::sync::Mutex::new(Cache::default()),
            asking: std::sync::Mutex::new(HashMap::new()),
        }
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
        let now = Utc::now();
        let tick = Instant::now();
        if let Some(allowed) = self.fresh(uid, &authority, now, tick) {
            return Decision {
                claim_uid: Some(uid),
                verdict: allowed.then_some(()).ok_or(Refusal::NotAllowed),
                served: Served::Cache,
            };
        }
        // One ask per claim at a time; whoever waited reads what the ask left.
        let ask_lock = self.asking_lock(uid);
        let held = ask_lock.lock().await;
        let decision = self.ask_and_decide(uid, &authority).await;
        drop(held);
        drop(ask_lock);
        lock(&self.asking).retain(|_, l| Arc::strong_count(l) > 1);
        decision
    }

    /// Under the claim's ask lock: a fresh entry a parallel check just filled, or the
    /// broker's answer now.
    async fn ask_and_decide(&self, uid: Uuid, authority: &Endpoint) -> Decision {
        if let Some(allowed) = self.fresh(uid, authority, Utc::now(), Instant::now()) {
            return Decision {
                claim_uid: Some(uid),
                verdict: allowed.then_some(()).ok_or(Refusal::NotAllowed),
                served: Served::Cache,
            };
        }
        match self.source.ask(uid).await {
            Ok(Answer::Found(answer)) => {
                let allowed = self.admit(uid, answer, Instant::now());
                Decision {
                    claim_uid: Some(uid),
                    verdict: allowed
                        .then_some(())
                        .ok_or(Refusal::NotAllowed)
                        .and_then(|()| self.decide(uid, authority)),
                    served: Served::Broker,
                }
            }
            Ok(Answer::Gone) => {
                lock(&self.cache).entries.remove(&uid);
                Decision::refuse(Some(uid), Refusal::ClaimGone, Served::Broker)
            }
            Err(AskError::Refused(status)) => {
                tracing::error!(claim_uid = %uid, status, "the broker refused the gateway identity");
                Decision::refuse(Some(uid), Refusal::BrokerRefused, Served::None)
            }
            Err(AskError::Unreachable(why)) => {
                if let Some(allowed) = self.stale(uid, authority, Utc::now(), Instant::now()) {
                    tracing::warn!(claim_uid = %uid, error = %why, "broker unreachable; serving the stale allowlist");
                    Decision {
                        claim_uid: Some(uid),
                        verdict: allowed.then_some(()).ok_or(Refusal::NotAllowed),
                        served: Served::Stale,
                    }
                } else {
                    tracing::warn!(claim_uid = %uid, error = %why, "broker unreachable and nothing cached; denied");
                    Decision::refuse(Some(uid), Refusal::BrokerUnreachable, Served::None)
                }
            }
        }
    }

    fn asking_lock(&self, uid: Uuid) -> Arc<tokio::sync::Mutex<()>> {
        lock(&self.asking).entry(uid).or_default().clone()
    }

    /// The fresh entry's verdict on `authority`, if there is one: within `fresh_for` and
    /// before the claim's deadline. Marks the entry used.
    fn fresh(
        &self,
        uid: Uuid,
        authority: &Endpoint,
        now: DateTime<Utc>,
        tick: Instant,
    ) -> Option<bool> {
        let mut cache = lock(&self.cache);
        let entry = cache.entries.get_mut(&uid)?;
        if entry.expires_at <= now {
            cache.entries.remove(&uid);
            return None;
        }
        if tick.duration_since(entry.fetched_at) >= self.cfg.fresh_for {
            return None;
        }
        entry.used_at = tick;
        Some(entry.allows(authority))
    }

    /// The stale entry's verdict, if one stands in: within `fresh_for + stale_for` and
    /// before the claim's deadline.
    fn stale(
        &self,
        uid: Uuid,
        authority: &Endpoint,
        now: DateTime<Utc>,
        tick: Instant,
    ) -> Option<bool> {
        let mut cache = lock(&self.cache);
        let entry = cache.entries.get_mut(&uid)?;
        if entry.expires_at <= now {
            cache.entries.remove(&uid);
            return None;
        }
        if tick.duration_since(entry.fetched_at) >= self.cfg.fresh_for + self.cfg.stale_for {
            cache.entries.remove(&uid);
            return None;
        }
        entry.used_at = tick;
        Some(entry.allows(authority))
    }

    /// Keep the broker's answer; `false` when it is already past its deadline, in which
    /// case nothing is kept.
    fn admit(&self, uid: Uuid, answer: ClaimEgress, tick: Instant) -> bool {
        if answer.expires_at <= Utc::now() {
            lock(&self.cache).entries.remove(&uid);
            return false;
        }
        let entry = Entry {
            egress: answer.egress.into_iter().map(normalised).collect(),
            expires_at: answer.expires_at,
            fetched_at: tick,
            used_at: tick,
        };
        lock(&self.cache).put(uid, entry, self.cfg.max_claims);
        true
    }

    fn decide(&self, uid: Uuid, authority: &Endpoint) -> Result<(), Refusal> {
        let cache = lock(&self.cache);
        cache
            .entries
            .get(&uid)
            .is_some_and(|e| e.allows(authority))
            .then_some(())
            .ok_or(Refusal::NotAllowed)
    }

    /// How many claims the cache holds now.
    #[must_use]
    pub fn cached(&self) -> usize {
        lock(&self.cache).entries.len()
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

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
            expires_at: Utc::now() + chrono::Duration::seconds(ttl_secs),
            egress: egress.iter().map(|e| e.parse().unwrap()).collect(),
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
