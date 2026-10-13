// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Leader election with a `coordination.k8s.io` Lease (ADR-0011 decision 6).
//!
//! One replica holds the Lease and runs the watcher; the others wait. A holder renews
//! every third of the lease duration and stops its work the moment a renewal does not
//! go through, so two replicas never bind at once. The verdict logic is pure and tested;
//! the loop around it only reads and replaces the one Lease object.

use std::future::Future;
use std::time::Duration;

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use k8s_openapi::jiff::{SignedDuration, Timestamp};
use kube::api::{ObjectMeta, PostParams};
use kube::{Api, Client};

/// Which Lease to hold, as whom, for how long.
#[derive(Clone, Debug)]
pub struct LeaseConfig {
    /// Namespace of the Lease (the broker's own).
    pub namespace: String,
    /// Lease name.
    pub name: String,
    /// This replica's identity (the pod name).
    pub holder: String,
    /// How long a holder keeps the lease without renewing it.
    pub duration: Duration,
}

/// What a replica may do with the Lease as it currently stands.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Nobody holds it, or the holder let it expire: take it.
    Acquire,
    /// We hold it: renew.
    Renew,
    /// Someone else holds it and it is current.
    Held(String),
}

/// Decide from the Lease's spec, never from local state.
#[must_use]
pub fn judge(spec: Option<&LeaseSpec>, me: &str, now: Timestamp) -> Verdict {
    let Some(spec) = spec else {
        return Verdict::Acquire;
    };
    match spec.holder_identity.as_deref() {
        None | Some("") => Verdict::Acquire,
        Some(holder) if holder == me => Verdict::Renew,
        Some(holder) => {
            let valid_for =
                SignedDuration::from_secs(i64::from(spec.lease_duration_seconds.unwrap_or(0)));
            let expired = spec
                .renew_time
                .as_ref()
                .is_none_or(|t| now.duration_since(t.0) >= valid_for);
            if expired {
                Verdict::Acquire
            } else {
                Verdict::Held(holder.to_owned())
            }
        }
    }
}

/// The spec to write for `verdict`: holder, renew time, duration, and on a takeover the
/// acquire time and the transition count.
#[must_use]
pub fn next_spec(
    prev: Option<&LeaseSpec>,
    verdict: &Verdict,
    me: &str,
    now: Timestamp,
    duration: Duration,
) -> LeaseSpec {
    let mut spec = prev.cloned().unwrap_or_default();
    if *verdict == Verdict::Acquire {
        spec.acquire_time = Some(MicroTime(now));
        let taken_over = prev
            .and_then(|p| p.holder_identity.as_deref())
            .is_some_and(|h| !h.is_empty() && h != me);
        if taken_over {
            spec.lease_transitions = Some(spec.lease_transitions.unwrap_or(0).saturating_add(1));
        }
    }
    spec.holder_identity = Some(me.to_owned());
    spec.renew_time = Some(MicroTime(now));
    spec.lease_duration_seconds = Some(i32::try_from(duration.as_secs()).unwrap_or(i32::MAX));
    spec
}

/// Read the Lease and, unless someone else holds it, write ourselves in. A conflicting
/// write (another replica got there first) surfaces as an error, which the caller treats
/// as "not leader this round".
async fn try_hold(api: &Api<Lease>, cfg: &LeaseConfig) -> anyhow::Result<Verdict> {
    let now = Timestamp::now();
    match api.get_opt(&cfg.name).await? {
        None => {
            let verdict = Verdict::Acquire;
            let lease = Lease {
                metadata: ObjectMeta {
                    name: Some(cfg.name.clone()),
                    namespace: Some(cfg.namespace.clone()),
                    ..ObjectMeta::default()
                },
                spec: Some(next_spec(None, &verdict, &cfg.holder, now, cfg.duration)),
            };
            api.create(&PostParams::default(), &lease).await?;
            Ok(verdict)
        }
        Some(mut lease) => {
            let verdict = judge(lease.spec.as_ref(), &cfg.holder, now);
            if let Verdict::Held(_) = verdict {
                return Ok(verdict);
            }
            lease.spec = Some(next_spec(
                lease.spec.as_ref(),
                &verdict,
                &cfg.holder,
                now,
                cfg.duration,
            ));
            api.replace(&cfg.name, &PostParams::default(), &lease)
                .await?;
            Ok(verdict)
        }
    }
}

/// Run `work` whenever this replica holds the Lease, and stop it when it does not.
///
/// Never returns on its own: a replica that lost the lease goes back to waiting, and one
/// whose work finished or failed tries again after an interval. Shut it down from outside.
pub async fn run_as_leader<F, Fut>(client: Client, cfg: LeaseConfig, work: F) -> anyhow::Result<()>
where
    F: Fn() -> Fut,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let api = Api::<Lease>::namespaced(client, &cfg.namespace);
    let interval = cfg.duration / 3;
    loop {
        match try_hold(&api, &cfg).await {
            Ok(Verdict::Held(by)) => {
                tracing::debug!(lease = %cfg.name, holder = %by, "lease held elsewhere; waiting");
                tokio::time::sleep(interval).await;
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(lease = %cfg.name, error = %e, "lease not acquired; waiting");
                tokio::time::sleep(interval).await;
                continue;
            }
        }
        tracing::info!(lease = %cfg.name, holder = %cfg.holder, "leading");
        let mut task = tokio::spawn(work());
        loop {
            tokio::select! {
                finished = &mut task => {
                    match finished {
                        Ok(Ok(())) => tracing::info!("watcher finished; will re-elect"),
                        Ok(Err(e)) => tracing::warn!(error = %e, "watcher failed; will re-elect"),
                        Err(e) => tracing::warn!(error = %e, "watcher task ended; will re-elect"),
                    }
                    break;
                }
                () = tokio::time::sleep(interval) => {
                    match try_hold(&api, &cfg).await {
                        Ok(Verdict::Renew | Verdict::Acquire) => {}
                        Ok(Verdict::Held(by)) => {
                            tracing::warn!(lease = %cfg.name, holder = %by, "lease lost; stopping the watcher");
                            task.abort();
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(lease = %cfg.name, error = %e, "lease not renewed; stopping the watcher");
                            task.abort();
                            break;
                        }
                    }
                }
            }
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_second(1_700_000_000 + secs).unwrap()
    }

    fn held_by(holder: &str, renewed_at: i64, seconds: i32) -> LeaseSpec {
        LeaseSpec {
            holder_identity: Some(holder.into()),
            renew_time: Some(MicroTime(at(renewed_at))),
            lease_duration_seconds: Some(seconds),
            ..LeaseSpec::default()
        }
    }

    #[test]
    fn an_absent_or_empty_lease_is_acquired() {
        assert_eq!(judge(None, "a", at(0)), Verdict::Acquire);
        assert_eq!(
            judge(Some(&LeaseSpec::default()), "a", at(0)),
            Verdict::Acquire
        );
        let empty = LeaseSpec {
            holder_identity: Some(String::new()),
            ..LeaseSpec::default()
        };
        assert_eq!(judge(Some(&empty), "a", at(0)), Verdict::Acquire);
    }

    #[test]
    fn our_own_lease_is_renewed_and_a_current_one_is_held() {
        let spec = held_by("a", 0, 15);
        assert_eq!(judge(Some(&spec), "a", at(10)), Verdict::Renew);
        assert_eq!(judge(Some(&spec), "b", at(10)), Verdict::Held("a".into()));
    }

    #[test]
    fn an_expired_lease_is_taken_over_exactly_at_expiry() {
        let spec = held_by("a", 0, 15);
        assert_eq!(judge(Some(&spec), "b", at(14)), Verdict::Held("a".into()));
        assert_eq!(judge(Some(&spec), "b", at(15)), Verdict::Acquire);
        let never_renewed = LeaseSpec {
            holder_identity: Some("a".into()),
            ..LeaseSpec::default()
        };
        assert_eq!(judge(Some(&never_renewed), "b", at(0)), Verdict::Acquire);
    }

    #[test]
    fn a_takeover_counts_a_transition_and_a_renewal_does_not() {
        let prev = held_by("a", 0, 15);
        let taken = next_spec(
            Some(&prev),
            &Verdict::Acquire,
            "b",
            at(20),
            Duration::from_secs(15),
        );
        assert_eq!(taken.holder_identity.as_deref(), Some("b"));
        assert_eq!(taken.lease_transitions, Some(1));
        assert_eq!(taken.acquire_time, Some(MicroTime(at(20))));
        assert_eq!(taken.renew_time, Some(MicroTime(at(20))));
        assert_eq!(taken.lease_duration_seconds, Some(15));

        let renewed = next_spec(
            Some(&taken),
            &Verdict::Renew,
            "b",
            at(25),
            Duration::from_secs(15),
        );
        assert_eq!(renewed.lease_transitions, Some(1));
        assert_eq!(renewed.acquire_time, Some(MicroTime(at(20))));
        assert_eq!(renewed.renew_time, Some(MicroTime(at(25))));

        let first = next_spec(None, &Verdict::Acquire, "a", at(0), Duration::from_secs(15));
        assert_eq!(first.lease_transitions, None);
    }
}
