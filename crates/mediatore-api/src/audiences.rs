// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Where a handler reads an audience's definition (ADR-0055 decision 2): the file's maps on
//! [`AppState`] under `config` and `shadow`, or under `bundles` one snapshot of the audience
//! catalog and the credentials read for it, seen from the claim's namespace. Every reader asks an
//! [`AudienceView`] for one namespace, so a team audience is never visible from another namespace
//! (decision 3) and a collision is never served (decision 2).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use jiff::{SignedDuration, Timestamp};
use mediatore_claims::audience::{Audience, AudienceCatalog, LiveCatalog};
use mediatore_claims::credential::CredentialCache;
use mediatore_policy::types::{Backend, CredentialFormat, Placement};
use mediatore_proto::{Endpoint, EndpointRule, HeaderPair, InjectRoute};

use crate::{AppState, AudienceSecret, DelegatedAudience};

/// The audience catalog and the credentials read for it (ADR-0055), when they serve.
#[derive(Clone, Debug)]
pub struct AudienceCatalogSource {
    /// The verified definitions, swapped as bundles arrive.
    pub live: Arc<LiveCatalog>,
    /// Their credentials, as last read.
    pub credentials: Arc<CredentialCache>,
}

/// The audiences of one namespace, from one snapshot of the catalog.
#[derive(Debug, Default)]
pub struct CatalogView {
    names: BTreeSet<String>,
    obo: BTreeSet<String>,
    egress: BTreeMap<String, Vec<Endpoint>>,
    rules: BTreeMap<String, Vec<EndpointRule>>,
    no_credential: BTreeSet<String>,
    secrets: BTreeMap<String, AudienceSecret>,
    unavailable: BTreeSet<String>,
    delegated: BTreeMap<String, DelegatedAudience>,
    inject: BTreeMap<String, Vec<InjectRoute>>,
    max_ttl: BTreeMap<String, i64>,
    /// The namespace of each team audience: the only one whose policies may grant it.
    team: BTreeMap<String, String>,
}

fn header_of(a: &Audience) -> String {
    a.definition
        .credential
        .header
        .clone()
        .unwrap_or_else(|| "authorization".to_owned())
}

fn extra_headers_of(a: &Audience) -> Vec<HeaderPair> {
    a.definition
        .credential
        .extra_headers
        .iter()
        .map(|h| HeaderPair {
            name: h.name.clone(),
            value: h.value.clone(),
        })
        .collect()
}

impl CatalogView {
    /// The audiences `catalog` resolves for a claim in `namespace` at `now`, with the
    /// credentials `credentials` holds for them. An audience that does not resolve from here
    /// (another namespace's team audience, a collision) is absent, as one that does not exist.
    #[must_use]
    pub fn build(
        catalog: &AudienceCatalog,
        credentials: &CredentialCache,
        namespace: &str,
        now: Timestamp,
    ) -> Self {
        let mut v = Self::default();
        for a in catalog.visible_from(namespace, now) {
            match catalog.resolve(namespace, &a.name, now) {
                Ok(r) if Arc::ptr_eq(r, a) => {}
                Ok(_) => continue,
                Err(why) => {
                    tracing::debug!(%namespace, audience = %a.name, ?why, "audience not served from this namespace (ADR-0055)");
                    continue;
                }
            }
            v.add(a, credentials, now);
        }
        v
    }

    fn add(&mut self, a: &Audience, credentials: &CredentialCache, now: Timestamp) {
        let name = a.name.clone();
        let ttl = i64::from(a.definition.max_ttl_seconds);
        self.names.insert(name.clone());
        self.egress.insert(name.clone(), a.endpoints.clone());
        self.rules.insert(name.clone(), a.rules.clone());
        self.max_ttl.insert(name.clone(), ttl);
        if a.kind == mediatore_claims::audience::AudienceKind::Team {
            self.team.insert(name.clone(), a.namespace.clone());
        }
        let header = header_of(a);
        let extra_headers = extra_headers_of(a);
        match a.definition.credential.backend {
            Backend::EntraObo => {
                self.obo.insert(name.clone());
            }
            Backend::None => {
                self.no_credential.insert(name.clone());
            }
            Backend::Delegated => {
                self.delegated.insert(
                    name.clone(),
                    DelegatedAudience {
                        header: header.clone(),
                        extra_headers: extra_headers.clone(),
                        ttl: SignedDuration::from_secs(ttl),
                        basic: a.definition.credential.format == CredentialFormat::Basic,
                    },
                );
            }
            Backend::Secret => match credentials.get(&a.namespace, &a.name, now) {
                Ok(m) => {
                    self.secrets.insert(
                        name.clone(),
                        AudienceSecret {
                            value: m.secret.clone(),
                            header: header.clone(),
                            extra_headers: extra_headers.clone(),
                            ttl: SignedDuration::from_secs(ttl),
                        },
                    );
                }
                Err(_) => {
                    self.unavailable.insert(name.clone());
                }
            },
            Backend::Sts => {}
        }
        if a.definition.credential.placement == Placement::Gateway {
            let routes = a
                .endpoints
                .iter()
                .map(|e| InjectRoute {
                    audience: name.clone(),
                    endpoint: e.clone(),
                    rules: a.rules.clone(),
                    header: header.clone(),
                    extra_headers: extra_headers.clone(),
                })
                .collect();
            self.inject.insert(name, routes);
        }
    }
}

enum Source<'a> {
    File(&'a AppState),
    Catalog(Box<CatalogView>),
}

/// The audiences a claim in one namespace can use, and how each is served.
pub struct AudienceView<'a> {
    namespace: String,
    source: Source<'a>,
}

impl AppState {
    /// The audiences as a claim in `namespace` meets them now: the file's under `config` and
    /// `shadow`, the catalog's under `bundles` (ADR-0055 decision 2).
    #[must_use]
    pub fn view(&self, namespace: &str) -> AudienceView<'_> {
        let source = match &self.audience_catalog {
            None => Source::File(self),
            Some(c) => Source::Catalog(Box::new(CatalogView::build(
                &c.live.snapshot(),
                &c.credentials,
                namespace,
                Timestamp::now(),
            ))),
        };
        AudienceView {
            namespace: namespace.to_owned(),
            source,
        }
    }
}

impl AudienceView<'_> {
    /// Whether the audience is defined at all (for the file: configured, wherever it is usable).
    #[must_use]
    pub fn exists(&self, audience: &str) -> bool {
        match &self.source {
            Source::File(st) => st.audiences.iter().any(|a| a == audience),
            Source::Catalog(v) => v.names.contains(audience),
        }
    }

    /// Whether a claim in this namespace may use it (ADR-0053 decision 4 for the file, ADR-0055
    /// decision 3 for the catalog). Says nothing about existence for the file.
    #[must_use]
    pub fn scope_allows(&self, audience: &str) -> bool {
        match &self.source {
            Source::File(st) => st.scope_allows(audience, &self.namespace),
            Source::Catalog(v) => v.names.contains(audience),
        }
    }

    /// Defined and usable from this namespace.
    #[must_use]
    pub fn usable(&self, audience: &str) -> bool {
        self.exists(audience) && self.scope_allows(audience)
    }

    /// Served On-Behalf-Of by Entra (ADR-0016).
    #[must_use]
    pub fn is_obo(&self, audience: &str) -> bool {
        match &self.source {
            Source::File(st) => st.obo_audiences.iter().any(|a| a == audience),
            Source::Catalog(v) => v.obo.contains(audience),
        }
    }

    /// Where the workload reaches it.
    #[must_use]
    pub fn egress(&self, audience: &str) -> &[Endpoint] {
        let map = match &self.source {
            Source::File(st) => &st.egress,
            Source::Catalog(v) => &v.egress,
        };
        map.get(audience).map_or(&[][..], Vec::as_slice)
    }

    /// The widest rules any grant may have: the file's top-level `rules`, or the definition's.
    #[must_use]
    pub fn ceiling(&self, audience: &str) -> &[EndpointRule] {
        let map = match &self.source {
            Source::File(st) => &st.rules,
            Source::Catalog(v) => &v.rules,
        };
        map.get(audience).map_or(&[][..], Vec::as_slice)
    }

    /// The file's per-namespace rules of a scoped audience (ADR-0053); none from the catalog.
    #[must_use]
    pub fn file_grant(&self, audience: &str) -> Option<&[EndpointRule]> {
        match &self.source {
            Source::File(st) => st
                .scopes
                .get(audience)
                .and_then(|per| per.get(&self.namespace))
                .map(Vec::as_slice),
            Source::Catalog(_) => None,
        }
    }

    /// Whether the routes carry per-namespace rules (an ADR-0053 scoped audience).
    #[must_use]
    pub fn is_scoped(&self, audience: &str) -> bool {
        match &self.source {
            Source::File(st) => st.scopes.contains_key(audience),
            Source::Catalog(_) => false,
        }
    }

    /// The rules the proxy applies in this namespace.
    #[must_use]
    pub fn rules_in(&self, audience: &str) -> Vec<EndpointRule> {
        match &self.source {
            Source::File(st) => st.rules_in(audience, &self.namespace),
            Source::Catalog(v) => v.rules.get(audience).cloned().unwrap_or_default(),
        }
    }

    /// The definition's longest lifetime, the cap on every credential handed out for it. `None`
    /// for the file, whose backends apply `max_ttl` themselves.
    #[must_use]
    pub fn max_ttl(&self, audience: &str) -> Option<i64> {
        match &self.source {
            Source::File(_) => None,
            Source::Catalog(v) => v.max_ttl.get(audience).copied(),
        }
    }

    /// For a team audience, its namespace: the one namespace whose policies may grant it (ADR-0055
    /// decision 3). `None` for a platform audience and for the file.
    #[must_use]
    pub fn team_namespace(&self, audience: &str) -> Option<&str> {
        match &self.source {
            Source::File(_) => None,
            Source::Catalog(v) => v.team.get(audience).map(String::as_str),
        }
    }

    /// The private CA the proxy trusts for it (the file's `ca_file`; the catalog serves none yet).
    #[must_use]
    pub fn ca(&self, audience: &str) -> Option<String> {
        match &self.source {
            Source::File(st) => st.cas.get(audience).cloned(),
            Source::Catalog(_) => None,
        }
    }

    /// Reached without a credential (`none`).
    #[must_use]
    pub fn no_credential(&self, audience: &str) -> bool {
        match &self.source {
            Source::File(st) => st.no_credential.contains(audience),
            Source::Catalog(v) => v.no_credential.contains(audience),
        }
    }

    /// The operator-held credential (`secret`), when one is held now.
    #[must_use]
    pub fn secret(&self, audience: &str) -> Option<&AudienceSecret> {
        match &self.source {
            Source::File(st) => st.secrets.get(audience),
            Source::Catalog(v) => v.secrets.get(audience),
        }
    }

    /// A `secret` audience whose credential has not been read, or not within two refresh
    /// periods (ADR-0055 decision 5): `503 credential_unavailable`. Never for the file.
    #[must_use]
    pub fn credential_unavailable(&self, audience: &str) -> bool {
        match &self.source {
            Source::File(_) => false,
            Source::Catalog(v) => v.unavailable.contains(audience),
        }
    }

    /// Served from the caller's own credential (`delegated`).
    #[must_use]
    pub fn delegated(&self, audience: &str) -> Option<&DelegatedAudience> {
        match &self.source {
            Source::File(st) => st.delegated.get(audience),
            Source::Catalog(v) => v.delegated.get(audience),
        }
    }

    /// The routes the gateway places it on, for a gateway-placed audience.
    #[must_use]
    pub fn inject(&self, audience: &str) -> Option<&Vec<InjectRoute>> {
        match &self.source {
            Source::File(st) => st.inject.get(audience),
            Source::Catalog(v) => v.inject.get(audience),
        }
    }
}
