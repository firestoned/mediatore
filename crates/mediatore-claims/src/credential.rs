// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! An audience's credential, read live (ADR-0055 decision 5).
//!
//! A credential is read from where its signed definition says, and nowhere else: a Secret in the
//! audience's own namespace (`secretRef`, which carries no namespace), or for a platform audience
//! a KV v2 path in the platform's `OpenBao`, read with the broker's own identity. Every audience is
//! read again each refresh period, so a rotation is served without a restart. A failed read keeps
//! the last good value for two refresh periods, then the audience has no credential until a read
//! succeeds; each transition is logged once. No value, and no reference to where it is read from,
//! is ever logged or printed.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use jiff::{SignedDuration, Timestamp};
use k8s_openapi::api::core::v1::Secret as KubeSecret;
use kube::{Api, Client};
use mediatore_policy::types::{CredentialFormat, CredentialSource, SecretRef};
use mediatore_proto::Secret;

use crate::audience::{AudienceCatalog, AudienceKind, LiveCatalog};

/// A credential as read: the token or password, and for `format: basic` the username.
#[derive(Clone, PartialEq, Eq)]
pub struct Material {
    /// The token or password. Prints redacted.
    pub secret: Secret,
    /// The username, for `format: basic`.
    pub username: Option<String>,
}

impl std::fmt::Debug for Material {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Material([redacted])")
    }
}

/// Why a read failed. Carries no reference and no value, so it can be logged as it is.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum ReadError {
    /// No such Secret or path, or no such key in it.
    #[error("not found")]
    NotFound,
    /// The broker may not read it: no `Role` granting `get` on that Secret, or no `OpenBao`
    /// policy granting the path.
    #[error("denied")]
    Denied,
    /// The API server or `OpenBao` did not answer.
    #[error("unavailable")]
    Unavailable,
    /// Present, but not a credential: an empty value, a missing key, `basic` without a username.
    #[error("malformed")]
    Malformed,
    /// A source the broker has no reader for (an `OpenBao` source with no `openbao` configured)
    /// or may not use (`OpenBao` for a team audience).
    #[error("no reader for this source")]
    NoReader,
}

/// Reads one credential source in one namespace.
#[async_trait::async_trait]
pub trait CredentialReader: Send + Sync {
    /// Read `source` for an audience of `namespace`, as `format` needs it.
    async fn read(
        &self,
        namespace: &str,
        source: &CredentialSource,
        format: CredentialFormat,
    ) -> Result<Material, ReadError>;
}

fn credential_text(raw: &[u8]) -> Result<String, ReadError> {
    let text = std::str::from_utf8(raw).map_err(|_| ReadError::Malformed)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.trim().is_empty() {
        return Err(ReadError::Malformed);
    }
    Ok(text.to_owned())
}

/// The credential in `secret` under `r`'s keys, as `format` needs it.
///
/// # Errors
/// [`ReadError::Malformed`] for a missing or empty key, or `basic` without a username key.
pub fn material_from_secret(
    secret: &KubeSecret,
    r: &SecretRef,
    format: CredentialFormat,
) -> Result<Material, ReadError> {
    let data = secret.data.as_ref().ok_or(ReadError::Malformed)?;
    let key = |k: &str| {
        data.get(k)
            .ok_or(ReadError::Malformed)
            .and_then(|v| credential_text(&v.0))
    };
    let username = match format {
        CredentialFormat::Bearer => None,
        CredentialFormat::Basic => Some(key(r
            .username_key
            .as_deref()
            .ok_or(ReadError::Malformed)?)?),
    };
    Ok(Material {
        secret: Secret(key(&r.token_key)?),
        username,
    })
}

/// Secrets read through the API server with `get` by name, in the audience's own namespace
/// (`deploy/audience-credentials`: a `Role` with `resourceNames`, nothing else).
pub struct KubeSecrets {
    client: Client,
}

impl KubeSecrets {
    /// A reader over `client`.
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl CredentialReader for KubeSecrets {
    async fn read(
        &self,
        namespace: &str,
        source: &CredentialSource,
        format: CredentialFormat,
    ) -> Result<Material, ReadError> {
        let CredentialSource::SecretRef(r) = source else {
            return Err(ReadError::NoReader);
        };
        let api = Api::<KubeSecret>::namespaced(self.client.clone(), namespace);
        match api.get(&r.name).await {
            Ok(secret) => material_from_secret(&secret, r, format),
            Err(kube::Error::Api(e)) if e.code == 404 => Err(ReadError::NotFound),
            Err(kube::Error::Api(e)) if e.code == 403 || e.code == 401 => Err(ReadError::Denied),
            Err(_) => Err(ReadError::Unavailable),
        }
    }
}

/// KV v2 in the platform's `OpenBao`, read with the broker's own login (ADR-0015).
pub struct OpenBaoKv {
    client: mediatore_openbao::Client,
}

impl OpenBaoKv {
    /// Log in once, so a wrong URL, CA, token file or role fails at start.
    ///
    /// # Errors
    /// The client's, as a message.
    pub async fn connect(cfg: &mediatore_openbao::KvConfig) -> anyhow::Result<Self> {
        let client = mediatore_openbao::Client::connect(&cfg.into())
            .await
            .map_err(|e| anyhow::anyhow!("policy.audience_definitions.openbao: {e}"))?;
        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl CredentialReader for OpenBaoKv {
    async fn read(
        &self,
        _namespace: &str,
        source: &CredentialSource,
        format: CredentialFormat,
    ) -> Result<Material, ReadError> {
        let CredentialSource::Openbao(o) = source else {
            return Err(ReadError::NoReader);
        };
        if format == CredentialFormat::Basic {
            // One key names no username.
            return Err(ReadError::Malformed);
        }
        let fields = self
            .client
            .kv_get(&o.mount, &o.path)
            .await
            .map_err(|e| match e {
                mediatore_openbao::Error::Denied(_) => ReadError::Denied,
                mediatore_openbao::Error::Rejected(_) => ReadError::NotFound,
                _ => ReadError::Unavailable,
            })?;
        let value = fields
            .get(&o.key)
            .and_then(serde_json::Value::as_str)
            .ok_or(ReadError::NotFound)?;
        Ok(Material {
            secret: Secret(credential_text(value.as_bytes())?),
            username: None,
        })
    }
}

/// Every reader the broker has: Secrets always, `OpenBao` when configured.
pub struct Readers {
    /// Secrets through the API server.
    pub kube: Option<Box<dyn CredentialReader>>,
    /// The platform's `OpenBao` KV.
    pub openbao: Option<Box<dyn CredentialReader>>,
}

#[async_trait::async_trait]
impl CredentialReader for Readers {
    async fn read(
        &self,
        namespace: &str,
        source: &CredentialSource,
        format: CredentialFormat,
    ) -> Result<Material, ReadError> {
        let reader = match source {
            CredentialSource::SecretRef(_) => self.kube.as_ref(),
            CredentialSource::Openbao(_) => self.openbao.as_ref(),
        };
        match reader {
            Some(r) => r.read(namespace, source, format).await,
            None => Err(ReadError::NoReader),
        }
    }
}

/// Why an audience has no credential to serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// Never read successfully, or its source changed since: `503 credential_unavailable`.
    NotRead,
    /// The last good read is older than two refresh periods.
    Stale,
}

#[derive(Clone)]
struct Entry {
    source: CredentialSource,
    format: CredentialFormat,
    material: Option<Arc<Material>>,
    last_ok: Option<Timestamp>,
    failing: Option<ReadError>,
}

/// `(namespace, name)` of an audience.
type Key = (String, String);

/// The credentials of the catalog's audiences, as last read.
pub struct CredentialCache {
    refresh: SignedDuration,
    entries: RwLock<HashMap<Key, Entry>>,
}

impl std::fmt::Debug for CredentialCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialCache")
            .field("refresh", &self.refresh)
            .field("audiences", &self.len())
            .finish_non_exhaustive()
    }
}

impl CredentialCache {
    /// A cache read again every `refresh`.
    #[must_use]
    pub fn new(refresh: SignedDuration) -> Self {
        Self {
            refresh,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// How many audiences have an entry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// No entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The credential of `namespace`/`name` at `now`, if one was read within two refresh
    /// periods.
    ///
    /// # Errors
    /// [`Unavailable`]: never read, or stale.
    pub fn get(
        &self,
        namespace: &str,
        name: &str,
        now: Timestamp,
    ) -> Result<Arc<Material>, Unavailable> {
        let entries = self.entries.read().unwrap_or_else(PoisonError::into_inner);
        let e = entries
            .get(&(namespace.to_owned(), name.to_owned()))
            .ok_or(Unavailable::NotRead)?;
        let (Some(m), Some(at)) = (&e.material, e.last_ok) else {
            return Err(Unavailable::NotRead);
        };
        if now.duration_since(at) > self.refresh * 2 {
            return Err(Unavailable::Stale);
        }
        Ok(m.clone())
    }

    /// Read every live audience of `catalog` that has a source, with `reader`, at `now`; drop
    /// the entries of audiences gone from it. Returns how many reads succeeded.
    pub async fn refresh(
        &self,
        catalog: &AudienceCatalog,
        reader: &dyn CredentialReader,
        now: Timestamp,
    ) -> usize {
        let wanted: Vec<_> = catalog
            .all_live(now)
            .filter_map(|a| {
                let source = a.definition.credential.source.clone()?;
                Some((
                    (a.namespace.clone(), a.name.clone()),
                    a.kind,
                    source,
                    a.definition.credential.format,
                ))
            })
            .collect();
        {
            let mut entries = self.entries.write().unwrap_or_else(PoisonError::into_inner);
            entries.retain(|k, e| {
                wanted
                    .iter()
                    .any(|(w, _, s, f)| w == k && *s == e.source && *f == e.format)
            });
        }
        let mut ok = 0;
        for (key, kind, source, format) in wanted {
            let outcome =
                if kind == AudienceKind::Team && matches!(source, CredentialSource::Openbao(_)) {
                    // audience_of never admits this; refused again rather than trusted.
                    Err(ReadError::NoReader)
                } else {
                    reader.read(&key.0, &source, format).await
                };
            let mut entries = self.entries.write().unwrap_or_else(PoisonError::into_inner);
            let e = entries.entry(key.clone()).or_insert_with(|| Entry {
                source,
                format,
                material: None,
                last_ok: None,
                failing: None,
            });
            match outcome {
                Ok(m) => {
                    ok += 1;
                    if e.last_ok.is_none() || e.failing.is_some() {
                        tracing::info!(namespace = %key.0, audience = %key.1, "audience credential read (ADR-0055)");
                    }
                    e.material = Some(Arc::new(m));
                    e.last_ok = Some(now);
                    e.failing = None;
                }
                Err(why) => {
                    if e.failing != Some(why) {
                        tracing::warn!(
                            namespace = %key.0,
                            audience = %key.1,
                            reason = %why,
                            serving_last_good = e.material.is_some(),
                            "audience credential not read (ADR-0055)"
                        );
                    }
                    e.failing = Some(why);
                }
            }
        }
        ok
    }
}

/// Read the credentials of `live`'s audiences every refresh period and whenever the catalog
/// changes, until the catalog is dropped. Every replica.
pub async fn run(
    live: Arc<LiveCatalog>,
    cache: Arc<CredentialCache>,
    reader: Arc<dyn CredentialReader>,
) -> anyhow::Result<()> {
    let period = std::time::Duration::try_from(cache.refresh)
        .map_err(|e| anyhow::anyhow!("credential refresh: {e}"))?;
    let mut changes = live.changes();
    let mut tick = tokio::time::interval(period);
    tracing::info!(
        every_secs = period.as_secs(),
        "audience credential refresh running"
    );
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            swapped = changes.changed() => {
                if swapped.is_err() {
                    anyhow::bail!("the audience catalog was dropped");
                }
            }
        }
        cache
            .refresh(&live.snapshot(), reader.as_ref(), Timestamp::now())
            .await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;

    use jiff::{SignedDuration, Timestamp};
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::Secret as KubeSecret;
    use mediatore_policy::types::{
        AudienceCredential, AudienceDefinition, Backend, CredentialFormat, CredentialSource,
        OpenBaoSource, Placement, SecretRef,
    };
    use mediatore_testkit::policy::signed_audience;
    use mediatore_testkit::transit::FakeTransit;

    use super::*;
    use crate::audience::{AudienceCatalog, audience_of};

    const PLATFORM: &str = "sandbox-platform";
    const TEAM: &str = "team-a";

    fn t0() -> Timestamp {
        "2026-11-20T12:00:00Z".parse().unwrap()
    }

    fn secret_ref(name: &str) -> CredentialSource {
        CredentialSource::SecretRef(SecretRef {
            name: name.into(),
            token_key: "token".into(),
            username_key: None,
        })
    }

    fn openbao(path: &str) -> CredentialSource {
        CredentialSource::Openbao(OpenBaoSource {
            mount: "secret".into(),
            path: path.into(),
            key: "token".into(),
        })
    }

    fn definition(source: Option<CredentialSource>, backend: Backend) -> AudienceDefinition {
        AudienceDefinition {
            credential: AudienceCredential {
                backend,
                placement: Placement::Gateway,
                format: CredentialFormat::Bearer,
                source,
                header: None,
                extra_headers: Vec::new(),
                refresh: None,
            },
            endpoints: vec!["r.example.com:443".into()],
            rules: Vec::new(),
            max_ttl_seconds: 300,
            ca_ref: None,
        }
    }

    fn catalog(entries: &[(&str, &str, AudienceDefinition)]) -> AudienceCatalog {
        let mut c = AudienceCatalog::new(PLATFORM);
        for (ns, name, d) in entries {
            let p = signed_audience(t0(), 1, ns, name, d.clone()).payload;
            c = c.with(audience_of(&p, PLATFORM).unwrap());
        }
        c
    }

    /// A reader that answers from a table the test changes as it goes, and counts the reads.
    #[derive(Default)]
    struct Table {
        answers: Mutex<HashMap<(String, String), Result<String, ReadError>>>,
        reads: Mutex<usize>,
    }

    impl Table {
        fn set(&self, ns: &str, name: &str, answer: Result<&str, ReadError>) {
            self.answers
                .lock()
                .unwrap()
                .insert((ns.to_owned(), name.to_owned()), answer.map(str::to_owned));
        }
    }

    #[async_trait::async_trait]
    impl CredentialReader for Table {
        async fn read(
            &self,
            namespace: &str,
            source: &CredentialSource,
            _format: CredentialFormat,
        ) -> Result<Material, ReadError> {
            *self.reads.lock().unwrap() += 1;
            let name = match source {
                CredentialSource::SecretRef(r) => r.name.clone(),
                CredentialSource::Openbao(o) => o.path.clone(),
            };
            match self
                .answers
                .lock()
                .unwrap()
                .get(&(namespace.to_owned(), name))
            {
                Some(Ok(v)) => Ok(Material {
                    secret: mediatore_proto::Secret(v.clone()),
                    username: None,
                }),
                Some(Err(e)) => Err(*e),
                None => Err(ReadError::NotFound),
            }
        }
    }

    fn refresh() -> SignedDuration {
        SignedDuration::from_secs(60)
    }

    #[tokio::test]
    async fn a_credential_is_read_from_the_audiences_own_namespace() {
        let c = catalog(&[(
            TEAM,
            "registry",
            definition(Some(secret_ref("reg")), Backend::Secret),
        )]);
        let table = Table::default();
        table.set(TEAM, "reg", Ok("team-token"));
        table.set(PLATFORM, "reg", Ok("platform-token"));
        let cache = CredentialCache::new(refresh());
        cache.refresh(&c, &table, t0()).await;
        let m = cache.get(TEAM, "registry", t0()).unwrap();
        assert_eq!(m.secret.0, "team-token");
    }

    #[tokio::test]
    async fn an_audience_with_no_source_needs_no_read() {
        let c = catalog(&[(TEAM, "open", definition(None, Backend::None))]);
        let table = Table::default();
        let cache = CredentialCache::new(refresh());
        cache.refresh(&c, &table, t0()).await;
        assert_eq!(*table.reads.lock().unwrap(), 0);
        assert_eq!(
            cache.get(TEAM, "open", t0()).unwrap_err(),
            Unavailable::NotRead
        );
    }

    #[tokio::test]
    async fn a_rotation_is_served_at_the_next_refresh() {
        let c = catalog(&[(
            TEAM,
            "registry",
            definition(Some(secret_ref("reg")), Backend::Secret),
        )]);
        let table = Table::default();
        let cache = CredentialCache::new(refresh());
        table.set(TEAM, "reg", Ok("v1"));
        cache.refresh(&c, &table, t0()).await;
        table.set(TEAM, "reg", Ok("v2"));
        cache.refresh(&c, &table, t0() + refresh()).await;
        assert_eq!(
            cache
                .get(TEAM, "registry", t0() + refresh())
                .unwrap()
                .secret
                .0,
            "v2"
        );
    }

    #[tokio::test]
    async fn a_failed_read_keeps_the_last_value_for_two_refresh_periods_then_none() {
        let c = catalog(&[(
            TEAM,
            "registry",
            definition(Some(secret_ref("reg")), Backend::Secret),
        )]);
        let table = Table::default();
        let cache = CredentialCache::new(refresh());
        table.set(TEAM, "reg", Ok("v1"));
        cache.refresh(&c, &table, t0()).await;
        table.set(TEAM, "reg", Err(ReadError::Unavailable));
        let at = |n: i64| t0() + SignedDuration::from_secs(60 * n);
        cache.refresh(&c, &table, at(1)).await;
        assert_eq!(cache.get(TEAM, "registry", at(1)).unwrap().secret.0, "v1");
        cache.refresh(&c, &table, at(2)).await;
        assert_eq!(cache.get(TEAM, "registry", at(2)).unwrap().secret.0, "v1");
        assert_eq!(
            cache
                .get(TEAM, "registry", at(2) + SignedDuration::from_secs(1))
                .unwrap_err(),
            Unavailable::Stale
        );
        // A read that succeeds again serves at once.
        table.set(TEAM, "reg", Ok("v2"));
        cache.refresh(&c, &table, at(3)).await;
        assert_eq!(cache.get(TEAM, "registry", at(3)).unwrap().secret.0, "v2");
    }

    #[tokio::test]
    async fn a_credential_never_read_is_not_served() {
        let c = catalog(&[(
            TEAM,
            "registry",
            definition(Some(secret_ref("reg")), Backend::Secret),
        )]);
        let table = Table::default();
        table.set(TEAM, "reg", Err(ReadError::Denied));
        let cache = CredentialCache::new(refresh());
        cache.refresh(&c, &table, t0()).await;
        assert_eq!(
            cache.get(TEAM, "registry", t0()).unwrap_err(),
            Unavailable::NotRead
        );
    }

    #[tokio::test]
    async fn a_changed_source_drops_the_old_value_and_a_withdrawn_audience_its_entry() {
        let table = Table::default();
        table.set(TEAM, "reg", Ok("old"));
        let cache = CredentialCache::new(refresh());
        let c = catalog(&[(
            TEAM,
            "registry",
            definition(Some(secret_ref("reg")), Backend::Secret),
        )]);
        cache.refresh(&c, &table, t0()).await;
        // The definition now points elsewhere, and that read fails: the old value is not
        // served for the new source.
        let c = catalog(&[(
            TEAM,
            "registry",
            definition(Some(secret_ref("moved")), Backend::Secret),
        )]);
        table.set(TEAM, "moved", Err(ReadError::Unavailable));
        cache.refresh(&c, &table, t0()).await;
        assert_eq!(
            cache.get(TEAM, "registry", t0()).unwrap_err(),
            Unavailable::NotRead
        );

        cache
            .refresh(&AudienceCatalog::new(PLATFORM), &table, t0())
            .await;
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn the_cache_prints_no_credential() {
        let c = catalog(&[(
            TEAM,
            "registry",
            definition(Some(secret_ref("reg")), Backend::Secret),
        )]);
        let table = Table::default();
        table.set(TEAM, "reg", Ok("do-not-print-me"));
        let cache = CredentialCache::new(refresh());
        cache.refresh(&c, &table, t0()).await;
        let printed = format!("{cache:?} {:?}", cache.get(TEAM, "registry", t0()).unwrap());
        assert!(!printed.contains("do-not-print-me"));
    }

    fn kube_secret(data: &[(&str, &str)]) -> KubeSecret {
        KubeSecret {
            data: Some(
                data.iter()
                    .map(|(k, v)| ((*k).to_owned(), ByteString(v.as_bytes().to_vec())))
                    .collect::<BTreeMap<_, _>>(),
            ),
            ..KubeSecret::default()
        }
    }

    #[test]
    fn a_secret_yields_its_token_and_for_basic_its_username() {
        let r = SecretRef {
            name: "reg".into(),
            token_key: "token".into(),
            username_key: Some("user".into()),
        };
        let m = material_from_secret(
            &kube_secret(&[("token", "t0k\n"), ("user", "octocat")]),
            &r,
            CredentialFormat::Basic,
        )
        .unwrap();
        assert_eq!(
            (m.secret.0.as_str(), m.username.as_deref()),
            ("t0k", Some("octocat"))
        );
        // Bearer ignores the username key.
        let m = material_from_secret(
            &kube_secret(&[("token", "t0k")]),
            &r,
            CredentialFormat::Bearer,
        )
        .unwrap();
        assert_eq!(m.username, None);
        // Missing or empty keys, and basic without a username key, are refused.
        for (data, format) in [
            (vec![("other", "x")], CredentialFormat::Bearer),
            (vec![("token", "  \n")], CredentialFormat::Bearer),
            (vec![("token", "t")], CredentialFormat::Basic),
        ] {
            assert_eq!(
                material_from_secret(&kube_secret(&data), &r, format).unwrap_err(),
                ReadError::Malformed,
                "{data:?}"
            );
        }
        let no_user = SecretRef {
            username_key: None,
            ..r
        };
        assert_eq!(
            material_from_secret(
                &kube_secret(&[("token", "t")]),
                &no_user,
                CredentialFormat::Basic
            )
            .unwrap_err(),
            ReadError::Malformed
        );
    }

    #[tokio::test]
    async fn a_platform_credential_is_read_from_openbao_kv() {
        let jwt = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(jwt.path(), "sa-jwt").unwrap();
        let fake = FakeTransit::spawn("mediatore", "sa-jwt", "unused").await;
        fake.put_kv("secret", "platform/registry", &[("token", "from-bao")]);
        fake.deny_kv("platform/other");
        let reader = OpenBaoKv::connect(&mediatore_openbao::KvConfig {
            url: fake.url.clone(),
            ca_file: None,
            role: "mediatore".into(),
            auth_mount: "kubernetes".into(),
            token_file: jwt.path().to_path_buf(),
        })
        .await
        .unwrap();
        let m = reader
            .read(
                PLATFORM,
                &openbao("platform/registry"),
                CredentialFormat::Bearer,
            )
            .await
            .unwrap();
        assert_eq!(m.secret.0, "from-bao");
        assert_eq!(
            reader
                .read(
                    PLATFORM,
                    &openbao("platform/other"),
                    CredentialFormat::Bearer
                )
                .await
                .unwrap_err(),
            ReadError::Denied
        );
        assert_eq!(
            reader
                .read(
                    PLATFORM,
                    &openbao("platform/none"),
                    CredentialFormat::Bearer
                )
                .await
                .unwrap_err(),
            ReadError::NotFound
        );
        // basic needs a username, and an OpenBao source names one key.
        assert_eq!(
            reader
                .read(
                    PLATFORM,
                    &openbao("platform/registry"),
                    CredentialFormat::Basic
                )
                .await
                .unwrap_err(),
            ReadError::Malformed
        );
    }

    #[tokio::test]
    async fn a_team_audience_is_never_read_from_openbao_even_if_it_reached_the_cache() {
        // audience_of refuses it; the cache refuses it again rather than trusting that.
        let mut a = audience_of(
            &signed_audience(
                t0(),
                1,
                PLATFORM,
                "registry",
                definition(Some(openbao("p")), Backend::Secret),
            )
            .payload,
            PLATFORM,
        )
        .unwrap();
        a.namespace = TEAM.into();
        a.kind = crate::audience::AudienceKind::Team;
        let c = AudienceCatalog::new(PLATFORM).with(a);
        let table = Table::default();
        table.set(TEAM, "p", Ok("x"));
        let cache = CredentialCache::new(refresh());
        cache.refresh(&c, &table, t0()).await;
        assert_eq!(*table.reads.lock().unwrap(), 0);
        assert!(cache.get(TEAM, "registry", t0()).is_err());
    }
}
