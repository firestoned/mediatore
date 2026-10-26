// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The workload rootfs: pulled from its OCI registry by the guest, as root, and unpacked
//! onto the sandbox tmpfs before the ruleset and the jail (ADR-0021).
//!
//! The guest speaks the distribution API itself, anonymously, following one bearer
//! challenge; every blob is verified against its digest, the manifest digest is what the
//! audit records. Layers are applied in order with whiteouts, and an entry that would land
//! outside the rootfs refuses the image.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

/// Docker Hub, as a reference names it.
const DOCKER_IO: &str = "docker.io";
/// Docker Hub, as the API reaches it.
const DOCKER_REGISTRY: &str = "registry-1.docker.io";
/// The tag a reference without one means.
const DEFAULT_TAG: &str = "latest";

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";

/// What `Accept` says on a manifest request: both families, image and index.
const ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json";

/// An image reference: `[registry/]repository[:tag][@sha256:digest]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// The registry host the API is reached at (`registry-1.docker.io` for Docker Hub).
    pub registry: String,
    /// Repository path (`library/busybox`).
    pub repository: String,
    /// Tag, when named.
    pub tag: Option<String>,
    /// Digest, when pinned; what the manifest must hash to.
    pub digest: Option<String>,
}

impl Reference {
    /// What the manifest is asked for by: the digest when pinned, else the tag, else `latest`.
    #[must_use]
    pub fn manifest_reference(&self) -> &str {
        self.digest
            .as_deref()
            .or(self.tag.as_deref())
            .unwrap_or(DEFAULT_TAG)
    }
}

fn is_digest(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_repository(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('/')
        && !s.ends_with('/')
        && s.split('/').all(|c| {
            !c.is_empty()
                && c.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        })
}

fn is_tag(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl std::str::FromStr for Reference {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (rest, digest) = match s.split_once('@') {
            Some((r, d)) => {
                if !is_digest(d) {
                    return Err(format!(
                        "image reference {s:?}: digest must be sha256:<64 hex>"
                    ));
                }
                (r, Some(d.to_string()))
            }
            None => (s, None),
        };
        // A colon after the last slash is the tag separator; before it, a registry port.
        let (name, tag) = match rest.rsplit_once(':') {
            Some((n, t)) if !t.contains('/') => {
                if !is_tag(t) {
                    return Err(format!("image reference {s:?}: tag {t:?} is not a tag"));
                }
                (n, Some(t.to_string()))
            }
            _ => (rest, None),
        };
        let (registry, repository) = match name.split_once('/') {
            Some((first, path))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_string(), path.to_string())
            }
            _ => (DOCKER_IO.to_string(), name.to_string()),
        };
        let (registry, repository) = if registry == DOCKER_IO {
            let repository = if repository.contains('/') {
                repository
            } else {
                format!("library/{repository}")
            };
            (DOCKER_REGISTRY.to_string(), repository)
        } else {
            (registry, repository)
        };
        if !is_repository(&repository) {
            return Err(format!(
                "image reference {s:?}: {repository:?} is not a repository path"
            ));
        }
        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        if let Some(t) = &self.tag {
            write!(f, ":{t}")?;
        }
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        }
        Ok(())
    }
}

/// The platform the guest selects from an index: `linux` and this machine's architecture
/// in the registry's spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    /// `linux`.
    pub os: String,
    /// `amd64`, `arm64`, ...
    pub architecture: String,
}

impl Platform {
    /// This machine's.
    #[must_use]
    pub fn this() -> Self {
        let architecture = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        Self {
            os: "linux".into(),
            architecture: architecture.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default)]
    platform: Option<Platform>,
}

impl<'de> Deserialize<'de> for Platform {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            os: String,
            architecture: String,
        }
        let r = Raw::deserialize(d)?;
        Ok(Self {
            os: r.os,
            architecture: r.architecture,
        })
    }
}

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    #[serde(default)]
    manifests: Vec<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

/// How a layer's bytes are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayerEncoding {
    Tar,
    Gzip,
}

fn layer_encoding(media_type: &str) -> anyhow::Result<LayerEncoding> {
    match media_type {
        "application/vnd.oci.image.layer.v1.tar"
        | "application/vnd.docker.image.rootfs.diff.tar" => Ok(LayerEncoding::Tar),
        "application/vnd.oci.image.layer.v1.tar+gzip"
        | "application/vnd.docker.image.rootfs.diff.tar.gzip" => Ok(LayerEncoding::Gzip),
        other => {
            anyhow::bail!("layer media type {other:?} is not supported (tar and tar+gzip are)")
        }
    }
}

/// What a pull produced, for the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pulled {
    /// The manifest digest the reference resolved to: what ran.
    pub digest: String,
    /// Layers applied.
    pub layers: usize,
    /// Bytes fetched for the layers.
    pub bytes: u64,
}

/// The pull client: one per guest, anonymous, HTTPS unless the registry is listed as plain.
#[derive(Debug, Clone)]
pub struct Puller {
    http: reqwest::Client,
    plain_http: BTreeSet<String>,
    platform: Platform,
}

/// One pull's bearer token, obtained from the registry's challenge, kept for the pull only.
#[derive(Default)]
struct Session {
    token: Option<String>,
}

impl Puller {
    /// A client for this platform; `plain_http` lists the registries (`host[:port]`)
    /// reached over HTTP instead of HTTPS.
    pub fn new(plain_http: &[String]) -> anyhow::Result<Self> {
        // TLS 1.3 over the Mozilla roots on aws-lc-rs (ADR-0007 decision 6): the registry
        // is a system we do not operate, so the far end keeps a classical fallback.
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(mediatore_proto::tls::https_client_config())
            .user_agent(concat!("mediatore-guest/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            plain_http: plain_http.iter().cloned().collect(),
            platform: Platform::this(),
        })
    }

    /// Select another platform from an index than this machine's. Tests only.
    #[cfg(test)]
    fn with_platform(mut self, p: Platform) -> Self {
        self.platform = p;
        self
    }

    fn base(&self, reference: &Reference) -> String {
        let scheme = if self.plain_http.contains(&reference.registry) {
            "http"
        } else {
            "https"
        };
        format!(
            "{scheme}://{}/v2/{}",
            reference.registry, reference.repository
        )
    }

    /// GET `url`, answering one bearer challenge.
    async fn get(
        &self,
        session: &mut Session,
        url: &str,
        accept: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        for attempt in 0..2 {
            let mut req = self.http.get(url);
            if let Some(a) = accept {
                req = req.header(reqwest::header::ACCEPT, a);
            }
            if let Some(t) = &session.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            if resp.status() != reqwest::StatusCode::UNAUTHORIZED || attempt == 1 {
                return Ok(resp);
            }
            let challenge = resp
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_bearer_challenge)
                .ok_or_else(|| anyhow::anyhow!("{url}: 401 without a bearer challenge"))?;
            session.token = Some(self.token(&challenge).await?);
        }
        unreachable!("two attempts, each returns");
    }

    async fn token(&self, c: &Challenge) -> anyhow::Result<String> {
        #[derive(Deserialize)]
        struct TokenResponse {
            #[serde(default)]
            token: Option<String>,
            #[serde(default)]
            access_token: Option<String>,
        }
        let mut query = Vec::new();
        if let Some(s) = &c.service {
            query.push(("service", s.as_str()));
        }
        if let Some(s) = &c.scope {
            query.push(("scope", s.as_str()));
        }
        let resp = self.http.get(&c.realm).query(&query).send().await?;
        anyhow::ensure!(
            resp.status().is_success(),
            "token endpoint {} refused: {}",
            c.realm,
            resp.status()
        );
        let t: TokenResponse = resp.json().await?;
        t.token
            .or(t.access_token)
            .ok_or_else(|| anyhow::anyhow!("token endpoint {} returned no token", c.realm))
    }

    async fn manifest(
        &self,
        session: &mut Session,
        reference: &Reference,
        by: &str,
    ) -> anyhow::Result<(String, Manifest)> {
        let url = format!("{}/manifests/{by}", self.base(reference));
        let resp = self.get(session, &url, Some(ACCEPT)).await?;
        anyhow::ensure!(
            resp.status().is_success(),
            "{reference}: manifest {by} refused: {}",
            resp.status()
        );
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        let body = resp.bytes().await?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&body)));
        if is_digest(by) {
            anyhow::ensure!(
                digest == by,
                "{reference}: manifest {by} hashes to {digest}; the registry served other bytes"
            );
        }
        let mut m: Manifest = serde_json::from_slice(&body)
            .map_err(|e| anyhow::anyhow!("{reference}: manifest {by} is not a manifest: {e}"))?;
        if m.media_type.is_empty() {
            m.media_type = content_type;
        }
        Ok((digest, m))
    }

    /// Pull `reference` into `rootfs`, staging each layer under `scratch` while it is
    /// hashed. `rootfs` and `scratch` exist and are empty.
    pub async fn pull(
        &self,
        reference: &Reference,
        rootfs: &Path,
        scratch: &Path,
    ) -> anyhow::Result<Pulled> {
        let mut session = Session::default();
        let by = reference.manifest_reference();
        let (mut digest, mut manifest) = self.manifest(&mut session, reference, by).await?;
        if matches!(
            manifest.media_type.as_str(),
            OCI_INDEX | DOCKER_MANIFEST_LIST
        ) || (!manifest.manifests.is_empty() && manifest.layers.is_empty())
        {
            let want = &self.platform;
            let entry = manifest
                .manifests
                .iter()
                .find(|d| d.platform.as_ref() == Some(want))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{reference}: the index {digest} has no manifest for {}/{}",
                        want.os,
                        want.architecture
                    )
                })?;
            let d = entry.digest.clone();
            anyhow::ensure!(
                is_digest(&d),
                "{reference}: index entry digest {d:?} is not sha256"
            );
            (digest, manifest) = self.manifest(&mut session, reference, &d).await?;
        }
        anyhow::ensure!(
            matches!(manifest.media_type.as_str(), OCI_MANIFEST | DOCKER_MANIFEST)
                || (!manifest.layers.is_empty() && manifest.manifests.is_empty()),
            "{reference}: {digest} is a {:?}, not an image manifest",
            manifest.media_type
        );
        anyhow::ensure!(
            !manifest.layers.is_empty(),
            "{reference}: {digest} has no layers"
        );
        // Refuse before any byte is fetched: an image with one layer we cannot read is not
        // an image we half-run.
        let encodings = manifest
            .layers
            .iter()
            .map(|l| layer_encoding(&l.media_type))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let mut bytes = 0;
        for (n, (layer, encoding)) in manifest.layers.iter().zip(encodings).enumerate() {
            anyhow::ensure!(
                is_digest(&layer.digest),
                "{reference}: layer {n} digest {:?} is not sha256",
                layer.digest
            );
            let staged = scratch.join(format!("layer-{n}"));
            let size = self
                .fetch_blob(&mut session, reference, layer, &staged)
                .await?;
            bytes += size;
            let rootfs = rootfs.to_path_buf();
            let staged_for_apply = staged.clone();
            let applied = tokio::task::spawn_blocking(move || {
                apply_layer(&staged_for_apply, encoding, &rootfs)
            })
            .await?;
            let _ = tokio::fs::remove_file(&staged).await;
            let applied = applied
                .map_err(|e| anyhow::anyhow!("{reference}: layer {n} ({}): {e}", layer.digest))?;
            tracing::debug!(
                layer = n,
                digest = %layer.digest,
                bytes = size,
                entries = applied.entries,
                skipped = applied.skipped,
                "layer applied"
            );
        }
        Ok(Pulled {
            digest,
            layers: manifest.layers.len(),
            bytes,
        })
    }

    /// Stream one blob to `dest`, hashing as it goes; the digest and size must match the
    /// descriptor or the file is removed and the pull fails.
    async fn fetch_blob(
        &self,
        session: &mut Session,
        reference: &Reference,
        d: &Descriptor,
        dest: &Path,
    ) -> anyhow::Result<u64> {
        let url = format!("{}/blobs/{}", self.base(reference), d.digest);
        let mut resp = self.get(session, &url, None).await?;
        anyhow::ensure!(
            resp.status().is_success(),
            "{reference}: blob {} refused: {}",
            d.digest,
            resp.status()
        );
        let mut file = tokio::fs::File::create(dest).await?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let result: anyhow::Result<()> = async {
            while let Some(chunk) = resp.chunk().await? {
                size += chunk.len() as u64;
                anyhow::ensure!(
                    size <= d.size,
                    "blob {} exceeds its declared size {}",
                    d.digest,
                    d.size
                );
                hasher.update(&chunk);
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            anyhow::ensure!(
                size == d.size,
                "blob {} is {size} bytes, declared {}",
                d.digest,
                d.size
            );
            let got = format!("sha256:{}", hex::encode(hasher.finalize()));
            anyhow::ensure!(
                got == d.digest,
                "blob {} hashes to {got}; the registry served other bytes",
                d.digest
            );
            Ok(())
        }
        .await;
        if let Err(e) = result {
            drop(file);
            let _ = tokio::fs::remove_file(dest).await;
            return Err(anyhow::anyhow!("{reference}: {e}"));
        }
        Ok(size)
    }
}

/// A parsed `WWW-Authenticate: Bearer realm="…",service="…",scope="…"`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Challenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

fn parse_bearer_challenge(header: &str) -> Option<Challenge> {
    let rest = header.trim().strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for part in rest.split(',') {
        let (k, v) = part.trim().split_once('=')?;
        let v = v.trim().trim_matches('"').to_string();
        match k.trim() {
            "realm" => realm = Some(v),
            "service" => service = Some(v),
            "scope" => scope = Some(v),
            _ => {}
        }
    }
    Some(Challenge {
        realm: realm?,
        service,
        scope,
    })
}

/// What applying a layer did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Applied {
    entries: usize,
    /// Device nodes, fifos and other entry types the rootfs does not take.
    skipped: usize,
}

/// A layer entry's path relative to the rootfs: `./` dropped, nothing but plain
/// components allowed. `..`, a root or a prefix refuses the layer.
fn relative(path: &Path) -> anyhow::Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("entry {} escapes the rootfs", path.display())
            }
        }
    }
    Ok(out)
}

/// Remove whatever is at `p`, file, link or tree. Missing is fine.
fn remove_any(p: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Apply one layer onto `rootfs`: whiteouts first-class, no path out of the rootfs, no
/// setuid, no device nodes, no ownership, no xattrs (ADR-0021 decision 4).
fn apply_layer(staged: &Path, encoding: LayerEncoding, rootfs: &Path) -> anyhow::Result<Applied> {
    let file = std::fs::File::open(staged)?;
    let reader: Box<dyn Read> = match encoding {
        LayerEncoding::Tar => Box::new(file),
        LayerEncoding::Gzip => Box::new(flate2::read::GzDecoder::new(file)),
    };
    let mut archive = tar::Archive::new(reader);
    // The defaults, stated: mode bits beyond 0o777 dropped, no xattrs, no uid/gid.
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);
    archive.set_preserve_ownerships(false);
    archive.set_overwrite(true);
    let mut applied = Applied::default();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let rel = relative(&path)?;
        let Some(name) = rel.file_name().and_then(|n| n.to_str()) else {
            // `./` alone: the root itself.
            continue;
        };
        let parent = rel
            .parent()
            .map_or_else(|| rootfs.to_path_buf(), |p| rootfs.join(p));
        if name == ".wh..wh..opq" {
            if let Ok(children) = std::fs::read_dir(&parent) {
                for c in children {
                    remove_any(&c?.path())?;
                }
            }
            applied.entries += 1;
            continue;
        }
        if let Some(target) = name.strip_prefix(".wh.") {
            remove_any(&parent.join(target))?;
            applied.entries += 1;
            continue;
        }
        let kind = entry.header().entry_type();
        let is_dir = kind.is_dir();
        if !matches!(
            kind,
            tar::EntryType::Regular
                | tar::EntryType::Continuous
                | tar::EntryType::Directory
                | tar::EntryType::Symlink
                | tar::EntryType::Link
        ) {
            tracing::debug!(entry = %path.display(), ?kind, "layer entry skipped");
            applied.skipped += 1;
            continue;
        }
        // Overlay semantics: a directory replaces a file or link and a file replaces a
        // tree, instead of writing through what the lower layer left there.
        let dest = rootfs.join(&rel);
        if let Ok(m) = std::fs::symlink_metadata(&dest) {
            if is_dir != m.is_dir() {
                remove_any(&dest)?;
            } else if !is_dir {
                std::fs::remove_file(&dest)?;
            }
        }
        anyhow::ensure!(
            entry.unpack_in(rootfs)?,
            "entry {} escapes the rootfs",
            path.display()
        );
        applied.entries += 1;
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use mediatore_testkit::registry::{Compression, FakeRegistry, Image, Layer, digest};

    use super::*;

    fn r(s: &str) -> Reference {
        s.parse().unwrap()
    }

    #[test]
    fn a_bare_name_is_docker_hub_library_latest() {
        let got = r("busybox");
        assert_eq!(got.registry, "registry-1.docker.io");
        assert_eq!(got.repository, "library/busybox");
        assert_eq!(got.tag, None);
        assert_eq!(got.manifest_reference(), "latest");
        assert_eq!(r("docker.io/busybox:1.37").repository, "library/busybox");
        assert_eq!(r("octocat/tool:1").repository, "octocat/tool");
        assert_eq!(r("octocat/tool:1").registry, "registry-1.docker.io");
    }

    #[test]
    fn a_registry_with_a_port_a_tag_and_a_digest_parse_apart() {
        let d = "sha256:".to_string() + &"a".repeat(64);
        let got = r(&format!("registry.internal:5000/team/tool:v2@{d}"));
        assert_eq!(got.registry, "registry.internal:5000");
        assert_eq!(got.repository, "team/tool");
        assert_eq!(got.tag.as_deref(), Some("v2"));
        assert_eq!(got.digest.as_deref(), Some(d.as_str()));
        assert_eq!(
            got.manifest_reference(),
            d,
            "a pinned reference is asked for by digest"
        );
        assert_eq!(
            got.to_string(),
            format!("registry.internal:5000/team/tool:v2@{d}")
        );
        let plain = r("localhost:5000/tool");
        assert_eq!(plain.registry, "localhost:5000");
        assert_eq!(plain.repository, "tool");
        assert_eq!(plain.tag, None);
        assert_eq!(r("ghcr.io/firestoned/mediatore").registry, "ghcr.io");
    }

    #[test]
    fn a_malformed_reference_is_refused() {
        for bad in [
            "",
            "Busybox",
            "ghcr.io/",
            "ghcr.io/x@sha256:short",
            "ghcr.io/x@md5:abc",
            "ghcr.io/x:tag with space",
            "ghcr.io//x",
        ] {
            assert!(bad.parse::<Reference>().is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn the_bearer_challenge_is_parsed_and_a_non_bearer_one_is_not() {
        let c = parse_bearer_challenge(
            "Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\",scope=\"repository:a/b:pull\"",
        )
        .unwrap();
        assert_eq!(c.realm, "https://ghcr.io/token");
        assert_eq!(c.service.as_deref(), Some("ghcr.io"));
        assert_eq!(c.scope.as_deref(), Some("repository:a/b:pull"));
        assert_eq!(parse_bearer_challenge("Basic realm=\"x\""), None);
        assert_eq!(
            parse_bearer_challenge("Bearer service=\"x\""),
            None,
            "no realm, no challenge"
        );
    }

    #[test]
    fn only_plain_components_are_relative_to_the_rootfs() {
        assert_eq!(
            relative(Path::new("./bin/sh")).unwrap(),
            PathBuf::from("bin/sh")
        );
        assert_eq!(
            relative(Path::new("bin/./sh")).unwrap(),
            PathBuf::from("bin/sh")
        );
        assert!(
            relative(Path::new("../x"))
                .unwrap_err()
                .to_string()
                .contains("escapes")
        );
        assert!(relative(Path::new("a/../../x")).is_err());
        assert!(relative(Path::new("/etc/passwd")).is_err());
    }

    struct Scratch {
        rootfs: PathBuf,
        scratch: PathBuf,
    }

    fn scratch() -> Scratch {
        let dir = mediatore_testkit::tempdir();
        let rootfs = dir.join("rootfs");
        let scratch = dir.join("layers");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        Scratch { rootfs, scratch }
    }

    fn puller(reg: &FakeRegistry) -> Puller {
        Puller::new(&[reg.host()]).unwrap()
    }

    fn reference(reg: &FakeRegistry, rest: &str) -> Reference {
        r(&format!("{}/{rest}", reg.host()))
    }

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[tokio::test]
    async fn layers_are_applied_in_order_with_whiteouts_and_replacements() {
        let reg = FakeRegistry::start().await;
        let lower = Layer::new()
            .dir("bin", 0o755)
            .file("bin/sh", 0o755, b"lower sh")
            .dir("etc", 0o755)
            .file("etc/old", 0o644, b"gone later")
            .file("etc/keep", 0o644, b"kept")
            .dir("var", 0o755)
            .file("var/a", 0o644, b"a")
            .file("var/b", 0o644, b"b")
            .file("conf", 0o644, b"a file that becomes a dir")
            .dir("tree", 0o755)
            .file("tree/leaf", 0o644, b"a tree that becomes a file")
            .symlink("link", "bin/sh");
        let upper = Layer::new()
            .file("bin/sh", 0o755, b"upper sh")
            .whiteout("etc/old")
            .opaque("var")
            .file("var/c", 0o644, b"c")
            .dir("conf", 0o755)
            .file("conf/x", 0o644, b"x")
            .file("tree", 0o644, b"now a file")
            .link("bin/sh-hard", "bin/sh")
            .dir("link", 0o755);
        let img = Image::new()
            .layer(lower, Compression::None)
            .layer(upper, Compression::Gzip)
            .build();
        let want = reg.push("team/tool", "v1", &img);
        let s = scratch();
        let got = puller(&reg)
            .pull(&reference(&reg, "team/tool:v1"), &s.rootfs, &s.scratch)
            .await
            .unwrap();
        assert_eq!(
            got.digest, want,
            "a tag resolves to the manifest digest that ran"
        );
        assert_eq!(got.layers, 2);
        assert_eq!(
            got.bytes,
            img.layers.iter().map(|l| l.bytes.len() as u64).sum::<u64>()
        );
        let read = |p: &str| std::fs::read_to_string(s.rootfs.join(p)).unwrap();
        assert_eq!(read("bin/sh"), "upper sh");
        assert_eq!(read("bin/sh-hard"), "upper sh");
        assert!(
            !s.rootfs.join("etc/old").exists(),
            "whiteout removes the lower file"
        );
        assert!(
            !s.rootfs.join("etc/.wh.old").exists(),
            "the whiteout itself is not unpacked"
        );
        assert_eq!(read("etc/keep"), "kept");
        let mut var: Vec<String> = std::fs::read_dir(s.rootfs.join("var"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        var.sort();
        assert_eq!(var, ["c"], "an opaque whiteout empties the lower directory");
        assert_eq!(read("conf/x"), "x", "a directory replaces a file");
        assert_eq!(read("tree"), "now a file", "a file replaces a tree");
        assert!(
            s.rootfs.join("link").is_dir(),
            "a directory replaces a symlink"
        );
        assert!(
            !std::fs::symlink_metadata(s.rootfs.join("link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(mode(&s.rootfs.join("bin/sh")), 0o755);
        assert!(
            std::fs::read_dir(&s.scratch).unwrap().next().is_none(),
            "staged layers are removed once applied"
        );
    }

    #[tokio::test]
    async fn docker_media_types_are_accepted_too() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .docker()
            .layer(
                Layer::new().file("hello", 0o644, b"hi"),
                Compression::DockerGzip,
            )
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        puller(&reg)
            .pull(&reference(&reg, "team/tool:v1"), &s.rootfs, &s.scratch)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(s.rootfs.join("hello")).unwrap(),
            "hi"
        );
    }

    #[tokio::test]
    async fn an_entry_that_escapes_by_dot_dot_refuses_the_image() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(
                Layer::new()
                    .file("ok", 0o644, b"ok")
                    .raw_file("../escape", b"outside"),
                Compression::None,
            )
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        let err = puller(&reg)
            .pull(&reference(&reg, "team/tool:v1"), &s.rootfs, &s.scratch)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("escapes the rootfs"), "{err}");
        assert!(!s.rootfs.parent().unwrap().join("escape").exists());
    }

    #[tokio::test]
    async fn an_entry_through_a_symlink_out_of_the_rootfs_refuses_the_image() {
        let reg = FakeRegistry::start().await;
        let outside = mediatore_testkit::tempdir();
        let img = Image::new()
            .layer(
                Layer::new()
                    .symlink("door", outside.to_str().unwrap())
                    .file("door/planted", 0o644, b"outside"),
                Compression::Gzip,
            )
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        let err = puller(&reg)
            .pull(&reference(&reg, "team/tool:v1"), &s.rootfs, &s.scratch)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("outside") || err.contains("escapes"), "{err}");
        assert!(
            !outside.join("planted").exists(),
            "nothing landed outside the rootfs"
        );
    }

    #[tokio::test]
    async fn a_symlink_inside_the_rootfs_is_followed_and_an_absolute_one_kept_as_is() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(
                Layer::new()
                    .dir("usr/bin", 0o755)
                    .symlink("bin", "usr/bin")
                    .file("bin/sh", 0o755, b"sh")
                    .symlink("sbin", "/usr/bin"),
                Compression::None,
            )
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        puller(&reg)
            .pull(&reference(&reg, "team/tool:v1"), &s.rootfs, &s.scratch)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(s.rootfs.join("usr/bin/sh")).unwrap(),
            "sh"
        );
        assert_eq!(
            std::fs::read_link(s.rootfs.join("sbin")).unwrap(),
            PathBuf::from("/usr/bin"),
            "an absolute link means inside the chroot"
        );
    }

    #[tokio::test]
    async fn setuid_bits_are_dropped_and_device_nodes_skipped() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(
                Layer::new()
                    .file("suid", 0o4755, b"#!/bin/sh")
                    .file("sgid", 0o2755, b"#!/bin/sh")
                    .dir("sticky", 0o1777)
                    .device("dev/mem"),
                Compression::None,
            )
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        puller(&reg)
            .pull(&reference(&reg, "team/tool:v1"), &s.rootfs, &s.scratch)
            .await
            .unwrap();
        assert_eq!(mode(&s.rootfs.join("suid")), 0o755);
        assert_eq!(mode(&s.rootfs.join("sgid")), 0o755);
        assert_eq!(mode(&s.rootfs.join("sticky")), 0o777);
        assert!(
            !s.rootfs.join("dev/mem").exists(),
            "no device nodes in the rootfs"
        );
    }

    #[tokio::test]
    async fn a_blob_whose_bytes_do_not_match_its_digest_is_refused() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .layer(Layer::new().file("b", 0o644, b"b"), Compression::Gzip)
            .build();
        reg.push("team/tool", "v1", &img);
        reg.tamper(&img.layers[1].digest());
        let s = scratch();
        let err = puller(&reg)
            .pull(&reference(&reg, "team/tool:v1"), &s.rootfs, &s.scratch)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("served other bytes"), "{err}");
        assert!(
            std::fs::read_dir(&s.scratch).unwrap().next().is_none(),
            "the tampered blob is not left staged"
        );
    }

    #[tokio::test]
    async fn a_reference_pinned_by_digest_must_match_what_the_registry_serves() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .build();
        let d = reg.push("team/tool", "v1", &img);
        let other = digest(b"something else");
        // The registry answers the pinned digest with a manifest that hashes differently.
        reg.push("team/tool", &other, &img);
        let s = scratch();
        let err = puller(&reg)
            .pull(
                &reference(&reg, &format!("team/tool@{other}")),
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("served other bytes"), "{err}");
        assert_eq!(
            reg.blob_requests(),
            0,
            "nothing fetched after a manifest mismatch"
        );
        let ok = puller(&reg)
            .pull(
                &reference(&reg, &format!("team/tool:v1@{d}")),
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(ok.digest, d);
    }

    #[tokio::test]
    async fn an_index_selects_this_platform_and_refuses_without_it() {
        let reg = FakeRegistry::start().await;
        let here = Image::new()
            .layer(Layer::new().file("arch", 0o644, b"here"), Compression::None)
            .build();
        let elsewhere = Image::new()
            .platform("s390x", "linux")
            .layer(
                Layer::new().file("arch", 0o644, b"elsewhere"),
                Compression::None,
            )
            .build();
        reg.push_index("team/tool", "multi", &[&elsewhere, &here]);
        reg.push_index("team/tool", "foreign", &[&elsewhere]);
        let s = scratch();
        let got = puller(&reg)
            .pull(&reference(&reg, "team/tool:multi"), &s.rootfs, &s.scratch)
            .await
            .unwrap();
        assert_eq!(
            got.digest,
            here.manifest.digest(),
            "the digest is the image's, not the index's"
        );
        assert_eq!(
            std::fs::read_to_string(s.rootfs.join("arch")).unwrap(),
            "here"
        );
        let err = puller(&reg)
            .pull(&reference(&reg, "team/tool:foreign"), &s.rootfs, &s.scratch)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no manifest for linux/"), "{err}");
        let got = puller(&reg)
            .with_platform(Platform {
                os: "linux".into(),
                architecture: "s390x".into(),
            })
            .pull(&reference(&reg, "team/tool:foreign"), &s.rootfs, &s.scratch)
            .await
            .unwrap();
        assert_eq!(got.digest, elsewhere.manifest.digest());
    }

    #[tokio::test]
    async fn an_unsupported_layer_is_refused_before_any_blob_is_fetched() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .layer(
                Layer::new().file("b", 0o644, b"b"),
                Compression::ZstdLabelled,
            )
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        let err = puller(&reg)
            .pull(&reference(&reg, "team/tool:v1"), &s.rootfs, &s.scratch)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("tar+zstd") && err.contains("not supported"),
            "{err}"
        );
        assert_eq!(reg.blob_requests(), 0);
        assert!(!s.rootfs.join("a").exists());
    }

    #[tokio::test]
    async fn the_bearer_challenge_is_answered_once_and_the_token_reused() {
        let reg = FakeRegistry::start().await;
        reg.require_token(true);
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .layer(Layer::new().file("b", 0o644, b"b"), Compression::None)
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        puller(&reg)
            .pull(&reference(&reg, "team/tool:v1"), &s.rootfs, &s.scratch)
            .await
            .unwrap();
        assert_eq!(reg.token_requests(), 1);
        assert_eq!(std::fs::read_to_string(s.rootfs.join("b")).unwrap(), "b");
    }

    #[tokio::test]
    async fn a_registry_not_listed_as_plain_is_reached_over_https_only() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        let err = Puller::new(&[])
            .unwrap()
            .pull(&reference(&reg, "team/tool:v1"), &s.rootfs, &s.scratch)
            .await
            .unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            !chain.contains("http://"),
            "the plain listener must not have been spoken to in the clear: {chain}"
        );
    }

    /// Pulls a real image from a real registry. Set `MEDIATORE_PULL_IMAGE` to a reference
    /// (`docker.io/library/busybox:1.37`); the test fails, never skips, without it.
    #[tokio::test]
    #[ignore = "needs the network: MEDIATORE_PULL_IMAGE=docker.io/library/busybox:1.37"]
    async fn a_real_image_pulls_from_its_registry() {
        let image = std::env::var("MEDIATORE_PULL_IMAGE").unwrap_or_else(|_| {
            panic!("set MEDIATORE_PULL_IMAGE to an image reference, e.g. docker.io/library/busybox:1.37")
        });
        let s = scratch();
        let got = Puller::new(&[])
            .unwrap()
            .pull(&r(&image), &s.rootfs, &s.scratch)
            .await
            .unwrap();
        assert!(is_digest(&got.digest));
        assert!(got.layers >= 1 && got.bytes > 0);
        assert!(
            std::fs::read_dir(&s.rootfs).unwrap().next().is_some(),
            "the rootfs has content"
        );
        eprintln!(
            "pulled {image} as {} ({} layers, {} bytes)",
            got.digest, got.layers, got.bytes
        );
    }
}
