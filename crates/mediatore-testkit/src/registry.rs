// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! A fake OCI registry on a real listener: the slice of the distribution API the guest's
//! pull uses (ADR-0021), with images built in the test from a list of entries.
//!
//! [`Layer`] builds one layer tar, entry by entry, including the shapes a hostile image
//! would carry (a path with `..`, a setuid bit, a device node); [`Image`] turns layers into
//! a manifest with digests; [`FakeRegistry`] serves them, optionally behind the bearer
//! challenge real registries send, and can serve a blob's bytes corrupted to prove the
//! digest check.

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use sha2::{Digest, Sha256};

/// OCI image manifest media type.
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// OCI image index media type.
pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// OCI config media type.
pub const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
/// OCI uncompressed layer.
pub const OCI_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
/// OCI gzip layer.
pub const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
/// OCI zstd layer, which the guest refuses.
pub const OCI_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
/// Docker schema 2 manifest.
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
/// Docker manifest list.
pub const DOCKER_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
/// Docker gzip layer.
pub const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// The bearer token the registry hands out when it requires one.
pub const TOKEN: &str = "fake-registry-token";

/// `sha256:<hex>` of `bytes`.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// One entry of a layer tar.
#[derive(Debug, Clone)]
enum Entry {
    File {
        path: String,
        mode: u32,
        data: Vec<u8>,
    },
    Dir {
        path: String,
        mode: u32,
    },
    Symlink {
        path: String,
        target: String,
    },
    Link {
        path: String,
        target: String,
    },
    Device {
        path: String,
    },
    /// A regular file whose header name is written as given, `..` and all.
    RawFile {
        path: String,
        data: Vec<u8>,
    },
}

/// A layer under construction. Entries are written in the order they were added.
#[derive(Debug, Clone, Default)]
pub struct Layer {
    entries: Vec<Entry>,
}

impl Layer {
    /// An empty layer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A regular file.
    #[must_use]
    pub fn file(mut self, path: &str, mode: u32, data: &[u8]) -> Self {
        self.entries.push(Entry::File {
            path: path.into(),
            mode,
            data: data.to_vec(),
        });
        self
    }

    /// A directory.
    #[must_use]
    pub fn dir(mut self, path: &str, mode: u32) -> Self {
        self.entries.push(Entry::Dir {
            path: path.into(),
            mode,
        });
        self
    }

    /// A symbolic link to `target`.
    #[must_use]
    pub fn symlink(mut self, path: &str, target: &str) -> Self {
        self.entries.push(Entry::Symlink {
            path: path.into(),
            target: target.into(),
        });
        self
    }

    /// A hard link to `target`, an earlier entry of this layer.
    #[must_use]
    pub fn link(mut self, path: &str, target: &str) -> Self {
        self.entries.push(Entry::Link {
            path: path.into(),
            target: target.into(),
        });
        self
    }

    /// A character device node.
    #[must_use]
    pub fn device(mut self, path: &str) -> Self {
        self.entries.push(Entry::Device { path: path.into() });
        self
    }

    /// A whiteout for `path`: `dir/.wh.name`, which removes `dir/name` from the layers below.
    #[must_use]
    pub fn whiteout(self, path: &str) -> Self {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
        let wh = if dir.is_empty() {
            format!(".wh.{name}")
        } else {
            format!("{dir}/.wh.{name}")
        };
        self.file(&wh, 0o644, b"")
    }

    /// An opaque whiteout for `dir`: everything below it from the layers below is gone.
    #[must_use]
    pub fn opaque(self, dir: &str) -> Self {
        self.file(&format!("{dir}/.wh..wh..opq"), 0o644, b"")
    }

    /// A regular file whose name is written into the header verbatim: the way to put
    /// `../escape` into a tar, which the `tar` crate's own path setter refuses.
    #[must_use]
    pub fn raw_file(mut self, path: &str, data: &[u8]) -> Self {
        self.entries.push(Entry::RawFile {
            path: path.into(),
            data: data.to_vec(),
        });
        self
    }

    /// The layer as an uncompressed tar.
    ///
    /// # Panics
    /// When an entry cannot be written (a raw name over the header's 100 bytes).
    #[must_use]
    pub fn tar(&self) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for e in &self.entries {
            match e {
                Entry::File { path, mode, data } => {
                    let mut h = tar::Header::new_gnu();
                    h.set_size(data.len() as u64);
                    h.set_mode(*mode);
                    h.set_entry_type(tar::EntryType::Regular);
                    b.append_data(&mut h, path, data.as_slice()).unwrap();
                }
                Entry::Dir { path, mode } => {
                    let mut h = tar::Header::new_gnu();
                    h.set_size(0);
                    h.set_mode(*mode);
                    h.set_entry_type(tar::EntryType::Directory);
                    b.append_data(&mut h, path, std::io::empty()).unwrap();
                }
                Entry::Symlink { path, target } => {
                    let mut h = tar::Header::new_gnu();
                    h.set_size(0);
                    h.set_mode(0o777);
                    h.set_entry_type(tar::EntryType::Symlink);
                    b.append_link(&mut h, path, target).unwrap();
                }
                Entry::Link { path, target } => {
                    let mut h = tar::Header::new_gnu();
                    h.set_size(0);
                    h.set_mode(0o644);
                    h.set_entry_type(tar::EntryType::Link);
                    b.append_link(&mut h, path, target).unwrap();
                }
                Entry::Device { path } => {
                    let mut h = tar::Header::new_gnu();
                    h.set_size(0);
                    h.set_mode(0o666);
                    h.set_entry_type(tar::EntryType::Char);
                    h.set_device_major(1).unwrap();
                    h.set_device_minor(3).unwrap();
                    b.append_data(&mut h, path, std::io::empty()).unwrap();
                }
                Entry::RawFile { path, data } => {
                    let mut h = tar::Header::new_gnu();
                    h.set_size(data.len() as u64);
                    h.set_mode(0o644);
                    h.set_entry_type(tar::EntryType::Regular);
                    let name = h.as_mut_bytes();
                    let bytes = path.as_bytes();
                    assert!(bytes.len() < 100, "a raw name fits the header's name field");
                    name[..bytes.len()].copy_from_slice(bytes);
                    h.set_cksum();
                    b.append(&h, data.as_slice()).unwrap();
                }
            }
        }
        b.into_inner().unwrap()
    }
}

/// How a layer is stored in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// `application/vnd.oci.image.layer.v1.tar`
    None,
    /// `application/vnd.oci.image.layer.v1.tar+gzip`
    Gzip,
    /// `application/vnd.docker.image.rootfs.diff.tar.gzip`: the Docker spelling of gzip
    DockerGzip,
    /// `application/vnd.oci.image.layer.v1.tar+zstd`, served as the gzip bytes under the
    /// wrong media type: the guest must refuse before it looks inside
    ZstdLabelled,
}

/// A blob the registry serves: its bytes and its media type.
#[derive(Debug, Clone)]
pub struct Blob {
    /// Media type in the manifest's descriptor.
    pub media_type: String,
    /// The bytes as served.
    pub bytes: Vec<u8>,
}

impl Blob {
    /// `sha256:` digest of the bytes.
    #[must_use]
    pub fn digest(&self) -> String {
        digest(&self.bytes)
    }
}

/// An image under construction: ordered layers and a platform.
#[derive(Debug, Clone)]
pub struct Image {
    layers: Vec<(Layer, Compression)>,
    architecture: String,
    os: String,
    docker_media_types: bool,
}

impl Default for Image {
    fn default() -> Self {
        Self {
            layers: Vec::new(),
            architecture: this_architecture().into(),
            os: "linux".into(),
            docker_media_types: false,
        }
    }
}

/// The architecture name the guest asks an index for on this machine, so a test image
/// matches wherever the tests run.
#[must_use]
pub fn this_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

impl Image {
    /// An image for this machine's architecture and `linux`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a layer.
    #[must_use]
    pub fn layer(mut self, layer: Layer, compression: Compression) -> Self {
        self.layers.push((layer, compression));
        self
    }

    /// Declare the platform; `new` already set this machine's.
    #[must_use]
    pub fn platform(mut self, architecture: &str, os: &str) -> Self {
        self.architecture = architecture.into();
        self.os = os.into();
        self
    }

    /// Use the Docker schema 2 media types instead of the OCI ones.
    #[must_use]
    pub fn docker(mut self) -> Self {
        self.docker_media_types = true;
        self
    }

    /// Build the blobs and the manifest.
    ///
    /// # Panics
    /// When a layer cannot be compressed or the manifest cannot be serialised.
    #[must_use]
    pub fn build(&self) -> Built {
        let mut blobs = Vec::new();
        let mut diff_ids = Vec::new();
        for (layer, compression) in &self.layers {
            let tar = layer.tar();
            diff_ids.push(digest(&tar));
            let gz = || {
                let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                e.write_all(&tar).unwrap();
                e.finish().unwrap()
            };
            let (media_type, bytes) = match compression {
                Compression::None => (OCI_LAYER_TAR, tar.clone()),
                Compression::Gzip => (OCI_LAYER_GZIP, gz()),
                Compression::DockerGzip => (DOCKER_LAYER_GZIP, gz()),
                Compression::ZstdLabelled => (OCI_LAYER_ZSTD, gz()),
            };
            blobs.push(Blob {
                media_type: media_type.into(),
                bytes,
            });
        }
        let config = Blob {
            media_type: OCI_CONFIG.into(),
            bytes: serde_json::to_vec(&serde_json::json!({
                "architecture": self.architecture,
                "os": self.os,
                "rootfs": { "type": "layers", "diff_ids": diff_ids },
            }))
            .unwrap(),
        };
        let manifest_type = if self.docker_media_types {
            DOCKER_MANIFEST
        } else {
            OCI_MANIFEST
        };
        let descriptor = |b: &Blob| serde_json::json!({ "mediaType": b.media_type, "digest": b.digest(), "size": b.bytes.len() });
        let manifest = serde_json::to_vec_pretty(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": manifest_type,
            "config": descriptor(&config),
            "layers": blobs.iter().map(descriptor).collect::<Vec<_>>(),
        }))
        .unwrap();
        Built {
            manifest: Blob {
                media_type: manifest_type.into(),
                bytes: manifest,
            },
            config,
            layers: blobs,
            architecture: self.architecture.clone(),
            os: self.os.clone(),
        }
    }
}

/// A built image: the manifest and every blob it names.
#[derive(Debug, Clone)]
pub struct Built {
    /// The manifest, OCI or Docker.
    pub manifest: Blob,
    /// The config blob.
    pub config: Blob,
    /// The layers, in order.
    pub layers: Vec<Blob>,
    /// Platform, for an index.
    pub architecture: String,
    /// Platform, for an index.
    pub os: String,
}

#[derive(Default)]
struct Inner {
    /// name → reference (tag or digest) → manifest
    manifests: Mutex<HashMap<String, HashMap<String, Blob>>>,
    /// digest → bytes, shared by every repository
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    tampered: Mutex<Vec<String>>,
    require_token: AtomicBool,
    /// The login `/token` demands, as HTTP Basic, before it hands out the bearer token.
    credential: Mutex<Option<(String, String)>>,
    /// Demand that login on the content itself, with a `Basic` challenge and no token
    /// endpoint: the shape of a plain private registry.
    basic_only: AtomicBool,
    token_requests: AtomicUsize,
    blob_requests: AtomicUsize,
    /// Content requests that carried `Authorization: Basic`.
    basic_on_content: AtomicUsize,
    requests: AtomicUsize,
    host: Mutex<String>,
}

/// The registry, serving on a loopback listener until dropped.
pub struct FakeRegistry {
    inner: Arc<Inner>,
    host: String,
    _task: tokio::task::JoinHandle<()>,
}

impl FakeRegistry {
    /// Bind a loopback listener and serve.
    ///
    /// # Panics
    /// When the listener cannot be bound.
    pub async fn start() -> Self {
        let inner = Arc::new(Inner::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the fake registry");
        let host = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        inner.host.lock().unwrap().clone_from(&host);
        let app = Router::new()
            .route("/v2/", get(base))
            .route("/v2/{*rest}", get(v2))
            .route("/token", get(token))
            .with_state(inner.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve the fake registry");
        });
        Self {
            inner,
            host,
            _task: task,
        }
    }

    /// `127.0.0.1:<port>`: the registry part of a reference, reached over plain HTTP.
    #[must_use]
    pub fn host(&self) -> String {
        self.host.clone()
    }

    /// Store `image` under `name` at `reference` (a tag) and at its digest; returns the
    /// manifest digest.
    ///
    /// # Panics
    /// When the registry's state lock is poisoned.
    pub fn push(&self, name: &str, reference: &str, image: &Built) -> String {
        {
            let mut blobs = self.inner.blobs.lock().unwrap();
            blobs.insert(image.config.digest(), image.config.bytes.clone());
            for l in &image.layers {
                blobs.insert(l.digest(), l.bytes.clone());
            }
        }
        let d = image.manifest.digest();
        let mut m = self.inner.manifests.lock().unwrap();
        let repo = m.entry(name.into()).or_default();
        repo.insert(reference.into(), image.manifest.clone());
        repo.insert(d.clone(), image.manifest.clone());
        d
    }

    /// Store an index at `reference` pointing at `images`, each pushed by digest; returns
    /// the index digest.
    ///
    /// # Panics
    /// When the registry's state lock is poisoned.
    pub fn push_index(&self, name: &str, reference: &str, images: &[&Built]) -> String {
        let entries: Vec<serde_json::Value> = images
            .iter()
            .map(|i| {
                self.push(name, &i.manifest.digest(), i);
                serde_json::json!({
                    "mediaType": i.manifest.media_type,
                    "digest": i.manifest.digest(),
                    "size": i.manifest.bytes.len(),
                    "platform": { "architecture": i.architecture, "os": i.os },
                })
            })
            .collect();
        let index = Blob {
            media_type: OCI_INDEX.into(),
            bytes: serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": OCI_INDEX,
                "manifests": entries,
            }))
            .unwrap(),
        };
        let d = index.digest();
        let mut m = self.inner.manifests.lock().unwrap();
        let repo = m.entry(name.into()).or_default();
        repo.insert(reference.into(), index.clone());
        repo.insert(d.clone(), index);
        d
    }

    /// Require `Authorization: Bearer` on every request, with the challenge real
    /// registries send; `/token` answers the challenge.
    pub fn require_token(&self, on: bool) {
        self.inner.require_token.store(on, Ordering::SeqCst);
    }

    /// Require this login at `/token` (ADR-0022): an anonymous token request is refused,
    /// one with the right HTTP Basic credential gets the bearer token. Implies
    /// `require_token`.
    ///
    /// # Panics
    /// When the registry's state lock is poisoned.
    pub fn require_credential(&self, username: &str, password: &str) {
        self.require_token(true);
        *self.inner.credential.lock().unwrap() = Some((username.into(), password.into()));
    }

    /// Challenge content requests with `Basic` and accept this login on them; no token
    /// endpoint is involved.
    ///
    /// # Panics
    /// When the registry's state lock is poisoned.
    pub fn basic_only(&self, username: &str, password: &str) {
        self.inner.basic_only.store(true, Ordering::SeqCst);
        *self.inner.credential.lock().unwrap() = Some((username.into(), password.into()));
    }

    /// How many manifest or blob requests carried `Authorization: Basic`.
    #[must_use]
    pub fn basic_on_content(&self) -> usize {
        self.inner.basic_on_content.load(Ordering::SeqCst)
    }

    /// How many requests of any kind arrived.
    #[must_use]
    pub fn requests(&self) -> usize {
        self.inner.requests.load(Ordering::SeqCst)
    }

    /// Serve the blob at `digest` with its first byte flipped.
    ///
    /// # Panics
    /// When the registry's state lock is poisoned.
    pub fn tamper(&self, digest: &str) {
        self.inner.tampered.lock().unwrap().push(digest.into());
    }

    /// How many times `/token` was asked.
    #[must_use]
    pub fn token_requests(&self) -> usize {
        self.inner.token_requests.load(Ordering::SeqCst)
    }

    /// How many blobs were fetched.
    #[must_use]
    pub fn blob_requests(&self) -> usize {
        self.inner.blob_requests.load(Ordering::SeqCst)
    }
}

/// `Authorization: Basic` decoded and compared to the configured login.
fn basic_matches(inner: &Inner, headers: &HeaderMap) -> bool {
    use base64::Engine as _;
    let Some((user, pass)) = inner.credential.lock().unwrap().clone() else {
        return false;
    };
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|raw| String::from_utf8(raw).ok())
        .is_some_and(|v| v == format!("{user}:{pass}"))
}

fn unauthorized(inner: &Inner, name: &str) -> Response {
    let host = inner.host.lock().unwrap().clone();
    let challenge = if inner.basic_only.load(Ordering::SeqCst) {
        "Basic realm=\"fake-registry\"".to_string()
    } else {
        format!(
            "Bearer realm=\"http://{host}/token\",service=\"fake-registry\",scope=\"repository:{name}:pull\""
        )
    };
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, challenge)],
        "{\"errors\":[{\"code\":\"UNAUTHORIZED\"}]}",
    )
        .into_response()
}

fn authorized(inner: &Inner, headers: &HeaderMap) -> bool {
    inner.requests.fetch_add(1, Ordering::SeqCst);
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Basic "))
    {
        inner.basic_on_content.fetch_add(1, Ordering::SeqCst);
    }
    if inner.basic_only.load(Ordering::SeqCst) {
        return basic_matches(inner, headers);
    }
    if !inner.require_token.load(Ordering::SeqCst) {
        return true;
    }
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == format!("Bearer {TOKEN}"))
}

async fn base(State(inner): State<Arc<Inner>>, headers: HeaderMap) -> Response {
    if !authorized(&inner, &headers) {
        return unauthorized(&inner, "");
    }
    (StatusCode::OK, "{}").into_response()
}

async fn token(
    State(inner): State<Arc<Inner>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    inner.requests.fetch_add(1, Ordering::SeqCst);
    inner.token_requests.fetch_add(1, Ordering::SeqCst);
    if inner.credential.lock().unwrap().is_some() && !basic_matches(&inner, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"fake-registry\"")],
            "{\"errors\":[{\"code\":\"UNAUTHORIZED\"}]}",
        )
            .into_response();
    }
    assert!(
        q.contains_key("service") && q.contains_key("scope"),
        "a token request carries the challenge's service and scope"
    );
    Json(serde_json::json!({ "token": TOKEN })).into_response()
}

async fn v2(
    State(inner): State<Arc<Inner>>,
    Path(rest): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some((name, reference)) = rest.rsplit_once("/manifests/") {
        if !authorized(&inner, &headers) {
            return unauthorized(&inner, name);
        }
        let found = inner
            .manifests
            .lock()
            .unwrap()
            .get(name)
            .and_then(|r| r.get(reference))
            .cloned();
        return match found {
            Some(m) => (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, m.media_type.clone()),
                    (
                        header::HeaderName::from_static("docker-content-digest"),
                        m.digest(),
                    ),
                ],
                m.bytes,
            )
                .into_response(),
            None => (
                StatusCode::NOT_FOUND,
                "{\"errors\":[{\"code\":\"MANIFEST_UNKNOWN\"}]}",
            )
                .into_response(),
        };
    }
    if let Some((name, digest)) = rest.rsplit_once("/blobs/") {
        if !authorized(&inner, &headers) {
            return unauthorized(&inner, name);
        }
        inner.blob_requests.fetch_add(1, Ordering::SeqCst);
        let found = inner.blobs.lock().unwrap().get(digest).cloned();
        return match found {
            Some(mut bytes) => {
                if inner.tampered.lock().unwrap().iter().any(|d| d == digest) {
                    bytes[0] ^= 0xff;
                }
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/octet-stream")],
                    bytes,
                )
                    .into_response()
            }
            None => (
                StatusCode::NOT_FOUND,
                "{\"errors\":[{\"code\":\"BLOB_UNKNOWN\"}]}",
            )
                .into_response(),
        };
    }
    StatusCode::NOT_FOUND.into_response()
}
