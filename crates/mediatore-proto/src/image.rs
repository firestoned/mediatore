// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The image reference grammar the broker and the guest share (ADR-0021, ADR-0022):
//! `[registry/]repository[:tag][@sha256:digest]`, Docker Hub's shorthand normalised to
//! the host the API reaches, so a credential configured for `docker.io` matches a
//! reference to `busybox`.

use std::fmt;

/// Docker Hub, as a reference names it.
pub const DOCKER_IO: &str = "docker.io";
/// Docker Hub, as the API reaches it.
pub const DOCKER_REGISTRY: &str = "registry-1.docker.io";
/// The tag a reference without one means.
pub const DEFAULT_TAG: &str = "latest";

/// An image reference, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    /// The registry host the API is reached at (`registry-1.docker.io` for Docker Hub).
    pub registry: String,
    /// Repository path (`library/busybox`).
    pub repository: String,
    /// Tag, when named.
    pub tag: Option<String>,
    /// Digest, when pinned; what the manifest must hash to.
    pub digest: Option<String>,
}

impl ImageReference {
    /// What the manifest is asked for by: the digest when pinned, else the tag, else `latest`.
    #[must_use]
    pub fn manifest_reference(&self) -> &str {
        self.digest
            .as_deref()
            .or(self.tag.as_deref())
            .unwrap_or(DEFAULT_TAG)
    }
}

/// `sha256:` followed by 64 hex digits.
#[must_use]
pub fn is_sha256_digest(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The registry an endpoint serves, by the name an image reference to it carries (ADR-0063 decision 2): the host,
/// with the port only when it is not 443, Docker Hub's name made its API host.
#[must_use]
pub fn registry_name(endpoint: &crate::Endpoint) -> String {
    let host = canonical_registry(&endpoint.host);
    if endpoint.port == 443 {
        host
    } else {
        format!("{host}:{}", endpoint.port)
    }
}

/// Why `image` may not be pulled by a claim that names `named` (ADR-0063 decision 2): none of the claim's audiences
/// of `role: registry` serves its registry. `registry_audiences` maps each such audience to the registries it serves;
/// `None` means nothing is granted by registry (no gateways), and nothing is refused. The answer is the same whether
/// the registry is served to another namespace or to none, so a refusal says nothing about another tenant.
#[must_use]
pub fn ungranted_registry(
    registry_audiences: Option<
        &std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    >,
    named: &[String],
    image: &ImageReference,
) -> Option<String> {
    let registry_audiences = registry_audiences?;
    let granted = named.iter().any(|a| {
        registry_audiences
            .get(a)
            .is_some_and(|r| r.contains(&image.registry))
    });
    (!granted).then(|| {
        format!(
            "registry {} is not granted to this sandbox: name an audience with role: registry that serves it (ADR-0063)",
            image.registry
        )
    })
}

/// A registry host as the API reaches it: Docker Hub's name becomes its API host,
/// anything else is itself.
#[must_use]
pub fn canonical_registry(host: &str) -> String {
    if host == DOCKER_IO {
        DOCKER_REGISTRY.to_string()
    } else {
        host.to_string()
    }
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

/// A registry host component: has a dot or a port, or is `localhost`; otherwise the first
/// path component is part of the repository and the registry is Docker Hub.
fn looks_like_registry(first: &str) -> bool {
    first.contains('.') || first.contains(':') || first == "localhost"
}

impl std::str::FromStr for ImageReference {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (rest, digest) = match s.split_once('@') {
            Some((r, d)) => {
                if !is_sha256_digest(d) {
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
            Some((first, path)) if looks_like_registry(first) => {
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

impl fmt::Display for ImageReference {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registry_is_named_as_an_image_reference_carries_it() {
        let e = |h: &str, p| crate::Endpoint {
            host: h.into(),
            port: p,
        };
        assert_eq!(
            registry_name(&e("registry.home.example", 443)),
            "registry.home.example"
        );
        assert_eq!(
            registry_name(&e("registry.home.example", 5443)),
            "registry.home.example:5443"
        );
        assert_eq!(registry_name(&e("docker.io", 443)), DOCKER_REGISTRY);
    }

    #[test]
    fn an_image_is_granted_only_by_a_registry_audience_the_claim_names() {
        let map: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> = [
            (
                "mirror".to_string(),
                ["registry.home.example".to_string()].into(),
            ),
            ("hub".to_string(), [DOCKER_REGISTRY.to_string()].into()),
        ]
        .into();
        let image: ImageReference = "registry.home.example/team/tool:v1".parse().unwrap();
        let named = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert_eq!(
            ungranted_registry(Some(&map), &named(&["mirror"]), &image),
            None
        );
        assert_eq!(
            ungranted_registry(None, &[], &image),
            None,
            "no gateways: nothing refused"
        );
        let busybox: ImageReference = "busybox".parse().unwrap();
        assert_eq!(
            ungranted_registry(Some(&map), &named(&["hub"]), &busybox),
            None
        );
        // Not named, named but serving another registry, or not a registry audience: one answer.
        for n in [named(&[]), named(&["hub"]), named(&["api"])] {
            let why = ungranted_registry(Some(&map), &n, &image).unwrap();
            assert_eq!(
                why,
                "registry registry.home.example is not granted to this sandbox: name an audience with role: registry that serves it (ADR-0063)",
                "{n:?}"
            );
        }
    }

    fn r(s: &str) -> ImageReference {
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
        assert_eq!(canonical_registry("docker.io"), "registry-1.docker.io");
        assert_eq!(canonical_registry("ghcr.io"), "ghcr.io");
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
            assert!(bad.parse::<ImageReference>().is_err(), "{bad:?} parsed");
        }
    }
}
