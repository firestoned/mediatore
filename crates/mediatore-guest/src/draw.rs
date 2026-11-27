// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The draw (ADR-0069 decision 3): which decoy ports, decoy routes and bait credentials one
//! claim gets, random per claim, generated, and never off the VM.
//!
//! [`draw`] takes its randomness from an [`Entropy`] and from nothing else: [`OsEntropy`] in
//! the guest, a seeded source in the tests of the rules. It draws the three counts first
//! (within `PORT_COUNT`, `ROUTE_COUNT`, `CREDENTIAL_COUNT`, or the deployment's narrower
//! range), then fills each place from one of four sources:
//!
//! - the **deployment's catalogue** ([`TrapCatalogue`]), weight 6 where it has entries of the
//!   kind: three times the seeds, and at least half of all the weight (no broker serves one
//!   yet: decision 4, amended);
//! - the **seeds**, roadmap 17's public tables, weight 2;
//! - **generated** entries, weight 2: a port anywhere in 1024 to 65535, a host from word
//!   lists, a variable from a stem, a provider and an ending;
//! - **derived** entries, weight 2, for routes only: a second host beside one of the claim's
//!   real ones.
//!
//! The first port of every draw is a generated one, so no draw is seed ports alone, and each
//! list is shuffled, so a place says nothing.
//!
//! An entry that collides with anything real is drawn again, never skipped: a port the proxy,
//! the pull listener or the workload uses; a host that is a route; a variable the guest or
//! the workload's specification sets; a credential whose provider is one of the claim's
//! routes, or whose variable is in a tool's lookup family with one that is set (either of
//! `GH_TOKEN` and `GITHUB_TOKEN` set excludes both); anything already drawn. A
//! place that still collides after [`ATTEMPTS`] draws fails the draw: a claim under `enforce`
//! then starts no jail (decision 5), and none ever runs with a smaller draw than it was owed.
//!
//! Every credential value is the provider's prefix, length and alphabet filled from the
//! source, with the checksum where the format has one. None is valid anywhere, and none is
//! kept after the claim.
//!
//! Two things differ from roadmap 17's tables, on purpose:
//!
//! - `SENTRY_DSN` is a decoy route's variable like the others, with no key in it. An SDK reads
//!   that variable on its own, so a well-formed DSN would be used by an honest run of any
//!   program that links one; a value that is not a DSN is ignored by the SDK and still trips
//!   whoever requests it.
//! - A file is planted once a draw: when two baits would write `~/.git-credentials`, the
//!   second keeps its variables and plants no file.
//!
//! Nothing here prints a bait value: [`BaitValue`] has no `Display` and a redacting `Debug`
//! (decision 12).

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use mediatore_proto::trip::{
    CREDENTIAL_COUNT, ClassAction, CountRange, MAX_TARGET_HOST_BYTES, MAX_TRAP_NAME_BYTES,
    MAX_TRAP_VARIABLE_BYTES, PORT_COUNT, ProxyBait, ProxyDecoyRoute, ProxyTraps, ROUTE_COUNT,
    TrapCatalogue, TrapGenerator, TrapVariable, TrapsBody, TripMode,
};
use mediatore_proto::{Route, Secret};

/// Where the draw's randomness comes from: the OS in the guest, a seeded source in a test.
pub trait Entropy: Send {
    /// Fill `buf` with random bytes.
    ///
    /// # Errors
    /// When the source fails, which the guest treats as a failure to arm.
    fn fill(&mut self, buf: &mut [u8]) -> anyhow::Result<()>;
}

/// The provider's random source, the one the phantom token is drawn from.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        aws_lc_rs::rand::fill(buf).map_err(|_| anyhow::anyhow!("the random source failed"))
    }
}

/// What a draw must know of the claim, so that nothing drawn collides with anything real.
#[derive(Debug, Clone, Copy)]
pub struct DrawInputs<'a> {
    /// The claim's real routes: a decoy is never one of them, and a bait credential never one
    /// of their providers.
    pub routes: &'a [Route],
    /// The egress proxy's loopback port.
    pub proxy_port: u16,
    /// The proxy's pull listener's port.
    pub pull_port: u16,
    /// Every other port a decoy must not take.
    pub reserved_ports: &'a [u16],
    /// The variables the guest sets itself (the phantom, the proxy's address, `HOME`) and
    /// every variable the workload's specification sets: no decoy takes one, and no bait takes
    /// one, or any other variable of a tool's lookup family that has a member here.
    pub reserved_env: &'a [&'a str],
    /// The deployment's catalogue, weighted above the seeds; no broker serves one yet.
    pub catalogue: Option<&'a TrapCatalogue>,
    /// Whether the metadata decoy may be drawn: only where a route to the address exists.
    pub metadata: bool,
}

/// One bait value. It never prints: read it with [`BaitValue::expose`], and only to plant it
/// or to hand it to the matcher.
#[derive(Clone, PartialEq, Eq)]
pub struct BaitValue(String);

impl BaitValue {
    /// Wrap a generated value.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The value itself. Never for a log line, a report or an error.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BaitValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// The first line a decoy listener answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Banner {
    /// An SSH identification string.
    Ssh,
    /// A Redis `-NOAUTH` error.
    Redis,
    /// An HTTP `401`.
    Http401,
    /// An SMTP greeting.
    Smtp,
    /// A `MySQL` handshake's first bytes.
    Mysql,
    /// A `PostgreSQL` refusal.
    Postgres,
    /// A development HTTP server's `200`.
    HttpDev,
}

/// One decoy listener on loopback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoyPort {
    /// The decoy's name, what a report's `trap` says.
    pub name: String,
    /// The loopback port.
    pub port: u16,
    /// What it answers.
    pub banner: Banner,
}

/// One decoy route of the proxy, advertised to the workload in a variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoyRoute {
    /// The decoy's name, what a report's `trap` says.
    pub name: String,
    /// The host a request would name.
    pub host: String,
    /// The variable that points at it through the proxy (`VAULT_ADDR`).
    pub env: String,
}

/// One bait credential: where it is planted and every value the matcher looks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bait {
    /// The catalogue entry's name, what a report's `trap` says.
    pub name: String,
    /// The variables it is planted in, and the value of each.
    pub env: Vec<(String, BaitValue)>,
    /// The files it is planted in: a path relative to the sandbox user's home, and the
    /// content. Never under `/work`.
    pub files: Vec<(String, BaitValue)>,
    /// Every secret value of this bait, wherever it is planted: what the proxy matches and
    /// what the output redactor strips.
    pub values: Vec<BaitValue>,
}

/// One claim's draw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draw {
    /// The decoy listeners.
    pub ports: Vec<DecoyPort>,
    /// `Some` when the metadata decoy was drawn. Since the maintainer's decision 13 of
    /// 2026-11-27 the metadata address is redirected to the claim's one trap listener
    /// ([`trap_port`]) and nothing listens on this number; it is still drawn off the claim's
    /// ports, so the draw is what it was.
    pub metadata_port: Option<u16>,
    /// The decoy routes.
    pub routes: Vec<DecoyRoute>,
    /// The bait credentials.
    pub credentials: Vec<Bait>,
}

/// The sandbox user's home in the jail, where the bait files are planted.
const JAIL_HOME: &str = "/home/sandbox";

/// How many times one slot is drawn again, and one number rejected, before the draw fails. A
/// collision redraws and never shortens the draw; a slot that cannot be filled is a failure to
/// arm, not a smaller draw.
const ATTEMPTS: usize = 64;

/// The proportions of a draw. The deployment's catalogue, when it has entries of a kind,
/// weighs three times the seeds and at least as much as every public source together;
/// without one the rest keep their proportions.
const WEIGHT_DEPLOYMENT: u32 = 6;
const WEIGHT_SEED: u32 = 2;
const WEIGHT_GENERATED: u32 = 2;
const WEIGHT_DERIVED: u32 = 2;

const DIGITS: &[u8] = b"0123456789";
const HEX: &[u8] = b"0123456789abcdef";
const LOWER_ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// Base62 in the order the checksummed token formats encode with.
const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Where one entry of a draw comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The deployment's catalogue.
    Deployment,
    /// The public tables of roadmap 17.
    Seed,
    /// Made from word lists, or anywhere in the port range.
    Generated,
    /// Shaped after one of the claim's real routes.
    Derived,
}

/// The entropy source with the draws built on it. Every number is unbiased (rejection
/// sampling) and every loop is bounded.
struct Rng<'a>(&'a mut dyn Entropy);

impl Rng<'_> {
    fn u32(&mut self) -> anyhow::Result<u32> {
        let mut buf = [0u8; 4];
        self.0.fill(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    /// A number in `0..n`, each equally likely.
    fn below(&mut self, n: u32) -> anyhow::Result<u32> {
        anyhow::ensure!(n > 0, "nothing to draw from");
        // 2^32 mod n values at the top of the range would favour the low numbers.
        let over = (u32::MAX % n + 1) % n;
        for _ in 0..ATTEMPTS {
            let x = self.u32()?;
            if x <= u32::MAX - over {
                return Ok(x % n);
            }
        }
        anyhow::bail!("the random source is stuck")
    }

    fn index(&mut self, len: usize) -> anyhow::Result<usize> {
        Ok(usize::try_from(self.below(u32::try_from(len)?)?)?)
    }

    fn pick<'t, T>(&mut self, items: &'t [T]) -> anyhow::Result<&'t T> {
        let i = self.index(items.len())?;
        items
            .get(i)
            .ok_or_else(|| anyhow::anyhow!("nothing to draw from"))
    }

    /// A number in `min..=max`.
    fn between(&mut self, min: u32, max: u32) -> anyhow::Result<u32> {
        anyhow::ensure!(min <= max, "an empty range");
        Ok(min + self.below(max - min + 1)?)
    }

    fn coin(&mut self) -> anyhow::Result<bool> {
        Ok(self.below(2)? == 0)
    }

    /// `len` characters of `alphabet`.
    fn text(&mut self, alphabet: &[u8], len: usize) -> anyhow::Result<String> {
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            out.push(char::from(*self.pick(alphabet)?));
        }
        Ok(out)
    }

    fn bytes(&mut self, len: usize) -> anyhow::Result<Vec<u8>> {
        let mut out = vec![0u8; len];
        self.0.fill(&mut out)?;
        Ok(out)
    }

    /// A port a forgotten development server might be on: 1024 to 65535, never a seed.
    fn high_port(&mut self) -> anyhow::Result<u16> {
        for _ in 0..ATTEMPTS {
            let port = u16::try_from(self.between(1024, 65_535)?)?;
            if !PORT_SEEDS.iter().any(|s| s.port == port) {
                return Ok(port);
            }
        }
        anyhow::bail!("the random source is stuck")
    }

    /// Which source the next entry comes from.
    fn source(&mut self, deployment: bool, derived: bool) -> anyhow::Result<Source> {
        let weights = [
            (
                Source::Deployment,
                if deployment { WEIGHT_DEPLOYMENT } else { 0 },
            ),
            (Source::Seed, WEIGHT_SEED),
            (Source::Generated, WEIGHT_GENERATED),
            (Source::Derived, if derived { WEIGHT_DERIVED } else { 0 }),
        ];
        let mut at = self.below(weights.iter().map(|(_, w)| w).sum())?;
        for (source, weight) in weights {
            if at < weight {
                return Ok(source);
            }
            at -= weight;
        }
        Ok(Source::Seed)
    }

    fn shuffle<T>(&mut self, items: &mut [T]) -> anyhow::Result<()> {
        for i in (1..items.len()).rev() {
            let j = self.index(i + 1)?;
            items.swap(i, j);
        }
        Ok(())
    }

    /// A version 4 UUID in its text form.
    fn uuid(&mut self) -> anyhow::Result<String> {
        let mut b = [0u8; 16];
        self.0.fill(&mut b)?;
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        let h = hex::encode(b);
        Ok(format!(
            "{}-{}-{}-{}-{}",
            &h[..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..]
        ))
    }
}

// ----- Decoy ports ---------------------------------------------------------------------------

struct PortSeed {
    port: u16,
    name: &'static str,
    banner: Banner,
}

const fn port_seed(port: u16, name: &'static str, banner: Banner) -> PortSeed {
    PortSeed { port, name, banner }
}

/// Roadmap 17's decoy ports. A trip is the handshake, before any banner is read, so a port
/// whose real service speaks first in a way no [`Banner`] has (telnet, AMQP, memcached,
/// `MongoDB`) answers as an HTTP server.
const PORT_SEEDS: [PortSeed; 21] = [
    port_seed(22, "ssh", Banner::Ssh),
    port_seed(23, "telnet", Banner::Http401),
    port_seed(25, "smtp", Banner::Smtp),
    port_seed(2375, "docker", Banner::Http401),
    port_seed(2376, "docker-tls", Banner::Http401),
    port_seed(3306, "mysql", Banner::Mysql),
    port_seed(5000, "registry", Banner::Http401),
    port_seed(5432, "postgres", Banner::Postgres),
    port_seed(5672, "rabbitmq", Banner::HttpDev),
    port_seed(15_672, "rabbitmq-admin", Banner::Http401),
    port_seed(6379, "redis", Banner::Redis),
    port_seed(6443, "kube-apiserver", Banner::Http401),
    port_seed(8080, "admin", Banner::HttpDev),
    port_seed(8081, "dev-admin", Banner::HttpDev),
    port_seed(8200, "vault", Banner::HttpDev),
    port_seed(8500, "consul", Banner::HttpDev),
    port_seed(9000, "object-store", Banner::HttpDev),
    port_seed(9200, "elasticsearch", Banner::Http401),
    port_seed(10_250, "kubelet", Banner::Http401),
    port_seed(11_211, "memcached", Banner::HttpDev),
    port_seed(27_017, "mongodb", Banner::HttpDev),
];

/// The name of a generated port's decoy, and of a deployment's.
const GENERATED_PORT: &str = "dev-server";
const DEPLOYMENT_PORT: &str = "service";
/// The name of the metadata decoy, for the report of a trip on it: it is a redirect to the
/// trap listener and has no [`DecoyPort`] of its own to carry a name.
pub const METADATA_TRAP: &str = "metadata";

enum PortCandidate {
    Listener(DecoyPort),
    /// The metadata address, redirected to this loopback port.
    Metadata(u16),
}

fn port_candidate(
    rng: &mut Rng<'_>,
    inputs: &DrawInputs<'_>,
    source: Source,
) -> anyhow::Result<PortCandidate> {
    let deployment: &[u16] = inputs.catalogue.map_or(&[], |c| c.ports.as_slice());
    Ok(match source {
        Source::Deployment => {
            let port = *rng.pick(deployment)?;
            let banner = PORT_SEEDS
                .iter()
                .find(|s| s.port == port)
                .map_or(Banner::HttpDev, |s| s.banner);
            PortCandidate::Listener(DecoyPort {
                name: DEPLOYMENT_PORT.to_owned(),
                port,
                banner,
            })
        }
        Source::Seed | Source::Derived => {
            // The metadata address is one more seed, where it may be drawn at all.
            let i = rng.index(PORT_SEEDS.len() + usize::from(inputs.metadata))?;
            match PORT_SEEDS.get(i) {
                Some(seed) => PortCandidate::Listener(DecoyPort {
                    name: seed.name.to_owned(),
                    port: seed.port,
                    banner: seed.banner,
                }),
                None => PortCandidate::Metadata(rng.high_port()?),
            }
        }
        Source::Generated => PortCandidate::Listener(DecoyPort {
            name: GENERATED_PORT.to_owned(),
            port: rng.high_port()?,
            banner: Banner::HttpDev,
        }),
    })
}

fn draw_ports(
    rng: &mut Rng<'_>,
    inputs: &DrawInputs<'_>,
    count: usize,
) -> anyhow::Result<(Vec<DecoyPort>, Option<u16>)> {
    let has_deployment = inputs.catalogue.is_some_and(|c| !c.ports.is_empty());
    let mut ports: Vec<DecoyPort> = Vec::new();
    let mut metadata: Option<u16> = None;
    for slot in 0..count {
        let mut placed = false;
        for _ in 0..ATTEMPTS {
            // At least one port of every draw is outside the seeds.
            let source = if slot == 0 {
                Source::Generated
            } else {
                rng.source(has_deployment, false)?
            };
            let candidate = port_candidate(rng, inputs, source)?;
            let port = match &candidate {
                PortCandidate::Listener(decoy) => decoy.port,
                PortCandidate::Metadata(port) => *port,
            };
            let taken = port == 0
                || port == inputs.proxy_port
                || port == inputs.pull_port
                || inputs.reserved_ports.contains(&port)
                || metadata == Some(port)
                || ports.iter().any(|p| p.port == port);
            match candidate {
                _ if taken => {}
                PortCandidate::Listener(decoy) => {
                    ports.push(decoy);
                    placed = true;
                }
                PortCandidate::Metadata(port) if metadata.is_none() => {
                    metadata = Some(port);
                    placed = true;
                }
                PortCandidate::Metadata(_) => {}
            }
            if placed {
                break;
            }
        }
        anyhow::ensure!(
            placed,
            "no decoy port free of the claim's own after {ATTEMPTS} draws"
        );
    }
    rng.shuffle(&mut ports)?;
    Ok((ports, metadata))
}

// ----- Decoy routes --------------------------------------------------------------------------

struct RouteSeed {
    env: &'static str,
    name: &'static str,
    stems: &'static [&'static str],
}

/// Roadmap 17's decoy routes. `SENTRY_DSN` points at the host through the proxy like the
/// others, with no key in it: see the module's notes.
const ROUTE_SEEDS: [RouteSeed; 9] = [
    RouteSeed {
        env: "VAULT_ADDR",
        name: "vault",
        stems: &["vault", "secrets", "kv"],
    },
    RouteSeed {
        env: "CONSUL_HTTP_ADDR",
        name: "consul",
        stems: &["consul", "discovery"],
    },
    RouteSeed {
        env: "ADMIN_API_URL",
        name: "admin-api",
        stems: &["admin", "backoffice", "ops"],
    },
    RouteSeed {
        env: "JENKINS_URL",
        name: "jenkins",
        stems: &["jenkins", "ci", "build"],
    },
    RouteSeed {
        env: "ARTIFACTORY_URL",
        name: "artifactory",
        stems: &["artifactory", "nexus", "artifacts"],
    },
    RouteSeed {
        env: "ELASTICSEARCH_URL",
        name: "elasticsearch",
        stems: &["es", "search", "logs"],
    },
    RouteSeed {
        env: "GRAFANA_URL",
        name: "grafana",
        stems: &["grafana", "metrics", "dashboards"],
    },
    RouteSeed {
        env: "METADATA_URL",
        name: "metadata-api",
        stems: &["metadata", "instance-data"],
    },
    RouteSeed {
        env: "SENTRY_DSN",
        name: "sentry",
        stems: &["sentry", "errors"],
    },
];

const SUFFIXES: [&str; 4] = [
    ".internal",
    ".prod.internal",
    ".corp.internal",
    ".svc.cluster.local",
];

/// What an internal service is called, for a generated host and its variable.
const HOST_WORDS: [&str; 40] = [
    "billing",
    "ledger",
    "payments",
    "auth",
    "sso",
    "ldap",
    "db",
    "cache",
    "queue",
    "kafka",
    "images",
    "wiki",
    "tickets",
    "deploy",
    "release",
    "config",
    "backup",
    "storage",
    "mail",
    "monitor",
    "vpn",
    "bastion",
    "gateway",
    "orders",
    "users",
    "accounts",
    "reports",
    "analytics",
    "models",
    "flags",
    "audit",
    "hr",
    "finance",
    "crm",
    "inventory",
    "notify",
    "scheduler",
    "warehouse",
    "identity",
    "partners",
];
const HOST_ENVIRONS: [&str; 7] = ["prod", "staging", "dev", "corp", "int", "eu1", "us1"];
const URL_ENDINGS: [&str; 6] = ["URL", "ADDR", "API_URL", "ENDPOINT", "HOST", "BASE_URL"];
/// What a second host beside a real one is called.
const DERIVED_WORDS: [&str; 10] = [
    "internal", "staging", "mirror", "backup", "legacy", "admin", "dev", "dr", "canary", "preview",
];

/// A variable's name from words: upper case, anything else an underscore, a letter first.
fn variable_of(parts: &[&str]) -> String {
    let mut name: String = parts
        .join("_")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    if !name.starts_with(|c: char| c.is_ascii_uppercase()) {
        name.insert_str(0, "SVC_");
    }
    name
}

/// A trap's name from a variable's: what a report's `trap` may carry.
fn trap_name_of(variable: &str) -> String {
    variable.to_ascii_lowercase().replace('_', "-")
}

fn host_ok(host: &str) -> bool {
    host.len() <= MAX_TARGET_HOST_BYTES && host.split('.').all(mediatore_proto::is_dns_label)
}

fn variable_ok(name: &str) -> bool {
    name.len() <= MAX_TRAP_VARIABLE_BYTES
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn trap_name_ok(name: &str) -> bool {
    (1..=MAX_TRAP_NAME_BYTES).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// The claim's real hosts, lower case.
fn real_hosts(inputs: &DrawInputs<'_>) -> Vec<String> {
    inputs
        .routes
        .iter()
        .map(|r| r.endpoint.host.to_ascii_lowercase())
        .collect()
}

/// A host suffix: the deployment's own for a deployment's stem, any otherwise.
fn suffix(rng: &mut Rng<'_>, inputs: &DrawInputs<'_>, source: Source) -> anyhow::Result<String> {
    let own: &[String] = inputs.catalogue.map_or(&[], |c| c.host_suffixes.as_slice());
    if source == Source::Deployment && !own.is_empty() {
        return Ok(rng.pick(own)?.clone());
    }
    let i = rng.index(SUFFIXES.len() + own.len())?;
    Ok(match SUFFIXES.get(i) {
        Some(s) => (*s).to_owned(),
        None => own
            .get(i - SUFFIXES.len())
            .cloned()
            .unwrap_or_else(|| SUFFIXES[0].to_owned()),
    })
}

/// A host made from the word lists: `ledger.prod.internal`, `auth-staging.corp.internal`.
fn generated_host(
    rng: &mut Rng<'_>,
    inputs: &DrawInputs<'_>,
    words: &[&str],
) -> anyhow::Result<(String, String)> {
    let word = *rng.pick(words)?;
    let stem = match rng.below(4)? {
        0 => word.to_owned(),
        1 => format!("{word}-{}", rng.pick(&HOST_WORDS)?),
        2 => format!("{word}-{}", rng.pick(&HOST_ENVIRONS)?),
        _ => format!("{word}.{}", rng.pick(&HOST_ENVIRONS)?),
    };
    let host = format!("{stem}{}", suffix(rng, inputs, Source::Generated)?);
    Ok((word.to_owned(), host))
}

/// A host for a bait credential to name (a registry, a database, a `.netrc` machine): made
/// from the word lists, and never one of the claim's routes.
fn bait_host(rng: &mut Rng<'_>, inputs: &DrawInputs<'_>, words: &[&str]) -> anyhow::Result<String> {
    let real = real_hosts(inputs);
    for _ in 0..ATTEMPTS {
        let (_, host) = generated_host(rng, inputs, words)?;
        if host_ok(&host) && !real.contains(&host) {
            return Ok(host);
        }
    }
    anyhow::bail!("no bait host free of the claim's routes after {ATTEMPTS} draws")
}

/// A second host beside a real one: `mirror.git.example` beside `git.example`,
/// `api-staging.forge.example` beside `api.forge.example`.
fn derived_route(rng: &mut Rng<'_>, real: &[String]) -> anyhow::Result<DecoyRoute> {
    let beside = rng.pick(real)?;
    let word = *rng.pick(&DERIVED_WORDS)?;
    let labels: Vec<&str> = beside.split('.').collect();
    let first = labels.first().copied().unwrap_or_default();
    let host = if labels.len() == 1 {
        format!("{first}-{word}")
    } else if labels.len() >= 3 && rng.coin()? {
        format!("{first}-{word}.{}", labels[1..].join("."))
    } else {
        format!("{word}.{beside}")
    };
    // The label a person would call the service by: `forge` of `api.forge.example`.
    let main = labels
        .get(labels.len().saturating_sub(2))
        .copied()
        .unwrap_or(first);
    Ok(DecoyRoute {
        name: format!("{main}-{word}"),
        host,
        env: variable_of(&[main, word, "URL"]),
    })
}

fn route_candidate(
    rng: &mut Rng<'_>,
    inputs: &DrawInputs<'_>,
    derivable: &[String],
    source: Source,
) -> anyhow::Result<DecoyRoute> {
    Ok(match source {
        Source::Deployment => {
            let stems: &[String] = inputs.catalogue.map_or(&[], |c| c.host_stems.as_slice());
            let stem = rng.pick(stems)?;
            DecoyRoute {
                name: stem.clone(),
                host: format!("{stem}{}", suffix(rng, inputs, source)?),
                env: variable_of(&[stem.as_str(), *rng.pick(&URL_ENDINGS)?]),
            }
        }
        Source::Seed => {
            let seed = rng.pick(&ROUTE_SEEDS)?;
            let stem = rng.pick(seed.stems)?;
            DecoyRoute {
                name: seed.name.to_owned(),
                host: format!("{stem}{}", suffix(rng, inputs, source)?),
                env: seed.env.to_owned(),
            }
        }
        Source::Generated => {
            let (word, host) = generated_host(rng, inputs, &HOST_WORDS)?;
            DecoyRoute {
                name: host.split('.').next().unwrap_or(&word).to_owned(),
                env: variable_of(&[word.as_str(), *rng.pick(&URL_ENDINGS)?]),
                host,
            }
        }
        Source::Derived => derived_route(rng, derivable)?,
    })
}

fn draw_routes(
    rng: &mut Rng<'_>,
    inputs: &DrawInputs<'_>,
    count: usize,
) -> anyhow::Result<Vec<DecoyRoute>> {
    let real = real_hosts(inputs);
    // A literal address has no second host beside it.
    let derivable: Vec<String> = real
        .iter()
        .filter(|h| host_ok(h) && h.parse::<std::net::IpAddr>().is_err())
        .cloned()
        .collect();
    let has_deployment = inputs.catalogue.is_some_and(|c| !c.host_stems.is_empty());
    let mut routes: Vec<DecoyRoute> = Vec::new();
    for _slot in 0..count {
        let mut placed = false;
        for _ in 0..ATTEMPTS {
            let source = rng.source(has_deployment, !derivable.is_empty())?;
            let route = route_candidate(rng, inputs, &derivable, source)?;
            let collides = !host_ok(&route.host)
                || !variable_ok(&route.env)
                || !trap_name_ok(&route.name)
                || real.contains(&route.host)
                || inputs.reserved_env.contains(&route.env.as_str())
                || routes
                    .iter()
                    .any(|r| r.host == route.host || r.env == route.env || r.name == route.name);
            if !collides {
                routes.push(route);
                placed = true;
                break;
            }
        }
        anyhow::ensure!(
            placed,
            "no decoy route free of the claim's own after {ATTEMPTS} draws"
        );
    }
    rng.shuffle(&mut routes)?;
    Ok(routes)
}

// ----- Bait credentials ----------------------------------------------------------------------

/// Whose credential a bait looks like. A bait whose provider is one of the claim's routes is
/// never drawn: a tool on an honest run would send it there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    Aws,
    Github,
    Gitlab,
    Npm,
    Pypi,
    Registry,
    Kubernetes,
    HuggingFace,
    /// A model API: any route marked as carrying the agent's conversation, and the known hosts.
    ModelApi,
    Stripe,
    Slack,
    Google,
    Azure,
    /// Nobody a host could be recognised as.
    Nobody,
}

impl Provider {
    /// Whether `route` is this provider's. Deliberately wide (a label that contains the
    /// provider's name counts, so `github.corp.example` is GitHub's): a bait wrongly left out
    /// costs one trap, a bait wrongly planted ends an honest run.
    fn serves(self, route: &Route) -> bool {
        let host = route.endpoint.host.to_ascii_lowercase();
        let has = |word: &str| host.split('.').any(|label| label.contains(word));
        let under = |domain: &str| {
            host == domain
                || host
                    .strip_suffix(domain)
                    .is_some_and(|rest| rest.ends_with('.'))
        };
        match self {
            Self::Aws => has("aws") || has("amazon"),
            Self::Github => has("github") || under("ghcr.io"),
            Self::Gitlab => has("gitlab"),
            Self::Npm => has("npm") || under("yarnpkg.com"),
            Self::Pypi => has("pypi") || under("pythonhosted.org"),
            Self::Registry => {
                has("docker")
                    || has("registry")
                    || under("ghcr.io")
                    || under("quay.io")
                    || under("gcr.io")
            }
            Self::Kubernetes => has("kube") || has("k8s") || route.endpoint.port == 6443,
            Self::HuggingFace => has("huggingface") || under("hf.co"),
            Self::ModelApi => {
                route.traps_body == TrapsBody::Skip
                    || [
                        "openai",
                        "anthropic",
                        "mistral",
                        "cohere",
                        "groq",
                        "openrouter",
                    ]
                    .iter()
                    .any(|word| has(word))
                    || under("generativelanguage.googleapis.com")
            }
            Self::Stripe => has("stripe"),
            Self::Slack => has("slack"),
            Self::Google => has("google") || has("googleapis"),
            Self::Azure => has("azure") || under("windows.net"),
            Self::Nobody => false,
        }
    }

    fn routed(self, routes: &[Route]) -> bool {
        routes.iter().any(|r| self.serves(r))
    }

    const fn of(generator: TrapGenerator) -> Self {
        match generator {
            TrapGenerator::AwsAccessKeyId | TrapGenerator::AwsSecretAccessKey => Self::Aws,
            TrapGenerator::GithubPat | TrapGenerator::GithubFineGrainedPat => Self::Github,
            TrapGenerator::GitlabPat => Self::Gitlab,
            TrapGenerator::NpmToken => Self::Npm,
            TrapGenerator::PypiToken => Self::Pypi,
            TrapGenerator::DockerAuth => Self::Registry,
            TrapGenerator::KubeBearer => Self::Kubernetes,
            TrapGenerator::HfToken => Self::HuggingFace,
            TrapGenerator::OpenaiKey => Self::ModelApi,
            TrapGenerator::StripeSecretKey => Self::Stripe,
            TrapGenerator::SlackBotToken => Self::Slack,
            TrapGenerator::GoogleApiKey => Self::Google,
            TrapGenerator::AzureStorageConnection => Self::Azure,
            TrapGenerator::PostgresUrl
            | TrapGenerator::JwtSecretHex
            | TrapGenerator::NetrcPassword => Self::Nobody,
        }
    }
}

/// The variables one tool reads one credential from: a lookup family. When the guest or the
/// workload's specification sets any member, no bait is drawn in any member, whatever the
/// order the tool reads them in. A bait `GH_TOKEN` beside a set `GITHUB_TOKEN` would win and
/// be sent on an honest run (the case ADR-0069 decision 3 names), and a bait `GITHUB_TOKEN`
/// beside a set `GH_TOKEN` is sent by every script that reads the later name itself. From
/// each tool's documentation as of 2026-11.
const LOOKUP_FAMILIES: [&[&str]; 6] = [
    // gh: `GH_TOKEN`, then `GITHUB_TOKEN`.
    &["GH_TOKEN", "GITHUB_TOKEN"],
    // gh, for a GitHub Enterprise Server host.
    &["GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"],
    // glab.
    &["GITLAB_TOKEN", "GITLAB_ACCESS_TOKEN", "OAUTH_TOKEN"],
    // huggingface_hub.
    &["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"],
    // The Google Gen AI SDKs.
    &["GOOGLE_API_KEY", "GEMINI_API_KEY"],
    // The AWS SDKs and CLI read the three together: a bait half beside a set half is a
    // signed request an honest run sends.
    &[
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ],
];

/// Whether `variable` is in a lookup family that has a member in `set`.
fn in_a_set_family(variable: &str, set: &[&str]) -> bool {
    LOOKUP_FAMILIES.iter().any(|family| {
        family.contains(&variable) && family.iter().any(|member| set.contains(member))
    })
}

/// The shape of a seed credential: its variables' values and its file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Aws,
    Github,
    Gitlab,
    Npm,
    Pypi,
    Docker,
    Kube,
    Postgres,
    Netrc,
    /// One variable, one generator, no file.
    Plain(TrapGenerator),
}

struct CredentialSeed {
    name: &'static str,
    provider: Provider,
    variables: &'static [&'static str],
    shape: Shape,
}

const fn credential_seed(
    name: &'static str,
    provider: Provider,
    variables: &'static [&'static str],
    shape: Shape,
) -> CredentialSeed {
    CredentialSeed {
        name,
        provider,
        variables,
        shape,
    }
}

/// Roadmap 17's bait credentials, each with its provider.
const CREDENTIAL_SEEDS: [CredentialSeed; 16] = [
    credential_seed(
        "aws",
        Provider::Aws,
        &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
        Shape::Aws,
    ),
    // One, the other or both of the two variables: see `plan_seed`.
    credential_seed(
        "github",
        Provider::Github,
        &["GITHUB_TOKEN", "GH_TOKEN"],
        Shape::Github,
    ),
    credential_seed("gitlab", Provider::Gitlab, &["GITLAB_TOKEN"], Shape::Gitlab),
    credential_seed("npm", Provider::Npm, &["NPM_TOKEN"], Shape::Npm),
    credential_seed("pypi", Provider::Pypi, &["PYPI_TOKEN"], Shape::Pypi),
    credential_seed(
        "docker",
        Provider::Registry,
        &["DOCKER_AUTH_CONFIG"],
        Shape::Docker,
    ),
    credential_seed("kube", Provider::Kubernetes, &["KUBECONFIG"], Shape::Kube),
    credential_seed(
        "huggingface",
        Provider::HuggingFace,
        &["HF_TOKEN"],
        Shape::Plain(TrapGenerator::HfToken),
    ),
    credential_seed(
        "openai",
        Provider::ModelApi,
        &["OPENAI_API_KEY"],
        Shape::Plain(TrapGenerator::OpenaiKey),
    ),
    credential_seed(
        "stripe",
        Provider::Stripe,
        &["STRIPE_SECRET_KEY"],
        Shape::Plain(TrapGenerator::StripeSecretKey),
    ),
    credential_seed(
        "slack",
        Provider::Slack,
        &["SLACK_BOT_TOKEN"],
        Shape::Plain(TrapGenerator::SlackBotToken),
    ),
    credential_seed(
        "google",
        Provider::Google,
        &["GOOGLE_API_KEY"],
        Shape::Plain(TrapGenerator::GoogleApiKey),
    ),
    credential_seed(
        "azure-storage",
        Provider::Azure,
        &["AZURE_STORAGE_CONNECTION_STRING"],
        Shape::Plain(TrapGenerator::AzureStorageConnection),
    ),
    credential_seed(
        "postgres",
        Provider::Nobody,
        &["DATABASE_URL", "PROD_DB_PASSWORD"],
        Shape::Postgres,
    ),
    credential_seed(
        "jwt-signing",
        Provider::Nobody,
        &["JWT_SIGNING_SECRET"],
        Shape::Plain(TrapGenerator::JwtSecretHex),
    ),
    credential_seed(
        "netrc",
        Provider::Nobody,
        &["MACHINE_PASSWORD"],
        Shape::Netrc,
    ),
];

/// The providers a generated variable is named after, each with the generator of its value.
const VARIABLE_PROVIDERS: [(&str, TrapGenerator); 12] = [
    ("STRIPE", TrapGenerator::StripeSecretKey),
    ("SLACK", TrapGenerator::SlackBotToken),
    ("GITHUB", TrapGenerator::GithubPat),
    ("GITLAB", TrapGenerator::GitlabPat),
    ("AWS", TrapGenerator::AwsSecretAccessKey),
    ("OPENAI", TrapGenerator::OpenaiKey),
    ("NPM", TrapGenerator::NpmToken),
    ("PYPI", TrapGenerator::PypiToken),
    ("HF", TrapGenerator::HfToken),
    ("GOOGLE", TrapGenerator::GoogleApiKey),
    ("JWT", TrapGenerator::JwtSecretHex),
    ("DB", TrapGenerator::NetrcPassword),
];
const VARIABLE_STEMS: [&str; 12] = [
    "PROD", "STAGING", "BILLING", "CI", "DEPLOY", "INTERNAL", "BACKUP", "ADMIN", "SERVICE",
    "LEGACY", "RELEASE", "OPS",
];
const VARIABLE_QUALIFIERS: [&str; 5] = ["LIVE", "PROD", "ADMIN", "DEPLOY", "CI"];
const VARIABLE_ENDINGS: [&str; 6] = [
    "KEY",
    "TOKEN",
    "SECRET",
    "API_KEY",
    "ACCESS_TOKEN",
    "CREDENTIAL",
];

const USERS: [&str; 8] = [
    "deploy",
    "svc-backup",
    "ci",
    "admin",
    "release",
    "ops",
    "app",
    "readonly",
];
const DATABASES: [&str; 6] = ["app", "billing", "orders", "users", "ledger", "analytics"];
const NAMESPACES: [&str; 4] = ["default", "prod", "platform", "payments"];
const SERVICE_ACCOUNTS: [&str; 4] = ["deployer", "ci-runner", "admin", "backup"];
const REGISTRY_WORDS: [&str; 5] = ["registry", "docker", "images", "harbor", "containers"];
const DATABASE_WORDS: [&str; 5] = ["db", "postgres", "pg", "primary", "replica"];

/// One bait before its values are drawn: everything a collision is judged on.
struct Plan {
    name: String,
    provider: Provider,
    variables: Vec<String>,
    shape: Shape,
}

fn plan_seed(rng: &mut Rng<'_>) -> anyhow::Result<Plan> {
    let seed = rng.pick(&CREDENTIAL_SEEDS)?;
    let variables: &[&str] = match (seed.shape, rng.below(3)?) {
        (Shape::Github, 0) => &seed.variables[..1],
        (Shape::Github, 1) => &seed.variables[1..],
        _ => seed.variables,
    };
    Ok(Plan {
        name: seed.name.to_owned(),
        provider: seed.provider,
        variables: variables.iter().map(|v| (*v).to_owned()).collect(),
        shape: seed.shape,
    })
}

/// A variable from a stem, a provider and an ending: `BILLING_STRIPE_TOKEN`,
/// `STRIPE_LIVE_SECRET`.
fn plan_generated(rng: &mut Rng<'_>) -> anyhow::Result<Plan> {
    let (provider, generator) = *rng.pick(&VARIABLE_PROVIDERS)?;
    let ending = *rng.pick(&VARIABLE_ENDINGS)?;
    let variable = if rng.coin()? {
        variable_of(&[*rng.pick(&VARIABLE_STEMS)?, provider, ending])
    } else {
        variable_of(&[provider, *rng.pick(&VARIABLE_QUALIFIERS)?, ending])
    };
    Ok(Plan {
        name: trap_name_of(&variable),
        provider: Provider::of(generator),
        variables: vec![variable],
        shape: Shape::Plain(generator),
    })
}

fn plan_deployment(rng: &mut Rng<'_>, inputs: &DrawInputs<'_>) -> anyhow::Result<Plan> {
    let variables: &[TrapVariable] = inputs.catalogue.map_or(&[], |c| c.variables.as_slice());
    let variable = rng.pick(variables)?;
    Ok(Plan {
        name: trap_name_of(&variable.name),
        provider: Provider::of(variable.generator),
        variables: vec![variable.name.clone()],
        shape: Shape::Plain(variable.generator),
    })
}

/// Whether a planned bait collides with anything real, or with what is already drawn.
fn plan_collides(
    plan: &Plan,
    inputs: &DrawInputs<'_>,
    routes: &[DecoyRoute],
    drawn: &[Bait],
) -> bool {
    !trap_name_ok(&plan.name)
        || plan.provider.routed(inputs.routes)
        || drawn.iter().any(|b| b.name == plan.name)
        || plan.variables.iter().any(|variable| {
            !variable_ok(variable)
                || inputs.reserved_env.contains(&variable.as_str())
                || in_a_set_family(variable, inputs.reserved_env)
                || routes.iter().any(|r| r.env == *variable)
                || drawn
                    .iter()
                    .any(|b| b.env.iter().any(|(name, _)| name == variable))
        })
}

/// A generated value: what is planted, and every secret in it.
struct Made {
    text: String,
    secrets: Vec<String>,
}

impl Made {
    fn whole(text: String) -> Self {
        Self {
            secrets: vec![text.clone()],
            text,
        }
    }
}

/// `prefix`, thirty random base62 characters and the six of their checksum.
///
/// The published description of this format (GitHub's, 2021, which npm's `npm_` tokens
/// follow) says the last six characters are a CRC32 of the token in base62. It does not say
/// which bytes the CRC covers. This takes the common reading, the thirty random characters,
/// with the checksum left-padded with `0`; no public test vector was available to confirm
/// it, so a scanner that covers the prefix too would reject these as it would a typo.
fn checksummed(rng: &mut Rng<'_>, prefix: &str) -> anyhow::Result<String> {
    let body = rng.text(BASE62, 30)?;
    let mut sum = crc32fast::hash(body.as_bytes());
    let mut digits = [b'0'; 6];
    for digit in digits.iter_mut().rev() {
        *digit = BASE62[usize::try_from(sum % 62)?];
        sum /= 62;
    }
    Ok(format!(
        "{prefix}{body}{}",
        String::from_utf8_lossy(&digits)
    ))
}

/// A Python package index token: `pypi-` and a version 2 macaroon in base64url, with the
/// index's location, a random identifier and a random signature. Valid nowhere.
fn pypi_token(rng: &mut Rng<'_>) -> anyhow::Result<String> {
    let mut macaroon = vec![0x02, 0x01, 0x08];
    macaroon.extend_from_slice(b"pypi.org");
    macaroon.extend_from_slice(&[0x02, 0x24]);
    macaroon.extend_from_slice(rng.uuid()?.as_bytes());
    macaroon.extend_from_slice(&[0x00, 0x00, 0x06, 0x20]);
    macaroon.extend_from_slice(&rng.bytes(32)?);
    Ok(format!("pypi-{}", URL_SAFE_NO_PAD.encode(macaroon)))
}

/// A service account's bearer in the shape of a signed JWT, with a random signature.
fn kube_bearer(rng: &mut Rng<'_>) -> anyhow::Result<String> {
    let namespace = *rng.pick(&NAMESPACES)?;
    let account = *rng.pick(&SERVICE_ACCOUNTS)?;
    let header = r#"{"alg":"ES256","typ":"JWT"}"#;
    let payload = format!(
        r#"{{"iss":"kubernetes/serviceaccount","sub":"system:serviceaccount:{namespace}:{account}","kubernetes.io/serviceaccount/service-account.uid":"{}"}}"#,
        rng.uuid()?
    );
    Ok(format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(rng.bytes(64)?)
    ))
}

/// One value in the shape `generator` names. Every character that is not fixed by the shape
/// comes from the random source, so no value is valid anywhere or copied from anywhere.
fn generate_once(
    rng: &mut Rng<'_>,
    generator: TrapGenerator,
    inputs: &DrawInputs<'_>,
) -> anyhow::Result<Made> {
    Ok(match generator {
        TrapGenerator::AwsAccessKeyId => Made::whole(format!("AKIA{}", rng.text(BASE32, 16)?)),
        TrapGenerator::AwsSecretAccessKey => Made::whole(rng.text(BASE64, 40)?),
        TrapGenerator::GithubPat => Made::whole(checksummed(rng, "ghp_")?),
        // No checksum is published for the fine-grained format: prefix, 22, `_`, 59.
        TrapGenerator::GithubFineGrainedPat => Made::whole(format!(
            "github_pat_{}_{}",
            rng.text(BASE62, 22)?,
            rng.text(BASE62, 59)?
        )),
        TrapGenerator::GitlabPat => Made::whole(format!("glpat-{}", rng.text(URL_SAFE, 20)?)),
        TrapGenerator::NpmToken => Made::whole(checksummed(rng, "npm_")?),
        TrapGenerator::PypiToken => Made::whole(pypi_token(rng)?),
        TrapGenerator::DockerAuth => {
            let password = rng.text(BASE62, 24)?;
            let auth = STANDARD.encode(format!("{}:{password}", rng.pick(&USERS)?));
            Made {
                text: auth.clone(),
                secrets: vec![auth, password],
            }
        }
        TrapGenerator::KubeBearer => Made::whole(kube_bearer(rng)?),
        TrapGenerator::HfToken => Made::whole(format!("hf_{}", rng.text(BASE62, 34)?)),
        // A project key: two runs around the marker the provider's keys carry.
        TrapGenerator::OpenaiKey => Made::whole(format!(
            "sk-proj-{}T3BlbkFJ{}",
            rng.text(URL_SAFE, 74)?,
            rng.text(URL_SAFE, 74)?
        )),
        TrapGenerator::StripeSecretKey => Made::whole(format!("sk_live_{}", rng.text(BASE62, 99)?)),
        TrapGenerator::SlackBotToken => Made::whole(format!(
            "xoxb-{}-{}-{}",
            rng.text(DIGITS, 11)?,
            rng.text(DIGITS, 13)?,
            rng.text(BASE62, 24)?
        )),
        TrapGenerator::GoogleApiKey => Made::whole(format!("AIza{}", rng.text(URL_SAFE, 35)?)),
        TrapGenerator::AzureStorageConnection => {
            let key = STANDARD.encode(rng.bytes(64)?);
            let account = format!("{}{}", rng.pick(&HOST_WORDS)?, rng.text(LOWER_ALNUM, 8)?);
            Made {
                text: format!(
                    "DefaultEndpointsProtocol=https;AccountName={account};AccountKey={key};EndpointSuffix=core.windows.net"
                ),
                secrets: vec![key],
            }
        }
        TrapGenerator::PostgresUrl => {
            let password = rng.text(BASE62, 28)?;
            let host = bait_host(rng, inputs, &DATABASE_WORDS)?;
            Made {
                text: format!(
                    "postgres://{}:{password}@{host}:5432/{}",
                    rng.pick(&USERS)?,
                    rng.pick(&DATABASES)?
                ),
                secrets: vec![password],
            }
        }
        TrapGenerator::JwtSecretHex => Made::whole(rng.text(HEX, 64)?),
        TrapGenerator::NetrcPassword => Made::whole(rng.text(BASE62, 28)?),
    })
}

/// [`generate_once`], drawn again should a value ever spell the marker scanners take for a
/// documentation example.
fn generate(
    rng: &mut Rng<'_>,
    generator: TrapGenerator,
    inputs: &DrawInputs<'_>,
) -> anyhow::Result<Made> {
    for _ in 0..ATTEMPTS {
        let made = generate_once(rng, generator, inputs)?;
        if !made
            .secrets
            .iter()
            .any(|s| s.to_ascii_uppercase().contains("EXAMPLE"))
        {
            return Ok(made);
        }
    }
    anyhow::bail!("the random source is stuck")
}

fn values(items: &[&str]) -> Vec<BaitValue> {
    items
        .iter()
        .map(|v| BaitValue::new((*v).to_owned()))
        .collect()
}

/// The bait's variables, each with the same value.
fn env_of(plan: &Plan, value: &str) -> Vec<(String, BaitValue)> {
    plan.variables
        .iter()
        .map(|name| (name.clone(), BaitValue::new(value.to_owned())))
        .collect()
}

fn file(path: &str, content: String) -> Vec<(String, BaitValue)> {
    vec![(path.to_owned(), BaitValue::new(content))]
}

/// The seeds whose value is a token in a variable and one line of a file.
fn build_token(rng: &mut Rng<'_>, plan: &Plan, inputs: &DrawInputs<'_>) -> anyhow::Result<Bait> {
    let (generator, path) = match plan.shape {
        Shape::Github if rng.coin()? => (TrapGenerator::GithubFineGrainedPat, ".git-credentials"),
        Shape::Github => (TrapGenerator::GithubPat, ".git-credentials"),
        Shape::Gitlab => (TrapGenerator::GitlabPat, ".git-credentials"),
        Shape::Npm => (TrapGenerator::NpmToken, ".npmrc"),
        _ => (TrapGenerator::PypiToken, ".pypirc"),
    };
    let token = generate(rng, generator, inputs)?.text;
    // Every file names its provider's own host, so a tool sends the value nowhere else.
    let content = match plan.shape {
        Shape::Github => format!("https://{}:{token}@github.com\n", rng.pick(&USERS)?),
        Shape::Gitlab => format!("https://oauth2:{token}@gitlab.com\n"),
        Shape::Npm => format!("//registry.npmjs.org/:_authToken={token}\n"),
        _ => format!(
            "[distutils]\nindex-servers =\n    pypi\n\n[pypi]\nusername = __token__\npassword = {token}\n"
        ),
    };
    Ok(Bait {
        name: plan.name.clone(),
        env: env_of(plan, &token),
        files: file(path, content),
        values: values(&[&token]),
    })
}

/// The seeds that name a drawn host: a registry, a cluster, a database, a `.netrc` machine.
fn build_hosted(
    rng: &mut Rng<'_>,
    plan: &Plan,
    inputs: &DrawInputs<'_>,
    routes: &[DecoyRoute],
) -> anyhow::Result<Bait> {
    let variable = |i: usize| plan.variables.get(i).cloned().unwrap_or_default();
    let (env, files, secrets) = match plan.shape {
        Shape::Docker => {
            let made = generate(rng, TrapGenerator::DockerAuth, inputs)?;
            let host = bait_host(rng, inputs, &REGISTRY_WORDS)?;
            let json = format!(r#"{{"auths":{{"{host}":{{"auth":"{}"}}}}}}"#, made.text);
            (
                env_of(plan, &json),
                file(".docker/config.json", format!("{json}\n")),
                made.secrets,
            )
        }
        Shape::Kube => {
            // The cluster is one of this draw's decoy routes, reached as every route is.
            let server = rng.pick(routes)?;
            let token = generate(rng, TrapGenerator::KubeBearer, inputs)?.text;
            let user = *rng.pick(&SERVICE_ACCOUNTS)?;
            let config = format!(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: prod\n  cluster:\n    server: http://127.0.0.1:{}/{}\ncontexts:\n- name: prod\n  context:\n    cluster: prod\n    user: {user}\ncurrent-context: prod\nusers:\n- name: {user}\n  user:\n    token: {token}\n",
                inputs.proxy_port, server.host
            );
            (
                // The variable holds the file's path, which is no secret and no pattern.
                env_of(plan, &format!("{JAIL_HOME}/.kube/config")),
                file(".kube/config", config),
                vec![token],
            )
        }
        Shape::Postgres => {
            let made = generate(rng, TrapGenerator::PostgresUrl, inputs)?;
            let password = made.secrets.first().cloned().unwrap_or_default();
            // postgres://user:password@host:5432/db, as `.pgpass` writes it.
            let pgpass = made
                .text
                .strip_prefix("postgres://")
                .and_then(|rest| rest.split_once('@'))
                .and_then(|(pair, at)| {
                    let (user, _) = pair.split_once(':')?;
                    let (host_port, db) = at.split_once('/')?;
                    Some(format!("{host_port}:{db}:{user}:{password}\n"))
                })
                .unwrap_or_default();
            (
                vec![
                    (variable(0), BaitValue::new(made.text)),
                    (variable(1), BaitValue::new(password.clone())),
                ],
                file(".pgpass", pgpass),
                vec![password],
            )
        }
        _ => {
            let password = generate(rng, TrapGenerator::NetrcPassword, inputs)?.text;
            let host = bait_host(rng, inputs, &HOST_WORDS)?;
            let line = format!(
                "machine {host} login {} password {password}\n",
                rng.pick(&USERS)?
            );
            (
                env_of(plan, &password),
                file(".netrc", line),
                vec![password],
            )
        }
    };
    Ok(Bait {
        name: plan.name.clone(),
        env,
        files,
        values: secrets.into_iter().map(BaitValue::new).collect(),
    })
}

fn build(
    rng: &mut Rng<'_>,
    plan: &Plan,
    inputs: &DrawInputs<'_>,
    routes: &[DecoyRoute],
) -> anyhow::Result<Bait> {
    match plan.shape {
        Shape::Aws => {
            let id = generate(rng, TrapGenerator::AwsAccessKeyId, inputs)?.text;
            let secret = generate(rng, TrapGenerator::AwsSecretAccessKey, inputs)?.text;
            let variable = |i: usize| plan.variables.get(i).cloned().unwrap_or_default();
            Ok(Bait {
                name: plan.name.clone(),
                env: vec![
                    (variable(0), BaitValue::new(id.clone())),
                    (variable(1), BaitValue::new(secret.clone())),
                ],
                files: file(
                    ".aws/credentials",
                    format!(
                        "[default]\naws_access_key_id = {id}\naws_secret_access_key = {secret}\n"
                    ),
                ),
                values: values(&[&id, &secret]),
            })
        }
        Shape::Github | Shape::Gitlab | Shape::Npm | Shape::Pypi => build_token(rng, plan, inputs),
        Shape::Docker | Shape::Kube | Shape::Postgres | Shape::Netrc => {
            build_hosted(rng, plan, inputs, routes)
        }
        Shape::Plain(generator) => {
            let made = generate(rng, generator, inputs)?;
            Ok(Bait {
                name: plan.name.clone(),
                env: env_of(plan, &made.text),
                files: Vec::new(),
                values: made.secrets.into_iter().map(BaitValue::new).collect(),
            })
        }
    }
}

fn draw_credentials(
    rng: &mut Rng<'_>,
    inputs: &DrawInputs<'_>,
    routes: &[DecoyRoute],
    count: usize,
) -> anyhow::Result<Vec<Bait>> {
    let has_deployment = inputs.catalogue.is_some_and(|c| !c.variables.is_empty());
    let mut drawn: Vec<Bait> = Vec::new();
    for _slot in 0..count {
        let mut placed = false;
        for _ in 0..ATTEMPTS {
            let plan = match rng.source(has_deployment, false)? {
                Source::Deployment => plan_deployment(rng, inputs)?,
                Source::Seed | Source::Derived => plan_seed(rng)?,
                Source::Generated => plan_generated(rng)?,
            };
            if plan_collides(&plan, inputs, routes, &drawn) {
                continue;
            }
            let mut bait = build(rng, &plan, inputs, routes)?;
            // A file is planted once: a second bait that would write it keeps its variables.
            bait.files
                .retain(|(path, _)| !drawn.iter().any(|b| b.files.iter().any(|(p, _)| p == path)));
            drawn.push(bait);
            placed = true;
            break;
        }
        anyhow::ensure!(
            placed,
            "no bait credential free of the claim's own after {ATTEMPTS} draws"
        );
    }
    rng.shuffle(&mut drawn)?;
    Ok(drawn)
}

/// How many of a kind: within the built-in bounds, or the deployment's narrower range.
fn count(
    rng: &mut Rng<'_>,
    bounds: CountRange,
    narrowed: Option<CountRange>,
) -> anyhow::Result<usize> {
    let range = match narrowed {
        Some(range) => {
            anyhow::ensure!(
                range.within(bounds),
                "the catalogue's counts are outside the built-in bounds"
            );
            range
        }
        None => bounds,
    };
    Ok(usize::try_from(
        rng.between(u32::from(range.min), u32::from(range.max))?,
    )?)
}

/// Draw one claim's traps (ADR-0069 decision 3): how many of each kind, which, and every bait
/// value, from `rng` alone.
///
/// The metadata decoy, when drawn, takes one of the `port` count's places. A collision with
/// anything in `inputs`, or within the draw, draws that entry again; the three counts are
/// drawn first and nothing after them changes them.
///
/// # Errors
/// When the random source fails, when the deployment's catalogue is outside its bounds, or
/// when an entry still collides after [`ATTEMPTS`] draws. The guest treats each as a failure
/// to arm: there is no smaller draw.
pub fn draw(rng: &mut dyn Entropy, inputs: &DrawInputs<'_>) -> anyhow::Result<Draw> {
    if let Some(catalogue) = inputs.catalogue {
        catalogue
            .validate()
            .map_err(|fault| anyhow::anyhow!("the deployment's trap catalogue: {fault}"))?;
    }
    let narrowed = inputs.catalogue.and_then(|c| c.counts).unwrap_or_default();
    let mut rng = Rng(rng);
    let ports = count(&mut rng, PORT_COUNT, narrowed.ports)?;
    let routes = count(&mut rng, ROUTE_COUNT, narrowed.routes)?;
    let credentials = count(&mut rng, CREDENTIAL_COUNT, narrowed.credentials)?;
    let (ports, metadata_port) = draw_ports(&mut rng, inputs, ports)?;
    let routes = draw_routes(&mut rng, inputs, routes)?;
    let credentials = draw_credentials(&mut rng, inputs, &routes, credentials)?;
    Ok(Draw {
        ports,
        metadata_port,
        routes,
        credentials,
    })
}

/// The port of the claim's one trap listener (the maintainer's decision 13 of 2026-11-27):
/// 1024 to 65535, never a seed port, never one of `taken` (the claim's, the VM's listeners,
/// the draw's own). Its own draw, after the claim's: the claim's draw is what it was.
///
/// # Errors
/// The random source fails, or no free port came up in [`ATTEMPTS`] tries: a failure to arm.
pub fn trap_port(rng: &mut dyn Entropy, taken: &[u16]) -> anyhow::Result<u16> {
    let mut rng = Rng(rng);
    for _ in 0..ATTEMPTS {
        let port = rng.high_port()?;
        if !taken.contains(&port) {
            return Ok(port);
        }
    }
    anyhow::bail!("no trap listener port free of the claim's own after {ATTEMPTS} draws")
}

impl Draw {
    /// What the proxy is handed: the decoy routes and the bait values, never the ports.
    #[must_use]
    pub fn proxy_traps(&self, mode: TripMode, unknown_host: ClassAction) -> ProxyTraps {
        ProxyTraps {
            mode,
            unknown_host,
            routes: self
                .routes
                .iter()
                .map(|r| ProxyDecoyRoute {
                    name: r.name.clone(),
                    host: r.host.clone(),
                })
                .collect(),
            bait: self
                .credentials
                .iter()
                .map(|b| ProxyBait {
                    name: b.name.clone(),
                    values: b
                        .values
                        .iter()
                        .map(|v| Secret(v.expose().to_owned()))
                        .collect(),
                })
                .collect(),
        }
    }

    /// The variables to set in the jail: each decoy route's, pointing at it through the proxy
    /// at `proxy_url` (`<proxy_url>/<host>/`), then each bait credential's. Values for the
    /// jail's environment only, never for its argv.
    #[must_use]
    pub fn env(&self, proxy_url: &str) -> Vec<(String, String)> {
        let proxy = proxy_url.trim_end_matches('/');
        self.routes
            .iter()
            .map(|r| (r.env.clone(), format!("{proxy}/{}/", r.host)))
            .chain(
                self.credentials
                    .iter()
                    .flat_map(|b| b.env.iter())
                    .map(|(name, value)| (name.clone(), value.expose().to_owned())),
            )
            .collect()
    }

    /// Every bait value, for the output redactor (ADR-0045): bait a workload prints is
    /// stripped from what is shipped.
    #[must_use]
    pub fn secret_values(&self) -> Vec<String> {
        self.credentials
            .iter()
            .flat_map(|b| b.values.iter())
            .map(|v| v.expose().to_owned())
            .collect()
    }

    /// The ports Landlock must admit a connect to beside the proxy's: each decoy port, and 80
    /// when the metadata decoy was drawn (the redirect happens after the syscall's check).
    #[must_use]
    pub fn connect_ports(&self) -> Vec<u16> {
        self.ports
            .iter()
            .map(|p| p.port)
            .chain(self.metadata_port.map(|_| 80))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mediatore_proto::trip::TrapCounts;
    use mediatore_proto::{Credential, Endpoint};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;

    /// A deterministic source for the rules: SHA-256 over a seed and a counter. Tests only;
    /// the guest draws from [`OsEntropy`].
    struct Seeded {
        seed: u64,
        block: u64,
        buf: Vec<u8>,
    }

    impl Seeded {
        fn new(seed: u64) -> Self {
            Self {
                seed,
                block: 0,
                buf: Vec::new(),
            }
        }
    }

    impl Entropy for Seeded {
        fn fill(&mut self, out: &mut [u8]) -> anyhow::Result<()> {
            for b in out {
                if self.buf.is_empty() {
                    let mut hasher = Sha256::new();
                    hasher.update(self.seed.to_be_bytes());
                    hasher.update(self.block.to_be_bytes());
                    self.buf = hasher.finalize().to_vec();
                    self.block += 1;
                }
                *b = self.buf.pop().unwrap_or_default();
            }
            Ok(())
        }
    }

    /// A source that answers one byte for ever.
    struct Stuck(u8);

    impl Entropy for Stuck {
        fn fill(&mut self, out: &mut [u8]) -> anyhow::Result<()> {
            out.fill(self.0);
            Ok(())
        }
    }

    /// A source that fails.
    struct Failing;

    impl Entropy for Failing {
        fn fill(&mut self, _: &mut [u8]) -> anyhow::Result<()> {
            anyhow::bail!("no entropy")
        }
    }

    const GUEST_ENV: [&str; 3] = ["MEDIATORE_TOKEN", "MEDIATORE_EGRESS_PROXY", "HOME"];

    fn inputs<'a>() -> DrawInputs<'a> {
        DrawInputs {
            routes: &[],
            proxy_port: 3128,
            pull_port: 3129,
            reserved_ports: &[],
            reserved_env: &GUEST_ENV,
            catalogue: None,
            metadata: true,
        }
    }

    fn route(host: &str, port: u16) -> Route {
        Route {
            audience: None,
            endpoint: Endpoint {
                host: host.to_owned(),
                port,
            },
            rules: Vec::new(),
            ca_pem: None,
            credential: Credential::Token,
            credential_header: None,
            inject_port: None,
            pull_only: false,
            traps_body: TrapsBody::Match,
        }
    }

    fn seeded(seed: u64, inputs: &DrawInputs<'_>) -> Draw {
        draw(&mut Seeded::new(seed), inputs).expect("a draw")
    }

    fn sizes(d: &Draw) -> (usize, usize, usize) {
        (
            d.ports.len() + usize::from(d.metadata_port.is_some()),
            d.routes.len(),
            d.credentials.len(),
        )
    }

    fn variables(d: &Draw) -> Vec<&str> {
        d.credentials
            .iter()
            .flat_map(|b| b.env.iter().map(|(name, _)| name.as_str()))
            .collect()
    }

    fn is_seed_port(port: u16) -> bool {
        PORT_SEEDS.iter().any(|s| s.port == port)
    }

    fn seed_variables() -> BTreeSet<&'static str> {
        CREDENTIAL_SEEDS
            .iter()
            .flat_map(|s| s.variables.iter().copied())
            .collect()
    }

    /// A deployment's catalogue, as an operator might write one. No broker serves one yet
    /// (ADR-0069 decision 4, amended): this value is built by hand.
    fn deployment() -> TrapCatalogue {
        let variable = |name: &str, generator| TrapVariable {
            name: name.to_owned(),
            generator,
        };
        TrapCatalogue {
            ports: vec![7001, 7443, 9443, 18_080, 4317, 9093],
            host_stems: ["acme-ledger", "acme-billing", "payroll", "fleet", "tariffs"]
                .map(str::to_owned)
                .to_vec(),
            host_suffixes: vec![".corp.example".to_owned(), ".acme.example".to_owned()],
            variables: vec![
                variable("ACME_BILLING_KEY", TrapGenerator::StripeSecretKey),
                variable("LEDGER_SIGNING_KEY", TrapGenerator::JwtSecretHex),
                variable("PAYROLL_DB_URL", TrapGenerator::PostgresUrl),
                variable("FLEET_DEPLOY_TOKEN", TrapGenerator::GitlabPat),
                variable("TARIFFS_API_KEY", TrapGenerator::GoogleApiKey),
                variable("ACME_ARTIFACTS_AUTH", TrapGenerator::DockerAuth),
            ],
            counts: None,
        }
    }

    fn sample() -> Draw {
        Draw {
            ports: vec![DecoyPort {
                name: "redis".into(),
                port: 6379,
                banner: Banner::Redis,
            }],
            metadata_port: Some(41_000),
            routes: vec![DecoyRoute {
                name: "vault".into(),
                host: "secrets.prod.internal".into(),
                env: "VAULT_ADDR".into(),
            }],
            credentials: vec![Bait {
                name: "aws".into(),
                env: vec![(
                    "AWS_SECRET_ACCESS_KEY".into(),
                    BaitValue::new("bait-value-one".into()),
                )],
                files: vec![(
                    ".aws/credentials".into(),
                    BaitValue::new("[default]\nkey = bait-value-one\n".into()),
                )],
                values: vec![BaitValue::new("bait-value-one".into())],
            }],
        }
    }

    #[test]
    fn the_projections_of_a_draw_cover_its_routes_its_bait_and_its_ports() {
        let d = sample();
        assert_eq!(
            d.env("http://127.0.0.1:3128/"),
            vec![
                (
                    "VAULT_ADDR".to_owned(),
                    "http://127.0.0.1:3128/secrets.prod.internal/".to_owned()
                ),
                (
                    "AWS_SECRET_ACCESS_KEY".to_owned(),
                    "bait-value-one".to_owned()
                ),
            ]
        );
        assert_eq!(d.secret_values(), vec!["bait-value-one".to_owned()]);
        assert_eq!(d.connect_ports(), vec![6379, 80]);
        let traps = d.proxy_traps(TripMode::Shadow, ClassAction::Trip);
        assert_eq!(traps.routes[0].host, "secrets.prod.internal");
        assert_eq!(traps.bait[0].name, "aws");
        assert_eq!(traps.bait[0].values.len(), 1);
    }

    #[test]
    fn counts_stay_within_the_built_in_bounds_over_ten_thousand_draws() {
        let inputs = inputs();
        let mut seen = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        for seed in 0..10_000 {
            let (ports, routes, credentials) = sizes(&seeded(seed, &inputs));
            seen.0.insert(ports);
            seen.1.insert(routes);
            seen.2.insert(credentials);
        }
        // Every count in the bounds is drawn, and none outside them.
        assert_eq!(seen.0.into_iter().collect::<Vec<_>>(), [2, 3, 4, 5]);
        assert_eq!(seen.1.into_iter().collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(seen.2.into_iter().collect::<Vec<_>>(), [3, 4, 5, 6]);
    }

    #[test]
    fn a_catalogue_can_narrow_the_counts_inside_the_bounds_and_never_outside() {
        let counts = |ports: (u8, u8), routes: (u8, u8), credentials: (u8, u8)| TrapCatalogue {
            counts: Some(TrapCounts {
                ports: Some(CountRange {
                    min: ports.0,
                    max: ports.1,
                }),
                routes: Some(CountRange {
                    min: routes.0,
                    max: routes.1,
                }),
                credentials: Some(CountRange {
                    min: credentials.0,
                    max: credentials.1,
                }),
            }),
            ..TrapCatalogue::default()
        };
        let narrow = counts((3, 3), (2, 2), (4, 5));
        let narrowed = DrawInputs {
            catalogue: Some(&narrow),
            ..inputs()
        };
        for seed in 0..500 {
            let (ports, routes, credentials) = sizes(&seeded(seed, &narrowed));
            assert_eq!((ports, routes), (3, 2));
            assert!((4..=5).contains(&credentials));
        }
        for outside in [
            counts((1, 5), (1, 3), (3, 6)),
            counts((2, 6), (1, 3), (3, 6)),
            counts((2, 5), (0, 3), (3, 6)),
            counts((2, 5), (1, 3), (3, 7)),
            counts((4, 3), (1, 3), (3, 6)),
        ] {
            let widened = DrawInputs {
                catalogue: Some(&outside),
                ..inputs()
            };
            assert!(
                draw(&mut Seeded::new(1), &widened).is_err(),
                "a catalogue widened the counts"
            );
        }
    }

    /// Every host a seed row can spell, as real routes.
    fn every_seed_host() -> Vec<Route> {
        ROUTE_SEEDS
            .iter()
            .flat_map(|seed| seed.stems.iter())
            .flat_map(|stem| SUFFIXES.iter().map(move |suffix| format!("{stem}{suffix}")))
            .map(|host| route(&host, 443))
            .collect()
    }

    #[test]
    fn every_exclusion_redraws_and_never_shortens_the_draw() {
        let plain = inputs();
        let seed_ports: Vec<u16> = PORT_SEEDS.iter().map(|s| s.port).collect();
        let seed_hosts = every_seed_host();
        let seed_route_env: Vec<&str> = ROUTE_SEEDS.iter().map(|s| s.env).collect();
        let seed_env: Vec<&str> = seed_variables().into_iter().collect();
        let providers = [
            route("api.github.com", 443),
            route("registry.npmjs.org", 443),
        ];
        let cases = [
            // The proxy's port, the pull listener's, the ports the workload serves.
            DrawInputs {
                proxy_port: 8080,
                pull_port: 6379,
                reserved_ports: &seed_ports[..12],
                ..plain
            },
            // A host that is one of the claim's routes.
            DrawInputs {
                routes: &seed_hosts,
                ..plain
            },
            // A variable the guest sets: a decoy route's, a bait credential's.
            DrawInputs {
                reserved_env: &seed_route_env,
                ..plain
            },
            DrawInputs {
                reserved_env: &seed_env,
                ..plain
            },
            // A credential whose provider is one of the claim's routes.
            DrawInputs {
                routes: &providers,
                ..plain
            },
        ];
        for seed in 0..1500 {
            let expected = sizes(&seeded(seed, &plain));
            for case in &cases {
                let d = seeded(seed, case);
                assert_eq!(sizes(&d), expected, "an exclusion changed a count");
                for port in d.ports.iter().map(|p| p.port).chain(d.metadata_port) {
                    assert!(port != case.proxy_port && port != case.pull_port);
                    assert!(!case.reserved_ports.contains(&port), "a reserved port");
                }
                for decoy in &d.routes {
                    assert!(
                        !case.routes.iter().any(|r| r.endpoint.host == decoy.host),
                        "a decoy is a real route"
                    );
                    assert!(!case.reserved_env.contains(&decoy.env.as_str()));
                }
                for variable in variables(&d) {
                    assert!(!case.reserved_env.contains(&variable), "a reserved name");
                }
            }
            // The fifth case: neither routed provider's bait.
            let d = seeded(seed, &cases[4]);
            assert!(
                !d.credentials
                    .iter()
                    .any(|b| b.name == "github" || b.name == "npm")
            );
        }
    }

    #[test]
    fn nothing_is_drawn_twice_and_every_name_fits_a_trip_report() {
        let catalogue = deployment();
        let real = [route("git.example", 443), route("api.forge.example", 443)];
        let rich = DrawInputs {
            routes: &real,
            catalogue: Some(&catalogue),
            ..inputs()
        };
        let plain = inputs();
        for seed in 0..3000 {
            let d = seeded(seed, if seed % 2 == 0 { &rich } else { &plain });
            let ports: BTreeSet<u16> = d
                .ports
                .iter()
                .map(|p| p.port)
                .chain(d.metadata_port)
                .collect();
            assert_eq!(ports.len(), sizes(&d).0, "a port twice");
            assert!(!ports.contains(&0) && !ports.contains(&3128) && !ports.contains(&3129));
            let hosts: BTreeSet<&str> = d.routes.iter().map(|r| r.host.as_str()).collect();
            assert_eq!(hosts.len(), d.routes.len(), "a host twice");
            let mut names: Vec<&str> = variables(&d);
            names.extend(d.routes.iter().map(|r| r.env.as_str()));
            let distinct: BTreeSet<&str> = names.iter().copied().collect();
            assert_eq!(distinct.len(), names.len(), "a variable twice");
            assert!(names.iter().all(|n| variable_ok(n)), "a variable's grammar");
            let files: Vec<&str> = d
                .credentials
                .iter()
                .flat_map(|b| b.files.iter().map(|(path, _)| path.as_str()))
                .collect();
            assert_eq!(
                files.iter().collect::<BTreeSet<_>>().len(),
                files.len(),
                "a file twice"
            );
            // Relative to the home, never above it and never the work directory.
            assert!(
                files
                    .iter()
                    .all(|p| p.starts_with('.') && !p.contains("..") && !p.starts_with('/'))
            );
            let traps: Vec<&str> = d
                .ports
                .iter()
                .map(|p| p.name.as_str())
                .chain(d.routes.iter().map(|r| r.name.as_str()))
                .chain(d.credentials.iter().map(|b| b.name.as_str()))
                .collect();
            assert!(traps.iter().all(|t| trap_name_ok(t)), "a trap's name");
            assert!(
                d.routes.iter().all(|r| host_ok(&r.host)),
                "a host's grammar"
            );
            let baits: BTreeSet<&str> = d.credentials.iter().map(|b| b.name.as_str()).collect();
            assert_eq!(baits.len(), d.credentials.len(), "a bait's name twice");
        }
    }

    #[test]
    fn a_set_variable_of_a_lookup_family_excludes_every_bait_of_that_family() {
        // By family, not by position: either name set excludes both.
        assert!(in_a_set_family("GITHUB_TOKEN", &["GH_TOKEN"]));
        assert!(in_a_set_family("GH_TOKEN", &["GITHUB_TOKEN"]));
        assert!(in_a_set_family(
            "AWS_SECRET_ACCESS_KEY",
            &["AWS_ACCESS_KEY_ID"]
        ));
        assert!(in_a_set_family("AWS_ACCESS_KEY_ID", &["AWS_SESSION_TOKEN"]));
        assert!(in_a_set_family("OAUTH_TOKEN", &["GITLAB_TOKEN"]));
        assert!(in_a_set_family("GITLAB_ACCESS_TOKEN", &["GITLAB_TOKEN"]));
        assert!(in_a_set_family("HUGGING_FACE_HUB_TOKEN", &["HF_TOKEN"]));
        assert!(in_a_set_family("GEMINI_API_KEY", &["GOOGLE_API_KEY"]));
        // A family is one tool's: another family's member set excludes nothing here.
        assert!(!in_a_set_family(
            "GITHUB_TOKEN",
            &["GITLAB_TOKEN", "AWS_ACCESS_KEY_ID"]
        ));
        assert!(!in_a_set_family("NPM_TOKEN", &["GH_TOKEN"]));
        assert!(!in_a_set_family(
            "GITHUB_TOKEN",
            &["MEDIATORE_TOKEN", "HOME"]
        ));

        // The workload's specification sets the first name of a pair, on a host that gives
        // no provider away: the later name is no bait either.
        let routes = [route("code.corp.example", 443)];
        let gh = [
            "MEDIATORE_TOKEN",
            "MEDIATORE_EGRESS_PROXY",
            "HOME",
            "GH_TOKEN",
        ];
        let aws = [
            "MEDIATORE_TOKEN",
            "MEDIATORE_EGRESS_PROXY",
            "HOME",
            "AWS_ACCESS_KEY_ID",
        ];
        let beside_gh = DrawInputs {
            routes: &routes,
            reserved_env: &gh,
            ..inputs()
        };
        let beside_aws = DrawInputs {
            routes: &routes,
            reserved_env: &aws,
            ..inputs()
        };
        let without = DrawInputs {
            routes: &routes,
            ..inputs()
        };
        let (mut github_control, mut aws_control) = (0, 0);
        for seed in 0..3000 {
            let expected = sizes(&seeded(seed, &without));
            let d = seeded(seed, &beside_gh);
            assert_eq!(sizes(&d), expected, "the exclusion shortened the draw");
            let drawn = variables(&d);
            assert!(
                !drawn.contains(&"GITHUB_TOKEN") && !drawn.contains(&"GH_TOKEN"),
                "a bait of gh's family beside a set GH_TOKEN"
            );
            let d = seeded(seed, &beside_aws);
            assert_eq!(sizes(&d), expected, "the exclusion shortened the draw");
            let drawn = variables(&d);
            assert!(
                !drawn.contains(&"AWS_SECRET_ACCESS_KEY")
                    && !drawn.contains(&"AWS_ACCESS_KEY_ID")
                    && !drawn.contains(&"AWS_SESSION_TOKEN"),
                "a bait of the AWS family beside a set AWS_ACCESS_KEY_ID"
            );
            let plain = seeded(seed, &without);
            let plain = variables(&plain);
            github_control += usize::from(plain.contains(&"GITHUB_TOKEN"));
            aws_control += usize::from(plain.contains(&"AWS_SECRET_ACCESS_KEY"));
        }
        assert!(
            github_control > 50,
            "with nothing set the later name is drawn"
        );
        assert!(aws_control > 50, "with nothing set the AWS pair is drawn");
    }

    #[test]
    fn a_bait_gh_token_is_never_drawn_beside_a_routed_github_phantom() {
        // The table itself: `gh` reads `GH_TOKEN` first, and either name set excludes both.
        assert!(in_a_set_family("GH_TOKEN", &["GITHUB_TOKEN"]));
        assert!(in_a_set_family("GITLAB_TOKEN", &["OAUTH_TOKEN"]));
        assert!(in_a_set_family("HF_TOKEN", &["HUGGING_FACE_HUB_TOKEN"]));
        assert!(!in_a_set_family("GH_TOKEN", &["MEDIATORE_TOKEN", "HOME"]));
        assert!(!in_a_set_family("NPM_TOKEN", &["GITHUB_TOKEN"]));
        // A GitHub the host does not give away, its phantom in `GITHUB_TOKEN`.
        let routes = [route("code.corp.example", 443)];
        let phantom = [
            "MEDIATORE_TOKEN",
            "MEDIATORE_EGRESS_PROXY",
            "HOME",
            "GITHUB_TOKEN",
        ];
        // A deployment that names the shadowing variable itself gets it no more than a seed does.
        let catalogue = TrapCatalogue {
            variables: vec![TrapVariable {
                name: "GH_TOKEN".to_owned(),
                generator: TrapGenerator::JwtSecretHex,
            }],
            ..TrapCatalogue::default()
        };
        let beside = DrawInputs {
            routes: &routes,
            reserved_env: &phantom,
            ..inputs()
        };
        let named = DrawInputs {
            catalogue: Some(&catalogue),
            ..beside
        };
        let without = DrawInputs {
            routes: &routes,
            ..inputs()
        };
        let mut control = 0;
        for seed in 0..3000 {
            for case in [&beside, &named] {
                let d = seeded(seed, case);
                let drawn = variables(&d);
                assert!(
                    !drawn.contains(&"GH_TOKEN"),
                    "a bait GH_TOKEN beside the phantom"
                );
                assert!(
                    !drawn.contains(&"GITHUB_TOKEN"),
                    "the phantom's own variable"
                );
            }
            control += usize::from(variables(&seeded(seed, &without)).contains(&"GH_TOKEN"));
        }
        assert!(control > 50, "without the phantom the variable is drawn");
    }

    #[test]
    fn a_claim_routed_to_github_npm_and_a_model_api_draws_none_of_their_providers() {
        let mut model = route("api.models.example", 443);
        model.traps_body = TrapsBody::Skip;
        let routes = [
            route("api.github.com", 443),
            route("registry.npmjs.org", 443),
            model,
        ];
        let named = [
            route("github.corp.example", 443),
            route("npm.corp.example", 4873),
            route("api.anthropic.com", 443),
        ];
        let catalogue = TrapCatalogue {
            variables: vec![
                TrapVariable {
                    name: "ACME_FORGE_TOKEN".to_owned(),
                    generator: TrapGenerator::GithubPat,
                },
                TrapVariable {
                    name: "ACME_PACKAGES_TOKEN".to_owned(),
                    generator: TrapGenerator::NpmToken,
                },
                TrapVariable {
                    name: "ACME_MODEL_KEY".to_owned(),
                    generator: TrapGenerator::OpenaiKey,
                },
                TrapVariable {
                    name: "ACME_LEDGER_KEY".to_owned(),
                    generator: TrapGenerator::JwtSecretHex,
                },
            ],
            ..TrapCatalogue::default()
        };
        let mut unrouted = 0;
        for seed in 0..2000 {
            for routes in [&routes, &named] {
                let case = DrawInputs {
                    routes,
                    catalogue: (seed % 2 == 0).then_some(&catalogue),
                    ..inputs()
                };
                let d = seeded(seed, &case);
                for bait in &d.credentials {
                    let leaks = bait.values.iter().any(|v| {
                        ["ghp_", "github_pat_", "npm_", "sk-proj-"]
                            .iter()
                            .any(|prefix| v.expose().starts_with(prefix))
                    });
                    assert!(!leaks, "a routed provider's credential was drawn");
                    assert!(!bait.files.iter().any(|(path, _)| path == ".npmrc"));
                    assert!(
                        !bait
                            .files
                            .iter()
                            .any(|(_, c)| c.expose().contains("@github.com"))
                    );
                }
                let drawn = variables(&d);
                for name in ["GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN", "OPENAI_API_KEY"] {
                    assert!(
                        !drawn.contains(&name),
                        "a routed provider's variable was drawn"
                    );
                }
                assert!(
                    !drawn
                        .iter()
                        .any(|n| n.contains("GITHUB") || n.contains("NPM") || n.contains("OPENAI"))
                );
            }
            // The same seeds with no such route do draw them: the check above has teeth.
            let d = seeded(seed, &inputs());
            unrouted += usize::from(
                variables(&d)
                    .iter()
                    .any(|n| n.contains("GITHUB") || n.contains("NPM") || n.contains("OPENAI")),
            );
        }
        assert!(unrouted > 200, "the providers are drawn when not routed");
        // The provider table, host by host.
        for (provider, host, port) in [
            (Provider::Github, "api.github.com", 443),
            (Provider::Github, "ghcr.io", 443),
            (Provider::Github, "github.corp.example", 443),
            (Provider::Npm, "registry.npmjs.org", 443),
            (Provider::Aws, "s3.eu-west-1.amazonaws.com", 443),
            (Provider::ModelApi, "api.openai.com", 443),
            (Provider::ModelApi, "api.anthropic.com", 443),
            (Provider::Kubernetes, "cluster.example", 6443),
            (Provider::Azure, "acct.blob.core.windows.net", 443),
        ] {
            assert!(provider.serves(&route(host, port)), "{host}");
        }
        assert!(!Provider::Github.serves(&route("git.example", 443)));
        assert!(!Provider::Github.serves(&route("notghcr.io", 443)));
        assert!(!Provider::Nobody.serves(&route("api.github.com", 443)));
    }

    #[test]
    fn two_draws_from_one_seed_are_equal() {
        let catalogue = deployment();
        let real = [route("git.example", 443)];
        let rich = DrawInputs {
            routes: &real,
            catalogue: Some(&catalogue),
            ..inputs()
        };
        for seed in 0..200 {
            assert!(
                seeded(seed, &rich) == seeded(seed, &rich),
                "a seed drew twice differently"
            );
            assert!(
                seeded(seed, &rich) != seeded(seed + 1, &rich),
                "two seeds drew alike"
            );
        }
    }

    #[test]
    fn two_draws_from_the_os_differ() {
        // Every draw holds at least three credentials of at least 100 random bits each and a
        // port from more than 64,000. Two of 32 draws being equal, or sharing one bait value,
        // has probability under 496 pairs * 36 value pairs * 2^-100, about 2^-86: this test
        // does not fail by chance.
        let inputs = inputs();
        let draws: Vec<Draw> = (0..32)
            .map(|_| draw(&mut OsEntropy, &inputs).expect("a draw from the OS"))
            .collect();
        let mut values = BTreeSet::new();
        let mut total = 0;
        for (i, d) in draws.iter().enumerate() {
            assert!(
                draws[..i].iter().all(|earlier| earlier != d),
                "two draws alike"
            );
            for value in d.secret_values() {
                total += 1;
                values.insert(value);
            }
        }
        assert_eq!(values.len(), total, "two bait values alike");
        // The layout differs too, not only the values: over 32 draws more than one port set.
        let layouts: BTreeSet<Vec<u16>> = draws
            .iter()
            .map(|d| {
                let mut ports: Vec<u16> = d.ports.iter().map(|p| p.port).collect();
                ports.sort_unstable();
                ports
            })
            .collect();
        assert_eq!(layouts.len(), 32, "two draws with the same ports");
    }

    #[test]
    fn every_draw_has_a_port_outside_the_seeds() {
        let catalogue = deployment();
        let with = DrawInputs {
            catalogue: Some(&catalogue),
            ..inputs()
        };
        let plain = inputs();
        let mut first_is_generated = 0;
        for seed in 0..5000 {
            let d = seeded(seed, if seed % 2 == 0 { &with } else { &plain });
            let outside = d
                .ports
                .iter()
                .any(|p| p.name == GENERATED_PORT && p.port >= 1024 && !is_seed_port(p.port));
            assert!(outside, "a draw of seed ports alone");
            first_is_generated += usize::from(d.ports[0].name == GENERATED_PORT);
        }
        // And its place in the list says nothing: the list is shuffled.
        assert!(
            first_is_generated < 4500,
            "the generated port is always first"
        );
    }

    #[test]
    fn the_metadata_decoy_is_drawn_only_where_it_may_be() {
        let never = DrawInputs {
            metadata: false,
            ..inputs()
        };
        let mut drawn = 0;
        for seed in 0..3000 {
            assert!(seeded(seed, &never).metadata_port.is_none());
            let d = seeded(seed, &inputs());
            if let Some(port) = d.metadata_port {
                drawn += 1;
                assert!(port >= 1024 && !is_seed_port(port));
                assert!(d.ports.iter().all(|p| p.port != port));
                assert!(d.connect_ports().contains(&80));
            }
        }
        assert!(drawn > 30, "the metadata decoy is drawn where it may be");
    }

    #[test]
    fn a_derived_decoy_looks_like_a_second_host_of_a_real_route_and_is_never_that_route() {
        let real = [
            route("git.example", 443),
            route("api.forge.example", 443),
            route("192.0.2.7", 443),
            route("registry", 5000),
        ];
        let beside = DrawInputs {
            routes: &real,
            ..inputs()
        };
        let mut derived = BTreeSet::new();
        for seed in 0..2000 {
            for decoy in seeded(seed, &beside).routes {
                assert!(
                    real.iter().all(|r| r.endpoint.host != decoy.host),
                    "a real route"
                );
                assert!(
                    !decoy.host.contains("192.0.2"),
                    "a second host of an address"
                );
                let second = decoy.host.ends_with(".git.example")
                    || decoy.host.ends_with(".forge.example")
                    || decoy.host.starts_with("registry-");
                if second {
                    derived.insert(decoy.host.clone());
                    assert!(decoy.env.ends_with("_URL") && variable_ok(&decoy.env));
                }
            }
        }
        // All three shapes: a label before, the first label extended, a bare name extended.
        assert!(derived.contains("mirror.git.example"));
        assert!(
            derived
                .iter()
                .any(|h| h.starts_with("api-") && h.ends_with(".forge.example"))
        );
        assert!(derived.iter().any(|h| h.starts_with("registry-")));
        assert!(
            derived.len() > 30,
            "the derived hosts are a space, not a list"
        );
    }

    /// How many of a draw's entries the deployment's catalogue gave, and the public seeds.
    fn shares(d: &Draw, catalogue: &TrapCatalogue) -> (usize, usize) {
        let seeds = seed_variables();
        let from_deployment = d
            .ports
            .iter()
            .filter(|p| catalogue.ports.contains(&p.port))
            .count()
            + d.routes
                .iter()
                .filter(|r| {
                    catalogue
                        .host_stems
                        .iter()
                        .any(|s| r.host.starts_with(&format!("{s}.")))
                })
                .count()
            + d.credentials
                .iter()
                .filter(|b| {
                    b.env
                        .iter()
                        .any(|(n, _)| catalogue.variables.iter().any(|v| v.name == *n))
                })
                .count();
        let from_seeds = d.ports.iter().filter(|p| is_seed_port(p.port)).count()
            + usize::from(d.metadata_port.is_some())
            + d.routes
                .iter()
                .filter(|r| ROUTE_SEEDS.iter().any(|s| s.env == r.env))
                .count()
            + d.credentials
                .iter()
                .filter(|b| b.env.iter().any(|(n, _)| seeds.contains(n.as_str())))
                .count();
        (from_deployment, from_seeds)
    }

    #[test]
    fn the_deployments_entries_outweigh_the_seeds() {
        let catalogue = deployment();
        let with = DrawInputs {
            catalogue: Some(&catalogue),
            ..inputs()
        };
        let (mut deployment_made, mut seed_made, mut all) = (0, 0, 0);
        for seed in 0..2000 {
            let d = seeded(seed, &with);
            let (from_deployment, from_seeds) = shares(&d, &catalogue);
            deployment_made += from_deployment;
            seed_made += from_seeds;
            all += sizes(&d).0 + d.routes.len() + d.credentials.len();
        }
        println!(
            "shares, with a deployment catalogue: {deployment_made} of {all} entries from it, {seed_made} from the seeds"
        );
        // Fixed seeds, so fixed figures: the bounds are loose on purpose.
        assert!(
            deployment_made > 2 * seed_made,
            "the deployment's entries do not outweigh the seeds"
        );
        assert!(
            2 * seed_made < all / 2,
            "the seeds are more than a quarter of a draw"
        );
        assert!(
            2 * deployment_made > all * 4 / 5,
            "the deployment gives under two in five"
        );
        // Without a catalogue nothing is the deployment's, and the seeds are still not all.
        let (mut none, mut seed_made, mut all) = (0, 0, 0);
        for seed in 0..2000 {
            let d = seeded(seed, &inputs());
            let (from_deployment, from_seeds) = shares(&d, &catalogue);
            none += from_deployment;
            seed_made += from_seeds;
            all += sizes(&d).0 + d.routes.len() + d.credentials.len();
        }
        // But for a generated port that lands on one of the deployment's six by chance.
        assert!(none <= 2);
        println!("shares, seeds alone: {seed_made} of {all} entries from the seeds");
        assert!(seed_made * 10 < all * 7 && seed_made * 10 > all * 3);
    }

    #[test]
    fn the_draw_never_prints() {
        let catalogue = deployment();
        let with = DrawInputs {
            catalogue: Some(&catalogue),
            ..inputs()
        };
        let plain = inputs();
        for seed in 0..300 {
            let d = seeded(seed, if seed % 2 == 0 { &with } else { &plain });
            let printed = format!(
                "{d:?} {:?} {:?}",
                d.credentials,
                d.proxy_traps(TripMode::Enforce, ClassAction::Report)
            );
            assert!(printed.contains("[redacted]"));
            for bait in &d.credentials {
                let planted = bait.values.iter().chain(bait.env.iter().map(|(_, v)| v));
                for value in planted.chain(bait.files.iter().map(|(_, v)| v)) {
                    assert!(
                        !printed.contains(value.expose()),
                        "a printed draw holds bait"
                    );
                }
            }
        }
    }

    #[test]
    fn the_env_and_the_secret_values_cover_every_bait_value() {
        let catalogue = deployment();
        let with = DrawInputs {
            catalogue: Some(&catalogue),
            ..inputs()
        };
        let plain = inputs();
        for seed in 0..1000 {
            let d = seeded(seed, if seed % 2 == 0 { &with } else { &plain });
            let env = d.env("http://127.0.0.1:3128");
            let secrets = d.secret_values();
            let handed = d.proxy_traps(TripMode::Enforce, ClassAction::Report);
            assert_eq!(env.len(), d.routes.len() + variables(&d).len());
            for decoy in &d.routes {
                let url = format!("http://127.0.0.1:3128/{}/", decoy.host);
                assert!(
                    env.contains(&(decoy.env.clone(), url)),
                    "a decoy route's variable"
                );
            }
            for (bait, armed) in d.credentials.iter().zip(&handed.bait) {
                assert!(
                    !bait.values.is_empty() && !bait.env.is_empty(),
                    "an empty bait"
                );
                assert_eq!(bait.values.len(), armed.values.len());
                for value in &bait.values {
                    let value = value.expose();
                    assert!(value.len() >= 20, "a bait value too short to match on");
                    assert!(
                        secrets.iter().any(|s| s == value),
                        "a value the redactor lacks"
                    );
                    assert!(
                        armed.values.iter().any(|s| s.0 == value),
                        "a value the proxy lacks"
                    );
                    // Planted where the workload can find it: a variable or a file, as it is
                    // or (a registry's password) inside the base64 pair that is.
                    let pairs: Vec<Vec<u8>> = bait
                        .values
                        .iter()
                        .filter_map(|v| STANDARD.decode(v.expose()).ok())
                        .collect();
                    let planted = bait
                        .env
                        .iter()
                        .chain(&bait.files)
                        .any(|(_, v)| v.expose().contains(value))
                        || pairs.iter().any(|pair| pair.ends_with(value.as_bytes()));
                    assert!(planted, "a value that is planted nowhere");
                }
                // And nothing planted is without a pattern: every variable and file holds one.
                for (_, planted) in bait.env.iter().chain(&bait.files) {
                    let holds = bait
                        .values
                        .iter()
                        .any(|v| planted.expose().contains(v.expose()));
                    let path = planted.expose() == format!("{JAIL_HOME}/.kube/config");
                    assert!(holds || path, "a planted text with no bait in it");
                }
            }
        }
    }

    // ----- The providers' offline checks, written from the published formats and not from the
    // generators: a CRC32 and a base62 of their own.

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    fn base62(text: &str) -> Option<u64> {
        text.chars().try_fold(0u64, |acc, c| {
            let digit = match c {
                '0'..='9' => u64::from(c) - u64::from('0'),
                'A'..='Z' => u64::from(c) - u64::from('A') + 10,
                'a'..='z' => u64::from(c) - u64::from('a') + 36,
                _ => return None,
            };
            Some(acc * 62 + digit)
        })
    }

    fn all(text: &str, len: usize, ok: impl Fn(char) -> bool) -> bool {
        text.len() == len && text.chars().all(ok)
    }

    fn alnum(c: char) -> bool {
        c.is_ascii_alphanumeric()
    }

    fn word(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '-' || c == '_'
    }

    /// `prefix`, 30 base62, and 6 base62 that are the CRC32 of the 30.
    fn checksum_holds(token: &str, prefix: &str) -> bool {
        token.strip_prefix(prefix).is_some_and(|rest| {
            all(rest, 36, alnum)
                && base62(&rest[30..]) == Some(u64::from(crc32(&rest.as_bytes()[..30])))
        })
    }

    fn pypi_holds(token: &str) -> bool {
        // The prefix a scanner looks for: the macaroon's version and its location, `pypi.org`.
        let Some(body) = token.strip_prefix("pypi-") else {
            return false;
        };
        let Ok(raw) = URL_SAFE_NO_PAD.decode(body) else {
            return false;
        };
        body.starts_with("AgEIcHlwaS5vcmcCJ")
            && body.len() >= 70
            && raw.starts_with(b"\x02\x01\x08pypi.org\x02\x24")
            && raw.len() >= 34
            && raw[raw.len() - 34..raw.len() - 32] == [0x06, 0x20]
    }

    fn jwt_holds(token: &str) -> bool {
        let parts: Vec<&str> = token.split('.').collect();
        let json = |part: &str| {
            URL_SAFE_NO_PAD
                .decode(part)
                .ok()
                .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        };
        parts.len() == 3
            && json(parts[0]).is_some_and(|h| h["alg"] == "ES256")
            && json(parts[1]).is_some_and(|p| {
                p["sub"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("system:serviceaccount:"))
            })
            && URL_SAFE_NO_PAD
                .decode(parts[2])
                .is_ok_and(|sig| sig.len() == 64)
    }

    fn connection_holds(text: &str) -> bool {
        let field = |name: &str| {
            text.split(';')
                .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
        };
        field("DefaultEndpointsProtocol") == Some("https")
            && field("AccountName").is_some_and(|n| {
                (3..=24).contains(&n.len())
                    && n.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            })
            && field("AccountKey")
                .and_then(|k| STANDARD.decode(k).ok())
                .is_some_and(|k| k.len() == 64)
    }

    fn postgres_holds(text: &str) -> bool {
        text.strip_prefix("postgres://")
            .and_then(|rest| rest.split_once('@'))
            .is_some_and(|(pair, at)| {
                let password_ok = pair
                    .split_once(':')
                    .is_some_and(|(u, p)| !u.is_empty() && all(p, 28, alnum));
                let host_ok = at
                    .split_once(":5432/")
                    .is_some_and(|(host, db)| super::host_ok(host) && !db.is_empty());
                password_ok && host_ok
            })
    }

    /// Whether `text` passes its provider's offline check: prefix, length, alphabet, and the
    /// checksum where the format has one.
    fn offline_check(generator: TrapGenerator, text: &str) -> bool {
        let after = |prefix: &str| text.strip_prefix(prefix).unwrap_or("\u{0}");
        match generator {
            TrapGenerator::AwsAccessKeyId => {
                all(after("AKIA"), 16, |c| matches!(c, 'A'..='Z' | '2'..='7'))
            }
            TrapGenerator::AwsSecretAccessKey => all(text, 40, |c| {
                c.is_ascii_alphanumeric() || c == '+' || c == '/'
            }),
            TrapGenerator::GithubPat => checksum_holds(text, "ghp_"),
            TrapGenerator::GithubFineGrainedPat => after("github_pat_")
                .split_once('_')
                .is_some_and(|(a, b)| all(a, 22, alnum) && all(b, 59, alnum)),
            TrapGenerator::GitlabPat => all(after("glpat-"), 20, word),
            TrapGenerator::NpmToken => checksum_holds(text, "npm_"),
            TrapGenerator::PypiToken => pypi_holds(text),
            TrapGenerator::DockerAuth => STANDARD
                .decode(text)
                .ok()
                .and_then(|raw| String::from_utf8(raw).ok())
                .is_some_and(|pair| {
                    pair.split_once(':')
                        .is_some_and(|(u, p)| !u.is_empty() && all(p, 24, alnum))
                }),
            TrapGenerator::KubeBearer => jwt_holds(text),
            TrapGenerator::HfToken => all(after("hf_"), 34, alnum),
            TrapGenerator::OpenaiKey => after("sk-proj-")
                .split_once("T3BlbkFJ")
                .is_some_and(|(a, b)| all(a, 74, word) && all(b, 74, word)),
            TrapGenerator::StripeSecretKey => all(after("sk_live_"), 99, alnum),
            TrapGenerator::SlackBotToken => {
                let parts: Vec<&str> = after("xoxb-").split('-').collect();
                let digits =
                    |p: &str| (10..=13).contains(&p.len()) && p.chars().all(|c| c.is_ascii_digit());
                parts.len() == 3 && digits(parts[0]) && digits(parts[1]) && all(parts[2], 24, alnum)
            }
            TrapGenerator::GoogleApiKey => all(after("AIza"), 35, word),
            TrapGenerator::AzureStorageConnection => connection_holds(text),
            TrapGenerator::PostgresUrl => postgres_holds(text),
            TrapGenerator::JwtSecretHex => {
                all(text, 64, |c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
            }
            TrapGenerator::NetrcPassword => all(text, 28, alnum),
        }
    }

    const EVERY_GENERATOR: [TrapGenerator; 18] = [
        TrapGenerator::AwsAccessKeyId,
        TrapGenerator::AwsSecretAccessKey,
        TrapGenerator::GithubPat,
        TrapGenerator::GithubFineGrainedPat,
        TrapGenerator::GitlabPat,
        TrapGenerator::NpmToken,
        TrapGenerator::PypiToken,
        TrapGenerator::DockerAuth,
        TrapGenerator::KubeBearer,
        TrapGenerator::HfToken,
        TrapGenerator::OpenaiKey,
        TrapGenerator::StripeSecretKey,
        TrapGenerator::SlackBotToken,
        TrapGenerator::GoogleApiKey,
        TrapGenerator::AzureStorageConnection,
        TrapGenerator::PostgresUrl,
        TrapGenerator::JwtSecretHex,
        TrapGenerator::NetrcPassword,
    ];

    #[test]
    fn every_generated_credential_passes_its_providers_offline_check() {
        // The checks' own CRC32 and base62, against values known apart from this crate.
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(base62("10"), Some(62));
        assert_eq!(base62("0000zz"), Some(61 * 62 + 61));
        assert_eq!(base62("a-b"), None);
        let inputs = inputs();
        let mut source = Seeded::new(7);
        let mut rng = Rng(&mut source);
        let mut seen = BTreeSet::new();
        for generator in EVERY_GENERATOR {
            for _ in 0..300 {
                let made = generate(&mut rng, generator, &inputs).expect("a value");
                assert!(
                    offline_check(generator, &made.text),
                    "{generator:?} fails its check"
                );
                assert!(!made.secrets.is_empty(), "{generator:?} has no secret");
                for secret in &made.secrets {
                    assert!(
                        made.text.contains(secret.as_str())
                            || generator == TrapGenerator::DockerAuth
                    );
                    assert!(secret.len() >= 20 && !secret.to_ascii_uppercase().contains("EXAMPLE"));
                    assert!(
                        seen.insert(secret.clone()),
                        "{generator:?} repeated a value"
                    );
                }
            }
        }
        // A checksummed token with one character changed fails its check: the check checks.
        let token = generate(&mut rng, TrapGenerator::GithubPat, &inputs)
            .expect("a value")
            .text;
        let flipped = token.replacen(
            &token[10..11],
            if &token[10..11] == "A" { "B" } else { "A" },
            1,
        );
        assert!(!offline_check(TrapGenerator::GithubPat, &flipped));
        assert!(!offline_check(TrapGenerator::NpmToken, &token));
    }

    #[test]
    fn every_seed_credential_is_planted_as_its_tool_reads_it() {
        let mut shapes = BTreeSet::new();
        let plain = inputs();
        for seed in 0..1500 {
            for bait in seeded(seed, &plain).credentials {
                let Some(seeded_from) = CREDENTIAL_SEEDS.iter().find(|s| s.name == bait.name)
                else {
                    assert!(bait.files.is_empty(), "a generated variable has no file");
                    continue;
                };
                shapes.insert(bait.name.clone());
                for (name, _) in &bait.env {
                    assert!(seeded_from.variables.contains(&name.as_str()));
                }
                let content = bait.files.first().map_or("", |(_, c)| c.expose());
                let needs = match bait.name.as_str() {
                    "aws" => "[default]\naws_access_key_id = AKIA",
                    "github" => "@github.com\n",
                    "gitlab" => "https://oauth2:glpat-",
                    "npm" => "//registry.npmjs.org/:_authToken=npm_",
                    "pypi" => "[pypi]\nusername = __token__\npassword = pypi-",
                    "docker" => "{\"auths\":{\"",
                    "kube" => "    server: http://127.0.0.1:3128/",
                    "postgres" => ":5432:",
                    "netrc" => "machine ",
                    _ => "",
                };
                // A second bait for one file keeps its variables alone.
                assert!(
                    bait.files.is_empty() || content.contains(needs),
                    "a bait file's shape"
                );
            }
        }
        assert_eq!(
            shapes.len(),
            CREDENTIAL_SEEDS.len(),
            "every seed is drawn over the seeds"
        );
    }

    #[test]
    fn a_draw_that_cannot_avoid_a_collision_fails_and_is_never_shortened() {
        // Every port is the workload's: no decoy port is free.
        let every: Vec<u16> = (1..=u16::MAX).collect();
        let full = DrawInputs {
            reserved_ports: &every,
            ..inputs()
        };
        for seed in 0..20 {
            let refused =
                draw(&mut Seeded::new(seed), &full).expect_err("a draw with no free port");
            assert!(refused.to_string().contains("no decoy port"));
        }
        // A source that answers one number for ever: every redraw is the same entry again.
        for byte in [0x00, 0x55, 0xff] {
            assert!(
                draw(&mut Stuck(byte), &inputs()).is_err(),
                "a stuck source drew"
            );
        }
        // A source that fails.
        assert!(draw(&mut Failing, &inputs()).is_err());
        // A catalogue outside its own bounds.
        let bad = TrapCatalogue {
            ports: vec![0],
            ..TrapCatalogue::default()
        };
        let with = DrawInputs {
            catalogue: Some(&bad),
            ..inputs()
        };
        assert!(draw(&mut Seeded::new(1), &with).is_err());
    }

    #[test]
    fn the_numbers_are_unbiased_and_bounded() {
        let mut source = Seeded::new(3);
        let mut rng = Rng(&mut source);
        let mut counts = [0u32; 6];
        for _ in 0..60_000 {
            counts[usize::try_from(rng.below(6).unwrap()).unwrap()] += 1;
        }
        // 10,000 expected a face, standard deviation about 91: 9,000 to 11,000 is eleven of them.
        assert!(counts.iter().all(|c| (9000..=11_000).contains(c)));
        assert!(rng.below(0).is_err());
        assert_eq!(rng.below(1).unwrap(), 0);
        for _ in 0..1000 {
            assert!((1024..=65_535).contains(&u32::from(rng.high_port().unwrap())));
            assert!((5..=9).contains(&rng.between(5, 9).unwrap()));
        }
        // Three is not a divisor of 2^32: the top value is rejected, for ever, and that ends.
        assert!(Rng(&mut Stuck(0xff)).below(3).is_err());
        assert_eq!(Rng(&mut Stuck(0xff)).below(4).unwrap(), 3);
    }

    /// What a workload that explores can see of a sandbox, and whether each is a trap.
    fn surface(d: &Draw, real: &[Route]) -> Vec<(String, bool)> {
        let mut seen = vec![
            ("port 3128".to_owned(), false),
            ("MEDIATORE_TOKEN".to_owned(), false),
        ];
        seen.extend(real.iter().map(|r| (r.endpoint.host.clone(), false)));
        seen.extend(d.ports.iter().map(|p| (format!("port {}", p.port), true)));
        seen.extend(d.routes.iter().map(|r| (r.env.clone(), true)));
        seen.extend(variables(d).into_iter().map(|v| (v.to_owned(), true)));
        seen
    }

    /// Whether the public tables of this repository name `item`: what a reader avoids.
    fn a_reader_avoids(item: &str) -> bool {
        PORT_SEEDS
            .iter()
            .any(|s| item == format!("port {}", s.port))
            || ROUTE_SEEDS.iter().any(|s| s.env == item)
            || seed_variables().contains(item)
    }

    /// A simulation, not a measurement: a prober that has read this repository's seed tables
    /// avoids every port and variable they name, then uses what else it finds in a random
    /// order. Returns the probes it made before its first trap (`None`: it found none), and
    /// how many of the draw's traps the reading let it avoid.
    fn probe(d: &Draw, real: &[Route], order: &mut Rng<'_>) -> (Option<usize>, usize, usize) {
        let seen = surface(d, real);
        let traps = seen.iter().filter(|(_, trap)| *trap).count();
        let mut left: Vec<&(String, bool)> = seen
            .iter()
            .filter(|(item, _)| !a_reader_avoids(item))
            .collect();
        let avoided = traps - left.iter().filter(|(_, trap)| *trap).count();
        order.shuffle(&mut left).expect("an order");
        let tripped = left.iter().position(|(_, trap)| *trap).map(|at| at + 1);
        (tripped, avoided, traps)
    }

    #[test]
    fn a_prober_that_avoids_every_seed_still_trips_within_n_probes_with_a_deployment_catalogue() {
        let catalogue = deployment();
        let mut model = route("api.models.example", 443);
        model.traps_body = TrapsBody::Skip;
        let real = [
            route("git.example", 443),
            route("packages.example", 443),
            model,
        ];
        let with = DrawInputs {
            routes: &real,
            catalogue: Some(&catalogue),
            ..inputs()
        };
        let without = DrawInputs {
            routes: &real,
            ..inputs()
        };
        // What is real on this surface: the proxy's port, the phantom, three routes.
        let harmless = 5;
        let mut source = Seeded::new(0x7e57);
        let mut order = Rng(&mut source);
        let mut figures = Vec::new();
        for case in [&with, &without] {
            let (mut worst, mut probes, mut avoided, mut traps) = (0, 0, 0, 0);
            for seed in 0..5000 {
                let d = seeded(seed, case);
                let (tripped, a, t) = probe(&d, &real, &mut order);
                // Every draw holds a trap no table names, so no reader walks free.
                let tripped = tripped.expect("the prober trips");
                worst = worst.max(tripped);
                probes += tripped;
                avoided += a;
                traps += t;
            }
            assert!(
                worst <= harmless + 1,
                "more probes than there are harmless things"
            );
            figures.push((worst, probes, avoided, traps));
        }
        // Recorded for ADR-0069 "What must be proven": the simulation's figures, fixed seeds.
        let [
            (worst, probes, avoided, traps),
            (worst_bare, probes_bare, avoided_bare, traps_bare),
        ] = figures[..]
        else {
            panic!("two cases");
        };
        println!(
            "simulation, with a deployment catalogue: worst {worst} probes, mean {:.2}, traps avoided by reading the seeds {avoided} of {traps}",
            f64::from(u32::try_from(probes).unwrap()) / 5000.0
        );
        println!(
            "simulation, seeds alone: worst {worst_bare} probes, mean {:.2}, traps avoided by reading the seeds {avoided_bare} of {traps_bare}",
            f64::from(u32::try_from(probes_bare).unwrap()) / 5000.0
        );
        // With a deployment's catalogue, reading the repository avoids under a quarter of the
        // traps; without one, under two thirds.
        assert!(avoided * 4 < traps, "the seeds are too much of a draw");
        assert!(
            avoided_bare * 3 < traps_bare * 2,
            "the seeds are nearly all of a draw"
        );
    }
}
