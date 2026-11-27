// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The check service Envoy calls, and the `mediatore gateway` role around it.
//!
//! Envoy's external authorization filter asks this service once per downstream request
//! with its own `Check` call, over gRPC on loopback or a unix socket (`ext_authz` with
//! `grpc_service`). The request carries what Envoy knows of the downstream connection and
//! request, and nothing the client could set: the peer's identity from its verified
//! certificate (the URI SAN, as `source.principal`), the request's method, its authority and
//! its path (`request.http.method`, `.host`, `.path`). Why gRPC, when the rest of mediatore
//! speaks none: Envoy's HTTP mode copies the downstream request's method and target into the
//! check, so for a tunnel the check is itself a `CONNECT`, and Envoy's own client then resets
//! any `2xx` to it and strips a refusal's body (verified on Envoy 1.40.2). The gRPC mode has
//! no such shape.
//!
//! An allow is an `OK` status; a refusal is `PERMISSION_DENIED` with the refusal's code as
//! the message and as the `403` body Envoy returns to the client. An unreachable service is
//! a refusal too, by Envoy's `failure_mode_allow: false`.
//!
//! # Two kinds of Envoy, two sockets (ADR-0040 decision 6)
//!
//! The tunnel check ([`SocketKind::Tunnel`]) answers yes or no to a `CONNECT` and can never
//! return a credential: an inject-shaped question on it is refused as `not_connect` before
//! anything is looked up. The inject check ([`SocketKind::Inject`]) answers the headers for a
//! gateway-placed request and refuses a `CONNECT`. Each is served on its own unix socket, in
//! its own directory, whose group is the one Envoy's (so the tunnel Envoy's group cannot
//! reach the inject socket), with the directory `0750` and the socket `0660`.

use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use envoy_types::ext_authz::v3::pb::{
    Authorization, AuthorizationServer, CheckRequest, CheckResponse, HeaderAppendAction,
};
use envoy_types::ext_authz::v3::{
    CheckResponseExt, DeniedHttpResponseBuilder, OkHttpResponseBuilder,
};
use envoy_types::pb::envoy::r#type::v3::StatusCode as HttpStatusCode;
use mediatore_proto::{DecisionKind, DecisionVerdict, GatewayDecision};
use tokio::net::{TcpListener, UnixListener};
use tonic::{Request, Response, Status};

use crate::broker::Broker;
use crate::{Authorizer, CacheConfig, InjectAllow, Refusal, Served};

/// The default loopback port Envoy's authorization cluster points at.
pub const DEFAULT_PORT: u16 = 9001;

/// Which Envoy a check service answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    /// The data-plane Envoy's tunnels: `CONNECT`, yes or no.
    Tunnel,
    /// The inject Envoy's requests: the headers to set, or a refusal.
    Inject,
}

/// `mediatore gateway`'s arguments.
#[derive(Debug, clap::Args)]
pub struct GatewayArgs {
    /// Loopback address and port the tunnel check is served on, unless `--check-socket` is given
    #[arg(long, default_value_t = SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT)))]
    pub listen: SocketAddr,
    /// Serve the tunnel check on this unix socket instead of loopback TCP (ADR-0040 decision 6)
    #[arg(long, value_name = "PATH")]
    pub check_socket: Option<PathBuf>,
    /// Serve the inject check on this unix socket: gateway-placed credentials are on (ADR-0040).
    /// Its directory must not be the check socket's
    #[arg(long, value_name = "PATH")]
    pub inject_socket: Option<PathBuf>,
    /// Octal mode of each socket's directory; no bit for others
    #[arg(long, default_value = "0750", value_parser = parse_mode)]
    pub socket_dir_mode: u32,
    /// Octal mode of each socket; no bit for others
    #[arg(long, default_value = "0660", value_parser = parse_mode)]
    pub socket_mode: u32,
    /// Owner of the sockets and their directories, a user name or a number; default: this process's
    #[arg(long, value_name = "USER")]
    pub socket_owner: Option<String>,
    /// Group of the check socket and its directory (the data-plane Envoy's), a name or a number
    #[arg(long, value_name = "GROUP")]
    pub check_socket_group: Option<String>,
    /// Group of the inject socket and its directory (the inject Envoy's), a name or a number
    #[arg(long, value_name = "GROUP")]
    pub inject_socket_group: Option<String>,
    /// mediatore sandbox-facing base URL
    #[arg(long, env = "MEDIATORE_URL")]
    pub mediatore_url: String,
    /// SPIRE Workload API socket
    #[arg(
        long,
        env = "SPIFFE_ENDPOINT_SOCKET",
        default_value = "/run/spire/sockets/agent.sock"
    )]
    pub workload_api_socket: String,
    /// Seconds an allowlist is used without asking the broker again
    #[arg(long, default_value_t = 30)]
    pub fresh_secs: u64,
    /// Seconds past that an allowlist still stands in while the broker is unreachable
    #[arg(long, default_value_t = 300)]
    pub stale_secs: u64,
    /// Claims the cache holds; past it, the least recently used goes
    #[arg(long, default_value_t = 4096)]
    pub max_claims: usize,
    /// This gateway's name in the decisions it reports to the broker (ADR-0062); default: the
    /// host name. Attribution, not authentication: every gateway has the one authorizer identity
    #[arg(long, env = "MEDIATORE_GATEWAY_NAME")]
    pub name: Option<String>,
    /// Where the probes reader (`mediatore gateway-probes`) leaves its summary of what the host
    /// table dropped, for the next batch of decisions (ADR-0070). Read, never written; absent
    /// off the gateway image, and then no probe is reported
    #[arg(long, value_name = "DIR", default_value = crate::probes::PROBES_DIR)]
    pub probes_dir: PathBuf,
    /// Dev only: send this SPIFFE ID, which must be `spiffe://<td>/gateway/authorizer`, as a
    /// header instead of mTLS (loopback `dev_mode` broker)
    #[cfg(feature = "dev")]
    #[arg(long)]
    pub dev_spiffe_id: Option<String>,
}

/// The setgid bit of a directory mode.
const SETGID: u32 = 0o2000;

/// An octal mode with no bit for others: a socket or a directory that hands a credential
/// service to every local user is refused. The setgid bit is the one special bit allowed.
pub fn parse_mode(s: &str) -> Result<u32, String> {
    if s.is_empty() || !s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(format!("{s:?} is not an octal mode"));
    }
    let mode = u32::from_str_radix(s, 8).map_err(|e| format!("{s:?}: {e}"))?;
    // The setgid bit is the one special bit allowed (for a directory: see `UnixSocket::validate`); setuid and sticky never.
    if mode & !SETGID > 0o777 {
        return Err(format!(
            "{s:?} is more than 0777 (and 2000, the setgid bit)"
        ));
    }
    if (mode & 0o777).trailing_zeros() < 3 {
        return Err(format!("{s:?} gives access to others"));
    }
    Ok(mode)
}

/// A unix socket for one Envoy: where, who owns it and its directory, and at what modes.
#[derive(Debug, Clone)]
pub struct UnixSocket {
    /// The socket's path; its directory is this socket's own and is created if missing.
    pub path: PathBuf,
    /// The directory's mode, set before the socket exists: the directory carries the access.
    pub dir_mode: u32,
    /// The socket's mode.
    pub socket_mode: u32,
    /// Owner of the directory and the socket; `None` leaves the process's own.
    pub owner: Option<u32>,
    /// Group of the directory and the socket (the Envoy's); `None` leaves the process's own.
    pub group: Option<u32>,
}

impl UnixSocket {
    /// The modes carry no bit for others and the path has a directory.
    pub fn validate(&self) -> anyhow::Result<()> {
        // A directory may carry the setgid bit, so a socket created in it takes the directory's group (the authorizer is
        // in neither Envoy's group and cannot chgrp to it); a socket may not.
        for (what, mode, special) in [
            ("directory", self.dir_mode, SETGID),
            ("socket", self.socket_mode, 0),
        ] {
            anyhow::ensure!(
                mode & !special <= 0o777 && (mode & 0o777).trailing_zeros() >= 3,
                "the {what} mode {mode:o} gives access to others or sets a bit it may not: {}",
                self.path.display()
            );
        }
        anyhow::ensure!(
            self.path
                .parent()
                .is_some_and(|p| !p.as_os_str().is_empty()),
            "the socket path {} has no directory",
            self.path.display()
        );
        Ok(())
    }

    /// Bind the socket, failing closed. The directory is checked (a real directory, not a
    /// symlink) or created with nothing created on the way to it, its mode and owner set
    /// before the socket exists; a stale socket is replaced and anything else at the path is
    /// refused; the socket's mode and owner are set and read back.
    pub fn bind(&self) -> anyhow::Result<UnixListener> {
        self.validate()?;
        let Some(dir) = self.path.parent() else {
            anyhow::bail!("the socket path {} has no directory", self.path.display());
        };
        match std::fs::symlink_metadata(dir) {
            Ok(m) if m.file_type().is_symlink() => {
                anyhow::bail!("{} is a symlink, not a directory of its own", dir.display())
            }
            Ok(m) if !m.is_dir() => anyhow::bail!("{} is not a directory", dir.display()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .mode(self.dir_mode)
                    .create(dir)
                    .map_err(|e| anyhow::anyhow!("creating {}: {e}", dir.display()))?;
            }
            Err(e) => anyhow::bail!("{}: {e}", dir.display()),
        }
        // The owner first, the mode last: a chown can clear the setgid bit on some systems, and the mode has the last word.
        self.chown(dir)?;
        // Only when it differs: a unit with `RestrictSUIDSGID=yes` cannot set the setgid bit (EPERM), and its root `ExecStartPre` made the
        // directory at the mode wanted, so a directory that is already right is left alone and the hardening stays on.
        if dir_mode_differs(dir, self.dir_mode)? {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(self.dir_mode))
                .map_err(|e| {
                    anyhow::anyhow!(
                        "setting mode {:o} on {}: {e} (a unit with RestrictSUIDSGID=yes cannot set the setgid bit: make the directory at that mode before the authorizer starts)",
                        self.dir_mode,
                        dir.display()
                    )
                })?;
        }
        match std::fs::symlink_metadata(&self.path) {
            Ok(m) if m.file_type().is_socket() => std::fs::remove_file(&self.path)?,
            Ok(_) => anyhow::bail!("{} exists and is not a socket", self.path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => anyhow::bail!("{}: {e}", self.path.display()),
        }
        let listener = UnixListener::bind(&self.path)
            .map_err(|e| anyhow::anyhow!("binding {}: {e}", self.path.display()))?;
        std::fs::set_permissions(
            &self.path,
            std::fs::Permissions::from_mode(self.socket_mode),
        )?;
        self.chown(&self.path)?;
        let mode = std::fs::metadata(&self.path)?.permissions().mode() & 0o7777;
        anyhow::ensure!(
            mode == self.socket_mode,
            "{} has mode {mode:o}, not {:o}",
            self.path.display(),
            self.socket_mode
        );
        Ok(listener)
    }

    fn chown(&self, path: &Path) -> anyhow::Result<()> {
        if self.owner.is_some() || self.group.is_some() {
            std::os::unix::fs::chown(path, self.owner, self.group)
                .map_err(|e| anyhow::anyhow!("chown {}: {e}", path.display()))?;
        }
        Ok(())
    }
}

/// Whether `dir`'s permission bits (including setgid) are not already `wanted`.
fn dir_mode_differs(dir: &Path, wanted: u32) -> std::io::Result<bool> {
    Ok(std::fs::metadata(dir)?.permissions().mode() & 0o7777 != wanted)
}

/// The two sockets never share a directory: the directory carries each Envoy's access, so a
/// shared one would let the tunnel Envoy's group reach the inject socket.
pub fn check_layout(tunnel: Option<&Path>, inject: Option<&Path>) -> anyhow::Result<()> {
    if let (Some(t), Some(i)) = (tunnel, inject) {
        anyhow::ensure!(
            t.parent() != i.parent(),
            "the check socket {} and the inject socket {} share a directory; each Envoy's group needs its own",
            t.display(),
            i.display()
        );
    }
    Ok(())
}

/// The numeric id of `name` in a passwd- or group-format file's contents: the third field of
/// the line whose first is `name`.
#[must_use]
pub fn lookup_id(contents: &str, name: &str) -> Option<u32> {
    if name.is_empty() {
        return None;
    }
    contents
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .find_map(|l| {
            let mut f = l.split(':');
            (f.next()? == name).then_some(())?;
            f.nth(1)?.parse().ok()
        })
}

/// A number as it is, a name looked up in `account_file` (`/etc/passwd` or `/etc/group`).
pub fn resolve_id(spec: &str, account_file: &Path) -> anyhow::Result<u32> {
    if let Ok(n) = spec.parse::<u32>() {
        return Ok(n);
    }
    let text = std::fs::read_to_string(account_file)
        .map_err(|e| anyhow::anyhow!("{}: {e}", account_file.display()))?;
    lookup_id(&text, spec)
        .ok_or_else(|| anyhow::anyhow!("{spec:?} is not in {}", account_file.display()))
}

/// The `Check` service over one [`Authorizer`], for one kind of Envoy.
pub struct Checks {
    authorizer: Arc<Authorizer>,
    kind: SocketKind,
}

impl Checks {
    /// A tunnel service answering from `authorizer`.
    #[must_use]
    pub fn new(authorizer: Arc<Authorizer>) -> Self {
        Self {
            authorizer,
            kind: SocketKind::Tunnel,
        }
    }

    /// An inject service answering from `authorizer`.
    #[must_use]
    pub fn inject(authorizer: Arc<Authorizer>) -> Self {
        Self {
            authorizer,
            kind: SocketKind::Inject,
        }
    }

    /// What one check says, as Envoy filled it: the peer's principal, the method and the
    /// authority. Anything absent is empty, which the authorizer refuses.
    fn fields(request: CheckRequest) -> (String, String, String) {
        let (peer, method, host, _) = Self::fields_with_path(request);
        (peer, method, host)
    }

    /// The same with the request path, which an inject check needs for the rules.
    fn fields_with_path(request: CheckRequest) -> (String, String, String, String) {
        let attributes = request.attributes.unwrap_or_default();
        let peer = attributes.source.map(|s| s.principal).unwrap_or_default();
        let http = attributes.request.and_then(|r| r.http).unwrap_or_default();
        (peer, http.method, http.host, http.path)
    }

    /// Answer one check: `OK` to allow, `PERMISSION_DENIED` with the code otherwise, the
    /// same code as the `403` body the client gets.
    pub async fn answer(&self, request: CheckRequest) -> CheckResponse {
        match self.kind {
            SocketKind::Tunnel => self.answer_tunnel(request).await,
            SocketKind::Inject => self.answer_inject(request).await,
        }
    }

    async fn answer_tunnel(&self, request: CheckRequest) -> CheckResponse {
        let (peer, method, authority) = Self::fields(request);
        let d = self.authorizer.authorize(&peer, &method, &authority).await;
        let served = match d.served {
            Served::Cache => "cache",
            Served::Broker => "broker",
            Served::Stale => "stale",
            Served::None => "none",
        };
        if let Some(uid) = d.claim_uid {
            self.authorizer.report(GatewayDecision {
                at: jiff::Timestamp::now(),
                claim_uid: uid,
                kind: DecisionKind::Tunnel,
                authority: authority.clone(),
                audience: None,
                verdict: verdict_of(d.verdict.as_ref().err().copied()),
                reason: d.verdict.as_ref().err().map(|w| w.code().to_owned()),
                served: Some(served.to_owned()),
            });
        }
        let claim_uid = d.claim_uid.map(|u| u.to_string()).unwrap_or_default();
        match d.verdict {
            Ok(()) => {
                tracing::info!(
                    claim_uid,
                    peer,
                    authority,
                    served,
                    verdict = "allow",
                    "tunnel"
                );
                CheckResponse::with_status(Status::ok(""))
            }
            Err(why) => {
                tracing::info!(
                    claim_uid,
                    peer,
                    authority,
                    served,
                    verdict = "deny",
                    reason = why.code(),
                    "tunnel"
                );
                denied(why)
            }
        }
    }

    /// One inject check. The decision line is the claim UID, the audience, the host, the
    /// verdict and the reason: never the credential, a header, the path or the query.
    async fn answer_inject(&self, request: CheckRequest) -> CheckResponse {
        let (peer, method, host, path) = Self::fields_with_path(request);
        let d = self
            .authorizer
            .authorize_inject(&peer, &method, &host, &path)
            .await;
        if let Some(uid) = d.claim_uid {
            self.authorizer.report(GatewayDecision {
                at: jiff::Timestamp::now(),
                claim_uid: uid,
                kind: DecisionKind::Inject,
                authority: d.host.clone(),
                audience: d.audience.clone(),
                verdict: verdict_of(d.verdict.as_ref().err().copied()),
                reason: d.verdict.as_ref().err().map(|w| w.code().to_owned()),
                served: None,
            });
        }
        let claim_uid = d.claim_uid.map(|u| u.to_string()).unwrap_or_default();
        let audience = d.audience.unwrap_or_default();
        match d.verdict {
            Ok(allow) => {
                tracing::info!(
                    claim_uid,
                    audience,
                    host = d.host,
                    verdict = "allow",
                    "inject"
                );
                allowed(&allow)
            }
            Err(why) => {
                tracing::info!(
                    claim_uid,
                    audience,
                    host = d.host,
                    verdict = "deny",
                    reason = why.code(),
                    "inject"
                );
                denied(why)
            }
        }
    }
}

/// A reported decision's verdict: allow, or deny for any refusal.
const fn verdict_of(refusal: Option<Refusal>) -> DecisionVerdict {
    match refusal {
        None => DecisionVerdict::Allow,
        Some(_) => DecisionVerdict::Deny,
    }
}

/// `PERMISSION_DENIED` with the refusal's code, and the `403` body Envoy returns to the client.
fn denied(why: Refusal) -> CheckResponse {
    let mut denied = DeniedHttpResponseBuilder::new();
    denied
        .set_http_status(HttpStatusCode::Forbidden)
        // Marks a refusal as the gateway's own: the guest's proxy turns it into `502 gateway_refused`, and an
        // upstream's own 403 (which cannot carry a header the gateway adds only on a refusal) passes through.
        .add_header(
            "x-mediatore-refusal",
            why.code(),
            Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
            false,
        )
        .set_body(format!("{}\n", why.code()));
    let mut response = CheckResponse::with_status(Status::permission_denied(why.code()));
    response.set_http_response(denied);
    response
}

/// `OK` with the headers set by overwrite (a client's copy of the same name is replaced, never
/// appended to) and the other credential-bearing headers removed.
fn allowed(allow: &InjectAllow) -> CheckResponse {
    let overwrite = Some(HeaderAppendAction::OverwriteIfExistsOrAdd);
    let mut ok = OkHttpResponseBuilder::new();
    ok.add_header(&allow.header, allow.value.0.clone(), overwrite, false);
    for h in &allow.extra_headers {
        ok.add_header(&h.name, &h.value, overwrite, false);
    }
    for h in &allow.remove_headers {
        ok.remove_header(h);
    }
    let mut response = CheckResponse::with_status(Status::ok(""));
    response.set_http_response(ok);
    response
}

#[tonic::async_trait]
impl Authorization for Checks {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        Ok(Response::new(self.answer(request.into_inner()).await))
    }
}

/// Serve tunnel checks on `listener` until it fails.
pub async fn serve(authorizer: Arc<Authorizer>, listener: TcpListener) -> anyhow::Result<()> {
    let incoming = tonic::transport::server::TcpIncoming::from(listener).with_nodelay(Some(true));
    tonic::transport::Server::builder()
        .add_service(AuthorizationServer::new(Checks::new(authorizer)))
        .serve_with_incoming(incoming)
        .await?;
    anyhow::bail!("the authorizer's listener ended")
}

/// Serve `kind` checks on a unix socket until it fails.
pub async fn serve_unix(
    authorizer: Arc<Authorizer>,
    listener: UnixListener,
    kind: SocketKind,
) -> anyhow::Result<()> {
    let checks = match kind {
        SocketKind::Tunnel => Checks::new(authorizer),
        SocketKind::Inject => Checks::inject(authorizer),
    };
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
    tonic::transport::Server::builder()
        .add_service(AuthorizationServer::new(checks))
        .serve_with_incoming(incoming)
        .await?;
    anyhow::bail!("the authorizer's unix listener ended")
}

/// The broker client under the authorizer's own identity, `spiffe://<td>/gateway/authorizer`
/// (ADR-0053 decision 2): its SVID from the Workload API, selected by ID, or under the `dev`
/// feature the same ID as a header. Any other name, or none in time, is a failed start.
async fn broker_for(args: &GatewayArgs) -> anyhow::Result<Broker> {
    #[cfg(feature = "dev")]
    {
        if let Some(id) = &args.dev_spiffe_id {
            crate::broker::ensure_authorizer(&mediatore_tls::SpiffeId::new(id)?)?;
            return Ok(Broker::dev_header(&args.mediatore_url, id));
        }
    }
    Broker::connect(&args.mediatore_url, &args.workload_api_socket).await
}

/// `mediatore gateway`: the authorizer, its identity from the Workload API. The tunnel check
/// on loopback TCP or a unix socket, and, with `--inject-socket`, the inject check on its own.
pub async fn run(args: GatewayArgs) -> anyhow::Result<()> {
    check_layout(args.check_socket.as_deref(), args.inject_socket.as_deref())?;
    if args.check_socket.is_none() {
        anyhow::ensure!(
            args.listen.ip().is_loopback(),
            "the authorizer listens on loopback only, for Envoy; got {}",
            args.listen
        );
    }
    let owner = args
        .socket_owner
        .as_deref()
        .map(|o| resolve_id(o, Path::new("/etc/passwd")))
        .transpose()?;
    let socket = |path: &Path, group: Option<&str>| -> anyhow::Result<UnixSocket> {
        let s = UnixSocket {
            path: path.to_owned(),
            dir_mode: args.socket_dir_mode,
            socket_mode: args.socket_mode,
            owner,
            group: group
                .map(|g| resolve_id(g, Path::new("/etc/group")))
                .transpose()?,
        };
        s.validate()?;
        Ok(s)
    };
    let check_socket = args
        .check_socket
        .as_deref()
        .map(|p| socket(p, args.check_socket_group.as_deref()))
        .transpose()?;
    let inject_socket = args
        .inject_socket
        .as_deref()
        .map(|p| socket(p, args.inject_socket_group.as_deref()))
        .transpose()?;
    let broker = broker_for(&args).await?;
    let trust_domain = broker.trust_domain()?;
    let cfg = CacheConfig {
        fresh_for: std::time::Duration::from_secs(args.fresh_secs),
        stale_for: std::time::Duration::from_secs(args.stale_secs),
        max_claims: args.max_claims,
        ..CacheConfig::default()
    };
    let name = crate::report::gateway_name(args.name.as_deref())?;
    let broker = Arc::new(broker);
    let (reporter, _reporting) = crate::report::Reporter::spawn(
        name.clone(),
        broker.clone(),
        crate::report::EVERY,
        Some(crate::probes::Inbox::open(&args.probes_dir)),
    );
    let mut authorizer =
        Authorizer::new(&trust_domain, broker.clone(), cfg).with_reporter(reporter);
    tracing::info!(
        gateway = name,
        "reporting decisions to the broker under this name (ADR-0062)"
    );
    if inject_socket.is_some() {
        authorizer = authorizer.with_credentials(broker);
    }
    let authorizer = Arc::new(authorizer);
    // A gateway-placed credential lives for its claim and not past it: the sweep notices a release without a request
    // for the claim, so the credential leaves memory within `sweep_every` of it (ADR-0040 decision 5).
    let sweeper = inject_socket.is_some().then(|| authorizer.spawn_sweeper());
    let tunnel = async {
        if let Some(s) = &check_socket {
            let listener = s.bind()?;
            tracing::info!(socket = %s.path.display(), trust_domain, "gateway authorizer listening (tunnel checks)");
            serve_unix(authorizer.clone(), listener, SocketKind::Tunnel).await
        } else {
            let listener = TcpListener::bind(args.listen).await?;
            tracing::info!(
                addr = %listener.local_addr()?,
                trust_domain,
                fresh_secs = args.fresh_secs,
                stale_secs = args.stale_secs,
                max_claims = args.max_claims,
                "gateway authorizer listening"
            );
            serve(authorizer.clone(), listener).await
        }
    };
    let inject = async {
        match &inject_socket {
            Some(s) => {
                let listener = s.bind()?;
                tracing::info!(socket = %s.path.display(), "gateway authorizer listening (inject checks)");
                serve_unix(authorizer.clone(), listener, SocketKind::Inject).await
            }
            None => std::future::pending().await,
        }
    };
    let served = tokio::try_join!(tunnel, inject).map(|((), ())| ());
    if let Some(sweeper) = sweeper {
        sweeper.abort();
    }
    served
}

#[cfg(test)]
mod tests {
    use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
    use envoy_types::pb::envoy::service::auth::v3::attribute_context::{
        HttpRequest, Peer, Request as HttpAttributes,
    };

    use super::*;

    #[test]
    fn a_check_is_read_from_the_principal_the_method_and_the_host_and_absent_parts_are_empty() {
        let full = CheckRequest {
            attributes: Some(AttributeContext {
                source: Some(Peer {
                    principal: "spiffe://sandbox.test/banlieue/claim/x".into(),
                    ..Default::default()
                }),
                request: Some(HttpAttributes {
                    http: Some(HttpRequest {
                        method: "CONNECT".into(),
                        host: "api.home.example:443".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        assert_eq!(
            Checks::fields(full),
            (
                "spiffe://sandbox.test/banlieue/claim/x".into(),
                "CONNECT".into(),
                "api.home.example:443".into()
            )
        );
        assert_eq!(
            Checks::fields(CheckRequest { attributes: None }),
            (String::new(), String::new(), String::new())
        );
    }

    // ----- inject checks and the unix sockets (ADR-0040 decisions 4 and 6) -------------------------------------

    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use envoy_types::pb::envoy::config::core::v3::HeaderValueOption;
    use envoy_types::pb::envoy::config::core::v3::header_value_option::HeaderAppendAction;
    use envoy_types::pb::envoy::service::auth::v3::authorization_client::AuthorizationClient;
    use mediatore_proto::{
        ClaimEgress, EndpointRule, GatewayCredential, HeaderPair, InjectRoute, Secret, Subject,
    };
    use uuid::Uuid;

    use crate::broker::{Allowlists, Answer, AskError, CredentialAnswer, Credentials};

    const TD: &str = "sandbox.test";
    const SECRET: &str = "sk-ant-oat01-NEVER-LOG-THIS";

    struct FakeAllow;

    #[async_trait::async_trait]
    impl Allowlists for FakeAllow {
        async fn ask(&self, _: Uuid) -> Result<Answer, AskError> {
            let route = InjectRoute {
                audience: "anthropic".into(),
                endpoint: "api.anthropic.example:443".parse().unwrap(),
                rules: vec![EndpointRule {
                    method: "POST".into(),
                    path: "/v1/messages".into(),
                }],
                header: "x-api-key".into(),
                extra_headers: vec![HeaderPair {
                    name: "anthropic-version".into(),
                    value: "2023-06-01".into(),
                }],
            };
            Ok(Answer::Found(ClaimEgress {
                claim_uid: Uuid::nil(),
                expires_at: jiff::Timestamp::now() + jiff::SignedDuration::from_secs(600),
                egress: vec![route.endpoint.clone()],
                inject: vec![route],
            }))
        }
    }

    struct FakeCreds(AtomicUsize);

    #[async_trait::async_trait]
    impl Credentials for FakeCreds {
        async fn credential(&self, _: Uuid, _: &str) -> Result<CredentialAnswer, AskError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(CredentialAnswer::Found(GatewayCredential {
                audience: "anthropic".into(),
                subject: Subject {
                    issuer: "https://login.example.test".into(),
                    id: "octocat".into(),
                    display: None,
                },
                header: "x-api-key".into(),
                value: Secret(SECRET.into()),
                extra_headers: vec![HeaderPair {
                    name: "anthropic-version".into(),
                    value: "2023-06-01".into(),
                }],
                expires_at: jiff::Timestamp::now() + jiff::SignedDuration::from_secs(200),
            }))
        }
    }

    #[tokio::test]
    async fn each_decision_about_a_claim_is_reported_and_one_about_no_claim_is_not() {
        // ADR-0062 decisions 1 and 2: the tunnel check's claim, authority, verdict and reason
        // reach the reporter; a peer that is no claim leaves only the gateway's own line.
        let (reporter, mut rx) = crate::report::Reporter::queue(8);
        let a = Authorizer::new(TD, Arc::new(FakeAllow), CacheConfig::default())
            .with_reporter(reporter);
        let checks = Checks::new(Arc::new(a));
        let uid = Uuid::new_v4();
        checks
            .answer(check(
                &claim_peer(uid),
                "CONNECT",
                "api.anthropic.example:443",
                "",
            ))
            .await;
        checks
            .answer(check(
                &claim_peer(uid),
                "CONNECT",
                "elsewhere.example:443",
                "",
            ))
            .await;
        checks
            .answer(check(
                "spiffe://x/y",
                "CONNECT",
                "api.anthropic.example:443",
                "",
            ))
            .await;
        let allowed = rx.try_recv().expect("the allow");
        assert_eq!(
            (allowed.claim_uid, allowed.kind, allowed.authority.as_str()),
            (uid, DecisionKind::Tunnel, "api.anthropic.example:443")
        );
        assert_eq!(allowed.verdict, DecisionVerdict::Allow);
        assert_eq!(allowed.reason, None);
        assert_eq!(allowed.served.as_deref(), Some("broker"));
        let denied = rx.try_recv().expect("the deny");
        assert_eq!(denied.authority, "elsewhere.example:443");
        assert_eq!(denied.verdict, DecisionVerdict::Deny);
        assert_eq!(denied.reason.as_deref(), Some("not_allowed"));
        assert!(rx.try_recv().is_err(), "no report without a claim");
    }

    fn authorizer() -> (Arc<Authorizer>, Arc<FakeCreds>) {
        let creds = Arc::new(FakeCreds(AtomicUsize::new(0)));
        let a = Authorizer::new(TD, Arc::new(FakeAllow), CacheConfig::default())
            .with_credentials(creds.clone());
        (Arc::new(a), creds)
    }

    fn check(peer: &str, method: &str, host: &str, path: &str) -> CheckRequest {
        CheckRequest {
            attributes: Some(AttributeContext {
                source: Some(Peer {
                    principal: peer.into(),
                    ..Default::default()
                }),
                request: Some(HttpAttributes {
                    http: Some(HttpRequest {
                        method: method.into(),
                        host: host.into(),
                        path: path.into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }
    }

    fn claim_peer(uid: Uuid) -> String {
        format!("spiffe://{TD}/banlieue/claim/{uid}")
    }

    fn ok_headers(r: &CheckResponse) -> Option<(&Vec<HeaderValueOption>, &Vec<String>)> {
        match r.http_response.as_ref()? {
            envoy_types::ext_authz::v3::pb::HttpResponse::OkResponse(ok) => {
                Some((&ok.headers, &ok.headers_to_remove))
            }
            _ => None,
        }
    }

    #[test]
    fn a_check_also_carries_the_path_and_never_anything_the_client_set() {
        let req = check(
            "spiffe://x/y",
            "POST",
            "api.example",
            "/v1/messages?beta=true",
        );
        assert_eq!(
            Checks::fields_with_path(req),
            (
                "spiffe://x/y".into(),
                "POST".into(),
                "api.example".into(),
                "/v1/messages?beta=true".into()
            )
        );
        assert_eq!(
            Checks::fields_with_path(CheckRequest { attributes: None }),
            (String::new(), String::new(), String::new(), String::new())
        );
    }

    #[tokio::test]
    async fn an_allowed_inject_check_sets_the_credential_by_overwrite_and_removes_the_other_headers()
     {
        let (a, _) = authorizer();
        let r = Checks::inject(a)
            .answer(check(
                &claim_peer(Uuid::new_v4()),
                "POST",
                "api.anthropic.example",
                "/v1/messages",
            ))
            .await;
        assert_eq!(r.status.as_ref().unwrap().code, 0, "OK");
        let (headers, remove) = ok_headers(&r).expect("an OK response");
        let by_name = |n: &str| {
            headers
                .iter()
                .find(|h| h.header.as_ref().unwrap().key == n)
                .unwrap_or_else(|| panic!("no header {n}"))
        };
        for name in ["x-api-key", "anthropic-version"] {
            assert_eq!(
                by_name(name).append_action,
                i32::from(HeaderAppendAction::OverwriteIfExistsOrAdd),
                "{name}: a client's copy is replaced, never appended to"
            );
        }
        assert_eq!(by_name("x-api-key").header.as_ref().unwrap().value, SECRET);
        assert_eq!(
            by_name("anthropic-version").header.as_ref().unwrap().value,
            "2023-06-01"
        );
        assert_eq!(
            remove,
            &vec!["authorization".to_owned()],
            "never the credential's own header"
        );
        assert!(r.dynamic_metadata.is_none());
    }

    #[tokio::test]
    async fn a_refused_inject_check_is_the_same_403_shape_with_the_code_and_no_credential() {
        let (a, creds) = authorizer();
        let checks = Checks::inject(a);
        for (peer, method, host, path, code) in [
            (
                format!("spiffe://{TD}/gateway"),
                "POST",
                "api.anthropic.example",
                "/v1/messages",
                "not_a_claim",
            ),
            (
                claim_peer(Uuid::new_v4()),
                "CONNECT",
                "api.anthropic.example:443",
                "",
                "not_inject",
            ),
            (
                claim_peer(Uuid::new_v4()),
                "POST",
                "other.example",
                "/v1/messages",
                "not_allowed",
            ),
            (
                claim_peer(Uuid::new_v4()),
                "GET",
                "api.anthropic.example",
                "/v1/messages",
                "not_allowed",
            ),
        ] {
            let r = checks.answer(check(&peer, method, host, path)).await;
            let status = r.status.as_ref().unwrap();
            assert_eq!(status.code, tonic::Code::PermissionDenied as i32, "{code}");
            assert_eq!(status.message, code);
            match r.http_response.as_ref().unwrap() {
                envoy_types::ext_authz::v3::pb::HttpResponse::DeniedResponse(d) => {
                    assert_eq!(
                        d.status.as_ref().unwrap().code,
                        HttpStatusCode::Forbidden as i32
                    );
                    assert_eq!(d.body, format!("{code}\n"));
                    // The guest's proxy turns a response carrying this header into `502 gateway_refused`
                    // (a refusal by the gateway itself, as opposed to the upstream's own 403).
                    let marker: Vec<(&str, &str)> = d
                        .headers
                        .iter()
                        .map(|h| {
                            let h = h.header.as_ref().unwrap();
                            (h.key.as_str(), h.value.as_str())
                        })
                        .collect();
                    assert_eq!(marker, [("x-mediatore-refusal", code)], "{code}");
                }
                _ => panic!("{code}: not a denied response"),
            }
            assert!(!format!("{r:?}").contains(SECRET));
        }
        assert_eq!(
            creds.0.load(Ordering::SeqCst),
            0,
            "no refused check reached the credential route"
        );
    }

    #[tokio::test]
    async fn the_tunnel_check_refuses_an_inject_question_outright() {
        let (a, creds) = authorizer();
        let r = Checks::new(a)
            .answer(check(
                &claim_peer(Uuid::new_v4()),
                "POST",
                "api.anthropic.example",
                "/v1/messages",
            ))
            .await;
        assert_eq!(
            r.status.as_ref().unwrap().code,
            tonic::Code::PermissionDenied as i32
        );
        assert_eq!(r.status.as_ref().unwrap().message, "not_connect");
        assert!(ok_headers(&r).is_none());
        assert_eq!(
            creds.0.load(Ordering::SeqCst),
            0,
            "the tunnel socket cannot reach a credential"
        );
        assert!(!format!("{r:?}").contains(SECRET));
    }

    /// Captured tracing output, as bytes.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// One global capture for the whole test binary: a scoped subscriber races with the callsite
    /// interest cache when tests run in parallel, and a global one does not. Tests pick out their
    /// own lines by their own claim UID.
    fn captured_logs() -> &'static Captured {
        static LOGS: std::sync::OnceLock<Captured> = std::sync::OnceLock::new();
        LOGS.get_or_init(|| {
            let captured = Captured::default();
            let _ = tracing_subscriber::fmt()
                .with_writer(captured.clone())
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .try_init();
            captured
        })
    }

    #[tokio::test]
    async fn the_credential_is_in_no_log_line_and_the_decision_line_carries_five_fields_only() {
        let logs = captured_logs();
        let (a, _) = authorizer();
        let checks = Checks::inject(a);
        let uid = Uuid::new_v4();
        checks
            .answer(check(
                &claim_peer(uid),
                "POST",
                "api.anthropic.example",
                "/v1/messages?secret-in-query=1",
            ))
            .await;
        checks
            .answer(check(
                &claim_peer(uid),
                "GET",
                "api.anthropic.example",
                "/v1/messages",
            ))
            .await;
        let out = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert!(
            !out.contains(SECRET),
            "the credential reached a log:\n{out}"
        );
        assert!(
            !out.contains("secret-in-query"),
            "a query string reached a log:\n{out}"
        );
        let mine = uid.to_string();
        let lines: Vec<&str> = out.lines().filter(|l| l.contains(&mine)).collect();
        assert_eq!(lines.len(), 2, "one line per decision:\n{out}");
        for field in ["claim_uid=", "audience=", "host=", "verdict="] {
            assert!(lines[0].contains(field), "{field} missing: {}", lines[0]);
        }
        assert!(
            lines[0].contains("verdict=\"allow\"") && lines[1].contains("verdict=\"deny\""),
            "{lines:?}"
        );
        assert!(lines[1].contains("reason=\"not_allowed\""), "{}", lines[1]);
        for absent in [
            "peer=",
            "path=",
            "method=",
            "served=",
            "x-api-key",
            "anthropic-version",
        ] {
            assert!(
                lines.iter().all(|l| !l.contains(absent)),
                "{absent} must not be on a decision line: {lines:?}"
            );
        }
    }

    /// A short directory under `/tmp`: a unix socket path must fit in `SUN_LEN` (104 bytes), which
    /// the testkit's deeper temp directories do not on every machine. Removed on drop.
    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Self {
            let id = Uuid::new_v4().simple().to_string();
            let dir = PathBuf::from("/tmp").join(format!("mg-{}", &id[..8]));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }

    impl std::ops::Deref for Tmp {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn me() -> (u32, u32) {
        let m = std::fs::metadata(mediatore_testkit::tempdir()).unwrap();
        (m.uid(), m.gid())
    }

    fn sock(dir: &Path, name: &str) -> UnixSocket {
        let (uid, gid) = me();
        UnixSocket {
            path: dir.join(name).join(format!("{name}.sock")),
            dir_mode: 0o750,
            socket_mode: 0o660,
            owner: Some(uid),
            group: Some(gid),
        }
    }

    #[tokio::test]
    async fn a_socket_is_bound_in_its_own_directory_at_the_modes_and_the_owner_asked() {
        let tmp = Tmp::new();
        let s = sock(&tmp, "i");
        let _l = s.bind().expect("bound");
        let dir = s.path.parent().unwrap();
        assert_eq!(mode_of(dir), 0o750, "the directory carries the access");
        assert_eq!(mode_of(&s.path), 0o660);
        assert!(
            std::fs::symlink_metadata(&s.path)
                .unwrap()
                .file_type()
                .is_socket()
        );
        let (uid, gid) = me();
        let m = std::fs::metadata(&s.path).unwrap();
        assert_eq!((m.uid(), m.gid()), (uid, gid));
        let d = std::fs::metadata(dir).unwrap();
        assert_eq!((d.uid(), d.gid()), (uid, gid));
    }

    #[tokio::test]
    async fn a_stale_socket_is_replaced_and_anything_else_at_the_path_fails_closed() {
        let tmp = Tmp::new();
        let s = sock(&tmp, "i");
        drop(s.bind().unwrap());
        assert!(s.path.exists(), "left behind by the dead process");
        drop(s.bind().expect("a stale socket is replaced"));
        let t = sock(&tmp, "j");
        std::fs::create_dir_all(t.path.parent().unwrap()).unwrap();
        std::fs::write(&t.path, b"not a socket").unwrap();
        let err = t.bind().unwrap_err().to_string();
        assert!(err.contains("not a socket"), "{err}");
        assert_eq!(
            std::fs::read(&t.path).unwrap(),
            b"not a socket",
            "left alone"
        );
    }

    #[tokio::test]
    async fn a_path_in_a_bad_directory_fails_closed() {
        let tmp = Tmp::new();
        // the parent's parent is missing: nothing is created on the way
        let mut s = sock(&tmp, "i");
        s.path = tmp.join("missing/deeper/i.sock");
        assert!(s.bind().is_err());
        assert!(
            !tmp.join("missing").exists(),
            "no directory created on the way"
        );
        // the parent is a file
        let file = tmp.join("afile");
        std::fs::write(&file, b"x").unwrap();
        let mut s = sock(&tmp, "i");
        s.path = file.join("i.sock");
        assert!(s.bind().is_err());
        // the parent is a symlink
        let real = tmp.join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, tmp.join("link")).unwrap();
        let mut s = sock(&tmp, "i");
        s.path = tmp.join("link/i.sock");
        let err = s.bind().unwrap_err().to_string();
        assert!(err.contains("symlink"), "{err}");
        // no path at all
        let mut s = sock(&tmp, "i");
        s.path = "i.sock".into();
        assert!(s.bind().is_err());
    }

    #[test]
    fn modes_that_open_a_socket_to_everyone_are_refused() {
        assert_eq!(parse_mode("0750").unwrap(), 0o750);
        assert_eq!(parse_mode("660").unwrap(), 0o660);
        for bad in ["", "9", "0xff", "01777", "0757", "0666", "0660x"] {
            assert!(parse_mode(bad).is_err(), "{bad:?}");
        }
        let tmp = Tmp::new();
        let mut s = sock(&tmp, "i");
        s.socket_mode = 0o666;
        assert!(s.validate().is_err(), "world-writable socket");
        let mut s = sock(&tmp, "i");
        s.dir_mode = 0o755;
        assert!(s.validate().is_err(), "world-readable directory");
    }

    #[tokio::test]
    async fn a_directory_may_be_setgid_so_a_socket_takes_its_envoys_group_and_nothing_else_special()
    {
        // The authorizer is in neither Envoy's group and so cannot chgrp a socket to it; a setgid directory owned by
        // that group makes the socket inherit it. The setgid bit is the one special bit allowed, on a directory only.
        assert_eq!(parse_mode("2750").unwrap(), 0o2750);
        assert_eq!(parse_mode("02750").unwrap(), 0o2750);
        for bad in ["4750", "1750", "6750", "2755", "2777", "2757"] {
            assert!(parse_mode(bad).is_err(), "{bad:?}");
        }
        let tmp = Tmp::new();
        let mut s = sock(&tmp, "i");
        s.dir_mode = 0o2750;
        assert!(s.validate().is_ok(), "a setgid directory");
        s.socket_mode = 0o2660;
        assert!(
            s.validate().is_err(),
            "setgid on the socket itself is refused"
        );
        let mut s = sock(&tmp, "g");
        s.dir_mode = 0o2750;
        let _l = s.bind().expect("binds in a setgid directory");
        let dir = s.path.parent().unwrap();
        assert_eq!(
            std::fs::metadata(dir).unwrap().permissions().mode() & 0o7777,
            0o2750,
            "the setgid bit survives the bind"
        );
    }

    #[test]
    fn a_directory_already_at_the_wanted_mode_is_not_chmodded_again() {
        // A hardened unit (`RestrictSUIDSGID=yes`) cannot set the setgid bit, and its root `ExecStartPre` already made the directory at
        // the mode the authorizer wants: the authorizer must leave a directory that is right alone, since any chmod to a setgid mode is
        // refused there with EPERM (found rolling v0.2.8 on a gateway).
        let tmp = Tmp::new();
        let dir = tmp.join("d");
        std::fs::create_dir(&dir).unwrap();
        // A group the test user belongs to: setgid on a directory of another group is dropped silently, as the unit's user finds.
        let (uid, gid) = me();
        std::os::unix::fs::chown(&dir, Some(uid), Some(gid)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(
            !dir_mode_differs(&dir, 0o750).unwrap(),
            "the same mode is no change"
        );
        assert!(
            dir_mode_differs(&dir, 0o2750).unwrap(),
            "a setgid bit that is missing is a change"
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o2750)).unwrap();
        assert!(!dir_mode_differs(&dir, 0o2750).unwrap());
        assert!(
            dir_mode_differs(&dir, 0o750).unwrap(),
            "a setgid bit that must go is a change"
        );
        assert!(
            dir_mode_differs(&tmp.join("missing"), 0o750).is_err(),
            "a directory that is not there is an error, not a no-change"
        );
    }

    #[tokio::test]
    async fn a_directory_made_at_the_wanted_setgid_mode_binds_and_keeps_it() {
        // What the unit's root `ExecStartPre` leaves behind: the directory exists at 2750 before the authorizer starts.
        let tmp = Tmp::new();
        let mut s = sock(&tmp, "p");
        s.dir_mode = 0o2750;
        let dir = s.path.parent().unwrap();
        std::fs::create_dir(dir).unwrap();
        let (uid, gid) = me();
        std::os::unix::fs::chown(dir, Some(uid), Some(gid)).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o2750)).unwrap();
        let _l = s
            .bind()
            .expect("binds in a directory that is already right");
        assert_eq!(mode_of(dir), 0o2750, "and it stays setgid");
    }

    #[test]
    fn the_two_sockets_never_share_a_directory_and_each_is_the_one_envoys() {
        let a = Path::new("/run/mediatore-gateway/check/check.sock");
        let b = Path::new("/run/mediatore-gateway/inject/inject.sock");
        assert!(check_layout(Some(a), Some(b)).is_ok());
        assert!(check_layout(Some(a), None).is_ok());
        assert!(check_layout(None, Some(b)).is_ok());
        let same = Path::new("/run/mediatore-gateway/check/inject.sock");
        let err = check_layout(Some(a), Some(same)).unwrap_err().to_string();
        assert!(
            err.contains("directory"),
            "one Envoy's group would reach the other's socket: {err}"
        );
        assert!(check_layout(Some(a), Some(a)).is_err());
    }

    #[test]
    fn user_and_group_names_resolve_from_the_account_files_and_numbers_are_taken_as_they_are() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\nmediatore-gateway:x:995:994::/nonexistent:/usr/sbin/nologin\n# c\nenvoy:x:996:995::/:/bin/false\n";
        assert_eq!(lookup_id(passwd, "mediatore-gateway"), Some(995));
        assert_eq!(lookup_id(passwd, "envoy"), Some(996));
        assert_eq!(lookup_id(passwd, "nobody"), None);
        assert_eq!(lookup_id(passwd, ""), None);
        assert_eq!(resolve_id("1234", Path::new("/nonexistent")).unwrap(), 1234);
        assert!(
            resolve_id("nobody-here", Path::new("/nonexistent")).is_err(),
            "no file, no name"
        );
    }

    async fn grpc_client(path: &Path) -> AuthorizationClient<tonic::transport::Channel> {
        let path = path.to_owned();
        let channel = tonic::transport::Endpoint::from_static("http://[::]:50051")
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let path = path.clone();
                async move {
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                        tokio::net::UnixStream::connect(path).await?,
                    ))
                }
            }))
            .await
            .expect("connected to the socket");
        AuthorizationClient::new(channel)
    }

    #[tokio::test]
    async fn a_real_grpc_client_gets_the_headers_from_the_inject_socket_and_a_no_from_the_tunnel_socket()
     {
        let tmp = Tmp::new();
        let (a, creds) = authorizer();
        let inject_sock = sock(&tmp, "i");
        let tunnel_sock = sock(&tmp, "t");
        let inject_listener = inject_sock.bind().unwrap();
        let tunnel_listener = tunnel_sock.bind().unwrap();
        tokio::spawn(serve_unix(a.clone(), inject_listener, SocketKind::Inject));
        tokio::spawn(serve_unix(a, tunnel_listener, SocketKind::Tunnel));
        let uid = Uuid::new_v4();
        let ask = check(
            &claim_peer(uid),
            "POST",
            "api.anthropic.example",
            "/v1/messages",
        );

        let r = grpc_client(&inject_sock.path)
            .await
            .check(ask.clone())
            .await
            .unwrap()
            .into_inner();
        assert_eq!(r.status.as_ref().unwrap().code, 0);
        let (headers, remove) = ok_headers(&r).expect("headers over the wire");
        assert!(
            headers
                .iter()
                .any(|h| h.header.as_ref().unwrap().key == "x-api-key"
                    && h.header.as_ref().unwrap().value == SECRET)
        );
        assert_eq!(remove, &vec!["authorization".to_owned()]);

        let r = grpc_client(&tunnel_sock.path)
            .await
            .check(ask)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            r.status.as_ref().unwrap().code,
            tonic::Code::PermissionDenied as i32
        );
        assert!(
            ok_headers(&r).is_none(),
            "the tunnel socket answers no credential"
        );
        assert!(!format!("{r:?}").contains(SECRET));
        assert_eq!(
            creds.0.load(Ordering::SeqCst),
            1,
            "one credential ask, from the inject socket alone"
        );

        // the tunnel question on the tunnel socket still works as before
        let connect = check(&claim_peer(uid), "CONNECT", "api.anthropic.example:443", "");
        let r = grpc_client(&tunnel_sock.path)
            .await
            .check(connect)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            r.status.as_ref().unwrap().code,
            0,
            "the tunnel to the claim's own egress is allowed"
        );
        // and the inject socket refuses a tunnel question
        let connect = check(&claim_peer(uid), "CONNECT", "api.anthropic.example:443", "");
        let r = grpc_client(&inject_sock.path)
            .await
            .check(connect)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(r.status.as_ref().unwrap().message, "not_inject");
    }
}
