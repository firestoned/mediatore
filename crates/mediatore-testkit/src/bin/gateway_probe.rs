// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The gateway kind tier's two ends (`make kind-e2e-gateway`, ADR-0028), test-only, never
//! shipped. `serve` is the destination behind the gateway: a plain or TLS HTTP server
//! answering every request with the host it was asked for. `via-proxy` is the jailed
//! workload: it drives the real `mediatore egress-proxy` beside it as the jail would
//! (`GET /<host:port>/<path>` on loopback, the phantom in `Authorization` when given), one
//! line per check on standard output, a non-zero exit when any check did not end as
//! expected. `check` is the sandbox leg by hand, what the forwarder does inside the proxy:
//! the claim SVID from the Workload API, TLS 1.3 to a gateway, its SVID verified as exactly
//! `spiffe://<td>/gateway`, `CONNECT host:port`, one request inside the tunnel; for probing
//! a gateway from a VM.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use mediatore_tls::{MaterialSource, SpiffeId, WorkloadApiSource};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser)]
#[command(
    name = "gateway-probe",
    about = "The gateway kind tier's workload and destination"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// CONNECT through the gateway as this pod's claim SVID, once per check (the sandbox
    /// leg by hand)
    Check(CheckArgs),
    /// The jailed workload: requests through the egress proxy on loopback, once per check
    ViaProxy(ViaProxyArgs),
    /// A destination: answers every request with the host it was asked for
    Serve {
        /// Address to listen on
        #[arg(long, default_value = "0.0.0.0:8080")]
        listen: String,
        /// Serve TLS with this certificate chain (PEM); with `--tls-key`
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// The certificate's private key (PEM, PKCS#8)
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
    },
}

#[derive(clap::Args)]
struct CheckArgs {
    /// The gateway's sandbox-side address, host:port
    #[arg(long)]
    gateway: String,
    /// The trust domain; the gateway must present spiffe://<td>/gateway
    #[arg(long)]
    trust_domain: String,
    /// SPIRE Workload API socket
    #[arg(
        long,
        env = "SPIFFE_ENDPOINT_SOCKET",
        default_value = "unix:///run/spire/sockets/spire-agent.sock"
    )]
    workload_api_socket: String,
    /// What to ask inside an opened tunnel
    #[arg(long, default_value = "/")]
    path: String,
    /// A check, `authority=expect`: expect `200` (the tunnel opens and the destination
    /// answers), `403:<code>` (the gateway refuses with the authorizer's code), or
    /// `handshake-refused` (the gateway's validator refuses this SVID)
    #[arg(long = "check", required = true)]
    checks: Vec<String>,
}

#[derive(clap::Args)]
struct ViaProxyArgs {
    /// The egress proxy's base URL, as the jail gets it in `MEDIATORE_EGRESS_PROXY`
    #[arg(long, default_value = "http://127.0.0.1:3128")]
    proxy: String,
    /// The phantom token to present on every request; without it, requests go bare
    #[arg(long)]
    phantom_file: Option<PathBuf>,
    /// What to ask the destination for
    #[arg(long, default_value = "/")]
    path: String,
    /// How long to wait for the proxy to listen before the first check
    #[arg(long, default_value_t = 120)]
    wait_secs: u64,
    /// A check, `host:port=expect`: expect `200` (the destination answered through the
    /// proxy) or `<status>:<code>` (the proxy refused with that JSON error code)
    #[arg(long = "check", required = true)]
    checks: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Check(args) => check(args).await,
        Cmd::ViaProxy(args) => via_proxy(args).await,
        Cmd::Serve {
            listen,
            tls_cert,
            tls_key,
        } => serve(&listen, tls_cert.zip(tls_key)).await,
    }
}

/// What one check ended as.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The tunnel opened and the destination answered this line.
    Opened(String),
    /// The gateway refused the CONNECT with this status and body.
    Refused(u16, String),
    /// The TLS handshake did not complete.
    HandshakeRefused(String),
}

async fn check(args: CheckArgs) -> anyhow::Result<()> {
    let endpoint = mediatore_tls::endpoint(&args.workload_api_socket);
    let source = WorkloadApiSource::connect(&endpoint, Duration::from_secs(90))
        .await
        .map_err(|e| anyhow::anyhow!("Workload API at {endpoint}: {e}"))?;
    let material = source.current()?;
    let gateway_id = SpiffeId::new(format!("spiffe://{}/gateway", args.trust_domain))?;
    println!(
        "probe identity={} gateway={} expects={}",
        material.spiffe_id, args.gateway, gateway_id
    );
    let cfg = Arc::new(mediatore_tls::client_config(&material, &gateway_id)?);
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let mut bad = 0;
    for spec in &args.checks {
        let (authority, expect) = spec
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("check {spec:?}: expected authority=expect"))?;
        let outcome = tunnel(&connector, &args.gateway, authority, &args.path).await;
        let ok = match (&outcome, expect) {
            (Outcome::Opened(line), "200") => line.contains("destination reached"),
            (Outcome::Refused(status, body), e) if e.starts_with("403:") => {
                *status == 403 && body.starts_with(&e[4..])
            }
            (Outcome::HandshakeRefused(_), "handshake-refused") => true,
            _ => false,
        };
        let (what, detail) = match &outcome {
            Outcome::Opened(line) => ("opened", line.clone()),
            Outcome::Refused(status, body) => ("refused", format!("{status} {body}")),
            Outcome::HandshakeRefused(e) => ("handshake-refused", e.clone()),
        };
        println!(
            "probe authority={authority} outcome={what} detail={detail:?} expected={expect} {}",
            if ok { "ok" } else { "MISMATCH" }
        );
        if !ok {
            bad += 1;
        }
    }
    println!("probe done checks={} mismatched={bad}", args.checks.len());
    anyhow::ensure!(bad == 0, "{bad} check(s) did not end as expected");
    Ok(())
}

/// One CONNECT through the gateway, then one request inside the tunnel.
async fn tunnel(
    connector: &tokio_rustls::TlsConnector,
    gateway: &str,
    authority: &str,
    path: &str,
) -> Outcome {
    let tcp = match TcpStream::connect(gateway).await {
        Ok(t) => t,
        Err(e) => return Outcome::HandshakeRefused(format!("connect: {e}")),
    };
    // SNI carries no trust (ADR-0007 decision 5); the name is a placeholder.
    let name = rustls::pki_types::ServerName::try_from("gateway").expect("a valid name");
    let mut tls = match connector.connect(name, tcp).await {
        Ok(t) => t,
        Err(e) => return Outcome::HandshakeRefused(e.to_string()),
    };
    let connect = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    if let Err(e) = tls.write_all(connect.as_bytes()).await {
        return Outcome::HandshakeRefused(format!("write: {e}"));
    }
    let (status, body) = match read_response(&mut tls).await {
        Ok(r) => r,
        Err(e) => return Outcome::HandshakeRefused(format!("read: {e}")),
    };
    if status != 200 {
        return Outcome::Refused(status, body.lines().next().unwrap_or("").to_owned());
    }
    let req = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    if let Err(e) = tls.write_all(req.as_bytes()).await {
        return Outcome::Refused(status, format!("tunnel write: {e}"));
    }
    match read_response(&mut tls).await {
        Ok((_, body)) => Outcome::Opened(body.lines().next().unwrap_or("").to_owned()),
        Err(e) => Outcome::Refused(status, format!("tunnel read: {e}")),
    }
}

/// The jailed workload's side: wait for the proxy, then one request per check through it.
async fn via_proxy(args: ViaProxyArgs) -> anyhow::Result<()> {
    let proxy = args
        .proxy
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("the proxy's URL is plain http on loopback"))?
        .trim_end_matches('/')
        .to_owned();
    let phantom = match &args.phantom_file {
        Some(p) => Some(std::fs::read_to_string(p)?.trim().to_owned()),
        None => None,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.wait_secs);
    loop {
        match TcpStream::connect(&proxy).await {
            Ok(_) => break,
            Err(e) if tokio::time::Instant::now() < deadline => {
                println!("probe waiting for the proxy at {proxy}: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => anyhow::bail!(
                "the proxy at {proxy} did not listen within {}s: {e}",
                args.wait_secs
            ),
        }
    }
    println!("probe via proxy={proxy} credential={}", phantom.is_some());
    let mut bad = 0;
    for spec in &args.checks {
        let (authority, expect) = spec
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("check {spec:?}: expected host:port=expect"))?;
        let (status, body) = match request(&proxy, authority, &args.path, phantom.as_deref()).await
        {
            Ok(r) => r,
            Err(e) => (0, format!("proxy unreachable: {e}")),
        };
        let first = body.lines().next().unwrap_or("").to_owned();
        let ok = match expect.split_once(':') {
            None => expect == "200" && status == 200 && body.contains("destination reached"),
            Some((want, code)) => {
                want.parse::<u16>().is_ok_and(|w| w == status)
                    && body.contains(&format!("\"error\":\"{code}\""))
            }
        };
        println!(
            "probe authority={authority} status={status} detail={first:?} expected={expect} {}",
            if ok { "ok" } else { "MISMATCH" }
        );
        if !ok {
            bad += 1;
        }
    }
    println!("probe done checks={} mismatched={bad}", args.checks.len());
    anyhow::ensure!(bad == 0, "{bad} check(s) did not end as expected");
    Ok(())
}

/// One request to the proxy as the jail makes it: `GET /<authority><path>`, the phantom as
/// the bearer when given, one connection.
async fn request(
    proxy: &str,
    authority: &str,
    path: &str,
    phantom: Option<&str>,
) -> anyhow::Result<(u16, String)> {
    let mut tcp = TcpStream::connect(proxy).await?;
    let credential = phantom.map_or(String::new(), |p| format!("Authorization: Bearer {p}\r\n"));
    let req = format!(
        "GET /{authority}{path} HTTP/1.1\r\nHost: {proxy}\r\nConnection: close\r\n{credential}\r\n"
    );
    tcp.write_all(req.as_bytes()).await?;
    read_response(&mut tcp).await
}

/// Read one HTTP/1.1 response head and whatever body follows within the deadline: the
/// status, and the body as text.
async fn read_response<S: AsyncReadExt + Unpin>(s: &mut S) -> anyhow::Result<(u16, String)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = tokio::time::timeout_at(deadline, s.read(&mut chunk)).await??;
        anyhow::ensure!(n > 0, "connection closed before a response head");
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("no status in {head:?}"))?;
    let length: Option<usize> = head
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        })
        .and_then(|(_, v)| v.trim().parse().ok());
    let mut body = buf[head_end..].to_vec();
    // A tunnel opening has no body; a refusal or a destination's answer carries one.
    if status != 200 || length.is_some() {
        let want = length.unwrap_or(0);
        while body.len() < want {
            let n = tokio::time::timeout_at(deadline, s.read(&mut chunk)).await??;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

/// The destination: every request is answered with the host it named. Plain HTTP, or TLS
/// 1.3 with the given certificate (the kind tier's fixture CA, which the proxy's route
/// carries as the audience's `ca_pem`).
async fn serve(listen: &str, tls: Option<(PathBuf, PathBuf)>) -> anyhow::Result<()> {
    mediatore_proto::tls::ensure_provider();
    let acceptor = match tls {
        Some((cert, key)) => {
            let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cert)
                .map_err(|e| anyhow::anyhow!("{}: {e}", cert.display()))?
                .collect::<Result<_, _>>()
                .map_err(|e| anyhow::anyhow!("{}: {e}", cert.display()))?;
            let key = PrivateKeyDer::from_pem_file(&key)
                .map_err(|e| anyhow::anyhow!("{}: {e}", key.display()))?;
            let mut config =
                rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .with_no_client_auth()
                    .with_single_cert(chain, key)?;
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Some(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
        }
        None => None,
    };
    let listener = TcpListener::bind(listen).await?;
    println!(
        "destination listening on {} tls={}",
        listener.local_addr()?,
        acceptor.is_some()
    );
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor {
                Some(a) => match a.accept(stream).await {
                    Ok(tls) => answer(tls, peer).await,
                    Err(e) => println!("destination handshake from={peer} failed: {e}"),
                },
                None => answer(stream, peer).await,
            }
        });
    }
}

/// One request: read the head, answer with the host it named.
async fn answer<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, peer: std::net::SocketAddr) {
    let mut buf = vec![0u8; 8192];
    let mut head = Vec::new();
    loop {
        let Ok(n) = stream.read(&mut buf).await else {
            return;
        };
        if n == 0 {
            return;
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head);
    let host = text
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
        })
        .map_or("", |(_, v)| v.trim());
    let target = text.lines().next().unwrap_or("").to_owned();
    // Never the headers: a request through the proxy carries a real token.
    println!("destination request from={peer} host={host} line={target:?}");
    let body = format!("destination reached: host={host}\n");
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
}
