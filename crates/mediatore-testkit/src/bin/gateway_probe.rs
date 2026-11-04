// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! A stand-in for `mediatore forward` and for a destination, for the gateway kind tier
//! (`make kind-e2e-gateway`, ADR-0028). `check` does what the forwarder will: fetch the
//! claim SVID from the Workload API, open TLS 1.3 to the gateway presenting it, verify the
//! gateway's SVID is exactly `spiffe://<td>/gateway`, send `CONNECT host:port`, and, when
//! the tunnel opens, one plain HTTP request through it. One line per check on standard
//! output, and a non-zero exit when any check did not end as expected. `serve` is the
//! destination: a plain HTTP server answering every request with the host it was asked for.
//! Test-only; never shipped.

use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use mediatore_tls::{MaterialSource, SpiffeId, WorkloadApiSource};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser)]
#[command(
    name = "gateway-probe",
    about = "The forwarder's shape and a destination, for the gateway kind tier"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// CONNECT through the gateway as this pod's claim SVID, once per check
    Check(CheckArgs),
    /// A destination: answers every request with the host it was asked for
    Serve {
        /// Address to listen on
        #[arg(long, default_value = "0.0.0.0:8080")]
        listen: String,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Check(args) => check(args).await,
        Cmd::Serve { listen } => serve(&listen).await,
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

/// The destination: every request is answered with the host it named.
async fn serve(listen: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    println!("destination listening on {}", listener.local_addr()?);
    loop {
        let (mut stream, peer) = listener.accept().await?;
        tokio::spawn(async move {
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
            println!("destination request from={peer} host={host} line={target:?}");
            let body = format!("destination reached: host={host}\n");
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}
