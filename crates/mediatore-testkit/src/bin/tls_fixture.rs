// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! A throwaway CA and a server certificate for the kind tier's PostgreSQL (ADR-0012): the
//! broker connects with `sslmode=verify-full` against this CA, so the live store runs the
//! same TLS path as the real deployment. Writes `ca.pem`, `server.pem` and
//! `server-key.pem` (PKCS#8) into `--out-dir`, valid for a day.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use clap::Parser;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use time::{Duration, OffsetDateTime};

#[derive(Parser)]
#[command(
    name = "tls-fixture",
    about = "A test CA and a server certificate for the kind tier's PostgreSQL"
)]
struct Cli {
    /// Directory to write ca.pem, server.pem and server-key.pem into.
    #[arg(long)]
    out_dir: PathBuf,
    /// DNS names the server certificate is valid for (repeatable).
    #[arg(long = "dns", required = true)]
    dns: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    mediatore_proto::tls::ensure_provider();
    let now = OffsetDateTime::now_utc();

    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "mediatore-testkit");
    dn.push(DnType::CommonName, "kind store CA");
    ca.distinguished_name = dn;
    ca.not_before = now - Duration::hours(1);
    ca.not_after = now + Duration::days(1);
    let ca_cert = ca.self_signed(&ca_key)?;
    let ca_pem = pem("CERTIFICATE", ca_cert.der());
    let issuer = Issuer::new(ca, ca_key);

    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut server = CertificateParams::default();
    server.is_ca = IsCa::NoCa;
    server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cli.dns[0].clone());
    server.distinguished_name = dn;
    server.subject_alt_names = cli
        .dns
        .iter()
        .map(|d| Ok(SanType::DnsName(d.as_str().try_into()?)))
        .collect::<Result<_, rcgen::Error>>()?;
    server.not_before = now - Duration::hours(1);
    server.not_after = now + Duration::days(1);
    let server_cert = server.signed_by(&key, &issuer)?;

    std::fs::create_dir_all(&cli.out_dir)?;
    std::fs::write(cli.out_dir.join("ca.pem"), ca_pem)?;
    std::fs::write(
        cli.out_dir.join("server.pem"),
        pem("CERTIFICATE", server_cert.der()),
    )?;
    std::fs::write(
        cli.out_dir.join("server-key.pem"),
        pem("PRIVATE KEY", &key.serialize_der()),
    )?;
    Ok(())
}

/// PEM armour (rcgen is built without its `pem` feature).
fn pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("base64 is ascii"))
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}
