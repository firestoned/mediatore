// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! fake-idp: a stand-in OIDC issuer for driving a `dev_mode` mediatore by hand.
//!
//! `fake-idp serve` runs the issuer and writes its signing key, generated for the run, to
//! `--key-file`; `fake-idp token` reads that file and prints a login token the running
//! issuer's JWKS verifies. No key is embedded anywhere. Test material only.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Default listen address; the issuer URL is `http://<this>`.
const DEFAULT_LISTEN: &str = "127.0.0.1:18082";

#[derive(Parser)]
#[command(
    name = "fake-idp",
    version,
    about = "Fake OIDC issuer for mediatore dev runs"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve OIDC discovery and the JWKS.
    Serve {
        /// Listen address
        #[arg(long, default_value = DEFAULT_LISTEN)]
        listen: String,
        /// Where to write this run's signing key (PKCS#8 PEM, mode 0600) for `token`
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Print a login token for a user.
    Token {
        /// Issuer URL the serve command runs under
        #[arg(long, default_value_t = format!("http://{DEFAULT_LISTEN}"))]
        issuer: String,
        /// Login name (becomes `preferred_username`)
        #[arg(long)]
        login: String,
        /// Audience (`aud`)
        #[arg(long, default_value = "mediatore")]
        aud: String,
        /// Groups to carry
        #[arg(long)]
        group: Vec<String>,
        /// The key file the serve command wrote
        #[arg(long)]
        key_file: PathBuf,
    },
}

/// Write `pem` to `path`, readable by the owner only, replacing what was there.
fn write_key(path: &PathBuf, pem: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(pem.as_bytes())
}

#[tokio::main]
async fn main() {
    match Cli::parse().cmd {
        Cmd::Serve { listen, key_file } => {
            if let Err(e) = write_key(&key_file, mediatore_testkit::idp_key_pem()) {
                eprintln!("fake-idp: cannot write {}: {e}", key_file.display());
                std::process::exit(1);
            }
            let idp = mediatore_testkit::FakeIdp::start_on(&listen).await;
            eprintln!(
                "fake-idp serving at {} (key in {})",
                idp.issuer,
                key_file.display()
            );
            tokio::signal::ctrl_c().await.expect("ctrl-c");
        }
        Cmd::Token {
            issuer,
            login,
            aud,
            group,
            key_file,
        } => {
            let pem = match std::fs::read_to_string(&key_file) {
                Ok(pem) => pem,
                Err(e) => {
                    eprintln!("fake-idp: cannot read {}: {e}", key_file.display());
                    std::process::exit(1);
                }
            };
            if mediatore_testkit::use_idp_key(pem).is_err() {
                eprintln!("fake-idp: a key is already in use");
                std::process::exit(1);
            }
            let token = mediatore_testkit::mint(
                &issuer,
                serde_json::json!({
                    "aud": aud,
                    "preferred_username": login,
                    "email": format!("{login}@example.com"),
                    "groups": group,
                }),
            );
            println!("{token}");
        }
    }
}
