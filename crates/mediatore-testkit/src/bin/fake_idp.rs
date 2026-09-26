// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! fake-idp: a stand-in OIDC issuer for driving a `dev_mode` mediatore by hand.
//!
//! `fake-idp serve` runs the issuer; `fake-idp token` prints a login token signed with the
//! same fixed test key, so the two commands need no shared state. Test material only.

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
    },
}

#[tokio::main]
async fn main() {
    match Cli::parse().cmd {
        Cmd::Serve { listen } => {
            let idp = mediatore_testkit::FakeIdp::start_on(&listen).await;
            eprintln!("fake-idp serving at {}", idp.issuer);
            tokio::signal::ctrl_c().await.expect("ctrl-c");
        }
        Cmd::Token {
            issuer,
            login,
            aud,
            group,
        } => {
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
