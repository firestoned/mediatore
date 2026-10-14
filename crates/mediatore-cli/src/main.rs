// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! mediatore-cli: `login` at the issuer, then `claim`, `get`, `delete` and `status`
//! against mediatore's user API (ADR-0013).

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use mediatore_cli::{Api, LoginOptions, Session};
use mediatore_proto::{ClaimRequest, Workload};

#[derive(Parser)]
#[command(
    name = "mediatore-cli",
    version,
    about = "Log in and ask mediatore for a sandbox"
)]
struct Cli {
    #[arg(
        long,
        env = "MEDIATORE_SESSION",
        global = true,
        help = "Session file (default: $XDG_CONFIG_HOME/mediatore/session.json)"
    )]
    session: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Log in at the issuer (PKCE, loopback redirect) and keep the session.
    Login {
        /// The OIDC issuer URL, exactly as mediatore's config names it
        #[arg(long, env = "MEDIATORE_ISSUER")]
        issuer: String,
        /// mediatore's public client id at that issuer
        #[arg(long, env = "MEDIATORE_CLIENT_ID", default_value = "mediatore")]
        client_id: String,
        /// Print the URL instead of opening a browser
        #[arg(long)]
        no_browser: bool,
        /// A login hint for the issuer
        #[arg(long)]
        login_hint: Option<String>,
    },
    /// Request a sandbox, delegating the session's refresh token to mediatore.
    Claim {
        /// mediatore's user API base URL
        #[arg(long, env = "MEDIATORE_URL")]
        mediatore: String,
        #[arg(long, help = "The VirtualMachinePool to claim from")]
        pool: String,
        /// Lifetime in seconds, counted from bind
        #[arg(long, default_value_t = 3600)]
        ttl: u32,
        /// Downstream audiences the sandbox may request (repeatable)
        #[arg(long = "audience")]
        audiences: Vec<String>,
        /// OCI image of the workload
        #[arg(long)]
        image: String,
        /// Workload argv (repeatable, in order)
        #[arg(long = "arg")]
        args: Vec<String>,
        /// Print the response as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show a sandbox.
    Get {
        /// mediatore's user API base URL
        #[arg(long, env = "MEDIATORE_URL")]
        mediatore: String,
        /// The sandbox name
        name: String,
    },
    /// Delete a sandbox.
    Delete {
        /// mediatore's user API base URL
        #[arg(long, env = "MEDIATORE_URL")]
        mediatore: String,
        /// The sandbox name
        name: String,
    },
    /// Show the session: who is logged in, until when, and whether a delegation is left.
    Status,
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(not(target_os = "macos"))]
    let opener = "xdg-open";
    match std::process::Command::new(opener).arg(url).spawn() {
        Ok(_) => eprintln!("Opening the browser; if nothing happens, visit:\n{url}"),
        Err(_) => eprintln!("Open this URL in a browser:\n{url}"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let path = match cli.session {
        Some(p) => p,
        None => Session::default_path()?,
    };
    match cli.cmd {
        Cmd::Login {
            issuer,
            client_id,
            no_browser,
            login_hint,
        } => {
            let opts = LoginOptions {
                issuer,
                client_id,
                scopes: LoginOptions::default_scopes(),
                login_hint,
            };
            let open = |url: &str| {
                if no_browser {
                    eprintln!("Open this URL in a browser:\n{url}");
                } else {
                    open_browser(url);
                }
            };
            let session = mediatore_cli::login(&opts, open).await?;
            session.save(&path)?;
            eprintln!(
                "logged in as {} at {}{}",
                session.login,
                session.issuer,
                if session.refresh_token.is_some() {
                    ""
                } else {
                    " (no refresh token: the issuer did not grant offline_access)"
                }
            );
        }
        Cmd::Claim {
            mediatore,
            pool,
            ttl,
            audiences,
            image,
            args,
            json,
        } => {
            let session = Session::load(&path)?;
            let request = ClaimRequest {
                pool_ref: pool,
                ttl_seconds: ttl,
                audiences,
                workload: Workload { image, args },
                refresh_token: None,
            };
            let (claim, spent) = Api::new(&mediatore)?.claim(&session, &request).await?;
            spent.save(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&claim)?);
            } else {
                println!("{}\t{:?}\tready={}", claim.name, claim.phase, claim.ready);
            }
        }
        Cmd::Get { mediatore, name } => {
            let session = Session::load(&path)?;
            let claim = Api::new(&mediatore)?.get(&session, &name).await?;
            println!("{}", serde_json::to_string_pretty(&claim)?);
        }
        Cmd::Delete { mediatore, name } => {
            let session = Session::load(&path)?;
            Api::new(&mediatore)?.delete(&session, &name).await?;
            println!("{name} deleted");
        }
        Cmd::Status => {
            let session = Session::load(&path)?;
            println!(
                "{} at {}: id token {}, delegation {}",
                session.login,
                session.issuer,
                if session.is_fresh(0) {
                    "valid"
                } else {
                    "expired"
                },
                if session.refresh_token.is_some() {
                    "available"
                } else {
                    "spent (log in again to claim)"
                }
            );
        }
    }
    Ok(())
}
