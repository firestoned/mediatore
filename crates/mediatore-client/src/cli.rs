// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The user's subcommands of the one `mediatore` binary (ADR-0014): `login` at the issuer,
//! then `sandbox create`, `sandbox get`, `sandbox delete` against mediatore's user API, and
//! `session` to show what is logged in (ADR-0013).

use std::path::PathBuf;

use clap::{Args, Subcommand};
use mediatore_proto::{ClaimRequest, Workload};

use crate::{Api, LoginOptions, Session};

/// Where the session file lives.
#[derive(Debug, Args)]
pub struct SessionFile {
    /// Where the session is kept; the default is under the XDG config home.
    #[arg(
        long,
        env = "MEDIATORE_SESSION",
        help = "Session file (default: $XDG_CONFIG_HOME/mediatore/session.json)"
    )]
    pub session: Option<PathBuf>,
}

impl SessionFile {
    fn path(&self) -> anyhow::Result<PathBuf> {
        match &self.session {
            Some(p) => Ok(p.clone()),
            None => Session::default_path(),
        }
    }
}

/// mediatore's user API and the session to talk to it with.
#[derive(Debug, Args)]
pub struct Target {
    /// mediatore's user API base URL
    #[arg(long, env = "MEDIATORE_URL")]
    pub mediatore: String,
    /// The session file.
    #[command(flatten)]
    pub session: SessionFile,
}

/// The user's subcommands, flattened into the binary's tree.
#[derive(Debug, Subcommand)]
pub enum UserCmd {
    /// Log in at the issuer (PKCE, loopback redirect) and keep the session.
    Login(LoginArgs),
    /// Request, show or delete a sandbox.
    #[command(subcommand)]
    Sandbox(SandboxCmd),
    /// Show the session: who is logged in, until when, and whether a delegation is left.
    Session(SessionFile),
}

/// Arguments of `login`.
#[derive(Debug, Args)]
pub struct LoginArgs {
    /// The OIDC issuer URL, exactly as mediatore's config names it
    #[arg(long, env = "MEDIATORE_ISSUER")]
    pub issuer: String,
    /// mediatore's public client id at that issuer
    #[arg(long, env = "MEDIATORE_CLIENT_ID", default_value = "mediatore")]
    pub client_id: String,
    /// Print the URL instead of opening a browser
    #[arg(long)]
    pub no_browser: bool,
    /// A login hint for the issuer
    #[arg(long)]
    pub login_hint: Option<String>,
    /// A PEM file with the CA that signs the issuer's certificate (private PKI); when
    /// given, nothing else is trusted
    #[arg(long)]
    pub ca_file: Option<PathBuf>,
    /// The session file.
    #[command(flatten)]
    pub session: SessionFile,
}

/// The `sandbox` subcommands.
#[derive(Debug, Subcommand)]
pub enum SandboxCmd {
    /// Request a sandbox, delegating the session's refresh token to mediatore.
    Create(CreateArgs),
    /// Show a sandbox.
    Get {
        /// Where and as whom.
        #[command(flatten)]
        target: Target,
        /// The sandbox name
        name: String,
    },
    /// Delete a sandbox.
    Delete {
        /// Where and as whom.
        #[command(flatten)]
        target: Target,
        /// The sandbox name
        name: String,
    },
}

/// Arguments of `sandbox create`.
#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Where and as whom.
    #[command(flatten)]
    pub target: Target,
    /// The pool to claim from.
    #[arg(long, help = "The VirtualMachinePool to claim from")]
    pub pool: String,
    /// Lifetime in seconds, counted from bind
    #[arg(long, default_value_t = 3600)]
    pub ttl: u32,
    /// Downstream audiences the sandbox may request (repeatable)
    #[arg(long = "audience")]
    pub audiences: Vec<String>,
    /// OCI image of the workload
    #[arg(long)]
    pub image: String,
    /// Workload argv (repeatable, in order)
    #[arg(long = "arg")]
    pub args: Vec<String>,
    /// Print the response as JSON
    #[arg(long)]
    pub json: bool,
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

/// Run one of the user's subcommands.
pub async fn run(cmd: UserCmd) -> anyhow::Result<()> {
    match cmd {
        UserCmd::Login(args) => login(args).await,
        UserCmd::Sandbox(SandboxCmd::Create(args)) => create(args).await,
        UserCmd::Sandbox(SandboxCmd::Get { target, name }) => {
            let session = Session::load(&target.session.path()?)?;
            let claim = Api::new(&target.mediatore)?.get(&session, &name).await?;
            println!("{}", serde_json::to_string_pretty(&claim)?);
            Ok(())
        }
        UserCmd::Sandbox(SandboxCmd::Delete { target, name }) => {
            let session = Session::load(&target.session.path()?)?;
            Api::new(&target.mediatore)?.delete(&session, &name).await?;
            println!("{name} deleted");
            Ok(())
        }
        UserCmd::Session(file) => {
            let session = Session::load(&file.path()?)?;
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
            Ok(())
        }
    }
}

async fn login(args: LoginArgs) -> anyhow::Result<()> {
    let path = args.session.path()?;
    let ca_pem = match &args.ca_file {
        Some(p) => {
            Some(std::fs::read(p).map_err(|e| anyhow::anyhow!("--ca-file {}: {e}", p.display()))?)
        }
        None => None,
    };
    let opts = LoginOptions {
        issuer: args.issuer,
        client_id: args.client_id,
        scopes: LoginOptions::default_scopes(),
        login_hint: args.login_hint,
        ca_pem,
    };
    let open = |url: &str| {
        if args.no_browser {
            eprintln!("Open this URL in a browser:\n{url}");
        } else {
            open_browser(url);
        }
    };
    let session = crate::login(&opts, open).await?;
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
    Ok(())
}

async fn create(args: CreateArgs) -> anyhow::Result<()> {
    let path = args.target.session.path()?;
    let session = Session::load(&path)?;
    let request = ClaimRequest {
        pool_ref: args.pool,
        ttl_seconds: args.ttl,
        audiences: args.audiences,
        workload: Workload {
            image: args.image,
            args: args.args,
        },
        refresh_token: None,
    };
    let (claim, spent) = Api::new(&args.target.mediatore)?
        .claim(&session, &request)
        .await?;
    spent.save(&path)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&claim)?);
    } else {
        println!("{}\t{:?}\tready={}", claim.name, claim.phase, claim.ready);
    }
    Ok(())
}
