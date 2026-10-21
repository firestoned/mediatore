// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The user's side of the Dex kind tier, driven from inside the cluster: runs the real
//! `mediatore login` and plays the browser it would open (follows the authorization URL
//! to Dex, fills in the password form, lets Dex redirect to the CLI's loopback listener),
//! then runs the real `mediatore sandbox create` and prints its JSON. Test-only: nothing
//! here is a shipped code path except the two subprocesses it spawns.

use std::path::PathBuf;
use std::process::Stdio;

use clap::Parser;
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Parser)]
#[command(
    name = "dex-driver",
    about = "Log in at a Dex with a password form and request a sandbox, through the real CLI"
)]
struct Cli {
    /// The mediatore binary to drive
    #[arg(long, default_value = "/usr/local/bin/mediatore")]
    bin: PathBuf,
    /// The issuer URL, as the broker's config names it
    #[arg(long)]
    issuer: String,
    /// The CA that signs the issuer's certificate
    #[arg(long)]
    ca_file: PathBuf,
    /// The login Dex's password form takes
    #[arg(long)]
    login: String,
    /// Its password
    #[arg(long)]
    password: String,
    /// Where the CLI keeps the session
    #[arg(long, default_value = "/work/session.json")]
    session: PathBuf,
    /// mediatore's user API
    #[arg(long)]
    mediatore: String,
    /// The pool to claim from
    #[arg(long)]
    pool: String,
    /// The audience the sandbox may request
    #[arg(long)]
    audience: String,
    /// The workload image
    #[arg(long)]
    image: String,
    /// The workload argv (repeatable)
    #[arg(long = "arg")]
    args: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    mediatore_proto::tls::ensure_provider();

    // 1. The real CLI, told not to open a browser: it prints the authorization URL.
    let mut login = tokio::process::Command::new(&cli.bin)
        .args(["login", "--no-browser", "--issuer", &cli.issuer])
        .arg("--ca-file")
        .arg(&cli.ca_file)
        .arg("--session")
        .arg(&cli.session)
        .args(["--login-hint", &cli.login])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = login.stderr.take().expect("piped stderr");
    let mut lines = BufReader::new(stderr).lines();
    let mut url = None;
    while let Some(line) = lines.next_line().await? {
        eprintln!("login: {line}");
        if line.starts_with("http") {
            url = Some(line);
            break;
        }
    }
    let url = url.ok_or_else(|| anyhow::anyhow!("mediatore login printed no URL"))?;
    // Keep the rest of the CLI's stderr visible.
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            eprintln!("login: {line}");
        }
    });

    // 2. The browser: Dex's password form, then its redirect to the CLI's loopback.
    browse(&cli, &url).await?;
    let status = login.wait().await?;
    anyhow::ensure!(status.success(), "mediatore login: {status}");
    eprintln!("driver: logged in through the real CLI");

    // 3. The claim, through the real CLI; its JSON goes out on one marked line, so a
    //    script can pick it out of a pod log where stderr is interleaved.
    let mut create = tokio::process::Command::new(&cli.bin);
    create
        .args(["sandbox", "create", "--json", "--mediatore", &cli.mediatore])
        .arg("--session")
        .arg(&cli.session)
        .args([
            "--pool",
            &cli.pool,
            "--audience",
            &cli.audience,
            "--image",
            &cli.image,
        ]);
    for a in &cli.args {
        create.args(["--arg", a]);
    }
    let out = create
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .await?;
    anyhow::ensure!(
        out.status.success(),
        "mediatore sandbox create: {}",
        out.status
    );
    let created: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    println!("sandbox: {created}");
    Ok(())
}

/// Follow the authorization URL to Dex, post the credentials into its login form, and
/// let the redirects run through `/approval` and `/callback` to the CLI's loopback
/// listener. Succeeds only when that listener answered.
async fn browse(cli: &Cli, auth_url: &str) -> anyhow::Result<()> {
    let ca = std::fs::read(&cli.ca_file)?;
    let http = reqwest::Client::builder()
        .use_preconfigured_tls(mediatore_proto::tls::https_client_config_with_ca(&ca)?)
        .build()?;

    let page = http.get(auth_url).send().await?.error_for_status()?;
    let page_url = page.url().clone();
    let html = page.text().await?;
    let action = html
        .split("action=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .ok_or_else(|| anyhow::anyhow!("no login form at {page_url}; page:\n{html}"))?
        .replace("&amp;", "&");
    let action = page_url.join(&action)?;
    eprintln!("browser: login form at {page_url}, posting to {action}");

    // Dex answers a connector failure (its directory restarting behind it) with a 500
    // "Login error" page and keeps the authorization request, so a browser user would
    // simply submit again; do the same, a few times, before calling it a failure.
    let mut attempt = 0;
    let done = loop {
        attempt += 1;
        let done = http
            .post(action.clone())
            .form(&[
                ("login", cli.login.as_str()),
                ("password", cli.password.as_str()),
            ])
            .send()
            .await?;
        if !done.status().is_server_error() || attempt >= 10 {
            break done;
        }
        eprintln!(
            "browser: Dex answered {} on attempt {attempt}; retrying in a second",
            done.status()
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    };
    let final_url = done.url().clone();
    let status = done.status();
    let body = done.text().await.unwrap_or_default();
    anyhow::ensure!(
        final_url.host_str() == Some("127.0.0.1") && status.is_success(),
        "the login did not reach the CLI's loopback listener: ended at {final_url} ({status})\n{body}"
    );
    eprintln!("browser: Dex redirected to {final_url}");
    Ok(())
}
