// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The user's subcommands of the one `mediatore` binary (ADR-0014): `login` at the issuer,
//! then `sandbox create`, `sandbox get`, `sandbox logs`, `sandbox delete` against mediatore's
//! user API, and `session` to show what is logged in (ADR-0013).

use std::io::Write as _;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use mediatore_proto::{ClaimRequest, PoolSelector, Selection, SelectionStrategy, Workload};

use crate::{Api, LoginOptions, Redirect, Session};

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
    /// A PEM file with the CA that signs mediatore's certificate (private PKI); when
    /// given, nothing else is trusted
    #[arg(long, env = "MEDIATORE_CA_FILE")]
    pub ca_file: Option<PathBuf>,
    /// Send the login and anything delegated to a plain http user API on another host (a
    /// test cluster with no TLS in front of the broker); without it only https, or http to
    /// this machine, is accepted
    #[arg(long, env = "MEDIATORE_ALLOW_PLAIN_HTTP")]
    pub allow_plain_http: bool,
    /// The session file.
    #[command(flatten)]
    pub session: SessionFile,
}

impl Target {
    /// The user API client for this target, with `--ca-file` as its only trust when given.
    pub fn api(&self) -> anyhow::Result<Api> {
        if self.allow_plain_http && self.ca_file.is_none() {
            return Api::plain_http(&self.mediatore);
        }
        match &self.ca_file {
            Some(p) => {
                let pem = std::fs::read(p)
                    .map_err(|e| anyhow::anyhow!("--ca-file {}: {e}", p.display()))?;
                Api::with_ca(&self.mediatore, &pem)
            }
            None => Api::new(&self.mediatore),
        }
    }
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
    /// Delete the credential mediatore saved for an audience in the OS credential store (ADR-0041).
    Logout(LogoutArgs),
}

/// Arguments of `logout`.
#[derive(Debug, Args)]
pub struct LogoutArgs {
    /// The audience whose saved user name and secret to delete
    #[arg(long)]
    pub audience: String,
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
    #[arg(long, env = "MEDIATORE_CA_FILE")]
    pub ca_file: Option<PathBuf>,
    /// A scope to request (repeatable); the default set is `openid profile email groups
    /// offline_access`, which Dex, Auth0 and Entra take. Google takes no `offline_access`
    #[arg(long = "scope")]
    pub scopes: Vec<String>,
    /// An extra parameter on the authorization request, `key=value` (repeatable): Google
    /// wants `access_type=offline` and `prompt=consent` for a refresh token, Auth0 may
    /// want `audience=...`
    #[arg(long = "auth-param", value_parser = parse_auth_param)]
    pub auth_params: Vec<(String, String)>,
    /// A file holding the client secret the issuer's token endpoint wants even from this
    /// public client (Google's installed-app clients)
    #[arg(long)]
    pub client_secret_file: Option<PathBuf>,
    /// A loopback port for the redirect, tried in order (repeatable). The default is
    /// kubelogin's, 8000 then 18000, which is what the login hub registers for mediatore's
    /// client: Dex matches redirect URIs exactly, so a random port cannot log in there.
    /// Pass `--redirect-port 0` for a port the OS chooses (an issuer that accepts any
    /// loopback port)
    #[arg(long = "redirect-port", default_values_t = [8000u16, 18000])]
    pub redirect_ports: Vec<u16>,
    /// The host in the redirect URI (the listener binds 127.0.0.1 either way)
    #[arg(long, default_value = "localhost")]
    pub redirect_host: String,
    /// What follows the port in the redirect URI, for an issuer that registered a path
    #[arg(long, default_value = "")]
    pub redirect_path: String,
    /// The session file.
    #[command(flatten)]
    pub session: SessionFile,
}

/// `key=value` for `--auth-param`.
fn parse_auth_param(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_owned(), v.to_owned())),
        _ => Err(format!("expected key=value, got {s:?}")),
    }
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
        /// The namespace to act in (ADR-0046); without it nothing is sent and the broker decides
        #[arg(long)]
        namespace: Option<String>,
    },
    /// Delete a sandbox.
    Delete {
        /// Where and as whom.
        #[command(flatten)]
        target: Target,
        /// The sandbox name
        name: String,
        /// The namespace to act in (ADR-0046); without it nothing is sent and the broker decides
        #[arg(long)]
        namespace: Option<String>,
    },
    /// Print the workload's output (ADR-0045): a sandbox created with --logs. Redaction
    /// happened in the VM and is best effort, not a guarantee; the output is kept for a
    /// bounded time after the claim ends, then swept. stdout records go to stdout and
    /// stderr records to stderr; the workload's exit code stays on `sandbox get`.
    Logs {
        /// Where and as whom.
        #[command(flatten)]
        target: Target,
        /// The sandbox name
        name: String,
        /// The namespace to act in (ADR-0046); without it nothing is sent and the broker decides
        #[arg(long)]
        namespace: Option<String>,
        /// Keep reading until the claim ends (Ctrl-C ends the read, not the claim)
        #[arg(short = 'f', long)]
        follow: bool,
        /// Only the last N records
        #[arg(long, value_name = "N")]
        tail: Option<u64>,
        /// Only records after this sequence number
        #[arg(long, value_name = "SEQ")]
        since: Option<u64>,
        /// Prefix each record with the time the guest read it
        #[arg(long)]
        timestamps: bool,
        /// Print the output exactly as stored. Without it, control characters (escape
        /// sequences, carriage returns) are written out as text such as \x1b, so the
        /// workload cannot drive this terminal; use --raw only when writing to a file
        #[arg(long)]
        raw: bool,
    },
}

/// Arguments of `sandbox create`.
#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Where and as whom.
    #[command(flatten)]
    pub target: Target,
    /// The namespace to claim in (ADR-0046). Without it nothing is sent: a broker with one
    /// namespace uses it, a broker with a namespace map answers `400 namespace_required`.
    #[arg(long)]
    pub namespace: Option<String>,
    /// One pool, by name. Without it and without --pool-selector, the claim is made across
    /// every pool in the sandbox namespace (ADR-0044 decision 3).
    #[arg(
        long,
        conflicts_with = "pool_selector",
        help = "The VirtualMachinePool to claim from; default: any pool in the namespace"
    )]
    pub pool: Option<String>,
    /// Any pool whose labels match, as <key>=<value> (repeatable; all must match). Without
    /// --pool and without this, every pool in the namespace.
    #[arg(long = "pool-selector", value_name = "KEY=VALUE")]
    pub pool_selector: Vec<String>,
    /// How banlieue picks the member among the Ready ones of the matched pools (ADR-0047):
    /// longest-ready (banlieue's default when absent), most-available (the failure domain
    /// with the most Ready members), spread (the domain where you hold the fewest members).
    /// Without it nothing is sent
    #[arg(long, value_enum)]
    pub strategy: Option<StrategyArg>,
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
    /// The notaio policy the sandbox is under, by name (optional; read in shadow)
    #[arg(long)]
    pub policy: Option<String>,
    /// What the guest does when the workload exits before the deadline (ADR-0033):
    /// always (restart until the deadline), on-failure (an exit 0 ends the claim), never
    /// (any exit ends the claim)
    #[arg(long, value_enum, default_value_t = RestartArg::Always)]
    pub restart: RestartArg,
    /// Your own credential for a `via: delegated` audience (ADR-0035), as
    /// <audience>=<source>: claude-code (Claude Code's own session), env:<NAME> (a token
    /// in that variable, a `claude setup-token`), file:<path> (a file holding the token).
    /// Read now, sent once with the claim, never kept (repeatable)
    #[arg(long = "delegate", value_name = "AUDIENCE=SOURCE")]
    pub delegate: Vec<String>,
    /// Capture the workload's stdout and stderr, redacted in the VM, for `sandbox logs`
    /// (ADR-0045); the broker must have logs enabled or the claim is refused
    #[arg(long)]
    pub logs: bool,
    /// Print the response as JSON
    #[arg(long)]
    pub json: bool,
}

/// `--restart`, as clap takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RestartArg {
    /// Restart whatever the status, until the deadline (the default)
    Always,
    /// Restart a non-zero exit; an exit 0 ends the claim
    OnFailure,
    /// Any exit ends the claim
    Never,
}

/// `--strategy`, as clap takes it (ADR-0047 decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum StrategyArg {
    /// The member Ready longest, wherever it runs (banlieue's default)
    LongestReady,
    /// From the failure domain with the most Ready members
    MostAvailable,
    /// From the failure domain where this subject holds the fewest members
    Spread,
}

impl From<StrategyArg> for SelectionStrategy {
    fn from(s: StrategyArg) -> Self {
        match s {
            StrategyArg::LongestReady => Self::LongestReady,
            StrategyArg::MostAvailable => Self::MostAvailable,
            StrategyArg::Spread => Self::Spread,
        }
    }
}

/// `--strategy` as the request carries it (ADR-0047 decisions 2 and 4): the strategy, or
/// nothing at all, never a default the CLI invents.
#[must_use]
pub fn selection_of(strategy: Option<StrategyArg>) -> Option<Selection> {
    strategy.map(|s| Selection { strategy: s.into() })
}

impl From<RestartArg> for mediatore_proto::RestartPolicy {
    fn from(r: RestartArg) -> Self {
        match r {
            RestartArg::Always => Self::Always,
            RestartArg::OnFailure => Self::OnFailure,
            RestartArg::Never => Self::Never,
        }
    }
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
        UserCmd::Logout(args) => {
            crate::delegate::forget(&args.audience);
            eprintln!("no credential saved for {} remains", args.audience);
            Ok(())
        }
        UserCmd::Sandbox(SandboxCmd::Create(args)) => create(args).await,
        UserCmd::Sandbox(SandboxCmd::Get {
            target,
            name,
            namespace,
        }) => {
            let session = Session::load(&target.session.path()?)?;
            let claim = get_claim(&target.api()?, &session, &name, namespace.as_deref()).await?;
            println!("{}", serde_json::to_string_pretty(&claim)?);
            Ok(())
        }
        UserCmd::Sandbox(SandboxCmd::Delete {
            target,
            name,
            namespace,
        }) => {
            let session = Session::load(&target.session.path()?)?;
            delete_claim(&target.api()?, &session, &name, namespace.as_deref()).await?;
            println!("{name} deleted");
            Ok(())
        }
        UserCmd::Sandbox(SandboxCmd::Logs {
            target,
            name,
            namespace,
            follow,
            tail,
            since,
            timestamps,
            raw,
        }) => {
            let session = Session::load(&target.session.path()?)?;
            let query = crate::logs::LogsQuery {
                follow,
                since,
                tail,
            };
            let resp = target
                .api()?
                .logs(&session, &name, namespace.as_deref(), &query)
                .await?;
            // With --follow, Ctrl-C ends this process and so the read; the claim is untouched,
            // the broker just sees the reader go.
            let (stdout, stderr) = (std::io::stdout(), std::io::stderr());
            let (mut out, mut err) = (stdout.lock(), stderr.lock());
            let reason =
                crate::logs::print_response(resp, &mut out, &mut err, timestamps, raw).await?;
            out.flush()?;
            if reason != mediatore_proto::LogEnd::ClaimEnded {
                writeln!(
                    err,
                    "[log stream ended: {}]",
                    serde_json::to_value(reason)?.as_str().unwrap_or("?")
                )?;
            }
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
    let client_secret = match &args.client_secret_file {
        Some(p) => Some(
            std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("--client-secret-file {}: {e}", p.display()))?
                .trim()
                .to_owned(),
        ),
        None => None,
    };
    let opts = LoginOptions {
        issuer: args.issuer,
        client_id: args.client_id,
        scopes: if args.scopes.is_empty() {
            LoginOptions::default_scopes()
        } else {
            args.scopes
        },
        extra_params: args.auth_params,
        client_secret,
        login_hint: args.login_hint,
        ca_pem,
        redirect: Redirect {
            host: args.redirect_host,
            // `--redirect-port 0` is the OS-chosen port: no fixed list.
            ports: args
                .redirect_ports
                .into_iter()
                .filter(|p| *p != 0)
                .collect(),
            path: args.redirect_path,
        },
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

/// `--pool` or `--pool-selector`, as the request carries it (ADR-0044 decision 3): a name,
/// a `match_labels` selector, or, with neither flag, the empty selector that means every
/// pool in the namespace, written down rather than left for the broker to guess.
///
/// # Errors
/// A selector term that is not `<key>=<value>`, or an empty key.
pub fn pool_choice(
    pool: Option<String>,
    selector: &[String],
) -> anyhow::Result<(Option<String>, Option<PoolSelector>)> {
    if let Some(name) = pool {
        return Ok((Some(name), None));
    }
    let mut sel = PoolSelector::default();
    for term in selector {
        let (k, v) = term
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--pool-selector takes <key>=<value>, got {term:?}"))?;
        if k.is_empty() {
            anyhow::bail!("--pool-selector takes <key>=<value>, got an empty key in {term:?}");
        }
        sel.match_labels.insert(k.to_owned(), v.to_owned());
    }
    Ok((None, Some(sel)))
}

/// ADR-0046 decision 16: when the user named a namespace, the broker must have reported the
/// same one. An absent `namespace` is a broker that predates the field and ignored the
/// request; a different one is a claim that landed elsewhere. Either is an error, and nothing
/// is deleted on the user's behalf: the CLI holds no list of namespaces and remembers none.
///
/// # Errors
/// The response's namespace is absent or differs from `asked`.
pub fn check_namespace(asked: Option<&str>, reported: Option<&str>) -> anyhow::Result<()> {
    match (asked, reported) {
        (Some(a), Some(r)) if a != r => anyhow::bail!(
            "you asked for namespace {a} but the broker answered for namespace {r}; \
             nothing was changed by the CLI (check what exists in {r})"
        ),
        (Some(a), None) => anyhow::bail!(
            "you asked for namespace {a} but the broker did not report a namespace (an older \
             broker ignores the field); it may have acted in its default namespace, and the \
             CLI changed nothing"
        ),
        _ => Ok(()),
    }
}

/// `sandbox get`: with a namespace, the answer must come from that namespace (ADR-0046
/// decision 16), so an old broker that ignores `?namespace=` is told apart.
async fn get_claim(
    api: &Api,
    session: &Session,
    name: &str,
    namespace: Option<&str>,
) -> anyhow::Result<mediatore_proto::ClaimResponse> {
    let claim = api.get(session, name, namespace).await?;
    check_namespace(namespace, claim.namespace.as_deref())?;
    Ok(claim)
}

/// `sandbox delete`: with a namespace, a GET first (ADR-0046 decision 16).
async fn delete_claim(
    api: &Api,
    session: &Session,
    name: &str,
    namespace: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(asked) = namespace {
        // An old broker ignores `?namespace=` and would delete in its default namespace; the
        // read tells it apart before anything is deleted.
        let claim = api.get(session, name, Some(asked)).await?;
        check_namespace(Some(asked), claim.namespace.as_deref())?;
    }
    api.delete(session, name, namespace).await
}

async fn create(args: CreateArgs) -> anyhow::Result<()> {
    let path = args.target.session.path()?;
    let session = Session::load(&path)?;
    let mut delegations = Vec::new();
    for arg in &args.delegate {
        let (audience, source) = crate::delegate::parse_delegate(arg)?;
        let cred = crate::delegate::read(&audience, &source, args.ttl)?;
        eprintln!(
            "delegating your {audience} credential to the broker for this claim ({})",
            cred.expires_at
                .map_or_else(|| "no expiry known".to_owned(), |e| format!("expires {e}"))
        );
        delegations.push(cred.delegation(&audience));
    }
    let (pool_ref, pool_selector) = pool_choice(args.pool, &args.pool_selector)?;
    if let Some(sel) = &pool_selector {
        eprintln!(
            "claiming from {} in the sandbox namespace",
            match mediatore_proto::PoolChoice::Selected(sel)
                .to_string()
                .as_str()
            {
                "any pool" => "any pool".to_owned(),
                terms => format!("any pool matching {terms}"),
            }
        );
    }
    let request = ClaimRequest {
        namespace: args.namespace.clone(),
        pool_ref,
        pool_selector,
        selection: selection_of(args.strategy),
        ttl_seconds: args.ttl,
        audiences: args.audiences,
        workload: Workload {
            image: args.image,
            args: args.args,
            restart: args.restart.into(),
            logs: args.logs,
        },
        refresh_token: None,
        policy_ref: args.policy,
        delegations,
    };
    let (claim, spent) = args.target.api()?.claim(&session, &request).await?;
    // The refresh token is spent at the broker whatever follows, so the session is saved first.
    spent.save(&path)?;
    check_namespace(args.namespace.as_deref(), claim.namespace.as_deref())?;
    if args.namespace.is_none()
        && let Some(ns) = &claim.namespace
    {
        eprintln!("claimed in namespace {ns} (the broker's default; --namespace names another)");
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&claim)?);
    } else {
        println!("{}\t{:?}\tready={}", claim.name, claim.phase, claim.ready);
        print_report(&claim);
    }
    Ok(())
}

/// The guest's report, when the claim has one (ADR-0029 decision 5): which image digest
/// and which rules ran, as the broker recorded them.
fn print_report(claim: &mediatore_proto::ClaimResponse) {
    if let Some(x) = &claim.exit {
        println!(
            "exited_at={}\tcode={}\tsignal={}\trestarts={}",
            x.exited_at,
            x.exit
                .code
                .map_or_else(|| "-".to_owned(), |c| c.to_string()),
            x.exit
                .signal
                .map_or_else(|| "-".to_owned(), |s| s.to_string()),
            x.exit.restarts
        );
    }
    let Some(r) = &claim.report else {
        return;
    };
    let host = match &r.report.host_table {
        mediatore_proto::HostTable::Loaded { sha256 } => format!("loaded sha256={sha256}"),
        mediatore_proto::HostTable::Missing => "MISSING (the environment has gateways)".to_owned(),
        mediatore_proto::HostTable::NotLoaded => "none (no gateways)".to_owned(),
    };
    println!(
        "reported_at={}\timage_digest={}\tsandbox_ruleset_sha256={}\thost_table={host}",
        r.reported_at, r.report.image_digest, r.report.sandbox_ruleset_sha256
    );
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct W {
        #[command(flatten)]
        login: LoginArgs,
    }

    fn parse(extra: &[&str]) -> LoginArgs {
        let mut argv = vec!["w", "--issuer", "https://dex.example"];
        argv.extend_from_slice(extra);
        W::try_parse_from(argv).unwrap().login
    }

    #[test]
    fn login_defaults_to_kubelogins_fixed_redirect() {
        let a = parse(&[]);
        assert_eq!(a.redirect_ports, vec![8000, 18000]);
        assert_eq!(a.redirect_host, "localhost");
        assert_eq!(a.redirect_path, "");
    }

    #[test]
    fn the_redirect_can_be_set_and_zero_means_an_os_chosen_port() {
        let a = parse(&[
            "--redirect-port",
            "9000",
            "--redirect-host",
            "127.0.0.1",
            "--redirect-path",
            "/callback",
        ]);
        assert_eq!(a.redirect_ports, vec![9000]);
        assert_eq!(a.redirect_host, "127.0.0.1");
        assert_eq!(a.redirect_path, "/callback");
        assert_eq!(parse(&["--redirect-port", "0"]).redirect_ports, vec![0]);
    }

    #[test]
    fn login_reads_the_ca_file_from_the_same_variable_as_the_other_commands() {
        use clap::Args as _;
        let env_of = |cmd: clap::Command| {
            cmd.get_arguments()
                .find(|a| a.get_id() == "ca_file")
                .and_then(|a| a.get_env().map(std::ffi::OsStr::to_owned))
        };
        let login = env_of(LoginArgs::augment_args(clap::Command::new("t")));
        let target = env_of(Target::augment_args(clap::Command::new("t")));
        assert_eq!(
            target.as_deref(),
            Some(std::ffi::OsStr::new("MEDIATORE_CA_FILE"))
        );
        assert_eq!(login, target, "login must honour MEDIATORE_CA_FILE too");
    }

    #[derive(Parser)]
    struct T {
        #[command(flatten)]
        target: Target,
    }

    fn target(extra: &[&str]) -> Target {
        let mut argv = vec!["t", "--mediatore", "https://mediatore.example"];
        argv.extend_from_slice(extra);
        T::try_parse_from(argv).unwrap().target
    }

    #[test]
    fn a_plain_http_user_api_on_another_host_is_taken_only_when_asked_for_by_name() {
        let plain = ["t", "--mediatore", "http://mediatore.example:8080"];
        let refused = T::try_parse_from(plain).unwrap().target;
        assert!(!refused.allow_plain_http);
        assert!(refused.api().is_err());
        let mut asked = plain.to_vec();
        asked.push("--allow-plain-http");
        let allowed = T::try_parse_from(asked).unwrap().target;
        assert!(allowed.api().is_ok());
    }

    #[test]
    fn the_user_api_commands_take_a_ca_file() {
        assert!(target(&[]).ca_file.is_none());
        let t = target(&["--ca-file", "/etc/ca.pem"]);
        assert_eq!(
            t.ca_file.as_deref(),
            Some(std::path::Path::new("/etc/ca.pem"))
        );
    }

    // ----- ADR-0044 decision 3: --pool, --pool-selector, or neither (any pool) -----------------

    #[test]
    fn a_named_pool_is_sent_as_pool_ref_alone() {
        assert_eq!(
            pool_choice(Some("pool-a".into()), &[]).unwrap(),
            (Some("pool-a".into()), None)
        );
    }

    #[test]
    fn selector_terms_become_match_labels() {
        let (name, sel) = pool_choice(
            None,
            &["sandbox.example.com/image=agent".into(), "zone=a".into()],
        )
        .unwrap();
        assert!(name.is_none());
        let sel = sel.expect("a selector");
        assert_eq!(
            sel.match_labels,
            std::collections::BTreeMap::from([
                ("sandbox.example.com/image".to_owned(), "agent".to_owned()),
                ("zone".to_owned(), "a".to_owned()),
            ])
        );
        assert_eq!(sel.match_expressions, Vec::new());
    }

    /// Neither flag is "any pool in the namespace", sent as the empty selector so the
    /// request says so, rather than leaving the broker to read an absence (ADR-0044
    /// decision 3; banlieue ADR-0132 decision 2).
    #[test]
    fn neither_flag_sends_the_empty_selector_not_nothing() {
        assert_eq!(
            pool_choice(None, &[]).unwrap(),
            (None, Some(PoolSelector::default()))
        );
    }

    #[test]
    fn a_selector_term_without_an_equals_sign_or_a_key_is_refused() {
        for bad in ["agent", "=agent"] {
            let err = pool_choice(None, &[bad.to_owned()])
                .expect_err(bad)
                .to_string();
            assert!(err.contains("--pool-selector"), "{err}");
            assert!(err.contains(bad), "{err}");
        }
    }

    // ----- ADR-0047 decision 4: --strategy, or nothing sent --------------------------------------

    #[test]
    fn the_strategy_flag_maps_onto_banlieues_values_and_none_sends_nothing() {
        assert_eq!(selection_of(None), None);
        assert_eq!(
            selection_of(Some(StrategyArg::Spread)),
            Some(Selection {
                strategy: SelectionStrategy::Spread
            })
        );
        assert_eq!(
            SelectionStrategy::from(StrategyArg::LongestReady),
            SelectionStrategy::LongestReady
        );
        assert_eq!(
            SelectionStrategy::from(StrategyArg::MostAvailable),
            SelectionStrategy::MostAvailable
        );
    }

    #[test]
    fn an_unreadable_ca_file_is_named_in_the_error() {
        let err = target(&["--ca-file", "/nonexistent/ca.pem"])
            .api()
            .err()
            .expect("a missing CA file is an error")
            .to_string();
        assert!(err.contains("--ca-file"), "{err}");
        assert!(err.contains("/nonexistent/ca.pem"), "{err}");
    }

    #[test]
    fn a_ca_file_without_a_certificate_is_refused() {
        let dir = std::env::temp_dir().join(format!("mediatore-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("empty.pem");
        std::fs::write(&f, "not a certificate\n").unwrap();
        let err = target(&["--ca-file", f.to_str().unwrap()])
            .api()
            .err()
            .expect("a CA file with no certificate is an error")
            .to_string();
        assert!(err.contains("no certificate"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ----- ADR-0046 decisions 15 and 16: --namespace --------------------------------------

    /// A one-shot HTTP server: answers `status` and `body` to the next request and hands back
    /// the whole request text (head and body) it received.
    async fn one_shot(status: &str, body: &str) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let reply = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let h = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got).into_owned();
                if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                    let want = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if rest.len() >= want {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            sock.write_all(reply.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&got).into_owned()
        });
        (url, h)
    }

    fn session() -> Session {
        Session {
            issuer: "https://dex.example".into(),
            client_id: "mediatore".into(),
            login: "octocat".into(),
            id_token: "id-token".into(),
            refresh_token: Some("refresh".into()),
            expires_at: i64::MAX,
        }
    }

    fn request(namespace: Option<&str>) -> ClaimRequest {
        ClaimRequest {
            namespace: namespace.map(str::to_owned),
            pool_ref: None,
            pool_selector: Some(PoolSelector::default()),
            selection: None,
            ttl_seconds: 60,
            audiences: vec![],
            workload: Workload {
                image: "registry.internal:5000/agent:1".into(),
                args: vec![],
                restart: mediatore_proto::RestartPolicy::Always,
                logs: false,
            },
            refresh_token: None,
            policy_ref: None,
            delegations: vec![],
        }
    }

    const CLAIM: &str = r#"{"name":"sb-1","namespace":"team-a","phase":"Pending"}"#;

    #[test]
    fn the_namespace_flag_parses_on_create_get_and_delete() {
        #[derive(Parser)]
        struct S {
            #[command(subcommand)]
            cmd: SandboxCmd,
        }
        let m = "https://mediatore.example";
        match S::try_parse_from([
            "s",
            "create",
            "--mediatore",
            m,
            "--image",
            "i",
            "--namespace",
            "team-a",
        ])
        .unwrap()
        .cmd
        {
            SandboxCmd::Create(a) => assert_eq!(a.namespace.as_deref(), Some("team-a")),
            _ => panic!("create"),
        }
        match S::try_parse_from(["s", "get", "--mediatore", m, "--namespace", "infra", "sb-1"])
            .unwrap()
            .cmd
        {
            SandboxCmd::Get { namespace, .. } => assert_eq!(namespace.as_deref(), Some("infra")),
            _ => panic!("get"),
        }
        match S::try_parse_from(["s", "delete", "--mediatore", m, "sb-1"])
            .unwrap()
            .cmd
        {
            SandboxCmd::Delete { namespace, .. } => assert!(namespace.is_none()),
            _ => panic!("delete"),
        }
    }

    #[test]
    fn sandbox_logs_parses_its_flags_and_create_takes_logs() {
        #[derive(Parser)]
        struct S {
            #[command(subcommand)]
            cmd: SandboxCmd,
        }
        let m = "https://mediatore.example";
        match S::try_parse_from([
            "s",
            "logs",
            "--mediatore",
            m,
            "-f",
            "--tail",
            "20",
            "--since",
            "7",
            "--timestamps",
            "--raw",
            "--namespace",
            "infra",
            "sb-1",
        ])
        .unwrap()
        .cmd
        {
            SandboxCmd::Logs {
                name,
                namespace,
                follow,
                tail,
                since,
                timestamps,
                raw,
                ..
            } => {
                assert_eq!(name, "sb-1");
                assert_eq!(namespace.as_deref(), Some("infra"));
                assert!(follow && timestamps);
                assert!(raw, "A-10: the opt-out of the client's escaping");
                assert_eq!(tail, Some(20));
                assert_eq!(since, Some(7));
            }
            _ => panic!("logs"),
        }
        match S::try_parse_from(["s", "logs", "--mediatore", m, "sb-1"])
            .unwrap()
            .cmd
        {
            SandboxCmd::Logs {
                follow,
                tail,
                since,
                timestamps,
                raw,
                ..
            } => {
                assert!(!follow && !timestamps);
                assert!(!raw, "escaped unless asked");
                assert_eq!((tail, since), (None, None));
            }
            _ => panic!("logs"),
        }
        match S::try_parse_from(["s", "create", "--mediatore", m, "--image", "i", "--logs"])
            .unwrap()
            .cmd
        {
            SandboxCmd::Create(a) => assert!(a.logs, "ADR-0045: the opt-in"),
            _ => panic!("create"),
        }
        match S::try_parse_from(["s", "create", "--mediatore", m, "--image", "i"])
            .unwrap()
            .cmd
        {
            SandboxCmd::Create(a) => assert!(!a.logs, "off unless asked"),
            _ => panic!("create"),
        }
    }

    #[tokio::test]
    async fn sandbox_logs_asks_the_logs_route_with_its_query_and_the_bearer() {
        let body = concat!(
            "{\"truncated_before\":0,\"claim_phase\":\"Bound\"}\n",
            "{\"end\":true,\"reason\":\"claim_ended\"}\n"
        );
        let (url, h) = one_shot("200 OK", body).await;
        let resp = Api::new(&url)
            .unwrap()
            .logs(
                &session(),
                "sb-1",
                Some("infra"),
                &crate::logs::LogsQuery {
                    follow: true,
                    since: Some(7),
                    tail: Some(20),
                },
            )
            .await
            .unwrap();
        let got = h.await.unwrap();
        assert!(
            got.starts_with(
                "GET /v1/claims/sb-1/logs?follow=true&tail=20&since=7&namespace=infra "
            ),
            "{got}"
        );
        assert!(got.contains("authorization: Bearer id-token"), "{got}");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let reason = crate::logs::print_response(resp, &mut out, &mut err, false, false)
            .await
            .unwrap();
        assert_eq!(reason, mediatore_proto::LogEnd::ClaimEnded);
        assert_eq!((out.len(), err.len()), (0, 0));

        // Nothing set: no query at all.
        let (url, h) = one_shot("200 OK", body).await;
        Api::new(&url)
            .unwrap()
            .logs(&session(), "sb-1", None, &crate::logs::LogsQuery::default())
            .await
            .unwrap();
        let got = h.await.unwrap();
        assert!(got.starts_with("GET /v1/claims/sb-1/logs "), "{got}");

        // A broker with logs off: the status is in the error, nothing is printed.
        let (url, _h) = one_shot(
            "501 Not Implemented",
            r#"{"error":"not_implemented","detail":"logs are not enabled on this broker"}"#,
        )
        .await;
        let e = Api::new(&url)
            .unwrap()
            .logs(&session(), "sb-1", None, &crate::logs::LogsQuery::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("501"), "{e}");
        assert!(e.contains("not_implemented"), "{e}");
    }

    #[tokio::test]
    async fn namespace_flag_is_sent_in_the_request_and_the_query() {
        let (url, h) = one_shot("201 Created", CLAIM).await;
        let api = Api::new(&url).unwrap();
        api.claim(&session(), &request(Some("team-a")))
            .await
            .unwrap();
        let got = h.await.unwrap();
        assert!(got.starts_with("POST /v1/claims "), "{got}");
        assert!(got.contains(r#""namespace":"team-a""#), "{got}");

        let (url, h) = one_shot("200 OK", CLAIM).await;
        Api::new(&url)
            .unwrap()
            .get(&session(), "sb-1", Some("team-a"))
            .await
            .unwrap();
        assert!(
            h.await
                .unwrap()
                .starts_with("GET /v1/claims/sb-1?namespace=team-a ")
        );

        let (url, h) = one_shot("204 No Content", "").await;
        Api::new(&url)
            .unwrap()
            .delete(&session(), "sb-1", Some("infra"))
            .await
            .unwrap();
        assert!(
            h.await
                .unwrap()
                .starts_with("DELETE /v1/claims/sb-1?namespace=infra ")
        );
    }

    #[tokio::test]
    async fn without_the_flag_the_request_has_no_namespace() {
        let (url, h) = one_shot("201 Created", CLAIM).await;
        Api::new(&url)
            .unwrap()
            .claim(&session(), &request(None))
            .await
            .unwrap();
        let got = h.await.unwrap();
        assert!(!got.contains("namespace"), "{got}");

        let (url, h) = one_shot("200 OK", CLAIM).await;
        Api::new(&url)
            .unwrap()
            .get(&session(), "sb-1", None)
            .await
            .unwrap();
        assert!(h.await.unwrap().starts_with("GET /v1/claims/sb-1 "));

        let (url, h) = one_shot("204 No Content", "").await;
        Api::new(&url)
            .unwrap()
            .delete(&session(), "sb-1", None)
            .await
            .unwrap();
        assert!(h.await.unwrap().starts_with("DELETE /v1/claims/sb-1 "));
    }

    #[test]
    fn a_response_namespace_that_differs_from_the_flag_is_an_error() {
        let err = check_namespace(Some("team-a"), Some("infra"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("team-a") && err.contains("infra"), "{err}");
        assert!(check_namespace(Some("team-a"), Some("team-a")).is_ok());
        // No flag: whatever the broker used is fine (it is printed, not checked).
        assert!(check_namespace(None, Some("infra")).is_ok());
        assert!(check_namespace(None, None).is_ok());
    }

    #[test]
    fn a_response_without_a_namespace_is_an_error_when_the_flag_was_given() {
        let err = check_namespace(Some("team-a"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("team-a"), "{err}");
        assert!(err.contains("did not report a namespace"), "{err}");
    }

    #[tokio::test]
    async fn the_400_namespace_required_message_is_shown_as_the_error() {
        let body = r#"{"error":"namespace_required","message":"a namespace is required: pass --namespace"}"#;
        let (url, h) = one_shot("400 Bad Request", body).await;
        let err = Api::new(&url)
            .unwrap()
            .claim(&session(), &request(None))
            .await
            .unwrap_err()
            .to_string();
        h.await.unwrap();
        assert!(err.contains("400"), "{err}");
        assert!(
            err.contains("a namespace is required: pass --namespace"),
            "{err}"
        );
    }

    type Log = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

    /// A server that answers `replies` to successive requests, in order, logging each request
    /// line. It keeps waiting after the last reply, so a test sees what was NOT sent.
    async fn sequence(replies: Vec<(&'static str, &'static str)>) -> (String, Log) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let log: Log = Log::default();
        let seen = log.clone();
        tokio::spawn(async move {
            for (status, body) in replies {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = sock.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                let line = String::from_utf8_lossy(&got)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                seen.lock().unwrap().push(line);
                let reply = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                sock.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        (url, log)
    }

    fn lines(log: &Log) -> Vec<String> {
        log.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn delete_with_a_namespace_gets_first_and_deletes_when_it_matches() {
        let (url, log) = sequence(vec![("200 OK", CLAIM), ("204 No Content", "")]).await;
        let api = Api::new(&url).unwrap();
        delete_claim(&api, &session(), "sb-1", Some("team-a"))
            .await
            .unwrap();
        let l = lines(&log);
        assert_eq!(l.len(), 2, "{l:?}");
        assert!(
            l[0].starts_with("GET /v1/claims/sb-1?namespace=team-a "),
            "{l:?}"
        );
        assert!(
            l[1].starts_with("DELETE /v1/claims/sb-1?namespace=team-a "),
            "{l:?}"
        );
    }

    #[tokio::test]
    async fn delete_with_a_namespace_does_not_delete_when_the_get_reports_a_different_namespace() {
        let (url, log) = sequence(vec![("200 OK", CLAIM), ("204 No Content", "")]).await;
        let api = Api::new(&url).unwrap();
        let err = delete_claim(&api, &session(), "sb-1", Some("infra"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("infra") && err.contains("team-a"), "{err}");
        let l = lines(&log);
        assert_eq!(l.len(), 1, "{l:?}");
        assert!(l[0].starts_with("GET "), "{l:?}");
    }

    #[tokio::test]
    async fn delete_with_a_namespace_does_not_delete_when_the_get_reports_none() {
        let body = r#"{"name":"sb-1","phase":"Pending"}"#;
        let (url, log) = sequence(vec![("200 OK", body), ("204 No Content", "")]).await;
        let api = Api::new(&url).unwrap();
        let err = delete_claim(&api, &session(), "sb-1", Some("team-a"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not report a namespace"), "{err}");
        let l = lines(&log);
        assert_eq!(l.len(), 1, "{l:?}");
        assert!(l[0].starts_with("GET "), "{l:?}");
    }

    #[tokio::test]
    async fn delete_with_a_namespace_sends_no_delete_when_the_get_is_404() {
        let body = r#"{"error":"not_found","message":"no such sandbox"}"#;
        let (url, log) = sequence(vec![("404 Not Found", body), ("204 No Content", "")]).await;
        let api = Api::new(&url).unwrap();
        let err = delete_claim(&api, &session(), "sb-1", Some("team-a"))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("404") && err.contains("no such sandbox"),
            "{err}"
        );
        assert_eq!(lines(&log).len(), 1, "{:?}", lines(&log));
    }

    #[tokio::test]
    async fn delete_without_a_namespace_sends_no_get() {
        let (url, log) = sequence(vec![("204 No Content", ""), ("200 OK", CLAIM)]).await;
        let api = Api::new(&url).unwrap();
        delete_claim(&api, &session(), "sb-1", None).await.unwrap();
        let l = lines(&log);
        assert_eq!(l.len(), 1, "{l:?}");
        assert!(l[0].starts_with("DELETE /v1/claims/sb-1 "), "{l:?}");
    }

    #[tokio::test]
    async fn get_with_a_namespace_that_differs_from_the_response_is_an_error() {
        let (url, _log) = sequence(vec![("200 OK", CLAIM)]).await;
        let api = Api::new(&url).unwrap();
        let err = get_claim(&api, &session(), "sb-1", Some("infra"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("infra") && err.contains("team-a"), "{err}");
    }

    #[tokio::test]
    async fn get_with_a_namespace_and_a_response_without_one_is_an_error() {
        let body = r#"{"name":"sb-1","phase":"Pending"}"#;
        let (url, _log) = sequence(vec![("200 OK", body)]).await;
        let api = Api::new(&url).unwrap();
        let err = get_claim(&api, &session(), "sb-1", Some("team-a"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not report a namespace"), "{err}");
    }

    #[tokio::test]
    async fn get_without_a_namespace_does_not_check() {
        let (url, log) = sequence(vec![("200 OK", CLAIM)]).await;
        let api = Api::new(&url).unwrap();
        let claim = get_claim(&api, &session(), "sb-1", None).await.unwrap();
        assert_eq!(claim.name, "sb-1");
        assert!(
            lines(&log)[0].starts_with("GET /v1/claims/sb-1 "),
            "{:?}",
            lines(&log)
        );
    }
}
