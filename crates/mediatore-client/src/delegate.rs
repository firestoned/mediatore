// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The requester's own credentials, read at claim time for a `via: delegated` audience
//! (ADR-0035 decision 6): `claude-code` reads Claude Code's credential store (the Keychain
//! item on macOS, the credentials file elsewhere), `env:<NAME>` a token from the
//! environment (a `claude setup-token` in `CLAUDE_CODE_OAUTH_TOKEN`), `file:<path>` a file
//! holding the token alone. For a `credential: basic` audience (ADR-0041) `prompt` asks for a user
//! name and a secret (echo off, a terminal only) and `store` reads mediatore's own Keychain item
//! (macOS), at most six hours old; both give `user:secret`. Nothing read is kept, printed or logged
//! (the Keychain item is the one thing kept, and only when the person says so): it is sent once, in
//! the claim.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use jiff::Timestamp;
use mediatore_proto::{Delegation, Secret};

/// The Keychain item Claude Code keeps its session in on macOS.
pub const CLAUDE_CODE_KEYCHAIN_SERVICE: &str = "Claude Code-credentials";
/// The credentials file Claude Code keeps its session in elsewhere, under the home.
pub const CLAUDE_CODE_CREDENTIALS_FILE: &str = ".claude/.credentials.json";

/// Where a delegated credential comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Claude Code's own credential store: the access token, its refresh token, its expiry.
    ClaudeCode,
    /// A token in this environment variable.
    Env(String),
    /// A token in this file, trailing whitespace trimmed.
    File(PathBuf),
    /// A user name and a secret typed at the terminal (ADR-0041 decision 4).
    Prompt,
    /// mediatore's own Keychain item for the audience, saved by `prompt` (ADR-0041 decision 5).
    Store,
}

impl FromStr for Source {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "claude-code" {
            return Ok(Self::ClaudeCode);
        }
        if s == "prompt" {
            return Ok(Self::Prompt);
        }
        if s == "store" {
            return Ok(Self::Store);
        }
        if let Some(name) = s.strip_prefix("env:") {
            anyhow::ensure!(!name.is_empty(), "env: needs a variable name");
            return Ok(Self::Env(name.to_owned()));
        }
        if let Some(path) = s.strip_prefix("file:") {
            anyhow::ensure!(!path.is_empty(), "file: needs a path");
            return Ok(Self::File(PathBuf::from(path)));
        }
        anyhow::bail!(
            "unknown delegation source {s:?}: claude-code, prompt, store, env:<NAME> or file:<path>"
        )
    }
}

/// `<audience>=<source>`, as `--delegate` takes it.
pub fn parse_delegate(arg: &str) -> anyhow::Result<(String, Source)> {
    let (audience, source) = arg
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("--delegate takes <audience>=<source>, got {arg:?}"))?;
    anyhow::ensure!(
        !audience.is_empty(),
        "--delegate: the audience is empty in {arg:?}"
    );
    Ok((audience.to_owned(), source.parse()?))
}

/// What a source yielded: the bearer, what renews it, when it dies.
#[derive(Clone)]
pub struct Credential {
    /// The bearer; `Debug` is not derived, so it is never printed by accident.
    pub token: String,
    /// What renews it, when the source has one.
    pub refresh_token: Option<String>,
    /// When it dies, when the source says.
    pub expires_at: Option<Timestamp>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("token", &"[redacted]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Credential {
    /// The delegation to send with the claim for `audience`.
    #[must_use]
    pub fn delegation(self, audience: &str) -> Delegation {
        Delegation {
            audience: audience.to_owned(),
            token: Some(Secret(self.token)),
            refresh_token: self.refresh_token.map(Secret),
            expires_at: self.expires_at,
            pending: false,
        }
    }
}

/// Read a source now. A credential the source says has expired is refused here, with the
/// fix, rather than by the broker later. `audience` names the Keychain item for `store` and the
/// prompt's question; `ttl_seconds` is the claim's, which bounds how long a saved item is kept.
pub fn read(audience: &str, source: &Source, ttl_seconds: u32) -> anyhow::Result<Credential> {
    let cred = match source {
        Source::Prompt => prompt_basic(audience, ttl_seconds)?,
        Source::Store => store::load(audience)?,
        Source::ClaudeCode => parse_claude_code(&claude_code_store()?)?,
        Source::Env(name) => {
            let token = std::env::var(name)
                .map_err(|_| anyhow::anyhow!("{name} is not set in the environment"))?;
            plain(token.trim())?
        }
        Source::File(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
            plain(raw.trim())?
        }
    };
    if let Some(e) = cred.expires_at
        && e <= Timestamp::now()
    {
        anyhow::bail!(
            "the credential expired at {e}; log in again at its source (`claude login` for claude-code)"
        );
    }
    Ok(cred)
}

fn plain(token: &str) -> anyhow::Result<Credential> {
    anyhow::ensure!(!token.is_empty(), "the token is empty");
    Ok(Credential {
        token: token.to_owned(),
        refresh_token: None,
        expires_at: None,
    })
}

/// Claude Code's credential store as JSON: the Keychain on macOS, the file elsewhere.
fn claude_code_store() -> anyhow::Result<String> {
    if cfg!(target_os = "macos") {
        let out = std::process::Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                CLAUDE_CODE_KEYCHAIN_SERVICE,
                "-w",
            ])
            .output()
            .map_err(|e| anyhow::anyhow!("running security(1): {e}"))?;
        anyhow::ensure!(
            out.status.success(),
            "no Claude Code session in the Keychain ({CLAUDE_CODE_KEYCHAIN_SERVICE:?}): run `claude login` first"
        );
        return Ok(String::from_utf8(out.stdout)?);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME is not set"))?;
    claude_code_file(&home.join(CLAUDE_CODE_CREDENTIALS_FILE))
}

fn claude_code_file(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!(
            "no Claude Code session at {}: run `claude login` first ({e})",
            path.display()
        )
    })
}

/// The store's shape: `{"claudeAiOauth": {"accessToken", "refreshToken", "expiresAt"}}`,
/// `expiresAt` in milliseconds since the epoch.
pub fn parse_claude_code(json: &str) -> anyhow::Result<Credential> {
    let v: serde_json::Value = serde_json::from_str(json.trim())
        .map_err(|e| anyhow::anyhow!("Claude Code's credential store is not JSON: {e}"))?;
    let oauth = v.get("claudeAiOauth").ok_or_else(|| {
        anyhow::anyhow!(
            "Claude Code's credential store has no claudeAiOauth session: run `claude login`"
        )
    })?;
    let token = oauth
        .get("accessToken")
        .and_then(|t| t.as_str())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Claude Code's session has no access token"))?
        .to_owned();
    let refresh_token = oauth
        .get("refreshToken")
        .and_then(|t| t.as_str())
        .filter(|t| !t.is_empty())
        .map(str::to_owned);
    let expires_at = oauth
        .get("expiresAt")
        .and_then(serde_json::Value::as_i64)
        .and_then(|ms| Timestamp::from_millisecond(ms).ok());
    Ok(Credential {
        token,
        refresh_token,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delegate_argument_names_the_audience_and_one_of_three_sources() {
        assert_eq!(
            parse_delegate("anthropic=claude-code").unwrap(),
            ("anthropic".into(), Source::ClaudeCode)
        );
        assert_eq!(
            parse_delegate("anthropic=env:CLAUDE_CODE_OAUTH_TOKEN").unwrap(),
            (
                "anthropic".into(),
                Source::Env("CLAUDE_CODE_OAUTH_TOKEN".into())
            )
        );
        assert_eq!(
            parse_delegate("x=file:/run/t").unwrap(),
            ("x".into(), Source::File("/run/t".into()))
        );
        for bad in [
            "anthropic",
            "=claude-code",
            "a=keychain",
            "a=env:",
            "a=file:",
        ] {
            assert!(parse_delegate(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn claude_codes_store_yields_the_session_and_its_expiry() {
        let fixture = r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-fixture","refreshToken":"sk-ant-ort01-fixture","expiresAt":4102444800000,"scopes":["user:inference"],"subscriptionType":"max"}}"#;
        let cred = parse_claude_code(fixture).unwrap();
        assert_eq!(cred.token, "sk-ant-oat01-fixture");
        assert_eq!(cred.refresh_token.as_deref(), Some("sk-ant-ort01-fixture"));
        assert_eq!(
            cred.expires_at.unwrap(),
            Timestamp::from_second(4_102_444_800).unwrap()
        );
        let d = cred.delegation("anthropic");
        assert_eq!(d.audience, "anthropic");
        assert!(d.token.is_some() && d.refresh_token.is_some() && !d.pending);
        assert_eq!(
            format!("{:?}", parse_claude_code(fixture).unwrap()),
            "Credential { token: \"[redacted]\", refresh_token: Some(\"[redacted]\"), expires_at: Some(2100-01-01T00:00:00Z) }"
        );

        for (bad, needle) in [
            ("{}", "no claudeAiOauth"),
            (
                r#"{"claudeAiOauth":{"refreshToken":"r"}}"#,
                "no access token",
            ),
            ("not json", "not JSON"),
        ] {
            let err = parse_claude_code(bad).unwrap_err().to_string();
            assert!(err.contains(needle), "{bad}: {err}");
        }
    }

    #[test]
    fn an_expired_source_is_refused_with_the_fix_and_a_file_source_is_trimmed() {
        let dir = mediatore_testkit::tempdir();
        let file = dir.join("token");
        std::fs::write(&file, "tok-from-file\n").unwrap();
        let cred = read("a", &Source::File(file.clone()), 900).unwrap();
        assert_eq!(cred.token, "tok-from-file");
        assert!(cred.refresh_token.is_none() && cred.expires_at.is_none());
        std::fs::write(&file, "   \n").unwrap();
        assert!(
            read("a", &Source::File(file), 900)
                .unwrap_err()
                .to_string()
                .contains("empty")
        );

        let expired = r#"{"claudeAiOauth":{"accessToken":"old","expiresAt":1000}}"#;
        let cred = parse_claude_code(expired).unwrap();
        assert!(cred.expires_at.unwrap() < Timestamp::now());
        // The read path refuses it; the parser alone reports what it found.
        let err = std::env::var("MEDIATORE_TEST_UNSET_VARIABLE")
            .err()
            .map(|_| {
                read(
                    "a",
                    &Source::Env("MEDIATORE_TEST_UNSET_VARIABLE".into()),
                    900,
                )
                .unwrap_err()
                .to_string()
            })
            .unwrap();
        assert!(err.contains("not set"), "{err}");
    }

    #[test]
    fn a_saved_credential_is_good_only_for_the_claim_it_was_saved_for() {
        // ADR-0043 decision 5: the item records the claim's TTL, and its age limit is the least of six hours and that
        // TTL. A credential typed for a 15 minute claim is not still usable an hour later.
        let now = Timestamp::from_second(1_800_000_000).unwrap();
        let item = |age: i64, max: Option<i64>| {
            let limit = max.map_or(String::new(), |m| format!(r#","max_age_secs":{m}"#));
            format!(
                r#"{{"saved_at":{}{limit},"token":"user:secret"}}"#,
                now.as_second() - age
            )
        };
        assert!(
            parse_stored(&item(1000, Some(900)), now).is_err(),
            "older than the 900 s claim it was saved for"
        );
        assert_eq!(
            parse_stored(&item(800, Some(900)), now).unwrap(),
            "user:secret",
            "inside the claim's TTL"
        );
        assert!(
            parse_stored(&item(7 * 3600, Some(24 * 3600)), now).is_err(),
            "a limit above six hours is capped at six hours"
        );
        assert!(
            parse_stored(&item(5 * 3600, None), now).is_ok(),
            "an item with no limit (saved before this change) keeps the six hours"
        );
    }

    #[test]
    fn prompt_and_store_are_sources_and_a_basic_token_joins_a_user_and_a_secret() {
        assert_eq!("prompt".parse::<Source>().unwrap(), Source::Prompt);
        assert_eq!("store".parse::<Source>().unwrap(), Source::Store);
        let (aud, src) = parse_delegate("examplegit=prompt").unwrap();
        assert_eq!((aud.as_str(), src), ("examplegit", Source::Prompt));
        assert_eq!(join_basic("alice", "p:w").unwrap(), "alice:p:w");
        for (u, p, why) in [
            ("", "x", "user name is empty"),
            ("a", "", "secret is empty"),
            ("a:b", "x", "colon"),
            ("a", "x\ny", "control"),
            ("a\r", "x", "control"),
        ] {
            let e = join_basic(u, p).unwrap_err().to_string();
            assert!(e.contains(why), "{u:?}/{p:?}: {e}");
            assert!(!e.contains("x\ny"), "the message must not echo the value");
        }
    }

    #[test]
    fn a_saved_credential_older_than_six_hours_is_refused_and_a_fresh_one_is_read() {
        let now = Timestamp::now();
        let fresh = stored_json(
            "alice:s3cret",
            now - jiff::SignedDuration::from_hours(5),
            24 * 3600,
        )
        .unwrap();
        assert_eq!(parse_stored(&fresh, now).unwrap(), "alice:s3cret");
        let old = stored_json(
            "alice:s3cret",
            now - jiff::SignedDuration::from_hours(7),
            24 * 3600,
        )
        .unwrap();
        let e = parse_stored(&old, now).unwrap_err().to_string();
        assert!(e.contains("six hours") && !e.contains("s3cret"), "{e}");
        let future = stored_json(
            "alice:s3cret",
            now + jiff::SignedDuration::from_hours(2),
            24 * 3600,
        )
        .unwrap();
        assert!(parse_stored(&future, now).is_err());
        assert!(parse_stored("not json", now).is_err());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn without_a_credential_store_the_store_source_says_so_and_logout_is_a_noop() {
        let e = read("a", &Source::Store, 900).unwrap_err().to_string();
        assert!(e.contains("no credential store"), "{e}");
        forget("a");
    }
}

// ----- ADR-0041: a user name and a secret ------------------------------------------------------------------------------

/// How old a Keychain item may be and still be used (ADR-0041 decision 5): a hard ceiling, not a
/// setting.
pub const STORE_MAX_AGE_SECS: i64 = 6 * 60 * 60;
/// The Keychain service mediatore's own items live under.
pub const STORE_SERVICE: &str = "mediatore";

/// `user:secret`, as a `credential: basic` delegation carries it. The user name ends at the first
/// colon (RFC 7617), so it has none; neither part is empty and neither holds a control character
/// (the broker refuses these too; refusing here says so before anything is sent). The error names
/// the rule, never the value.
pub fn join_basic(user: &str, secret: &str) -> anyhow::Result<String> {
    anyhow::ensure!(!user.is_empty(), "the user name is empty");
    anyhow::ensure!(!secret.is_empty(), "the secret is empty");
    anyhow::ensure!(
        !user.contains(':'),
        "the user name cannot hold a colon (RFC 7617)"
    );
    anyhow::ensure!(
        !user.chars().chain(secret.chars()).any(char::is_control),
        "the user name and the secret cannot hold a control character"
    );
    Ok(format!("{user}:{secret}"))
}

fn basic(token: String) -> Credential {
    Credential {
        token,
        refresh_token: None,
        expires_at: None,
    }
}

/// What the Keychain item holds: when it was saved and the `user:secret`.
#[derive(serde::Serialize, serde::Deserialize)]
struct Stored {
    saved_at: i64,
    /// How long the item may be used, in seconds: the claim's TTL, at most six hours (ADR-0043 decision 5). An item
    /// saved before this field existed has none, and keeps the six hours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_age_secs: Option<i64>,
    token: String,
}

/// The `user:secret` of a stored item, or an error when it is older than six hours or unreadable.
/// `now` is a parameter so the age rule is testable.
pub fn parse_stored(json: &str, now: Timestamp) -> anyhow::Result<String> {
    let s: Stored = serde_json::from_str(json)
        .map_err(|_| anyhow::anyhow!("the saved credential is not what mediatore wrote"))?;
    let age = now.as_second() - s.saved_at;
    // The least of the item's own limit (the claim it was saved for) and the six hours no item may pass.
    let limit = s
        .max_age_secs
        .map_or(STORE_MAX_AGE_SECS, |m| m.min(STORE_MAX_AGE_SECS));
    anyhow::ensure!(
        age <= limit,
        "the saved credential is older than the claim it was saved for (at most six hours); enter it again (--delegate <audience>=prompt)"
    );
    anyhow::ensure!(
        age >= -60,
        "the saved credential is dated in the future; enter it again"
    );
    Ok(s.token)
}

/// The Keychain item as JSON for `token`, saved now for a claim of `ttl_seconds`: it is good for that long and no
/// longer, and never past six hours.
#[cfg(any(target_os = "macos", test))]
fn stored_json(token: &str, now: Timestamp, ttl_seconds: u32) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&Stored {
        saved_at: now.as_second(),
        max_age_secs: Some(i64::from(ttl_seconds).min(STORE_MAX_AGE_SECS)),
        token: token.to_owned(),
    })?)
}

/// A lifetime in words for the prompt: `15 minutes`, `1 hour`, `90 seconds`.
fn lifetime_words(secs: i64) -> String {
    let plural = |n: i64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    if secs >= 3600 && secs % 3600 == 0 {
        plural(secs / 3600, "hour")
    } else if secs >= 60 && secs % 60 == 0 {
        plural(secs / 60, "minute")
    } else {
        plural(secs, "second")
    }
}

/// Type a user name and a secret at the terminal: the question on stderr, the secret with echo off,
/// nothing when stdin is not a terminal (a script uses `env:` or `file:`). On macOS it then offers to
/// keep them in the Keychain for the claim's TTL (at most six hours); the default is no.
fn prompt_basic(audience: &str, ttl_seconds: u32) -> anyhow::Result<Credential> {
    use std::io::{BufRead, IsTerminal, Write};
    anyhow::ensure!(
        std::io::stdin().is_terminal(),
        "no terminal to ask on: use --delegate {audience}=env:<NAME> or file:<path> (user:secret)"
    );
    let mut stdin = std::io::stdin().lock();
    let mut line = String::new();
    eprint!("{audience} user name: ");
    std::io::stderr().flush().ok();
    stdin.read_line(&mut line)?;
    let user = line.trim_end_matches(['\r', '\n']).to_owned();
    eprint!("{audience} password or token (not shown): ");
    std::io::stderr().flush().ok();
    let secret = {
        let _echo = EchoOff::new();
        let mut secret = String::new();
        stdin.read_line(&mut secret)?;
        eprintln!();
        secret.trim_end_matches(['\r', '\n']).to_owned()
    };
    let token = join_basic(&user, &secret)?;
    if cfg!(target_os = "macos") {
        let keep = i64::from(ttl_seconds).min(STORE_MAX_AGE_SECS);
        eprint!(
            "Keep it in the macOS Keychain for the claim's TTL, {}? [y/N] ",
            lifetime_words(keep)
        );
        std::io::stderr().flush().ok();
        let mut yn = String::new();
        stdin.read_line(&mut yn)?;
        if matches!(yn.trim(), "y" | "Y" | "yes") {
            store::save(audience, &token, ttl_seconds)?;
            eprintln!("saved; `mediatore logout --audience {audience}` removes it");
        }
    }
    Ok(basic(token))
}

/// Switches the terminal's echo off with `stty` and back on when dropped (no `unsafe`, no new crate).
struct EchoOff(bool);

impl EchoOff {
    fn new() -> Self {
        let ok = std::process::Command::new("stty")
            .arg("-echo")
            .stdin(std::process::Stdio::inherit())
            .status()
            .is_ok_and(|s| s.success());
        Self(ok)
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        if self.0 {
            let _ = std::process::Command::new("stty")
                .arg("echo")
                .stdin(std::process::Stdio::inherit())
                .status();
        }
    }
}

/// Delete mediatore's saved credential for `audience` (`mediatore logout --audience`). Idempotent.
pub fn forget(audience: &str) {
    store::delete(audience);
}

#[cfg(target_os = "macos")]
mod store {
    use super::{STORE_SERVICE, Timestamp, parse_stored, stored_json};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    pub fn load(audience: &str) -> anyhow::Result<super::Credential> {
        let raw = get_generic_password(STORE_SERVICE, audience).map_err(|_| {
            anyhow::anyhow!(
                "no saved credential for {audience}: enter it with --delegate {audience}=prompt"
            )
        })?;
        let json = String::from_utf8(raw)
            .map_err(|_| anyhow::anyhow!("the saved credential is not what mediatore wrote"))?;
        match parse_stored(&json, Timestamp::now()) {
            Ok(token) => Ok(super::basic(token)),
            Err(e) => {
                let _ = delete_generic_password(STORE_SERVICE, audience);
                Err(e)
            }
        }
    }

    pub fn save(audience: &str, token: &str, ttl_seconds: u32) -> anyhow::Result<()> {
        let json = stored_json(token, Timestamp::now(), ttl_seconds)?;
        set_generic_password(STORE_SERVICE, audience, json.as_bytes())
            .map_err(|e| anyhow::anyhow!("saving to the Keychain: {e}"))
    }

    pub fn delete(audience: &str) {
        // Not there is not an error: logout is idempotent.
        let _ = delete_generic_password(STORE_SERVICE, audience);
    }
}

#[cfg(not(target_os = "macos"))]
mod store {
    pub fn load(_audience: &str) -> anyhow::Result<super::Credential> {
        anyhow::bail!(
            "no credential store on this platform yet (macOS only): use --delegate <audience>=prompt, env:<NAME> or file:<path>"
        )
    }

    pub fn save(_audience: &str, _token: &str, _ttl_seconds: u32) -> anyhow::Result<()> {
        anyhow::bail!("no credential store on this platform yet (macOS only)")
    }

    pub fn delete(_audience: &str) {}
}
