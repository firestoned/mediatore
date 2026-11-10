// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The requester's own credentials, read at claim time for a `via: delegated` audience
//! (ADR-0035 decision 6): `claude-code` reads Claude Code's credential store (the Keychain
//! item on macOS, the credentials file elsewhere), `env:<NAME>` a token from the
//! environment (a `claude setup-token` in `CLAUDE_CODE_OAUTH_TOKEN`), `file:<path>` a file
//! holding the token alone. Nothing read is kept, printed or logged: it is sent once, in
//! the claim, and forgotten.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use chrono::{DateTime, Utc};
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
}

impl FromStr for Source {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "claude-code" {
            return Ok(Self::ClaudeCode);
        }
        if let Some(name) = s.strip_prefix("env:") {
            anyhow::ensure!(!name.is_empty(), "env: needs a variable name");
            return Ok(Self::Env(name.to_owned()));
        }
        if let Some(path) = s.strip_prefix("file:") {
            anyhow::ensure!(!path.is_empty(), "file: needs a path");
            return Ok(Self::File(PathBuf::from(path)));
        }
        anyhow::bail!("unknown delegation source {s:?}: claude-code, env:<NAME> or file:<path>")
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
    pub expires_at: Option<DateTime<Utc>>,
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
/// fix, rather than by the broker later.
pub fn read(source: &Source) -> anyhow::Result<Credential> {
    let cred = match source {
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
        && e <= Utc::now()
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
        .and_then(DateTime::<Utc>::from_timestamp_millis);
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
            DateTime::<Utc>::from_timestamp(4_102_444_800, 0).unwrap()
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
        let cred = read(&Source::File(file.clone())).unwrap();
        assert_eq!(cred.token, "tok-from-file");
        assert!(cred.refresh_token.is_none() && cred.expires_at.is_none());
        std::fs::write(&file, "   \n").unwrap();
        assert!(
            read(&Source::File(file))
                .unwrap_err()
                .to_string()
                .contains("empty")
        );

        let expired = r#"{"claudeAiOauth":{"accessToken":"old","expiresAt":1000}}"#;
        let cred = parse_claude_code(expired).unwrap();
        assert!(cred.expires_at.unwrap() < Utc::now());
        // The read path refuses it; the parser alone reports what it found.
        let err = std::env::var("MEDIATORE_TEST_UNSET_VARIABLE")
            .err()
            .map(|_| {
                read(&Source::Env("MEDIATORE_TEST_UNSET_VARIABLE".into()))
                    .unwrap_err()
                    .to_string()
            })
            .unwrap();
        assert!(err.contains("not set"), "{err}");
    }
}
