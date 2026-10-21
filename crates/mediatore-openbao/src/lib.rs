// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The `OpenBao` client (ADR-0015, ADR-0016): the broker logs in at the Kubernetes auth
//! method with its projected `ServiceAccount` token, keeps the `OpenBao` token it gets with
//! its lease, exchanges it again before the lease ends or at once when `OpenBao` answers
//! 403, and makes one transit call at a time (`encrypt`, `decrypt`, `sign`). The transit
//! sealer in `mediatore-store` and the client-assertion signer in `mediatore-entra` are
//! its two callers; neither holds a key, only this leased capability to use one.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// `OpenBao` transit, as configuration (`store.sealing.transit` and
/// `issuers[].entra.transit`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitConfig {
    /// `https://openbao.example:8200`; `http` only under `dev_mode`.
    pub url: String,
    /// PEM file with the CA certificates `OpenBao`'s certificate chains to; when set,
    /// nothing else is trusted for it.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// The transit engine's mount path (default `transit`).
    #[serde(default = "default_mount")]
    pub mount: String,
    /// The transit key: the derived key envelopes are sealed under, or the RSA key that
    /// signs the client assertion.
    pub key: String,
    /// The Kubernetes auth role the broker logs in as.
    pub role: String,
    /// The projected `ServiceAccount` token (audience `openbao`) presented at login
    /// (default `/var/run/secrets/openbao/token`). Read at every login, since it rotates.
    #[serde(default = "default_token_file")]
    pub token_file: PathBuf,
}

fn default_mount() -> String {
    "transit".to_owned()
}
fn default_token_file() -> PathBuf {
    PathBuf::from("/var/run/secrets/openbao/token")
}

/// What an `OpenBao` call can come back with.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `OpenBao` did not answer, or answered 5xx: an outage, not a refusal.
    #[error("openbao unavailable: {0}")]
    Unavailable(String),
    /// The login was refused, or the token was refused twice: a role, policy or token
    /// problem on the broker's side.
    #[error("openbao denied: {0}")]
    Denied(String),
    /// `OpenBao` refused the operation (400): a bad context, a tampered or retired
    /// ciphertext, a missing key, a key of the wrong type. Nothing to retry.
    #[error("openbao rejected the call: {0}")]
    Rejected(String),
    /// The configuration could not be used: an unreadable CA or token file, a client
    /// that would not build.
    #[error("openbao config: {0}")]
    Config(String),
}

/// How long before its lease ends a token is exchanged again.
const TOKEN_RENEW_MARGIN: Duration = Duration::from_secs(60);

struct Token {
    value: String,
    expires_at: Instant,
}

/// One `OpenBao` transit mount, reached as the broker's `ServiceAccount`.
pub struct Client {
    http: reqwest::Client,
    base: String,
    mount: String,
    role: String,
    token_file: PathBuf,
    token: tokio::sync::Mutex<Option<Token>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base)
            .field("mount", &self.mount)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// An `OpenBao` error body: `{"errors": ["..."]}`.
fn openbao_errors(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("errors").and_then(|e| e.as_array()).map(|e| {
                e.iter()
                    .filter_map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            })
        })
        .unwrap_or_else(|| body.chars().take(200).collect())
}

impl Client {
    /// Build the client over `ca_file` (or the public roots) and log in once, so a wrong
    /// URL, CA, token file or role fails here. The caller probes the key it needs.
    pub async fn connect(cfg: &TransitConfig) -> Result<Self, Error> {
        mediatore_proto::tls::ensure_provider();
        let tls = match &cfg.ca_file {
            Some(path) => {
                let pem = std::fs::read(path)
                    .map_err(|e| Error::Config(format!("ca_file {}: {e}", path.display())))?;
                mediatore_proto::tls::https_client_config_with_ca(&pem)
                    .map_err(|e| Error::Config(format!("ca_file: {e}")))?
            }
            None => mediatore_proto::tls::https_client_config(),
        };
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .build()
            .map_err(|e| Error::Config(format!("client: {e}")))?;
        let client = Self {
            http,
            base: cfg.url.trim_end_matches('/').to_owned(),
            mount: cfg.mount.trim_matches('/').to_owned(),
            role: cfg.role.clone(),
            token_file: cfg.token_file.clone(),
            token: tokio::sync::Mutex::new(None),
        };
        client.token(true).await?;
        Ok(client)
    }

    /// The mount this client speaks to, as configured (`transit` by default).
    #[must_use]
    pub fn mount(&self) -> &str {
        &self.mount
    }

    /// `POST auth/kubernetes/login` with the projected token, read now.
    async fn login(&self) -> Result<Token, Error> {
        let jwt = std::fs::read_to_string(&self.token_file)
            .map_err(|e| Error::Config(format!("token_file {}: {e}", self.token_file.display())))?;
        let resp = self
            .http
            .post(format!("{}/v1/auth/kubernetes/login", self.base))
            .json(&serde_json::json!({ "role": self.role, "jwt": jwt.trim() }))
            .send()
            .await
            .map_err(|e| Error::Unavailable(format!("login: {e}")))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.is_server_error() {
            return Err(Error::Unavailable(format!(
                "login: {status}: {}",
                openbao_errors(&body)
            )));
        }
        if !status.is_success() {
            return Err(Error::Denied(format!(
                "login refused: {status}: {}",
                openbao_errors(&body)
            )));
        }
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| Error::Unavailable(format!("login: {e}")))?;
        let auth = v
            .get("auth")
            .ok_or_else(|| Error::Denied("login: no auth in reply".into()))?;
        let value = auth
            .get("client_token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| Error::Denied("login: no client_token".into()))?
            .to_owned();
        let lease = auth
            .get("lease_duration")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        Ok(Token {
            value,
            expires_at: Instant::now() + Duration::from_secs(lease),
        })
    }

    /// The cached token, exchanged again when it is about to expire or `force` is set.
    async fn token(&self, force: bool) -> Result<String, Error> {
        let mut slot = self.token.lock().await;
        let stale = slot.as_ref().is_none_or(|t| {
            t.expires_at.saturating_duration_since(Instant::now()) < TOKEN_RENEW_MARGIN
        });
        if force || stale {
            *slot = Some(self.login().await?);
        }
        Ok(slot.as_ref().map(|t| t.value.clone()).unwrap_or_default())
    }

    /// One transit call, `POST /v1/<mount>/<op>/<key>`; a 403 is retried once after a
    /// fresh login, since the token may have been revoked or expired early.
    pub async fn call(
        &self,
        op: &str,
        key: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, Error> {
        let url = format!("{}/v1/{}/{op}/{key}", self.base, self.mount);
        let mut force = false;
        for _ in 0..2 {
            let token = self.token(force).await?;
            let resp = self
                .http
                .post(&url)
                .header("X-Vault-Token", token)
                .json(&body)
                .send()
                .await
                .map_err(|e| Error::Unavailable(format!("{op}: {e}")))?;
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::FORBIDDEN && !force {
                force = true;
                continue;
            }
            if status.is_server_error() {
                return Err(Error::Unavailable(format!(
                    "{op}: {status}: {}",
                    openbao_errors(&text)
                )));
            }
            if status == reqwest::StatusCode::FORBIDDEN {
                return Err(Error::Denied(format!(
                    "{op}: permission denied: {}",
                    openbao_errors(&text)
                )));
            }
            if !status.is_success() {
                return Err(Error::Rejected(format!(
                    "{op}: {status}: {}",
                    openbao_errors(&text)
                )));
            }
            return serde_json::from_str(&text)
                .map_err(|e| Error::Unavailable(format!("{op}: {e}")));
        }
        Err(Error::Denied(format!(
            "{op}: permission denied after a fresh login"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_transit_config_defaults_to_the_transit_mount_and_the_projected_token() {
        let cfg: TransitConfig = serde_json::from_value(serde_json::json!({
            "url": "https://openbao.home.example:8200", "key": "mediatore", "role": "mediatore"
        }))
        .unwrap();
        assert_eq!(cfg.mount, "transit");
        assert_eq!(
            cfg.token_file,
            PathBuf::from("/var/run/secrets/openbao/token")
        );
        assert!(cfg.ca_file.is_none());
    }

    #[test]
    fn an_openbao_error_body_is_summarised() {
        assert_eq!(
            openbao_errors(r#"{"errors":["permission denied","and more"]}"#),
            "permission denied; and more"
        );
        assert_eq!(openbao_errors("not json"), "not json");
    }
}
