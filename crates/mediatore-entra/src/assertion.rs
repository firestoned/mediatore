// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The broker's credential at Entra (ADR-0016 decision 4): a client assertion, a JWT
//! that is `PS256` with `x5t#S256` naming the registered certificate, `aud` the token
//! endpoint, `iss` and `sub` the client id, a fresh `jti` and five minutes of life. The
//! signature comes from an RSA key in a file, from `OpenBao` transit (the key never enters
//! the process), or the assertion is the pod's projected `ServiceAccount` token under
//! workload identity federation (no key anywhere).

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use mediatore_proto::cert::ClientCertificate;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::IdpError;

/// How long a signed assertion is good for. Microsoft asks for minutes, not hours.
const ASSERTION_LIFETIME: Duration = Duration::minutes(5);

/// Entra ID (`backend: entra-obo`): how the broker authenticates as itself. Exactly one
/// of `key_file`, `transit` or `token_file`; the first two name the registered certificate
/// with `certificate_file`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntraConfig {
    /// The certificate registered on the app registration (PEM), for the `x5t#S256`
    /// header and the startup check that the signing key is its key.
    #[serde(default)]
    pub certificate_file: Option<PathBuf>,
    /// An RSA private key (PKCS#8 or PKCS#1 PEM) in a Secret volume: the homelab shape.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// An RSA key in `OpenBao` transit, signing with PSS over SHA-256: the work shape.
    #[serde(default)]
    pub transit: Option<mediatore_openbao::TransitConfig>,
    /// A projected `ServiceAccount` token presented as the assertion itself, for an app
    /// registration with a federated credential (audience `api://AzureADTokenExchange`):
    /// the AKS shape.
    #[serde(default)]
    pub token_file: Option<PathBuf>,
}

impl EntraConfig {
    /// The exactly-one rule: a key file or transit, each with a certificate, or a token
    /// file with none.
    pub fn validate(&self) -> Result<(), String> {
        let signers = usize::from(self.key_file.is_some())
            + usize::from(self.transit.is_some())
            + usize::from(self.token_file.is_some());
        if signers != 1 {
            return Err("exactly one of key_file, transit or token_file".to_owned());
        }
        match (self.token_file.is_some(), self.certificate_file.is_some()) {
            (false, false) => Err("certificate_file is required with key_file or transit".into()),
            (true, true) => Err("token_file takes no certificate_file".into()),
            _ => Ok(()),
        }
    }
}

/// Who signs the assertion.
enum Signer {
    /// The key in the process (`key_file`).
    Local(EncodingKey),
    /// The key in `OpenBao` transit; `sign` with PSS, SHA-256, the salt the hash's length.
    Transit {
        client: mediatore_openbao::Client,
        key: String,
    },
}

/// The broker's credential at Entra.
pub struct ClientAssertion(Kind);

enum Kind {
    /// A certificate credential: the assertion is signed, here or in `OpenBao`.
    Certificate {
        signer: Box<Signer>,
        thumbprint: String,
        verify: Box<DecodingKey>,
    },
    /// A federated credential: the projected token, read for every request.
    Federated { token_file: PathBuf },
}

impl std::fmt::Debug for ClientAssertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Kind::Certificate {
                thumbprint, signer, ..
            } => f
                .debug_struct("ClientAssertion::Certificate")
                .field("thumbprint", thumbprint)
                .field(
                    "signer",
                    &match signer.as_ref() {
                        Signer::Local(_) => "key_file",
                        Signer::Transit { .. } => "transit",
                    },
                )
                .finish(),
            Kind::Federated { token_file } => f
                .debug_struct("ClientAssertion::Federated")
                .field("token_file", token_file)
                .finish(),
        }
    }
}

/// The claims of a signed assertion.
#[derive(Serialize, Deserialize)]
struct Claims<'a> {
    aud: &'a str,
    iss: &'a str,
    sub: &'a str,
    jti: String,
    nbf: i64,
    iat: i64,
    exp: i64,
}

impl From<mediatore_openbao::Error> for IdpError {
    fn from(e: mediatore_openbao::Error) -> Self {
        use mediatore_openbao::Error;
        match e {
            Error::Unavailable(why) => IdpError::Upstream(format!("openbao: {why}")),
            Error::Denied(why) | Error::Rejected(why) | Error::Config(why) => {
                IdpError::Credential(format!("openbao: {why}"))
            }
        }
    }
}

impl ClientAssertion {
    /// Build the credential `cfg` describes and exercise it: a signed probe must verify
    /// against the certificate's public key, so a key that is not the registered
    /// certificate's, a wrong transit role or key, or an unreadable file fails here.
    pub async fn build(cfg: &EntraConfig) -> Result<Self, IdpError> {
        cfg.validate().map_err(IdpError::Credential)?;
        if let Some(token_file) = &cfg.token_file {
            let assertion = Self(Kind::Federated {
                token_file: token_file.clone(),
            });
            assertion.assert("probe", "probe").await?;
            return Ok(assertion);
        }
        let certificate_file = cfg
            .certificate_file
            .as_ref()
            .ok_or_else(|| IdpError::Credential("certificate_file is required".into()))?;
        let pem = std::fs::read(certificate_file).map_err(|e| {
            IdpError::Credential(format!(
                "certificate_file {}: {e}",
                certificate_file.display()
            ))
        })?;
        let cert = ClientCertificate::from_pem(&pem)
            .map_err(|e| IdpError::Credential(format!("certificate_file: {e}")))?;
        let signer = if let Some(key_file) = &cfg.key_file {
            let key = std::fs::read(key_file).map_err(|e| {
                IdpError::Credential(format!("key_file {}: {e}", key_file.display()))
            })?;
            Signer::Local(
                EncodingKey::from_rsa_pem(&key)
                    .map_err(|e| IdpError::Credential(format!("key_file: {e}")))?,
            )
        } else if let Some(transit) = &cfg.transit {
            Signer::Transit {
                client: mediatore_openbao::Client::connect(transit).await?,
                key: transit.key.clone(),
            }
        } else {
            return Err(IdpError::Credential("no signer".into()));
        };
        let assertion = Self(Kind::Certificate {
            signer: Box::new(signer),
            thumbprint: URL_SAFE_NO_PAD.encode(cert.thumbprint_s256()),
            verify: Box::new(DecodingKey::from_rsa_der(cert.rsa_public_key_der())),
        });
        assertion.probe().await?;
        Ok(assertion)
    }

    /// Sign a probe and verify it against the certificate: the key is the certificate's.
    async fn probe(&self) -> Result<(), IdpError> {
        let Kind::Certificate { verify, .. } = &self.0 else {
            return Ok(());
        };
        let jwt = self.assert("probe-client", "probe-endpoint").await?;
        let mut validation = Validation::new(Algorithm::PS256);
        validation.set_audience(&["probe-endpoint"]);
        validation.set_issuer(&["probe-client"]);
        jsonwebtoken::decode::<serde_json::Value>(&jwt, verify, &validation).map_err(|e| {
            IdpError::Credential(format!(
                "the signing key is not the registered certificate's: {e}"
            ))
        })?;
        Ok(())
    }

    /// The assertion for one request as `client_id` to `token_endpoint`.
    pub async fn assert(&self, client_id: &str, token_endpoint: &str) -> Result<String, IdpError> {
        match &self.0 {
            Kind::Federated { token_file } => std::fs::read_to_string(token_file)
                .map(|t| t.trim().to_owned())
                .map_err(|e| {
                    IdpError::Credential(format!("token_file {}: {e}", token_file.display()))
                }),
            Kind::Certificate {
                signer, thumbprint, ..
            } => {
                let now = Utc::now();
                let claims = Claims {
                    aud: token_endpoint,
                    iss: client_id,
                    sub: client_id,
                    jti: Uuid::new_v4().to_string(),
                    nbf: now.timestamp(),
                    iat: now.timestamp(),
                    exp: (now + ASSERTION_LIFETIME).timestamp(),
                };
                let header = Header {
                    alg: Algorithm::PS256,
                    typ: Some("JWT".to_owned()),
                    x5t_s256: Some(thumbprint.clone()),
                    ..Default::default()
                };
                match signer.as_ref() {
                    Signer::Local(key) => jsonwebtoken::encode(&header, &claims, key)
                        .map_err(|e| IdpError::Credential(format!("sign: {e}"))),
                    Signer::Transit { client, key } => {
                        let input = format!(
                            "{}.{}",
                            URL_SAFE_NO_PAD.encode(
                                serde_json::to_vec(&header)
                                    .map_err(|e| IdpError::Credential(e.to_string()))?
                            ),
                            URL_SAFE_NO_PAD.encode(
                                serde_json::to_vec(&claims)
                                    .map_err(|e| IdpError::Credential(e.to_string()))?
                            )
                        );
                        let reply = client
                            .call(
                                "sign",
                                key,
                                serde_json::json!({
                                    "input": STANDARD.encode(input.as_bytes()),
                                    "hash_algorithm": "sha2-256",
                                    "signature_algorithm": "pss",
                                    "salt_length": "hash",
                                }),
                            )
                            .await?;
                        let signature = reply
                            .get("data")
                            .and_then(|d| d.get("signature"))
                            .and_then(|s| s.as_str())
                            .and_then(|s| s.strip_prefix("vault:v"))
                            .and_then(|s| s.split_once(':'))
                            .map(|(_, b64)| b64)
                            .ok_or_else(|| {
                                IdpError::Credential("sign: no signature in reply".into())
                            })?;
                        let bytes = STANDARD.decode(signature).map_err(|e| {
                            IdpError::Credential(format!("sign: signature not base64: {e}"))
                        })?;
                        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(bytes)))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mediatore_testkit::tempdir;

    fn decode(jwt: &str, aud: &str, iss: &str) -> (Header, serde_json::Value) {
        let cert = ClientCertificate::from_pem(
            mediatore_testkit::entra::client_credential()
                .certificate_pem
                .as_bytes(),
        )
        .unwrap();
        let mut validation = Validation::new(Algorithm::PS256);
        validation.set_audience(&[aud]);
        validation.set_issuer(&[iss]);
        let data = jsonwebtoken::decode::<serde_json::Value>(
            jwt,
            &DecodingKey::from_rsa_der(cert.rsa_public_key_der()),
            &validation,
        )
        .expect("a PS256 assertion the certificate verifies");
        (data.header, data.claims)
    }

    #[test]
    fn the_config_names_exactly_one_signer_and_a_certificate_for_a_key() {
        let ok = |c: EntraConfig| c.validate().unwrap();
        ok(EntraConfig {
            certificate_file: Some("c".into()),
            key_file: Some("k".into()),
            ..Default::default()
        });
        ok(EntraConfig {
            token_file: Some("t".into()),
            ..Default::default()
        });
        for (cfg, why) in [
            (EntraConfig::default(), "exactly one"),
            (
                EntraConfig {
                    certificate_file: Some("c".into()),
                    key_file: Some("k".into()),
                    token_file: Some("t".into()),
                    ..Default::default()
                },
                "exactly one",
            ),
            (
                EntraConfig {
                    key_file: Some("k".into()),
                    ..Default::default()
                },
                "certificate_file is required",
            ),
            (
                EntraConfig {
                    certificate_file: Some("c".into()),
                    token_file: Some("t".into()),
                    ..Default::default()
                },
                "takes no certificate_file",
            ),
        ] {
            let err = cfg.validate().unwrap_err();
            assert!(err.contains(why), "{err}");
        }
    }

    #[tokio::test]
    async fn a_key_file_signs_ps256_with_the_certificate_thumbprint_for_the_endpoint() {
        let dir = tempdir();
        let (key, cert) = mediatore_testkit::entra::write_client_credential(&dir);
        let assertion = ClientAssertion::build(&EntraConfig {
            certificate_file: Some(cert),
            key_file: Some(key),
            ..Default::default()
        })
        .await
        .unwrap();
        let jwt = assertion
            .assert("app-id", "https://login.example/t/oauth2/v2.0/token")
            .await
            .unwrap();
        let (header, claims) = decode(&jwt, "https://login.example/t/oauth2/v2.0/token", "app-id");
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        let cert = ClientCertificate::from_pem(
            mediatore_testkit::entra::client_credential()
                .certificate_pem
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            header.x5t_s256.as_deref(),
            Some(URL_SAFE_NO_PAD.encode(cert.thumbprint_s256()).as_str())
        );
        assert_eq!(claims["sub"], "app-id");
        assert!(claims["jti"].as_str().is_some_and(|j| !j.is_empty()));
        let life = claims["exp"].as_i64().unwrap() - claims["nbf"].as_i64().unwrap();
        assert_eq!(life, ASSERTION_LIFETIME.num_seconds());
        let again = assertion.assert("app-id", "x").await.unwrap();
        assert_ne!(jwt, again, "every assertion has its own jti");
    }

    #[tokio::test]
    async fn a_key_that_is_not_the_certificates_and_a_missing_file_fail_the_build() {
        let dir = tempdir();
        let (_, cert) = mediatore_testkit::entra::write_client_credential(&dir);
        // Another RSA key than the certificate's: the probe does not verify.
        let other = dir.join("other.pem");
        std::fs::write(&other, mediatore_testkit::entra::fresh_rsa_key_pem()).unwrap();
        let err = ClientAssertion::build(&EntraConfig {
            certificate_file: Some(cert.clone()),
            key_file: Some(other),
            ..Default::default()
        })
        .await
        .unwrap_err();
        assert!(
            matches!(err, IdpError::Credential(ref m) if m.contains("not the registered certificate")),
            "{err}"
        );
        let err = ClientAssertion::build(&EntraConfig {
            certificate_file: Some(cert),
            key_file: Some(dir.join("missing.pem")),
            ..Default::default()
        })
        .await
        .unwrap_err();
        assert!(matches!(err, IdpError::Credential(_)), "{err}");
        let err = ClientAssertion::build(&EntraConfig {
            token_file: Some(dir.join("missing-token")),
            ..Default::default()
        })
        .await
        .unwrap_err();
        assert!(matches!(err, IdpError::Credential(_)), "{err}");
    }

    #[tokio::test]
    async fn transit_signs_the_same_assertion_without_the_key_in_the_process() {
        let dir = tempdir();
        let (_, cert) = mediatore_testkit::entra::write_client_credential(&dir);
        let fake = mediatore_testkit::FakeTransit::spawn("mediatore", "sa-jwt", "sealing").await;
        fake.create_rsa_key("entra");
        let token_file = dir.join("token");
        std::fs::write(&token_file, "sa-jwt").unwrap();
        let transit = |key: &str| mediatore_openbao::TransitConfig {
            url: fake.url.clone(),
            ca_file: None,
            mount: "transit".into(),
            key: key.into(),
            role: "mediatore".into(),
            token_file: token_file.clone(),
        };
        let assertion = ClientAssertion::build(&EntraConfig {
            certificate_file: Some(cert.clone()),
            transit: Some(transit("entra")),
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(fake.signs(), 1, "the probe");
        let jwt = assertion.assert("app-id", "endpoint").await.unwrap();
        let (header, claims) = decode(&jwt, "endpoint", "app-id");
        assert_eq!(header.alg, Algorithm::PS256);
        assert_eq!(claims["iss"], "app-id");
        assert_eq!(fake.signs(), 2);
        // The sealing key is AES: transit refuses to sign with it, and the build fails.
        let err = ClientAssertion::build(&EntraConfig {
            certificate_file: Some(cert),
            transit: Some(transit("sealing")),
            ..Default::default()
        })
        .await
        .unwrap_err();
        assert!(matches!(err, IdpError::Credential(_)), "{err}");
    }

    #[tokio::test]
    async fn a_federated_credential_is_the_projected_token_read_for_every_request() {
        let dir = tempdir();
        let token_file = dir.join("token");
        std::fs::write(&token_file, "first\n").unwrap();
        let assertion = ClientAssertion::build(&EntraConfig {
            token_file: Some(token_file.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(assertion.assert("app", "ep").await.unwrap(), "first");
        std::fs::write(&token_file, "rotated").unwrap();
        assert_eq!(assertion.assert("app", "ep").await.unwrap(), "rotated");
    }
}
