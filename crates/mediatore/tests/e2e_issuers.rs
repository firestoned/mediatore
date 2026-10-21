// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Issuer profiles end to end (ADR-0017): the same broker, the same CLI login code and
//! the same session path against the fake issuer playing Google and Auth0, the two
//! genuine OIDC providers banlieue documents beside GitHub-through-Dex. Google: `email`
//! as the subject, no groups, `access_type=offline` for the refresh token, a client
//! secret the token endpoint wants from the installed-app client. Auth0: `email` as the
//! subject, groups under a namespaced claim, `offline_access` for the refresh token.

use std::future::IntoFuture;
use std::sync::Arc;

use chrono::Duration;
use mediatore_api::{AppState, Limiter};
use mediatore_client::{Api, LoginOptions, Session};
use mediatore_entra::{Backend, IssuerConfig, SessionConfig, Validator};
use mediatore_proto::{
    ClaimRequest, ClaimResponse, ErrorBody, NodeRegistration, Secret, TokenResponse, Workload,
};
use mediatore_spire::{MemoryEntries, Naming};
use mediatore_store::seal::LocalKeySealer;
use mediatore_store::{ClaimStore, MemoryStore};
use mediatore_sts::Sts;
use mediatore_testkit::{AUTH0_GROUPS_CLAIM, FakeIdp, Profile};

const TRUST_DOMAIN: &str = "sandbox.test";
const AUDIENCE: &str = "grafana.test";
const CLIENT_ID: &str = "mediatore";
/// Google's installed-app client secret: not a secret, but the token endpoint wants it.
const GOOGLE_SECRET: &str = "GOCSPX-not-a-secret";
const REQUIRED_GROUP: &str = "firestoned:sandbox-users";
const PEER_HEADER: &str = "x-mediatore-peer-spiffe-id";
const EK_HASH: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";

struct Harness {
    google: FakeIdp,
    auth0: FakeIdp,
    store: Arc<MemoryStore>,
    user_url: String,
    sandbox_url: String,
    http: reqwest::Client,
}

impl Harness {
    async fn start() -> Self {
        let google = FakeIdp::start_as(Profile::Google).await;
        google.set_client_secret(CLIENT_ID, GOOGLE_SECRET);
        let auth0 = FakeIdp::start_as(Profile::Auth0).await;
        let dir = mediatore_testkit::tempdir();
        let secret_file = dir.join("google-secret");
        std::fs::write(&secret_file, format!("{GOOGLE_SECRET}\n")).unwrap();
        let google_issuer = IssuerConfig {
            url: google.issuer.clone(),
            backend: Backend::Sts,
            client_id: CLIENT_ID.into(),
            subject_claim: "email".into(),
            required_group: None,
            session: Some(SessionConfig {
                client_id: CLIENT_ID.into(),
                client_secret_file: Some(secret_file),
            }),
            ca_file: None,
            entra: None,
            groups_claim: None,
        };
        let auth0_issuer = IssuerConfig {
            url: auth0.issuer.clone(),
            backend: Backend::Sts,
            client_id: CLIENT_ID.into(),
            subject_claim: "email".into(),
            required_group: Some(REQUIRED_GROUP.into()),
            session: Some(SessionConfig {
                client_id: CLIENT_ID.into(),
                client_secret_file: None,
            }),
            ca_file: None,
            entra: None,
            groups_claim: Some(AUTH0_GROUPS_CLAIM.into()),
        };
        // What `validator` in main.rs does with `client_secret_file`.
        let validator = Validator::new(vec![google_issuer, auth0_issuer])
            .with_session_secret(&google.issuer, Secret(GOOGLE_SECRET.into()));
        let sts = Sts::new(
            "https://mediatore.test",
            "e2e-1",
            mediatore_testkit::entra::fresh_p256_key_pem().as_bytes(),
            Duration::minutes(15),
        )
        .expect("sts");
        let store = MemoryStore::shared();
        let state = Arc::new(AppState {
            store: store.clone(),
            spire: Arc::new(MemoryEntries::default()),
            naming: Naming {
                trust_domain: TRUST_DOMAIN.into(),
            },
            validator,
            sts: Some(sts),
            audiences: vec![AUDIENCE.into()],
            obo_audiences: vec![],
            sandboxes: None,
            sandbox_namespace: "sandboxes".into(),
            sealer: Some(Arc::new(LocalKeySealer::new([5u8; 32]))),
            limiter: Limiter::new(60),
            dev_mode: true,
        });
        let user = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sandbox = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let user_url = format!("http://{}", user.local_addr().unwrap());
        let sandbox_url = format!("http://{}", sandbox.local_addr().unwrap());
        tokio::spawn(axum::serve(user, mediatore_api::user_router(state.clone())).into_future());
        tokio::spawn(axum::serve(sandbox, mediatore_api::sandbox_router(state)).into_future());
        mediatore_proto::tls::ensure_provider();
        let h = Self {
            google,
            auth0,
            store,
            user_url,
            sandbox_url,
            http: reqwest::Client::new(),
        };
        h.register_node().await;
        h
    }

    async fn register_node(&self) {
        let resp = self
            .http
            .post(format!("{}/v1/nodes", self.sandbox_url))
            .header(
                PEER_HEADER,
                format!("spiffe://{TRUST_DOMAIN}/banlieue/node/{EK_HASH}"),
            )
            .json(&NodeRegistration {
                ek_hash: EK_HASH.into(),
                dmi_uuid: uuid::Uuid::new_v4(),
                hostname: "pool-a-7".into(),
                provider: None,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    /// The real CLI login against `idp`, with the "browser" following the URL.
    async fn login(idp: &FakeIdp, login: &str, opts: LoginOptions) -> anyhow::Result<Session> {
        let _ = idp;
        mediatore_client::login(
            &LoginOptions {
                login_hint: Some(login.into()),
                ..opts
            },
            |url| {
                let url = url.to_owned();
                tokio::spawn(async move {
                    reqwest::Client::new().get(url).send().await.unwrap();
                });
            },
        )
        .await
    }

    /// Google's shape: no `offline_access`, `access_type=offline` and `prompt=consent`
    /// on the request, the installed-app secret at the token endpoint.
    fn google_opts(&self) -> LoginOptions {
        LoginOptions {
            issuer: self.google.issuer.clone(),
            client_id: CLIENT_ID.into(),
            scopes: ["openid", "email", "profile"]
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
            extra_params: vec![
                ("access_type".into(), "offline".into()),
                ("prompt".into(), "consent".into()),
            ],
            client_secret: Some(GOOGLE_SECRET.into()),
            login_hint: None,
            ca_pem: None,
        }
    }

    /// Auth0's shape: the default scopes (`offline_access` included), an `audience`.
    fn auth0_opts(&self) -> LoginOptions {
        LoginOptions {
            issuer: self.auth0.issuer.clone(),
            client_id: CLIENT_ID.into(),
            scopes: LoginOptions::default_scopes(),
            extra_params: vec![("audience".into(), "https://mediatore.test".into())],
            client_secret: None,
            login_hint: None,
            ca_pem: None,
        }
    }

    async fn claim(&self, session: &Session) -> anyhow::Result<(ClaimResponse, Session)> {
        Api::new(&self.user_url)
            .unwrap()
            .claim(
                session,
                &ClaimRequest {
                    pool_ref: "pool-a".into(),
                    ttl_seconds: 3600,
                    audiences: vec![AUDIENCE.into()],
                    workload: Workload {
                        image: "registry.internal:5000/sandbox:latest".into(),
                        args: vec![],
                    },
                    refresh_token: None,
                },
            )
            .await
    }

    async fn token(&self, claim: &ClaimResponse) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/token", self.sandbox_url))
            .header(
                PEER_HEADER,
                format!(
                    "spiffe://{TRUST_DOMAIN}/banlieue/claim/{}",
                    claim.uid.unwrap()
                ),
            )
            .json(&mediatore_proto::TokenRequest {
                audience: AUDIENCE.into(),
            })
            .send()
            .await
            .unwrap()
    }
}

async fn error_code(resp: reqwest::Response) -> (u16, String) {
    let status = resp.status().as_u16();
    let body: ErrorBody = resp.json().await.unwrap();
    (status, body.error)
}

fn payload(token: &str) -> serde_json::Value {
    use base64::Engine as _;
    let part = token.split('.').nth(1).unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn a_google_login_is_by_email_with_the_installed_app_secret_and_access_type_offline() {
    let h = Harness::start().await;
    let session = Harness::login(&h.google, "octocat", h.google_opts())
        .await
        .unwrap();
    assert_eq!(
        session.login, "octocat@example.com",
        "no username at Google"
    );
    assert!(session.refresh_token.is_some(), "access_type=offline");
    let (claim, spent) = h.claim(&session).await.unwrap();
    assert!(spent.refresh_token.is_none());
    let rec = h.store.get_claim(claim.uid.unwrap()).await.unwrap();
    assert_eq!(rec.subject.id, "octocat@example.com");
    assert_eq!(rec.subject.issuer, h.google.issuer);
    // Every issue refreshes at Google, with the secret the token endpoint wants.
    let resp = h.token(&claim).await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let minted: TokenResponse = resp.json().await.unwrap();
    let claims = payload(&minted.access_token);
    assert_eq!(claims["sub"], "octocat@example.com");
    assert!(
        claims
            .get("groups")
            .is_none_or(|g| g == &serde_json::json!([])),
        "Google has no groups: {claims}"
    );
    assert_eq!(h.google.refreshes(), 1);
    // Revoked at Google: released at the next issue.
    h.google.revoke("octocat");
    assert_eq!(
        error_code(h.token(&claim).await).await,
        (403, "session_revoked".into())
    );
}

#[tokio::test]
async fn a_google_login_without_access_type_offline_has_no_session_to_delegate() {
    let h = Harness::start().await;
    let mut opts = h.google_opts();
    opts.extra_params.clear();
    let session = Harness::login(&h.google, "octocat", opts).await.unwrap();
    assert!(session.refresh_token.is_none());
    let err = h.claim(&session).await.unwrap_err().to_string();
    assert!(err.contains("session_required"), "{err}");
    // offline_access is not a scope Google knows.
    let mut opts = h.google_opts();
    opts.scopes.push("offline_access".into());
    assert!(Harness::login(&h.google, "octocat", opts).await.is_err());
    // And the secret is not optional there.
    let mut opts = h.google_opts();
    opts.client_secret = None;
    assert!(Harness::login(&h.google, "octocat", opts).await.is_err());
}

#[tokio::test]
async fn an_auth0_login_is_by_email_with_groups_under_the_namespaced_claim() {
    let h = Harness::start().await;
    let session = Harness::login(&h.auth0, "hexley", h.auth0_opts())
        .await
        .unwrap();
    assert_eq!(session.login, "hexley@example.com");
    assert!(session.refresh_token.is_some(), "offline_access");
    let (claim, _) = h.claim(&session).await.unwrap();
    let minted: TokenResponse = h.token(&claim).await.json().await.unwrap();
    let claims = payload(&minted.access_token);
    assert_eq!(claims["sub"], "hexley@example.com");
    assert_eq!(
        claims["groups"],
        serde_json::json!([REQUIRED_GROUP]),
        "read from the namespaced claim"
    );
    // Taken out of the group at Auth0: the gate on the fresh token releases the claim.
    h.auth0.set_groups("hexley", &["firestoned:other"]);
    assert_eq!(
        error_code(h.token(&claim).await).await,
        (403, "session_revoked".into())
    );
    // A login outside the group never gets a sandbox.
    h.auth0.set_groups("hexley", &["firestoned:other"]);
    let session = Harness::login(&h.auth0, "hexley", h.auth0_opts())
        .await
        .unwrap();
    let err = h.claim(&session).await.unwrap_err().to_string();
    assert!(err.contains("403"), "{err}");
}
