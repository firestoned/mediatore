// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Issuer profiles end to end (ADR-0017): the same broker, the same CLI login code and
//! the same session path against the fake issuer playing Google and Auth0, the two
//! genuine OIDC providers banlieue documents beside GitHub-through-Dex. Google: `email`
//! as the subject, no groups, `access_type=offline` for the refresh token, a client
//! secret the token endpoint wants from the installed-app client. Auth0: `email` as the
//! subject, groups under a namespaced claim, `offline_access` for the refresh token.
//!
//! Both identify a person by `email`, so the two subject spaces overlap: the same address
//! at each is two people. ADR-0071: each issuer has a `subject_prefix`, the minted `sub`
//! carries it, and a broker with two issuers and no prefixes does not start. ADR-0073: the
//! same prefix qualifies each of the token's `groups`. ADR-0074: a namespace's groups are
//! read only from the issuers its entry lists.

use std::future::IntoFuture;
use std::sync::Arc;

use jiff::SignedDuration;
use mediatore_api::{AppState, Limiter, NamespaceGrant, Namespaces};
use mediatore_client::{Api, LoginOptions, Session};
use mediatore_entra::{Backend, IssuerConfig, SessionConfig, Validator};
use mediatore_proto::{
    ClaimRequest, ClaimResponse, ErrorBody, NodeRegistration, Secret, TokenResponse, Workload,
};
use mediatore_spire::{MemoryEntries, Naming};
use mediatore_store::seal::LocalKeySealer;
use mediatore_store::{ClaimStore, MemoryStore};
use mediatore_sts::{Sts, SubjectPrefixes};
use mediatore_testkit::{AUTH0_GROUPS_CLAIM, FakeIdp, Profile};

const TRUST_DOMAIN: &str = "sandbox.test";
const AUDIENCE: &str = "grafana.test";
const CLIENT_ID: &str = "mediatore";
/// Google's installed-app client secret: not a secret, but the token endpoint wants it.
const GOOGLE_SECRET: &str = "GOCSPX-not-a-secret";
const REQUIRED_GROUP: &str = "firestoned:sandbox-users";
const PEER_HEADER: &str = "x-mediatore-peer-spiffe-id";
/// The `subject_prefix` of each issuer (ADR-0071 decision 1).
const GOOGLE_PREFIX: &str = "google:";
const AUTH0_PREFIX: &str = "auth0:";
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
    /// Both issuers, each with its `subject_prefix`.
    async fn start() -> Self {
        Self::start_with(Issuers::Both).await
    }

    #[allow(clippy::too_many_lines)] // three IdPs and every AppState field, listed in full
    async fn start_with(which: Issuers) -> Self {
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
            required_groups: None,
            allow_any_authenticated: true,
            session: Some(SessionConfig {
                client_id: CLIENT_ID.into(),
                client_secret_file: Some(secret_file),
            }),
            ca_file: None,
            entra: None,
            groups_claim: None,
            subject_prefix: which.prefix(GOOGLE_PREFIX),
        };
        let auth0_issuer = IssuerConfig {
            url: auth0.issuer.clone(),
            backend: Backend::Sts,
            client_id: CLIENT_ID.into(),
            subject_claim: "email".into(),
            required_group: Some(REQUIRED_GROUP.into()),
            required_groups: None,
            allow_any_authenticated: false,
            session: Some(SessionConfig {
                client_id: CLIENT_ID.into(),
                client_secret_file: None,
            }),
            ca_file: None,
            entra: None,
            groups_claim: Some(AUTH0_GROUPS_CLAIM.into()),
            subject_prefix: which.prefix(AUTH0_PREFIX),
        };
        let issuers = match which {
            Issuers::Both => vec![google_issuer, auth0_issuer],
            Issuers::GoogleAloneWithoutAPrefix => vec![google_issuer],
        };
        // What `sts` in main.rs does with the issuers' `subject_prefix` (ADR-0071): the set is
        // the one `Config::parse` accepted.
        let prefixes = SubjectPrefixes::new(
            issuers
                .iter()
                .map(|i| (i.url.as_str(), i.subject_prefix.as_deref())),
        )
        .expect("subject prefixes");
        // What `validator` in main.rs does with `client_secret_file`.
        let validator = Validator::new(issuers)
            .with_session_secret(&google.issuer, Secret(GOOGLE_SECRET.into()));
        let sts = Sts::new(
            "https://mediatore.test",
            "e2e-1",
            mediatore_testkit::entra::fresh_p256_key_pem().as_bytes(),
            SignedDuration::from_mins(15),
        )
        .expect("sts")
        .with_subject_prefixes(prefixes);
        let store = MemoryStore::shared();
        let state = Arc::new(AppState {
            inject: std::collections::BTreeMap::new(),
            inject_port: None,
            audience_catalog: None,
            logs: None,
            log_limiter: Limiter::per_second(2),
            log_wakes: mediatore_api::LogWakes::default(),
            accept_plain_gateway_identity: false,
            scopes: std::collections::BTreeMap::new(),
            store: store.clone(),
            spire: Arc::new(MemoryEntries::default()),
            naming: Naming {
                trust_domain: TRUST_DOMAIN.into(),
            },
            validator,
            sts: Some(sts),
            audiences: vec![AUDIENCE.into()],
            obo_audiences: vec![],
            egress: std::collections::BTreeMap::new(),
            rules: std::collections::BTreeMap::new(),
            cas: std::collections::BTreeMap::new(),
            no_credential: std::collections::BTreeSet::new(),
            secrets: std::collections::BTreeMap::new(),
            delegated: std::collections::BTreeMap::new(),
            registries: std::collections::BTreeMap::new(),
            registry_audiences: None,
            policy_egress: None,
            sandboxes: None,
            namespaces: Namespaces::Single("sandboxes".into()),
            max_ttl_seconds: mediatore_proto::DEFAULT_MAX_TTL_SECONDS,
            sealer: Some(Arc::new(LocalKeySealer::new([5u8; 32]))),
            limiter: Limiter::new(60),
            dev_mode: true,
            gateways: vec![],
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
                attestation: None,
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
            redirect: mediatore_client::Redirect::default(),
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
            redirect: mediatore_client::Redirect::default(),
        }
    }

    async fn claim(&self, session: &Session) -> anyhow::Result<(ClaimResponse, Session)> {
        Api::new(&self.user_url)
            .unwrap()
            .claim(
                session,
                &ClaimRequest {
                    namespace: None,
                    pool_ref: Some("pool-a".into()),
                    pool_selector: None,
                    selection: None,
                    ttl_seconds: 3600,
                    audiences: vec![AUDIENCE.into()],
                    workload: Workload {
                        image: "registry.internal:5000/sandbox:latest".into(),
                        args: vec![],
                        restart: mediatore_proto::RestartPolicy::Always,
                        logs: false,
                    },
                    refresh_token: None,
                    policy_ref: None,
                    delegations: vec![],
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

/// Which issuers the broker under test trusts.
#[derive(Clone, Copy)]
enum Issuers {
    /// Google and Auth0, each with its `subject_prefix`.
    Both,
    /// Google alone and no `subject_prefix`: a deployment from before ADR-0071.
    GoogleAloneWithoutAPrefix,
}

impl Issuers {
    fn prefix(self, prefix: &str) -> Option<String> {
        matches!(self, Self::Both).then(|| prefix.to_owned())
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
    assert_eq!(
        claims["sub"],
        format!("{GOOGLE_PREFIX}octocat@example.com"),
        "two issuers: the issuer's prefix, then the id (ADR-0071)"
    );
    assert_eq!(claims["upstream_iss"], h.google.issuer);
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
    assert_eq!(claims["sub"], format!("{AUTH0_PREFIX}hexley@example.com"));
    assert_eq!(
        claims["groups"],
        serde_json::json!([format!("{AUTH0_PREFIX}{REQUIRED_GROUP}")]),
        "read from the namespaced claim, behind the issuer's prefix (ADR-0073)"
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

// ----- ADR-0046 decision 2: the spelling of a group is exactly what the operator lists ------------------------------

const GATE_PREFIXED: &str = "example-org:APP_EXAMPLE_ADMIN";
const GATE_BARE: &str = "APP_EXAMPLE_ADMIN";

/// A user API over real HTTP behind one issuer whose gate is `gate`, and a token for a
/// service ID that carries exactly `groups`. Returns the status and the raw body of
/// `POST /v1/claims`.
async fn claim_through_gate(gate: IssuerGate, groups: &[&str]) -> (u16, String) {
    let idp = FakeIdp::start().await;
    let (required_group, required_groups) = match gate {
        IssuerGate::Single(g) => (Some(g.to_owned()), None),
        IssuerGate::List(l) => (None, Some(l.iter().map(|g| (*g).to_owned()).collect())),
    };
    let validator = Validator::new(vec![IssuerConfig {
        url: idp.issuer.clone(),
        backend: Backend::Sts,
        client_id: CLIENT_ID.into(),
        subject_claim: "preferred_username".into(),
        required_group,
        required_groups,
        allow_any_authenticated: false,
        session: None,
        ca_file: None,
        entra: None,
        groups_claim: None,
        subject_prefix: None,
    }]);
    let state = Arc::new(AppState {
        inject: std::collections::BTreeMap::new(),
        inject_port: None,
        audience_catalog: None,
        logs: None,
        log_limiter: Limiter::per_second(2),
        log_wakes: mediatore_api::LogWakes::default(),
        accept_plain_gateway_identity: false,
        scopes: std::collections::BTreeMap::new(),
        store: MemoryStore::shared(),
        spire: Arc::new(MemoryEntries::default()),
        naming: Naming {
            trust_domain: TRUST_DOMAIN.into(),
        },
        validator,
        sts: None,
        audiences: vec![AUDIENCE.into()],
        obo_audiences: vec![],
        egress: std::collections::BTreeMap::new(),
        rules: std::collections::BTreeMap::new(),
        cas: std::collections::BTreeMap::new(),
        no_credential: std::collections::BTreeSet::new(),
        secrets: std::collections::BTreeMap::new(),
        delegated: std::collections::BTreeMap::new(),
        registries: std::collections::BTreeMap::new(),
        registry_audiences: None,
        policy_egress: None,
        sandboxes: None,
        namespaces: Namespaces::Single("sandboxes".into()),
        max_ttl_seconds: mediatore_proto::DEFAULT_MAX_TTL_SECONDS,
        sealer: Some(Arc::new(LocalKeySealer::new([5u8; 32]))),
        limiter: Limiter::new(60),
        dev_mode: true,
        gateways: vec![],
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(axum::serve(listener, mediatore_api::user_router(state)).into_future());
    let token = idp.token(serde_json::json!({
        "aud": CLIENT_ID,
        "sub": "svc-example",
        "preferred_username": "svc-example",
        "groups": groups,
    }));
    let resp = reqwest::Client::new()
        .post(format!("{url}/v1/claims"))
        .bearer_auth(token)
        .json(&ClaimRequest {
            namespace: None,
            pool_ref: Some("pool-a".into()),
            pool_selector: None,
            selection: None,
            ttl_seconds: 600,
            audiences: vec![AUDIENCE.into()],
            workload: Workload {
                image: "registry.internal:5000/sandbox:latest".into(),
                args: vec![],
                restart: mediatore_proto::RestartPolicy::Always,
                logs: false,
            },
            refresh_token: None,
            policy_ref: None,
            delegations: vec![],
        })
        .send()
        .await
        .unwrap();
    (resp.status().as_u16(), resp.text().await.unwrap())
}

enum IssuerGate {
    /// The pre-ADR-0046 `required_group: <value>`.
    Single(&'static str),
    /// `required_groups: [..]`.
    List(&'static [&'static str]),
}

#[tokio::test]
async fn a_service_id_with_a_bare_group_passes_when_both_spellings_are_listed() {
    let (status, body) =
        claim_through_gate(IssuerGate::List(&[GATE_PREFIXED, GATE_BARE]), &[GATE_BARE]).await;
    assert_eq!(status, 201, "{body}");
}

#[tokio::test]
async fn the_same_service_id_is_refused_under_the_single_prefixed_required_group() {
    let (status, body) = claim_through_gate(IssuerGate::Single(GATE_PREFIXED), &[GATE_BARE]).await;
    assert_eq!(status, 403, "{body}");
    for group in [GATE_PREFIXED, GATE_BARE] {
        assert!(!body.contains(group), "the 403 names a group: {body}");
    }
}

#[tokio::test]
async fn a_prefixed_group_is_refused_under_a_gate_that_lists_only_the_bare_name() {
    let (status, body) = claim_through_gate(IssuerGate::List(&[GATE_BARE]), &[GATE_PREFIXED]).await;
    assert_eq!(status, 403, "{body}");
    assert!(!body.contains(GATE_BARE), "the 403 names a group: {body}");
}

// ----- ADR-0071: `sub` qualified by upstream issuer ------------------------------------------------------------------

#[tokio::test]
async fn the_same_subject_id_at_two_issuers_gets_two_different_subs() {
    let h = Harness::start().await;
    // One address, two accounts: `octocat@example.com` at Google and at Auth0.
    h.auth0.set_groups("octocat", &[REQUIRED_GROUP]);
    let at_google = Harness::login(&h.google, "octocat", h.google_opts())
        .await
        .unwrap();
    let at_auth0 = Harness::login(&h.auth0, "octocat", h.auth0_opts())
        .await
        .unwrap();
    let (google_claim, _) = h.claim(&at_google).await.unwrap();
    let google_rec = h.store.get_claim(google_claim.uid.unwrap()).await.unwrap();
    let minted: TokenResponse = h.token(&google_claim).await.json().await.unwrap();
    let google = payload(&minted.access_token);
    let (auth0_claim, _) = h.claim(&at_auth0).await.unwrap();
    let auth0_rec = h.store.get_claim(auth0_claim.uid.unwrap()).await.unwrap();
    let minted: TokenResponse = h.token(&auth0_claim).await.json().await.unwrap();
    let auth0 = payload(&minted.access_token);

    // The broker's own records hold the same id under two issuers ...
    assert_eq!(google_rec.subject.id, "octocat@example.com");
    assert_eq!(auth0_rec.subject.id, google_rec.subject.id);
    assert_ne!(auth0_rec.subject.issuer, google_rec.subject.issuer);
    // ... and a resource server that reads `sub` alone still sees two people.
    assert_eq!(google["sub"], format!("{GOOGLE_PREFIX}octocat@example.com"));
    assert_eq!(auth0["sub"], format!("{AUTH0_PREFIX}octocat@example.com"));
    assert_ne!(google["sub"], auth0["sub"]);
    assert_eq!(google["upstream_iss"], h.google.issuer);
    assert_eq!(auth0["upstream_iss"], h.auth0.issuer);
}

#[tokio::test]
async fn one_issuer_without_a_prefix_mints_the_bare_sub() {
    let h = Harness::start_with(Issuers::GoogleAloneWithoutAPrefix).await;
    let session = Harness::login(&h.google, "octocat", h.google_opts())
        .await
        .unwrap();
    let (claim, _) = h.claim(&session).await.unwrap();
    let minted: TokenResponse = h.token(&claim).await.json().await.unwrap();
    let claims = payload(&minted.access_token);
    assert_eq!(
        claims["sub"], "octocat@example.com",
        "one issuer, no prefix: the token of before ADR-0071"
    );
    assert_eq!(claims["upstream_iss"], h.google.issuer);
}

// ----- ADR-0073 and ADR-0074: one group name at two issuers ---------------------------------------------------------

/// The group name both directories use, for two different sets of people.
const SHARED_GROUP: &str = "platform-admins";
const DEX_PREFIX: &str = "dex:";
const CORP_PREFIX: &str = "corp:";

/// A broker trusting two Dex-shaped session issuers, `dex:` and `corp:`, both of which put
/// groups in their tokens, serving `namespaces` (with [`FIRST`] and [`SECOND`] standing for
/// the two issuers' URLs).
struct TwoDirectories {
    first: FakeIdp,
    second: FakeIdp,
    user_url: String,
    sandbox_url: String,
    http: reqwest::Client,
}

const FIRST: &str = "https://first.placeholder.test";
const SECOND: &str = "https://second.placeholder.test";

impl TwoDirectories {
    #[allow(clippy::too_many_lines)] // every AppState field, listed in full
    async fn start(namespaces: Namespaces) -> Self {
        let first = FakeIdp::start().await;
        let second = FakeIdp::start().await;
        let issuer = |url: &str, prefix: &str| IssuerConfig {
            url: url.to_owned(),
            backend: Backend::Sts,
            client_id: CLIENT_ID.into(),
            subject_claim: "preferred_username".into(),
            required_group: None,
            required_groups: None,
            allow_any_authenticated: true,
            session: Some(SessionConfig {
                client_id: CLIENT_ID.into(),
                client_secret_file: None,
            }),
            ca_file: None,
            entra: None,
            groups_claim: None,
            subject_prefix: Some(prefix.to_owned()),
        };
        let issuers = vec![
            issuer(&first.issuer, DEX_PREFIX),
            issuer(&second.issuer, CORP_PREFIX),
        ];
        let prefixes = SubjectPrefixes::new(
            issuers
                .iter()
                .map(|i| (i.url.as_str(), i.subject_prefix.as_deref())),
        )
        .expect("subject prefixes");
        let namespaces = match namespaces {
            Namespaces::Map(map) => Namespaces::Map(
                map.into_iter()
                    .map(|(ns, mut grant)| {
                        for i in &mut grant.issuers {
                            if i == FIRST {
                                first.issuer.clone_into(i);
                            } else if i == SECOND {
                                second.issuer.clone_into(i);
                            }
                        }
                        (ns, grant)
                    })
                    .collect(),
            ),
            single @ Namespaces::Single(_) => single,
        };
        let sts = Sts::new(
            "https://mediatore.test",
            "e2e-1",
            mediatore_testkit::entra::fresh_p256_key_pem().as_bytes(),
            SignedDuration::from_mins(15),
        )
        .expect("sts")
        .with_subject_prefixes(prefixes);
        let state = Arc::new(AppState {
            inject: std::collections::BTreeMap::new(),
            inject_port: None,
            audience_catalog: None,
            logs: None,
            log_limiter: Limiter::per_second(2),
            log_wakes: mediatore_api::LogWakes::default(),
            accept_plain_gateway_identity: false,
            scopes: std::collections::BTreeMap::new(),
            store: MemoryStore::shared(),
            spire: Arc::new(MemoryEntries::default()),
            naming: Naming {
                trust_domain: TRUST_DOMAIN.into(),
            },
            validator: Validator::new(issuers),
            sts: Some(sts),
            audiences: vec![AUDIENCE.into()],
            obo_audiences: vec![],
            egress: std::collections::BTreeMap::new(),
            rules: std::collections::BTreeMap::new(),
            cas: std::collections::BTreeMap::new(),
            no_credential: std::collections::BTreeSet::new(),
            secrets: std::collections::BTreeMap::new(),
            delegated: std::collections::BTreeMap::new(),
            registries: std::collections::BTreeMap::new(),
            registry_audiences: None,
            policy_egress: None,
            sandboxes: None,
            namespaces,
            max_ttl_seconds: mediatore_proto::DEFAULT_MAX_TTL_SECONDS,
            sealer: Some(Arc::new(LocalKeySealer::new([6u8; 32]))),
            limiter: Limiter::new(60),
            dev_mode: true,
            gateways: vec![],
        });
        let user = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sandbox = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let user_url = format!("http://{}", user.local_addr().unwrap());
        let sandbox_url = format!("http://{}", sandbox.local_addr().unwrap());
        tokio::spawn(axum::serve(user, mediatore_api::user_router(state.clone())).into_future());
        tokio::spawn(axum::serve(sandbox, mediatore_api::sandbox_router(state)).into_future());
        mediatore_proto::tls::ensure_provider();
        let h = Self {
            first,
            second,
            user_url,
            sandbox_url,
            http: reqwest::Client::new(),
        };
        let resp = h
            .http
            .post(format!("{}/v1/nodes", h.sandbox_url))
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
        h
    }

    /// A login at `idp` holding [`SHARED_GROUP`], delegated with a claim in `namespace`.
    async fn claim(
        &self,
        idp: &FakeIdp,
        login: &str,
        namespace: Option<&str>,
    ) -> reqwest::Response {
        idp.set_groups(login, &[SHARED_GROUP]);
        let (id_token, refresh_token) = idp.session(login, CLIENT_ID);
        self.http
            .post(format!("{}/v1/claims", self.user_url))
            .bearer_auth(id_token)
            .json(&ClaimRequest {
                namespace: namespace.map(ToOwned::to_owned),
                pool_ref: Some("pool-a".into()),
                pool_selector: None,
                selection: None,
                ttl_seconds: 3600,
                audiences: vec![AUDIENCE.into()],
                workload: Workload {
                    image: "registry.internal:5000/sandbox:latest".into(),
                    args: vec![],
                    restart: mediatore_proto::RestartPolicy::Always,
                    logs: false,
                },
                refresh_token: Some(Secret(refresh_token)),
                policy_ref: None,
                delegations: vec![],
            })
            .send()
            .await
            .unwrap()
    }

    /// The claims of a token the broker mints for `claim`.
    async fn minted(&self, claim: &ClaimResponse) -> serde_json::Value {
        let resp = self
            .http
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
            .unwrap();
        assert_eq!(resp.status(), 200);
        let minted: TokenResponse = resp.json().await.unwrap();
        payload(&minted.access_token)
    }
}

#[tokio::test]
async fn the_same_group_at_two_issuers_reaches_the_resource_server_as_two() {
    let h = TwoDirectories::start(Namespaces::Single("sandboxes".into())).await;
    let mut tokens = vec![];
    for idp in [&h.first, &h.second] {
        let resp = h.claim(idp, "octocat", None).await;
        assert_eq!(resp.status(), 201);
        let claim: ClaimResponse = resp.json().await.unwrap();
        tokens.push(h.minted(&claim).await);
    }
    let (at_first, at_second) = (&tokens[0], &tokens[1]);
    assert_eq!(at_first["sub"], format!("{DEX_PREFIX}octocat"));
    assert_eq!(at_second["sub"], format!("{CORP_PREFIX}octocat"));
    assert_eq!(
        at_first["groups"],
        serde_json::json!([format!("{DEX_PREFIX}{SHARED_GROUP}")])
    );
    assert_eq!(
        at_second["groups"],
        serde_json::json!([format!("{CORP_PREFIX}{SHARED_GROUP}")])
    );
    assert_ne!(
        at_first["groups"], at_second["groups"],
        "a resource server that maps groups sees two groups"
    );
}

#[tokio::test]
async fn the_same_group_name_at_two_issuers_reaches_only_the_listed_issuers_namespace() {
    let entry = |issuer: &str| NamespaceGrant {
        groups: vec![SHARED_GROUP.to_owned()],
        issuers: vec![issuer.to_owned()],
    };
    let h = TwoDirectories::start(Namespaces::Map(std::collections::BTreeMap::from([
        ("team-dex".to_owned(), entry(FIRST)),
        ("team-corp".to_owned(), entry(SECOND)),
    ])))
    .await;
    for (idp, own, other) in [
        (&h.first, "team-dex", "team-corp"),
        (&h.second, "team-corp", "team-dex"),
    ] {
        let resp = h.claim(idp, "octocat", Some(own)).await;
        assert_eq!(resp.status(), 201, "{own}: {}", resp.text().await.unwrap());
        let resp = h.claim(idp, "octocat", Some(other)).await;
        assert_eq!(resp.status(), 403, "{other} lists the other issuer");
        let body: ErrorBody = resp.json().await.unwrap();
        assert_eq!(body.error, "forbidden");
    }
}

/// `mediatore serve` on `config`: its exit status and what it wrote to stderr. The run is
/// expected to end at the configuration load; one that is still up after a minute is killed.
fn serve_until_exit(config: &std::path::Path) -> (Option<i32>, String) {
    use std::io::Read as _;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mediatore"))
        .arg("serve")
        .arg("--config")
        .arg(config)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the broker binary runs");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (status.and_then(|s| s.code()), stderr)
}

/// A whole broker configuration under `dev_mode` on loopback with an `sts`, trusting
/// `issuers` (the YAML list items).
fn broker_config(dir: &std::path::Path, issuers: &str) -> std::path::PathBuf {
    let key = dir.join("sts.pem");
    std::fs::write(&key, mediatore_testkit::entra::fresh_p256_key_pem()).unwrap();
    let path = dir.join("mediatore.yaml");
    std::fs::write(
        &path,
        format!(
            "trust_domain: {TRUST_DOMAIN}\nlisten: {{ user: 127.0.0.1:0, sandbox: 127.0.0.1:0 }}\ndev_mode: true\nsts: {{ issuer: https://mediatore.test, kid: k, signing_key_file: {} }}\naudiences:\n  - {{ name: {AUDIENCE}, via: sts }}\nissuers:\n{issuers}",
            key.display()
        ),
    )
    .unwrap();
    path
}

#[test]
fn two_issuers_without_subject_prefixes_refuse_to_start() {
    let dir = mediatore_testkit::tempdir();
    let two = "  - { url: \"https://accounts.example.com\", backend: sts, client_id: m, subject_claim: email, allow_any_authenticated: true }\n  - { url: \"https://login.example.com\", backend: sts, client_id: m, subject_claim: email, allow_any_authenticated: true }\n";
    let (code, stderr) = serve_until_exit(&broker_config(&dir, two));
    assert_eq!(code, Some(1), "the broker must not start: {stderr}");
    assert!(
        stderr.contains("issuers[https://accounts.example.com].subject_prefix"),
        "the start error names the key and the issuer: {stderr}"
    );
    assert!(stderr.contains("ADR-0071"), "{stderr}");

    // One prefix is not enough, and the same prefix twice is the same refusal.
    for (issuers, named) in [
        (
            two.replacen("client_id: m,", "client_id: m, subject_prefix: \"a:\",", 1),
            "issuers[https://login.example.com].subject_prefix",
        ),
        (
            two.replace("client_id: m,", "client_id: m, subject_prefix: \"a:\","),
            "overlap",
        ),
    ] {
        let dir = mediatore_testkit::tempdir();
        let (code, stderr) = serve_until_exit(&broker_config(&dir, &issuers));
        assert_eq!(code, Some(1), "the broker must not start: {stderr}");
        assert!(stderr.contains(named), "{stderr}");
    }
}
