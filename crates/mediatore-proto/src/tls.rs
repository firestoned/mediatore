// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The process-wide TLS provider (ADR-0007 decision 6).
//!
//! Every TLS client and server in the workspace is rustls on `aws-lc-rs`, and nothing else
//! is compiled in: `reqwest` and `kube` are built without a provider and `cargo deny` bans
//! `ring`. `reqwest` refuses to build a client until a provider is installed, so every
//! binary calls this first and every constructor that builds a client calls it too.
//!
//! Post-quantum posture: the provider is built with rustls's `prefer-post-quantum`, so
//! every key share we offer lists X25519MLKEM768 first and a peer that supports it gets
//! ML-KEM; the sandbox leg, where both ends are ours, accepts nothing else
//! (`mediatore-tls`). Outbound clients to systems we do not control (the identity provider, the
//! Kubernetes API) keep a classical fallback, since refusing them would only deny service.

/// Install `aws-lc-rs` as the default provider if none is installed yet. Idempotent: a
/// second call is a no-op, and with `ring` banned from the graph the provider already in
/// place can only be this one.
pub fn ensure_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Err means another thread won the race to install the same provider.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

/// A TLS 1.3-only client config over the Mozilla root store, for HTTPS to systems we do
/// not operate (identity-provider discovery, JWKS and token endpoints). Key exchange prefers
/// X25519MLKEM768 and falls back to classical groups, because the far end is not ours.
pub fn https_client_config() -> rustls::ClientConfig {
    ensure_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// A TLS 1.3-only client config that trusts exactly the CA certificates in `pem` and
/// nothing else: for an identity provider on a private PKI (`issuers[].ca_file`). The
/// public roots are deliberately absent, so a certificate from any other authority is
/// refused. Fails if `pem` holds no certificate.
pub fn https_client_config_with_ca(pem: &[u8]) -> Result<rustls::ClientConfig, std::io::Error> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject as _;

    ensure_provider();
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        let cert = cert.map_err(|e| std::io::Error::other(format!("ca_file: {e}")))?;
        roots
            .add(cert)
            .map_err(|e| std::io::Error::other(format!("ca_file: {e}")))?;
    }
    if roots.is_empty() {
        return Err(std::io::Error::other("ca_file holds no certificate"));
    }
    Ok(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A TLS 1.3-only client config over the Mozilla root store with the CA certificates in
/// `pem` added beside them: for the pool's registry mirror on a private PKI
/// (`MEDIATORE_REGISTRY_CA`, ADR-0029 decision 1), reached by the same client as any public
/// registry. Fails if `pem` holds no certificate.
pub fn https_client_config_with_extra_roots(
    pem: &[u8],
) -> Result<rustls::ClientConfig, std::io::Error> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject as _;

    ensure_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut added = 0;
    for cert in CertificateDer::pem_slice_iter(pem) {
        let cert = cert.map_err(|e| std::io::Error::other(format!("registry CA: {e}")))?;
        roots
            .add(cert)
            .map_err(|e| std::io::Error::other(format!("registry CA: {e}")))?;
        added += 1;
    }
    if added == 0 {
        return Err(std::io::Error::other("registry CA holds no certificate"));
    }
    Ok(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// The lowest TLS version the guest's egress proxy offers an upstream: a host a policy
/// bundle lists, a system we do not operate. TLS 1.3 unless the operator opts in to 1.2
/// (`MEDIATORE_EGRESS_MIN_TLS=1.2`), for an upstream that has no 1.3, such as an older
/// GitHub Enterprise Server. With 1.2 allowed the proxy still offers 1.3 first, so any
/// upstream that has it gets it; only an upstream that refuses 1.3 falls back.
///
/// It reaches nothing else: the broker, the identity provider, the registry pull and the
/// sandbox leg stay TLS 1.3 only whatever this is set to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UpstreamTls {
    /// TLS 1.3 only (the default).
    #[default]
    Tls13,
    /// TLS 1.3 preferred, TLS 1.2 accepted.
    Tls12,
}

impl UpstreamTls {
    fn versions(self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        static TLS13_ONLY: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
        static TLS13_THEN_12: [&rustls::SupportedProtocolVersion; 2] =
            [&rustls::version::TLS13, &rustls::version::TLS12];
        match self {
            Self::Tls13 => &TLS13_ONLY,
            Self::Tls12 => &TLS13_THEN_12,
        }
    }

    /// The setting as it is written in the environment: `1.3` or `1.2`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls13 => "1.3",
            Self::Tls12 => "1.2",
        }
    }
}

impl std::fmt::Display for UpstreamTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for UpstreamTls {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "1.3" => Ok(Self::Tls13),
            "1.2" => Ok(Self::Tls12),
            other => Err(format!(
                "{other:?} is not a TLS version setting: write 1.3 or 1.2"
            )),
        }
    }
}

/// The egress proxy's client config for an upstream that carries no CA of its own (a policy
/// bundle's direct egress): the Mozilla roots, plus the CA certificates in `extra_roots_pem`
/// when given (an operator's private PKI, `MEDIATORE_EGRESS_CA`), at the TLS versions `min`
/// allows. With no extra roots and [`UpstreamTls::Tls13`] it is [`https_client_config`].
///
/// # Errors
/// `extra_roots_pem` is given and holds no certificate: the proxy must not start with a CA
/// setting that did nothing.
pub fn egress_upstream_config(
    extra_roots_pem: Option<&[u8]>,
    min: UpstreamTls,
) -> Result<rustls::ClientConfig, std::io::Error> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject as _;

    ensure_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_roots_pem {
        let mut added = 0;
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|e| std::io::Error::other(format!("egress CA: {e}")))?;
            roots
                .add(cert)
                .map_err(|e| std::io::Error::other(format!("egress CA: {e}")))?;
            added += 1;
        }
        if added == 0 {
            return Err(std::io::Error::other("egress CA holds no certificate"));
        }
    }
    Ok(
        rustls::ClientConfig::builder_with_protocol_versions(min.versions())
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed CA, PEM-armoured by hand (rcgen is built without `pem`).
    fn ca_pem() -> Vec<u8> {
        use base64::Engine as _;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().to_vec();
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let body: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            body.join("\n")
        )
        .into_bytes()
    }

    #[test]
    fn a_private_ca_builds_a_config_and_an_empty_or_broken_file_does_not() {
        assert!(https_client_config_with_ca(&ca_pem()).is_ok());
        let err = https_client_config_with_ca(b"").unwrap_err();
        assert!(err.to_string().contains("no certificate"), "{err}");
        assert!(
            https_client_config_with_ca(
                b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"
            )
            .is_err()
        );
    }

    #[test]
    fn installs_aws_lc_rs_once_and_tolerates_repeats() {
        ensure_provider();
        ensure_provider();
        let p = rustls::crypto::CryptoProvider::get_default().expect("a provider");
        // aws-lc-rs is the only provider compiled in (cargo deny bans ring), and with
        // `prefer-post-quantum` its first key exchange group is the ML-KEM hybrid: that
        // is the key share every client we build sends first.
        assert_eq!(
            p.kx_groups.first().map(|g| g.name()),
            Some(rustls::NamedGroup::X25519MLKEM768),
            "expected X25519MLKEM768 to be preferred"
        );
    }

    #[test]
    fn the_upstream_setting_defaults_to_tls13() {
        assert_eq!(UpstreamTls::default(), UpstreamTls::Tls13);
        assert!(egress_upstream_config(None, UpstreamTls::Tls13).is_ok());
        assert!(egress_upstream_config(None, UpstreamTls::Tls12).is_ok());
    }

    #[test]
    fn the_upstream_setting_parses_1_3_and_1_2_and_refuses_anything_else() {
        assert_eq!("1.3".parse::<UpstreamTls>(), Ok(UpstreamTls::Tls13));
        assert_eq!(" 1.2 ".parse::<UpstreamTls>(), Ok(UpstreamTls::Tls12));
        for bad in ["", "1.1", "1.0", "tls1.2", "3", "TLS12"] {
            assert!(bad.parse::<UpstreamTls>().is_err(), "{bad:?}");
        }
        assert_eq!(UpstreamTls::Tls12.to_string(), "1.2");
    }

    #[test]
    fn upstream_extra_roots_must_hold_a_certificate_and_keep_the_public_roots() {
        let err = egress_upstream_config(Some(b""), UpstreamTls::Tls13).unwrap_err();
        assert!(err.to_string().contains("no certificate"), "{err}");
        assert!(
            egress_upstream_config(
                Some(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"),
                UpstreamTls::Tls13
            )
            .is_err()
        );
        assert!(egress_upstream_config(Some(&ca_pem()), UpstreamTls::Tls12).is_ok());
    }

    #[test]
    fn the_https_client_offers_mlkem_first() {
        let cfg = https_client_config();
        assert_eq!(
            cfg.crypto_provider().kx_groups.first().map(|g| g.name()),
            Some(rustls::NamedGroup::X25519MLKEM768)
        );
    }
}
