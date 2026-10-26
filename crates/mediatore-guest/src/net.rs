// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The jail's network bound (ADR-0020): one nftables table per claim whose output hook
//! sends the sandbox uid's packets to a chain that admits the broker, the resolved egress
//! endpoints of the claim's audiences and DNS to the VM's resolvers, then logs and drops.
//! Every other uid is untouched. Rendered as text so the exact ruleset is pinned by tests
//! and hashed in the log; loaded in one `nft -f` transaction before the jail starts.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;
use std::process::Stdio;

use anyhow::Context as _;
use mediatore_proto::Endpoint;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt as _;

/// The table, `inet` family so one ruleset covers both address families.
pub const TABLE: &str = "mediatore_sandbox";
/// The `nftables` command; `/usr/sbin` is on root's path under systemd.
pub const NFT: &str = "nft";
/// Where the VM's resolvers are read from.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";
/// Prefix of the kernel log line for a dropped packet.
const LOG_PREFIX: &str = "mediatore-sandbox drop: ";

/// What the sandbox uid may reach, with every name already resolved (decision 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    /// The sandbox user's uid, what `meta skuid` matches.
    pub uid: u32,
    /// TCP destinations: the broker and the claim's egress, as addresses.
    pub allow: BTreeSet<(IpAddr, u16)>,
    /// Resolvers DNS may go to, UDP and TCP 53.
    pub dns: BTreeSet<IpAddr>,
}

impl Ruleset {
    /// The broker and `egress` resolved for `uid`, the resolvers read from `resolv_conf`.
    ///
    /// # Errors
    /// A broker URL without a host or port, or a broker that resolves to nothing: nothing
    /// would work. An egress endpoint that does not resolve is omitted with a warning.
    pub async fn resolve(
        uid: u32,
        mediatore_url: &str,
        egress: &[Endpoint],
        resolv_conf: &Path,
    ) -> anyhow::Result<Self> {
        let broker = broker_endpoint(mediatore_url)?;
        let mut allow = BTreeSet::new();
        let addrs = lookup(&broker)
            .await
            .with_context(|| format!("resolving the broker {broker}"))?;
        anyhow::ensure!(
            !addrs.is_empty(),
            "the broker {broker} resolves to no address"
        );
        allow.extend(addrs);
        for e in egress {
            match lookup(e).await {
                Ok(a) if !a.is_empty() => allow.extend(a),
                Ok(_) => {
                    tracing::warn!(endpoint = %e, "egress endpoint resolves to no address; omitted");
                }
                Err(err) => {
                    tracing::warn!(endpoint = %e, error = %err, "egress endpoint does not resolve; omitted");
                }
            }
        }
        Ok(Self {
            uid,
            allow,
            dns: resolvers(resolv_conf),
        })
    }

    /// The `nft -f` script: creates the table if absent, deletes it, defines it again, so
    /// a stale table from an earlier claim is replaced in the same transaction.
    #[must_use]
    pub fn render(&self) -> String {
        let uid = self.uid;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# mediatore guest (ADR-0020): uid {uid} reaches the broker, the claim's egress and DNS; nothing else"
        );
        let _ = writeln!(out, "table inet {TABLE}");
        let _ = writeln!(out, "delete table inet {TABLE}");
        let _ = writeln!(out, "table inet {TABLE} {{");
        let (v4, v6): (Vec<_>, Vec<_>) = self.allow.iter().partition(|(ip, _)| ip.is_ipv4());
        let (d4, d6): (Vec<_>, Vec<_>) = self.dns.iter().partition(|ip| ip.is_ipv4());
        let pairs = |v: &[&(IpAddr, u16)]| {
            v.iter()
                .map(|(ip, port)| format!("{ip} . {port}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let addrs = |v: &[&IpAddr]| {
            v.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        set(&mut out, "allow4", "ipv4_addr . inet_service", &pairs(&v4));
        set(&mut out, "allow6", "ipv6_addr . inet_service", &pairs(&v6));
        set(&mut out, "dns4", "ipv4_addr", &addrs(&d4));
        set(&mut out, "dns6", "ipv6_addr", &addrs(&d6));
        let _ = writeln!(out, "  chain output {{");
        let _ = writeln!(
            out,
            "    type filter hook output priority filter; policy accept;"
        );
        let _ = writeln!(out, "    meta skuid {uid} jump sandbox");
        let _ = writeln!(out, "  }}");
        let _ = writeln!(out, "  chain sandbox {{");
        for rule in [
            "ct state established,related accept",
            "ip daddr . tcp dport @allow4 accept",
            "ip6 daddr . tcp dport @allow6 accept",
            "ip daddr @dns4 udp dport 53 accept",
            "ip daddr @dns4 tcp dport 53 accept",
            "ip6 daddr @dns6 udp dport 53 accept",
            "ip6 daddr @dns6 tcp dport 53 accept",
        ] {
            let _ = writeln!(out, "    {rule}");
        }
        let _ = writeln!(out, "    log prefix \"{LOG_PREFIX}\" counter drop");
        let _ = writeln!(out, "  }}");
        let _ = writeln!(out, "}}");
        out
    }

    /// SHA-256 of [`Self::render`], hex: what the log carries so a change is visible.
    #[must_use]
    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(self.render().as_bytes()))
    }
}

/// One named set; `elements` only when there are any (`nft` refuses an empty list).
fn set(out: &mut String, name: &str, ty: &str, elements: &str) {
    if elements.is_empty() {
        let _ = writeln!(out, "  set {name} {{ type {ty}; }}");
    } else {
        let _ = writeln!(
            out,
            "  set {name} {{ type {ty}; elements = {{ {elements} }} }}"
        );
    }
}

/// The host and port of the broker's URL: always admitted.
///
/// # Errors
/// A URL that does not parse or names no host or port.
pub fn broker_endpoint(url: &str) -> anyhow::Result<Endpoint> {
    let u = reqwest::Url::parse(url).with_context(|| format!("mediatore URL {url:?}"))?;
    let host = u
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("mediatore URL {url:?} has no host"))?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = u
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("mediatore URL {url:?} has no port"))?;
    Ok(Endpoint {
        host: host.to_owned(),
        port,
    })
}

/// The `nameserver` lines of a `resolv.conf`; a scope suffix (`%eth0`) is dropped and a
/// line that is not an address is ignored.
#[must_use]
pub fn resolvers(path: &Path) -> BTreeSet<IpAddr> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeSet::new();
    };
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|addr| addr.split('%').next()?.parse().ok())
        .collect()
}

async fn lookup(e: &Endpoint) -> std::io::Result<Vec<(IpAddr, u16)>> {
    Ok(tokio::net::lookup_host((e.host.as_str(), e.port))
        .await?
        .map(|a| (a.ip(), a.port()))
        .collect())
}

/// Load the ruleset in one transaction. Returns its SHA-256.
///
/// # Errors
/// `nft` missing or refusing the script: the jail must not start (decision 5).
pub async fn load(rs: &Ruleset) -> anyhow::Result<String> {
    let script = rs.render();
    let mut child = tokio::process::Command::new(NFT)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {NFT}: is nftables on the image?"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).await?;
        stdin.shutdown().await?;
    }
    let out = child.wait_with_output().await?;
    anyhow::ensure!(
        out.status.success(),
        "{NFT} refused the ruleset ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(rs.sha256())
}

/// Delete the table. Best effort: logged, never fatal; the next claim replaces it anyway.
pub async fn unload() {
    match tokio::process::Command::new(NFT)
        .args(["delete", "table", "inet", TABLE])
        .output()
        .await
    {
        Ok(out) if out.status.success() => tracing::info!(table = TABLE, "sandbox ruleset removed"),
        Ok(out) => tracing::warn!(
            table = TABLE,
            status = %out.status,
            error = %String::from_utf8_lossy(&out.stderr).trim(),
            "could not remove the sandbox ruleset (already gone?)"
        ),
        Err(e) => {
            tracing::warn!(table = TABLE, error = %e, "could not run nft to remove the sandbox ruleset");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> Endpoint {
        s.parse().unwrap()
    }

    fn full() -> Ruleset {
        Ruleset {
            uid: 1234,
            allow: [
                ("198.51.100.7".parse().unwrap(), 443),
                ("192.0.2.10".parse().unwrap(), 8443),
                ("2001:db8::1".parse().unwrap(), 8443),
            ]
            .into_iter()
            .collect(),
            dns: [
                "2001:db8::53".parse().unwrap(),
                "192.0.2.53".parse().unwrap(),
            ]
            .into_iter()
            .collect(),
        }
    }

    #[test]
    fn the_ruleset_admits_the_uid_to_the_broker_the_egress_and_dns_and_drops_the_rest() {
        let expected = "\
# mediatore guest (ADR-0020): uid 1234 reaches the broker, the claim's egress and DNS; nothing else
table inet mediatore_sandbox
delete table inet mediatore_sandbox
table inet mediatore_sandbox {
  set allow4 { type ipv4_addr . inet_service; elements = { 192.0.2.10 . 8443, 198.51.100.7 . 443 } }
  set allow6 { type ipv6_addr . inet_service; elements = { 2001:db8::1 . 8443 } }
  set dns4 { type ipv4_addr; elements = { 192.0.2.53 } }
  set dns6 { type ipv6_addr; elements = { 2001:db8::53 } }
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid 1234 jump sandbox
  }
  chain sandbox {
    ct state established,related accept
    ip daddr . tcp dport @allow4 accept
    ip6 daddr . tcp dport @allow6 accept
    ip daddr @dns4 udp dport 53 accept
    ip daddr @dns4 tcp dport 53 accept
    ip6 daddr @dns6 udp dport 53 accept
    ip6 daddr @dns6 tcp dport 53 accept
    log prefix \"mediatore-sandbox drop: \" counter drop
  }
}
";
        assert_eq!(full().render(), expected);
    }

    #[test]
    fn only_the_uids_packets_enter_the_chain_and_the_chain_ends_in_a_drop() {
        let text = full().render();
        let output: Vec<&str> = text
            .lines()
            .skip_while(|l| !l.contains("chain output"))
            .skip(1)
            .take_while(|l| l.trim() != "}")
            .map(str::trim)
            .collect();
        assert_eq!(
            output,
            [
                "type filter hook output priority filter; policy accept;",
                "meta skuid 1234 jump sandbox"
            ],
            "one rule in the base chain, keyed by the uid; everyone else keeps the policy"
        );
        let last = text
            .lines()
            .map(str::trim)
            .rfind(|l| l.ends_with("accept") || l.ends_with("drop"))
            .unwrap();
        assert!(last.ends_with("counter drop"), "{last}");
    }

    #[test]
    fn empty_sets_render_without_elements_and_the_broker_alone_is_enough() {
        let rs = Ruleset {
            uid: 7,
            allow: [("192.0.2.10".parse().unwrap(), 8443)]
                .into_iter()
                .collect(),
            dns: BTreeSet::new(),
        };
        let text = rs.render();
        assert!(text.contains(
            "  set allow4 { type ipv4_addr . inet_service; elements = { 192.0.2.10 . 8443 } }\n"
        ));
        assert!(text.contains("  set allow6 { type ipv6_addr . inet_service; }\n"));
        assert!(text.contains("  set dns4 { type ipv4_addr; }\n"));
        assert!(text.contains("  set dns6 { type ipv6_addr; }\n"));
    }

    #[test]
    fn the_hash_is_of_the_rendered_text_and_does_not_depend_on_insertion_order() {
        let a = full();
        let mut b = a.clone();
        b.allow = a.allow.iter().rev().copied().collect();
        assert_eq!(a.sha256(), b.sha256());
        assert_eq!(
            a.sha256(),
            hex::encode(Sha256::digest(a.render().as_bytes()))
        );
        assert_eq!(a.sha256().len(), 64);
    }

    #[test]
    fn resolvers_come_from_nameserver_lines_only() {
        let dir = mediatore_testkit::tempdir();
        let path = dir.join("resolv.conf");
        std::fs::write(
            &path,
            "# generated\nsearch home.example\nnameserver 192.0.2.53\n  nameserver fe80::1%eth0\nnameserver bogus\noptions edns0\nnameserver\n",
        )
        .unwrap();
        let got = resolvers(&path);
        let want: BTreeSet<IpAddr> = ["192.0.2.53".parse().unwrap(), "fe80::1".parse().unwrap()]
            .into_iter()
            .collect();
        assert_eq!(got, want);
        assert_eq!(resolvers(&dir.join("absent")), BTreeSet::new());
    }

    #[test]
    fn the_broker_endpoint_is_the_urls_host_and_port() {
        assert_eq!(
            broker_endpoint("https://mediatore.home.example").unwrap(),
            ep("mediatore.home.example:443")
        );
        assert_eq!(
            broker_endpoint("https://mediatore.home.example:8443/").unwrap(),
            ep("mediatore.home.example:8443")
        );
        assert_eq!(
            broker_endpoint("https://[2001:db8::1]:8443").unwrap(),
            ep("[2001:db8::1]:8443")
        );
        assert_eq!(
            broker_endpoint("http://127.0.0.1:8080").unwrap(),
            ep("127.0.0.1:8080")
        );
        assert!(broker_endpoint("file:///tmp/x").is_err());
        assert!(broker_endpoint("not a url").is_err());
    }

    #[tokio::test]
    async fn address_literals_need_no_dns_and_a_name_that_does_not_resolve_is_omitted() {
        let dir = mediatore_testkit::tempdir();
        let resolv = dir.join("resolv.conf");
        std::fs::write(&resolv, "nameserver 192.0.2.53\n").unwrap();
        let rs = Ruleset::resolve(
            4242,
            "https://192.0.2.10:8443",
            &[ep("198.51.100.7:443"), ep("no-such-host.invalid:443")],
            &resolv,
        )
        .await
        .unwrap();
        let want: BTreeSet<(IpAddr, u16)> = [
            ("192.0.2.10".parse().unwrap(), 8443),
            ("198.51.100.7".parse().unwrap(), 443),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            rs.allow, want,
            "the broker always, the literal, not the unresolvable name"
        );
        assert_eq!(rs.uid, 4242);
        assert_eq!(rs.dns.len(), 1);
    }

    #[tokio::test]
    async fn a_broker_that_does_not_resolve_is_an_error_not_a_ruleset() {
        let err = Ruleset::resolve(
            1,
            "https://no-such-host.invalid",
            &[],
            Path::new("/nonexistent"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("no-such-host.invalid"), "{err}");
    }

    /// Hands the rendered text to a real `nft -c`, which checks syntax through netlink and
    /// therefore wants `CAP_NET_ADMIN` even to check. Set `MEDIATORE_NFT` to the command,
    /// `sudo /usr/sbin/nft` on the build host; the test fails, never skips, without it.
    #[tokio::test]
    #[ignore = "needs an nft with CAP_NET_ADMIN: MEDIATORE_NFT='sudo /usr/sbin/nft'"]
    async fn nft_accepts_the_rendered_ruleset() {
        let cmd = std::env::var("MEDIATORE_NFT").unwrap_or_else(|_| {
            panic!("set MEDIATORE_NFT to an nft command that may open netlink, e.g. 'sudo /usr/sbin/nft'")
        });
        let mut parts = cmd.split_whitespace();
        let program = parts.next().expect("a command");
        let args: Vec<&str> = parts.collect();
        let empty = Ruleset {
            uid: 7,
            allow: [("192.0.2.10".parse().unwrap(), 8443)]
                .into_iter()
                .collect(),
            dns: BTreeSet::new(),
        };
        for rs in [full(), empty] {
            let mut child = tokio::process::Command::new(program)
                .args(&args)
                .args(["-c", "-f", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn nft");
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(rs.render().as_bytes()).await.unwrap();
            stdin.shutdown().await.unwrap();
            drop(stdin);
            let out = child.wait_with_output().await.unwrap();
            // nft names the offending line; the text itself is pinned by the unit tests above.
            assert!(
                out.status.success(),
                "nft -c refused the ruleset: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }
}
