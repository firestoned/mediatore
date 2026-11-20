// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The third layer inside the jail (ADR-0051): a seccomp-bpf denylist applied by
//! `mediatore jail-exec` after Landlock and before the workload's exec. It names what
//! nftables (addresses and ports) and Landlock (paths and TCP ports) cannot: the *kind* of
//! socket and `io_uring`. The policy is plain data here, pinned by unit tests on every
//! platform and evaluated by [`Filter::verdict`] so the tests need no kernel; on Linux
//! it is compiled with `seccompiler` and installed.

/// `EPERM`, the Linux value on every architecture the guest runs on.
pub const EPERM: i32 = 1;
/// `EAFNOSUPPORT`, what a refused socket family reports.
pub const EAFNOSUPPORT: i32 = 97;

/// `AF_UNIX`, `AF_INET`, `AF_INET6`: the only families the workload may open (an allowlist
/// of three, so every family added later is closed).
pub const ALLOWED_FAMILIES: [u64; 3] = [1, 2, 10];
/// The inet families whose sockets must also be streams.
pub const INET_FAMILIES: [u64; 2] = [2, 10];
/// The protocols an inet socket may name: `0` (the family's default for a stream, TCP) and
/// `IPPROTO_TCP`. Anything else on a stream type is another transport behind the same type
/// (MPTCP is protocol 262), which ADR-0051's amendment of 2026-11-19 closes here too.
pub const INET_STREAM_PROTOCOLS: [u64; 2] = [0, 6];
/// `SOCK_STREAM`.
pub const SOCK_STREAM: u64 = 1;
/// `SOCK_TYPE_MASK`: the kernel's own mask, which drops `SOCK_NONBLOCK` and `SOCK_CLOEXEC`.
pub const SOCK_TYPE_MASK: u64 = 0xf;

/// Syscalls refused outright with `EPERM`. Each is already refused by a dropped capability
/// or by Landlock; listing it makes the refusal independent of both (ADR-0051 decision 2).
/// `ptrace` is not here: a filter cannot tell the jail's own processes from others, and the
/// `subset=pid` `/proc` (ADR-0036) with Yama's scope carries it.
pub const DENIED_SYSCALLS: &[&str] = &[
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "bpf",
    "userfaultfd",
    "perf_event_open",
    "kexec_load",
    "init_module",
    "finit_module",
    "delete_module",
    "mount",
    "umount2",
    "pivot_root",
    "setns",
    "unshare",
    "open_by_handle_at",
];

/// How a syscall argument is compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// `(arg & mask) == value`.
    MaskedEq(u64),
}

/// One argument condition; all of a rule's conditions must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cond {
    /// Argument index.
    pub arg: u8,
    /// The comparison.
    pub op: Op,
    /// The value compared against (the low 32 bits: these are `int` arguments).
    pub value: u64,
}

/// A syscall and the conditions under which it is refused; no condition means always.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The syscall's name.
    pub syscall: &'static str,
    /// All must hold; empty refuses every call.
    pub conds: Vec<Cond>,
}

/// A set of rules that all fail with one errno; everything else is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// What a matched call returns.
    pub errno: i32,
    /// Any one may match.
    pub rules: Vec<Rule>,
}

impl Filter {
    /// The errno this filter returns for the call, or `None` when it allows it.
    #[must_use]
    pub fn verdict(&self, syscall: &str, args: [u64; 6]) -> Option<i32> {
        let hit = self.rules.iter().any(|r| {
            r.syscall == syscall
                && r.conds.iter().all(|c| {
                    let a = args[usize::from(c.arg)] & 0xffff_ffff;
                    match c.op {
                        Op::Eq => a == c.value,
                        Op::Ne => a != c.value,
                        Op::MaskedEq(m) => a & m == c.value,
                    }
                })
        });
        hit.then_some(self.errno)
    }
}

/// The two filters of the policy, installed in this order. Their matches are disjoint (a
/// socket call is refused by the family filter only when its family is not allowed, by the
/// second only when the family is inet), so the kernel's precedence between them never
/// decides an errno. The protocol rule sits in the second filter beside the type rules: it
/// too matches inet families alone, and a call it shares with a type rule gets `EPERM` from
/// either.
#[must_use]
pub fn filters() -> [Filter; 2] {
    let cond = |arg, op, value| Cond { arg, op, value };
    // socket() and socketpair(): a domain outside the allowlist, every `Ne` must hold.
    let outside: Vec<Cond> = ALLOWED_FAMILIES
        .iter()
        .map(|f| cond(0, Op::Ne, *f))
        .collect();
    let mut family = Vec::new();
    for syscall in ["socket", "socketpair"] {
        family.push(Rule {
            syscall,
            conds: outside.clone(),
        });
    }
    // socket() on an inet family whose type (after the kernel's own mask) is not a stream:
    // one rule per other type value, as a masked comparison has no "not equal".
    let mut rest = Vec::new();
    for domain in INET_FAMILIES {
        for ty in (0..=SOCK_TYPE_MASK).filter(|t| *t != SOCK_STREAM) {
            rest.push(Rule {
                syscall: "socket",
                conds: vec![
                    cond(0, Op::Eq, domain),
                    cond(1, Op::MaskedEq(SOCK_TYPE_MASK), ty),
                ],
            });
        }
    }
    // socket() on an inet family whose protocol is none of the allowed ones, every `Ne` must
    // hold: one rule per family, whatever the type (a type that is not a stream is refused
    // above with the same errno).
    for domain in INET_FAMILIES {
        let mut conds = vec![cond(0, Op::Eq, domain)];
        conds.extend(INET_STREAM_PROTOCOLS.iter().map(|p| cond(2, Op::Ne, *p)));
        rest.push(Rule {
            syscall: "socket",
            conds,
        });
    }
    rest.extend(DENIED_SYSCALLS.iter().map(|syscall| Rule {
        syscall,
        conds: vec![],
    }));
    [
        Filter {
            errno: EAFNOSUPPORT,
            rules: family,
        },
        Filter {
            errno: EPERM,
            rules: rest,
        },
    ]
}

/// What the combined policy answers for a call: the first filter's errno, else the second's.
#[must_use]
pub fn verdict(syscall: &str, args: [u64; 6]) -> Option<i32> {
    filters().iter().find_map(|f| f.verdict(syscall, args))
}

/// The syscall number of a name in the policy, for the architecture this is built for.
#[cfg(target_os = "linux")]
fn syscall_nr(name: &str) -> Option<i64> {
    Some(match name {
        "socket" => libc::SYS_socket,
        "socketpair" => libc::SYS_socketpair,
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,
        "bpf" => libc::SYS_bpf,
        "userfaultfd" => libc::SYS_userfaultfd,
        "perf_event_open" => libc::SYS_perf_event_open,
        "kexec_load" => libc::SYS_kexec_load,
        "init_module" => libc::SYS_init_module,
        "finit_module" => libc::SYS_finit_module,
        "delete_module" => libc::SYS_delete_module,
        "mount" => libc::SYS_mount,
        "umount2" => libc::SYS_umount2,
        "pivot_root" => libc::SYS_pivot_root,
        "setns" => libc::SYS_setns,
        "unshare" => libc::SYS_unshare,
        "open_by_handle_at" => libc::SYS_open_by_handle_at,
        _ => return None,
    })
}

/// Compile one filter of the policy for this architecture.
#[cfg(target_os = "linux")]
fn compile(filter: &Filter) -> anyhow::Result<seccompiler::BpfProgram> {
    use anyhow::Context as _;
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    };
    use std::collections::BTreeMap;

    let mut by_nr: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for rule in &filter.rules {
        let nr = syscall_nr(rule.syscall)
            .with_context(|| format!("no syscall number for {}", rule.syscall))?;
        let mut conds = Vec::new();
        for c in &rule.conds {
            let op = match c.op {
                Op::Eq => SeccompCmpOp::Eq,
                Op::Ne => SeccompCmpOp::Ne,
                Op::MaskedEq(m) => SeccompCmpOp::MaskedEq(m),
            };
            conds.push(SeccompCondition::new(
                c.arg,
                SeccompCmpArgLen::Dword,
                op,
                c.value,
            )?);
        }
        // seccompiler refuses a rule with no conditions; an empty rule list for the syscall
        // is how it spells "every call".
        let rules = by_nr.entry(nr).or_default();
        if !conds.is_empty() {
            rules.push(SeccompRule::new(conds)?);
        }
    }
    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| anyhow::anyhow!("seccomp does not support {}: {e}", std::env::consts::ARCH))?;
    let errno = u32::try_from(filter.errno)?;
    let program: seccompiler::BpfProgram = SeccompFilter::new(
        by_nr,
        SeccompAction::Allow,
        SeccompAction::Errno(errno),
        arch,
    )?
    .try_into()?;
    Ok(program)
}

/// Install the policy on this process and everything it will exec or fork (irreversible),
/// returning how many filters are now installed (the caller logs it, so an operator can see
/// from the guest's journal that the layer is on). `apply_filter` sets `no_new_privs` itself.
/// A filter that cannot be compiled or loaded is an error the caller turns into a refusal
/// (ADR-0051 decision 4).
///
/// # Errors
///
/// The architecture is unsupported, or the kernel refused the filter.
#[cfg(target_os = "linux")]
pub fn apply() -> anyhow::Result<usize> {
    use anyhow::Context as _;

    let mut installed = 0;
    for filter in &filters() {
        let program = compile(filter)?;
        seccompiler::apply_filter(&program)
            .with_context(|| format!("loading the seccomp filter for errno {}", filter.errno))?;
        installed += 1;
    }
    Ok(installed)
}

/// Not Linux: no seccomp, no substitute (ADR-0051 decision 4).
///
/// # Errors
///
/// Always.
#[cfg(not(target_os = "linux"))]
pub fn apply() -> anyhow::Result<usize> {
    anyhow::bail!("seccomp needs Linux, not {}", std::env::consts::OS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AF_UNIX: u64 = 1;
    const AF_INET: u64 = 2;
    const AF_INET6: u64 = 10;
    const AF_NETLINK: u64 = 16;
    const AF_PACKET: u64 = 17;
    const AF_VSOCK: u64 = 40;
    const SOCK_DGRAM: u64 = 2;
    const SOCK_RAW: u64 = 3;
    const SOCK_NONBLOCK: u64 = 0o4000;
    const SOCK_CLOEXEC: u64 = 0o2_000_000;

    const IPPROTO_TCP: u64 = 6;
    const IPPROTO_UDP: u64 = 17;
    const IPPROTO_MPTCP: u64 = 262;

    fn socket(domain: u64, ty: u64) -> Option<i32> {
        verdict("socket", [domain, ty, 0, 0, 0, 0])
    }

    fn socket_with(domain: u64, ty: u64, protocol: u64) -> Option<i32> {
        verdict("socket", [domain, ty, protocol, 0, 0, 0])
    }

    #[test]
    fn unix_and_inet_streams_are_allowed_with_the_flags_a_runtime_uses() {
        for flags in [0, SOCK_NONBLOCK, SOCK_CLOEXEC, SOCK_NONBLOCK | SOCK_CLOEXEC] {
            for domain in [AF_UNIX, AF_INET, AF_INET6] {
                assert_eq!(
                    socket(domain, SOCK_STREAM | flags),
                    None,
                    "{domain} {flags}"
                );
            }
        }
        assert_eq!(
            socket(AF_UNIX, SOCK_DGRAM),
            None,
            "local datagrams stay (logging, IPC)"
        );
        assert_eq!(
            verdict("socketpair", [AF_UNIX, SOCK_STREAM, 0, 0, 0, 0]),
            None
        );
        assert_eq!(
            verdict("read", [0; 6]),
            None,
            "everything unlisted is allowed"
        );
    }

    #[test]
    fn every_other_family_is_refused_with_eafnosupport() {
        for domain in [AF_VSOCK, AF_NETLINK, AF_PACKET, 0, 3, 38, 44, 45, 255] {
            assert_eq!(
                socket(domain, SOCK_STREAM),
                Some(EAFNOSUPPORT),
                "family {domain}"
            );
            assert_eq!(
                verdict("socketpair", [domain, SOCK_STREAM, 0, 0, 0, 0]),
                Some(EAFNOSUPPORT)
            );
        }
    }

    #[test]
    fn an_inet_socket_that_is_not_a_stream_is_refused_with_eperm_whatever_the_flags() {
        for domain in [AF_INET, AF_INET6] {
            for flags in [0, SOCK_NONBLOCK | SOCK_CLOEXEC] {
                for ty in 0..=15u64 {
                    let want = (ty != SOCK_STREAM).then_some(EPERM);
                    assert_eq!(
                        socket(domain, ty | flags),
                        want,
                        "{domain} type {ty} {flags}"
                    );
                }
            }
            assert_eq!(socket(domain, SOCK_DGRAM), Some(EPERM));
            assert_eq!(socket(domain, SOCK_RAW), Some(EPERM));
        }
    }

    #[test]
    fn an_inet_stream_socket_whose_protocol_is_not_tcp_is_refused_with_eperm() {
        assert_eq!(INET_STREAM_PROTOCOLS, [0, IPPROTO_TCP]);
        for flags in [0, SOCK_NONBLOCK, SOCK_CLOEXEC, SOCK_NONBLOCK | SOCK_CLOEXEC] {
            let ty = SOCK_STREAM | flags;
            for domain in [AF_INET, AF_INET6] {
                for protocol in INET_STREAM_PROTOCOLS {
                    assert_eq!(
                        socket_with(domain, ty, protocol),
                        None,
                        "{domain} {flags} protocol {protocol}"
                    );
                }
                for protocol in [IPPROTO_MPTCP, 1, IPPROTO_UDP, 132, 255, 0xffff_ffff] {
                    assert_eq!(
                        socket_with(domain, ty, protocol),
                        Some(EPERM),
                        "{domain} {flags} protocol {protocol}"
                    );
                }
                // The protocol is an `int`: the kernel reads the low half of the register,
                // and so does the filter.
                assert_eq!(socket_with(domain, ty, IPPROTO_TCP | (1 << 32)), None);
                assert_eq!(
                    socket_with(domain, ty, IPPROTO_MPTCP | (1 << 32)),
                    Some(EPERM)
                );
            }
            // A local socket's protocol is not this rule's to judge.
            for protocol in [0, 1, IPPROTO_TCP, IPPROTO_MPTCP] {
                assert_eq!(
                    socket_with(AF_UNIX, ty, protocol),
                    None,
                    "unix {flags} protocol {protocol}"
                );
                assert_eq!(socket_with(AF_UNIX, SOCK_DGRAM | flags, protocol), None);
            }
        }
        // The errnos of the other rules are unchanged by a protocol.
        assert_eq!(
            socket_with(AF_VSOCK, SOCK_STREAM, IPPROTO_MPTCP),
            Some(EAFNOSUPPORT)
        );
        assert_eq!(socket_with(AF_INET, SOCK_DGRAM, IPPROTO_UDP), Some(EPERM));
        assert_eq!(
            verdict("socketpair", [AF_UNIX, SOCK_STREAM, IPPROTO_MPTCP, 0, 0, 0]),
            None,
            "the rule is on socket() alone"
        );
    }

    #[test]
    fn io_uring_and_the_listed_syscalls_are_refused_with_eperm() {
        for name in DENIED_SYSCALLS {
            assert_eq!(verdict(name, [0; 6]), Some(EPERM), "{name}");
        }
        for name in ["io_uring_setup", "io_uring_enter", "io_uring_register"] {
            assert!(DENIED_SYSCALLS.contains(&name));
        }
        assert_eq!(
            verdict("ptrace", [0; 6]),
            None,
            "left to the pid namespace and Yama"
        );
    }

    #[test]
    fn the_two_filters_never_refuse_the_same_call() {
        let [a, b] = filters();
        for domain in 0..=64u64 {
            for ty in 0..=15u64 {
                for protocol in [0, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_MPTCP] {
                    let args = [domain, ty, protocol, 0, 0, 0];
                    for call in ["socket", "socketpair"] {
                        assert!(
                            a.verdict(call, args).is_none() || b.verdict(call, args).is_none(),
                            "{call} {domain} {ty} {protocol}"
                        );
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_rule_resolves_to_a_syscall_number_and_compiles_for_this_architecture() {
        for filter in &filters() {
            for rule in &filter.rules {
                assert!(syscall_nr(rule.syscall).is_some(), "{}", rule.syscall);
            }
            let program = compile(filter).unwrap();
            assert_ne!(program.len(), 0, "a compiled filter has instructions");
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn without_linux_applying_the_policy_is_an_error() {
        assert!(apply().is_err());
    }
}
