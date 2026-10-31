#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# What the sandbox VM image must carry, and must not (ADR-0023), checked inside the built
# image with a container runtime. Runs in CI on every pull request and on the build host
# with `make guest-image-check`. Boots nothing: the live proof is a libvirt member.
set -euo pipefail

IMAGE=${1:?usage: check.sh <image>}
CLI=${CONTAINER_CLI:-docker}
PLUGIN_SHA=$(sed -n 's/.*plugin_checksum = "\([0-9a-f]*\)".*/\1/p' "$(dirname "$0")/spire/agent.conf")
[ -n "$PLUGIN_SHA" ] || { echo "image/spire/agent.conf carries no plugin_checksum"; exit 1; }

run() { "$CLI" run --rm --entrypoint sh "$IMAGE" -c "$1"; }

fail=0
check() { # <what> <shell>
  if run "$2" >/dev/null 2>&1; then echo "✓ $1"; else echo "✗ $1"; fail=1; fi
}

echo "checking $IMAGE"
check "the one mediatore binary at the pinned path, static, runs" \
  'test -x /usr/bin/mediatore && /usr/bin/mediatore --help >/dev/null && ! ldd /usr/bin/mediatore 2>/dev/null | grep -q "=>"'
check "no binary under /usr/local (the persistent partition mounts over it)" \
  '! find /usr/local/bin /usr/local/sbin -type f 2>/dev/null | grep -q .'
check "the SPIRE agent in the rootfs" \
  'test -x /usr/bin/spire-agent && /usr/bin/spire-agent --version 2>&1 | grep -q "[0-9]\.[0-9]"'
check "the TPM attestor plugin at the path agent.conf names, with the checksum it pins" \
  "echo '$PLUGIN_SHA  /usr/lib/spire/tpm_attestor_agent' | sha256sum -c - >/dev/null"
check "nftables, for the jail's ruleset (ADR-0020)" 'nft --version >/dev/null'
check "nsjail, the jail itself, linked against what the image has" \
  'test -x /usr/bin/nsjail && ! ldd /usr/bin/nsjail | grep -q "not found" && /usr/bin/nsjail --help 2>&1 | grep -q -- "--chroot"'
check "mount and umount, for the sandbox tmpfs (ADR-0021)" 'command -v mount && command -v umount'
check "tpm2-tools, for the EK certificate export (banlieue examples/21)" 'command -v tpm2_nvread'
check "qemu-guest-agent, the libvirt channel for GuestReady (ADR-0019)" 'command -v qemu-ga'
check "the spire user, in the TPM device group" 'id -nG spire | tr " " "\n" | grep -qx tss'
check "both units installed" \
  'test -f /etc/systemd/system/spire-agent.service && test -f /etc/systemd/system/mediatore-guest.service'
check "both units enabled" \
  'test -L /etc/systemd/system/multi-user.target.wants/spire-agent.service && test -L /etc/systemd/system/multi-user.target.wants/mediatore-guest.service'
check "the units point at the paths the image has" \
  'grep -q "^ExecStart=/usr/bin/spire-agent run -config /etc/spire/agent.conf" /etc/systemd/system/spire-agent.service && grep -q "^ExecStart=/usr/bin/mediatore guest" /etc/systemd/system/mediatore-guest.service'
check "no sshd, and ssh masked (ADR-0010: nothing inbound)" \
  '! command -v sshd && for u in ssh.service ssh.socket; do test "$(readlink /etc/systemd/system/$u)" = /dev/null || exit 1; done'
check "no other listener the base shipped (snmpd, lldpd, rpcbind)" \
  '! command -v snmpd && ! command -v lldpd && ! command -v rpcbind'
check "Yama's ptrace scope raised in the image's sysctl (ADR-0025, roadmap 06)" \
  'grep -qx "kernel.yama.ptrace_scope = 1" /etc/sysctl.d/99-mediatore.conf'
check "no private key material (banlieue ADR-0108 decision 2)" \
  '! grep -rl "PRIVATE KEY" /etc /usr/share/mediatore /var/lib 2>/dev/null | grep -q .'

[ "$fail" -eq 0 ] && echo "image ok" || { echo "image check failed"; exit 1; }
