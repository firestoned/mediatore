#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# What the egress gateway VM image must carry, and must not (ADR-0028 decisions 8 and 10,
# ADR-0027 decisions 1 and 5), checked inside the built image with a container runtime.
# Runs in CI on every pull request and on the build host with `make gateway-image-check`.
# Boots nothing: the live proof is a gateway VM.
set -euo pipefail

IMAGE=${1:?usage: check.sh <image>}
CLI=${CONTAINER_CLI:-docker}
PLUGIN_SHA=$(sed -n 's/.*plugin_checksum = "\([0-9a-f]*\)".*/\1/p' "$(dirname "$0")/../spire/agent.conf")
[ -n "$PLUGIN_SHA" ] || { echo "image/spire/agent.conf carries no plugin_checksum"; exit 1; }

run() { "$CLI" run --rm --entrypoint sh "$IMAGE" -c "$1"; }

fail=0
check() { # <what> <shell>
  if run "$2" >/dev/null 2>&1; then echo "✓ $1"; else echo "✗ $1"; fail=1; fi
}

echo "checking $IMAGE"
check "the one mediatore binary at the pinned path, static, with the gateway role" \
  'test -x /usr/bin/mediatore && /usr/bin/mediatore gateway --help >/dev/null && ! ldd /usr/bin/mediatore 2>/dev/null | grep -q "=>"'
check "Envoy at the pinned version, runs, linked against what the image has" \
  'test -x /usr/bin/envoy && /usr/bin/envoy --version | grep -q 1.40.2 && ! ldd /usr/bin/envoy | grep -q "not found"'
check "no binary under /usr/local (the persistent partition mounts over it)" \
  '! find /usr/local/bin /usr/local/sbin -type f 2>/dev/null | grep -q .'
check "the SPIRE agent in the rootfs" \
  'test -x /usr/bin/spire-agent && /usr/bin/spire-agent --version 2>&1 | grep -q "[0-9]\.[0-9]"'
check "the TPM attestor plugin at the path agent.conf names, with the checksum it pins" \
  "echo '$PLUGIN_SHA  /usr/lib/spire/tpm_attestor_agent' | sha256sum -c - >/dev/null"
check "nftables, for the host table (ADR-0027 decision 5)" 'nft --version >/dev/null'
check "the render script and the six templates" \
  'test -x /usr/libexec/mediatore-gateway/render && for t in envoy/gateway.yaml.in envoy/relay.yaml.in envoy/inject.yaml.in nftables.conf.in network.in; do test -f /usr/share/mediatore-gateway/$t || exit 1; done'
check "the examples render every template, so the documented env is complete" \
  'cd /usr/share/mediatore-gateway && for t in envoy/gateway.yaml.in envoy/relay.yaml.in envoy/inject.yaml.in nftables.conf.in network.in; do /usr/libexec/mediatore-gateway/render $t - env.example vm.env.example >/dev/null || exit 1; done'
check "the rendered data plane, relay and inject Envoy are bootstraps Envoy accepts" \
  'cd /usr/share/mediatore-gateway && mkdir -p /tmp/r && for b in gateway relay inject; do /usr/libexec/mediatore-gateway/render envoy/$b.yaml.in /tmp/r/$b.yaml env.example vm.env.example && /usr/bin/envoy --mode validate -c /tmp/r/$b.yaml >/dev/null 2>&1 || exit 1; done'
check "no admin block in any bootstrap (ADR-0028 decision 8)" \
  '! grep -q "^admin:" /usr/share/mediatore-gateway/envoy/gateway.yaml.in /usr/share/mediatore-gateway/envoy/relay.yaml.in /usr/share/mediatore-gateway/envoy/inject.yaml.in'
check "the relay has no SDS and no TLS context (ADR-0027 decision 1: no credential)" \
  '! grep -qiE "sds_config|tls_context|transport_socket" /usr/share/mediatore-gateway/envoy/relay.yaml.in'
check "the relay has four fixed legs: SPIRE, broker, the SPIRE bundle endpoint (ADR-0037) and the registry (ADR-0038), rendered with their ports and the host table admitting all four" \
  'cd /usr/share/mediatore-gateway && mkdir -p /tmp/r && /usr/libexec/mediatore-gateway/render envoy/relay.yaml.in /tmp/r/relay3.yaml env.example vm.env.example && test "$(grep -c "stat_prefix: relay_" /tmp/r/relay3.yaml)" = 4 && grep -q "upstream=bundle" /tmp/r/relay3.yaml && grep -q "name: spire_bundle" /tmp/r/relay3.yaml && grep -q "upstream=registry" /tmp/r/relay3.yaml && grep -q "name: registry" /tmp/r/relay3.yaml && /usr/libexec/mediatore-gateway/render nftables.conf.in - env.example vm.env.example | grep -q "elements = { 3129, 3130, 3131, 3132 }"'
check "the four service users, none in the TPM group, the agent in it" \
  'for u in envoy envoy-relay envoy-inject mediatore-gateway; do id "$u" >/dev/null && ! id -nG "$u" | tr " " "\n" | grep -qx tss || exit 1; done && id -nG spire | tr " " "\n" | grep -qx tss'
check "the six units installed and enabled, and the inject Envoy's installed and NOT enabled (it is off until a deployment turns it on, ADR-0040)" \
  'for u in spire-agent mediatore-gateway-network mediatore-gateway-nft envoy-gateway envoy-relay mediatore-gateway; do test -f /etc/systemd/system/$u.service && test -L /etc/systemd/system/multi-user.target.wants/$u.service || exit 1; done && test -f /etc/systemd/system/envoy-inject.service && ! test -e /etc/systemd/system/multi-user.target.wants/envoy-inject.service'
check "the units point at the paths the image has" \
  'grep -q "^ExecStart=/usr/bin/envoy -c /run/mediatore-gateway/gateway.yaml" /etc/systemd/system/envoy-gateway.service && grep -q "^ExecStart=/usr/bin/envoy -c /run/mediatore-gateway/relay.yaml" /etc/systemd/system/envoy-relay.service && grep -q "^ExecStart=/usr/bin/mediatore gateway --listen 127.0.0.1:9001" /etc/systemd/system/mediatore-gateway.service && grep -q "^ExecStart=/usr/sbin/nft -f /run/mediatore-gateway/nftables.conf" /etc/systemd/system/mediatore-gateway-nft.service'
check "all three Envoys unprivileged, no capability, read-only root, no new privileges (ADR-0028 decision 8, ADR-0040 decision 3)" \
  'for u in envoy-gateway envoy-relay envoy-inject; do f=/etc/systemd/system/$u.service; grep -q "^NoNewPrivileges=yes" $f && grep -q "^CapabilityBoundingSet=$" $f && grep -q "^ProtectSystem=strict" $f && grep -q "^PrivateTmp=yes" $f || exit 1; done && grep -q "^User=envoy$" /etc/systemd/system/envoy-gateway.service && grep -q "^User=envoy-relay$" /etc/systemd/system/envoy-relay.service && grep -q "^User=envoy-inject$" /etc/systemd/system/envoy-inject.service'
check "the relay is kept out of /run/spire by its unit (ADR-0027 decision 1)" \
  'grep -q "^InaccessiblePaths=/run/spire" /etc/systemd/system/envoy-relay.service'
check "the inject Envoy (ADR-0040 decision 3) is its own user, reads the agent's socket (unlike the relay), logs at info and is not kept out of /run/spire" \
  'f=/etc/systemd/system/envoy-inject.service; grep -q "^Group=envoy-inject$" $f && grep -q "^ExecStart=/usr/bin/envoy -c /run/mediatore-gateway/inject.yaml --log-level info" $f && grep -q "^Requires=.*spire-agent.service" $f && grep -q "^ReadOnlyPaths=.*/run/spire/sockets" $f && ! grep -q "^InaccessiblePaths" $f'
check "the inject bootstrap: claim mutual TLS, a bare-host route, TLS origination with SNI and a DNS SAN, ext_authz to the inject socket in inject mode, and no header mutation, CONNECT, strip_any_host_port or admin block (ADR-0040 decisions 3 and 4)" \
  'cd /usr/share/mediatore-gateway && r=$(/usr/libexec/mediatore-gateway/render envoy/inject.yaml.in - env.example vm.env.example | grep -v "^[[:space:]]*#") && printf "%s\n" "$r" | grep -q "require_client_certificate: true" && printf "%s\n" "$r" | grep -q "tls_minimum_protocol_version: TLSv1_3" && printf "%s\n" "$r" | grep -q "mode: inject" && printf "%s\n" "$r" | grep -q "failure_mode_allow: false" && printf "%s\n" "$r" | grep -q "suppress_envoy_headers: true" && printf "%s\n" "$r" | grep -q "pipe: { path: /run/mediatore-gateway/inject/inject.sock }" && ! printf "%s\n" "$r" | grep -Eq "request_headers_to_(add|remove)|response_headers_to_add|strip_any_host_port|connect_matcher|upgrade_configs|dynamic_forward_proxy|^admin:" && ! printf "%s\n" "$r" | grep -Eqi "authorization|x-api-key"'
check "off by default: the example env keeps the authorizer on loopback and the host table at the four relay ports; env.inject.example in front of it moves the data plane to the CHECK socket and admits the inject port" \
  'cd /usr/share/mediatore-gateway && /usr/libexec/mediatore-gateway/render envoy/gateway.yaml.in - env.example vm.env.example | grep -q "port_value: 9001" && /usr/libexec/mediatore-gateway/render nftables.conf.in - env.example vm.env.example | grep -q "elements = { 3129, 3130, 3131, 3132 } }" && /usr/libexec/mediatore-gateway/render envoy/gateway.yaml.in - env.inject.example env.example vm.env.example | grep -q "pipe: { path: /run/mediatore-gateway/check/check.sock }" && /usr/libexec/mediatore-gateway/render nftables.conf.in - env.inject.example env.example vm.env.example | grep -q "elements = { 3129, 3130, 3131, 3132, 3133 } }"'
check "the system roots the inject Envoy verifies its upstream against exist in the image" \
  'test -s /etc/ssl/certs/ca-certificates.crt'
check "the agent's unit is the gateway's: it requires the gateway's host table, not the pool's" \
  'grep -q "^Requires=mediatore-gateway-nft.service" /etc/systemd/system/spire-agent.service && ! grep -qE "^(Requires|After|Wants)=.*mediatore-host-nft" /etc/systemd/system/spire-agent.service'
check "the sandbox interface file sorts before the base's DHCP catch-all (10- before 20-dhcp)" \
  'grep -q "^ExecStart=.* /run/systemd/network/10-sandbox.network " /etc/systemd/system/mediatore-gateway-network.service && ! grep -q "^ExecStart=.*/[2-9][0-9]-sandbox.network" /etc/systemd/system/mediatore-gateway-network.service'
check "the Envoys require the table and the interface first (fail closed)" \
  'for u in envoy-gateway envoy-relay envoy-inject; do grep -q "^Requires=.*mediatore-gateway-nft.service" /etc/systemd/system/$u.service && grep -q "^Requires=.*mediatore-gateway-network.service" /etc/systemd/system/$u.service || exit 1; done'
check "forwarding off in the image's sysctl (ADR-0028 decision 8)" \
  'grep -qx "net.ipv4.ip_forward = 0" /etc/sysctl.d/99-mediatore-gateway.conf && grep -qx "net.ipv6.conf.all.forwarding = 0" /etc/sysctl.d/99-mediatore-gateway.conf'
check "Yama's ptrace scope and the kernel hardening in the image's sysctl: no MPTCP, no io_uring, kernel addresses and the kernel log restricted, no unprivileged bpf, the BPF JIT hardened" \
  'grep -qx "kernel.yama.ptrace_scope = 1" /etc/sysctl.d/99-mediatore-gateway.conf && for k in "net.mptcp.enabled = 0" "kernel.io_uring_disabled = 2" "kernel.kptr_restrict = 2" "kernel.dmesg_restrict = 1" "kernel.unprivileged_bpf_disabled = 1" "net.core.bpf_jit_harden = 2"; do grep -qx "$k" /etc/sysctl.d/99-mediatore-gateway.conf || exit 1; done'
check "the host table drops input and forward by default and admits the sandbox ports alone" \
  'grep -q "type filter hook input priority filter; policy drop;" /usr/share/mediatore-gateway/nftables.conf.in && grep -q "type filter hook forward priority filter; policy drop;" /usr/share/mediatore-gateway/nftables.conf.in && grep -q "iifname \"@SANDBOX_IF@\" tcp dport @DATA_PORT@" /usr/share/mediatore-gateway/nftables.conf.in && grep -q "ct count over @RELAY_CAP@" /usr/share/mediatore-gateway/nftables.conf.in && grep -q "flags dynamic" /usr/share/mediatore-gateway/nftables.conf.in'
check "no sshd, ssh and the distribution's nftables unit masked" \
  '! command -v sshd && for u in ssh.service ssh.socket nftables.service; do test "$(readlink /etc/systemd/system/$u)" = /dev/null || exit 1; done'
check "no other listener the base shipped (snmpd, lldpd, rpcbind)" \
  '! command -v snmpd && ! command -v lldpd && ! command -v rpcbind'
check "no private key material (banlieue ADR-0108 decision 2)" \
  '! grep -rl "PRIVATE KEY" /etc /usr/share/mediatore /usr/share/mediatore-gateway /var/lib 2>/dev/null | grep -q .'

[ "$fail" -eq 0 ] && echo "image ok" || { echo "image check failed"; exit 1; }
