#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# The gateway's host table and what ADR-0070 decision 4 added to it, as text: named counters
# on the rules that drop, a set of who probed which port, and one more drop. Proven here by
# taking the additions away again: what is left must be, byte for byte, the table as it was
# before them (rendered from the example env, comments aside), so no rule's verdict changed,
# none moved, and nothing new is accepted. Also pinned: the units of the reader that reads
# those counters. Runs on any host with sh and sed (`make gateway-render-check`); that the
# kernel loads the table and counts as the text says is the build host's to show
# (docs/guides/testing.md), not this script's.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
got=$("$here/render" "$here/nftables.conf.in" - "$here/env.example" "$here/vm.env.example" | grep -v '^[[:space:]]*#')

# The table before ADR-0070, rendered from the same two example files.
before=$(cat <<'NFT'
flush ruleset
table inet mediatore_gateway {
  set egress_refused { type ipv4_addr; flags interval; auto-merge; elements = { 169.254.0.0/16, 192.0.2.20, 192.0.2.20, 192.0.2.21 } }
  set check_tcp { type inet_service;  }
  set resolvers { type ipv4_addr;  }
  set relay_ports { type inet_service; elements = { 3129, 3130, 3131 } }
  set relay_sources { type ipv4_addr; flags dynamic; size 65535; }
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    ct state invalid drop
    iifname "enp2s0" tcp dport @relay_ports ct state new add @relay_sources { ip saddr ct count over 16 } log prefix "mediatore-gateway cap: " counter drop
    iifname "enp2s0" tcp dport @relay_ports ct state new accept
    iifname "enp2s0" tcp dport 8443 ct state new accept
    log prefix "mediatore-gateway drop: " counter drop
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    log prefix "mediatore-gateway forward: " counter drop
  }
  chain output {
    type filter hook output priority filter; policy accept;
    ct state established,related accept
    oifname "enp2s0" ct state new log prefix "mediatore-gateway out sandbox: " counter drop
    ip daddr 169.254.169.254 log prefix "mediatore-gateway out imds: " counter drop
    ip daddr 168.63.129.16 jump output_wireserver
    meta skuid "mediatore-gateway" jump output_authorizer
    meta skuid "envoy-relay" jump output_relay
    meta skuid "spire" jump output_agent
    meta skuid "envoy" jump output_envoy
    meta skuid "envoy-inject" jump output_listener
    ip daddr 192.0.2.21 ct state new log prefix "mediatore-gateway out broker: " counter drop
  }
  chain output_wireserver {
    meta l4proto { tcp, udp } th dport 53 return
    meta skuid 0 tcp dport { 80, 32526 } accept
    meta skuid "systemd-network" udp sport 68 udp dport 67 accept
    log prefix "mediatore-gateway out wireserver: " counter drop
  }
  chain output_authorizer {
    ip daddr 192.0.2.21 tcp dport 443 accept
    log prefix "mediatore-gateway out authorizer: " counter drop
  }
  chain output_relay {
    ip daddr 192.0.2.20 tcp dport 8081 accept
    ip daddr 192.0.2.21 tcp dport 443 accept
    ip daddr 192.0.2.20 tcp dport 8443 accept
    log prefix "mediatore-gateway out relay: " counter drop
  }
  chain output_agent {
    ip daddr 192.0.2.20 tcp dport 8081 accept
    log prefix "mediatore-gateway out agent: " counter drop
  }
  chain output_envoy {
    oif "lo" ip daddr 127.0.0.1 tcp dport @check_tcp accept
    jump output_listener
  }
  chain output_listener {
    ip daddr @resolvers meta l4proto { tcp, udp } th dport 53 accept
    oif "lo" log prefix "mediatore-gateway out loopback: " counter drop
    meta nfproto ipv6 log prefix "mediatore-gateway out ipv6: " counter drop
    ip daddr @egress_refused log prefix "mediatore-gateway out refused: " counter drop
    accept
  }
}
NFT
)

# What ADR-0070 added: the set, the counters, and one rule. Each line is in the render once.
added='  set probe_sources { type ipv4_addr . inet_service; size 4096; flags dynamic,timeout; counter; timeout 5m; }
  counter gateway_port { }
  counter gateway_output_sandbox { }
  counter gateway_output_imds { }
  counter gateway_output_wireserver { }
  counter gateway_output_broker { }
  counter gateway_output_authorizer { }
  counter gateway_output_relay { }
  counter gateway_output_agent { }
  counter gateway_output_loopback { }
  counter gateway_output_ipv6 { }
  counter gateway_output_refused { }
    iifname "enp2s0" meta nfproto ipv4 meta l4proto tcp ct state new counter name "gateway_port" update @probe_sources { ip saddr . tcp dport } log prefix "mediatore-gateway drop: " drop'
while IFS= read -r line; do
  [ "$(printf '%s\n' "$got" | grep -cxF -- "$line")" = 1 ] || { echo "✗ the table does not carry, exactly once: $line"; exit 1; }
done <<< "$added"
echo "✓ the table carries the probe set, the eleven named counters and the one probe rule, each once"

# 2026-11-28, after ADR-0070: one accept, both Envoys to resolved's stub on loopback port 53 (image/gateway/resolve), the first
# line of output_listener, ahead of its loopback drop; the table otherwise as above. Pinned here, then taken away with the rest.
stub='    oif "lo" ip daddr 127.0.0.53 meta l4proto { tcp, udp } th dport 53 accept'
[ "$(printf '%s\n' "$got" | grep -cxF -- "$stub")" = 1 ] \
  && printf '%s\n' "$got" | grep -A1 -xF '  chain output_listener {' | tail -1 | grep -qxF -- "$stub" \
  || { echo "✗ the stub rule is not once, the first line of output_listener: $stub"; exit 1; }
echo "✓ both Envoys reach resolved's stub, loopback port 53, ahead of output_listener's loopback drop, and no other loopback address"
got=$(printf '%s\n' "$got" | grep -vxF -- "$stub")

# Take them away: drop the added lines, and turn each named counter on a dropping rule back
# into the anonymous one it replaced.
without=$(printf '%s\n' "$got" | grep -vxF -f <(printf '%s\n' "$added") \
  | sed 's/counter name "gateway_output_[a-z0-9]*" log prefix \("[^"]*"\) drop$/log prefix \1 counter drop/')
if [ "$without" != "$before" ]; then
  echo "✗ without the counters of ADR-0070 the table is not the table it was:"; diff <(printf '%s\n' "$before") <(printf '%s\n' "$without") || true; exit 1
fi
echo "✓ without them the table is byte for byte the one before: no verdict changed, no rule moved"

# The same thing said the other way: the lines that decide (a verdict, a jump, a policy).
verdicts() { grep -E '(accept|drop|return|jump [a-z_]+|policy (accept|drop);)$' | sed 's/counter name "gateway_[a-z0-9_]*" //; s/ counter drop$/ drop/; s/ update @probe_sources { ip saddr \. tcp dport }//'; }
new_only=$(diff <(printf '%s\n' "$before" | verdicts) <(printf '%s\n' "$got" | verdicts) | grep '^[<>]' || true)
[ "$new_only" = '>     iifname "enp2s0" meta nfproto ipv4 meta l4proto tcp ct state new log prefix "mediatore-gateway drop: " drop' ] \
  || { echo "✗ the deciding lines differ by more than the one added drop:"; printf '%s\n' "$new_only"; exit 1; }
[ "$(printf '%s\n' "$got" | grep -c 'accept')" = "$(printf '%s\n' "$before" | grep -c 'accept')" ] \
  && [ "$(printf '%s\n' "$got" | grep -c 'accept')" = 16 ] \
  || { echo "✗ the table accepts in more places than before (16 lines name accept, the two policy lines included)"; exit 1; }
printf '%s\n' "$added" | grep -q 'accept' && { echo "✗ an added line accepts"; exit 1; } || true
echo "✓ the deciding lines are the old ones and one more drop; accept is named on 16 lines, as before"

# Where the counters sit: on a rule that drops, as a statement, never alone and never before an accept.
bad=$(printf '%s\n' "$got" | grep 'counter name' | grep -v ' drop$' || true)
[ -z "$bad" ] || { echo "✗ a named counter on a rule that does not drop: $bad"; exit 1; }
[ "$(printf '%s\n' "$got" | grep -c 'counter name "gateway_')" = 11 ] || { echo "✗ not eleven counted rules"; exit 1; }
for c in $(printf '%s\n' "$got" | sed -n 's/^  counter \(gateway_[a-z0-9_]*\) { }$/\1/p'); do
  [ "$(printf '%s\n' "$got" | grep -c "counter name \"$c\" ")" = 1 ] || { echo "✗ the counter $c is not on exactly one rule"; exit 1; }
done
echo "✓ each named counter is on exactly one rule, and that rule drops"

# The probe rule: after every accept of the input chain and directly in front of its last
# drop, so a packet it does not finish with (the set full, the update failed) is dropped by
# the next rule; the counter before the update, so a full set still counts.
input=$(printf '%s\n' "$got" | sed -n '/^  chain input {$/,/^  }$/p')
n=$(printf '%s\n' "$input" | grep -n 'counter name "gateway_port"' | cut -d: -f1)
last_accept=$(printf '%s\n' "$input" | grep -n 'accept$' | tail -1 | cut -d: -f1)
[ "$n" -gt "$last_accept" ] \
  && [ "$(printf '%s\n' "$input" | sed -n "$((n + 1))p")" = '    log prefix "mediatore-gateway drop: " counter drop' ] \
  && [ "$(printf '%s\n' "$input" | sed -n "$((n + 2))p")" = '  }' ] \
  && printf '%s\n' "$input" | sed -n "${n}p" | grep -q 'counter name "gateway_port" update @probe_sources' \
  || { echo "✗ the probe rule is not the last but one of the input chain, counter first, the chain's own drop after it"; exit 1; }
echo "✓ the probe rule sits after every accept and in front of the input chain's last drop, its counter ahead of the set update"

# The reader (mediatore-gateway-probes): a user of its own, not root, with CAP_NET_ADMIN alone,
# netlink alone, no address reachable, the hardening of the units beside it, /run read-only
# but for one directory; and the authorizer still without any capability.
u="$here/systemd/mediatore-gateway-probes.service"; t="$here/systemd/mediatore-gateway-probes.timer"; a="$here/systemd/mediatore-gateway.service"
has() { grep -qx -- "$2" "$1" || { echo "✗ $(basename "$1") lacks the line: $2"; exit 1; }; }
for l in 'Type=oneshot' 'User=mediatore-probes' 'Group=mediatore-probes' 'CapabilityBoundingSet=CAP_NET_ADMIN' 'AmbientCapabilities=CAP_NET_ADMIN' 'NoNewPrivileges=yes' \
  'RestrictAddressFamilies=AF_NETLINK' 'IPAddressDeny=any' 'ProtectSystem=strict' 'ProtectHome=yes' 'PrivateTmp=yes' 'PrivateDevices=yes' \
  'ProtectKernelTunables=yes' 'ProtectKernelModules=yes' 'ProtectKernelLogs=yes' 'ProtectControlGroups=yes' 'ProtectClock=yes' \
  'ProtectHostname=yes' 'RestrictNamespaces=yes' 'RestrictRealtime=yes' 'RestrictSUIDSGID=yes' 'LockPersonality=yes' \
  'MemoryDenyWriteExecute=yes' 'SystemCallArchitectures=native' 'ReadOnlyPaths=/run' 'ReadWritePaths=/run/mediatore-gateway/probes' \
  'ExecStart=/usr/bin/mediatore gateway-probes --dir /run/mediatore-gateway/probes' \
  'Requisite=mediatore-gateway-nft.service' 'After=mediatore-gateway-nft.service'; do has "$u" "$l"; done
for k in CapabilityBoundingSet AmbientCapabilities RestrictAddressFamilies IPAddressDeny ExecStart User Group ReadOnlyPaths ReadWritePaths; do
  [ "$(grep -c "^$k=" "$u")" = 1 ] || { echo "✗ the reader's unit sets $k more than once (a second line would add to the first)"; exit 1; }
done
# Its directory comes from tmpfiles.d at boot, never from a step of its own: systemd sets the mount namespace up before any
# ExecStartPre, and a ReadWritePaths= on a directory not yet made failed every run with 226/NAMESPACE (2026-11-27).
has "$here/tmpfiles.d/mediatore-gateway.conf" 'd /run/mediatore-gateway/probes 2750 mediatore-probes mediatore-gateway -'
grep -q '^ExecStartPre=' "$u" && { echo "✗ the reader's unit has an ExecStartPre: its directory is the tmpfiles.d entry's"; exit 1; } || true
grep -q '^COPY image/gateway/tmpfiles.d/mediatore-gateway.conf /usr/lib/tmpfiles.d/mediatore-gateway.conf$' "$here/Dockerfile" \
  || { echo "✗ the image does not install the tmpfiles.d entry"; exit 1; }
grep -Eq '^(IPAddressAllow|PrivateNetwork|Restart|WantedBy|SupplementaryGroups)=' "$u" && { echo "✗ the reader's unit opens an address, restarts, is wanted by a target or takes another group"; exit 1; } || true
grep -q 'useradd .* mediatore-probes$' "$here/Dockerfile" || { echo "✗ the image does not create the reader's user"; exit 1; }
# Every hardening line of the authorizer's unit is in the reader's too, but for the three that differ on purpose.
grep -E '^(NoNewPrivileges|Protect[A-Za-z]*|Private[A-Za-z]*|Restrict[A-Za-z]*|LockPersonality|MemoryDenyWriteExecute|SystemCallArchitectures)=' "$a" \
  | grep -v '^RestrictAddressFamilies=' | while IFS= read -r l; do has "$u" "$l"; done
has "$a" 'CapabilityBoundingSet='; has "$a" 'AmbientCapabilities='; has "$a" 'User=mediatore-gateway'
[ "$(grep -c '^CapabilityBoundingSet=' "$a")" = 1 ] && ! grep -q 'probes' "$a" || { echo "✗ the authorizer's unit gained a capability line or names the probes directory"; exit 1; }
has "$t" 'OnUnitActiveSec=30s'; has "$t" 'Unit=mediatore-gateway-probes.service'; has "$t" 'WantedBy=timers.target'
grep -q 'mediatore-gateway-probes.service' "$here/Dockerfile" && grep -q '^ *mediatore-gateway-probes.timer \\$' "$here/Dockerfile" \
  || { echo "✗ the image does not install the reader's unit or enable its timer"; exit 1; }
echo "✓ the reader's unit: its own user with CAP_NET_ADMIN alone, netlink alone, no address, the authorizer's hardening, /run read-only but for one directory made by tmpfiles.d; the authorizer still holds no capability"

echo "gateway table-test: ok"
