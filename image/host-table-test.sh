#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# image/host-table pinned: the exact table it renders from a pool's files (ADR-0029
# decision 3), the names and the missing inputs it refuses. Runs on any host with sh and
# sed (`make host-table-test`, a step of the image check in CI); whether `nft` accepts the
# text is the build host's `nft -c` (testing guide).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
# The platform the table is rendered for is read from the DMI chassis asset tag (ADR-0068). A CI runner may
# itself be an Azure VM, so every render below names its tag file: absent here, so the pinned table is the
# non-Azure one wherever the test runs.
export CHASSIS_ASSET_TAG_FILE="$d/no-asset-tag"
printf '# the pool bootstrap list\n198.51.100.1:8443\n198.51.100.2:8443\n\n  198.51.100.3:8443  \n' > "$d/gateways"
printf '# no registry on the segment (ADR-0063)\n\n' > "$d/registries"
printf 'MEDIATORE_URL=https://198.51.100.1:3130\nSPIFFE_ENDPOINT_SOCKET=/run/spire/sockets/agent.sock\nRUST_LOG=info\nSPIRE_BUNDLE_HOST=spire.home.example\nSPIRE_BUNDLE_PORT=3131\nSPIRE_BUNDLE_GATEWAY=198.51.100.1\n' > "$d/env"
printf 'agent {\n  trust_domain = "sandbox.home.example"\n  server_address = "198.51.100.1"\n  server_port = "3129"\n}\n' > "$d/agent.conf"

want='# mediatore host table (ADR-0029, ADR-0063): every uid reaches the gateways'"'"' two planes and nothing else; nothing comes in
table inet mediatore_host
delete table inet mediatore_host
table inet mediatore_host {
  set allow4 { type ipv4_addr . inet_service; elements = { 198.51.100.1 . 8443, 198.51.100.2 . 8443, 198.51.100.3 . 8443, 198.51.100.1 . 3130, 198.51.100.1 . 3129, 198.51.100.1 . 3131 } }
  set inbound_sources { type ipv4_addr . inet_service; size 4096; flags dynamic,timeout; counter; timeout 5m; }
  set output_ports { type inet_service; size 1024; flags dynamic,timeout; counter; timeout 5m; }
  counter pool_inbound { }
  counter pool_output { }
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    ct state invalid drop
    meta nfproto ipv4 meta l4proto tcp ct state new counter name "pool_inbound" update @inbound_sources { ip saddr . tcp dport } log prefix "mediatore-host input: " drop
    log prefix "mediatore-host input: " counter drop
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    log prefix "mediatore-host forward: " counter drop
  }
  chain output {
    type filter hook output priority filter; policy drop;
    oif "lo" accept
    ct state established,related accept
    ip daddr . tcp dport @allow4 accept
    meta l4proto tcp ct state new counter name "pool_output" update @output_ports { tcp dport } log prefix "mediatore-host drop: " drop
    log prefix "mediatore-host drop: " counter drop
  }
}'
got=$("$here/host-table" --render "$d/gateways" "$d/registries" "$d/env" "$d/agent.conf")
if [ "$got" != "$want" ]; then
  echo "host-table: the rendered table drifted:"; diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") || true; exit 1
fi
echo "✓ the table renders as pinned, duplicates folded, comments and blanks skipped, a registries file of comments alone accepted"

# ADR-0070 decision 4: what the table drops and no honest machine sends is counted by name, for the guest's segment
# reader (pool_inbound with its sources, pool_output with its ports). Proven by taking the six added lines away
# again: what is left is, byte for byte, the table as it was before them, so no verdict changed, no rule moved and
# nothing new is accepted. The same holds for the Azure render below, which is built from this one.
added='  set inbound_sources { type ipv4_addr . inet_service; size 4096; flags dynamic,timeout; counter; timeout 5m; }
  set output_ports { type inet_service; size 1024; flags dynamic,timeout; counter; timeout 5m; }
  counter pool_inbound { }
  counter pool_output { }
    meta nfproto ipv4 meta l4proto tcp ct state new counter name "pool_inbound" update @inbound_sources { ip saddr . tcp dport } log prefix "mediatore-host input: " drop
    meta l4proto tcp ct state new counter name "pool_output" update @output_ports { tcp dport } log prefix "mediatore-host drop: " drop'
before='# mediatore host table (ADR-0029, ADR-0063): every uid reaches the gateways'"'"' two planes and nothing else; nothing comes in
table inet mediatore_host
delete table inet mediatore_host
table inet mediatore_host {
  set allow4 { type ipv4_addr . inet_service; elements = { 198.51.100.1 . 8443, 198.51.100.2 . 8443, 198.51.100.3 . 8443, 198.51.100.1 . 3130, 198.51.100.1 . 3129, 198.51.100.1 . 3131 } }
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    ct state invalid drop
    log prefix "mediatore-host input: " counter drop
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    log prefix "mediatore-host forward: " counter drop
  }
  chain output {
    type filter hook output priority filter; policy drop;
    oif "lo" accept
    ct state established,related accept
    ip daddr . tcp dport @allow4 accept
    log prefix "mediatore-host drop: " counter drop
  }
}'
while IFS= read -r line; do
  [ "$(printf '%s\n' "$got" | grep -cxF -- "$line")" = 1 ] || { echo "✗ the table does not carry, exactly once: $line"; exit 1; }
done <<< "$added"
without=$(printf '%s\n' "$got" | grep -vxF -f <(printf '%s\n' "$added"))
if [ "$without" != "$before" ]; then
  echo "✗ without the counters of ADR-0070 the table is not the table it was:"; diff <(printf '%s\n' "$before") <(printf '%s\n' "$without") || true; exit 1
fi
printf '%s\n' "$added" | grep -q 'accept' && { echo "✗ an added line accepts"; exit 1; } || true
[ "$(printf '%s\n' "$got" | grep -c 'accept$')" = 5 ] || { echo "✗ the table does not accept in exactly the five places it did"; exit 1; }
bad=$(printf '%s\n' "$got" | grep 'counter name' | grep -v ' drop$' || true)
[ -z "$bad" ] && [ "$(printf '%s\n' "$got" | grep -c 'counter name')" = 2 ] || { echo "✗ a named counter that is not on one of the two dropping rules: $bad"; exit 1; }
# Each counted rule sits after every accept of its chain and directly in front of the chain's own last drop, its
# counter ahead of the set update: a packet the rule does not finish with (the set full) is dropped by the next one,
# and was counted.
for pair in 'input:pool_inbound:mediatore-host input: ' 'output:pool_output:mediatore-host drop: '; do
  chain=${pair%%:*}; rest=${pair#*:}; name=${rest%%:*}; prefix=${rest#*:}
  c=$(printf '%s\n' "$got" | sed -n "/^  chain $chain {\$/,/^  }\$/p")
  n=$(printf '%s\n' "$c" | grep -n "counter name \"$name\" update @" | cut -d: -f1)
  [ -n "$n" ] && [ "$n" -gt "$(printf '%s\n' "$c" | grep -n 'accept$' | tail -1 | cut -d: -f1)" ] \
    && [ "$(printf '%s\n' "$c" | sed -n "$((n + 1))p")" = "    log prefix \"$prefix\" counter drop" ] \
    && [ "$(printf '%s\n' "$c" | sed -n "$((n + 2))p")" = '  }' ] \
    || { echo "✗ the $name rule is not the last but one of the $chain chain, after its accepts, counter first"; exit 1; }
done
echo "✓ the two dropping rules are counted by name (pool_inbound, pool_output), each in front of its chain's last drop; without the six added lines the table is the one before, and it accepts in the same five places"

# no registries file: the same table
cp "$d/registries" "$d/registries-comments"; rm "$d/registries"
[ "$("$here/host-table" --render "$d/gateways" "$d/registries" "$d/env" "$d/agent.conf")" = "$got" ] \
  || { echo "✗ without a registries file the table differs"; exit 1; }
echo "✓ a pool with no registries file admits the gateways and the relay alone (its three legs: broker, SPIRE, bundle)"

# a pool with no bundle fetch configured (the bundle is a file in the layer): no bundle element
sed '/^SPIRE_BUNDLE_/d' "$d/env" > "$d/env-nobundle"
"$here/host-table" --render "$d/gateways" "$d/registries" "$d/env-nobundle" "$d/agent.conf" 2>/dev/null | grep -q '3131' \
  && { echo "✗ a pool with no bundle fetch admitted 3131"; exit 1; } || true
echo "✓ a pool that does not fetch its bundle admits no bundle port"

# ADR-0063 decision 4: no registry address for any uid; a registry on the segment or a relay registry leg is refused
printf '198.51.100.10:5000\n' > "$d/reg-segment"
printf 'MEDIATORE_URL=https://198.51.100.1:3130\nMEDIATORE_RELAY_REGISTRIES=registry.home.example=3132\n' > "$d/env-relay"
for args in "$d/reg-segment $d/env" "$d/registries $d/env-relay"; do
  set -- $args
  if "$here/host-table" --render "$d/gateways" "$1" "$2" "$d/agent.conf" >/dev/null 2>"$d/err"; then echo "✗ a registry around the gateway was accepted ($args)"; exit 1; fi
  grep -q 'ADR-0063' "$d/err" || { echo "✗ the refusal does not say why"; cat "$d/err"; exit 1; }
done
printf '%s\n' "$got" | grep -q 'registry4' && { echo "✗ a registry set was rendered"; exit 1; } || true
echo "✓ a registry on the segment and a relay registry leg are refused, and no registry set is ever rendered"

# the inject port (ADR-0040): a gateway-placed claim's proxy dials each gateway at it, as the sandbox uid, so the host table (every uid, like the data port) admits it; the sandbox uid's own table is the second layer
printf 'MEDIATORE_URL=https://198.51.100.1:3130\nMEDIATORE_INJECT_PORT=3133\n' > "$d/env-inject"
inj=$("$here/host-table" --render "$d/gateways" "$d/registries" "$d/env-inject" "$d/agent.conf")
for gw in 198.51.100.1 198.51.100.2 198.51.100.3; do
  printf '%s\n' "$inj" | grep 'set allow4' | grep -qF "$gw . 3133" || { echo "✗ the inject port is admitted for gateway $gw"; exit 1; }
done
echo "✓ MEDIATORE_INJECT_PORT admits every gateway at that port, in the every-uid set"
printf '%s\n' "$got" | grep -q '3133' && { echo "✗ a pool with no inject port admitted 3133"; exit 1; } || true
echo "✓ a pool that sets no inject port admits none"

refuse() { # <what> <args...>
  local what=$1; shift
  if "$here/host-table" --render "$@" >/dev/null 2>"$d/err"; then echo "✗ $what was accepted"; exit 1; fi
  grep -q 'host-table:' "$d/err" || { echo "✗ $what: no reason given"; cat "$d/err"; exit 1; }
  echo "✓ refused: $what"
}
printf 'gateway-1.home.example:8443\n' > "$d/named"; refuse "a gateway given by name" "$d/named" "$d/registries" "$d/env" "$d/agent.conf"
printf '198.51.100.1\n' > "$d/noport"; refuse "a gateway without a port" "$d/noport" "$d/registries" "$d/env" "$d/agent.conf"
printf '# nothing\n' > "$d/empty"; refuse "an empty gateway list" "$d/empty" "$d/registries" "$d/env" "$d/agent.conf"
refuse "no gateway list at all (a direct pool loads no host table)" "$d/absent" "$d/registries" "$d/env" "$d/agent.conf"
printf 'MEDIATORE_URL=https://mediatore.home.example\n' > "$d/env-name"; refuse "a broker given by name" "$d/gateways" "$d/registries" "$d/env-name" "$d/agent.conf"
printf 'agent {\n  server_address = "spire.home.example"\n  server_port = "8081"\n}\n' > "$d/agent-name"; refuse "a SPIRE server given by name" "$d/gateways" "$d/registries" "$d/env" "$d/agent-name"
printf 'MEDIATORE_URL=https://198.51.100.1:3130\nSPIRE_BUNDLE_HOST=spire.home.example\nSPIRE_BUNDLE_PORT=3131\nSPIRE_BUNDLE_GATEWAY=gateway-1.home.example\n' > "$d/env-bgname"; refuse "a bundle gateway given by name" "$d/gateways" "$d/registries" "$d/env-bgname" "$d/agent.conf"
printf 'MEDIATORE_URL=https://198.51.100.1:3130\nSPIRE_BUNDLE_HOST=spire.home.example\nSPIRE_BUNDLE_GATEWAY=198.51.100.1\n' > "$d/env-bgport"; refuse "a bundle gateway without a bundle port" "$d/gateways" "$d/registries" "$d/env-bgport" "$d/agent.conf"
printf 'mirror.home.example:5000\n' > "$d/reg-name"; refuse "a registry given by name" "$d/gateways" "$d/reg-name" "$d/env" "$d/agent.conf"
for bad in 'x' '0' '70000' '33 33' '-1'; do
  printf 'MEDIATORE_URL=https://198.51.100.1:3130\nMEDIATORE_INJECT_PORT=%s\n' "$bad" > "$d/env-ip-bad"; refuse "an inject port '$bad'" "$d/gateways" "$d/registries" "$d/env-ip-bad" "$d/agent.conf"
done
# host-quiet (ADR-0063 decision 8): the units that dial out masked for the boot and stopped, the DHCP catch-all gone,
# the deployment's static file kept
want_units='systemd-timesyncd.service
systemd-resolved.service
apt-daily.timer
apt-daily-upgrade.timer
iscsid.socket
iscsid.service
open-iscsi.service
open-vm-tools.service
vgauth.service'
[ "$("$here/host-quiet" --list)" = "$want_units" ] || { echo "✗ host-quiet's units drifted"; "$here/host-quiet" --list; exit 1; }
mkdir "$d/net"; touch "$d/net/10-static.network" "$d/net/20-dhcp.network" "$d/net/20-dhcp-legacy.network"
printf '#!/bin/sh\necho "$*" >> "%s"\n' "$d/calls" > "$d/systemctl"; chmod +x "$d/systemctl"
SYSTEMCTL="$d/systemctl" NETWORK_DIR="$d/net" "$here/host-quiet" > "$d/quiet.out"
[ -e "$d/net/10-static.network" ] || { echo "✗ host-quiet removed the static network file"; exit 1; }
[ ! -e "$d/net/20-dhcp.network" ] && [ ! -e "$d/net/20-dhcp-legacy.network" ] || { echo "✗ the DHCP catch-all survived"; exit 1; }
for u in $want_units; do
  grep -qx "mask --runtime $u" "$d/calls" && grep -qx "stop --no-block $u" "$d/calls" || { echo "✗ $u was not masked for the boot and stopped"; cat "$d/calls"; exit 1; }
done
grep -q 'DHCP catch-all removed: 20-dhcp.network 20-dhcp-legacy.network' "$d/quiet.out" || { echo "✗ host-quiet does not say what it removed"; cat "$d/quiet.out"; exit 1; }
echo "✓ host-quiet masks the units that dial out for the boot, stops them, and removes the DHCP catch-all but not the static file"

# ADR-0068: on Azure (the DMI chassis asset tag Azure sets) the output chain also drops IMDS explicitly, admits
# root alone to WireServer at its two ports, and the network daemon's DHCP renewal to it; anywhere else the table is
# byte for byte the pinned one, and no render admits a link-local or platform address through the pool's files.
azure_tag='7783-7084-3265-9085-8269-3286-77'
for other in 'No Asset Tag' '' '7783-7084-3265-9085-8269-3286-78'; do
  printf '%s\n' "$other" > "$d/tag-other"
  [ "$(CHASSIS_ASSET_TAG_FILE="$d/tag-other" "$here/host-table" --render "$d/gateways" "$d/registries" "$d/env" "$d/agent.conf")" = "$got" ] \
    || { echo "✗ a chassis asset tag of '$other' changed the table"; exit 1; }
done
echo "✓ off Azure (no tag file, another tag, an empty one) the table is the pinned one, unchanged"

want_azure=$(printf '%s\n' "$want" | sed '/^    oif "lo" accept$/a\
    ip daddr 169.254.169.254 log prefix "mediatore-host imds: " counter drop
/^    ip daddr \. tcp dport @allow4 accept$/a\
    ip daddr 168.63.129.16 tcp dport { 80, 32526 } meta skuid 0 accept\
    ip daddr 168.63.129.16 udp sport 68 udp dport 67 meta skuid "systemd-network" accept
/^# mediatore host table/a\
# on Azure (ADR-0068): IMDS dropped for every uid; WireServer for root alone, at 80 and 32526, and the DHCP renewal of systemd-networkd')
printf '%s\n' "$azure_tag" > "$d/tag-azure"
az=$(CHASSIS_ASSET_TAG_FILE="$d/tag-azure" "$here/host-table" --render "$d/gateways" "$d/registries" "$d/env" "$d/agent.conf")
if [ "$az" != "$want_azure" ]; then
  echo "host-table: the Azure table drifted:"; diff <(printf '%s\n' "$want_azure") <(printf '%s\n' "$az") || true; exit 1
fi
echo "✓ on Azure the table renders as pinned: the pinned table plus the IMDS drop, root's WireServer and the DHCP renewal"
printf '  %s  \n\n' "$azure_tag" > "$d/tag-azure-ws"
[ "$(CHASSIS_ASSET_TAG_FILE="$d/tag-azure-ws" "$here/host-table" --render "$d/gateways" "$d/registries" "$d/env" "$d/agent.conf")" = "$az" ] \
  || { echo "✗ the Azure tag with the whitespace sysfs adds was not recognised"; exit 1; }
echo "✓ the tag is read as sysfs writes it (trailing newline, blanks)"

# What the Azure rules admit, and to whom: every line naming WireServer is root's at 80 or 32526, or the network
# daemon's DHCP; IMDS appears once, as a drop, before any accept but loopback; nothing names link-local otherwise.
out=$(printf '%s\n' "$az" | sed -n '/chain output {/,/^  }/p')
printf '%s\n' "$out" | grep -F '168.63.129.16' | while IFS= read -r l; do
  case $l in
    *'tcp dport { 80, 32526 } meta skuid 0 accept') ;;
    *'udp sport 68 udp dport 67 meta skuid "systemd-network" accept') ;;
    *) echo "✗ a WireServer rule that is not root's (or the DHCP renewal's): $l"; exit 1 ;;
  esac
done
[ "$(printf '%s\n' "$out" | grep -c '168.63.129.16')" = 2 ] || { echo "✗ WireServer named other than twice"; exit 1; }
printf '%s\n' "$az" | grep -F 'set allow4' | grep -Eq '168\.63\.129\.16|169\.254\.' && { echo "✗ a platform address in the every-uid set"; exit 1; } || true
first_accept=$(printf '%s\n' "$out" | grep -n 'accept$' | grep -v 'oif "lo" accept' | head -1 | cut -d: -f1)
imds=$(printf '%s\n' "$out" | grep -n '169.254.169.254' | cut -d: -f1)
[ -n "$imds" ] && [ "$(printf '%s\n' "$imds" | wc -l | tr -d ' ')" = 1 ] && [ "$imds" -lt "$first_accept" ] \
  && printf '%s\n' "$out" | grep -F '169.254.169.254' | grep -q 'drop$' \
  || { echo "✗ IMDS is not dropped explicitly, for every uid, before the first accept"; exit 1; }
printf '%s\n' "$out" | grep -F '169.254.169.254' | grep -q skuid && { echo "✗ the IMDS drop is keyed on a uid"; exit 1; } || true
echo "✓ on Azure WireServer is root's alone (TCP 80 and 32526) and the DHCP renewal's, and IMDS is dropped for every uid first"
printf '%s\n' "$got" | grep -Eq '168\.63\.129\.16|169\.254\.169\.254|skuid' && { echo "✗ the non-Azure table names a platform address or a uid"; exit 1; } || true
echo "✓ the non-Azure table names no platform address and no uid"

# No pool file may put a link-local address (IMDS among them) or WireServer in the every-uid set, on any platform.
for bad in 169.254.169.254:80 169.254.1.1:8443 168.63.129.16:80; do
  printf '%s\n' "$bad" > "$d/gw-platform"; refuse "a gateway at $bad" "$d/gw-platform" "$d/registries" "$d/env" "$d/agent.conf"
  printf 'MEDIATORE_URL=https://%s\n' "$bad" > "$d/env-platform"; refuse "a broker at $bad" "$d/gateways" "$d/registries" "$d/env-platform" "$d/agent.conf"
done
printf 'agent {\n  server_address = "169.254.169.254"\n  server_port = "3129"\n}\n' > "$d/agent-imds"; refuse "a SPIRE server at IMDS" "$d/gateways" "$d/registries" "$d/env" "$d/agent-imds"
CHASSIS_ASSET_TAG_FILE="$d/tag-azure" "$here/host-table" --render "$d/gw-platform" "$d/registries" "$d/env" "$d/agent.conf" >/dev/null 2>&1 \
  && { echo "✗ WireServer in the gateway list was accepted on Azure"; exit 1; } || true
echo "✓ a link-local address or WireServer in a pool's files is refused, on Azure too"

echo "host-table-test: ok"
