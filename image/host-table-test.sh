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
printf '# the pool bootstrap list\n198.51.100.1:8443\n198.51.100.2:8443\n\n  198.51.100.3:8443  \n' > "$d/gateways"
printf '# no registry on the segment (ADR-0063)\n\n' > "$d/registries"
printf 'MEDIATORE_URL=https://198.51.100.1:3130\nSPIFFE_ENDPOINT_SOCKET=/run/spire/sockets/agent.sock\nRUST_LOG=info\nSPIRE_BUNDLE_HOST=spire.home.example\nSPIRE_BUNDLE_PORT=3131\nSPIRE_BUNDLE_GATEWAY=198.51.100.1\n' > "$d/env"
printf 'agent {\n  trust_domain = "sandbox.home.example"\n  server_address = "198.51.100.1"\n  server_port = "3129"\n}\n' > "$d/agent.conf"

want='# mediatore host table (ADR-0029, ADR-0063): every uid reaches the gateways'"'"' two planes and nothing else; nothing comes in
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
got=$("$here/host-table" --render "$d/gateways" "$d/registries" "$d/env" "$d/agent.conf")
if [ "$got" != "$want" ]; then
  echo "host-table: the rendered table drifted:"; diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") || true; exit 1
fi
echo "✓ the table renders as pinned, duplicates folded, comments and blanks skipped, a registries file of comments alone accepted"

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

echo "host-table-test: ok"
