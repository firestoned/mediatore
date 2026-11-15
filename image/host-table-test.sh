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
printf '198.51.100.10:5000\n198.51.100.10:5000\n' > "$d/registries"
printf 'MEDIATORE_URL=https://198.51.100.1:3130\nSPIFFE_ENDPOINT_SOCKET=/run/spire/sockets/agent.sock\nRUST_LOG=info\nSPIRE_BUNDLE_HOST=spire.home.example\nSPIRE_BUNDLE_PORT=3131\nSPIRE_BUNDLE_GATEWAY=198.51.100.1\n' > "$d/env"
printf 'agent {\n  trust_domain = "sandbox.home.example"\n  server_address = "198.51.100.1"\n  server_port = "3129"\n}\n' > "$d/agent.conf"

want='# mediatore host table (ADR-0029): every uid reaches the gateways'"'"' two planes and the segment'"'"'s registries; nothing else leaves, nothing comes in
table inet mediatore_host
delete table inet mediatore_host
table inet mediatore_host {
  set allow4 { type ipv4_addr . inet_service; elements = { 198.51.100.1 . 8443, 198.51.100.2 . 8443, 198.51.100.3 . 8443, 198.51.100.10 . 5000, 198.51.100.1 . 3130, 198.51.100.1 . 3129, 198.51.100.1 . 3131 } }
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
echo "✓ the table renders as pinned, duplicates folded, comments and blanks skipped, the broker URL without a port given 443"

# no registries file: the gateways and the relay alone
rm "$d/registries"
"$here/host-table" --render "$d/gateways" "$d/registries" "$d/env" "$d/agent.conf" | grep -q '198.51.100.1 . 8443, 198.51.100.2 . 8443, 198.51.100.3 . 8443, 198.51.100.1 . 3130, 198.51.100.1 . 3129, 198.51.100.1 . 3131 }' \
  || { echo "✗ without a registries file the set is the gateways and the relay"; exit 1; }
echo "✓ a pool without a registry on the segment admits the gateways and the relay alone (its three legs: broker, SPIRE, bundle)"

# a pool with no bundle fetch configured (the bundle is a file in the layer): no bundle element
sed '/^SPIRE_BUNDLE_/d' "$d/env" > "$d/env-nobundle"
"$here/host-table" --render "$d/gateways" "$d/registries" "$d/env-nobundle" "$d/agent.conf" 2>/dev/null | grep -q '3131' \
  && { echo "✗ a pool with no bundle fetch admitted 3131"; exit 1; } || true
echo "✓ a pool that does not fetch its bundle admits no bundle port"

# the registry leg (ADR-0038 decision 3): the pull is root's, so its destination is admitted to uid 0 alone
printf 'MEDIATORE_URL=https://198.51.100.1:3130\nMEDIATORE_RELAY_REGISTRIES=registry.home.example=3132,mirror.home.example=3133\n' > "$d/env-relay"
relay=$("$here/host-table" --render "$d/gateways" "$d/registries" "$d/env-relay" "$d/agent.conf")
printf '%s\n' "$relay" | grep -qF 'set registry4 { type ipv4_addr . inet_service; elements = { 198.51.100.1 . 3132, 198.51.100.1 . 3133 } }' \
  || { echo "✗ the registry legs are one set, the MEDIATORE_URL gateway at each leg's port"; printf '%s\n' "$relay"; exit 1; }
printf '%s\n' "$relay" | grep -qF '    meta skuid 0 ip daddr . tcp dport @registry4 accept' \
  || { echo "✗ the registry set is admitted by a rule that matches root"; exit 1; }
if printf '%s\n' "$relay" | grep 'set allow4' | grep -Eq '3132|3133'; then echo "✗ a registry leg leaked into the every-uid set"; exit 1; fi
if printf '%s\n' "$relay" | grep -n 'registry4 accept' | grep -vq 'skuid 0'; then echo "✗ the registry rule is not owner-matched"; exit 1; fi
a=$(printf '%s\n' "$relay" | grep -n '@allow4 accept' | cut -d: -f1); r=$(printf '%s\n' "$relay" | grep -n '@registry4 accept' | cut -d: -f1)
[ "$a" -lt "$r" ] || { echo "✗ the registry rule comes after the every-uid rule and before the drop"; exit 1; }
printf '%s\n' "$relay" | sed -n '/chain output/,$p' | grep -n 'log prefix "mediatore-host drop: "' | grep -q . || { echo "✗ the drop stays last"; exit 1; }
echo "✓ the registry legs are a set of their own, admitted to uid 0 only, after the every-uid rule, before the drop"

# without the variable the table is the pinned one: no set, no rule
printf '%s\n' "$got" | grep -q 'registry4' && { echo "✗ a pool with no registry leg got a registry set"; exit 1; } || true
echo "✓ a pool that declares no relay registry gets no registry set and no registry rule"

# the same port twice is one element
printf 'MEDIATORE_URL=https://198.51.100.1:3130\nMEDIATORE_RELAY_REGISTRIES=a.home.example=3132,b.home.example=3132\n' > "$d/env-relay-dup"
"$here/host-table" --render "$d/gateways" "$d/registries" "$d/env-relay-dup" "$d/agent.conf" | grep -qF 'elements = { 198.51.100.1 . 3132 } }' \
  || { echo "✗ two names on one leg are one element"; exit 1; }
echo "✓ two registry names on one leg are one element"

# the inject port (ADR-0040): a gateway-placed claim's proxy dials each gateway at it, as the sandbox uid, so the host table (every uid, like the data port) admits it; the sandbox uid's own table is the second layer
printf 'MEDIATORE_URL=https://198.51.100.1:3130\nMEDIATORE_INJECT_PORT=3133\n' > "$d/env-inject"
inj=$("$here/host-table" --render "$d/gateways" "$d/registries" "$d/env-inject" "$d/agent.conf")
for gw in 198.51.100.1 198.51.100.2 198.51.100.3; do
  printf '%s\n' "$inj" | grep 'set allow4' | grep -qF "$gw . 3133" || { echo "✗ the inject port is admitted for gateway $gw"; exit 1; }
done
printf '%s\n' "$inj" | grep -q 'registry4' && { echo "✗ the inject port leaked into the root-only registry set"; exit 1; } || true
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
printf 'MEDIATORE_URL=https://mediatore.home.example:3130\nMEDIATORE_RELAY_REGISTRIES=registry.home.example=3132\n' > "$d/env-rr-name"; refuse "a registry leg whose gateway (MEDIATORE_URL) is a name" "$d/gateways" "$d/registries" "$d/env-rr-name" "$d/agent.conf"
for bad in 'registry.home.example' 'registry.home.example=' '=3132' 'registry.home.example=0' 'registry.home.example=70000' 'registry.home.example=x' 'registry.home.example:443=3132' 'a b=3132' 'a.home.example=3132,,b.home.example=3133'; do
  printf 'MEDIATORE_URL=https://198.51.100.1:3130\nMEDIATORE_RELAY_REGISTRIES=%s\n' "$bad" > "$d/env-rr-bad"; refuse "a relay registry entry '$bad'" "$d/gateways" "$d/registries" "$d/env-rr-bad" "$d/agent.conf"
done
for bad in 'x' '0' '70000' '33 33' '-1'; do
  printf 'MEDIATORE_URL=https://198.51.100.1:3130\nMEDIATORE_INJECT_PORT=%s\n' "$bad" > "$d/env-ip-bad"; refuse "an inject port '$bad'" "$d/gateways" "$d/registries" "$d/env-ip-bad" "$d/agent.conf"
done
echo "host-table-test: ok"
