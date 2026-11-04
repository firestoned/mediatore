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
printf 'MEDIATORE_URL=https://198.51.100.1:3130\nSPIFFE_ENDPOINT_SOCKET=/run/spire/sockets/agent.sock\nRUST_LOG=info\n' > "$d/env"
printf 'agent {\n  trust_domain = "sandbox.home.example"\n  server_address = "198.51.100.1"\n  server_port = "3129"\n}\n' > "$d/agent.conf"

want='# mediatore host table (ADR-0029): every uid reaches the gateways'"'"' two planes and the segment'"'"'s registries; nothing else leaves, nothing comes in
table inet mediatore_host
delete table inet mediatore_host
table inet mediatore_host {
  set allow4 { type ipv4_addr . inet_service; elements = { 198.51.100.1 . 8443, 198.51.100.2 . 8443, 198.51.100.3 . 8443, 198.51.100.10 . 5000, 198.51.100.1 . 3130, 198.51.100.1 . 3129 } }
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
"$here/host-table" --render "$d/gateways" "$d/registries" "$d/env" "$d/agent.conf" | grep -q '198.51.100.1 . 8443, 198.51.100.2 . 8443, 198.51.100.3 . 8443, 198.51.100.1 . 3130, 198.51.100.1 . 3129 }' \
  || { echo "✗ without a registries file the set is the gateways and the relay"; exit 1; }
echo "✓ a pool without a registry on the segment admits the gateways and the relay alone"

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
printf 'mirror.home.example:5000\n' > "$d/reg-name"; refuse "a registry given by name" "$d/gateways" "$d/reg-name" "$d/env" "$d/agent.conf"
echo "host-table-test: ok"
