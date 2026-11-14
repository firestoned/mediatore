#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# image/spire-bundle-fetch pinned (ADR-0037): the exact curl it runs against the gateway's bundle leg,
# the write that is atomic, and what it refuses (a name for the gateway, a missing CA, a reply that is
# not a SPIFFE bundle). A stub stands in for curl, so this runs on any host with sh and grep
# (`make bundle-fetch-test`, a step of the image check); the live proof is a pool member's boot.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT

# A stub curl: records its arguments, writes $STUB_BODY to the --output file, exits $STUB_RC.
cat > "$d/curl" <<'STUB'
#!/bin/sh
printf '%s\n' "$@" > "$STUB_ARGS"
out=''
while [ $# -gt 0 ]; do case $1 in --output) out=$2; shift ;; esac; shift; done
[ "${STUB_RC:-0}" = 0 ] || exit "$STUB_RC"
printf '%s' "$STUB_BODY" > "$out"
STUB
chmod +x "$d/curl"
export STUB_ARGS="$d/args" CURL="$d/curl" SPIRE_BUNDLE_OUT="$d/bundle.json"
good='{"keys":[{"use":"x509-svid","kty":"EC","crv":"P-256","x5c":["MIIB"]}],"spiffe_sequence":1}'
: > "$d/ca.pem"

run() { env "$@" "$here/spire-bundle-fetch"; }

# 1. the curl it runs, and the file it writes
STUB_BODY=$good run SPIRE_BUNDLE_HOST=spire.home.example SPIRE_BUNDLE_PORT=3131 SPIRE_BUNDLE_GATEWAY=198.51.100.1 SPIRE_BUNDLE_CA="$d/ca.pem" >/dev/null
want="--fail
--silent
--show-error
--proto
=https
--tlsv1.2
--connect-timeout
5
--max-time
20
--retry
10
--retry-delay
3
--retry-all-errors
--resolve
spire.home.example:3131:198.51.100.1
--cacert
$d/ca.pem
--output
$SPIRE_BUNDLE_OUT.tmp.$$
https://spire.home.example:3131/"
got=$(sed "s/bundle.json.tmp.[0-9][0-9]*/bundle.json.tmp.PID/" "$d/args")
want=$(printf '%s\n' "$want" | sed "s/bundle.json.tmp.[0-9][0-9]*/bundle.json.tmp.PID/")
[ "$got" = "$want" ] || { echo "✗ the curl drifted:"; diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") || true; exit 1; }
[ "$(cat "$SPIRE_BUNDLE_OUT")" = "$good" ] || { echo "✗ the bundle was not written"; exit 1; }
[ "$(stat -c %a "$SPIRE_BUNDLE_OUT" 2>/dev/null || stat -f %Lp "$SPIRE_BUNDLE_OUT")" = 644 ] || { echo "✗ the bundle is not 0644"; exit 1; }
ls "$d" | grep -q 'bundle.json.tmp' && { echo "✗ a temporary file was left"; exit 1; } || true
echo "✓ one pinned https request to the gateway's bundle leg under the endpoint's own hostname, written 0644"

# 2. without SPIRE_BUNDLE_CA the system trust store is used (no --cacert)
STUB_BODY=$good run SPIRE_BUNDLE_HOST=spire.home.example SPIRE_BUNDLE_PORT=3131 SPIRE_BUNDLE_GATEWAY=198.51.100.1 >/dev/null
grep -q -- '--cacert' "$d/args" && { echo "✗ --cacert given with no SPIRE_BUNDLE_CA"; exit 1; } || true
echo "✓ no SPIRE_BUNDLE_CA: the system trust store"

# 3. not configured: a no-op, nothing run, nothing written
rm -f "$SPIRE_BUNDLE_OUT" "$d/args"
run SPIRE_BUNDLE_HOST= >/dev/null
[ ! -e "$d/args" ] && [ ! -e "$SPIRE_BUNDLE_OUT" ] || { echo "✗ a pool with no SPIRE_BUNDLE_HOST ran curl or wrote a file"; exit 1; }
echo "✓ no SPIRE_BUNDLE_HOST: nothing runs (the pool carries its bundle as a file)"

refuse() { # <what> <env...>
  local what=$1; shift
  if STUB_BODY=${STUB_BODY:-$good} run "$@" >/dev/null 2>"$d/err"; then echo "✗ $what was accepted"; exit 1; fi
  grep -q 'spire-bundle-fetch:' "$d/err" || { echo "✗ $what: no reason given"; cat "$d/err"; exit 1; }
  echo "✓ refused: $what"
}
base="SPIRE_BUNDLE_HOST=spire.home.example SPIRE_BUNDLE_PORT=3131 SPIRE_BUNDLE_GATEWAY=198.51.100.1"
# shellcheck disable=SC2086
refuse "a gateway given by name" SPIRE_BUNDLE_HOST=spire.home.example SPIRE_BUNDLE_PORT=3131 SPIRE_BUNDLE_GATEWAY=gateway-1.home.example
refuse "no gateway" SPIRE_BUNDLE_HOST=spire.home.example SPIRE_BUNDLE_PORT=3131
refuse "no port" SPIRE_BUNDLE_HOST=spire.home.example SPIRE_BUNDLE_GATEWAY=198.51.100.1
refuse "a host that is a URL" SPIRE_BUNDLE_HOST=https://spire.home.example SPIRE_BUNDLE_PORT=3131 SPIRE_BUNDLE_GATEWAY=198.51.100.1
refuse "a CA file that is not there" SPIRE_BUNDLE_HOST=spire.home.example SPIRE_BUNDLE_PORT=3131 SPIRE_BUNDLE_GATEWAY=198.51.100.1 SPIRE_BUNDLE_CA="$d/absent.pem"

# 4. a reply that is not a SPIFFE bundle, and a failing curl, leave the previous file alone
printf 'previous' > "$SPIRE_BUNDLE_OUT"
STUB_BODY='<html>proxy error</html>' refuse "a reply that is not a SPIFFE bundle" $base
STUB_RC=22 refuse "a failing curl" $base
[ "$(cat "$SPIRE_BUNDLE_OUT")" = previous ] || { echo "✗ a bad fetch replaced the previous bundle"; exit 1; }
ls "$d" | grep -q 'bundle.json.tmp' && { echo "✗ a temporary file was left after a bad fetch"; exit 1; } || true
echo "✓ a bad fetch leaves the previous bundle in place and no temporary file"
echo "spire-bundle-fetch-test: ok"
