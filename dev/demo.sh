#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0

# Front-to-back dev-mode demo of the mediatore loop, runbook Part 8 shape:
#
#   fake IdP login -> POST /v1/claims -> bind to a registered node -> GET /v1/me
#   -> POST /v1/token -> verify against mediatore's JWKS -> release -> cut-off
#
# The peer identity is a header (dev_mode), SPIRE is Noop, and the dev binder stands in
# for banlieue's claim controller. Everything else is the production code path.
set -euo pipefail
cd "$(dirname "$0")/.."

USER_URL=http://127.0.0.1:8080
SANDBOX_URL=http://127.0.0.1:8443
IDP_URL=http://127.0.0.1:18082
TRUST_DOMAIN=sandbox.home.example
AUDIENCE=grafana.home.example
GROUP=firestoned:sandbox-users
EK_HASH=$(printf 'demo%060d' 7)

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; exit 1; }

command -v jq >/dev/null || fail "jq is required"

say "build"
cargo build -q -p mediatore -p mediatore-testkit -p mediatore-guest -p sandbox-token
BIN=target/debug

[ -f dev/sts.pem ] || { say "generate STS signing key"; openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out dev/sts.pem; }

PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT

say "start fake-idp and mediatore"
"$BIN/fake-idp" serve & PIDS+=($!)
"$BIN/mediatore" serve --config dev/demo.yaml & PIDS+=($!)
for url in "$IDP_URL/jwks" "$USER_URL/healthz" "$SANDBOX_URL/healthz"; do
  for _ in $(seq 1 50); do curl -fsS "$url" >/dev/null 2>&1 && break; sleep 0.2; done
  curl -fsS "$url" >/dev/null || fail "$url never came up"
done

say "boot the 'pool member': mediatore-guest registers and waits for a claim"
NODE_SVID="spiffe://$TRUST_DOMAIN/banlieue/node/$EK_HASH"
"$BIN/mediatore-guest" \
  --mediatore-url "$SANDBOX_URL" \
  --dev-spiffe-id "$NODE_SVID" \
  --dev-ek-hash "$EK_HASH" \
  --dev-dmi-uuid "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
  --dev-skip-setup \
  --provider libvirt & GUEST=$!; PIDS+=("$GUEST")

say "login (fake IdP) and create the claim through the front door"
TOKEN=$("$BIN/fake-idp" token --login octocat --group "$GROUP")
CLAIM=$(curl -fsS "$USER_URL/v1/claims" -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"pool_ref\":\"pool-a\",\"ttl_seconds\":3600,\"audiences\":[\"$AUDIENCE\"],\"workload\":{\"image\":\"registry.internal:5000/sandbox:latest\",\"args\":[\"/bin/sh\"]}}")
echo "$CLAIM" | jq .
NAME=$(echo "$CLAIM" | jq -r .name)
UID_=$(echo "$CLAIM" | jq -r .uid)

say "wait for the claim to bind (the guest may still be registering)"
PHASE=$(echo "$CLAIM" | jq -r .phase)
for _ in $(seq 1 60); do
  [ "$PHASE" = "Bound" ] && break
  sleep 0.5
  PHASE=$(curl -fsS "$USER_URL/v1/claims/$NAME" -H "Authorization: Bearer $TOKEN" | jq -r .phase)
done
[ "$PHASE" = "Bound" ] || fail "expected Bound, got $PHASE"
echo "phase: $PHASE"

say "the guest agent fetches its subject and exits (dev_skip_setup)"
wait "$GUEST" || fail "mediatore-guest failed"

say "the 'jailed workload' trades its claim SVID for an audience token"
CLAIM_SVID="spiffe://$TRUST_DOMAIN/banlieue/claim/$UID_"
ACCESS=$(MEDIATORE_DEV_SPIFFE_ID="$CLAIM_SVID" "$BIN/sandbox-token" \
  --audience "$AUDIENCE" --mediatore-url "$SANDBOX_URL")
echo "payload:"
PAYLOAD=$(echo "$ACCESS" | cut -d. -f2)
while [ $(( ${#PAYLOAD} % 4 )) -ne 0 ]; do PAYLOAD="$PAYLOAD="; done
printf '%s' "$PAYLOAD" | base64 -d | jq '{iss, sub, aud, act, claim_uid, exp}'

say "negative: an audience outside the allowlist is refused"
if MEDIATORE_DEV_SPIFFE_ID="$CLAIM_SVID" "$BIN/sandbox-token" --audience api://something-else --mediatore-url "$SANDBOX_URL" 2>/dev/null; then
  fail "unknown audience was issued a token"
fi
echo "refused, as it must be"

say "negative: the node identity gets no token"
if MEDIATORE_DEV_SPIFFE_ID="$NODE_SVID" "$BIN/sandbox-token" --audience "$AUDIENCE" --mediatore-url "$SANDBOX_URL" 2>/dev/null; then
  fail "node SVID was issued a token"
fi
echo "refused, as it must be"

say "release the claim and confirm the cut-off"
curl -fsS -X DELETE "$USER_URL/v1/claims/$NAME" -H "Authorization: Bearer $TOKEN" -o /dev/null -w 'DELETE -> %{http_code}\n'
if MEDIATORE_DEV_SPIFFE_ID="$CLAIM_SVID" "$BIN/sandbox-token" --audience "$AUDIENCE" --mediatore-url "$SANDBOX_URL" 2>/dev/null; then
  fail "revoked claim was issued a token"
fi
echo "no more tokens after release"

say "PASS: full loop verified"
