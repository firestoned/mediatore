#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# Bring the kind OpenBao (dev/kind/openbao/openbao.yaml) to the state the transit sealer
# needs (ADR-0015): initialised and unsealed, the transit engine with a derived key
# `mediatore`, the Kubernetes auth method configured against this cluster, a policy that
# allows encrypt and decrypt on that key and nothing else, and a role for the broker's
# ServiceAccount with audience `openbao`. And, for the SPIRE server (ADR-0031): a PKI mount
# `spire` with a ten-year P-384 root named after the trust domain (the mount's maximum lease
# then set to a week, the cap on any intermediate), a policy allowing
# update on spire/root/sign-intermediate alone, and a role for the server's ServiceAccount
# (audience `openbao`); the root's certificate lands in <state dir>/upstream-root.pem, the
# bundle the kind agents start with. Every `bao` runs inside the pod on its loopback.
# The unseal key and root token land in <state dir>/init.json: fixtures of a throwaway
# cluster, and in-memory storage forgets them on the next pod restart anyway.
#
#   openbao-setup.sh <kubeconfig> <state dir> [trust domain]
set -euo pipefail

KUBECONFIG_PATH=${1:?kubeconfig}
STATE=${2:?state dir}
TD=${3:-sandbox.test}
NS=banlieue-system
K=(kubectl --kubeconfig "$KUBECONFIG_PATH" -n "$NS")
bao() { "${K[@]}" exec deploy/mediatore-openbao -- bao "$@"; }

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
mkdir -p "$STATE"

# `bao status` exits 2 while sealed and still prints its JSON; use the JSON when there is one.
status() {
  local out
  out=$(bao status -format=json 2>/dev/null) || true
  if [ -n "$out" ]; then echo "$out"; else echo '{"initialized":false,"sealed":true}'; fi
}

if [ "$(status | jq -r .initialized)" != "true" ]; then
  bao operator init -key-shares=1 -key-threshold=1 -format=json > "$STATE/init.json"
  echo "openbao: initialised"
fi
if [ "$(status | jq -r .sealed)" = "true" ]; then
  bao operator unseal "$(jq -r '.unseal_keys_b64[0]' "$STATE/init.json")" >/dev/null
  echo "openbao: unsealed"
fi
ROOT=$(jq -r .root_token "$STATE/init.json")
bao_root() { "${K[@]}" exec deploy/mediatore-openbao -- env BAO_TOKEN="$ROOT" bao "$@"; }
# The same with stdin forwarded, for a policy written from a heredoc.
bao_root_stdin() { "${K[@]}" exec -i deploy/mediatore-openbao -- env BAO_TOKEN="$ROOT" bao "$@"; }

bao_root secrets list -format=json | jq -e '."transit/"' >/dev/null 2>&1 || bao_root secrets enable transit >/dev/null
# A derived key: the broker's binding UID is the derivation context (ADR-0015 decision 2).
bao_root read transit/keys/mediatore >/dev/null 2>&1 || bao_root write -f transit/keys/mediatore derived=true type=aes256-gcm96 >/dev/null
bao_root read -format=json transit/keys/mediatore | jq -e '.data.derived == true' >/dev/null || { echo "openbao: key mediatore is not derived" >&2; exit 1; }

bao_root auth list -format=json | jq -e '."kubernetes/"' >/dev/null 2>&1 || bao_root auth enable kubernetes >/dev/null
# In-cluster: OpenBao reviews tokens with its own ServiceAccount (system:auth-delegator).
bao_root write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc:443 >/dev/null

bao_root_stdin policy write mediatore-transit - >/dev/null <<'HCL'
path "transit/encrypt/mediatore" { capabilities = ["update"] }
path "transit/decrypt/mediatore" { capabilities = ["update"] }
HCL
bao_root write auth/kubernetes/role/mediatore \
  bound_service_account_names=mediatore \
  bound_service_account_namespaces="$NS" \
  audience=openbao \
  token_policies=mediatore-transit \
  token_ttl=1h >/dev/null
echo "openbao: transit key mediatore (derived), Kubernetes auth role mediatore for $NS/mediatore (audience openbao)"

# The SPIRE server's upstream authority (ADR-0031): the mount, the root once, the policy, the role.
bao_root secrets list -format=json | jq -e '."spire/"' >/dev/null 2>&1 || bao_root secrets enable -path=spire pki >/dev/null
bao_root secrets tune -max-lease-ttl=87600h spire >/dev/null
if ! bao_root read -field=certificate spire/cert/ca 2>/dev/null | grep -q 'BEGIN CERTIFICATE'; then
  bao_root write -format=json spire/root/generate/internal common_name="$TD" key_type=ec key_bits=384 ttl=87600h issuer_name=root >/dev/null
fi
bao_root read -field=certificate spire/cert/ca > "$STATE/upstream-root.pem"
grep -q 'BEGIN CERTIFICATE' "$STATE/upstream-root.pem" || { echo "openbao: no root certificate on the spire mount" >&2; exit 1; }
# With the root issued, the mount's maximum lease comes down to a week: sign-intermediate
# truncates any longer ttl to it, so a server (or whoever holds its token) cannot obtain an
# intermediate that outlives the operator's attention. The server asks for ca_ttl (24h).
bao_root secrets tune -max-lease-ttl=168h spire >/dev/null
bao_root_stdin policy write spire-upstream - >/dev/null <<'HCL'
path "spire/root/sign-intermediate" { capabilities = ["update"] }
HCL
bao_root write auth/kubernetes/role/spire-server \
  bound_service_account_names=spire-server \
  bound_service_account_namespaces=spire-server \
  audience=openbao \
  token_policies=spire-upstream \
  token_ttl=1h >/dev/null
echo "openbao: PKI mount spire with root CN=$TD (P-384, 87600h; intermediates capped at 168h) in $STATE/upstream-root.pem, role spire-server for spire-server/spire-server (sign-intermediate only)"
