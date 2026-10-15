#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# Bring the kind OpenBao (dev/kind/openbao/openbao.yaml) to the state the transit sealer
# needs (ADR-0015): initialised and unsealed, the transit engine with a derived key
# `mediatore`, the Kubernetes auth method configured against this cluster, a policy that
# allows encrypt and decrypt on that key and nothing else, and a role for the broker's
# ServiceAccount with audience `openbao`. Every `bao` runs inside the pod on its loopback.
# The unseal key and root token land in <state dir>/init.json: fixtures of a throwaway
# cluster, and in-memory storage forgets them on the next pod restart anyway.
#
#   openbao-setup.sh <kubeconfig> <state dir>
set -euo pipefail

KUBECONFIG_PATH=${1:?kubeconfig}
STATE=${2:?state dir}
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
