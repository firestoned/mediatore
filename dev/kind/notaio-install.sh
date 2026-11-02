#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# notaio in kind (`make kind-notaio`), from its release manifests as an operator would
# install it (notaio's install guide): the CRDs and the controller with its image pinned
# by digest, downloaded from the GitHub release and checked against the SHA-256 the
# Makefile pins, signing with the kind OpenBao `make kind-openbao` runs (ADR-0026
# decision 2 on notaio's side: a non-exportable Ed25519 transit key, a policy that
# allows signing with it and nothing else, a Kubernetes auth role for notaio's
# ServiceAccount). The public key consumers trust is written to <state dir>/notaio/
# public-key.txt as `notaio:v<N> <base64>`, which is what the broker's `policy` section
# takes. Idempotent: every step checks before it acts.
#
#   notaio-install.sh <kubeconfig> <state dir> <version> <crds sha256> <manifest sha256>
set -euo pipefail

KUBECONFIG_PATH=${1:?kubeconfig}
STATE=${2:?state dir}
VERSION=${3:?notaio version}
CRDS_SHA256=${4:?sha256 of the crds manifest}
MANIFEST_SHA256=${5:?sha256 of the install manifest}
K=(kubectl --kubeconfig "$KUBECONFIG_PATH")
OPENBAO_NS=banlieue-system
NS=notaio-system
DIR=$STATE/notaio
RELEASE=https://github.com/firestoned/notaio/releases/download/v$VERSION
CRDS=notaio-$VERSION-crds.yaml
MANIFEST=notaio-$VERSION.yaml

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
mkdir -p "$DIR"

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
fetch() { # <file> <sha256>: download unless the copy here already matches
  if [ ! -f "$DIR/$1" ] || [ "$(sha256 "$DIR/$1")" != "$2" ]; then
    curl -sSLf -o "$DIR/$1" "$RELEASE/$1"
  fi
  [ "$(sha256 "$DIR/$1")" = "$2" ] || { echo "notaio: $1 does not match the pinned SHA-256" >&2; exit 1; }
}
fetch "$CRDS" "$CRDS_SHA256"
fetch "$MANIFEST" "$MANIFEST_SHA256"
echo "notaio: release v$VERSION manifests verified against the pinned checksums"

# The signer: the kind OpenBao, with its root token from `make kind-openbao`.
[ -f "$STATE/openbao/init.json" ] || { echo "notaio: no $STATE/openbao/init.json: run make kind-openbao first" >&2; exit 1; }
ROOT=$(jq -r .root_token "$STATE/openbao/init.json")
bao_root() { "${K[@]}" -n "$OPENBAO_NS" exec deploy/mediatore-openbao -- env BAO_TOKEN="$ROOT" bao "$@"; }
bao_root_stdin() { "${K[@]}" -n "$OPENBAO_NS" exec -i deploy/mediatore-openbao -- env BAO_TOKEN="$ROOT" bao "$@"; }
bao_root read transit/keys/notaio >/dev/null 2>&1 \
  || bao_root write -f transit/keys/notaio type=ed25519 exportable=false >/dev/null
bao_root read -format=json transit/keys/notaio \
  | jq -e '.data.type == "ed25519" and .data.exportable == false' >/dev/null \
  || { echo "notaio: transit key notaio is not a non-exportable ed25519 key" >&2; exit 1; }
bao_root_stdin policy write notaio-sign - >/dev/null <<'HCL'
path "transit/sign/notaio" { capabilities = ["update"] }
HCL
bao_root write auth/kubernetes/role/notaio \
  bound_service_account_names=notaio \
  bound_service_account_namespaces="$NS" \
  audience=openbao \
  token_policies=notaio-sign \
  token_ttl=15m token_max_ttl=15m >/dev/null
bao_root read -format=json transit/keys/notaio \
  | jq -r '.data.keys | to_entries | max_by(.key | tonumber) | "notaio:v\(.key) \(.value.public_key)"' \
  > "$DIR/public-key.txt"
echo "notaio: OpenBao transit key notaio (ed25519, not exportable), policy notaio-sign, auth role notaio; consumers trust $(cut -d' ' -f1 "$DIR/public-key.txt")"

# The namespace first, so the CA the controller trusts is there before its pod starts.
"${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: $NS
  labels:
    app.kubernetes.io/name: notaio
    pod-security.kubernetes.io/enforce: restricted
YAML
"${K[@]}" -n "$NS" create configmap openbao-ca --from-file=ca.crt="$STATE/openbao/ca.pem" \
  --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null

"${K[@]}" apply -f "$DIR/$CRDS" >/dev/null
"${K[@]}" wait --for=condition=Established --timeout=60s -f "$DIR/$CRDS" >/dev/null
"${K[@]}" apply -f "$DIR/$MANIFEST" >/dev/null
# The two site-specific edits the install guide names: where OpenBao is, for the
# controller and for its NetworkPolicy's egress rule.
"${K[@]}" -n "$NS" set env deployment/notaio \
  NOTAIO_OPENBAO_ADDR="https://mediatore-openbao.$OPENBAO_NS.svc:8200" >/dev/null
"${K[@]}" -n "$NS" patch networkpolicy notaio --type=json -p "$(cat <<JSON
[{"op": "replace", "path": "/spec/egress/2/to/0", "value": {
  "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "$OPENBAO_NS"}},
  "podSelector": {"matchLabels": {"app.kubernetes.io/name": "mediatore-openbao"}}}}]
JSON
)" >/dev/null
"${K[@]}" -n "$NS" rollout status deployment/notaio --timeout=300s >/dev/null
profiles_valid() {
  local n
  n=$("${K[@]}" get sandboxprofiles -o json | jq '[.items[] | select(any(.status.conditions[]?; .type == "Valid" and .status == "True"))] | length')
  [ "$n" -ge 4 ]
}
for _ in $(seq 1 60); do profiles_valid && break; sleep 2; done
profiles_valid || { echo "notaio: the built-in profiles did not turn Valid" >&2; "${K[@]}" get sandboxprofiles -o yaml >&2; exit 1; }
echo "notaio: v$VERSION installed in $NS, signing with the kind OpenBao, the built-in profiles Valid"
