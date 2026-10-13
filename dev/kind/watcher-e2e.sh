#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# ADR-0011 against a real cluster (`make kind-e2e-watcher`): the broker from deploy/base
# holds the watcher Lease; a pool member that publishes its vTPM endorsement certificate
# gets a node entry declared through the admission policy as the broker ServiceAccount;
# a member without a certificate gets nothing; a managed claim the broker has no record
# for binds nothing and is left alone. banlieue's CRDs come from the pinned banlieue-api
# (dev/kind banlieue-crds); no banlieue controller runs, so statuses are patched by hand.
#
#   watcher-e2e.sh <kubeconfig> <trust domain> <ek pem> <ek hash file>
set -euo pipefail
cd "$(dirname "$0")/../.."

KUBECONFIG_PATH=${1:?kubeconfig}
TD=${2:?trust domain}
EK_PEM=${3:?ek pem}
EK_HASH=$(tr -d '\n' < "${4:?ek hash file}")
K=(kubectl --kubeconfig "$KUBECONFIG_PATH")
BROKER_NS=banlieue-system
NS=mediatore-e2e-watcher
TIMEOUT=${MEDIATORE_KIND_TIMEOUT:-120}
ENTRY_SELECTOR=app.kubernetes.io/managed-by=mediatore

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; dump; exit 1; }
plain() { sed "s/$(printf '\033')\[[0-9;]*m//g"; }

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

broker_pod()  { "${K[@]}" -n "$BROKER_NS" get pods -l app.kubernetes.io/name=mediatore -o json 2>/dev/null | jq -r '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")] | sort_by(.metadata.creationTimestamp) | last | select(. != null) | "pod/" + .metadata.name'; }
BROKER_POD=""
broker_logs() { [ -n "$BROKER_POD" ] && "${K[@]}" -n "$BROKER_NS" logs "$BROKER_POD" 2>/dev/null | plain || true; }
entries()     { "${K[@]}" get clusterstaticentries -l "$ENTRY_SELECTOR" -o jsonpath='{range .items[*]}{.metadata.name} {.spec.spiffeID}{"\n"}{end}' 2>/dev/null || true; }

dump() {
  printf '\n--- broker (last 40 lines)\n'; broker_logs | tail -40
  printf '\n--- lease\n'; "${K[@]}" -n "$BROKER_NS" get lease mediatore-watcher -o yaml 2>/dev/null | grep -A8 '^spec' || true
  printf '\n--- entries\n'; entries
  printf '\n--- %s\n' "$NS"; "${K[@]}" -n "$NS" get virtualmachines,virtualmachineclaims 2>/dev/null || true
}

cleanup() {
  "${K[@]}" delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() { # <seconds> <description> <command...>
  local secs=$1 what=$2 i; shift 2
  for ((i = 0; i < secs; i++)); do "$@" && return 0; sleep 1; done
  fail "$what not seen within ${secs}s"
}

say "broker: the watcher Lease is held by the running pod"
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=60s >/dev/null
BROKER_POD=$(broker_pod)
[ -n "$BROKER_POD" ] || fail "no Running broker pod in $BROKER_NS"
holder_is_pod() { [ "$("${K[@]}" -n "$BROKER_NS" get lease mediatore-watcher -o jsonpath='{.spec.holderIdentity}' 2>/dev/null)" = "${BROKER_POD#pod/}" ]; }
wait_for "$TIMEOUT" "lease mediatore-watcher held by ${BROKER_POD#pod/}" holder_is_pod
log_has() { broker_logs | grep -F "$1" | grep -qF "${2:-}"; }
wait_for "$TIMEOUT" "'claim watcher running' in the broker log" log_has "claim watcher running"
echo "held by ${BROKER_POD#pod/}; controllers running"

say "fixtures: a namespace, two pool members, one managed claim"
"${K[@]}" delete namespace "$NS" --ignore-not-found --wait=true >/dev/null
"${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=true >/dev/null
"${K[@]}" create namespace "$NS" >/dev/null
for m in member-1 member-2; do
  "${K[@]}" -n "$NS" apply -f - >/dev/null <<YAML
apiVersion: banlieue.io/v1alpha1
kind: VirtualMachine
metadata:
  name: $m
  labels: { banlieue.io/pool: e2e }
spec:
  classRef: { name: small }
  imageRef: { name: sandbox }
YAML
done
# member-1 publishes its endorsement certificate; member-2 never does.
jq -Rs '{status: {tpmEndorsementCertificates: [.]}}' < "$EK_PEM" \
  | "${K[@]}" -n "$NS" patch virtualmachine member-1 --subresource=status --type=merge --patch-file=/dev/stdin >/dev/null
"${K[@]}" -n "$NS" apply -f - >/dev/null <<YAML
apiVersion: banlieue.io/v1alpha1
kind: VirtualMachineClaim
metadata:
  name: claim-orphan
  labels: { app.kubernetes.io/managed-by: mediatore }
spec:
  poolRef: { name: e2e }
  subject: { issuer: "https://issuer.example.com", id: octocat }
  ttlSeconds: 600
YAML
jq -Rs '{status: {phase: "Bound", tpmEndorsementCertificates: [.]}}' < "$EK_PEM" \
  | "${K[@]}" -n "$NS" patch virtualmachineclaim claim-orphan --subresource=status --type=merge --patch-file=/dev/stdin >/dev/null
echo "applied"

say "member-1's certificate becomes the node entry spiffe://$TD/banlieue/node/$EK_HASH"
node_entry_declared() { entries | grep -qF "mediatore-node-$EK_HASH spiffe://$TD/banlieue/node/$EK_HASH"; }
wait_for "$TIMEOUT" "node entry for $EK_HASH" node_entry_declared
wait_for "$TIMEOUT" "'node entry declared' in the broker log" log_has "node entry declared" "$EK_HASH"
echo "declared through the admission policy as the broker ServiceAccount"

say "member-2 (no certificate) and the claim without a record get nothing"
sleep 10
n=$(entries | wc -l | tr -d ' ')
[ "$n" -eq 1 ] || fail "expected exactly one entry, saw $n"
entries | grep -q '/banlieue/claim/' && fail "a claim entry was declared for a claim the broker has no record of"
"${K[@]}" -n "$NS" get virtualmachineclaim claim-orphan >/dev/null || fail "the claim without a record was deleted"
echo "one node entry, no claim entry, claim left alone"

say "PASS: ADR-0011 holds against a real cluster (lease, node-entry trigger, fail-closed bind)"
