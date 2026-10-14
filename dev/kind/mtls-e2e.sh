#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# ADR-0007 against a real SPIRE (`make kind-e2e-mtls`): the broker Deployment from
# deploy/base running on the CSI driver's socket, and client pods whose SVIDs a real
# agent issued, talking to the sandbox listener with the shipped binary's guest and token roles.
#
#   mtls-e2e.sh <kubeconfig> [trust domain]
#
# What it proves, and the hermetic suite (crates/mediatore/tests/e2e_mtls.rs) cannot:
# the ClusterSPIFFEID in deploy/base renders to spiffe://<td>/mediatore for the broker
# pod; the CSI inline volume delivers the Workload API under PSS restricted; the k8s
# workload attestor's SVIDs chain to the bundle the broker got from the same agent;
# X25519MLKEM768 and AES-256-GCM-SHA384 are what two agent-issued SVIDs negotiate.
# The identities are fixtures in dev/kind/mtls/clients.yaml.
set -euo pipefail
cd "$(dirname "$0")/../.."

KUBECONFIG_PATH=${1:?kubeconfig}
TD=${2:-sandbox.test}
K=(kubectl --kubeconfig "$KUBECONFIG_PATH")
BROKER_NS=banlieue-system
NS=mediatore-e2e
CLIENTS=dev/kind/mtls/clients.yaml
CLAIM_UID=6b0a3e9c-1f4d-4c2e-9a7b-0d1e2f3a4b5c
EK_HASH=$(printf 'ec%062x' 7)
TIMEOUT=${MEDIATORE_KIND_TIMEOUT:-180}

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; dump; exit 1; }

# Logs with any ANSI colour stripped, so a field and its value stay adjacent.
plain()       { sed "s/$(printf '\033')\[[0-9;]*m//g"; }
# The newest broker pod that is Running and not being deleted, resolved once: after a
# rollout restart the old pod lingers in phase Running with a deletion timestamp, and its
# log has none of this run's connections.
broker_pod()  { "${K[@]}" -n "$BROKER_NS" get pods -l app.kubernetes.io/name=mediatore -o json 2>/dev/null | jq -r '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")] | sort_by(.metadata.creationTimestamp) | last | select(. != null) | "pod/" + .metadata.name'; }
BROKER_POD=""
broker_logs() { [ -n "$BROKER_POD" ] && "${K[@]}" -n "$BROKER_NS" logs "$BROKER_POD" 2>/dev/null | plain || true; }
pod_logs()    { "${K[@]}" -n "$NS" logs "pod/$1" 2>/dev/null | plain || true; }
pod_phase()   { "${K[@]}" -n "$NS" get pod "$1" -o jsonpath='{.status.phase}' 2>/dev/null || true; }

dump() {
  printf '\n--- broker (last 40 lines)\n'; broker_logs | tail -40
  printf '\n--- %s pods\n' "$NS"; "${K[@]}" -n "$NS" get pods -o wide 2>/dev/null || true
  for p in claim node intruder impersonator; do
    printf '\n--- %s (last 20 lines)\n' "$p"; pod_logs "$p" | tail -20
  done
}

# Before the run, wait for a previous run's namespace to be gone; on exit, do not.
cleanup() { "${K[@]}" delete -f "$CLIENTS" --ignore-not-found --wait="${1:-false}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Wait until a pod's log contains a line, or the pod has finished without it.
wait_for_log() {
  local pod=$1 want=$2 i
  for ((i = 0; i < TIMEOUT; i++)); do
    pod_logs "$pod" | grep -qF -- "$want" && return 0
    case "$(pod_phase "$pod")" in Succeeded|Failed) pod_logs "$pod" | grep -qF -- "$want" && return 0; fail "$pod finished without '$want'" ;; esac
    sleep 1
  done
  fail "$pod: '$want' not seen within ${TIMEOUT}s"
}

wait_for_end() {
  local pod=$1 i
  for ((i = 0; i < TIMEOUT; i++)); do
    case "$(pod_phase "$pod")" in Succeeded|Failed) return 0 ;; esac
    sleep 1
  done
  fail "$pod: still running after ${TIMEOUT}s"
}

say "broker: identity from the Workload API over the CSI mount"
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=60s >/dev/null
BROKER_POD=$(broker_pod)
[ -n "$BROKER_POD" ] || fail "no Running broker pod in $BROKER_NS"
broker_logs | grep -F "broker identity from the Workload API" | grep -qF "spiffe_id=spiffe://$TD/mediatore" \
  || fail "the broker did not report spiffe://$TD/mediatore from the Workload API"
echo "spiffe://$TD/mediatore, from the ClusterSPIFFEID in deploy/base"

say "client pods: SVIDs issued by the agent (claim, node, intruder, broker impersonator)"
cleanup true
"${K[@]}" apply -f "$CLIENTS" >/dev/null

say "claim SVID: handshake, then an HTTP answer about this claim UID"
wait_for_log claim "unknown claim"
echo "403 unknown claim: the listener derived $CLAIM_UID from the certificate"

say "node SVID: POST /v1/nodes accepted for its own EK hash"
wait_for_log node "node registered"
echo "registered as spiffe://$TD/banlieue/node/$EK_HASH"

say "SVID outside /banlieue/: refused in the handshake"
wait_for_end intruder
pod_logs intruder | grep -qF "mediatore: " && fail "the intruder received an HTTP answer"
echo "no HTTP answer"

say "the broker's own ID as a client: refused in the handshake"
wait_for_end impersonator
pod_logs impersonator | grep -qF "mediatore: " && fail "the impersonator received an HTTP answer"
echo "no HTTP answer"

say "broker log: who got in, over what, and who did not"
LOGS=$(broker_logs)
claim_line=$(grep -F "mtls connection" <<<"$LOGS" | grep -F "spiffe_id=spiffe://$TD/banlieue/claim/$CLAIM_UID" || true)
[ -n "$claim_line" ] || fail "no mtls connection line for the claim SVID"
grep -qF "X25519MLKEM768" <<<"$claim_line" || fail "the claim connection did not use X25519MLKEM768"
grep -qF "TLS13_AES_256_GCM_SHA384" <<<"$claim_line" || fail "the claim connection did not use AES-256-GCM-SHA384"
echo "claim: X25519MLKEM768, TLS13_AES_256_GCM_SHA384"
grep -F "mtls connection" <<<"$LOGS" | grep -qF "spiffe_id=spiffe://$TD/banlieue/node/$EK_HASH" || fail "no mtls connection line for the node SVID"
echo "node: connected"
grep -F "peer authenticated but not authorized here" <<<"$LOGS" | grep -qF "spiffe_id=spiffe://$TD/intruder" || fail "the intruder was not refused by the authorizer"
echo "intruder: authenticated, not authorized"
grep -F "peer authenticated but not authorized here" <<<"$LOGS" | grep -qF "spiffe_id=spiffe://$TD/mediatore" || fail "the impersonator was not refused by the authorizer"
echo "impersonator: authenticated, not authorized"
n=$(grep -cF "mtls handshake refused" <<<"$LOGS" || true)
[ "$n" -ge 2 ] || fail "expected at least two refused handshakes in the broker log, saw $n"

say "PASS: ADR-0007 holds against a real agent and the CSI driver"
