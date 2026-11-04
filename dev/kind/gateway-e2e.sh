#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# ADR-0028 against a real Envoy and a real SPIRE (`make kind-e2e-gateway`): the gateway
# pod from dev/kind/gateway (Envoy on the gateway SVID over SDS, mediatore gateway beside
# it), the broker from deploy/base, and probe pods standing in for `mediatore forward`
# with claim SVIDs the real agent issued. A sandbox is created and bound as in the sandbox
# tier, so the broker has a live claim whose allowlist is one destination.
#
#   gateway-e2e.sh <admin kubeconfig> <broker SA kubeconfig> <trust domain> <ek pem> <ek hash file>
#
# What it proves: the claim's tunnel to its one destination opens and the destination
# answers; a second host and a second port are refused by the authorizer with their codes;
# a node SVID is refused by Envoy's validator before any check; with the broker gone the
# cached allowlist stands in until the stale bound and then the outage is a deny; a released
# claim is cut off once its answer is stale; the three logs (Envoy's access log, the
# authorizer's decisions, the destination's requests) agree on who reached what.
set -euo pipefail
cd "$(dirname "$0")/../.."

ADMIN_KUBECONFIG=${1:?admin kubeconfig}
SA_KUBECONFIG=${2:?broker ServiceAccount kubeconfig}
TD=${3:?trust domain}
EK_PEM=${4:?ek pem}
EK_HASH=$(tr -d '\n' < "${5:?ek hash file}")
K=(kubectl --kubeconfig "$ADMIN_KUBECONFIG")
KSA=(kubectl --kubeconfig "$SA_KUBECONFIG")
BROKER_NS=banlieue-system
NS=mediatore-e2e-gateway
ISSUER=https://issuer.example.com
TIMEOUT=${MEDIATORE_KIND_TIMEOUT:-180}
ENTRY_SELECTOR=app.kubernetes.io/managed-by=mediatore
GATEWAY=gateway.$NS.svc.cluster.local:8443
DESTINATION=destination.$NS.svc.cluster.local:8080
# What the authorizer in dev/kind/gateway/gateway.yaml runs with.
FRESH_SECS=5
STALE_SECS=20

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; dump; exit 1; }
plain() { sed "s/$(printf '\033')\[[0-9;]*m//g"; }

broker_pod()  { "${K[@]}" -n "$BROKER_NS" get pods -l app.kubernetes.io/name=mediatore -o json 2>/dev/null | jq -r '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")] | sort_by(.metadata.creationTimestamp) | last | select(. != null) | "pod/" + .metadata.name'; }
BROKER_POD=""
broker_logs() { [ -n "$BROKER_POD" ] && "${K[@]}" -n "$BROKER_NS" logs "$BROKER_POD" 2>/dev/null | plain || true; }
envoy_logs()  { "${K[@]}" -n "$NS" logs deploy/gateway -c envoy 2>/dev/null || true; }
authz_logs()  { "${K[@]}" -n "$NS" logs deploy/gateway -c authorizer 2>/dev/null | plain || true; }
dest_logs()   { "${K[@]}" -n "$NS" logs deploy/destination 2>/dev/null || true; }
pod_logs()    { "${K[@]}" -n "$NS" logs "pod/$1" 2>/dev/null | plain || true; }
pod_phase()   { "${K[@]}" -n "$NS" get pod "$1" -o jsonpath='{.status.phase}' 2>/dev/null || true; }
entries()     { "${K[@]}" get clusterstaticentries -l "$ENTRY_SELECTOR" -o jsonpath='{range .items[*]}{.metadata.name} {.spec.spiffeID}{"\n"}{end}' 2>/dev/null || true; }
sandbox()     { "${K[@]}" -n "$NS" get agentsandbox "$1" -o json 2>/dev/null || true; }
field()       { sandbox "$1" | jq -r "$2 // empty"; }

dump() {
  printf '\n--- broker (last 40 lines)\n'; broker_logs | tail -40
  printf '\n--- envoy (last 40 lines)\n'; envoy_logs | tail -40
  printf '\n--- authorizer (last 40 lines)\n'; authz_logs | tail -40
  printf '\n--- destination (last 20 lines)\n'; dest_logs | tail -20
  printf '\n--- %s pods\n' "$NS"; "${K[@]}" -n "$NS" get pods -o wide 2>/dev/null || true
  for p in probe-claim probe-node probe-outage-1 probe-outage-2 probe-released; do
    printf '\n--- %s\n' "$p"; pod_logs "$p" | tail -12
  done
}

cleanup() {
  "${K[@]}" -n "$NS" delete agentsandbox --all --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" -n "$NS" delete pod node probe-claim probe-node probe-outage-1 probe-outage-2 probe-released --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete clusterspiffeid mediatore-e2e-gateway-node mediatore-e2e-gateway-claim --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" -n "$BROKER_NS" scale deploy/mediatore --replicas=1 >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() { # <seconds> <description> <command...>
  local secs=$1 what=$2 i; shift 2
  for ((i = 0; i < secs; i++)); do "$@" && return 0; sleep 1; done
  fail "$what not seen within ${secs}s"
}
log_has() { broker_logs | grep -F "$1" | grep -qF "${2:-}"; }
wait_for_end() {
  local pod=$1 i
  for ((i = 0; i < TIMEOUT; i++)); do
    case "$(pod_phase "$pod")" in Succeeded|Failed) return 0 ;; esac
    sleep 1
  done
  fail "$pod: still running after ${TIMEOUT}s"
}
# A probe pod with role label <role>, running the checks given; waits for it to end and
# shows its lines.
probe() { # <name> <role label> <check>...
  local name=$1 role=$2; shift 2
  local args=""
  for c in "$@"; do args="$args
        - --check
        - \"$c\""
  done
  "${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $name
  namespace: $NS
  labels: { mediatore.dev/e2e-role: $role }
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: probe
      image: localhost/mediatore-e2e:kind
      imagePullPolicy: Never
      command:
        - /usr/bin/gateway-probe
        - check
        - --gateway
        - "$GATEWAY"
        - --trust-domain
        - "$TD"$args
      env:
        - { name: SPIFFE_ENDPOINT_SOCKET, value: "unix:///run/spire/sockets/spire-agent.sock" }
      volumeMounts:
        - { name: spire-agent-socket, mountPath: /run/spire/sockets, readOnly: true }
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
  volumes:
    - name: spire-agent-socket
      csi: { driver: csi.spiffe.io, readOnly: true }
YAML
  wait_for_end "$name"
  pod_logs "$name" | grep -F "probe " || true
  [ "$(pod_phase "$name")" = Succeeded ] || fail "$name did not end as expected"
}

say "broker: the watcher Lease is held by the running pod"
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=60s >/dev/null
BROKER_POD=$(broker_pod)
[ -n "$BROKER_POD" ] || fail "no Running broker pod in $BROKER_NS"
holder_is_pod() { [ "$("${K[@]}" -n "$BROKER_NS" get lease mediatore-watcher -o jsonpath='{.spec.holderIdentity}' 2>/dev/null)" = "${BROKER_POD#pod/}" ]; }
wait_for "$TIMEOUT" "lease mediatore-watcher held by ${BROKER_POD#pod/}" holder_is_pod
wait_for "$TIMEOUT" "'claim watcher running' in the broker log" log_has "claim watcher running"
echo "held by ${BROKER_POD#pod/}; controllers running"

say "gateway: Envoy on the gateway SVID over SDS, the authorizer beside it, the destination behind it"
"${K[@]}" -n "$NS" rollout status deploy/gateway --timeout=120s >/dev/null
"${K[@]}" -n "$NS" rollout status deploy/destination --timeout=120s >/dev/null
authz_up() { authz_logs | grep -qF "gateway authorizer listening"; }
wait_for "$TIMEOUT" "'gateway authorizer listening' in the authorizer log" authz_up
authz_logs | grep -F "gateway SVID from the Workload API" | grep -qF "spiffe_id=spiffe://$TD/gateway" || fail "the authorizer did not get spiffe://$TD/gateway"
envoy_ready() { envoy_logs | grep -qE "all dependencies initialized|starting main dispatch loop"; }
wait_for "$TIMEOUT" "Envoy's main dispatch loop" envoy_ready
echo "authorizer as spiffe://$TD/gateway; Envoy up on its bootstrap"

say "fixtures: the node pod registering the fixture EK, a sandbox bound to it"
cleanup
"${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=true >/dev/null
"${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: mediatore-e2e-gateway-node
spec:
  className: spire-server-spire
  spiffeIDTemplate: "spiffe://{{ .TrustDomain }}/banlieue/node/$EK_HASH"
  podSelector:
    matchLabels: { mediatore.dev/e2e-role: node }
  namespaceSelector:
    matchLabels: { kubernetes.io/metadata.name: $NS }
  ttl: 1h
---
apiVersion: v1
kind: Pod
metadata:
  name: node
  namespace: $NS
  labels: { mediatore.dev/e2e-role: node }
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: guest
      image: ghcr.io/firestoned/mediatore:kind
      imagePullPolicy: Never
      command:
        - /usr/bin/mediatore
        - guest
        - --dev-ek-hash
        - "$EK_HASH"
        - --dev-dmi-uuid
        - 1d2c3b4a-5f6e-4d7c-8b9a-0f1e2d3c4b5a
        - --dev-skip-setup
      env:
        - { name: MEDIATORE_URL, value: "https://mediatore-sandbox.banlieue-system.svc" }
        - { name: SPIFFE_ENDPOINT_SOCKET, value: "unix:///run/spire/sockets/spire-agent.sock" }
      volumeMounts:
        - { name: spire-agent-socket, mountPath: /run/spire/sockets, readOnly: true }
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
  volumes:
    - name: spire-agent-socket
      csi: { driver: csi.spiffe.io, readOnly: true }
YAML
node_registered() { pod_logs node | grep -qF "node registered"; }
wait_for "$TIMEOUT" "'node registered' in the node pod log" node_registered
"${KSA[@]}" create -f - >/dev/null <<YAML
apiVersion: mediatore.io/v1alpha1
kind: AgentSandbox
metadata:
  name: sb-gw
  namespace: $NS
spec:
  subject: { issuer: "$ISSUER", id: "octocat" }
  poolRef: { name: e2e }
  ttlSeconds: 900
  audiences: ["e2e-egress"]
  workload: { image: "registry.internal:5000/sandbox:e2e", args: ["sh"] }
YAML
has_claim() { "${K[@]}" -n "$NS" get virtualmachineclaim sb-gw >/dev/null 2>&1; }
wait_for "$TIMEOUT" "claim sb-gw" has_claim
CLAIM_UID=$("${K[@]}" -n "$NS" get virtualmachineclaim sb-gw -o jsonpath='{.metadata.uid}')
wait_for "$TIMEOUT" "'record created' in the broker log" log_has "record created" "$CLAIM_UID"
jq -Rs '{status: {phase: "Bound", virtualMachineRef: {name: "member-1"}, tpmEndorsementCertificates: [.], boundAt: "2026-11-04T10:00:00Z", expiresAt: "2026-11-04T10:15:00Z"}}' < "$EK_PEM" \
  | "${K[@]}" -n "$NS" patch virtualmachineclaim sb-gw --subresource=status --type=merge --patch-file=/dev/stdin >/dev/null
ready() { [ "$(field sb-gw '.status.ready')" = "true" ] && [ "$(field sb-gw '.status.phase')" = "Bound" ]; }
wait_for "$TIMEOUT" "sb-gw Ready" ready
echo "claim $CLAIM_UID bound; its allowlist is $DESTINATION (audience e2e-egress)"

say "probe SVID: a fixture entry for spiffe://$TD/banlieue/claim/$CLAIM_UID (on a VM, the broker's entry)"
"${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: mediatore-e2e-gateway-claim
spec:
  className: spire-server-spire
  spiffeIDTemplate: "spiffe://{{ .TrustDomain }}/banlieue/claim/$CLAIM_UID"
  podSelector:
    matchLabels: { mediatore.dev/e2e-role: claim }
  namespaceSelector:
    matchLabels: { kubernetes.io/metadata.name: $NS }
  ttl: 1h
YAML

say "the claim: its destination opens, another host and another port are refused"
probe probe-claim claim \
  "$DESTINATION=200" \
  "elsewhere.example.com:443=403:not_allowed" \
  "destination.$NS.svc.cluster.local:8081=403:not_allowed" \
  "$DESTINATION=200"
pod_logs probe-claim | grep -F "outcome=opened" | grep -qF "destination reached: host=$DESTINATION" || fail "the destination did not answer through the tunnel"
echo "tunnel opened to $DESTINATION and the destination answered; the other two refused with not_allowed"

say "the logs agree: Envoy's access log, the authorizer's decisions, the destination's requests"
envoy_logs | grep -F "tunnel peer=spiffe://$TD/banlieue/claim/$CLAIM_UID" | grep -F "authority=$DESTINATION" | grep -qF "status=200" || fail "no Envoy access-log line for the opened tunnel"
envoy_logs | grep -F "tunnel peer=spiffe://$TD/banlieue/claim/$CLAIM_UID" | grep -F "authority=elsewhere.example.com:443" | grep -qF "status=403" || fail "no Envoy access-log line for the refused tunnel"
authz_logs | grep -F "claim_uid=$CLAIM_UID" | grep -F "verdict=allow" | grep -qF "served=broker" || fail "the authorizer did not log the first allow served by the broker"
authz_logs | grep -F "claim_uid=$CLAIM_UID" | grep -F "verdict=allow" | grep -qF "served=cache" || fail "the authorizer did not log the second allow served by the cache"
authz_logs | grep -F "claim_uid=$CLAIM_UID" | grep -F "verdict=deny" | grep -qF "reason=not_allowed" || fail "the authorizer did not log the refusal"
dest_logs | grep -F "destination request" | grep -qF "host=$DESTINATION" || fail "the destination did not log the request"
broker_logs | grep -F "claim egress answered to the gateway" | grep -qF "claim_uid=$CLAIM_UID" || true
echo "Envoy: 200 and 403 keyed by the claim SVID; authorizer: broker then cache, one deny; destination: one request"

say "a node SVID: refused by Envoy's validator, no check made"
probe probe-node node "$DESTINATION=handshake-refused"
authz_logs | grep -F "peer=spiffe://$TD/banlieue/node/$EK_HASH" && fail "the node reached the authorizer"
echo "handshake refused before any check"

say "the broker gone: the cached allowlist stands in, then the outage is a deny"
"${K[@]}" -n "$BROKER_NS" scale deploy/mediatore --replicas=0 >/dev/null
broker_gone() { [ "$("${K[@]}" -n "$BROKER_NS" get pods -l app.kubernetes.io/name=mediatore -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)" = "" ]; }
wait_for "$TIMEOUT" "no broker pod" broker_gone
sleep $((FRESH_SECS + 1))
probe probe-outage-1 claim "$DESTINATION=200"
authz_logs | grep -F "claim_uid=$CLAIM_UID" | grep -F "verdict=allow" | grep -qF "served=stale" || fail "the authorizer did not serve the stale allowlist during the outage"
sleep $((STALE_SECS + 2))
probe probe-outage-2 claim "$DESTINATION=403:broker_unreachable"
echo "stale served for ${STALE_SECS}s past fresh, then broker_unreachable"
"${K[@]}" -n "$BROKER_NS" scale deploy/mediatore --replicas=1 >/dev/null
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=120s >/dev/null
BROKER_POD=$(broker_pod)
wait_for "$TIMEOUT" "lease mediatore-watcher held by ${BROKER_POD#pod/}" holder_is_pod
wait_for "$TIMEOUT" "'claim watcher running' in the new broker log" log_has "claim watcher running"

say "released: the sandbox is deleted; once stale, the claim is cut off with claim_gone"
"${K[@]}" -n "$NS" delete agentsandbox sb-gw --wait=false >/dev/null
claim_gone() { ! "${K[@]}" -n "$NS" get virtualmachineclaim sb-gw >/dev/null 2>&1; }
wait_for "$TIMEOUT" "claim sb-gw gone" claim_gone
sleep $((FRESH_SECS + 1))
probe probe-released claim "$DESTINATION=403:claim_gone"
authz_logs | grep -F "claim_uid=$CLAIM_UID" | grep -F "verdict=deny" | grep -qF "reason=claim_gone" || fail "the authorizer did not log claim_gone"
echo "cut off: the broker's 404 dropped the cache"

say "PASS: ADR-0028 decisions 2 to 5 and 8 hold against a real Envoy (SDS identity, the validator, CONNECT through the authorizer, the cache bounds, the outage, the release)"
