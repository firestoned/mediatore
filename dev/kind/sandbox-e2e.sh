#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# ADR-0008 against a real cluster (`make kind-e2e-sandbox`): the AgentSandbox CRD from
# deploy/base/crds, its subject admission policy, and the reconciler in the broker from
# deploy/base. An AgentSandbox created as the broker ServiceAccount becomes an owned
# VirtualMachineClaim and a store record; when the claim is patched Bound with the
# fixture endorsement certificate of a node that registered over mTLS, the claim entry
# is declared and the sandbox turns Ready; the guest in the node pod fetches the subject;
# deleting the sandbox retracts the entry, deletes the claim and lets the object go. A
# sandbox naming an audience outside the broker's configuration fails without a claim.
# No banlieue controller runs: the claim's status is patched by hand, as in the watcher
# tier.
#
#   sandbox-e2e.sh <admin kubeconfig> <broker SA kubeconfig> <trust domain> <ek pem> <ek hash file>
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
NS=mediatore-e2e-sandbox
ISSUER=https://issuer.example.com
TIMEOUT=${MEDIATORE_KIND_TIMEOUT:-120}
ENTRY_SELECTOR=app.kubernetes.io/managed-by=mediatore

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; dump; exit 1; }
plain() { sed "s/$(printf '\033')\[[0-9;]*m//g"; }

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

broker_pod()  { "${K[@]}" -n "$BROKER_NS" get pods -l app.kubernetes.io/name=mediatore -o json 2>/dev/null | jq -r '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")] | sort_by(.metadata.creationTimestamp) | last | select(. != null) | "pod/" + .metadata.name'; }
BROKER_POD=""
broker_logs() { [ -n "$BROKER_POD" ] && "${K[@]}" -n "$BROKER_NS" logs "$BROKER_POD" 2>/dev/null | plain || true; }
node_logs()   { "${K[@]}" -n "$NS" logs pod/node 2>/dev/null | plain || true; }
entries()     { "${K[@]}" get clusterstaticentries -l "$ENTRY_SELECTOR" -o jsonpath='{range .items[*]}{.metadata.name} {.spec.spiffeID}{"\n"}{end}' 2>/dev/null || true; }
sandbox()     { "${K[@]}" -n "$NS" get agentsandbox "$1" -o json 2>/dev/null || true; }
field()       { sandbox "$1" | jq -r "$2 // empty"; }

dump() {
  printf '\n--- broker (last 60 lines)\n'; broker_logs | tail -60
  printf '\n--- node pod (last 20 lines)\n'; node_logs | tail -20
  printf '\n--- entries\n'; entries
  printf '\n--- %s\n' "$NS"; "${K[@]}" -n "$NS" get agentsandboxes,virtualmachineclaims,pods 2>/dev/null || true
}

cleanup() {
  "${K[@]}" delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete clusterspiffeid mediatore-e2e-sandbox-node --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() { # <seconds> <description> <command...>
  local secs=$1 what=$2 i; shift 2
  for ((i = 0; i < secs; i++)); do "$@" && return 0; sleep 1; done
  fail "$what not seen within ${secs}s"
}
log_has() { broker_logs | grep -F "$1" | grep -qF "${2:-}"; }

# An AgentSandbox manifest for <name> with subject id <id> and audiences <json array>.
manifest() {
  cat <<YAML
apiVersion: mediatore.io/v1alpha1
kind: AgentSandbox
metadata:
  name: $1
  namespace: $NS
spec:
  subject: { issuer: "$ISSUER", id: "$2" }
  poolRef: { name: e2e }
  ttlSeconds: 600
  audiences: $3
  workload: { image: "registry.internal:5000/sandbox:e2e", args: ["sh"] }
YAML
}

say "broker: the watcher Lease is held by the running pod"
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=60s >/dev/null
BROKER_POD=$(broker_pod)
[ -n "$BROKER_POD" ] || fail "no Running broker pod in $BROKER_NS"
holder_is_pod() { [ "$("${K[@]}" -n "$BROKER_NS" get lease mediatore-watcher -o jsonpath='{.spec.holderIdentity}' 2>/dev/null)" = "${BROKER_POD#pod/}" ]; }
wait_for "$TIMEOUT" "lease mediatore-watcher held by ${BROKER_POD#pod/}" holder_is_pod
wait_for "$TIMEOUT" "'claim watcher running' in the broker log" log_has "claim watcher running"
echo "held by ${BROKER_POD#pod/}; controllers running"

say "fixtures: a namespace, and a node pod registering the fixture EK over mTLS"
"${K[@]}" delete namespace "$NS" --ignore-not-found --wait=true >/dev/null
"${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=true >/dev/null
"${K[@]}" create namespace "$NS" >/dev/null
# The impersonated requesters get RBAC to create sandboxes here, so that admission, not
# authorization, is what decides their requests.
"${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: e2e-requesters
  namespace: $NS
rules:
  - apiGroups: ["mediatore.io"]
    resources: ["agentsandboxes"]
    verbs: ["create", "get", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: e2e-requesters
  namespace: $NS
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: e2e-requesters
subjects:
  - { kind: User, name: stranger }
  - { kind: User, name: e2e-broker }
---
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: mediatore-e2e-sandbox-node
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
        - /usr/local/bin/mediatore
        - guest
        - --dev-ek-hash
        - "$EK_HASH"
        - --dev-dmi-uuid
        # The same VM as the mTLS and watcher tiers (same EK, same DMI): the node row now
        # outlives the broker (ADR-0012), and another DMI under this EK would be a clone.
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
node_registered() { node_logs | grep -qF "node registered"; }
wait_for "$TIMEOUT" "'node registered' in the node pod log" node_registered
echo "node $EK_HASH registered over its agent-issued SVID"

say "admission: spec.subject is pinned to the caller"
ME=$("${K[@]}" auth whoami -o jsonpath='{.status.userInfo.username}')
denied() { # <description> <kubectl args...>: the create must be refused with the policy's message
  local what=$1; shift
  local out
  if out=$("$@" 2>&1); then fail "$what: admitted, expected a denial"; fi
  echo "$out" | grep -q 'spec.subject.id is' || fail "$what: refused, but not by the subject policy: $out"
  echo "denied: $what"
}
admitted() { # <description> <kubectl args...>
  local what=$1; shift
  "$@" >/dev/null || fail "$what: refused, expected admission"
  echo "admitted: $what"
}
manifest sb-admin octocat '[]' | denied "$ME naming octocat" "${K[@]}" create -f -
manifest sb-stranger octocat '[]' | denied "an impersonated stranger naming octocat" "${K[@]}" --as=stranger create -f -
manifest sb-self "$ME" '[]' | admitted "$ME naming itself" "${K[@]}" create -f -
manifest sb-broker octocat '[]' | admitted "a listed broker (e2e-broker) naming octocat" "${K[@]}" --as=e2e-broker create -f -
manifest sb-e2e octocat '["e2e"]' | admitted "the broker ServiceAccount naming octocat" "${KSA[@]}" create -f -
if out=$("${K[@]}" -n "$NS" patch agentsandbox sb-e2e --type=merge -p '{"spec":{"ttlSeconds":1200}}' 2>&1); then
  fail "spec.ttlSeconds changed on an existing sandbox; the spec must be immutable"
fi
echo "$out" | grep -q 'spec is immutable' || fail "the patch was refused, but not by the policy: $out"
echo "denied: changing the spec afterwards"
"${K[@]}" -n "$NS" delete agentsandbox sb-self sb-broker --wait=false >/dev/null

say "reconcile: sb-e2e gets a finalizer, an owned claim and a record"
has_claim() { "${K[@]}" -n "$NS" get virtualmachineclaim sb-e2e >/dev/null 2>&1; }
wait_for "$TIMEOUT" "claim sb-e2e" has_claim
CLAIM=$("${K[@]}" -n "$NS" get virtualmachineclaim sb-e2e -o json)
SB_UID=$(field sb-e2e '.metadata.uid')
echo "$CLAIM" | jq -e --arg uid "$SB_UID" '.metadata.ownerReferences[] | select(.kind == "AgentSandbox" and .uid == $uid and .controller == true and .blockOwnerDeletion == true)' >/dev/null || fail "the claim is not owned by sb-e2e"
echo "$CLAIM" | jq -e '.metadata.labels["app.kubernetes.io/managed-by"] == "mediatore"' >/dev/null || fail "the claim lacks the managed-by label"
echo "$CLAIM" | jq -e --arg iss "$ISSUER" '.spec.subject == {issuer: $iss, id: "octocat"} and .spec.poolRef.name == "e2e" and .spec.ttlSeconds == 600' >/dev/null || fail "the claim's spec is not the sandbox's"
CLAIM_UID=$(echo "$CLAIM" | jq -r '.metadata.uid')
status_is() { [ "$(field sb-e2e '.status.phase')" = "$1" ] && [ "$(field sb-e2e '.status.claimUid')" = "$CLAIM_UID" ]; }
wait_for "$TIMEOUT" "sb-e2e status Pending with claimUid $CLAIM_UID" status_is Pending
sandbox sb-e2e | jq -e '.metadata.finalizers | index("mediatore.io/sandbox")' >/dev/null || fail "no mediatore.io/sandbox finalizer"
wait_for "$TIMEOUT" "'record created' in the broker log" log_has "record created" "$CLAIM_UID"
echo "claim $CLAIM_UID owned by sb-e2e ($SB_UID); record created; status Pending"

say "bind: the claim goes Bound with the node's certificate; the entry is declared; the sandbox turns Ready"
jq -Rs '{status: {phase: "Bound", virtualMachineRef: {name: "member-1"}, tpmEndorsementCertificates: [.], boundAt: "2026-10-14T10:00:00Z", expiresAt: "2026-10-14T10:10:00Z"}}' < "$EK_PEM" \
  | "${K[@]}" -n "$NS" patch virtualmachineclaim sb-e2e --subresource=status --type=merge --patch-file=/dev/stdin >/dev/null
claim_entry_declared() { entries | grep -qF "mediatore-claim-$CLAIM_UID spiffe://$TD/banlieue/claim/$CLAIM_UID"; }
wait_for "$TIMEOUT" "claim entry for $CLAIM_UID" claim_entry_declared
ready() { [ "$(field sb-e2e '.status.ready')" = "true" ] && [ "$(field sb-e2e '.status.entrySet')" = "true" ] && [ "$(field sb-e2e '.status.phase')" = "Bound" ]; }
wait_for "$TIMEOUT" "sb-e2e Ready" ready
[ "$(field sb-e2e '.status.virtualMachineRef.name')" = "member-1" ] || fail "virtualMachineRef not mirrored"
[ -n "$(field sb-e2e '.status.expiresAt')" ] || fail "expiresAt not mirrored"
subject_fetched() { node_logs | grep -F "subject fetched" | grep -qF "$CLAIM_UID"; }
wait_for "$TIMEOUT" "'subject fetched' with claim $CLAIM_UID in the node pod log" subject_fetched
node_logs | grep -F "subject fetched" | grep -qF "subject=octocat" || fail "the guest did not get octocat as the subject"
echo "entry declared through the admission policy; sandbox Bound, entry set, Ready; the guest fetched octocat's claim $CLAIM_UID"

say "restart: the broker comes back on the store; the record, the node and the entry survive (ADR-0012)"
"${K[@]}" -n "$BROKER_NS" rollout restart deploy/mediatore >/dev/null
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=120s >/dev/null
BROKER_POD=$(broker_pod)
[ -n "$BROKER_POD" ] || fail "no Running broker pod after the restart"
wait_for "$TIMEOUT" "lease mediatore-watcher held by ${BROKER_POD#pod/}" holder_is_pod
wait_for "$TIMEOUT" "'claim watcher running' in the new broker log" log_has "claim watcher running"
resynced() { broker_logs | grep -F "resync" | grep -q "archived="; }
wait_for "$TIMEOUT" "a resync in the new broker log" resynced
ready || fail "sb-e2e is no longer Ready after the restart"
log_has "record created" "$CLAIM_UID" && fail "the record was created again: the store did not keep it"
log_has "claim bound: entry set" && fail "the claim was bound again: the store did not keep the entry id"
n=$(entries | grep -c "mediatore-claim-$CLAIM_UID " || true)
[ "$n" -eq 1 ] || fail "expected one claim entry after the restart, found $n"
echo "still Ready on ${BROKER_POD#pod/}: record, entry id and node found in the store, nothing redone"

say "refused: a sandbox naming an audience the broker does not serve creates nothing"
manifest sb-bad octocat '["nope"]' | "${KSA[@]}" create -f - >/dev/null
failed_bad() { [ "$(field sb-bad '.status.phase')" = "Failed" ]; }
wait_for "$TIMEOUT" "sb-bad Failed" failed_bad
field sb-bad '.status.reason' | grep -qF "audience nope is not configured" || fail "unexpected reason: $(field sb-bad '.status.reason')"
"${K[@]}" -n "$NS" get virtualmachineclaim sb-bad >/dev/null 2>&1 && fail "a claim was created for a refused sandbox"
echo "sb-bad Failed ($(field sb-bad '.status.reason')), no claim"

say "delete: the finalizer retracts the entry, deletes the claim, then lets the sandbox go"
"${K[@]}" -n "$NS" delete agentsandbox sb-e2e --wait=false >/dev/null
claim_gone() { ! "${K[@]}" -n "$NS" get virtualmachineclaim sb-e2e >/dev/null 2>&1; }
wait_for "$TIMEOUT" "claim sb-e2e gone" claim_gone
entry_gone() { ! entries | grep -qF "mediatore-claim-$CLAIM_UID"; }
wait_for "$TIMEOUT" "claim entry for $CLAIM_UID gone" entry_gone
sandbox_gone() { [ -z "$(sandbox sb-e2e)" ]; }
wait_for "$TIMEOUT" "agentsandbox sb-e2e gone" sandbox_gone
wait_for "$TIMEOUT" "'sandbox released' in the broker log" log_has "sandbox released" "sb-e2e"
n=$(entries | grep -c '/banlieue/claim/' || true)
[ "$n" -eq 0 ] || fail "claim entries left behind: $n"
echo "entry retracted, claim deleted, sandbox gone"

say "audit: the released record is swept into the audit table at the next resync (ADR-0012)"
# The kind config keeps ended rows for 0 s and resyncs every 15 s.
archived() { broker_logs | grep -F "resync" | grep -qE 'archived=[1-9]'; }
wait_for "$TIMEOUT" "a resync archiving at least one row" archived
echo "archived at resync"

say "PASS: ADR-0008 holds against a real cluster (subject policy, owned claim and record, bind to Ready, a restart on the store, fail-closed audience, finalizer, the audit sweep)"
