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
# ADR-0044: a sandbox with `poolSelector: {}` is admitted and its claim carries the empty
# selector and no `poolRef`, accepted by banlieue's own CRD rule; a sandbox with neither
# field, or both, is refused by the API server before the reconciler sees it. ADR-0047: a
# sandbox with `selection: { strategy: Spread }` is admitted and its claim carries the
# strategy as written, while one with a strategy banlieue does not have is refused by the
# schema. ADR-0049: a sandbox written as `v1alpha1` is governed by the same subject policy,
# answered with the deprecation warning, read back as `v1beta1`, owns its claim through
# `v1beta1`, and its spec is frozen through either name. ADR-0072: once the policy's
# `issuerPrefixes` lists anything, an unlisted issuer is refused and a list that cannot tell
# its issuers apart admits nothing; `mediatore.io/front-door` is the broker's alone and
# immutable; a sandbox created by hand naming an issuer outside
# `sandboxes.declarative_issuers` is Failed by the reconciler. ADR-0069: a sandbox whose record a
# trap ended (`tripped` patched on the record, as the API writes it) is Failed with
# `Tripped=True`, its claim deleted and never recreated, and `status.tripwires` is held by the
# schema under both names. No banlieue controller runs: the claim's status is patched by hand, as in the
# watcher tier.
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
BROKER_NS=mediatore-system
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

# An AgentSandbox manifest for <name> with subject id <id> and audiences <json array>, and
# optionally the pool line(s) in place of `poolRef: { name: e2e }` (ADR-0044).
manifest() {
  local pool=${4-"poolRef: { name: e2e }"}
  cat <<YAML
apiVersion: mediatore.io/v1beta1
kind: AgentSandbox
metadata:
  name: $1
  namespace: $NS
spec:
  subject: { issuer: "$ISSUER", id: "$2" }
  $pool
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
  # A user whose API-server username carries a per-issuer prefix (ADR-0072).
  - { kind: User, name: "e2e:octocat" }
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
        - /usr/bin/mediatore
        - guest
        - --dev-ek-hash
        - "$EK_HASH"
        - --dev-dmi-uuid
        # The same VM as the mTLS and watcher tiers (same EK, same DMI): the node row now
        # outlives the broker (ADR-0012), and another DMI under this EK would be a clone.
        - 1d2c3b4a-5f6e-4d7c-8b9a-0f1e2d3c4b5a
        - --dev-skip-setup
      env:
        - { name: MEDIATORE_URL, value: "https://mediatore-sandbox.mediatore-system.svc" }
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

say "ADR-0072: the issuer a hand-created sandbox names, and the broker's mark"
# The broker trusts two issuers and declares one for this path, so the rule is in force and
# the broker proved the policy guards its mark before it served.
log_has "self-check passed, ADR-0072" || fail "the broker did not log the front-door self-check"
echo "the broker's log: $(broker_logs | grep -F 'self-check passed, ADR-0072' | tail -1 | sed 's/.*INFO //' | cut -c1-160)"
DEX=https://mediatore-dex.mediatore-system.svc:5556
OTHER=https://other.example.com
as_issuer() { sed "s#issuer: \"$ISSUER\"#issuer: \"$1\"#"; } # <issuer>: the manifest on stdin names it
marked() { sed "/^metadata:\$/a\\  annotations: { mediatore.io/front-door: \"${1:-api}\" }"; } # [value]
subject_param() { # <issuerPrefixes>: the parameter's per-issuer list, as given
  "${K[@]}" -n "$BROKER_NS" patch configmap mediatore-agentsandbox-subject-policy --type=merge \
    -p "$(jq -n --arg v "$1" '{data: {issuerPrefixes: $v}}')" >/dev/null
}
# The API server reads the parameter from a cache: a decision is retried until the edit is
# seen. An object admitted on the way there is deleted before the next try.
until_denied() { # <description> <message fragment> <kubectl args...>; the manifest on stdin
  local what=$1 frag=$2 m out i; shift 2; m=$(cat)
  for ((i = 0; i < TIMEOUT; i++)); do
    if out=$(printf '%s\n' "$m" | "$@" 2>&1); then
      printf '%s\n' "$m" | "${K[@]}" delete -f - --wait=false >/dev/null 2>&1 || true
    elif echo "$out" | grep -qF "$frag"; then
      echo "denied: $what"; return 0
    fi
    sleep 1
  done
  fail "$what: not denied with '$frag' within ${TIMEOUT}s: $out"
}
until_admitted() { # <description> <kubectl args...>; the manifest on stdin
  local what=$1 m out i; shift; m=$(cat)
  for ((i = 0; i < TIMEOUT; i++)); do
    if out=$(printf '%s\n' "$m" | "$@" 2>&1); then echo "admitted: $what"; return 0; fi
    sleep 1
  done
  fail "$what: not admitted within ${TIMEOUT}s: $out"
}
trap 'subject_param ""; cleanup' EXIT

# Decision 1: once issuerPrefixes lists anything, an issuer it does not list is refused,
# with no fallback to usernamePrefix; a listed one is checked under its own prefix.
subject_param "$ISSUER e2e:"
manifest sb-unlisted octocat '[]' | as_issuer "$OTHER" \
  | until_denied "e2e:octocat naming an issuer issuerPrefixes does not list" "is not listed in issuerPrefixes" "${K[@]}" --as=e2e:octocat create -f -
manifest sb-listed octocat '[]' \
  | until_admitted "e2e:octocat naming the listed issuer, under its prefix" "${K[@]}" --as=e2e:octocat create -f -
# Decision 2: a list that cannot tell its issuers apart admits nothing.
subject_param "$ISSUER e2e:
$OTHER e2e:x"
manifest sb-overlap octocat '[]' \
  | until_denied "e2e:octocat under a list with one prefix the start of another" "cannot tell its issuers apart" "${K[@]}" --as=e2e:octocat create -f -
subject_param "$ISSUER e2e:
not-a-pair"
manifest sb-malformed octocat '[]' \
  | until_denied "e2e:octocat under a list with a line that is not a pair" "cannot tell its issuers apart" "${K[@]}" --as=e2e:octocat create -f -
subject_param ""
manifest sb-back "$ME" '[]' | as_issuer "$OTHER" \
  | until_admitted "$ME naming any issuer once the list is empty again (the single-issuer cluster of ADR-0008)" "${K[@]}" create -f -
"${K[@]}" -n "$NS" delete agentsandbox sb-listed sb-back --ignore-not-found --wait=false >/dev/null

# Decision 3: the mark is the broker's own, on create, and nobody's to change.
mark_denied() { # <description> <kubectl args...>; the manifest on stdin
  local what=$1 out; shift
  if out=$("$@" 2>&1); then fail "$what: admitted, expected a denial"; fi
  echo "$out" | grep -qF "mediatore.io/front-door is the broker's own" || fail "$what: refused, but not for the mark: $out"
  echo "denied: $what"
}
manifest sb-forged stranger '[]' | marked | mark_denied "an impersonated stranger setting the mark on its own sandbox" "${K[@]}" --as=stranger create -f -
manifest sb-forged octocat '[]' | marked | mark_denied "the listed broker (e2e-broker) setting the mark" "${K[@]}" --as=e2e-broker create -f -
manifest sb-forged octocat '[]' | marked selfcheck | mark_denied "the broker ServiceAccount setting the mark to another value" "${KSA[@]}" create -f -
manifest sb-marked octocat '[]' | marked | admitted "the broker ServiceAccount setting the mark to api" "${KSA[@]}" create -f -
manifest sb-unmarked "$ME" '[]' | admitted "$ME naming itself, unmarked" "${K[@]}" create -f -
immutable() { # <description> <kubectl args...>
  local what=$1 out; shift
  if out=$("$@" 2>&1); then fail "$what: admitted, expected a denial"; fi
  echo "$out" | grep -qF "mediatore.io/front-door is immutable" || fail "$what: refused, but not for the mark: $out"
  echo "denied: $what"
}
immutable "changing the mark on sb-marked" "${K[@]}" -n "$NS" annotate agentsandbox sb-marked --overwrite mediatore.io/front-door=x
immutable "removing the mark from sb-marked" "${K[@]}" -n "$NS" annotate agentsandbox sb-marked mediatore.io/front-door-
immutable "adding the mark to sb-unmarked" "${KSA[@]}" -n "$NS" annotate agentsandbox sb-unmarked mediatore.io/front-door=api
"${K[@]}" -n "$NS" delete agentsandbox sb-marked sb-unmarked --wait=false >/dev/null

# Decision 4: the listed broker may name any id, and is still held to the declared issuers.
manifest sb-dex octocat '[]' | as_issuer "$DEX" \
  | admitted "the listed broker naming octocat at the second configured issuer" "${K[@]}" --as=e2e-broker create -f -
failed_dex() { [ "$(field sb-dex '.status.phase')" = "Failed" ]; }
wait_for "$TIMEOUT" "sb-dex Failed" failed_dex
field sb-dex '.status.reason' | grep -qF "issuer $DEX may not be named by a sandbox created through the Kubernetes API: it is not in sandboxes.declarative_issuers (ADR-0072)" \
  || fail "unexpected reason: $(field sb-dex '.status.reason')"
"${K[@]}" -n "$NS" get virtualmachineclaim sb-dex >/dev/null 2>&1 && fail "a claim was created for sb-dex"
"${K[@]}" -n "$NS" delete agentsandbox sb-dex --wait=false >/dev/null
echo "sb-dex admitted by the policy and Failed by the reconciler ($(field sb-dex '.status.reason' | cut -c1-60)...), no claim"

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

say "restart: the broker comes back on the store, the Kubernetes API; the record, the node and the entry survive (ADR-0034)"
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

say "pool (ADR-0044): a sandbox selects its pool, or names it, exactly one; the claim carries the selector as written"
manifest sb-any octocat '[]' 'poolSelector: {}' | admitted "the broker ServiceAccount selecting any pool" "${KSA[@]}" create -f -
has_any_claim() { "${K[@]}" -n "$NS" get virtualmachineclaim sb-any >/dev/null 2>&1; }
wait_for "$TIMEOUT" "claim sb-any" has_any_claim
ANY=$("${K[@]}" -n "$NS" get virtualmachineclaim sb-any -o json)
echo "$ANY" | jq -e '.spec.poolSelector == {} and (.spec | has("poolRef") | not)' >/dev/null || fail "the claim does not carry the empty selector alone: $(echo "$ANY" | jq -c .spec)"
[ -z "$(field sb-any '.status.poolRef.name')" ] || fail "a Pending sandbox shows a pool it was not bound from"
"${K[@]}" -n "$NS" get agentsandbox sb-any -o custom-columns='POOL:.status.poolRef.name' --no-headers | grep -qE '^<none>$|^$' || fail "the Pool column reads something while Pending"
rejected() { # <description> <manifest on stdin>: the API server refuses it with the CEL rule's message
  local what=$1 out
  if out=$("${KSA[@]}" create -f - 2>&1); then fail "$what: admitted, expected the CEL refusal"; fi
  echo "$out" | grep -qF 'exactly one of poolRef or poolSelector' || fail "$what: refused, but not by the CEL rule: $out"
  echo "refused: $what"
}
manifest sb-none octocat '[]' '# no pool' | rejected "a sandbox with neither poolRef nor poolSelector"
manifest sb-both octocat '[]' 'poolRef: { name: e2e }
  poolSelector: { matchLabels: { tier: e2e } }' | rejected "a sandbox with both poolRef and poolSelector"
# The same rule guards the claim: a selector claim written by hand with both is refused by
# banlieue's CRD, so the reconciler could never produce one the API server would take.
if out=$("${K[@]}" -n "$NS" create -f - 2>&1 <<YAML
apiVersion: banlieue.io/v1alpha1
kind: VirtualMachineClaim
metadata: { name: claim-both, namespace: $NS }
spec:
  subject: { issuer: "$ISSUER", id: "octocat" }
  ttlSeconds: 600
YAML
); then fail "a claim with no pool was admitted by banlieue's CRD"; fi
echo "$out" | grep -qF 'exactly one of poolRef or poolSelector' || fail "the claim was refused, but not by banlieue's CEL rule: $out"
echo "refused: a claim with neither, by banlieue's own rule"
echo "$ANY" | jq -e '.spec | has("selection") | not' >/dev/null || fail "a sandbox without a strategy produced a claim with one: $(echo "$ANY" | jq -c .spec)"
"${K[@]}" -n "$NS" delete agentsandbox sb-any --wait=false >/dev/null
any_gone() { [ -z "$(sandbox sb-any)" ]; }
wait_for "$TIMEOUT" "agentsandbox sb-any gone" any_gone
echo "sb-any: claim with poolSelector {} and no poolRef, Pool column blank while Pending; neither and both refused at admission; deleted"

say "strategy (ADR-0047): a sandbox says how banlieue picks the member; the claim carries it as written; a strategy banlieue does not have is refused by the schema"
manifest sb-spread octocat '[]' 'poolSelector: {}
  selection: { strategy: Spread }' | admitted "the broker ServiceAccount asking for Spread" "${KSA[@]}" create -f -
has_spread_claim() { "${K[@]}" -n "$NS" get virtualmachineclaim sb-spread >/dev/null 2>&1; }
wait_for "$TIMEOUT" "claim sb-spread" has_spread_claim
SPREAD=$("${K[@]}" -n "$NS" get virtualmachineclaim sb-spread -o json)
echo "$SPREAD" | jq -e '.spec.selection == {"strategy": "Spread"}' >/dev/null || fail "the claim does not carry the strategy as written: $(echo "$SPREAD" | jq -c .spec)"
if out=$(manifest sb-pack octocat '[]' 'poolSelector: {}
  selection: { strategy: Pack }' | "${KSA[@]}" create -f - 2>&1); then fail "a sandbox with a strategy banlieue does not have was admitted"; fi
echo "$out" | grep -qF 'Unsupported value' || fail "refused, but not by the schema's enum: $out"
echo "refused: a sandbox asking for Pack, by the schema"
"${K[@]}" -n "$NS" delete agentsandbox sb-spread --wait=false >/dev/null
spread_gone() { [ -z "$(sandbox sb-spread)" ]; }
wait_for "$TIMEOUT" "agentsandbox sb-spread gone" spread_gone
echo "sb-spread: claim with selection.strategy Spread as written; Pack refused at admission; deleted"

say "v1alpha1 (ADR-0049): the deprecated name is served, governed by the same policy, and is the same object as v1beta1"
alpha() { manifest "$@" | sed 's#^apiVersion: mediatore.io/v1beta1$#apiVersion: mediatore.io/v1alpha1#'; }
alpha sb-alpha-stranger octocat '[]' | grep -qx 'apiVersion: mediatore.io/v1alpha1' || fail "the v1alpha1 manifest does not name v1alpha1"
alpha sb-alpha-stranger octocat '[]' | denied "an impersonated stranger naming octocat as v1alpha1" "${K[@]}" --as=stranger create -f -
out=$(alpha sb-alpha octocat '[]' | "${KSA[@]}" create -f - 2>&1) || fail "the broker ServiceAccount's v1alpha1 sandbox was refused: $out"
echo "$out" | grep -qF 'deprecated; use mediatore.io/v1beta1' || fail "no deprecation warning naming v1beta1: $out"
echo "admitted, with the deprecation warning: the broker ServiceAccount naming octocat as v1alpha1"
[ "$("${K[@]}" -n "$NS" get agentsandboxes.v1beta1.mediatore.io sb-alpha -o jsonpath='{.apiVersion}')" = mediatore.io/v1beta1 ] \
  || fail "sb-alpha is not readable as v1beta1"
has_alpha_claim() { "${K[@]}" -n "$NS" get virtualmachineclaim sb-alpha >/dev/null 2>&1; }
wait_for "$TIMEOUT" "claim sb-alpha" has_alpha_claim
"${K[@]}" -n "$NS" get virtualmachineclaim sb-alpha -o json \
  | jq -e '.metadata.ownerReferences[0] | .kind == "AgentSandbox" and .apiVersion == "mediatore.io/v1beta1"' >/dev/null \
  || fail "the claim of a v1alpha1 sandbox is not owned through v1beta1"
if out=$("${K[@]}" -n "$NS" patch agentsandboxes.v1alpha1.mediatore.io sb-alpha --type=merge -p '{"spec":{"ttlSeconds":1200}}' 2>&1); then
  fail "spec.ttlSeconds changed through v1alpha1; the spec must be immutable"
fi
echo "$out" | grep -q 'spec is immutable' || fail "the v1alpha1 patch was refused, but not by the policy: $out"
"${K[@]}" -n "$NS" delete agentsandbox sb-alpha --wait=false >/dev/null
alpha_gone() { [ -z "$(sandbox sb-alpha)" ]; }
wait_for "$TIMEOUT" "agentsandbox sb-alpha gone" alpha_gone
echo "sb-alpha: created as v1alpha1, read as v1beta1, its claim owned through v1beta1, the spec frozen through either name; deleted"

say "trip (ADR-0069 decision 9): a record a trap ended fails its sandbox with Tripped=True; the sandbox stays and gets no second claim; status.tripwires is served by both versions"
manifest sb-trip octocat '[]' | admitted "the broker ServiceAccount naming octocat for the trip" "${KSA[@]}" create -f -
has_trip_claim() { "${K[@]}" -n "$NS" get virtualmachineclaim sb-trip >/dev/null 2>&1; }
wait_for "$TIMEOUT" "claim sb-trip" has_trip_claim
TRIP_UID=$("${K[@]}" -n "$NS" get virtualmachineclaim sb-trip -o jsonpath='{.metadata.uid}')
trip_recorded() { [ "$(field sb-trip '.status.record.claimUid')" = "$TRIP_UID" ]; }
wait_for "$TIMEOUT" "a record on sb-trip" trip_recorded
# What the API writes on a trip (`trip::end_claim`): `tripped` on the record, as `Tripped`
# serialises, under the broker ServiceAccount's name (the status admission policy admits no
# other; its RBAC has patch on the subresource but not the get kubectl does first, so the
# group is the admin's).
KBROKER=("${K[@]}" --as=system:serviceaccount:"$BROKER_NS":mediatore --as-group=system:masters --as-group=system:authenticated)
# The fold's entry goes through v1alpha1 and is read back through v1beta1, so the API server
# holds the schema the same under both names and prunes nothing of it.
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
"${KBROKER[@]}" -n "$NS" patch agentsandboxes.v1alpha1.mediatore.io sb-trip --subresource=status --type=merge \
  -p "{\"status\":{\"tripwires\":{\"updatedAt\":\"$NOW\",\"entries\":[{\"effect\":\"tripped\",\"kind\":\"credential\",\"trap\":\"aws\",\"target\":{\"host\":\"git.example\"},\"source\":\"workload\",\"count\":1,\"firstAt\":\"$NOW\",\"lastAt\":\"$NOW\"}]}}}" >/dev/null \
  || fail "status.tripwires refused through v1alpha1"
"${K[@]}" -n "$NS" get agentsandboxes.v1beta1.mediatore.io sb-trip -o json \
  | jq -e '.status.tripwires.entries[0] | .effect == "tripped" and .kind == "credential" and .trap == "aws" and .target.host == "git.example" and .count == 1' >/dev/null \
  || fail "status.tripwires written as v1alpha1 is not read back whole as v1beta1"
if out=$("${KBROKER[@]}" -n "$NS" patch agentsandbox sb-trip --subresource=status --type=merge \
  -p '{"status":{"tripwires":{"entries":[{"effect":"exploded","kind":"credential","source":"workload","count":1,"firstAt":"2026-10-14T10:00:00Z","lastAt":"2026-10-14T10:00:00Z"}]}}}' 2>&1); then
  fail "a status.tripwires entry with an effect the schema does not have was admitted"
fi
echo "$out" | grep -qF 'Unsupported value' || fail "the bad effect was refused, but not by the schema's enum: $out"
"${KBROKER[@]}" -n "$NS" patch agentsandbox sb-trip --subresource=status --type=merge \
  -p "{\"status\":{\"record\":{\"tripped\":{\"id\":\"$(cat /proc/sys/kernel/random/uuid)\",\"at\":\"$NOW\",\"recorded_at\":\"$NOW\",\"kind\":\"credential\",\"trap\":\"aws\",\"target\":{\"host\":\"git.example\"},\"source\":\"workload\"}}}}" >/dev/null
TRIPPED_SB=""
tripped_failed() {
  TRIPPED_SB=$(sandbox sb-trip)
  echo "$TRIPPED_SB" | jq -e '.status.phase == "Failed" and .status.reason == "tripped: credential" and .status.ready != true and ([.status.conditions[]? | select(.type == "Tripped" and .status == "True" and .reason == "credential")] | length == 1)' >/dev/null
}
wait_for "$TIMEOUT" "sb-trip Failed with Tripped=True" tripped_failed
echo "$TRIPPED_SB" | jq -e '.status.record.revokedAt != null and .status.record.tripped.kind == "credential" and .status.tripwires.entries[0].effect == "tripped"' >/dev/null \
  || fail "the tripped sandbox's record is not released with tripped kept, or its status.tripwires went"
wait_for "$TIMEOUT" "'sandbox tripped' in the broker log" log_has "sandbox tripped" "$TRIP_UID"
# The reconciler never deletes the sandbox; the kind config's zero retention (ADR-0034
# decision 4) sweeps its released record, and the object with it, at the next resync. Until
# then, and through it, no second claim.
trip_swept() { has_trip_claim && fail "a tripped sandbox got a second claim"; [ -z "$(sandbox sb-trip)" ]; }
wait_for "$TIMEOUT" "sb-trip swept with its released record, never claiming again" trip_swept
log_has "claim swept after its retention" "$TRIP_UID" || fail "sb-trip went without the sweep's audit line"
echo "sb-trip: tripped on its record, Failed with Tripped=True, claim deleted, record released, never a second claim, swept at retention; status.tripwires served by both versions"

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

say "retention: the released sandbox, held by its finalizer, is swept at the next resync with the audit line (ADR-0034 decision 4)"
# The kind config keeps ended claims for 0 s and resyncs every 15 s.
archived() { broker_logs | grep -F "resync" | grep -qE 'archived=[1-9]'; }
wait_for "$TIMEOUT" "a resync archiving at least one row" archived
echo "archived at resync"

say "PASS: ADR-0008, ADR-0034, ADR-0044, ADR-0047, ADR-0049, ADR-0069 and ADR-0072 hold against a real cluster (subject policy, the issuer list with no fallback and the broker's mark, owned claim and record on the resource, bind to Ready, a restart on the Kubernetes store, fail-closed audience, the pool selector and its exactly-one rule, the selection strategy carried as written, v1alpha1 served as the same object, a tripped sandbox failed and never claiming again, finalizer, the retention sweep)"
