#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# ADR-0013 against a real Dex (`make kind-e2e-dex`): the Dex `make kind-dex` runs over TLS
# with a glauth directory behind it, the broker from deploy/base verifying it against the
# CA that target minted. From a pod inside the cluster the real CLI logs in (PKCE, the
# loopback redirect, the testkit's dex-driver playing the browser) and requests a sandbox
# with the session delegated; the claim is bound to the node that registered over mTLS,
# and a workload pod with the claim SVID trades it for an STS token, which refreshes the
# session at Dex first (Dex's refresh token record shows the use). Then the two ways a
# session ends upstream: the user is taken out of the gated group in the directory, and
# the refresh token is deleted at Dex; each one makes the next issue a 403 session_revoked
# and releases the claim at once. No banlieue controller runs: the claim's status is
# patched by hand, as in the sandbox tier.
#
#   dex-e2e.sh <admin kubeconfig> <trust domain> <ek pem> <ek hash file>
set -euo pipefail
cd "$(dirname "$0")/../.."

KUBECONFIG_PATH=${1:?kubeconfig}
TD=${2:?trust domain}
EK_PEM=${3:?ek pem}
EK_HASH=$(tr -d '\n' < "${4:?ek hash file}")
K=(kubectl --kubeconfig "$KUBECONFIG_PATH")
BROKER_NS=banlieue-system
# The broker's sandboxes.namespace: where the user API creates the resource.
NS=mediatore-e2e-sandbox
ISSUER=https://mediatore-dex.banlieue-system.svc:5556
USER_API=http://mediatore.banlieue-system.svc:8080
SANDBOX_API=https://mediatore-sandbox.banlieue-system.svc
AUDIENCE=e2e-sts
LOGIN=octocat
PASSWORD=octocat-e2e
GLAUTH_CFG=dev/kind/dex/glauth.cfg
TIMEOUT=${MEDIATORE_KIND_TIMEOUT:-120}
ENTRY_SELECTOR=app.kubernetes.io/managed-by=mediatore

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
# On stderr: a failure inside a command substitution must still reach the log.
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; dump >&2; exit 1; }
plain() { sed "s/$(printf '\033')\[[0-9;]*m//g"; }

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

broker_pod()  { "${K[@]}" -n "$BROKER_NS" get pods -l app.kubernetes.io/name=mediatore -o json 2>/dev/null | jq -r '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")] | sort_by(.metadata.creationTimestamp) | last | select(. != null) | "pod/" + .metadata.name'; }
BROKER_POD=""
broker_logs() { [ -n "$BROKER_POD" ] && "${K[@]}" -n "$BROKER_NS" logs "$BROKER_POD" 2>/dev/null | plain || true; }
pod_logs()    { "${K[@]}" -n "$NS" logs "pod/$1" --all-containers 2>/dev/null | plain || true; }
pod_phase()   { "${K[@]}" -n "$NS" get pod "$1" -o jsonpath='{.status.phase}' 2>/dev/null || true; }
entries()     { "${K[@]}" get clusterstaticentries -l "$ENTRY_SELECTOR" -o jsonpath='{range .items[*]}{.metadata.name} {.spec.spiffeID}{"\n"}{end}' 2>/dev/null || true; }
sandbox()     { "${K[@]}" -n "$NS" get agentsandbox "$1" -o json 2>/dev/null || true; }
field()       { sandbox "$1" | jq -r "$2 // empty"; }
dex_tokens()  { "${K[@]}" -n "$BROKER_NS" get refreshtokens.dex.coreos.com -o json 2>/dev/null | jq -c '[.items[] | {id: .metadata.name, lastUsed: .LastUsed, generation: .metadata.generation}]' || echo '[]'; }

dump() {
  printf '\n--- broker (last 60 lines)\n'; broker_logs | tail -60
  printf '\n--- dex (last 30 lines)\n'; "${K[@]}" -n "$BROKER_NS" logs deploy/mediatore-dex --tail=30 2>/dev/null | plain || true
  printf '\n--- dex refresh tokens\n'; dex_tokens
  printf '\n--- %s\n' "$NS"; "${K[@]}" -n "$NS" get agentsandboxes,virtualmachineclaims,pods 2>/dev/null || true
  for p in cli-1 cli-2 token-1 token-2 token-3 token-4 token-5; do
    [ -n "$(pod_phase "$p")" ] || continue
    printf '\n--- %s (last 20 lines)\n' "$p"; pod_logs "$p" | tail -20
  done
}

glauth_config() { # <otherGroups value>: the directory with octocat in that group set
  sed "s/otherGroups = \[5502\]/otherGroups = [$1]/" "$GLAUTH_CFG"
}
# glauth's Service has exactly one endpoint, ready and not terminating: the rollout is
# over and the old pod is out of the endpoint list, so Dex's next LDAP dial is not
# routed to a pod that is gone.
glauth_settled() {
  "${K[@]}" -n "$BROKER_NS" get endpointslices -l kubernetes.io/service-name=mediatore-glauth -o json 2>/dev/null \
    | jq -e '[.items[].endpoints[]?] | length == 1 and all(.conditions.ready == true and (.conditions.terminating // false) == false)' >/dev/null
}
set_directory() { # <otherGroups value>
  glauth_config "$1" | "${K[@]}" -n "$BROKER_NS" create configmap mediatore-glauth-config --from-file=glauth.cfg=/dev/stdin --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
  "${K[@]}" -n "$BROKER_NS" rollout restart deploy/mediatore-glauth >/dev/null
  "${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore-glauth --timeout=120s >/dev/null
  wait_for "$TIMEOUT" "glauth's endpoint settled after the restart" glauth_settled
}

cleanup() {
  set_directory 5502 || true
  "${K[@]}" delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete clusterspiffeid mediatore-e2e-dex-node mediatore-e2e-dex-claim --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() { # <seconds> <description> <command...>
  local secs=$1 what=$2 i; shift 2
  for ((i = 0; i < secs; i++)); do "$@" && return 0; sleep 1; done
  fail "$what not seen within ${secs}s"
}
log_has() { broker_logs | grep -F "$1" | grep -qF "${2:-}"; }
pod_done() { [ "$(pod_phase "$1")" = "Succeeded" ] || [ "$(pod_phase "$1")" = "Failed" ]; }

# The user's side, in a pod: the real CLI driven by dex-driver. Prints the created
# sandbox's JSON.
claim_via_cli() { # <pod name>
  "${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $1
  namespace: $NS
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: cli
      image: localhost/mediatore-e2e:kind
      imagePullPolicy: Never
      command:
        - /usr/local/bin/dex-driver
        - --issuer=$ISSUER
        - --ca-file=/etc/mediatore-dex/ca.pem
        - --login=$LOGIN
        - --password=$PASSWORD
        - --mediatore=$USER_API
        - --pool=e2e
        - --audience=$AUDIENCE
        - --image=registry.internal:5000/sandbox:e2e
        - --arg=sh
      volumeMounts:
        - { name: work, mountPath: /work }
        - { name: dex-ca, mountPath: /etc/mediatore-dex, readOnly: true }
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
  volumes:
    - name: work
      emptyDir: {}
    - name: dex-ca
      configMap: { name: mediatore-dex-ca }
YAML
  wait_for "$TIMEOUT" "pod $1 finished" pod_done "$1"
  [ "$(pod_phase "$1")" = "Succeeded" ] || fail "pod $1 failed: $(pod_logs "$1" | tail -15)"
  pod_logs "$1" | sed -n 's/^sandbox: //p' | tail -1
}

# A workload pod with the claim SVID asking for a token, once: the Workload API blocks
# until the SVID exists, and a refusal must stay in the one log the pod has.
token_pod() { # <pod name>
  "${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $1
  namespace: $NS
  labels: { mediatore.dev/e2e-role: dex-claim }
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: token
      image: ghcr.io/firestoned/mediatore:kind
      imagePullPolicy: Never
      command: ["/usr/local/bin/mediatore", "token", "--audience", "$AUDIENCE"]
      env:
        - { name: MEDIATORE_URL, value: "$SANDBOX_API" }
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
}
token_line() { pod_logs "$1" | grep -E '^eyJ' | tail -1; }
has_token()  { [ -n "$(token_line "$1")" ]; }
refused()    { pod_logs "$1" | grep -qF "session_revoked"; }
payload()    { # <jwt>: its payload as JSON
  local p; p=$(echo "$1" | cut -d. -f2)
  while [ $(( ${#p} % 4 )) -ne 0 ]; do p="$p="; done
  printf '%s' "$p" | tr '_-' '/+' | base64 -d 2>/dev/null
}

# Bind a sandbox's claim to the fixture node and point a ClusterSPIFFEID at the claim.
bind() { # <sandbox name>
  local name=$1
  has_claim() { "${K[@]}" -n "$NS" get virtualmachineclaim "$name" >/dev/null 2>&1; }
  wait_for "$TIMEOUT" "claim $name" has_claim
  CLAIM_UID=$("${K[@]}" -n "$NS" get virtualmachineclaim "$name" -o jsonpath='{.metadata.uid}')
  wait_for "$TIMEOUT" "'record created' for $CLAIM_UID in the broker log" log_has "record created" "$CLAIM_UID"
  jq -Rs '{status: {phase: "Bound", virtualMachineRef: {name: "member-1"}, tpmEndorsementCertificates: [.], boundAt: "2026-10-15T10:00:00Z", expiresAt: "2026-10-15T10:10:00Z"}}' < "$EK_PEM" \
    | "${K[@]}" -n "$NS" patch virtualmachineclaim "$name" --subresource=status --type=merge --patch-file=/dev/stdin >/dev/null
  ready() { [ "$(field "$name" '.status.ready')" = "true" ] && [ "$(field "$name" '.status.phase')" = "Bound" ]; }
  wait_for "$TIMEOUT" "$name Ready" ready
  "${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: mediatore-e2e-dex-claim
spec:
  className: spire-server-spire
  spiffeIDTemplate: "spiffe://{{ .TrustDomain }}/banlieue/claim/$CLAIM_UID"
  podSelector:
    matchLabels: { mediatore.dev/e2e-role: dex-claim }
  namespaceSelector:
    matchLabels: { kubernetes.io/metadata.name: $NS }
  ttl: 1h
YAML
  echo "claim $CLAIM_UID bound; $name Ready; the claim SVID assigned to the workload pods"
}

say "broker: running, with the Dex issuer pinned to the CA kind-dex minted"
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=60s >/dev/null
BROKER_POD=$(broker_pod)
[ -n "$BROKER_POD" ] || fail "no Running broker pod in $BROKER_NS"
wait_for "$TIMEOUT" "'issuer pinned to a private CA' in the broker log" log_has "issuer pinned to a private CA" "$ISSUER"
wait_for "$TIMEOUT" "'claim watcher running' in the broker log" log_has "claim watcher running"
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore-dex --timeout=60s >/dev/null
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore-glauth --timeout=60s >/dev/null
echo "broker ${BROKER_POD#pod/}, Dex and glauth up"

say "fixtures: a namespace, the directory as shipped, and a node registering the fixture EK over mTLS"
"${K[@]}" delete namespace "$NS" --ignore-not-found --wait=true >/dev/null
"${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=true >/dev/null
"${K[@]}" -n "$BROKER_NS" delete refreshtokens.dex.coreos.com --all --ignore-not-found >/dev/null 2>&1 || true
set_directory 5502
"${K[@]}" create namespace "$NS" >/dev/null
# The Dex CA for the user-side pod: ConfigMaps are namespaced, so copy the broker's.
"${K[@]}" -n "$BROKER_NS" get configmap mediatore-dex-ca -o jsonpath='{.data.ca\.pem}' \
  | "${K[@]}" -n "$NS" create configmap mediatore-dex-ca --from-file=ca.pem=/dev/stdin >/dev/null
"${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: mediatore-e2e-dex-node
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
        - 1d2c3b4a-5f6e-4d7c-8b9a-0f1e2d3c4b5a
        - --dev-skip-setup
      env:
        - { name: MEDIATORE_URL, value: "$SANDBOX_API" }
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
echo "node $EK_HASH registered"

say "login and claim: the real CLI, from a pod, at the real Dex (PKCE, loopback redirect), the session delegated"
CREATED=$(claim_via_cli cli-1)
[ -n "$CREATED" ] || fail "cli-1 printed no sandbox"
NAME=$(echo "$CREATED" | jq -r .name)
[ -n "$NAME" ] && [ "$NAME" != null ] || fail "no sandbox name in: $CREATED"
pod_logs cli-1 | grep -qF "logged in as octocat at $ISSUER" || fail "the CLI did not report octocat's login"
wait_for "$TIMEOUT" "'session parked' in the broker log" log_has "session parked" "subject=octocat"
TOKENS=$(dex_tokens)
[ "$(echo "$TOKENS" | jq length)" -eq 1 ] || fail "expected one refresh token at Dex after the login, found: $TOKENS"
echo "sandbox $NAME created for octocat; one refresh token at Dex, delegated and parked"

bind "$NAME"
subject_fetched() { pod_logs node | grep -F "subject fetched" | grep -qF "$CLAIM_UID"; }
wait_for "$TIMEOUT" "'subject fetched' for $CLAIM_UID in the node pod log" subject_fetched

say "issue: the workload's claim SVID becomes an STS token, after a refresh at Dex"
BEFORE=$(dex_tokens | jq -r '.[0].lastUsed')
token_pod token-1
wait_for "$TIMEOUT" "a token in the token-1 pod log" has_token token-1
CLAIMS=$(payload "$(token_line token-1)")
echo "$CLAIMS" | jq -e --arg uid "$CLAIM_UID" --arg aud "$AUDIENCE" '.sub == "octocat" and .aud == $aud and .claim_uid == $uid and .iss == "https://mediatore.sandbox.test"' >/dev/null \
  || fail "unexpected token claims: $CLAIMS"
AFTER=$(dex_tokens | jq -r '.[0].lastUsed')
[ "$AFTER" != "$BEFORE" ] || fail "Dex's refresh token was not used before the issue (lastUsed $BEFORE)"
log_has "upstream session refused" && fail "a refusal was logged on a good session"
echo "token for octocat, aud $AUDIENCE, claim $CLAIM_UID; Dex refresh token used at $AFTER (was $BEFORE)"

say "revoked upstream, one way: octocat leaves the gated group in the directory"
set_directory ""
token_pod token-2
wait_for "$TIMEOUT" "'session_revoked' in the token-2 pod log" refused token-2
wait_for "$TIMEOUT" "'upstream session refused; claim released' for $CLAIM_UID in the broker log" log_has "upstream session refused; claim released" "$CLAIM_UID"
entry_gone() { ! entries | grep -qF "mediatore-claim-$CLAIM_UID"; }
wait_for "$TIMEOUT" "claim entry for $CLAIM_UID gone" entry_gone
echo "403 session_revoked; the claim released: entry retracted"
set_directory 5502

say "a second login and claim, for the other way"
CREATED=$(claim_via_cli cli-2)
NAME2=$(echo "$CREATED" | jq -r .name)
[ -n "$NAME2" ] && [ "$NAME2" != null ] || fail "no sandbox name in: $CREATED"
[ "$NAME2" != "$NAME" ] || fail "the second claim reused the first name"
bind "$NAME2"
token_pod token-3
wait_for "$TIMEOUT" "a token in the token-3 pod log" has_token token-3
echo "$(payload "$(token_line token-3)")" | jq -e --arg uid "$CLAIM_UID" '.claim_uid == $uid' >/dev/null || fail "token-3 is not for $CLAIM_UID"
echo "sandbox $NAME2 created, bound, issuing"

say "revoked upstream, the other way: the refresh token is deleted at Dex"
"${K[@]}" -n "$BROKER_NS" delete refreshtokens.dex.coreos.com --all >/dev/null
token_pod token-4
wait_for "$TIMEOUT" "'session_revoked' in the token-4 pod log" refused token-4
wait_for "$TIMEOUT" "'upstream session refused; claim released' for $CLAIM_UID in the broker log" log_has "upstream session refused; claim released" "$CLAIM_UID"
wait_for "$TIMEOUT" "claim entry for $CLAIM_UID gone" entry_gone
echo "403 session_revoked; the claim released: entry retracted"

say "PASS: ADR-0013 holds against a real Dex (the CLI's PKCE login, the delegated session, a refresh before every issue, revocation by group and by token)"
