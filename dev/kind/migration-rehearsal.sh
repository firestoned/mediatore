#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# The rehearsal of ADR-0056 decision 7 (`make kind-rehearse-migration`): a running broker
# moved from banlieue's namespace to its own by the copy path, with a claim bound before
# the move issuing a token after it. Not a tier of `make kind-e2e`: it is run when the
# migration procedure in docs/guides/deploying.md changes, and its output is the
# transcript in docs/guides/testing.md.
#
# It starts from `make kind-broker` (the new shape: the broker and its fixtures in
# mediatore-system), puts the broker back as it stood before the move (the overlay in
# dev/kind/migration, which is step 1 of the procedure: the fail-closed policies and the
# self-check in the old namespace, the parameter naming the old username), runs the first
# half of the Dex tier there, performs steps 2 to 8 with the commands the guide gives,
# and runs the second half of the Dex tier against the broker in its new namespace. Dex,
# glauth and OpenBao stay where `make kind-broker` put them throughout: they stand for an
# issuer and a transit engine outside the broker's namespace.
#
#   migration-rehearsal.sh <admin kubeconfig> <trust domain> <ek pem> <ek hash file> <state dir>
set -euo pipefail
cd "$(dirname "$0")/../.."

KUBECONFIG_PATH=${1:?kubeconfig}
TD=${2:?trust domain}
EK_PEM=${3:?ek pem}
EK_HASH_FILE=${4:?ek hash file}
STATE=${5:?state dir}
K=(kubectl --kubeconfig "$KUBECONFIG_PATH")
OLD=banlieue-system
NEW=mediatore-system
DEX_STATE=$STATE/migration-claim
TIMEOUT=${MEDIATORE_KIND_TIMEOUT:-180}

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }
plain() { sed "s/$(printf '\033')\[[0-9;]*m//g"; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

broker_log() { "${K[@]}" -n "$1" logs deploy/mediatore 2>/dev/null | plain || true; }
wait_log() { # <namespace> <text>
  local i
  for ((i = 0; i < TIMEOUT; i++)); do broker_log "$1" | grep -qF "$2" && return 0; sleep 1; done
  broker_log "$1" | tail -30 >&2
  fail "'$2' not in the broker log in $1 within ${TIMEOUT}s"
}
no_pods() { [ -z "$("${K[@]}" -n "$1" get pods -l app.kubernetes.io/name=mediatore -o name 2>/dev/null)" ]; }
wait_no_pods() { local i; for ((i = 0; i < TIMEOUT; i++)); do no_pods "$1" && return 0; sleep 1; done; fail "broker pods still in $1"; }
# The OpenBao role of the transit sealer, bound to these namespaces (ADR-0015).
ROOT=$(jq -r .root_token "$STATE/openbao/init.json")
bao_role() { # <comma-separated namespaces>
  "${K[@]}" -n "$NEW" exec deploy/mediatore-openbao -- env BAO_TOKEN="$ROOT" bao write auth/kubernetes/role/mediatore \
    bound_service_account_names=mediatore bound_service_account_namespaces="$1" audience=openbao \
    token_policies=mediatore-transit,mediatore-audiences token_ttl=1h >/dev/null
}
# A namespaced object re-created elsewhere: the same name, labels and data, and none of
# what belongs to the object it was (ADR-0056 decision 7 step 6). The same filter as
# docs/guides/deploying.md gives: change both or neither.
copied() { # <new namespace>: a kubectl JSON list on stdin, the copies on stdout
  jq --arg ns "$1" '.items[] |= (del(.metadata.ownerReferences, .metadata.uid, .metadata.resourceVersion, .metadata.creationTimestamp, .metadata.managedFields, .metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"], .status) | .metadata.namespace = $ns)' | jq '.items[]'
}
sha() { "${K[@]}" -n "$1" get secret "$2" -o json | jq -r '.data | to_entries | map(.key + "=" + .value) | join("\n")' | sha256sum | cut -c1-16; }

cleanup() {
  # Back to what `make kind-broker` leaves, whatever happened: nothing of the broker's in $OLD.
  bao_role "$NEW" 2>/dev/null || true
  "${K[@]}" delete namespace "$OLD" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  rm -f "$DEX_STATE"
}
trap cleanup EXIT

say "before: the broker as it stood, in $OLD (step 1: this build and base, the parameter naming the old username)"
"${K[@]}" -n "$NEW" scale deploy/mediatore --replicas=0 >/dev/null
wait_no_pods "$NEW"
"${K[@]}" -n "$NEW" delete lease mediatore-watcher --ignore-not-found >/dev/null
# The new home starts empty of store objects, as a namespace just created is (earlier tiers left theirs).
"${K[@]}" -n "$NEW" delete sandboxnodes,policyfloors --all --ignore-not-found >/dev/null
"${K[@]}" -n "$NEW" delete secrets -l mediatore.io/sandbox-uid --ignore-not-found >/dev/null
"${K[@]}" get namespace "$OLD" >/dev/null 2>&1 || "${K[@]}" create namespace "$OLD" >/dev/null
# What the operator created there: the STS key and the two CA bundles the kind broker mounts.
"${K[@]}" -n "$NEW" get secret mediatore-sts -o json | jq '{items: [.]}' | copied "$OLD" | "${K[@]}" apply -f - >/dev/null
for cm in mediatore-dex-ca mediatore-openbao-ca; do
  "${K[@]}" -n "$NEW" get configmap "$cm" -o json | jq '{items: [.]}' | copied "$OLD" | "${K[@]}" apply -f - >/dev/null
done
bao_role "$OLD"
"${K[@]}" apply -k dev/kind/migration >/dev/null
"${K[@]}" -n "$OLD" rollout restart deploy/mediatore >/dev/null
"${K[@]}" -n "$OLD" rollout status deploy/mediatore --timeout=300s >/dev/null
wait_log "$OLD" "claim watcher running"
broker_log "$OLD" | grep -F "store: the Kubernetes API" | grep -qF "namespace=\"$OLD\"" || fail "the old broker's store is not in $OLD"
echo "broker in $OLD: its self-check passed under the parameter broker=$("${K[@]}" -n "$OLD" get configmap mediatore-agentsandbox-subject-policy -o jsonpath='{.data.broker}')"

MEDIATORE_BROKER_NS=$OLD MEDIATORE_DEX_PHASE=until-first-token MEDIATORE_DEX_STATE=$DEX_STATE \
  ./dev/kind/dex-e2e.sh "$KUBECONFIG_PATH" "$TD" "$EK_PEM" "$EK_HASH_FILE"
read -r SANDBOX CLAIM_UID < "$DEX_STATE"
SANDBOX_UID=$("${K[@]}" -n mediatore-e2e-sandbox get agentsandbox "$SANDBOX" -o jsonpath='{.metadata.uid}')
"${K[@]}" -n "$OLD" get secret "mediatore-session-$SANDBOX_UID" >/dev/null || fail "no session Secret for $SANDBOX in $OLD"
# What step 5 exists for, as fixtures (the Dex tier reads no bundle and bans nobody): a
# version floor and a banned node in the old home, each to be found unchanged in the new.
FLOOR=mediatore-e2e-migration.rehearsal
BANNED=$(printf 'ba%062x' 7)
"${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: mediatore.io/v1alpha1
kind: PolicyFloor
metadata: { name: $FLOOR, namespace: $OLD }
spec:
  policyNamespace: mediatore-e2e-migration
  policyName: rehearsal
  uid: 5f0c1e2d-3b4a-4c5d-8e6f-7a8b9c0d1e2f
  version: 7
  issuedAt: "2026-11-27T00:00:00Z"
---
apiVersion: mediatore.io/v1alpha1
kind: SandboxNode
metadata: { name: $BANNED, namespace: $OLD }
spec:
  ekHash: $BANNED
  nodeId: spiffe://$TD/spire/agent/tpm/$BANNED
  dmiUuid: 0b0a0d00-0000-4000-8000-000000000007
  hostname: banned-fixture
  banned: true
  registeredAt: "2026-11-27T00:00:00Z"
YAML
spec_of() { "${K[@]}" -n "$1" get "$2" "$3" -o json | jq -cS .spec; }
echo "in $OLD: $("${K[@]}" -n "$OLD" get secrets -l mediatore.io/sandbox-uid -o name | wc -l | tr -d ' ') store Secret(s), $("${K[@]}" -n "$OLD" get sandboxnodes -o name | wc -l | tr -d ' ') SandboxNode(s), $("${K[@]}" -n "$OLD" get policyfloors -o name | wc -l | tr -d ' ') PolicyFloor(s)"

say "step 2: the namespace, and what the operator created, copied (the same STS key, so the kid and the JWKS do not change)"
"${K[@]}" apply -f deploy/base/namespace.yaml >/dev/null
"${K[@]}" -n "$OLD" get secret mediatore-sts -o json | jq '{items: [.]}' | copied "$NEW" | "${K[@]}" apply -f - >/dev/null
[ "$(sha "$OLD" mediatore-sts)" = "$(sha "$NEW" mediatore-sts)" ] || fail "the STS key in $NEW is not the one in $OLD"
echo "mediatore-sts in $NEW is the key in $OLD (digest of the data compared, never printed)"

say "step 3: the bindings outside the repository name the new subject beside the old one"
bao_role "$OLD,$NEW"
echo "OpenBao role mediatore: bound_service_account_namespaces=$OLD,$NEW (banlieue's brokers list and a policy namespace's RoleBinding take the same second line; neither exists in this cluster)"

say "step 4: the old broker scaled to zero (the one outage starts)"
"${K[@]}" -n "$OLD" scale deploy/mediatore --replicas=0 >/dev/null
wait_no_pods "$OLD"
echo "no broker pod in $OLD; the Lease there has no holder to renew it"

say "step 5: every PolicyFloor and every banned SandboxNode"
"${K[@]}" -n "$OLD" get policyfloors -o json | copied "$NEW" | "${K[@]}" apply -f - | sed 's/^/  /'
"${K[@]}" -n "$OLD" get sandboxnodes -o json | jq '.items |= map(select(.spec.banned == true))' | copied "$NEW" | "${K[@]}" apply -f - | sed 's/^/  /'
[ "$(spec_of "$NEW" policyfloor "$FLOOR")" = "$(spec_of "$OLD" policyfloor "$FLOOR")" ] || fail "the floor $FLOOR did not arrive in $NEW as it was in $OLD"
[ "$(spec_of "$NEW" sandboxnode "$BANNED" | jq .banned)" = "true" ] || fail "the banned node did not arrive in $NEW banned"
"${K[@]}" -n "$NEW" get sandboxnodes -o json | jq -e '[.items[] | select(.spec.banned != true)] | length == 0' >/dev/null || fail "step 5 copied a node that is not banned"
echo "in $NEW as in $OLD: floor $FLOOR at version $(spec_of "$NEW" policyfloor "$FLOOR" | jq .version), node ${BANNED:0:12}... banned; no unbanned node copied yet"

say "step 6 (claims not drained): the store's Secrets and the bound SandboxNodes, with no ownerReferences, uid or resourceVersion"
"${K[@]}" -n "$OLD" get secrets -l mediatore.io/sandbox-uid -o json | copied "$NEW" | "${K[@]}" apply -f - | sed 's/^/  /'
"${K[@]}" -n "$OLD" get secrets -l mediatore.io/logs -o json | copied "$NEW" | "${K[@]}" apply -f - 2>/dev/null | sed 's/^/  /' || true
"${K[@]}" -n "$OLD" get sandboxnodes -o json | copied "$NEW" | "${K[@]}" apply -f - | sed 's/^/  /'
"${K[@]}" -n "$NEW" get secret "mediatore-session-$SANDBOX_UID" -o json | jq -e '(.metadata.ownerReferences // []) == []' >/dev/null || fail "the copied session Secret carries an owner reference"
echo "the copied session of $SANDBOX carries no owner reference"

say "step 7: the base in $NEW, the parameter naming the new username"
"${K[@]}" apply -k dev/kind/broker >/dev/null
"${K[@]}" -n "$NEW" scale deploy/mediatore --replicas=1 >/dev/null
"${K[@]}" -n "$NEW" rollout restart deploy/mediatore >/dev/null
"${K[@]}" -n "$NEW" rollout status deploy/mediatore --timeout=300s >/dev/null
wait_log "$NEW" "claim watcher running"
broker_log "$NEW" | grep -F "store: the Kubernetes API" | grep -qF "namespace=\"$NEW\"" || fail "the new broker's store is not in $NEW"
broker_log "$NEW" | grep -F "store: the Kubernetes API" | tail -1
echo "parameter broker=$("${K[@]}" -n "$NEW" get configmap mediatore-agentsandbox-subject-policy -o jsonpath='{.data.broker}'); ClusterRoleBinding subject namespace=$("${K[@]}" get clusterrolebinding mediatore -o jsonpath='{.subjects[0].namespace}'); ClusterSPIFFEID selects $("${K[@]}" get clusterspiffeid mediatore -o jsonpath='{.spec.namespaceSelector.matchLabels.kubernetes\.io/metadata\.name}')"

say "step 8: verify (the claim bound before the move issues after it, then a new login and claim), then clean $OLD"
MEDIATORE_BROKER_NS=$NEW MEDIATORE_DEX_PHASE=from-second-token MEDIATORE_DEX_STATE=$DEX_STATE \
  ./dev/kind/dex-e2e.sh "$KUBECONFIG_PATH" "$TD" "$EK_PEM" "$EK_HASH_FILE"
"${K[@]}" -n "$OLD" delete deployment/mediatore service/mediatore service/mediatore-sandbox configmap/mediatore-config \
  rolebinding/mediatore-sessions rolebinding/mediatore-store rolebinding/mediatore-watcher-lease \
  role/mediatore-sessions role/mediatore-store role/mediatore-watcher-lease \
  serviceaccount/mediatore lease/mediatore-watcher configmap/mediatore-agentsandbox-subject-policy --ignore-not-found >/dev/null
"${K[@]}" -n "$OLD" delete secrets -l mediatore.io/sandbox-uid --ignore-not-found >/dev/null
"${K[@]}" -n "$OLD" delete secrets -l mediatore.io/logs --ignore-not-found >/dev/null
"${K[@]}" -n "$OLD" delete sandboxnodes,policyfloors --all --ignore-not-found >/dev/null
"${K[@]}" -n "$OLD" delete secret mediatore-sts --ignore-not-found >/dev/null
bao_role "$NEW"
"${K[@]}" -n "$NEW" delete policyfloor "$FLOOR" --ignore-not-found >/dev/null
"${K[@]}" -n "$NEW" delete sandboxnode "$BANNED" --ignore-not-found >/dev/null
left=$("${K[@]}" -n "$OLD" get secrets,serviceaccounts,roles,rolebindings,leases,sandboxnodes,policyfloors -o name 2>/dev/null | grep -c mediatore || true)
[ "$left" -eq 0 ] || fail "$left object(s) of the broker's left in $OLD"
echo "nothing of the broker's left in $OLD; the OpenBao role is bound to $NEW alone"

say "PASS: ADR-0056 decision 7 by the copy path: claim $CLAIM_UID bound with the broker in $OLD, its token issued by the broker in $NEW"
