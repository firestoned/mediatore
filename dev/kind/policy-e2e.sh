#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# ADR-0026 against a real cluster (`make kind-e2e-policy`): notaio from its release
# manifest, signing with the kind OpenBao, publishes the bundle of a policy and its
# ceiling in the e2e namespace; the broker, trusting that key through its `policy`
# section, admits the bundle, records it on each sandbox's claim, and compares every
# sandbox with it. A sandbox the broker is configured for exactly as the bundle allows
# reports PolicyConformant True; one asking for an audience the bundle lacks reports
# False with P001; one without a policyRef reports P010; one naming a policy with no
# bundle reports P011; every one of them gets its claim, because nothing is refused on
# the bundle's account. A change to the policy publishes a newer version the broker
# admits; the earlier bundle delivered again is refused by the version floor, and still
# refused after a broker restart, because the floor lives in the store with the claims.
#
#   policy-e2e.sh <admin kubeconfig> <broker SA kubeconfig> <state dir>
set -euo pipefail
cd "$(dirname "$0")/../.."

ADMIN_KUBECONFIG=${1:?admin kubeconfig}
SA_KUBECONFIG=${2:?broker ServiceAccount kubeconfig}
STATE=${3:?state dir}
K=(kubectl --kubeconfig "$ADMIN_KUBECONFIG")
KSA=(kubectl --kubeconfig "$SA_KUBECONFIG")
BROKER_NS=banlieue-system
NS=mediatore-e2e-sandbox
ISSUER=https://issuer.example.com
TIMEOUT=${MEDIATORE_KIND_TIMEOUT:-180}
POLICY=agent
BUNDLE_CM=$POLICY-bundle
REPLAY_CM=$POLICY-bundle-replay
VERSION_ANN='sandbox\.firestoned\.io/bundle-version'
DIR=$STATE/notaio

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; dump; exit 1; }
plain() { sed "s/$(printf '\033')\[[0-9;]*m//g"; }

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
[ -f "$DIR/public-key.txt" ] || { echo "no $DIR/public-key.txt: run make kind-notaio first" >&2; exit 1; }

broker_pod()  { "${K[@]}" -n "$BROKER_NS" get pods -l app.kubernetes.io/name=mediatore -o json 2>/dev/null | jq -r '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")] | sort_by(.metadata.creationTimestamp) | last | select(. != null) | "pod/" + .metadata.name'; }
BROKER_POD=""
broker_logs() { [ -n "$BROKER_POD" ] && "${K[@]}" -n "$BROKER_NS" logs "$BROKER_POD" 2>/dev/null | plain || true; }
log_has()     { broker_logs | grep -F "$1" | grep -qF "${2:-}"; }
sandbox()     { "${K[@]}" -n "$NS" get agentsandbox "$1" -o json 2>/dev/null || true; }
field()       { sandbox "$1" | jq -r "$2 // empty"; }
verdict()     { sandbox "$1" | jq -r '.status.conditions[]? | select(.type == "PolicyConformant") | "\(.status) \(.reason) \(.message)"'; }
bundle_version() { "${K[@]}" -n "$NS" get configmap "$BUNDLE_CM" -o jsonpath="{.metadata.annotations.$VERSION_ANN}" 2>/dev/null || true; }

dump() {
  printf '\n--- broker (last 60 lines)\n'; broker_logs | tail -60
  printf '\n--- notaio (last 30 lines)\n'; "${K[@]}" -n notaio-system logs deploy/notaio --tail=30 2>/dev/null | plain || true
  printf '\n--- %s\n' "$NS"; "${K[@]}" -n "$NS" get sandboxpolicies,exposureceilings,configmaps,agentsandboxes,virtualmachineclaims 2>/dev/null || true
  printf '\n--- verdicts\n'; for sb in sb-ok sb-gap sb-none sb-orphan; do printf '%s: %s\n' "$sb" "$(verdict "$sb")"; done
}

cleanup() {
  "${K[@]}" -n "$NS" delete configmap "$REPLAY_CM" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  # The broker's configuration as the overlay ships it, for the tiers after this one.
  "${K[@]}" apply -k dev/kind/broker >/dev/null 2>&1 || true
  "${K[@]}" -n "$BROKER_NS" rollout restart deploy/mediatore >/dev/null 2>&1 || true
  "${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=120s >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() { # <seconds> <description> <command...>
  local secs=$1 what=$2 i; shift 2
  for ((i = 0; i < secs; i++)); do "$@" && return 0; sleep 1; done
  fail "$what not seen within ${secs}s"
}

# An AgentSandbox manifest for <name> with audiences <json array> and policyRef <name or
# empty>, for octocat: the broker ServiceAccount creates these, exempt from the subject
# check, as POST /v1/claims does.
manifest() {
  cat <<YAML
apiVersion: mediatore.io/v1alpha1
kind: AgentSandbox
metadata:
  name: $1
  namespace: $NS
spec:
  subject: { issuer: "$ISSUER", id: "octocat" }
  poolRef: { name: e2e }
  ttlSeconds: 600
  audiences: $2
  workload: { image: "registry.internal:5000/sandbox:e2e", args: ["sh"] }
$( [ -n "${3:-}" ] && printf '  policyRef: { name: %s }\n' "$3" )
YAML
}

restart_broker() {
  "${K[@]}" -n "$BROKER_NS" rollout restart deploy/mediatore >/dev/null
  "${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=120s >/dev/null
  BROKER_POD=$(broker_pod)
  [ -n "$BROKER_POD" ] || fail "no Running broker pod in $BROKER_NS"
  wait_for "$TIMEOUT" "'policy bundle reflector running' in the broker log" log_has "policy bundle reflector running"
  wait_for "$TIMEOUT" "'claim watcher running' in the broker log" log_has "claim watcher running"
}

say "fixtures: the namespace, notaio's bundle Role and the broker's read Role in it"
"${K[@]}" delete namespace "$NS" --ignore-not-found --wait=true >/dev/null
"${K[@]}" create namespace "$NS" >/dev/null
"${K[@]}" -n "$NS" apply -f dev/kind/notaio/notaio-bundles.yaml >/dev/null
mkdir -p "$STATE/policy-bundles"
printf 'namespace: %s\nresources:\n  - ../../deploy/policy-bundles\n' "$NS" > "$STATE/policy-bundles/kustomization.yaml"
"${K[@]}" apply -k "$STATE/policy-bundles" >/dev/null
echo "roles in $NS: notaio writes bundles, the broker reads them"

say "broker: the policy section trusting notaio's key, bundles read from $NS"
read -r KEY_ID PUBLIC_KEY < "$DIR/public-key.txt"
{
  cat dev/kind/broker/mediatore.yaml
  printf 'policy:\n  trusted_keys:\n    - { id: "%s", public_key: "%s" }\n  namespaces: [%s]\n' "$KEY_ID" "$PUBLIC_KEY" "$NS"
} > "$DIR/mediatore.yaml"
"${K[@]}" -n "$BROKER_NS" create configmap mediatore-config --from-file=mediatore.yaml="$DIR/mediatore.yaml" \
  --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
restart_broker
echo "reflector running on ${BROKER_POD#pod/} trusting $KEY_ID"

say "notaio: a policy and its ceiling publish a signed bundle"
"${K[@]}" -n "$NS" apply -f - >/dev/null <<YAML
apiVersion: sandbox.firestoned.io/v1alpha2
kind: ExposureCeiling
metadata:
  name: $POLICY
spec:
  audiences:
    - name: internal-git
      access: Read
      maxTtlSeconds: 300
      endpoints: ["git.foo.io:443"]
  egressHosts: []
  tools: []
  maxLeaseSeconds: 14400
  approvals:
    - role: Security
      reference: https://github.com/firestoned/notaio/pull/1
---
apiVersion: sandbox.firestoned.io/v1alpha2
kind: SandboxPolicy
metadata:
  name: $POLICY
spec:
  profileRef: hardened
  subjects:
    groups: ["00000000-0000-0000-0000-000000000000"]
  audiences:
    - name: internal-git
      access: Read
      scopes: ["repo:read"]
      endpoints: ["git.foo.io:443"]
      rules:
        - { method: GET, path: "/repos/**" }
  egress: []
  tools: []
YAML
published() { [ -n "$(bundle_version)" ]; }
wait_for "$TIMEOUT" "ConfigMap $BUNDLE_CM with a bundle version" published
V1=$(bundle_version)
"${K[@]}" -n "$NS" get configmap "$BUNDLE_CM" -o jsonpath='{.data.bundle\.dsse\.json}' > "$DIR/bundle-v$V1.json"
[ -s "$DIR/bundle-v$V1.json" ] || fail "the bundle ConfigMap carries no envelope"
wait_for "$TIMEOUT" "'policy bundle admitted' version=$V1 in the broker log" log_has "policy bundle admitted" "version=$V1"
echo "bundle v$V1 of $NS/$POLICY published by notaio and admitted by the broker"

say "sandboxes: conformant, a gap, no policyRef, a policy with no bundle; all admitted"
manifest sb-ok '["internal-git"]' "$POLICY" | "${KSA[@]}" create -f - >/dev/null
manifest sb-gap '["internal-git", "e2e"]' "$POLICY" | "${KSA[@]}" create -f - >/dev/null
manifest sb-none '["internal-git"]' "" | "${KSA[@]}" create -f - >/dev/null
manifest sb-orphan '["internal-git"]' unsigned | "${KSA[@]}" create -f - >/dev/null
has_verdict() { [ -n "$(verdict "$1")" ] && [ -n "$(field "$1" '.status.claimRef.name')" ]; }
for sb in sb-ok sb-gap sb-none sb-orphan; do
  wait_for "$TIMEOUT" "$sb with a claim and a PolicyConformant condition" has_verdict "$sb"
  [ "$(field "$sb" '.status.phase')" = "Pending" ] || fail "$sb is $(field "$sb" '.status.phase'), expected Pending"
  [ -z "$(field "$sb" '.status.reason')" ] || fail "$sb has a reason: $(field "$sb" '.status.reason')"
  "${K[@]}" -n "$NS" get virtualmachineclaim "$sb" >/dev/null 2>&1 || fail "$sb has no claim: something was refused on the bundle's account"
done
expect() { # <sandbox> <status reason prefix> <substring>
  local v
  v=$(verdict "$1")
  case "$v" in "$2"*) ;; *) fail "$1: expected '$2...', got '$v'" ;; esac
  echo "$v" | grep -qF "$3" || fail "$1: expected '$3' in '$v'"
  echo "$1: $v"
}
expect sb-ok "True Conformant" "v$V1"
expect sb-gap "False Gaps" "P001 audience e2e"
expect sb-none "False Gaps" "P010"
expect sb-orphan "False Gaps" "P011"
wait_for "$TIMEOUT" "'policy gap' with code P001 in the broker log" log_has "policy gap" "P001"
wait_for "$TIMEOUT" "'record created' naming bundle version $V1 in the broker log" log_has "record created" "bundle_version=Some($V1)"
echo "four claims, nothing refused; the gaps logged"

say "a newer bundle: the policy changes, v$V1 gives way, the verdicts follow"
"${K[@]}" -n "$NS" patch sandboxpolicy "$POLICY" --type=merge -p '{"spec":{"audiences":[{"name":"internal-git","access":"Read","scopes":["repo:read","repo:status"],"endpoints":["git.foo.io:443"],"rules":[{"method":"GET","path":"/repos/**"}]}]}}' >/dev/null
newer() { [ -n "$(bundle_version)" ] && [ "$(bundle_version)" != "$V1" ]; }
wait_for "$TIMEOUT" "a bundle version after $V1" newer
V2=$(bundle_version)
[ "$V2" -gt "$V1" ] || fail "bundle version went from $V1 to $V2"
wait_for "$TIMEOUT" "'policy bundle admitted' version=$V2 in the broker log" log_has "policy bundle admitted" "version=$V2"
ok_on_v2() { verdict sb-ok | grep -qF "v$V2"; }
wait_for "$TIMEOUT" "sb-ok compared with v$V2" ok_on_v2
expect sb-ok "True Conformant" "v$V2"
expect sb-gap "False Gaps" "P001 audience e2e"
echo "v$V2 admitted; every sandbox compared again"

say "the floor: v$V1 delivered again is refused, before and after a broker restart"
replay() {
  "${K[@]}" -n "$NS" delete configmap "$REPLAY_CM" --ignore-not-found --wait=true >/dev/null
  "${K[@]}" -n "$NS" create configmap "$REPLAY_CM" --from-file=bundle.dsse.json="$DIR/bundle-v$V1.json" \
    --dry-run=client -o yaml | "${K[@]}" label --local -f - app.kubernetes.io/managed-by=notaio -o yaml \
    | "${K[@]}" apply -f - >/dev/null
}
replay
wait_for "$TIMEOUT" "'policy bundle refused' with Downgrade in the broker log" log_has "policy bundle refused" "Downgrade"
"${K[@]}" -n "$NS" delete configmap "$REPLAY_CM" --wait=true >/dev/null
sleep 2
log_has "policy bundle gone" "configmap=$REPLAY_CM" && fail "deleting the replay dropped the policy from the cache"
expect sb-ok "True Conformant" "v$V2"
echo "replay refused (Downgrade); the cache kept v$V2"
restart_broker
wait_for "$TIMEOUT" "'policy bundle admitted' version=$V2 in the new broker log" log_has "policy bundle admitted" "version=$V2"
replay
wait_for "$TIMEOUT" "'policy bundle refused' with Downgrade in the new broker log" log_has "policy bundle refused" "Downgrade"
"${K[@]}" -n "$NS" delete configmap "$REPLAY_CM" --wait=true >/dev/null
expect sb-ok "True Conformant" "v$V2"
for sb in sb-ok sb-gap sb-none sb-orphan; do
  "${K[@]}" -n "$NS" get virtualmachineclaim "$sb" >/dev/null 2>&1 || fail "$sb lost its claim"
done
echo "still refused on ${BROKER_POD#pod/}: the floor came back from the store"

say "PASS: ADR-0026 holds against a real cluster (notaio from its release signing with OpenBao, the bundle admitted and recorded, the comparison's verdicts and codes, a newer version followed, a replay refused by the floor across a restart, nothing refused on the bundle's account)"
