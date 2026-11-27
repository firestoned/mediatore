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
# admits; the earlier bundle written back into the policy's own object is refused by the
# version floor, and still refused after a broker restart, because the floor lives in the
# store with the claims; a valid bundle copied under another policy's name is refused as
# `WrongSubject` and its deletion drops nothing (notaio v0.8.0).
# Then ADR-0053 phase 2: the broker is restarted with `policy.audiences: enforce`, and a
# sandbox with no policyRef, one naming a policy with no bundle, one asking for an audience
# the bundle lacks and one asking for more than the policy's lease are each Failed with
# their reason and get no claim, while a conformant one still gets its claim.
#
# ADR-0054 last: a second policy namespace the broker reads, whose policy the sandbox
# namespace may not name until `policy.sources` says it draws from there. Without the
# entry a sandbox naming it reports P011 in shadow (and is still created), and is Failed
# with policy_not_resolved under enforce, with no claim and the same reason as a policy
# that exists nowhere; with the entry and a restart it is admitted and recorded.
#
#   policy-e2e.sh <admin kubeconfig> <broker SA kubeconfig> <state dir>
set -euo pipefail
cd "$(dirname "$0")/../.."

ADMIN_KUBECONFIG=${1:?admin kubeconfig}
SA_KUBECONFIG=${2:?broker ServiceAccount kubeconfig}
STATE=${3:?state dir}
K=(kubectl --kubeconfig "$ADMIN_KUBECONFIG")
KSA=(kubectl --kubeconfig "$SA_KUBECONFIG")
BROKER_NS=mediatore-system
NS=mediatore-e2e-sandbox
# A policy namespace beside the sandbox one (ADR-0054): read by the broker, drawn from only
# when policy.sources says so.
NSP=mediatore-e2e-policies
OTHER=infra
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
  printf '\n--- %s\n' "$NSP"; "${K[@]}" -n "$NSP" get sandboxpolicies,exposureceilings,configmaps 2>/dev/null || true
  printf '\n--- verdicts\n'
  for sb in sb-ok sb-gap sb-none sb-orphan sb-elsewhere sb-elsewhere-enf sb-nowhere-enf sb-own-enf sb-mapped; do
    printf '%s: %s | %s %s\n' "$sb" "$(verdict "$sb")" "$(field "$sb" '.status.phase')" "$(field "$sb" '.status.reason')"
  done
}

cleanup() {
  "${K[@]}" -n "$NS" delete configmap "$REPLAY_CM" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete namespace "$NSP" --ignore-not-found --wait=false >/dev/null 2>&1 || true
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
apiVersion: mediatore.io/v1beta1
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
# The overlay's configuration plus a policy section reading <namespaces>, with any further
# lines of that section (egress, sources) as the second argument; applied and restarted.
policy_config() {
  {
    cat dev/kind/broker/mediatore.yaml
    printf 'policy:\n  trusted_keys:\n    - { id: "%s", public_key: "%s" }\n  namespaces: [%s]\n' "$KEY_ID" "$PUBLIC_KEY" "$1"
    [ -n "${2:-}" ] && printf '%s\n' "$2"
  } > "$DIR/mediatore.yaml"
  "${K[@]}" -n "$BROKER_NS" create configmap mediatore-config --from-file=mediatore.yaml="$DIR/mediatore.yaml" \
    --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
  restart_broker
}
policy_config "$NS"
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
"${K[@]}" -n "$NS" get configmap "$BUNDLE_CM" -o jsonpath='{.data.bundle\.dsse\.json}' > "$DIR/bundle-v$V2.json"
[ -s "$DIR/bundle-v$V2.json" ] || fail "the bundle ConfigMap carries no envelope at v$V2"

say "the floor: v$V1 written back into the policy's own object is refused, before and after a broker restart"
# What a ConfigMap writer can still do (notaio v0.8.0): put an older signed bundle into the object notaio
# writes for the policy. The floor refuses it; the copy is put back after, as notaio would on its next write.
put_bundle() { # <envelope file>
  "${K[@]}" -n "$NS" patch configmap "$BUNDLE_CM" --type merge \
    -p "$(jq -n --rawfile b "$1" '{data: {"bundle.dsse.json": $b}}')" >/dev/null
}
replay() {
  put_bundle "$DIR/bundle-v$V1.json"
}
restore() {
  put_bundle "$DIR/bundle-v$V2.json"
}
replay
wait_for "$TIMEOUT" "'policy bundle refused' with Downgrade in the broker log" log_has "policy bundle refused" "Downgrade"
restore
expect sb-ok "True Conformant" "v$V2"
echo "replay refused (Downgrade); the cache kept v$V2"

say "the subject: a valid bundle copied under another policy's name is refused, and its deletion drops nothing"
"${K[@]}" -n "$NS" create configmap "$REPLAY_CM" --from-file=bundle.dsse.json="$DIR/bundle-v$V2.json" \
  --dry-run=client -o yaml | "${K[@]}" label --local -f - app.kubernetes.io/managed-by=notaio -o yaml \
  | "${K[@]}" apply -f - >/dev/null
wait_for "$TIMEOUT" "'policy bundle refused' with WrongSubject for $REPLAY_CM" log_has "policy bundle refused" "configmap=$REPLAY_CM code=\"WrongSubject\""
"${K[@]}" -n "$NS" delete configmap "$REPLAY_CM" --wait=true >/dev/null
sleep 2
log_has "policy bundle gone" "configmap=$REPLAY_CM" && fail "deleting the copy dropped the policy from the cache"
expect sb-ok "True Conformant" "v$V2"
echo "the copy refused (WrongSubject); deleting it left v$V2 where it was"

restart_broker
wait_for "$TIMEOUT" "'policy bundle admitted' version=$V2 in the new broker log" log_has "policy bundle admitted" "version=$V2"
replay
wait_for "$TIMEOUT" "'policy bundle refused' with Downgrade in the new broker log" log_has "policy bundle refused" "Downgrade"
restore
expect sb-ok "True Conformant" "v$V2"
for sb in sb-ok sb-gap sb-none sb-orphan; do
  "${K[@]}" -n "$NS" get virtualmachineclaim "$sb" >/dev/null 2>&1 || fail "$sb lost its claim"
done
echo "still refused on ${BROKER_POD#pod/}: the floor came back from the store"

say "ADR-0053 phase 2: policy.audiences: enforce, the bundle decides what a sandbox may have"
{
  cat dev/kind/broker/mediatore.yaml
  printf 'policy:\n  trusted_keys:\n    - { id: "%s", public_key: "%s" }\n  namespaces: [%s]\n  audiences: enforce\n' "$KEY_ID" "$PUBLIC_KEY" "$NS"
} > "$DIR/mediatore-enforce.yaml"
"${K[@]}" -n "$BROKER_NS" create configmap mediatore-config --from-file=mediatore.yaml="$DIR/mediatore-enforce.yaml" \
  --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
restart_broker
wait_for "$TIMEOUT" "'policy bundle admitted' version=$V2 under enforce" log_has "policy bundle admitted" "version=$V2"
log_has "policy.audiences" "mode=enforce" || fail "the broker did not log policy.audiences mode=enforce"
echo "broker restarted on ${BROKER_POD#pod/} with policy.audiences: enforce"

manifest_ttl() { manifest "$1" "$2" "$3" | sed 's/ttlSeconds: 600/ttlSeconds: 2592000/'; }
manifest sb-e-ok '["internal-git"]' "$POLICY" | "${KSA[@]}" create -f - >/dev/null
manifest sb-e-none '["internal-git"]' "" | "${KSA[@]}" create -f - >/dev/null
manifest sb-e-orphan '["internal-git"]' unsigned | "${KSA[@]}" create -f - >/dev/null
manifest sb-e-gap '["internal-git", "e2e"]' "$POLICY" | "${KSA[@]}" create -f - >/dev/null
manifest_ttl sb-e-ttl '["internal-git"]' "$POLICY" | "${KSA[@]}" create -f - >/dev/null
has_phase() { [ -n "$(field "$1" '.status.phase')" ]; }
has_verdict_claim_sb_e_ok() { "${K[@]}" -n "$NS" get virtualmachineclaim sb-e-ok >/dev/null 2>&1; }
for sb in sb-e-ok sb-e-none sb-e-orphan sb-e-gap sb-e-ttl; do
  wait_for "$TIMEOUT" "$sb with a phase" has_phase "$sb"
done
wait_for "$TIMEOUT" "sb-e-ok with a claim" has_verdict_claim_sb_e_ok
is_failed() { [ "$(field "$1" '.status.phase')" = Failed ]; }
refused() { # <sandbox> <reason substring>
  local reason phase
  wait_for "$TIMEOUT" "$1 Failed" is_failed "$1"
  reason=$(field "$1" '.status.reason'); phase=$(field "$1" '.status.phase')
  echo "$reason" | grep -qF "$2" || fail "$1: expected '$2' in the reason, got '$phase: $reason'"
  "${K[@]}" -n "$NS" get virtualmachineclaim "$1" >/dev/null 2>&1 && fail "$1 was refused and still has a claim"
  echo "$1: $reason (no claim)"
}
refused sb-e-none "policyRef is required"
refused sb-e-orphan "no verified bundle"
refused sb-e-gap "audience e2e is not configured"
refused sb-e-ttl "above the policy's lease"
"${K[@]}" -n "$NS" get virtualmachineclaim sb-e-ok >/dev/null 2>&1 || fail "sb-e-ok is conformant and was refused, or never got its claim"
[ "$(field sb-e-ok '.status.phase')" != Failed ] || fail "sb-e-ok failed: $(field sb-e-ok '.status.reason')"
wait_for "$TIMEOUT" "'claim refused' or the record of sb-e-ok" log_has "record created" "bundle_version=Some($V2)"
echo "enforce: four refusals with their reasons and no claim, the conformant sandbox admitted under v$V2"
for sb in sb-ok sb-gap sb-none sb-orphan; do
  "${K[@]}" -n "$NS" get virtualmachineclaim "$sb" >/dev/null 2>&1 || fail "$sb, created before enforce, lost its claim"
done
echo "the four claims made before enforce are untouched: a refusal is only before a claim exists"


say "ADR-0054: policy $OTHER in $NSP, a namespace the broker reads but $NS does not draw from"
"${K[@]}" delete namespace "$NSP" --ignore-not-found --wait=true >/dev/null
"${K[@]}" create namespace "$NSP" >/dev/null
"${K[@]}" -n "$NSP" apply -f dev/kind/notaio/notaio-bundles.yaml >/dev/null
mkdir -p "$STATE/policy-bundles-$NSP"
printf 'namespace: %s\nresources:\n  - ../../deploy/policy-bundles\n' "$NSP" > "$STATE/policy-bundles-$NSP/kustomization.yaml"
"${K[@]}" apply -k "$STATE/policy-bundles-$NSP" >/dev/null
policy_config "$NS, $NSP" "  egress: shadow"
# The same content as $POLICY, so a sandbox admitted under it has no gap.
"${K[@]}" -n "$NS" get exposureceiling "$POLICY" -o json \
  | jq --arg ns "$NSP" --arg n "$OTHER" '{apiVersion, kind, metadata: {name: $n, namespace: $ns}, spec}' \
  | "${K[@]}" apply -f - >/dev/null
"${K[@]}" -n "$NS" get sandboxpolicy "$POLICY" -o json \
  | jq --arg ns "$NSP" --arg n "$OTHER" '{apiVersion, kind, metadata: {name: $n, namespace: $ns}, spec}' \
  | "${K[@]}" apply -f - >/dev/null
other_published() { [ -n "$("${K[@]}" -n "$NSP" get configmap "$OTHER-bundle" -o jsonpath="{.metadata.annotations.$VERSION_ANN}" 2>/dev/null)" ]; }
wait_for "$TIMEOUT" "ConfigMap $NSP/$OTHER-bundle with a bundle version" other_published
wait_for "$TIMEOUT" "'policy bundle admitted' for $OTHER in the broker log" log_has "policy bundle admitted" "policy=$OTHER"

say "ADR-0054 shadow, no sources entry: P011, the sandbox still created, the log names where the policy is held"
manifest sb-elsewhere '["internal-git"]' "$OTHER" | "${KSA[@]}" create -f - >/dev/null
wait_for "$TIMEOUT" "sb-elsewhere with a claim and a PolicyConformant condition" has_verdict sb-elsewhere
expect sb-elsewhere "False Gaps" "P011"
[ -z "$(field sb-elsewhere '.status.reason')" ] || fail "sb-elsewhere refused in shadow: $(field sb-elsewhere '.status.reason')"
wait_for "$TIMEOUT" "the 'outside this sandbox's sources' line in the broker log" log_has "outside this sandbox's sources" "held_in=$NSP"
log_has "policy sources:" "namespace=$NS" || fail "no 'policy sources' start line for $NS"
echo "shadow: reported, nothing refused"

say "ADR-0054 enforce, no sources entry: refused before any claim, the same reason as a policy nowhere"
policy_config "$NS, $NSP" "  egress: enforce"
manifest sb-elsewhere-enf '["internal-git"]' "$OTHER" | "${KSA[@]}" create -f - >/dev/null
manifest sb-nowhere-enf '["internal-git"]' unsigned | "${KSA[@]}" create -f - >/dev/null
manifest sb-own-enf '["internal-git"]' "$POLICY" | "${KSA[@]}" create -f - >/dev/null
for sb in sb-elsewhere-enf sb-nowhere-enf; do
  wait_for "$TIMEOUT" "$sb Failed" is_failed "$sb"
  sleep 2
  "${K[@]}" -n "$NS" get virtualmachineclaim "$sb" >/dev/null 2>&1 && fail "$sb has a claim although its policy does not resolve"
  echo "$sb: $(field "$sb" '.status.reason')"
done
want="policy_not_resolved: no verified bundle for policy $OTHER in the namespaces $NS draws its policies from"
[ "$(field sb-elsewhere-enf '.status.reason')" = "$want" ] || fail "sb-elsewhere-enf: expected '$want'"
# Elsewhere and nowhere read alike once the name is swapped: the answer never says where
# else a policy exists.
[ "$(field sb-nowhere-enf '.status.reason' | sed "s/policy unsigned /policy $OTHER /")" = "$want" ] \
  || fail "the refusal for a policy nowhere differs from the one for a policy elsewhere"
field sb-elsewhere-enf '.status.reason' | grep -qF "$NSP" && fail "the reason names $NSP"
wait_for "$TIMEOUT" "sb-own-enf with a claim and a PolicyConformant condition" has_verdict sb-own-enf
expect sb-own-enf "True Conformant" "v"
echo "enforce: the other namespace's policy refused, the own namespace's admitted"

say "ADR-0054 enforce with policy.sources.$NS = [$NS, $NSP]: the same name admitted and recorded"
policy_config "$NS, $NSP" "$(printf '  egress: enforce\n  sources:\n    %s:\n      namespaces: [%s, %s]' "$NS" "$NS" "$NSP")"
log_has "policy sources:" "sources=$NS, $NSP" || fail "no 'policy sources' start line naming $NS, $NSP"
manifest sb-mapped '["internal-git"]' "$OTHER" | "${KSA[@]}" create -f - >/dev/null
wait_for "$TIMEOUT" "sb-mapped with a claim and a PolicyConformant condition" has_verdict sb-mapped
expect sb-mapped "True Conformant" "v"
[ -z "$(field sb-mapped '.status.reason')" ] || fail "sb-mapped refused: $(field sb-mapped '.status.reason')"
wait_for "$TIMEOUT" "'record created' for sb-mapped with a bundle version" log_has "record created" "bundle_version=Some("
echo "mapped: admitted under $NSP/$OTHER"

say "PASS: ADR-0026 holds against a real cluster (notaio from its release signing with OpenBao, the bundle admitted and recorded, the comparison's verdicts and codes, a newer version followed, a replay refused by the floor across a restart, nothing refused on the bundle's account), ADR-0053 phase 2 (under policy.audiences: enforce the bundle decides what a sandbox may have) and ADR-0054 (another namespace's policy P011 in shadow, refused under enforce with the reason of a policy nowhere, admitted once policy.sources maps it)"
