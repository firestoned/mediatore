#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# ADR-0075 on a real API server (`make kind-e2e-entries`): the ClusterSPIFFEID admission
# policy (deploy/base/admission/clusterspiffeid.yaml) judged by server-side dry runs as an
# administrator, after `make kind-deploy` applied it with the kind binding
# (dev/kind/broker/clusterspiffeid-fixtures.yaml). Nothing is ever created.
#
#   clusterspiffeid-admission.sh <admin kubeconfig> [seconds to wait for enforcement]
#
# Admitted: the SPIRE chart's template, the base's own ClusterSPIFFEID under another name,
# a spec-changing update of each ClusterSPIFFEID the chart installed, an excluded fixture's
# name with a reserved template. Refused: a claim's, a node's and the gateways' two paths,
# the live annotation template of 2026-11-27, a templated first segment, /mediatore for
# another namespace or as a sub-path, and an update of a chart object to a reserved path.
set -euo pipefail
cd "$(dirname "$0")/../.."

KUBECONFIG_PATH=${1:?admin kubeconfig}
DEADLINE=${2:-60}
K=(kubectl --kubeconfig "$KUBECONFIG_PATH")
POLICY=mediatore-clusterspiffeid
CLAIM_UID=6b0a3e9c-1f4d-4c2e-9a7b-0d1e2f3a4b5c
EK_HASH=$(printf 'ec%062x' 7)
# Single-quoted in the YAML below, so the double quotes stay.
ANNOTATION='spiffe://{{ .TrustDomain }}{{ index .PodMeta.Annotations "x/id" }}'
CHART='spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}'

fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

# A dry-run create of a ClusterSPIFFEID named $1 with template $2; the API server's answer.
create() {
  "${K[@]}" create --dry-run=server -o name -f - 2>&1 <<YAML || true
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: $1
spec:
  className: spire-server-spire
  spiffeIDTemplate: '$2'
  podSelector:
    matchLabels: { mediatore.dev/e2e-role: admission-probe }
YAML
}

# The base's own object, renamed, its namespace optionally replaced, its template optionally
# replaced: what a second /mediatore would look like.
broker_like() {
  local name=$1 ns=${2:-mediatore-system} path=${3:-/mediatore}
  sed -e "s/^  name: mediatore\$/  name: $name/" \
      -e "s/kubernetes.io\/metadata.name: mediatore-system/kubernetes.io\/metadata.name: $ns/" \
      -e "s|{{ .TrustDomain }}/mediatore\"|{{ .TrustDomain }}$path\"|" \
      deploy/base/clusterspiffeid.yaml |
    "${K[@]}" create --dry-run=server -o name -f - 2>&1 || true
}

admitted() {
  local what=$1 out=$2
  if grep -q "$POLICY" <<<"$out"; then fail "$what was refused by $POLICY: $out"; fi
  # AlreadyExists is decided after admission: the fixture exists from an earlier tier.
  # `-o name` prints the object's name alone on a dry-run create; a patch adds "patched".
  if ! grep -Eq '^clusterspiffeid\.spire\.spiffe\.io/[a-z0-9.-]+( (patched|created)( \(server dry run\))?)?$|AlreadyExists|already exists' <<<"$out"; then
    fail "$what: unexpected answer: $out"
  fi
  echo "✓ admitted: $what"
}

refused() {
  local what=$1 out=$2
  grep -q "ValidatingAdmissionPolicy '$POLICY'" <<<"$out" || fail "$what was not refused by $POLICY: $out"
  echo "✓ refused:  $what"
}

for ((i = 0; i < DEADLINE; i++)); do
  out=$(create admission-probe-settle "$ANNOTATION")
  grep -q "ValidatingAdmissionPolicy '$POLICY'" <<<"$out" && break
  sleep 1
done
grep -q "ValidatingAdmissionPolicy '$POLICY'" <<<"$out" \
  || fail "the ClusterSPIFFEID policy is not enforced after ${DEADLINE}s; last answer: $out"
echo "✓ the ClusterSPIFFEID admission policy is enforced"

admitted "the chart's ns/sa template" "$(create admission-probe-chart "$CHART")"
admitted "a literal first segment that is not reserved" "$(create admission-probe-workload 'spiffe://{{ .TrustDomain }}/workload/{{ .PodMeta.Name }}')"
admitted "the base's broker ClusterSPIFFEID, renamed" "$(broker_like admission-probe-broker)"
admitted "an excluded fixture with a claim's path (the kind binding)" \
  "$(create mediatore-e2e-gateway-claim-b "spiffe://{{ .TrustDomain }}/banlieue/claim/$CLAIM_UID")"

refused "a claim's path" "$(create admission-probe-claim "spiffe://{{ .TrustDomain }}/banlieue/claim/$CLAIM_UID")"
refused "a node's path" "$(create admission-probe-node "spiffe://{{ .TrustDomain }}/banlieue/node/$EK_HASH")"
refused "the gateway listeners' path" "$(create admission-probe-gateway 'spiffe://{{ .TrustDomain }}/gateway')"
refused "the gateway authorizer's path" "$(create admission-probe-authorizer 'spiffe://{{ .TrustDomain }}/gateway/authorizer')"
refused "the path from a pod annotation (the live template)" "$(create admission-probe-annotation "$ANNOTATION")"
refused "a templated first segment" "$(create admission-probe-templated 'spiffe://{{ .TrustDomain }}/{{ .PodMeta.Namespace }}/x')"
refused "/mediatore for another namespace" "$(broker_like admission-probe-broker-elsewhere default)"
refused "a path under /mediatore" "$(broker_like admission-probe-broker-sub mediatore-system /mediatore/x)"

# UPDATE: each ClusterSPIFFEID the chart installed, with a spec that changes (an unchanged
# spec is not judged), admitted; the same object moved to a claim's path, refused.
chart=$("${K[@]}" get clusterspiffeids -o json |
  jq -r '.items[] | select(.metadata.name | startswith("spire-server-")) | .metadata.name')
[ -n "$chart" ] || fail "no ClusterSPIFFEID of the SPIRE chart to update"
for name in $chart; do
  admitted "an update of $name" \
    "$("${K[@]}" patch clusterspiffeid "$name" --type merge -p '{"spec":{"hint":"admission-probe"}}' --dry-run=server 2>&1 || true)"
done
first=$(head -1 <<<"$chart")
refused "an update of $first to a claim's path" \
  "$("${K[@]}" patch clusterspiffeid "$first" --type merge -p "{\"spec\":{\"spiffeIDTemplate\":\"spiffe://{{ .TrustDomain }}/banlieue/claim/$CLAIM_UID\"}}" --dry-run=server 2>&1 || true)"

echo "PASS: ClusterSPIFFEID admission (ADR-0075)"
