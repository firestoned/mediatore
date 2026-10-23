#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# Wait until the API server enforces deploy/base's ClusterStaticEntry admission policy
# for the broker's ServiceAccount. `kubectl apply` returns when the policy and its
# binding are stored; the admission plugin picks them up a moment later, and a live
# test that creates a forbidden entry in that moment sees it admitted. The probe is a
# server-side dry run, as the ServiceAccount, of an entry the policy's first rule
# refuses (its name does not start with mediatore-); nothing is ever created.
#
#   admission-settled.sh <ServiceAccount kubeconfig> <trust domain> [seconds]
set -euo pipefail

SA_KUBECONFIG=${1:?ServiceAccount kubeconfig}
TD=${2:?trust domain}
DEADLINE=${3:-60}
ZEROS=0000000000000000000000000000000000000000000000000000000000000000

probe() {
  kubectl --kubeconfig "$SA_KUBECONFIG" create --dry-run=server -f - 2>&1 <<YAML || true
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterStaticEntry
metadata:
  name: admission-probe
spec:
  spiffeID: spiffe://$TD/banlieue/claim/00000000-0000-4000-8000-000000000000
  parentID: spiffe://$TD/spire/agent/tpm/$ZEROS
  selectors: ["unix:user:sb-000000000000"]
  className: spire-server-spire
YAML
}

for ((i = 0; i < DEADLINE; i++)); do
  out=$(probe)
  if grep -q 'named mediatore-\*' <<<"$out"; then
    echo "✓ admission policy enforced for the broker's ServiceAccount"
    exit 0
  fi
  sleep 1
done
echo "ERROR: the ClusterStaticEntry admission policy is not enforced after ${DEADLINE}s; last answer:" >&2
echo "$out" >&2
exit 1
