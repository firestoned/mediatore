#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# Write a kubeconfig whose only identity is a short-lived token for the broker's
# ServiceAccount, so the live tests run with exactly what production gets: the
# ClusterRole's verbs and the admission policy, never the admin credential.
#
#   sa-kubeconfig.sh <admin kubeconfig> <output path> [duration]
set -euo pipefail

ADMIN=${1:?admin kubeconfig}
OUT=${2:?output path}
DURATION=${3:-1h}
NS=banlieue-system
SA=mediatore

SERVER=$(kubectl --kubeconfig "$ADMIN" config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')
CA=$(kubectl --kubeconfig "$ADMIN" config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
TOKEN=$(kubectl --kubeconfig "$ADMIN" -n "$NS" create token "$SA" --duration="$DURATION")
[ -n "$SERVER" ] && [ -n "$CA" ] && [ -n "$TOKEN" ] || { echo "could not assemble the ServiceAccount kubeconfig" >&2; exit 1; }

umask 077
cat > "$OUT" <<YAML
apiVersion: v1
kind: Config
clusters:
  - name: cluster
    cluster:
      server: $SERVER
      certificate-authority-data: $CA
users:
  - name: $SA
    user:
      token: $TOKEN
contexts:
  - name: $SA
    context:
      cluster: cluster
      user: $SA
current-context: $SA
YAML
echo "wrote $OUT for system:serviceaccount:$NS:$SA ($DURATION)"
