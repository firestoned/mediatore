#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# ADR-0012 against a real PostgreSQL (`make kind-e2e-store`): the broker from deploy/base
# runs on the PostgreSQL in kind over TLS the client verifies (sslmode=verify-full against
# the tier's CA), and the store conformance suite runs against that same database through a
# port-forward, so the one query set is proven on PostgreSQL and not only on SQLite.
#
#   store-e2e.sh <admin kubeconfig> <ca pem>
set -euo pipefail
cd "$(dirname "$0")/../.."

ADMIN_KUBECONFIG=${1:?admin kubeconfig}
CA_PEM=$(cd "$(dirname "${2:?ca pem}")" && pwd)/$(basename "$2")
K=(kubectl --kubeconfig "$ADMIN_KUBECONFIG")
BROKER_NS=banlieue-system
PORT=${MEDIATORE_KIND_PG_PORT:-15432}
TIMEOUT=${MEDIATORE_KIND_TIMEOUT:-120}

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; exit 1; }
plain() { sed "s/$(printf '\033')\[[0-9;]*m//g"; }

PF_PID=""
cleanup() { [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true; }
trap cleanup EXIT

say "broker: running on PostgreSQL over verify-full"
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=60s >/dev/null
"${K[@]}" -n "$BROKER_NS" logs deploy/mediatore 2>/dev/null | plain | grep -F "store: migrated and connected" | grep -q "engine=Postgres" \
  || fail "the broker did not report a migrated PostgreSQL store"
"${K[@]}" -n "$BROKER_NS" logs deploy/mediatore 2>/dev/null | plain | grep -q "e2e@" && fail "the store password reached the broker log"
echo "migrated and connected; the URL is not in the log"

say "conformance: the store suite against the kind PostgreSQL"
"${K[@]}" -n "$BROKER_NS" port-forward svc/mediatore-postgres "$PORT:5432" >/dev/null 2>&1 &
PF_PID=$!
for ((i = 0; i < TIMEOUT; i++)); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then break; fi
  sleep 1
done
# `localhost` is in the certificate's names; the port-forward answers there. The cases
# share one database and each starts by emptying it, so they run one at a time.
MEDIATORE_LIVE_STORE_URL="postgres://mediatore:e2e@localhost:$PORT/mediatore?sslmode=verify-full&sslrootcert=$CA_PEM" \
  cargo test -q -p mediatore-store --lib -- --ignored --test-threads=1 sql::tests::postgres 2>&1 | tail -40
echo "the conformance suite holds on PostgreSQL over TLS"

say "PASS: ADR-0012 holds against a real PostgreSQL (verify-full, migrations, the conformance suite)"
