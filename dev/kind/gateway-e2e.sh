#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# ADR-0028 against a real Envoy and a real SPIRE (`make kind-e2e-gateway`): the gateway
# pod from dev/kind/gateway (Envoy on the gateway SVID over SDS, mediatore gateway beside
# it), the broker from deploy/base, and claim-side pods shaped like a sandbox VM: the real
# `mediatore egress-proxy` as a sidecar with a claim SVID the real agent issued, its
# forwarder tunnelling every upstream through the gateway (ADR-0028 decision 3, ADR-0027
# decision 8), and a workload beside it with no socket and no route of its own, driving the
# proxy as the jail does (the testkit's probe in its via-proxy mode). A sandbox is created
# and bound as in the sandbox tier, so the broker has a live claim whose allowlist is one
# destination, a TLS server on the fixture CA `make kind-gateway` minted.
#
#   gateway-e2e.sh <admin kubeconfig> <broker SA kubeconfig> <trust domain> <ek pem> <ek hash file> <destination ca pem> [<state dir>]
#
# With a state dir (`make kind-e2e-gateway-policy`, ADR-0030), the same run goes under a
# policy: notaio publishes a bundle for the claim's policy whose direct `egress[]` names the
# destination's second port and an entry with rules; the broker, trusting notaio's key, runs
# in `policy.egress: shadow` first, so the second port stays refused at the gateway while the
# broker logs what it would have added and the sandbox reports P006; then in `enforce`, so a
# tunnel to the second port opens and the destination answers through it, the entry with
# rules is still refused (P007) and the audience endpoints stand. The rest of the run is the
# same in both modes, which is what "shadow serves today's answer" means.
#
# What it proves: the workload's request reaches its one destination through the proxy's
# tunnel, with the STS token swapped in, and the destination answers; a second host and a
# second port are refused by the authorizer and the workload sees 502 gateway_refused with
# the code in the proxy's log; a proxy holding a node SVID is refused by Envoy's validator
# before any check and the workload sees 502 gateway_unreachable; with the broker gone the
# cached allowlist stands in until the stale bound and then the outage is a refusal; a
# released claim is cut off once its answer is stale; the logs (Envoy's access log, the
# authorizer's decisions, the proxy's forwards, the destination's requests) agree on who
# reached what.
set -euo pipefail
cd "$(dirname "$0")/../.."

ADMIN_KUBECONFIG=${1:?admin kubeconfig}
SA_KUBECONFIG=${2:?broker ServiceAccount kubeconfig}
TD=${3:?trust domain}
EK_PEM=${4:?ek pem}
EK_HASH=$(tr -d '\n' < "${5:?ek hash file}")
DEST_CA_PEM=${6:?destination ca pem}
# Set: the ADR-0030 stages, with notaio's key in <state dir>/notaio/public-key.txt.
POLICY_STATE=${7:-}
K=(kubectl --kubeconfig "$ADMIN_KUBECONFIG")
KSA=(kubectl --kubeconfig "$SA_KUBECONFIG")
BROKER_NS=banlieue-system
NS=mediatore-e2e-gateway
ISSUER=https://issuer.example.com
TIMEOUT=${MEDIATORE_KIND_TIMEOUT:-180}
ENTRY_SELECTOR=app.kubernetes.io/managed-by=mediatore
GATEWAY=gateway.$NS.svc.cluster.local:8443
DEST_HOST=destination.$NS.svc.cluster.local
DESTINATION=$DEST_HOST:8443
# ADR-0030: the destination's second port, a policy's direct egress entry the gateway can
# enforce exactly; and one it cannot (rules), never served.
DIRECT=$DEST_HOST:8081
RULED=only-some.$NS.svc.cluster.local:443
POLICY=e2e-gateway
BUNDLE_CM=$POLICY-bundle
VERSION_ANN='sandbox\.firestoned\.io/bundle-version'
PROXY=http://127.0.0.1:3128
# The phantom the workload presents (ADR-0025 decision 3); a fixture, never a secret.
PHANTOM=e2e-phantom-0123456789abcdef0123456789abcdef
# What the authorizer in dev/kind/gateway/gateway.yaml runs with.
FRESH_SECS=5
STALE_SECS=120

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
[ -z "$POLICY_STATE" ] || [ -f "$POLICY_STATE/notaio/public-key.txt" ] || { echo "no $POLICY_STATE/notaio/public-key.txt: run make kind-notaio first" >&2; exit 1; }

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; dump; exit 1; }
plain() { sed "s/$(printf '\033')\[[0-9;]*m//g"; }

broker_pod()  { "${K[@]}" -n "$BROKER_NS" get pods -l app.kubernetes.io/name=mediatore -o json 2>/dev/null | jq -r '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")] | sort_by(.metadata.creationTimestamp) | last | select(. != null) | "pod/" + .metadata.name'; }
BROKER_POD=""
broker_logs() { [ -n "$BROKER_POD" ] && "${K[@]}" -n "$BROKER_NS" logs "$BROKER_POD" 2>/dev/null | plain || true; }
envoy_logs()  { "${K[@]}" -n "$NS" logs deploy/gateway -c envoy 2>/dev/null || true; }
# The authorizer's and the proxy's string fields print quoted (tracing's Debug form);
# the quotes are dropped so a field can be matched as key=value.
authz_logs()  { "${K[@]}" -n "$NS" logs deploy/gateway -c authorizer 2>/dev/null | plain | tr -d '"' || true; }
dest_logs()   { "${K[@]}" -n "$NS" logs deploy/destination -c destination 2>/dev/null || true; }
direct_logs() { "${K[@]}" -n "$NS" logs deploy/destination -c direct 2>/dev/null || true; }
pod_logs()    { "${K[@]}" -n "$NS" logs "pod/$1" -c workload 2>/dev/null | plain || true; }
proxy_logs()  { "${K[@]}" -n "$NS" logs "pod/$1" -c proxy 2>/dev/null | plain | tr -d '"' || true; }
node_logs()   { "${K[@]}" -n "$NS" logs pod/node 2>/dev/null | plain || true; }
pod_phase()   { "${K[@]}" -n "$NS" get pod "$1" -o jsonpath='{.status.phase}' 2>/dev/null || true; }
entries()     { "${K[@]}" get clusterstaticentries -l "$ENTRY_SELECTOR" -o jsonpath='{range .items[*]}{.metadata.name} {.spec.spiffeID}{"\n"}{end}' 2>/dev/null || true; }
sandbox()     { "${K[@]}" -n "$NS" get agentsandbox "$1" -o json 2>/dev/null || true; }
field()       { sandbox "$1" | jq -r "$2 // empty"; }
verdict()     { sandbox "$1" | jq -r '.status.conditions[]? | select(.type == "PolicyConformant") | "\(.status) \(.reason) \(.message)"'; }
verdict_has() { verdict sb-gw | grep -F "$1" | grep -qF "${2:-}"; }
bundle_version() { "${K[@]}" -n "$NS" get configmap "$BUNDLE_CM" -o jsonpath="{.metadata.annotations.$VERSION_ANN}" 2>/dev/null || true; }

PROBES=(probe-claim probe-node probe-enforce probe-warm probe-outage-1 probe-outage-2 probe-released)

dump() {
  printf '\n--- broker (last 40 lines)\n'; broker_logs | tail -40
  printf '\n--- envoy (last 40 lines)\n'; envoy_logs | tail -40
  printf '\n--- authorizer (last 40 lines)\n'; authz_logs | tail -40
  printf '\n--- destination (last 20 lines)\n'; dest_logs | tail -20
  if [ -n "$POLICY_STATE" ]; then
    printf '\n--- destination, direct port (last 10 lines)\n'; direct_logs | tail -10
    printf '\n--- sb-gw verdict: %s\n' "$(verdict sb-gw)"
    printf '\n--- notaio (last 20 lines)\n'; "${K[@]}" -n notaio-system logs deploy/notaio --tail=20 2>/dev/null | plain || true
  fi
  printf '\n--- %s pods\n' "$NS"; "${K[@]}" -n "$NS" get pods -o wide 2>/dev/null || true
  for p in "${PROBES[@]}"; do
    printf '\n--- %s (workload)\n' "$p"; pod_logs "$p" | tail -12
    printf '\n--- %s (proxy)\n' "$p"; proxy_logs "$p" | tail -12
  done
}

FILES=$(mktemp -d)
cleanup() {
  rm -rf "$FILES"
  "${K[@]}" -n "$NS" delete agentsandbox --all --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" -n "$NS" delete pod node "${PROBES[@]}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" -n "$NS" delete configmap forward-files --ignore-not-found >/dev/null 2>&1 || true
  "${K[@]}" delete clusterspiffeid mediatore-e2e-gateway-node mediatore-e2e-gateway-claim --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" -n "$BROKER_NS" scale deploy/mediatore --replicas=1 >/dev/null 2>&1 || true
}
# At the end only (cleanup also runs mid-script, for a clean slate): the policy fixtures
# removed and the broker's configuration as the overlay ships it, for the tiers after this one.
policy_teardown() {
  [ -n "$POLICY_STATE" ] || return 0
  "${K[@]}" -n "$NS" delete sandboxpolicy "$POLICY" exposureceiling "$POLICY" configmap "$BUNDLE_CM" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" apply -k dev/kind/broker >/dev/null 2>&1 || true
  "${K[@]}" -n "$BROKER_NS" rollout restart deploy/mediatore >/dev/null 2>&1 || true
  "${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=120s >/dev/null 2>&1 || true
}
trap 'cleanup; policy_teardown' EXIT

wait_for() { # <seconds> <description> <command...>
  local secs=$1 what=$2 i; shift 2
  for ((i = 0; i < secs; i++)); do "$@" && return 0; sleep 1; done
  fail "$what not seen within ${secs}s"
}
log_has() { broker_logs | grep -F "$1" | grep -qF "${2:-}"; }
# A line of a log carrying every fragment given. Used through wait_for: Envoy writes a
# tunnel's access-log line when the stream ends and kubectl shows it a moment later, which
# a one-shot grep lost on a slow runner (CI, 2026-11-04).
envoy_has() { envoy_logs | grep -F "$1" | grep -F "${2:-}" | grep -qF "${3:-}"; }
authz_has() { authz_logs | grep -F "$1" | grep -F "${2:-}" | grep -qF "${3:-}"; }
dest_has()  { dest_logs | grep -F "$1" | grep -qF "${2:-}"; }
direct_has() { direct_logs | grep -F "$1" | grep -qF "${2:-}"; }
proxy_has() { proxy_logs "$1" | grep -F "$2" | grep -qF "${3:-}"; }
LOG_WAIT=30
wait_for_end() {
  local pod=$1 i
  for ((i = 0; i < TIMEOUT; i++)); do
    case "$(pod_phase "$pod")" in Succeeded|Failed) return 0 ;; esac
    sleep 1
  done
  fail "$pod: still running after ${TIMEOUT}s"
}
# A sandbox-shaped pod with role label <role>: the real egress proxy as a sidecar (the
# claim SVID through the CSI volume, the routes, the gateways and the phantom from the
# ConfigMap, its forwarder dialling the gateway) and the workload beside it with no socket,
# driving the proxy through the checks given. <credential> is `phantom` to present the
# phantom on every request or `bare` to send none. Waits for the pod to end and shows the
# workload's lines.
probe() { # <name> <role label> <credential> <check>...
  local name=$1 role=$2 credential=$3; shift 3
  local args="" phantom_arg=""
  for c in "$@"; do args="$args
        - --check
        - \"$c\""
  done
  [ "$credential" = phantom ] && phantom_arg="
        - --phantom-file
        - /etc/forward/phantom"
  "${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $name
  namespace: $NS
  labels: { mediatore.dev/e2e-role: $role }
  annotations: { kubectl.kubernetes.io/default-container: workload }
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: { type: RuntimeDefault }
  initContainers:
    # The egress proxy as a native sidecar: up before the workload, ended with the pod.
    - name: proxy
      image: ghcr.io/firestoned/mediatore:kind
      imagePullPolicy: Never
      restartPolicy: Always
      command:
        - /usr/bin/mediatore
        - egress-proxy
        - --listen
        - 127.0.0.1:3128
        - --mediatore-url
        - https://mediatore-sandbox.banlieue-system.svc
        - --routes
        - /etc/forward/routes.json
        - --gateways
        - /etc/forward/gateways.json
        - --phantom-file
        - /etc/forward/phantom
      env:
        - { name: SPIFFE_ENDPOINT_SOCKET, value: "unix:///run/spire/sockets/spire-agent.sock" }
        - { name: RUST_LOG, value: "info" }
      volumeMounts:
        - { name: spire-agent-socket, mountPath: /run/spire/sockets, readOnly: true }
        - { name: forward-files, mountPath: /etc/forward, readOnly: true }
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
  containers:
    # The workload: no Workload API socket, no broker, the proxy on loopback and the phantom.
    - name: workload
      image: localhost/mediatore-e2e:kind
      imagePullPolicy: Never
      command:
        - /usr/bin/gateway-probe
        - via-proxy
        - --proxy
        - "$PROXY"$phantom_arg$args
      volumeMounts:
        - { name: forward-files, mountPath: /etc/forward, readOnly: true }
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
  volumes:
    - name: spire-agent-socket
      csi: { driver: csi.spiffe.io, readOnly: true }
    - name: forward-files
      configMap: { name: forward-files }
YAML
  wait_for_end "$name"
  pod_logs "$name" | grep -F "probe " || true
  [ "$(pod_phase "$name")" = Succeeded ] || fail "$name did not end as expected"
}

# ADR-0030: the broker's configuration with a `policy` section trusting notaio's key, the
# bundles read from this namespace, the switch as given; applied and the broker restarted.
broker_policy_config() { # <shadow|enforce>
  local key_id public_key
  read -r key_id public_key < "$POLICY_STATE/notaio/public-key.txt"
  {
    cat dev/kind/broker/mediatore.yaml
    printf 'policy:\n  trusted_keys:\n    - { id: "%s", public_key: "%s" }\n  namespaces: [%s]\n  egress: %s\n' "$key_id" "$public_key" "$NS" "$1"
  } > "$FILES/mediatore.yaml"
  "${K[@]}" -n "$BROKER_NS" create configmap mediatore-config --from-file=mediatore.yaml="$FILES/mediatore.yaml" \
    --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
  "${K[@]}" -n "$BROKER_NS" rollout restart deploy/mediatore >/dev/null
  "${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=120s >/dev/null
  BROKER_POD=$(broker_pod)
  [ -n "$BROKER_POD" ] || fail "no Running broker pod in $BROKER_NS"
  wait_for "$TIMEOUT" "'policy bundle reflector running' in the broker log" log_has "policy bundle reflector running"
  # The mode is read off the log, never inferred from the start succeeding.
  wait_for "$TIMEOUT" "'policy.egress' mode=$1 in the broker log" log_has "policy.egress" "mode=$1"
}

if [ -n "$POLICY_STATE" ]; then
  say "policy (ADR-0030): notaio's bundle Role and the broker's read Role in $NS; the broker in policy.egress: shadow"
  "${K[@]}" -n "$NS" delete sandboxpolicy "$POLICY" exposureceiling "$POLICY" configmap "$BUNDLE_CM" --ignore-not-found --wait=true >/dev/null
  "${K[@]}" -n "$NS" apply -f dev/kind/notaio/notaio-bundles.yaml >/dev/null
  mkdir -p "$POLICY_STATE/policy-bundles"
  printf 'namespace: %s\nresources:\n  - ../../deploy/policy-bundles\n' "$NS" > "$POLICY_STATE/policy-bundles/kustomization.yaml"
  "${K[@]}" apply -k "$POLICY_STATE/policy-bundles" >/dev/null
  broker_policy_config shadow
  echo "reflector running on ${BROKER_POD#pod/}, switch shadow"

  say "policy (ADR-0030): the claim's policy, its audience exactly the broker's, two direct egress entries ($DIRECT; $RULED with rules)"
  "${K[@]}" -n "$NS" apply -f - >/dev/null <<YAML
apiVersion: sandbox.firestoned.io/v1alpha2
kind: ExposureCeiling
metadata:
  name: $POLICY
spec:
  audiences:
    - name: e2e-egress
      access: Read
      maxTtlSeconds: 900
      endpoints: ["$DESTINATION"]
  egressHosts: ["$DIRECT", "$RULED"]
  tools: []
  maxLeaseSeconds: 3600
  approvals:
    - role: Security
      reference: https://github.com/firestoned/mediatore/pull/1
---
apiVersion: sandbox.firestoned.io/v1alpha2
kind: SandboxPolicy
metadata:
  name: $POLICY
spec:
  # lab: the one profile that admits rules on a direct egress entry (K4.1 R2), which the
  # gateway cannot enforce and the broker never serves (decision 3, P007).
  profileRef: lab
  subjects:
    groups: ["00000000-0000-0000-0000-000000000000"]
  audiences:
    - name: e2e-egress
      access: Read
      scopes: ["e2e:read"]
      ttlSeconds: 900
      endpoints: ["$DESTINATION"]
      rules: []
  egress:
    - { endpoint: "$DIRECT", rules: [] }
    - endpoint: "$RULED"
      rules:
        - { method: GET, path: "/only/**" }
  tools: []
  lease:
    maxDurationSeconds: 3600
    maxConcurrent: 1
YAML
  published() { [ -n "$(bundle_version)" ]; }
  wait_for "$TIMEOUT" "ConfigMap $BUNDLE_CM with a bundle version" published
  BUNDLE_V=$(bundle_version)
  wait_for "$TIMEOUT" "'policy bundle admitted' version=$BUNDLE_V in the broker log" log_has "policy bundle admitted" "version=$BUNDLE_V"
  echo "bundle v$BUNDLE_V of $NS/$POLICY published by notaio and admitted by the broker"
fi

say "broker: the watcher Lease is held by the running pod"
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=60s >/dev/null
BROKER_POD=$(broker_pod)
[ -n "$BROKER_POD" ] || fail "no Running broker pod in $BROKER_NS"
holder_is_pod() { [ "$("${K[@]}" -n "$BROKER_NS" get lease mediatore-watcher -o jsonpath='{.spec.holderIdentity}' 2>/dev/null)" = "${BROKER_POD#pod/}" ]; }
wait_for "$TIMEOUT" "lease mediatore-watcher held by ${BROKER_POD#pod/}" holder_is_pod
wait_for "$TIMEOUT" "'claim watcher running' in the broker log" log_has "claim watcher running"
echo "held by ${BROKER_POD#pod/}; controllers running"

say "gateway: Envoy on the gateway SVID over SDS, the authorizer beside it, the TLS destination behind it"
"${K[@]}" -n "$NS" rollout status deploy/gateway --timeout=120s >/dev/null
"${K[@]}" -n "$NS" rollout status deploy/destination --timeout=120s >/dev/null
authz_up() { authz_logs | grep -qF "gateway authorizer listening"; }
wait_for "$TIMEOUT" "'gateway authorizer listening' in the authorizer log" authz_up
authz_logs | grep -F "gateway SVID from the Workload API" | grep -qF "spiffe_id=spiffe://$TD/gateway" || fail "the authorizer did not get spiffe://$TD/gateway"
envoy_ready() { envoy_logs | grep -qE "all dependencies initialized|starting main dispatch loop"; }
wait_for "$TIMEOUT" "Envoy's main dispatch loop" envoy_ready
dest_logs | grep -F "destination listening" | grep -qF "tls=true" || fail "the destination is not serving TLS"
echo "authorizer as spiffe://$TD/gateway; Envoy up on its bootstrap; the destination on the fixture CA"

say "fixtures: a clean slate, then the node pod registering the fixture EK, a sandbox bound to it"
cleanup
FILES=$(mktemp -d)
"${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=true >/dev/null

say "the proxy's files: the routes (the destination on the fixture CA, two more the gateway will refuse), the gateway list, the phantom"
# What the guest writes for the proxy from GET /v1/me (ADR-0025, ADR-0028): here by hand,
# since the proxy runs in a pod with the claim's SVID and not on the node that fetched
# the subject. The two extra routes exist so the proxy admits the requests and the
# gateway, not the proxy, is what refuses them.
# The second port is the bundle's direct egress entry: its route is the shape the broker
# renders for one under ADR-0030's enforce (ADR-0025 decision 8: no audience, no rules,
# credential none, the phantom dropped), with the fixture CA kept so the proxy reaches the
# destination's TLS. The ruled host is a route the gateway refuses in every mode.
jq -n --arg ca "$(cat "$DEST_CA_PEM")" --arg host "$DEST_HOST" --arg ruled "${RULED%:*}" '[
  { audience: "e2e-egress", endpoint: { host: $host, port: 8443 }, rules: [], ca_pem: $ca },
  { audience: "e2e-egress", endpoint: { host: "elsewhere.example.com", port: 443 }, rules: [] },
  { endpoint: { host: $host, port: 8081 }, rules: [], ca_pem: $ca, credential: "none" },
  { audience: "e2e-egress", endpoint: { host: $ruled, port: 443 }, rules: [] }
]' > "$FILES/routes.json"
jq -n --arg host "gateway.$NS.svc.cluster.local" '[ { host: $host, port: 8443 } ]' > "$FILES/gateways.json"
printf '%s' "$PHANTOM" > "$FILES/phantom"
"${K[@]}" -n "$NS" create configmap forward-files --from-file="$FILES/routes.json" --from-file="$FILES/gateways.json" --from-file="$FILES/phantom" --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
echo "routes: 4 (the destination's two ports with the CA), gateways: 1 ($GATEWAY)"

"${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: mediatore-e2e-gateway-node
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
"${KSA[@]}" create -f - >/dev/null <<YAML
apiVersion: mediatore.io/v1alpha1
kind: AgentSandbox
metadata:
  name: sb-gw
  namespace: $NS
spec:
  subject: { issuer: "$ISSUER", id: "octocat" }
  poolRef: { name: e2e }
  ttlSeconds: 900
  audiences: ["e2e-egress"]
  workload: { image: "registry.internal:5000/sandbox:e2e", args: ["sh"] }
$( [ -n "$POLICY_STATE" ] && printf '  policyRef: { name: %s }\n' "$POLICY" )
YAML
has_claim() { "${K[@]}" -n "$NS" get virtualmachineclaim sb-gw >/dev/null 2>&1; }
wait_for "$TIMEOUT" "claim sb-gw" has_claim
CLAIM_UID=$("${K[@]}" -n "$NS" get virtualmachineclaim sb-gw -o jsonpath='{.metadata.uid}')
wait_for "$TIMEOUT" "'record created' in the broker log" log_has "record created" "$CLAIM_UID"
jq -Rs '{status: {phase: "Bound", virtualMachineRef: {name: "member-1"}, tpmEndorsementCertificates: [.], boundAt: "2026-11-04T10:00:00Z", expiresAt: "2026-11-04T10:15:00Z"}}' < "$EK_PEM" \
  | "${K[@]}" -n "$NS" patch virtualmachineclaim sb-gw --subresource=status --type=merge --patch-file=/dev/stdin >/dev/null
ready() { [ "$(field sb-gw '.status.ready')" = "true" ] && [ "$(field sb-gw '.status.phase')" = "Bound" ]; }
wait_for "$TIMEOUT" "sb-gw Ready" ready
echo "claim $CLAIM_UID bound; its allowlist is $DESTINATION (audience e2e-egress)"
if [ -n "$POLICY_STATE" ]; then
  wait_for "$TIMEOUT" "sb-gw's PolicyConformant with P006 under shadow" verdict_has "False Gaps" "P006 the bundle holds 2 direct egress entries"
  verdict sb-gw | grep -F "P00" | grep -vF "P006" | grep -q . && fail "a gap other than P006 under shadow: $(verdict sb-gw)"
  echo "under shadow: $(verdict sb-gw)"
fi

say "claim SVID: a fixture entry for spiffe://$TD/banlieue/claim/$CLAIM_UID (on a VM, the broker's entry)"
"${K[@]}" apply -f - >/dev/null <<YAML
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: mediatore-e2e-gateway-claim
spec:
  className: spire-server-spire
  spiffeIDTemplate: "spiffe://{{ .TrustDomain }}/banlieue/claim/$CLAIM_UID"
  podSelector:
    matchLabels: { mediatore.dev/e2e-role: claim }
  namespaceSelector:
    matchLabels: { kubernetes.io/metadata.name: $NS }
  ttl: 1h
YAML

say "the claim: its destination answers through the tunnel with the token swapped in; another host and another port are refused by the gateway"
probe probe-claim claim phantom \
  "$DESTINATION=200" \
  "elsewhere.example.com:443=502:gateway_refused" \
  "$DEST_HOST:8081=502:gateway_refused" \
  "$DESTINATION=200"
pod_logs probe-claim | grep -F "status=200" | grep -qF "destination reached: host=$DESTINATION" || fail "the destination did not answer through the tunnel"
wait_for "$LOG_WAIT" "the proxy taking the gateway list" proxy_has probe-claim "upstreams are tunnelled through the egress gateways" "gateway_id=spiffe://$TD/gateway"
wait_for "$LOG_WAIT" "a forward through the gateway with the credential in the proxy's log" proxy_has probe-claim "forwarded" "via=$GATEWAY"
proxy_logs probe-claim | grep -F "forwarded" | grep -F "via=$GATEWAY" | grep -qF "credential=true" || fail "the forward through the gateway did not carry the credential"
wait_for "$LOG_WAIT" "the gateway's not_allowed in the proxy's log" proxy_has probe-claim "the gateway refused the tunnel" "403 not_allowed"
wait_for "$LOG_WAIT" "the token fetched over the claim SVID in the proxy's log" proxy_has probe-claim "token fetched for the proxy" "e2e-egress"
echo "two tunnels to $DESTINATION with the token swapped in; the other two refused with not_allowed, 502 gateway_refused at the workload"

say "the logs agree: Envoy's access log, the authorizer's decisions, the destination's requests"
wait_for "$LOG_WAIT" "Envoy's access-log line for the opened tunnel" envoy_has "tunnel peer=spiffe://$TD/banlieue/claim/$CLAIM_UID" "authority=$DESTINATION" "status=200"
wait_for "$LOG_WAIT" "Envoy's access-log line for the refused tunnel" envoy_has "tunnel peer=spiffe://$TD/banlieue/claim/$CLAIM_UID" "authority=elsewhere.example.com:443" "status=403"
wait_for "$LOG_WAIT" "the authorizer's first allow, served by the broker" authz_has "claim_uid=$CLAIM_UID" "verdict=allow" "served=broker"
wait_for "$LOG_WAIT" "the authorizer's second allow, served by the cache" authz_has "claim_uid=$CLAIM_UID" "verdict=allow" "served=cache"
wait_for "$LOG_WAIT" "the authorizer's refusal" authz_has "claim_uid=$CLAIM_UID" "verdict=deny" "reason=not_allowed"
wait_for "$LOG_WAIT" "the destination's request line" dest_has "destination request" "host=$DESTINATION"
broker_logs | grep -F "claim egress answered to the gateway" | grep -qF "claim_uid=$CLAIM_UID" || true
echo "Envoy: 200 and 403 keyed by the claim SVID; authorizer: broker then cache, one deny; destination: the requests"
if [ -n "$POLICY_STATE" ]; then
  say "shadow (ADR-0030 decision 4): the second port refused as today, the broker logging what enforce would add"
  wait_for "$LOG_WAIT" "the broker's shadow line for the claim" log_has "policy.egress is shadow: direct egress not served" "claim_uid=$CLAIM_UID"
  broker_logs | grep -F "policy.egress is shadow" | grep -F "claim_uid=$CLAIM_UID" | grep -qF "would_add=$DIRECT" || fail "the shadow line does not name $DIRECT alone"
  wait_for "$LOG_WAIT" "Envoy's 403 for the second port" envoy_has "tunnel peer=spiffe://$TD/banlieue/claim/$CLAIM_UID" "authority=$DIRECT" "status=403"
  wait_for "$LOG_WAIT" "the authorizer's not_allowed for the second port" authz_has "authority=$DIRECT" "verdict=deny" "reason=not_allowed"
  echo "shadow: $DIRECT refused at the gateway; would_add=$DIRECT logged; $RULED named nowhere"
fi

say "a node SVID: the proxy's handshake refused by Envoy's validator, no check made, 502 gateway_unreachable at the workload"
probe probe-node node bare "$DESTINATION=502:gateway_unreachable"
# TLS 1.3: the validator's refusal reaches the client as a fatal alert on its first read.
wait_for "$LOG_WAIT" "the validator's alert in the proxy's log" proxy_has probe-node "gateway unreachable; trying the next" "fatal alert"
authz_logs | grep -F "peer=spiffe://$TD/banlieue/node/$EK_HASH" && fail "the node reached the authorizer"
echo "handshake refused before any check; no gateway carried the tunnel"

if [ -n "$POLICY_STATE" ]; then
  say "enforce (ADR-0030 decisions 1, 3, 6): the switch flipped, the second port opens, the ruled entry never served"
  broker_policy_config enforce
  wait_for "$TIMEOUT" "lease mediatore-watcher held by ${BROKER_POD#pod/}" holder_is_pod
  wait_for "$TIMEOUT" "'claim watcher running' in the new broker log" log_has "claim watcher running"
  wait_for "$TIMEOUT" "'policy bundle admitted' version=$BUNDLE_V in the new broker log" log_has "policy bundle admitted" "version=$BUNDLE_V"
  wait_for "$TIMEOUT" "sb-gw's PolicyConformant with P007 under enforce" verdict_has "False Gaps" "P007 direct egress $RULED is not served by the broker: has_rules"
  verdict sb-gw | grep -qF "P006" && fail "P006 still reported under enforce: $(verdict sb-gw)"
  echo "under enforce: $(verdict sb-gw)"
  probe probe-enforce claim phantom \
    "$DIRECT=200" \
    "$RULED=502:gateway_refused" \
    "elsewhere.example.com:443=502:gateway_refused" \
    "$DESTINATION=200"
  pod_logs probe-enforce | grep -F "status=200" | grep -qF "destination reached: host=$DIRECT" || fail "the second port did not answer through the tunnel"
  wait_for "$LOG_WAIT" "the forward to the second port in the proxy's log" proxy_has probe-enforce "forwarded" "host=$DIRECT"
  proxy_logs probe-enforce | grep -F "forwarded" | grep -F "host=$DIRECT" | grep -qF "credential=false" || fail "the forward to the direct entry carried a credential (ADR-0025 decision 8: the phantom is dropped, nothing goes in its place)"
  wait_for "$LOG_WAIT" "Envoy's 200 for the second port" envoy_has "tunnel peer=spiffe://$TD/banlieue/claim/$CLAIM_UID" "authority=$DIRECT" "status=200"
  wait_for "$LOG_WAIT" "the authorizer's allow for the second port, served by the broker" authz_has "authority=$DIRECT" "verdict=allow" "served=broker"
  wait_for "$LOG_WAIT" "the authorizer's not_allowed for the ruled entry" authz_has "authority=$RULED" "verdict=deny" "reason=not_allowed"
  wait_for "$LOG_WAIT" "the second port's request line" direct_has "destination request" "host=$DIRECT"
  echo "enforce: a tunnel to $DIRECT opened and answered, bare, on the credential-less route; $RULED and the other host refused; $DESTINATION as before"
fi

say "the broker gone: the cached allowlist stands in, then the outage is a refusal"
# A fresh answer in the cache right before the broker goes, so the stale window the next
# probe must start inside begins now and not at the claim probe's last tunnel.
probe probe-warm claim bare "$DESTINATION=200"
"${K[@]}" -n "$BROKER_NS" scale deploy/mediatore --replicas=0 >/dev/null
broker_gone() { [ "$("${K[@]}" -n "$BROKER_NS" get pods -l app.kubernetes.io/name=mediatore -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)" = "" ]; }
wait_for "$TIMEOUT" "no broker pod" broker_gone
sleep $((FRESH_SECS + 1))
probe probe-outage-1 claim bare "$DESTINATION=200"
wait_for "$LOG_WAIT" "the stale allowlist served during the outage" authz_has "claim_uid=$CLAIM_UID" "verdict=allow" "served=stale"
sleep $((STALE_SECS + 2))
probe probe-outage-2 claim bare "$DESTINATION=502:gateway_refused"
wait_for "$LOG_WAIT" "the gateway's broker_unreachable in the proxy's log" proxy_has probe-outage-2 "the gateway refused the tunnel" "broker_unreachable"
echo "stale served for ${STALE_SECS}s past fresh, then broker_unreachable, 502 gateway_refused at the workload"
"${K[@]}" -n "$BROKER_NS" scale deploy/mediatore --replicas=1 >/dev/null
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=120s >/dev/null
BROKER_POD=$(broker_pod)
wait_for "$TIMEOUT" "lease mediatore-watcher held by ${BROKER_POD#pod/}" holder_is_pod
wait_for "$TIMEOUT" "'claim watcher running' in the new broker log" log_has "claim watcher running"

say "released: the sandbox is deleted; once stale, the claim is cut off with claim_gone"
"${K[@]}" -n "$NS" delete agentsandbox sb-gw --wait=false >/dev/null
claim_gone() { ! "${K[@]}" -n "$NS" get virtualmachineclaim sb-gw >/dev/null 2>&1; }
wait_for "$TIMEOUT" "claim sb-gw gone" claim_gone
sleep $((FRESH_SECS + 1))
probe probe-released claim bare "$DESTINATION=502:gateway_refused"
wait_for "$LOG_WAIT" "the authorizer's claim_gone" authz_has "claim_uid=$CLAIM_UID" "verdict=deny" "reason=claim_gone"
wait_for "$LOG_WAIT" "the gateway's claim_gone in the proxy's log" proxy_has probe-released "the gateway refused the tunnel" "claim_gone"
echo "cut off: the broker's 404 dropped the cache; the workload sees 502 gateway_refused"

[ -z "$POLICY_STATE" ] || say "PASS: ADR-0030 holds against a real Envoy: under shadow the gateway's answer is today's and the broker logs what it would add; under enforce the bundle's exact entry opens at the gateway and the destination answers through it, an entry with rules is never served (P007), the audience endpoints stand"
say "PASS: ADR-0028 decisions 2 to 5, 7 and 8 hold against a real Envoy through the real forwarder (SDS identity, the validator, the proxy's tunnel through the authorizer with the token swapped in, the cache bounds, the outage, the release)"
