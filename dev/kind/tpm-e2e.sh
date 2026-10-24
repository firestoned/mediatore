#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# ADR-0018 against a real SPIRE (`make kind-e2e-tpm`): the attestation path a pool VM
# takes, with a vTPM behind the kind node (dev/kind/vtpm.sh) in place of libvirt's. A pod
# runs the SPIRE agent on the image's own configuration (image/spire/agent.conf, the two
# placeholders replaced, the trust bundle exported with `spire-server bundle show`) with
# the tpm attestor plugin from its pinned image and /dev/tpmrm0 from the node; the server
# runs deploy/spire-tpm. First the EK trust bundle is a CA that never signed this EK, and
# the agent is refused. Then it is the vTPM's own local CA, and the agent attests as
# spiffe://<td>/spire/agent/tpm/<hash>, the hash mediatore computes from the EK
# certificate. A pool member publishing that certificate gets its node entry under that
# agent, and the guest beside the agent registers the node over the SVID the agent issues
# and only then announces GuestReady (ADR-0019)
# it. The pod is then replaced (fresh agent state, as a VM that lost its disk): the same
# agent ID re-attests, the server lists one agent, the node registers again, no clone is
# reported.
#
#   tpm-e2e.sh <admin kubeconfig> <trust domain> <vtpm dir>   (TPM_PLUGIN_AGENT_IMG set)
set -euo pipefail
cd "$(dirname "$0")/../.."

KUBECONFIG_PATH=${1:?admin kubeconfig}
TD=${2:?trust domain}
VTPM=${3:?vtpm dir}
PLUGIN_IMG=${TPM_PLUGIN_AGENT_IMG:?TPM_PLUGIN_AGENT_IMG}
K=(kubectl --kubeconfig "$KUBECONFIG_PATH")
BROKER_NS=banlieue-system
SPIRE_NS=spire-server
SERVER_POD=spire-server-0
NS=mediatore-e2e-tpm
TIMEOUT=${MEDIATORE_KIND_TIMEOUT:-120}
ENTRY_SELECTOR=app.kubernetes.io/managed-by=mediatore
# A DMI UUID of its own: the node row is keyed by the EK, and this EK is this vTPM's.
DMI=7a1d0c2b-3e4f-4a5b-8c6d-9e0f1a2b3c4d
AGENT_IMAGE=$(sed -n 's/.*image: "\(ghcr.io\/spiffe\/spire-agent:[^"]*\)".*/\1/p' dev/kind/spire/spire.yaml | head -1)

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; dump; exit 1; }
plain() { sed "s/$(printf '\033')\[[0-9;]*m//g"; }

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
for f in device ek.pem ek-ecc.pem ek.hash ek-ca.pem; do
  [ -r "$VTPM/$f" ] || { echo "$VTPM/$f missing: run make kind-vtpm" >&2; exit 1; }
done
[ -n "$AGENT_IMAGE" ] || { echo "no spire-agent image in dev/kind/spire/spire.yaml" >&2; exit 1; }
EK_HASH=$(tr -d '\n' < "$VTPM/ek.hash")
AGENT_ID="spiffe://$TD/spire/agent/tpm/$EK_HASH"

broker_pod()  { "${K[@]}" -n "$BROKER_NS" get pods -l app.kubernetes.io/name=mediatore -o json 2>/dev/null | jq -r '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")] | sort_by(.metadata.creationTimestamp) | last | select(. != null) | "pod/" + .metadata.name'; }
BROKER_POD=""
broker_logs() { [ -n "$BROKER_POD" ] && "${K[@]}" -n "$BROKER_NS" logs "$BROKER_POD" 2>/dev/null | plain || true; }
member_pod()  { "${K[@]}" -n "$NS" get pods -l "mediatore.dev/e2e-role=$1" -o json 2>/dev/null | jq -r '[.items[] | select(.metadata.deletionTimestamp == null)] | sort_by(.metadata.creationTimestamp) | last | select(. != null) | .metadata.name'; }
agent_logs()  { local p; p=$(member_pod "$1"); [ -n "$p" ] && "${K[@]}" -n "$NS" logs "pod/$p" -c spire-agent 2>/dev/null || true; }
guest_logs()  { local p; p=$(member_pod "$1"); [ -n "$p" ] && "${K[@]}" -n "$NS" logs "pod/$p" -c guest 2>/dev/null | plain || true; }
server_logs() { "${K[@]}" -n "$SPIRE_NS" logs "pod/$SERVER_POD" -c spire-server 2>/dev/null || true; }
agents()      { "${K[@]}" -n "$SPIRE_NS" exec "$SERVER_POD" -c spire-server -- spire-server agent list -output json 2>/dev/null || echo '{"agents":[]}'; }
tpm_agents()  { agents | jq -r '.agents[] | select(.attestation_type == "tpm") | "spiffe://" + .id.trust_domain + .id.path'; }
entries()     { "${K[@]}" get clusterstaticentries -l "$ENTRY_SELECTOR" -o jsonpath='{range .items[*]}{.metadata.name} {.spec.spiffeID} {.spec.parentID}{"\n"}{end}' 2>/dev/null || true; }

dump() {
  printf '\n--- spire-server agents (tpm)\n'; tpm_agents
  printf '\n--- spire-server (last 30 lines)\n'; server_logs | tail -30
  printf '\n--- agent, refused pod (last 20 lines)\n'; agent_logs refused | tail -20
  printf '\n--- agent, member pod (last 30 lines)\n'; agent_logs member | tail -30
  printf '\n--- guest (last 20 lines)\n'; guest_logs member | tail -20
  printf '\n--- broker (last 30 lines)\n'; broker_logs | tail -30
  printf '\n--- entries\n'; entries
  printf '\n--- %s\n' "$NS"; "${K[@]}" -n "$NS" get pods,virtualmachines -o wide 2>/dev/null || true
}

cleanup() {
  "${K[@]}" delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() { # <seconds> <description> <command...>
  local secs=$1 what=$2 i; shift 2
  for ((i = 0; i < secs; i++)); do "$@" && return 0; sleep 1; done
  fail "$what not seen within ${secs}s"
}
log_has() { broker_logs | grep -F "$1" | grep -qF "${2:-}"; }

# The EK trust bundle on the server: ConfigMap spire-tpm-ek-cas replaced whole (the
# component's placeholder file would fail every attestation, since the attestor parses
# every file in ca_path), then the server restarted so the mounted files are the new ones.
ek_cas() { # <name> <pem>
  "${K[@]}" -n "$SPIRE_NS" create configmap spire-tpm-ek-cas --from-file="$1=$2" --dry-run=client -o yaml \
    | "${K[@]}" apply -f - >/dev/null
  "${K[@]}" -n "$SPIRE_NS" rollout restart statefulset/spire-server >/dev/null
  "${K[@]}" -n "$SPIRE_NS" rollout status statefulset/spire-server --timeout=300s >/dev/null
  plugin_loaded() { server_logs | grep -Eq 'Plugin loaded.*plugin_name=tpm'; }
  wait_for "$TIMEOUT" "the tpm attestor loaded on the restarted server" plugin_loaded
}

# A pod shaped like a pool VM: the agent on the image's agent.conf with the plugin from
# its image and the node's /dev/tpmrm0, and beside it, when <with guest> is yes, the guest
# as root on the pinned binary path (the node entry selects unix:uid:0 and unix:path,
# ADR-0006) over the agent's socket. One PID namespace, as on a VM: the unix workload
# attestor reads the guest's /proc entry.
member() { # <role> <with guest: yes|no>
  local guest=""
  if [ "$2" = yes ]; then
    guest=$(cat <<YAML
        - name: guest
          image: ghcr.io/firestoned/mediatore:kind
          imagePullPolicy: Never
          command:
            - /usr/local/bin/mediatore
            - guest
            - --dev-ek-hash
            - "$EK_HASH"
            - --dev-dmi-uuid
            - $DMI
            - --dev-skip-setup
          env:
            - { name: MEDIATORE_URL, value: "https://mediatore-sandbox.banlieue-system.svc" }
            - { name: SPIFFE_ENDPOINT_SOCKET, value: "unix:///run/spire/sockets/agent.sock" }
          securityContext:
            runAsUser: 0
            runAsGroup: 0
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
          volumeMounts:
            - { name: sockets, mountPath: /run/spire/sockets, readOnly: true }
            # The VM's tmpfs /run, where the GuestReady marker goes (ADR-0019); the
            # container's root is read-only, a VM's /run is not.
            - { name: phase, mountPath: /run/banlieue }
YAML
)
  fi
  cat <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $1
  namespace: $NS
spec:
  replicas: 1
  selector:
    matchLabels: { mediatore.dev/e2e-role: $1 }
  template:
    metadata:
      labels: { mediatore.dev/e2e-role: $1 }
    spec:
      shareProcessNamespace: true
      initContainers:
        - name: tpm-attestor-plugin
          image: $PLUGIN_IMG
          command: ["/bin/sh", "-c", "cp /app/tpm_attestor_agent /plugin/ && chmod 0555 /plugin/tpm_attestor_agent"]
          volumeMounts:
            - { name: plugin, mountPath: /plugin }
      containers:
        - name: spire-agent
          image: $AGENT_IMAGE
          args: ["-config", "/opt/spire/conf/agent.conf"]
          # /dev/tpmrm0; the VM's unit allows the two TPM devices instead (image/systemd).
          securityContext: { privileged: true }
          volumeMounts:
            - { name: conf, mountPath: /opt/spire/conf, readOnly: true }
            - { name: plugin, mountPath: /opt/spire/bin/tpm_attestor_agent, subPath: tpm_attestor_agent, readOnly: true }
            - { name: data, mountPath: /var/lib/spire/agent }
            - { name: sockets, mountPath: /run/spire/sockets }
            - { name: tpm, mountPath: /dev/tpmrm0 }
$guest
      volumes:
        - { name: conf, configMap: { name: tpm-agent } }
        - { name: plugin, emptyDir: {} }
        - { name: data, emptyDir: {} }
        - { name: sockets, emptyDir: {} }
        - { name: tpm, hostPath: { path: /dev/tpmrm0, type: CharDevice } }
        - { name: phase, emptyDir: { medium: Memory } }
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

say "the agent's side as the image carries it: image/spire/agent.conf and the exported trust bundle"
"${K[@]}" delete namespace "$NS" --ignore-not-found --wait=true >/dev/null
"${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=true >/dev/null
"${K[@]}" create namespace "$NS" >/dev/null
# Part 1.5 of the runbook, the command the deploying guide gives for the VM image.
"${K[@]}" -n "$SPIRE_NS" exec "$SERVER_POD" -c spire-server -- spire-server bundle show > "$VTPM/bundle.pem"
grep -q 'BEGIN CERTIFICATE' "$VTPM/bundle.pem" || fail "spire-server bundle show returned no certificate"
# The two placeholders, and the port: a VM reaches the server on 8081 where the operator
# exposes it; a pod reaches the Service, which maps 443 to the pod's 8081.
sed -e "s#spire-server.sandbox.home.example#spire-server.$SPIRE_NS#" -e "s#sandbox.home.example#$TD#" \
  -e 's#server_port = "8081"#server_port = "443"#' image/spire/agent.conf > "$VTPM/agent.conf"
grep -q "trust_domain = \"$TD\"" "$VTPM/agent.conf" || fail "the trust domain placeholder was not replaced"
grep -q 'server_port = "443"' "$VTPM/agent.conf" || fail "the server port was not replaced"
"${K[@]}" -n "$NS" create configmap tpm-agent --from-file=agent.conf="$VTPM/agent.conf" --from-file=bundle.pem="$VTPM/bundle.pem" >/dev/null
echo "bundle exported ($(grep -c 'BEGIN CERTIFICATE' "$VTPM/bundle.pem") certificate(s)); agent.conf for $TD at spire-server.$SPIRE_NS:443; plugin $PLUGIN_IMG"

say "refused: a CA that never signed this EK, then the local CA's root alone, make the vTPM no agent"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj /CN=stranger-localca \
  -keyout "$VTPM/stranger-ca.key" -out "$VTPM/stranger-ca.pem" >/dev/null 2>&1
refused() { { agent_logs refused; server_logs; } | grep -Eq 'could not verify cert|could not validate EK|certificate signed by unknown authority'; }
refuse_under() { # <key> <pem> <what>
  ek_cas "$1" "$2"
  member refused no | "${K[@]}" apply -f - >/dev/null
  wait_for "$TIMEOUT" "the agent refused over the EK certificate's chain under $3" refused
  tpm_agents | grep -qF "$AGENT_ID" && fail "$AGENT_ID attested under $3"
  "${K[@]}" -n "$NS" delete deploy refused --wait=true >/dev/null
  echo "refused under $3; no tpm agent listed"
}
refuse_under stranger.pem "$VTPM/stranger-ca.pem" "a CA that never signed this EK"
# The EK certificate is signed by the local CA's issuing certificate, and the plugin
# verifies against the files in ca_path with no intermediates: the root alone is no anchor.
refuse_under rootca.pem "$VTPM/rootca.pem" "the local CA's root alone"

say "attested: with the vTPM's local CA, the agent is $AGENT_ID"
ek_cas kind.pem "$VTPM/ek-ca.pem"
member member yes | "${K[@]}" apply -f - >/dev/null
attested() { agent_logs member | grep -q 'Node attestation was successful'; }
wait_for "$TIMEOUT" "'Node attestation was successful' in the agent log" attested
listed() { tpm_agents | grep -qxF "$AGENT_ID"; }
wait_for "$TIMEOUT" "$AGENT_ID in spire-server agent list" listed
n=$(tpm_agents | wc -l | tr -d ' ')
[ "$n" -eq 1 ] || fail "expected one tpm agent, the server lists $n"
echo "attested as $AGENT_ID: the plugin's hash of the EK is the hash computed from its certificate"

say "the member's certificates become the node entry under that agent; the guest registers the node"
"${K[@]}" -n "$NS" apply -f - >/dev/null <<YAML
apiVersion: banlieue.io/v1alpha1
kind: VirtualMachine
metadata:
  name: member-1
  labels: { banlieue.io/pool: e2e }
spec:
  classRef: { name: small }
  imageRef: { name: sandbox }
YAML
# Both EK certificates, as a vTPM carries them; the RSA one is the identity.
jq -n --rawfile rsa "$VTPM/ek.pem" --rawfile ecc "$VTPM/ek-ecc.pem" '{status: {tpmEndorsementCertificates: [$rsa, $ecc]}}' \
  | "${K[@]}" -n "$NS" patch virtualmachine member-1 --subresource=status --type=merge --patch-file=/dev/stdin >/dev/null
node_entry() { entries | grep -qxF "mediatore-node-$EK_HASH spiffe://$TD/banlieue/node/$EK_HASH $AGENT_ID"; }
wait_for "$TIMEOUT" "node entry for $EK_HASH with parent $AGENT_ID" node_entry
registered() { guest_logs member | grep -qF "node registered"; }
wait_for "$TIMEOUT" "'node registered' in the guest log" registered
guest_logs member | grep -F "SVID from the Workload API" | grep -qF "spiffe://$TD/banlieue/node/$EK_HASH" || fail "the guest's SVID is not the node's"
# ADR-0019: the pool hears GuestReady only after the registration, never before. In the
# pod the marker file is the one channel (no rpctool, no /dev/vsock).
announced() { guest_logs member | grep -qF "GuestReady announced"; }
wait_for "$TIMEOUT" "'GuestReady announced' in the guest log" announced
announced_after_registered() {
  local reg ann
  reg=$(guest_logs member | grep -nF "node registered" | tail -1 | cut -d: -f1)
  ann=$(guest_logs member | grep -nF "GuestReady announced" | tail -1 | cut -d: -f1)
  [ -n "$reg" ] && [ -n "$ann" ] && [ "$ann" -gt "$reg" ] || fail "GuestReady (line ${ann:-none}) was not announced after the registration (line ${reg:-none})"
  guest_logs member | grep -F "GuestReady announced" | grep -qF "file=announced" || fail "the marker file was not written"
}
announced_after_registered
echo "entry declared with parent $AGENT_ID; the guest got spiffe://$TD/banlieue/node/$EK_HASH from the attested agent, registered, then announced GuestReady"

say "replaced: a fresh pod (new agent state) re-attests as the same agent; one agent, the node registered again"
OLD_POD=$(member_pod member)
"${K[@]}" -n "$NS" rollout restart deploy/member >/dev/null
new_pod() { local p; p=$(member_pod member); [ -n "$p" ] && [ "$p" != "$OLD_POD" ]; }
wait_for "$TIMEOUT" "a new member pod" new_pod
"${K[@]}" -n "$NS" rollout status deploy/member --timeout=120s >/dev/null
wait_for "$TIMEOUT" "'Node attestation was successful' in the new agent's log" attested
wait_for "$TIMEOUT" "$AGENT_ID listed after the re-attestation" listed
n=$(tpm_agents | wc -l | tr -d ' ')
[ "$n" -eq 1 ] || fail "expected one tpm agent after the re-attestation, the server lists $n"
wait_for "$TIMEOUT" "'node registered' in the new guest's log" registered
guest_logs member | grep -qF "already registered" && fail "the re-registration was taken for a clone"
wait_for "$TIMEOUT" "'GuestReady announced' in the new guest's log" announced
announced_after_registered
echo "re-attested as $AGENT_ID (${OLD_POD} replaced by $(member_pod member)); one tpm agent; registered and announced again"

say "PASS: ADR-0018 holds against a real SPIRE with a vTPM (the image's agent.conf, the pinned plugin on both sides, the EK CA fail-closed, the agent ID the hash of the EK, the node entry under it, re-attestation), and ADR-0019's GuestReady follows the registration"
