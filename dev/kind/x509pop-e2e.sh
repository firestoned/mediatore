#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# ADR-0049 against a real SPIRE and the real broker (`make kind-e2e-x509pop`): the path a
# pool guest with no vTPM takes, from the server's x509pop attestor (deploy/spire-x509pop)
# to the node registered at the broker. A pod runs the SPIRE agent on the image's own
# configuration for such a pool (image/spire/agent-x509pop.conf, the two placeholders
# replaced, the trust bundle the OpenBao PKI root, ADR-0031) and beside it the guest with
# --node-attestation x509pop.
#
# What stands in for the host: a pod has no vsock, so the host's signer is not in this
# tier. The guest's half of that exchange, `mediatore node-cert`, was proven against
# banlieue's real signer and a real server and agent on the build host (#168). Here the
# script is the host: it makes a throwaway host CA (EC P-256, CA:TRUE with a path length of
# zero, keyCertSign) and a leaf for the guest (CA:FALSE, digitalSignature, the subject's
# common name a machine UID, no SAN) with openssl, the shape banlieue's signer issues
# (ADR-0049 decision 3). The CA keys never leave the tier's state directory and are deleted
# when it ends; a leaf and its key go into a Secret of the tier's namespace, the pod's
# stand-in for the files node-cert writes under /run/spire/x509pop. Nothing prints a key or
# a certificate body.
#
# In order: an agent is refused while the server's bundle lacks its host CA, and again when
# its leaf was signed by another key under the host CA's own name; with the host CA in the
# bundle it attests as spiffe://<td>/spire/agent/x509pop/<host CA CN>/<subject>, the ID the
# script computed before the pod existed. A Provider carrying that CA inline and a
# VirtualMachine of a pool listed in watcher.x509pop_pools get the node entry under that
# agent, named by the SHA-256 of the agent ID (decision 7); a listed machine with an EK and
# no subject, and one whose Provider's CA may sign further CAs, get nothing. The bundle the
# server was given passes `mediatore x509pop-bundle check`, and the two bundles decision 2
# forbids (two CAs under one name, a CA free to sign further CAs) are refused by it. The guest
# registers the node over the SVID the agent issues and only then announces GuestReady
# (ADR-0019). The pod is replaced: the same agent ID, registered again. Last, a machine of
# a pool that is not listed, with the same subject and an EK certificate, gets the tpm
# entry it always got and no x509pop one (decision 9). Last of all a sandbox's claim, Bound
# to the listed machine, is bound under the x509pop node: its entry's parent is that agent.
#
# The broker runs with the overlay's configuration plus watcher.x509pop_pools for the run;
# the overlay's is restored after. No banlieue controller runs: the statuses are patched.
#
#   x509pop-e2e.sh <admin kubeconfig> <trust domain> <state dir> <ek pem> <ek hash file>   (UPSTREAM_ROOT set)
set -euo pipefail
cd "$(dirname "$0")/../.."

KUBECONFIG_PATH=${1:?admin kubeconfig}
TD=${2:?trust domain}
STATE=${3:?state dir}
EK_PEM=${4:?ek pem}
EK_HASH=$(tr -d '\n' < "${5:?ek hash file}")
# The root the server's CA chains to, as `make kind-openbao` read it from the PKI mount (ADR-0031).
UPSTREAM_ROOT=${UPSTREAM_ROOT:?UPSTREAM_ROOT}
K=(kubectl --kubeconfig "$KUBECONFIG_PATH")
BROKER_NS=mediatore-system
BROKER_SA=system:serviceaccount:$BROKER_NS:mediatore
SPIRE_NS=spire-server
SERVER_POD=spire-server-0
NS=mediatore-e2e-x509pop
TIMEOUT=${MEDIATORE_KIND_TIMEOUT:-120}
ENTRY_SELECTOR=app.kubernetes.io/managed-by=mediatore
# The pool the broker is told attests with x509pop, and one it is not told about.
POOL=x509pop
OTHER_POOL=e2e
# The host CA's common name: the issuer segment of every agent ID it can mint (decision 2).
HOST_CN=kind-host
# A DMI UUID of its own: the node's record is keyed by the node key, not by this.
DMI=5c2e9b1a-7d3f-4e6a-9b8c-0a1f2e3d4c5b
AGENT_IMAGE=$(sed -n 's/.*image: "\(ghcr.io\/spiffe\/spire-agent:[^"]*\)".*/\1/p' dev/kind/spire/spire.yaml | head -1)

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; dump; exit 1; }
plain() { sed "s/$(printf '\033')\[[0-9;]*m//g"; }

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
[ -r "$UPSTREAM_ROOT" ] || { echo "$UPSTREAM_ROOT missing: run make kind-openbao" >&2; exit 1; }
[ -r "$EK_PEM" ] || { echo "$EK_PEM missing: run make kind-banlieue-crds" >&2; exit 1; }
[ -n "$AGENT_IMAGE" ] || { echo "no spire-agent image in dev/kind/spire/spire.yaml" >&2; exit 1; }

# The machine's UID, what banlieue publishes as status.attestationSubject and the host's
# signer sets as the leaf's common name. New at every run, so a second run in the same
# cluster never finds its agent already attested by the first.
SUBJECT=$(openssl rand -hex 16 | sed -E 's/^(.{8})(.{4})(.{4})(.{4})(.{12})$/\1-\2-\3-\4-\5/')
AGENT_ID="spiffe://$TD/spire/agent/x509pop/$HOST_CN/$SUBJECT"
# Decision 7: the node key is the lowercase hex SHA-256 of the agent ID, computed here as
# `node_key` computes it in crates/mediatore-spire/src/x509pop.rs, from nothing the cluster said.
NODE_KEY=$(printf '%s' "$AGENT_ID" | openssl dgst -sha256 -r | cut -d' ' -f1)
NODE_ID="spiffe://$TD/banlieue/node/$NODE_KEY"
TPM_AGENT_ID="spiffe://$TD/spire/agent/tpm/$EK_HASH"

broker_pod()  { "${K[@]}" -n "$BROKER_NS" get pods -l app.kubernetes.io/name=mediatore -o json 2>/dev/null | jq -r '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")] | sort_by(.metadata.creationTimestamp) | last | select(. != null) | "pod/" + .metadata.name'; }
BROKER_POD=""
broker_logs() { [ -n "$BROKER_POD" ] && "${K[@]}" -n "$BROKER_NS" logs "$BROKER_POD" 2>/dev/null | plain || true; }
member_pod()  { "${K[@]}" -n "$NS" get pods -l "mediatore.dev/e2e-role=$1" -o json 2>/dev/null | jq -r '[.items[] | select(.metadata.deletionTimestamp == null)] | sort_by(.metadata.creationTimestamp) | last | select(. != null) | .metadata.name'; }
agent_logs()  { local p; p=$(member_pod "$1"); [ -n "$p" ] && "${K[@]}" -n "$NS" logs "pod/$p" -c spire-agent 2>/dev/null || true; }
guest_logs()  { local p; p=$(member_pod "$1"); [ -n "$p" ] && "${K[@]}" -n "$NS" logs "pod/$p" -c guest 2>/dev/null | plain || true; }
server_logs() { "${K[@]}" -n "$SPIRE_NS" logs "pod/$SERVER_POD" -c spire-server 2>/dev/null || true; }
agents()      { "${K[@]}" -n "$SPIRE_NS" exec "$SERVER_POD" -c spire-server -- spire-server agent list -output json 2>/dev/null || echo '{"agents":[]}'; }
x509pop_agents() { agents | jq -r '.agents[] | select(.attestation_type == "x509pop") | "spiffe://" + .id.trust_domain + .id.path'; }
agent_serial() { agents | jq -r --arg id "$AGENT_ID" '.agents[] | select(("spiffe://" + .id.trust_domain + .id.path) == $id) | .x509svid_serial_number'; }
entries()     { "${K[@]}" get clusterstaticentries -l "$ENTRY_SELECTOR" -o jsonpath='{range .items[*]}{.metadata.name} {.spec.spiffeID} {.spec.parentID}{"\n"}{end}' 2>/dev/null || true; }

dump() {
  printf '\n--- spire-server agents (x509pop)\n'; x509pop_agents
  printf '\n--- spire-server (last 30 lines)\n'; server_logs | tail -30
  printf '\n--- agent, refused pod (last 20 lines)\n'; agent_logs refused | tail -20
  printf '\n--- agent, impostor pod (last 20 lines)\n'; agent_logs impostor | tail -20
  printf '\n--- agent, member pod (last 30 lines)\n'; agent_logs member | tail -30
  printf '\n--- guest (last 20 lines)\n'; guest_logs member | tail -20
  printf '\n--- broker (last 40 lines)\n'; broker_logs | tail -40
  printf '\n--- entries\n'; entries
  printf '\n--- %s\n' "$NS"; "${K[@]}" -n "$NS" get pods,virtualmachines,providers -o wide 2>/dev/null || true
}

# The CA keys by name, never the directory with a wildcard: the state directory is the
# Makefile's .kind/x509pop and holds nothing else, but a path given by hand might.
KEYS=(host-ca.key stranger-ca.key impostor-ca.key loose-ca.key member.key impostor.key)
cleanup() {
  local k
  for k in "${KEYS[@]}"; do rm -f "$STATE/$k"; done
  "${K[@]}" -n "$SPIRE_NS" delete pod x509pop-bundle-check --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=false >/dev/null 2>&1 || true
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
log_has() { broker_logs | grep -F "$1" | grep -qF "${2:-}"; }

# openssl's extensions, from a file of the tier's own: the distribution's openssl.cnf adds
# a basicConstraints of its own to a self-signed certificate, and what a host CA carries
# is the point here.
umask 077
mkdir -p "$STATE"
cat > "$STATE/openssl.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = replaced-by-subj
[host_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign
subjectKeyIdentifier = hash
[loose_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign
subjectKeyIdentifier = hash
[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
CNF
make_ca() { # <file stem> <common name> <extensions section>
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=$2" \
    -config "$STATE/openssl.cnf" -extensions "$3" -keyout "$STATE/$1.key" -out "$STATE/$1.pem" >/dev/null 2>&1 \
    || { echo "openssl could not make the CA $2" >&2; exit 1; }
}
# What the host's signer does with a guest's request: the subject is the machine's UID,
# CA:FALSE, digitalSignature, nothing else (decision 3).
make_leaf() { # <file stem> <CA file stem> <subject common name>
  if ! { openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$3" \
      -config "$STATE/openssl.cnf" -keyout "$STATE/$1.key" -out "$STATE/$1.csr" \
    && openssl x509 -req -in "$STATE/$1.csr" -CA "$STATE/$2.pem" -CAkey "$STATE/$2.key" -CAcreateserial -days 1 \
      -extfile "$STATE/openssl.cnf" -extensions leaf -out "$STATE/$1.pem"; } >/dev/null 2>&1; then
    echo "openssl could not make the leaf $1" >&2; exit 1
  fi
  rm -f "$STATE/$1.csr"
}
describe() { # <certificate>: its subject, issuer and constraints on one line, never its body
  openssl x509 -in "$1" -noout -subject -issuer -ext basicConstraints,keyUsage 2>/dev/null | tr -s ' \n' ' '
}

# The x509pop bundle on the server: ConfigMap spire-x509pop-host-cas replaced whole, then
# the server restarted, since the init container joins the files and the attestor loads
# the result when the server starts (deploy/spire-x509pop).
host_cas() { # <key> <pem>
  "${K[@]}" -n "$SPIRE_NS" create configmap spire-x509pop-host-cas --from-file="$1=$2" --dry-run=client -o yaml \
    | "${K[@]}" apply -f - >/dev/null
  "${K[@]}" -n "$SPIRE_NS" rollout restart statefulset/spire-server >/dev/null
  "${K[@]}" -n "$SPIRE_NS" rollout status statefulset/spire-server --timeout=300s >/dev/null
  plugin_loaded() { server_logs | grep -Eq 'Plugin loaded.*plugin_name=x509pop'; }
  wait_for "$TIMEOUT" "the x509pop attestor loaded on the restarted server" plugin_loaded
}

# `mediatore x509pop-bundle check` (decision 2: no two CAs under one common name, every CA
# with a path length of zero) over keys of a ConfigMap, run from the broker's own image in
# a pod, so the binary under test is the one the cluster runs. The pod's end is left in
# BUNDLE_PHASE and what it printed in BUNDLE_OUT; common names only, never a certificate.
BUNDLE_PHASE=""
BUNDLE_OUT=""
bundle_check() { # <namespace> <configmap> <key>...
  local ns=$1 cm=$2 pod=x509pop-bundle-check files; shift 2
  files=$(printf '"/host-cas/%s", ' "$@")
  "${K[@]}" -n "$ns" delete pod "$pod" --ignore-not-found --wait=true >/dev/null
  "${K[@]}" -n "$ns" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $pod
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: check
      image: ghcr.io/firestoned/mediatore:kind
      imagePullPolicy: Never
      command: ["/usr/bin/mediatore", "x509pop-bundle", "check", ${files%, }]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
      volumeMounts:
        - { name: host-cas, mountPath: /host-cas, readOnly: true }
  volumes:
    - { name: host-cas, configMap: { name: $cm } }
YAML
  bundle_phase() { BUNDLE_PHASE=$("${K[@]}" -n "$ns" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true); [ "$BUNDLE_PHASE" = Succeeded ] || [ "$BUNDLE_PHASE" = Failed ]; }
  wait_for "$TIMEOUT" "the bundle check over $ns/$cm to end" bundle_phase
  BUNDLE_OUT=$("${K[@]}" -n "$ns" logs "pod/$pod" 2>/dev/null | plain || true)
  "${K[@]}" -n "$ns" delete pod "$pod" --ignore-not-found --wait=true >/dev/null
}
bundle_refused() { # <what it must say> <what it must name> <configmap> <key>...
  local why=$1 names=$2; shift 2
  bundle_check "$NS" "$@"
  [ "$BUNDLE_PHASE" = Failed ] || fail "mediatore x509pop-bundle check passed a bundle it must refuse ($why): $BUNDLE_OUT"
  grep -F -- "$why" <<<"$BUNDLE_OUT" | grep -qF -- "$names" || fail "the bundle check refused, but not for '$why' naming $names: $BUNDLE_OUT"
  echo "refused by mediatore x509pop-bundle check: $(grep -F -- "$why" <<<"$BUNDLE_OUT" | tail -1 | cut -c1-200)"
}

# A pod shaped like a pool VM with no vTPM: the agent on the image's agent-x509pop.conf,
# its key and certificate where node-cert would have written them, and beside it, when
# <with guest> is yes, the guest as root on the pinned binary path (the node entry selects
# unix:uid:0 and unix:path, ADR-0006) over the agent's socket, reading the certificate and
# never the key. One PID namespace, as on a VM: the unix workload attestor reads the
# guest's /proc entry, which is what CAP_SYS_PTRACE is for, as in the VM's unit. No
# device, no privilege: there is no TPM to open.
member() { # <role> <secret> <with guest: yes|no>
  local guest=""
  if [ "$3" = yes ]; then
    guest=$(cat <<YAML
        - name: guest
          image: ghcr.io/firestoned/mediatore:kind
          imagePullPolicy: Never
          command:
            - /usr/bin/mediatore
            - guest
            - --node-attestation
            - x509pop
            - --dev-dmi-uuid
            - $DMI
            - --dev-skip-setup
          env:
            - { name: MEDIATORE_URL, value: "https://mediatore-sandbox.mediatore-system.svc" }
            - { name: SPIFFE_ENDPOINT_SOCKET, value: "unix:///run/spire/sockets/agent.sock" }
          securityContext:
            runAsUser: 0
            runAsGroup: 0
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
          volumeMounts:
            - { name: sockets, mountPath: /run/spire/sockets, readOnly: true }
            - { name: x509pop-cert, mountPath: /run/spire/x509pop, readOnly: true }
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
      containers:
        - name: spire-agent
          image: $AGENT_IMAGE
          args: ["-config", "/etc/spire/agent.conf"]
          securityContext:
            runAsUser: 0
            runAsGroup: 0
            allowPrivilegeEscalation: false
            capabilities: { drop: ["ALL"], add: ["SYS_PTRACE"] }
          volumeMounts:
            - { name: conf, mountPath: /etc/spire, readOnly: true }
            # The data directory the image's configuration names: tmpfs, as a VM's /run is.
            - { name: data, mountPath: /run/spire/agent }
            - { name: sockets, mountPath: /run/spire/sockets }
            - { name: x509pop, mountPath: /run/spire/x509pop, readOnly: true }
$guest
      volumes:
        - { name: conf, configMap: { name: x509pop-agent } }
        - { name: data, emptyDir: { medium: Memory } }
        - { name: sockets, emptyDir: {} }
        - { name: x509pop, secret: { secretName: $2, defaultMode: 0400 } }
        - { name: x509pop-cert, secret: { secretName: $2, defaultMode: 0444, items: [{ key: cert.pem, path: cert.pem }] } }
        - { name: phase, emptyDir: { medium: Memory } }
YAML
}
node_files() { # <secret> <file stem>: cert.pem and key.pem, the names agent-x509pop.conf reads
  "${K[@]}" -n "$NS" create secret generic "$1" --from-file=cert.pem="$STATE/$2.pem" --from-file=key.pem="$STATE/$2.key" >/dev/null
}

# The overlay's configuration with watcher.x509pop_pools added under its watcher section,
# applied, and the broker restarted on it.
say "broker: watcher.x509pop_pools lists $NS/$POOL; its role lists Providers and no more; the watcher Lease is held by the running pod"
"${K[@]}" get crd providers.banlieue.io >/dev/null 2>&1 \
  || fail "no Provider CRD (providers.banlieue.io): the watcher reads the host CA from the Provider, so make kind-banlieue-crds must render it from the pinned banlieue-api"
may() { [ "$("${K[@]}" auth can-i "$1" providers.banlieue.io -n "$NS" --as="$BROKER_SA" 2>/dev/null || true)" = yes ]; }
may list || fail "the broker's ServiceAccount may not list providers.banlieue.io (deploy/base/rbac.yaml, ADR-0049 decision 10)"
for verb in get watch create update patch delete; do
  may "$verb" && fail "the broker's ServiceAccount may $verb providers.banlieue.io: decision 10 grants listing, nothing more"
done
awk -v pools="  x509pop_pools: [\"$NS/$POOL\"]" '{ print } /^watcher:[[:space:]]*$/ { print pools; n++ } END { exit n == 1 ? 0 : 1 }' \
  dev/kind/broker/mediatore.yaml > "$STATE/mediatore.yaml" \
  || fail "dev/kind/broker/mediatore.yaml has no single watcher: section to add x509pop_pools to"
"${K[@]}" -n "$BROKER_NS" create configmap mediatore-config --from-file=mediatore.yaml="$STATE/mediatore.yaml" \
  --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
"${K[@]}" -n "$BROKER_NS" rollout restart deploy/mediatore >/dev/null
"${K[@]}" -n "$BROKER_NS" rollout status deploy/mediatore --timeout=120s >/dev/null \
  || fail "the broker did not roll out on a configuration with watcher.x509pop_pools"
BROKER_POD=$(broker_pod)
[ -n "$BROKER_POD" ] || fail "no Running broker pod in $BROKER_NS"
holder_is_pod() { [ "$("${K[@]}" -n "$BROKER_NS" get lease mediatore-watcher -o jsonpath='{.spec.holderIdentity}' 2>/dev/null)" = "${BROKER_POD#pod/}" ]; }
wait_for "$TIMEOUT" "lease mediatore-watcher held by ${BROKER_POD#pod/}" holder_is_pod
wait_for "$TIMEOUT" "'claim watcher running' in the broker log" log_has "claim watcher running"
echo "held by ${BROKER_POD#pod/}; controllers running; providers: listed, nothing else"

say "the host's side, made here: a host CA named $HOST_CN and the leaf its signer would issue to machine $SUBJECT"
"${K[@]}" delete namespace "$NS" --ignore-not-found --wait=true >/dev/null
"${K[@]}" delete clusterstaticentries -l "$ENTRY_SELECTOR" --ignore-not-found --wait=true >/dev/null
"${K[@]}" create namespace "$NS" >/dev/null
make_ca host-ca "$HOST_CN" host_ca
# Another host's CA, which never signed anything of this guest's.
make_ca stranger-ca stranger-host host_ca
# The host CA's name on another key: what a signer outside the bundle would have to present.
make_ca impostor-ca "$HOST_CN" host_ca
# A CA free to sign further CAs: no path length (decision 2, amended 2026-11-26).
make_ca loose-ca loose-host loose_ca
make_leaf member host-ca "$SUBJECT"
make_leaf impostor impostor-ca "$SUBJECT"
openssl verify -CAfile "$STATE/host-ca.pem" "$STATE/member.pem" >/dev/null 2>&1 || fail "the leaf does not chain to the host CA"
openssl verify -CAfile "$STATE/host-ca.pem" "$STATE/impostor.pem" >/dev/null 2>&1 && fail "the impostor's leaf chains to the host CA"
openssl x509 -in "$STATE/host-ca.pem" -noout -ext basicConstraints 2>/dev/null | grep -q 'CA:TRUE, pathlen:0' || fail "the host CA does not carry CA:TRUE with a path length of zero"
openssl x509 -in "$STATE/loose-ca.pem" -noout -ext basicConstraints 2>/dev/null | grep -q 'pathlen' && fail "the loose CA carries a path length"
openssl x509 -in "$STATE/member.pem" -noout -ext basicConstraints,keyUsage 2>/dev/null | tr -s ' \n' ' ' | grep -q 'CA:FALSE.*Digital Signature' || fail "the leaf is not CA:FALSE with digitalSignature"
echo "host CA: $(describe "$STATE/host-ca.pem")"
echo "leaf:    $(describe "$STATE/member.pem")"
node_files x509pop-member member
node_files x509pop-impostor impostor
# The two placeholders, and the port: a VM reaches the server on 8081 where the operator
# exposes it; a pod reaches the Service, which maps 443 to the pod's 8081. The bundle: the
# image's configuration names the file its boot-time fetch writes, in the SPIFFE format
# (ADR-0037). This tier has no bundle endpoint, so it does what image/spire/agent.conf
# prescribes for such a deployment: the PEM root, trust_bundle_path pointed at it,
# trust_bundle_format dropped (`make kind-e2e-tpm` proves that root is the server's whole bundle).
sed -e "s#spire-server.sandbox.home.example#spire-server.$SPIRE_NS#" -e "s#sandbox.home.example#$TD#" \
  -e 's#server_port = "8081"#server_port = "443"#' \
  -e 's#trust_bundle_path = "/run/spire/bundle.json"#trust_bundle_path = "/etc/spire/bundle.pem"#' \
  -e '/^ *trust_bundle_format = /d' image/spire/agent-x509pop.conf > "$STATE/agent.conf"
grep -q "trust_domain = \"$TD\"" "$STATE/agent.conf" || fail "the trust domain placeholder was not replaced"
grep -q 'server_port = "443"' "$STATE/agent.conf" || fail "the server port was not replaced"
grep -q 'trust_bundle_path = "/etc/spire/bundle.pem"' "$STATE/agent.conf" || fail "the trust bundle path was not pointed at the mounted PEM"
! grep -qE '^ *trust_bundle_format *=' "$STATE/agent.conf" || fail "the SPIFFE bundle format was left on a PEM bundle"
grep -q 'NodeAttestor "x509pop"' "$STATE/agent.conf" || fail "image/spire/agent-x509pop.conf names no x509pop attestor"
grep -q 'private_key_path = "/run/spire/x509pop/key.pem"' "$STATE/agent.conf" || fail "image/spire/agent-x509pop.conf does not read the key where node-cert writes it"
grep -q 'certificate_path = "/run/spire/x509pop/cert.pem"' "$STATE/agent.conf" || fail "image/spire/agent-x509pop.conf does not read the certificate where node-cert writes it"
! grep -qE '^ *intermediates_path *=' "$STATE/agent.conf" || fail "image/spire/agent-x509pop.conf sets intermediates_path, which SPIRE refuses for a self-signed host CA"
# A member with no vTPM cannot seal its disk: the agent's SVID key stays in memory and its
# data directory is on tmpfs (ADR-0049, amended 2026-11-27). The agent here runs on exactly
# that, so its restart below is the proof that it attests again from nothing.
grep -q 'KeyManager "memory"' "$STATE/agent.conf" || fail "image/spire/agent-x509pop.conf does not use the memory key manager"
grep -q 'KeyManager "disk"' "$STATE/agent.conf" && fail "image/spire/agent-x509pop.conf still names the disk key manager"
grep -qx ' *data_dir = "/run/spire/agent"' "$STATE/agent.conf" || fail "image/spire/agent-x509pop.conf does not keep the agent's data on tmpfs under /run/spire"
grep -v '^ *#' "$STATE/agent.conf" | grep -q '/var/lib' && fail "image/spire/agent-x509pop.conf names a path under /var/lib"
"${K[@]}" -n "$NS" create configmap x509pop-agent --from-file=agent.conf="$STATE/agent.conf" --from-file=bundle.pem="$UPSTREAM_ROOT" >/dev/null
echo "agent.conf for $TD at spire-server.$SPIRE_NS:443 from image/spire/agent-x509pop.conf; the agent this leaf can become is $AGENT_ID"

say "refused: the bundle holds another host's CA, then the host CA while the leaf was signed by another key under its name"
# The refusal is read on the server: its x509pop attestor saying the certificate did not
# verify. The agent's own "certificate signed by unknown authority" is also what a wrong TLS
# trust bundle looks like, and proves nothing about the attestor. Each attempt follows a
# server restart (host_cas), so the server's log holds this attempt's lines alone; that it
# holds none yet is checked before the agent exists.
SERVER_REFUSAL='nodeattestor(x509pop): certificate verification failed'
server_refused() { server_logs | grep -qiF "$SERVER_REFUSAL"; }
refuse() { # <role> <secret> <what>
  server_refused && fail "the server already logged an x509pop refusal before the agent started ($3): the attempt cannot be told from an earlier one"
  member "$1" "$2" no | "${K[@]}" apply -f - >/dev/null
  wait_for "$TIMEOUT" "the server's '$SERVER_REFUSAL' ($3)" server_refused
  agent_logs "$1" | grep -q 'Node attestation was successful' && fail "the agent attested ($3)"
  x509pop_agents | grep -qxF "$AGENT_ID" && fail "$AGENT_ID is listed ($3)"
  "${K[@]}" -n "$NS" delete deploy "$1" --wait=true >/dev/null
  echo "refused by the server's attestor: $(server_logs | grep -iF "$SERVER_REFUSAL" | tail -1 | grep -oiE 'nodeattestor\(x509pop\)[^"]*' | cut -c1-200) ($3); $AGENT_ID not in spire-server agent list"
}
host_cas stranger.pem "$STATE/stranger-ca.pem"
refuse refused x509pop-member "the bundle is a CA that never signed this leaf"
host_cas "$HOST_CN.pem" "$STATE/host-ca.pem"
# The bundle the server now runs on is one decision 2 allows, by the command an operator
# runs before adding a host; the two it forbids are refused by the same command.
bundle_check "$SPIRE_NS" spire-x509pop-host-cas "$HOST_CN.pem"
[ "$BUNDLE_PHASE" = Succeeded ] || fail "mediatore x509pop-bundle check refused the server's own bundle: $BUNDLE_OUT"
grep -F "ok: 1 host CA" <<<"$BUNDLE_OUT" | grep -qF "$HOST_CN" || fail "the bundle check did not name the one host CA: $BUNDLE_OUT"
echo "the server's bundle: $(grep -F 'ok:' <<<"$BUNDLE_OUT" | tail -1)"
"${K[@]}" -n "$NS" create configmap twin-cas --from-file=a.pem="$STATE/host-ca.pem" --from-file=b.pem="$STATE/impostor-ca.pem" >/dev/null
bundle_refused "share the common name" "$HOST_CN" twin-cas a.pem b.pem
"${K[@]}" -n "$NS" create configmap loose-cas --from-file=a.pem="$STATE/host-ca.pem" --from-file=b.pem="$STATE/loose-ca.pem" >/dev/null
bundle_refused "path length constraint must be 0" loose-host loose-cas a.pem b.pem
# The name is not the trust: the same common name on another key is no host CA.
refuse impostor x509pop-impostor "the host CA is in the bundle, the leaf is another key's under the same name"

say "attested: with the host CA in the bundle, the agent is $AGENT_ID"
member member x509pop-member yes | "${K[@]}" apply -f - >/dev/null
# The newest member pod's own agent, and under which ID: the line carries it.
attested() { agent_logs member | grep -F 'Node attestation was successful' | grep -qF "$AGENT_ID"; }
wait_for "$TIMEOUT" "'Node attestation was successful' as $AGENT_ID in the agent log" attested
listed() { x509pop_agents | grep -qxF "$AGENT_ID"; }
wait_for "$TIMEOUT" "$AGENT_ID in spire-server agent list" listed
n=$(x509pop_agents | grep -cxF "$AGENT_ID" || true)
[ "$n" -eq 1 ] || fail "expected $AGENT_ID once, the server lists it $n times"
x509pop_agents | grep -qF "/spire/agent/x509pop/stranger-host/" && fail "an agent attested under the stranger CA's name"
# The agent that attested is the one with no key on disk: the catalog says which key
# manager it loaded.
memory_km() { agent_logs member | grep -F 'Plugin loaded' | grep -F 'plugin_type=KeyManager' | grep -qF 'plugin_name=memory'; }
memory_km || fail "the agent did not load the memory key manager: $(agent_logs member | grep -F 'plugin_type=KeyManager' | tail -2)"
agent_logs member | grep -F 'plugin_type=KeyManager' | grep -qF 'plugin_name=disk' && fail "the agent loaded the disk key manager"
echo "attested as $AGENT_ID: the server's agent_path_template gives the ID computed from the host CA's name and the machine's UID; the agent's key manager is the memory one, its data directory tmpfs"

say "the Provider's host CA and the member's subject become the node entry under that agent"
provider() { # <name> <CA pem>: the administrator's statement of a host's CA, inline (decision 10)
  jq -n --arg name "$1" --arg ns "$NS" --rawfile ca "$2" '{
    apiVersion: "banlieue.io/v1alpha1", kind: "Provider", metadata: {name: $name, namespace: $ns},
    spec: {providerClassRef: {name: "cloud-hypervisor"}, connection: {endpoint: "https://hv-01.home.example:8443"},
           attestation: {hostCa: {inline: $ca}}}}' | "${K[@]}" apply -f - >/dev/null
}
machine() { # <name> <pool>
  "${K[@]}" -n "$NS" apply -f - >/dev/null <<YAML
apiVersion: banlieue.io/v1alpha1
kind: VirtualMachine
metadata:
  name: $1
  labels: { banlieue.io/pool: $2 }
spec:
  classRef: { name: small }
  imageRef: { name: sandbox }
YAML
}
status() { # <machine> <status as a jq program over \$ek>
  jq -n --rawfile ek "$EK_PEM" "{status: $2}" \
    | "${K[@]}" -n "$NS" patch virtualmachine "$1" --subresource=status --type=merge --patch-file=/dev/stdin >/dev/null
}
scheduled() { printf '{providerName: "%s", providerClass: "cloud-hypervisor", failureDomain: "%s"}' "$1" "$1"; }
provider kind-host "$STATE/host-ca.pem"
machine member-1 "$POOL"
status member-1 "{scheduled: $(scheduled kind-host), attestationSubject: \"$SUBJECT\"}"
node_entry() { entries | grep -qxF "mediatore-node-$NODE_KEY $NODE_ID $AGENT_ID"; }
wait_for "$TIMEOUT" "node entry mediatore-node-$NODE_KEY with parent $AGENT_ID" node_entry
echo "mediatore-node-$NODE_KEY declared: $NODE_ID under $AGENT_ID"

say "fail closed: a listed machine with an EK and no subject, and one whose Provider's CA may sign further CAs, get no entry"
provider loose-host "$STATE/loose-ca.pem"
machine member-nosubject "$POOL"
status member-nosubject "{scheduled: $(scheduled kind-host), tpmEndorsementCertificates: [\$ek]}"
machine member-loose "$POOL"
status member-loose "{scheduled: $(scheduled loose-host), attestationSubject: \"$SUBJECT\"}"
# The reason the broker gives for the loose CA is the check's own (refuse_unconfined_ca).
wait_for "$TIMEOUT" "the broker naming loose-host's path length as the reason" log_has "loose-host" "path length constraint must be 0"
# Two resyncs of the kind configuration (watcher.resync_secs: 15) for anything to appear.
sleep 30
n=$(entries | wc -l | tr -d ' ')
[ "$n" -eq 1 ] || fail "expected the one node entry, saw $n"
entries | grep -qF "/spire/agent/x509pop/loose-host/" && fail "a node entry was declared under a host CA that may sign further CAs"
entries | grep -qF "/spire/agent/tpm/" && fail "a listed machine fell back to its EK: a tpm entry was declared"
"${K[@]}" -n "$NS" delete virtualmachine member-nosubject member-loose --wait=true >/dev/null
echo "one entry still; the broker: $(broker_logs | grep -F loose-host | grep -F 'path length constraint must be 0' | tail -1 | cut -c1-240)"

say "the guest registers the node over the SVID the attested agent issues, then announces GuestReady"
registered() { guest_logs member | grep -qF "node registered"; }
wait_for "$TIMEOUT" "'node registered' in the guest log" registered
guest_logs member | grep -F "SVID from the Workload API" | grep -qF "$NODE_ID" || fail "the guest's SVID is not the node's"
# Decision 8: the record is keyed by the node key and stores the agent ID the attestation
# gives, the x509pop one, never a tpm ID recomputed from the key.
recorded() { "${K[@]}" get sandboxnodes -A -o json 2>/dev/null | jq -e --arg id "$AGENT_ID" '[.items[] | select(.spec.nodeId == $id)] | length == 1' >/dev/null; }
wait_for "$TIMEOUT" "one SandboxNode whose nodeId is $AGENT_ID" recorded
"${K[@]}" get sandboxnodes -A -o json | jq -e --arg key "$NODE_KEY" '[.items[] | select(.spec.nodeId | endswith("/spire/agent/tpm/" + $key))] | length == 0' >/dev/null \
  || fail "a SandboxNode carries a tpm agent ID made from the x509pop node key"
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
echo "the guest got $NODE_ID from the attested agent, registered (the record's agent is $AGENT_ID), then announced GuestReady"

say "replaced: a fresh pod (new agent state, the same key and certificate) re-attests as the same agent; the node registered again"
OLD_POD=$(member_pod member)
# What the server holds for the agent before: the serial of the SVID the first attestation
# was answered with. The agent list alone would still show this agent had the new pod never
# attested at all.
OLD_SERIAL=$(agent_serial)
[ -n "$OLD_SERIAL" ] || fail "spire-server agent list gives no SVID serial for $AGENT_ID"
"${K[@]}" -n "$NS" rollout restart deploy/member >/dev/null
new_pod() { local p; p=$(member_pod member); [ -n "$p" ] && [ "$p" != "$OLD_POD" ]; }
wait_for "$TIMEOUT" "a new member pod" new_pod
"${K[@]}" -n "$NS" rollout status deploy/member --timeout=120s >/dev/null
wait_for "$TIMEOUT" "'Node attestation was successful' as $AGENT_ID in the new pod's agent log" attested
[ "$(member_pod member)" != "$OLD_POD" ] || fail "the attestation line read is the old pod's"
memory_km || fail "the new pod's agent did not load the memory key manager"
reissued() { local now; now=$(agent_serial); [ -n "$now" ] && [ "$now" != "$OLD_SERIAL" ]; }
wait_for "$TIMEOUT" "a new SVID serial for $AGENT_ID in spire-server agent list (it was $OLD_SERIAL)" reissued
wait_for "$TIMEOUT" "$AGENT_ID listed after the re-attestation" listed
n=$(x509pop_agents | grep -cxF "$AGENT_ID" || true)
[ "$n" -eq 1 ] || fail "expected $AGENT_ID once after the re-attestation, the server lists it $n times"
wait_for "$TIMEOUT" "'node registered' in the new guest's log" registered
guest_logs member | grep -qF "already registered" && fail "the re-registration was taken for a clone"
wait_for "$TIMEOUT" "'GuestReady announced' in the new guest's log" announced
announced_after_registered
echo "re-attested as $AGENT_ID (${OLD_POD} replaced by $(member_pod member); the server's SVID serial for it went from $OLD_SERIAL to $(agent_serial)); registered and announced again"

say "the TPM path is untouched: a machine of a pool that is not listed, with the same subject and an EK certificate, gets its tpm entry and no x509pop one"
machine elsewhere-1 "$OTHER_POOL"
status elsewhere-1 "{scheduled: $(scheduled kind-host), attestationSubject: \"$SUBJECT\", tpmEndorsementCertificates: [\$ek]}"
tpm_entry() { entries | grep -qxF "mediatore-node-$EK_HASH spiffe://$TD/banlieue/node/$EK_HASH $TPM_AGENT_ID"; }
wait_for "$TIMEOUT" "node entry mediatore-node-$EK_HASH with parent $TPM_AGENT_ID" tpm_entry
sleep 30
n=$(entries | grep -cF "/spire/agent/x509pop/" || true)
[ "$n" -eq 1 ] || fail "expected one x509pop entry (member-1's), saw $n"
n=$(entries | wc -l | tr -d ' ')
[ "$n" -eq 2 ] || fail "expected two entries (member-1's x509pop, elsewhere-1's tpm), saw $n"
node_entry || fail "member-1's node entry is gone"
echo "elsewhere-1 ($NS/$OTHER_POOL, not listed): mediatore-node-$EK_HASH under $TPM_AGENT_ID; still one x509pop entry"

say "a sandbox's claim, Bound to the listed machine, is bound under the x509pop node: the claim's entry is parented to $AGENT_ID"
# As the sandbox tier does it: the broker's ServiceAccount creates the AgentSandbox (the
# subject policy lets it name a subject), the reconciler creates the owned claim and its
# record, and the script stands in for banlieue's bind, in the order banlieue writes it: the
# phase with the machine, then what it mirrors from the machine.
KSA=("${K[@]}" --as="$BROKER_SA")
"${KSA[@]}" create -f - >/dev/null <<YAML || fail "the broker's ServiceAccount could not create an AgentSandbox in $NS"
apiVersion: mediatore.io/v1beta1
kind: AgentSandbox
metadata:
  name: sb-x509pop
  namespace: $NS
spec:
  subject: { issuer: "https://issuer.example.com", id: "octocat" }
  poolRef: { name: $POOL }
  ttlSeconds: 600
  audiences: []
  workload: { image: "registry.internal:5000/sandbox:e2e", args: ["sh"] }
YAML
has_claim() { "${K[@]}" -n "$NS" get virtualmachineclaim sb-x509pop >/dev/null 2>&1; }
wait_for "$TIMEOUT" "claim sb-x509pop" has_claim
CLAIM_UID=$("${K[@]}" -n "$NS" get virtualmachineclaim sb-x509pop -o jsonpath='{.metadata.uid}')
wait_for "$TIMEOUT" "'record created' for claim $CLAIM_UID in the broker log" log_has "record created" "$CLAIM_UID"
# The machine's EK certificate is mirrored too, as banlieue would for a guest that has both:
# the pool is listed, so it must count for nothing.
jq -n --rawfile ek "$EK_PEM" --arg subject "$SUBJECT" --arg pool "$POOL" \
  '{status: {phase: "Bound", virtualMachineRef: {name: "member-1"}, poolRef: {name: $pool}, attestationSubject: $subject, tpmEndorsementCertificates: [$ek], boundAt: "2026-11-27T10:00:00Z", expiresAt: "2026-11-27T10:10:00Z"}}' \
  | "${K[@]}" -n "$NS" patch virtualmachineclaim sb-x509pop --subresource=status --type=merge --patch-file=/dev/stdin >/dev/null
claim_entry() { entries | grep -qxF "mediatore-claim-$CLAIM_UID spiffe://$TD/banlieue/claim/$CLAIM_UID $AGENT_ID"; }
wait_for "$TIMEOUT" "claim entry mediatore-claim-$CLAIM_UID with parent $AGENT_ID" claim_entry
entries | grep -F "mediatore-claim-$CLAIM_UID " | grep -qF "/spire/agent/tpm/" && fail "the claim's entry is parented to a tpm agent"
sandbox_ready() { [ "$("${K[@]}" -n "$NS" get agentsandbox sb-x509pop -o jsonpath='{.status.phase}/{.status.entrySet}/{.status.ready}' 2>/dev/null)" = "Bound/true/true" ]; }
wait_for "$TIMEOUT" "sb-x509pop Bound, entry set, Ready" sandbox_ready
subject_fetched() { guest_logs member | grep -F "subject fetched" | grep -qF "$CLAIM_UID"; }
wait_for "$TIMEOUT" "'subject fetched' with claim $CLAIM_UID in the guest log" subject_fetched
echo "mediatore-claim-$CLAIM_UID declared under $AGENT_ID through the admission policy; sb-x509pop Ready; the guest, on its node SVID, fetched the claim"
"${K[@]}" -n "$NS" delete agentsandbox sb-x509pop --wait=false >/dev/null
claim_entry_gone() { ! entries | grep -qF "mediatore-claim-$CLAIM_UID "; }
wait_for "$TIMEOUT" "claim entry for $CLAIM_UID retracted after the sandbox's deletion" claim_entry_gone

say "PASS: ADR-0049 holds against a real SPIRE and the real broker (deploy/spire-x509pop and the image's agent-x509pop.conf; refused under a bundle without the host CA and under the host CA's name on another key; attested as x509pop/<host CA CN>/<machine UID>; the node entry named by the SHA-256 of that agent ID, declared from the Provider's inline host CA and the machine's subject for a pool in watcher.x509pop_pools only; no entry without a subject or under a CA with no path length of zero; the guest registered with --node-attestation x509pop and the record holds the x509pop agent ID; re-attestation under the same ID with a new SVID; a pool not listed still tpm; a claim bound under the x509pop node with its entry parented to that agent; the bundle check passing the server's bundle and refusing a shared name and a loose CA), and ADR-0019's GuestReady follows the registration"
