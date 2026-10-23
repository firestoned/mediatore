#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# A vTPM for the kind node (`make kind-vtpm`, roadmap 02): swtpm behind the kernel's vtpm
# proxy is a character device on the host, /dev/tpmrmN, which kind mounts into the node
# at creation and a pod opens the way a pool VM opens its own. The EK certificate is
# signed by a throwaway swtpm local CA this script creates under <dir>, never the host's
# own /var/lib/swtpm-localca, so the test's trust anchors are the test's. Needs sudo (the
# proxy's control device and the device nodes are root's), swtpm, swtpm_setup, openssl.
#
#   vtpm.sh up <dir>     writes into <dir>:
#     device      the host path of the resource-manager device (/dev/tpmrmN)
#     ek.pem      the RSA EK certificate as the TPM carries it (NV 0x01c00002)
#     ek-ecc.pem  the ECC one (NV 0x01c0000a)
#     ek.hash     sha256 of the RSA EK's SubjectPublicKeyInfo DER: the agent ID the
#                 attestor derives, and the node identity mediatore computes
#     ek-ca.pem   the certificate that signed the EK certificates (the local CA's issuing
#                 certificate, issuercert.pem); what the EK trust bundle must carry
#     rootca.pem  the local CA's root, which signed ek-ca.pem and nothing else
#   vtpm.sh down <dir>   stops the swtpm (the device disappears) and removes <dir>
set -euo pipefail

cmd=${1:?up|down}
D=${2:?state dir}
# Absolute: the swtpm daemon changes directory, and the device path is read by make.
mkdir -p "$D"; D=$(cd "$D" && pwd)

need() { command -v "$1" >/dev/null 2>&1 || { echo "$1 is required" >&2; exit 1; }; }

case $cmd in
up)
  need sudo; need swtpm; need swtpm_setup; need openssl
  if [ -r "$D/device" ] && [ -c "$(cat "$D/device")" ] && [ -r "$D/pid" ] && sudo kill -0 "$(cat "$D/pid")" 2>/dev/null; then
    echo "✓ vTPM already up at $(cat "$D/device") (EK $(cat "$D/ek.hash"))"
    exit 0
  fi
  sudo rm -rf "$D"
  mkdir -p "$D/localca" "$D/state" "$D/ek"
  cat > "$D/swtpm-localca.conf" <<EOF
statedir = $D/localca
signingkey = $D/localca/signkey.pem
issuercert = $D/localca/issuercert.pem
certserial = $D/localca/certserial
EOF
  cat > "$D/swtpm-localca.options" <<EOF
--platform-manufacturer mediatore
--platform-version 1
--platform-model kind
EOF
  cat > "$D/swtpm_setup.conf" <<EOF
create_certs_tool = $(command -v swtpm_localca)
create_certs_tool_config = $D/swtpm-localca.conf
create_certs_tool_options = $D/swtpm-localca.options
active_pcr_banks = sha256
EOF
  sudo modprobe tpm_vtpm_proxy
  # swtpm_localca creates the local CA (a root and the issuing certificate it signs) on
  # its first use, as it does on a hypervisor; the EK certificates are written out beside
  # being put in the TPM's NV, so the test has them without tpm2-tools.
  sudo swtpm_setup --tpm2 --tpmstate "$D/state" --create-ek-cert --create-platform-cert --overwrite \
    --config "$D/swtpm_setup.conf" --write-ek-cert-files "$D/ek" > "$D/setup.log" 2>&1 \
    || { cat "$D/setup.log" >&2; echo "swtpm_setup failed" >&2; exit 1; }
  out=$(sudo swtpm chardev --vtpm-proxy --tpm2 --tpmstate "dir=$D/state" --daemon --pid "file=$D/pid" \
    --log "file=$D/swtpm.log,level=1" --flags not-need-init,startup-clear)
  dev=$(sed -n 's#^New TPM device: \(/dev/tpm[0-9]*\).*#\1#p' <<<"$out")
  [ -n "$dev" ] || { echo "swtpm did not report a device: $out" >&2; exit 1; }
  rm=${dev/tpm/tpmrm}
  for _ in $(seq 1 50); do [ -c "$rm" ] && break; sleep 0.2; done
  [ -c "$rm" ] || {
    echo "$rm did not appear; swtpm:" >&2; sudo cat "$D/swtpm.log" >&2 || true
    echo "kernel:" >&2; sudo dmesg | grep -i tpm | tail -5 >&2 || true
    exit 1
  }
  # The invoking user owns the device nodes: that is root inside a rootless kind node and
  # irrelevant under a rootful runtime. The state stays readable by root's swtpm.
  sudo chown "$(id -u)" "$dev" "$rm"
  sudo chown -R "$(id -u)" "$D"
  openssl x509 -inform DER -in "$D/ek/ek-rsa2048.crt" -out "$D/ek.pem"
  openssl x509 -inform DER -in "$D/ek/ek-secp384r1.crt" -out "$D/ek-ecc.pem"
  openssl x509 -in "$D/ek.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1 | tr -d '\n' > "$D/ek.hash"
  cp "$D/localca/issuercert.pem" "$D/ek-ca.pem"
  cp "$D/localca/swtpm-localca-rootca-cert.pem" "$D/rootca.pem"
  openssl verify -CAfile "$D/rootca.pem" -untrusted "$D/ek-ca.pem" "$D/ek.pem" >/dev/null \
    || { echo "the EK certificate does not chain to the local CA" >&2; exit 1; }
  printf '%s' "$rm" > "$D/device"
  echo "✓ vTPM at $rm; EK $(cat "$D/ek.hash"), its certificate signed by $(openssl x509 -in "$D/ek-ca.pem" -noout -subject | sed 's/^subject=//')"
  ;;
down)
  [ -d "$D" ] || exit 0
  if [ -r "$D/pid" ] && sudo kill -0 "$(cat "$D/pid")" 2>/dev/null; then
    sudo kill "$(cat "$D/pid")"
    dev=$(cat "$D/device" 2>/dev/null || true)
    for _ in $(seq 1 50); do [ -n "$dev" ] && [ -c "$dev" ] || break; sleep 0.2; done
  fi
  sudo rm -rf "$D"
  echo "✓ vTPM down"
  ;;
*)
  echo "usage: vtpm.sh up|down <dir>" >&2
  exit 2
  ;;
esac
