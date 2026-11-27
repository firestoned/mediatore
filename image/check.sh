#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# What the sandbox VM image must carry, and must not (ADR-0023), checked inside the built
# image with a container runtime. Runs in CI on every pull request and on the build host
# with `make guest-image-check`. Boots nothing: the live proof is a libvirt member.
set -euo pipefail

IMAGE=${1:?usage: check.sh <image>}
CLI=${CONTAINER_CLI:-docker}
PLUGIN_SHA=$(sed -n 's/.*plugin_checksum = "\([0-9a-f]*\)".*/\1/p' "$(dirname "$0")/spire/agent.conf")
[ -n "$PLUGIN_SHA" ] || { echo "image/spire/agent.conf carries no plugin_checksum"; exit 1; }

run() { "$CLI" run --rm --entrypoint sh "$IMAGE" -c "$1"; }

# file_of <cloud-config> <path>: the content of one `files` entry of a cloud-config layer,
# as the member would find it at <path>. For the checks that read an example's embedded files.
FILE_OF=$(cat <<'SH'
file_of() {
  awk -v p="$2" '
    $1 == "-" && $2 == "path:" { want = ($3 == p); body = 0; next }
    want && $1 == "content:" { body = 1; match($0, /^ */); indent = RLENGTH; next }
    body { match($0, /^ */); if (NF && RLENGTH <= indent) { body = 0; want = 0; next } print substr($0, indent + 3) }
  ' "$1"
}
SH
)

fail=0
check() { # <what> <shell>
  if run "$2" >/dev/null 2>&1; then echo "✓ $1"; else echo "✗ $1"; fail=1; fi
}

echo "checking $IMAGE"
check "the one mediatore binary at the pinned path, static, runs" \
  'test -x /usr/bin/mediatore && /usr/bin/mediatore --help >/dev/null && ! ldd /usr/bin/mediatore 2>/dev/null | grep -q "=>"'
check "no binary under /usr/local (the persistent partition mounts over it)" \
  '! find /usr/local/bin /usr/local/sbin -type f 2>/dev/null | grep -q .'
check "the SPIRE agent in the rootfs" \
  'test -x /usr/bin/spire-agent && /usr/bin/spire-agent --version 2>&1 | grep -q "[0-9]\.[0-9]"'
check "the TPM attestor plugin at the path agent.conf names, with the checksum it pins" \
  "echo '$PLUGIN_SHA  /usr/lib/spire/tpm_attestor_agent' | sha256sum -c - >/dev/null"
check "nftables, for the jail's ruleset (ADR-0020)" 'nft --version >/dev/null'
check "nsjail, the jail itself, linked against what the image has" \
  'test -x /usr/bin/nsjail && ! ldd /usr/bin/nsjail | grep -q "not found" && /usr/bin/nsjail --help 2>&1 | grep -q -- "--chroot"'
check "mount and umount, for the sandbox tmpfs (ADR-0021)" 'command -v mount && command -v umount'
check "kill, for the sandbox user's processes at the end of a claim (ADR-0020 decision 6)" 'test -x /usr/bin/kill || test -x /bin/kill'
check "the sandbox root and the agent's configuration directory, 0755, in the immutable root" \
  'test "$(stat -c %a /mnt/sandbox)" = 755 && test "$(stat -c %a /etc/spire)" = 755'
check "tpm2-tools, for the EK certificate export (banlieue examples/21)" 'command -v tpm2_nvread'
check "qemu-guest-agent, the libvirt channel for GuestReady (ADR-0019)" 'command -v qemu-ga'
check "the guest agent's allow-list (R-43): /etc/qemu/qemu-ga.conf names the eight commands the hypervisor side sends, and no exec, file write, password or ssh key command" \
  'f=/etc/qemu/qemu-ga.conf; test -f $f && grep -qx "\[general\]" $f && test "$(grep -c "^allow-rpcs=" $f)" -eq 1 && l=$(sed -n "s/^allow-rpcs=//p" $f) && for c in guest-sync-delimited guest-sync guest-ping guest-info guest-file-open guest-file-read guest-file-close guest-network-get-interfaces; do printf "%s\n" "$l" | tr "," "\n" | grep -qx "$c" || exit 1; done && test "$(printf "%s\n" "$l" | tr "," "\n" | wc -l)" -eq 8 && ! grep -v "^#" $f | grep -Eq "guest-exec|guest-file-write|guest-set-user-password|guest-ssh-|block-rpcs|blacklist"'
check "the agent itself reports that allow-list: allow-rpcs is a key this qemu-ga reads, not one it ignores" \
  'qemu-ga --dump-conf | grep "^allow-rpcs=" | grep -q "guest-file-read" && ! qemu-ga --dump-conf | grep "^allow-rpcs=" | grep -Eq "guest-exec|guest-file-write|guest-set-user-password|guest-ssh-"'
check "the spire user, in the TPM device group" 'id -nG spire | tr " " "\n" | grep -qx tss'
check "the four units installed" \
  'test -f /etc/systemd/system/spire-agent.service && test -f /etc/systemd/system/mediatore-guest.service && test -f /etc/systemd/system/mediatore-host-nft.service && test -f /etc/systemd/system/spire-bundle-fetch.service'
check "the four units enabled" \
  'for u in spire-agent mediatore-guest mediatore-host-nft spire-bundle-fetch; do test -L /etc/systemd/system/multi-user.target.wants/$u.service || exit 1; done'
check "the bundle fetch (ADR-0037): curl and the system CAs, the script, its unit before the agent, which requires it" \
  'command -v curl && test -f /etc/ssl/certs/ca-certificates.crt && test -x /usr/libexec/mediatore/spire-bundle-fetch && grep -q "^Before=spire-agent.service" /etc/systemd/system/spire-bundle-fetch.service && grep -q "^Requires=.*spire-bundle-fetch.service" /etc/systemd/system/spire-agent.service && grep -q "^After=.*mediatore-host-nft.service" /etc/systemd/system/spire-bundle-fetch.service'
check "the host table script, rendering from the pool's files, refusing a name and refusing a registry around the gateway (ADR-0029, ADR-0063)" \
  'test -x /usr/libexec/mediatore/host-table && d=$(mktemp -d) && printf "198.51.100.1:8443\n" > $d/g && : > $d/r && printf "MEDIATORE_URL=https://198.51.100.1:3130\n" > $d/e && printf "agent {\n  server_address = \"198.51.100.1\"\n  server_port = \"3129\"\n}\n" > $d/a && /usr/libexec/mediatore/host-table --render $d/g $d/r $d/e $d/a | grep -q "policy drop" && printf "198.51.100.10:5000\n" > $d/r && ! /usr/libexec/mediatore/host-table --render $d/g $d/r $d/e $d/a >/dev/null 2>&1 && : > $d/r && printf "gateway.home.example:8443\n" > $d/g && ! /usr/libexec/mediatore/host-table --render $d/g $d/r $d/e $d/a >/dev/null 2>&1'
check "the host table on Azure (ADR-0068): IMDS dropped, WireServer root's at 80 and 32526 and the DHCP renewal's, by the user systemd-networkd runs as, which exists; another tag renders no platform rule" \
  'id -u systemd-network >/dev/null && grep -qx "User=systemd-network" /usr/lib/systemd/system/systemd-networkd.service && d=$(mktemp -d) && printf "198.51.100.1:8443\n" > $d/g && : > $d/r && printf "MEDIATORE_URL=https://198.51.100.1:3130\n" > $d/e && printf "agent {\n  server_address = \"198.51.100.1\"\n  server_port = \"3129\"\n}\n" > $d/a && printf "7783-7084-3265-9085-8269-3286-77\n" > $d/t && t=$(CHASSIS_ASSET_TAG_FILE=$d/t /usr/libexec/mediatore/host-table --render $d/g $d/r $d/e $d/a) && printf "%s\n" "$t" | grep -q "ip daddr 169.254.169.254 log prefix \"mediatore-host imds: \" counter drop" && printf "%s\n" "$t" | grep -q "ip daddr 168.63.129.16 tcp dport { 80, 32526 } meta skuid 0 accept" && printf "%s\n" "$t" | grep -q "ip daddr 168.63.129.16 udp sport 68 udp dport 67 meta skuid \"systemd-network\" accept" && printf "none\n" > $d/t && ! CHASSIS_ASSET_TAG_FILE=$d/t /usr/libexec/mediatore/host-table --render $d/g $d/r $d/e $d/a | grep -Eq "168\.63|169\.254"'
check "the host table counts what it drops by name (ADR-0070 decision 4): pool_inbound with its sources and pool_output with its ports, each on one rule in front of its chain's last drop; a named counter is only on a rule that drops, and the table accepts in the five places it did before" \
  'd=$(mktemp -d) && printf "198.51.100.1:8443\n" > $d/g && : > $d/r && printf "MEDIATORE_URL=https://198.51.100.1:3130\n" > $d/e && printf "agent {\n  server_address = \"198.51.100.1\"\n  server_port = \"3129\"\n}\n" > $d/a && t=$(CHASSIS_ASSET_TAG_FILE=$d/none /usr/libexec/mediatore/host-table --render $d/g $d/r $d/e $d/a) && printf "%s\n" "$t" | grep -qx "    meta nfproto ipv4 meta l4proto tcp ct state new counter name \"pool_inbound\" update @inbound_sources { ip saddr . tcp dport } log prefix \"mediatore-host input: \" drop" && printf "%s\n" "$t" | grep -qx "    meta l4proto tcp ct state new counter name \"pool_output\" update @output_ports { tcp dport } log prefix \"mediatore-host drop: \" drop" && printf "%s\n" "$t" | grep -qx "  set inbound_sources { type ipv4_addr . inet_service; size 4096; flags dynamic,timeout; counter; timeout 5m; }" && printf "%s\n" "$t" | grep -qx "  set output_ports { type inet_service; size 1024; flags dynamic,timeout; counter; timeout 5m; }" && printf "%s\n" "$t" | grep -qx "  counter pool_inbound { }" && printf "%s\n" "$t" | grep -qx "  counter pool_output { }" && test "$(printf "%s\n" "$t" | grep -c "counter name")" = 2 && ! printf "%s\n" "$t" | grep "counter name" | grep -qv " drop\$" && test "$(printf "%s\n" "$t" | grep -c "accept\$")" = 5 && printf "%s\n" "$t" | sed -n "/^  chain input {\$/,/^  }\$/p" | tail -2 | head -1 | grep -qx "    log prefix \"mediatore-host input: \" counter drop" && printf "%s\n" "$t" | sed -n "/^  chain output {\$/,/^  }\$/p" | tail -2 | head -1 | grep -qx "    log prefix \"mediatore-host drop: \" counter drop"'
check "the host table unit runs only with a gateway list, before the agent and the guest, which require it" \
  'grep -q "^ConditionPathExists=/etc/mediatore/gateways" /etc/systemd/system/mediatore-host-nft.service && grep -q "^ExecStart=/usr/libexec/mediatore/host-table" /etc/systemd/system/mediatore-host-nft.service && grep -q "^Requires=.*mediatore-host-nft.service" /etc/systemd/system/spire-agent.service && grep -q "^Requires=.*mediatore-host-nft.service" /etc/systemd/system/mediatore-guest.service'
check "the units point at the paths the image has" \
  'grep -q "^ExecStart=/usr/bin/spire-agent run -config /etc/spire/agent.conf" /etc/systemd/system/spire-agent.service && grep -q "^ExecStart=/usr/bin/mediatore guest" /etc/systemd/system/mediatore-guest.service'
check "the agent unit: a private /tmp for the attestor plugin, CAP_SYS_PTRACE for the unix attestor, its runtime directory" \
  'grep -q "^PrivateTmp=yes" /etc/systemd/system/spire-agent.service && grep -q "^AmbientCapabilities=CAP_SYS_PTRACE" /etc/systemd/system/spire-agent.service && grep -q "^RuntimeDirectory=spire" /etc/systemd/system/spire-agent.service'
check "the x509pop node-cert units installed but not enabled, and their examples (ADR-0049)" \
  'u=/etc/systemd/system && grep -q "^ExecStart=/usr/bin/mediatore node-cert fetch" $u/mediatore-node-cert.service && grep -q "^Before=spire-agent.service" $u/mediatore-node-cert.service && grep -q "^User=spire" $u/mediatore-node-cert.service && grep -q "^ExecStart=/usr/bin/mediatore node-cert renew" $u/mediatore-node-cert-renew.service && ! test -e $u/multi-user.target.wants/mediatore-node-cert.service && grep -q "^Requires=mediatore-node-cert.service" /usr/share/mediatore/spire-agent-x509pop.conf.example && grep -q "NodeAttestor \"x509pop\"" /usr/share/mediatore/agent-x509pop.conf.example && ! grep -q "^ *intermediates_path" /usr/share/mediatore/agent-x509pop.conf.example && /usr/bin/mediatore node-cert --help >/dev/null'
# A member with no vTPM cannot seal its disk, so its agent writes nothing of its identity to
# one (ADR-0049, amended 2026-11-27): the key manager is the memory one and the data
# directory is on tmpfs, in the shipped configuration and in the pool's example alike, and
# the drop-in makes that directory with a binary the image has.
check "the x509pop agent keeps its SVID key in memory and its data on tmpfs, nothing under /var/lib (ADR-0049)" \
  "$FILE_OF"'
  f=/usr/share/mediatore/cloud-config-deployment-x509pop.example.yaml && d=$(mktemp -d) && file_of $f /etc/spire/agent.conf > $d/agent.conf \
  && for c in /usr/share/mediatore/agent-x509pop.conf.example $d/agent.conf; do test "$(grep -c "^ *KeyManager " $c)" = 1 && grep -q "^ *KeyManager \"memory\" {" $c && grep -qx " *data_dir = \"/run/spire/agent\"" $c && ! grep -v "^ *#" $c | grep -q "/var/lib" || exit 1; done \
  && grep -qx "ExecStartPre=/usr/bin/install -d -m 0700 /run/spire/agent" /usr/share/mediatore/spire-agent-x509pop.conf.example && test -x /usr/bin/install \
  && grep -q "^RuntimeDirectory=spire$" /etc/systemd/system/spire-agent.service && grep -q "^RuntimeDirectoryPreserve=yes" /etc/systemd/system/spire-agent.service && grep -q "^ReadWritePaths=.*/run/spire" /etc/systemd/system/spire-agent.service'
check "the x509pop pool's cloud-config example (ADR-0049): a cloud-config kairos-agent accepts, its agent.conf one spire-agent accepts, naming the x509pop attestor over node-cert's two files and nothing of the TPM plugin, no intermediates_path, its drop-in the image's own, the guest told MEDIATORE_NODE_ATTESTATION=x509pop" \
  "$FILE_OF"'
  f=/usr/share/mediatore/cloud-config-deployment-x509pop.example.yaml && d=$(mktemp -d) && test "$(head -n 1 $f)" = "#cloud-config" && kairos-agent validate $f \
  && file_of $f /etc/spire/agent.conf > $d/agent.conf && /usr/bin/spire-agent validate -config $d/agent.conf \
  && grep -q "NodeAttestor \"x509pop\"" $d/agent.conf && ! grep -Eq "NodeAttestor \"tpm\"|plugin_cmd|plugin_checksum" $d/agent.conf && ! grep -q "intermediates_path *=" $f \
  && for k in private_key_path certificate_path; do test "$(grep -c "^ *$k = " $d/agent.conf)" = 1 && test "$(grep "^ *$k = " $d/agent.conf | tr -d " ")" = "$(grep "^ *$k = " /usr/share/mediatore/agent-x509pop.conf.example | tr -d " ")" || exit 1; done \
  && file_of $f /etc/systemd/system/spire-agent.service.d/x509pop.conf > $d/dropin && test -s $d/dropin && test "$(cat $d/dropin)" = "$(grep -v "^#" /usr/share/mediatore/spire-agent-x509pop.conf.example | grep .)" \
  && file_of $f /etc/mediatore-guest/env > $d/env && test "$(grep -c "^MEDIATORE_NODE_ATTESTATION=" $d/env)" = 1 && grep -qx "MEDIATORE_NODE_ATTESTATION=x509pop" $d/env && ! grep -v "^#" $d/env | grep -q "[[:space:]]#"'
check "no sshd, ssh and the distribution's nftables unit masked (ADR-0010: nothing inbound; ADR-0029: one owner of the table)" \
  '! command -v sshd && for u in ssh.service ssh.socket nftables.service; do test "$(readlink /etc/systemd/system/$u)" = /dev/null || exit 1; done'
check "no other listener the base shipped (snmpd, lldpd, rpcbind)" \
  '! command -v snmpd && ! command -v lldpd && ! command -v rpcbind'
check "Yama's ptrace scope raised in the image's sysctl (ADR-0025, roadmap 06)" \
  'grep -qx "kernel.yama.ptrace_scope = 1" /etc/sysctl.d/99-mediatore.conf'
check "the kernel hardening in the image's sysctl: no MPTCP, no io_uring, kernel addresses and the kernel log restricted, no unprivileged bpf, the BPF JIT hardened" \
  'for k in "net.mptcp.enabled = 0" "kernel.io_uring_disabled = 2" "kernel.kptr_restrict = 2" "kernel.dmesg_restrict = 1" "kernel.unprivileged_bpf_disabled = 1" "net.core.bpf_jit_harden = 2"; do grep -qx "$k" /etc/sysctl.d/99-mediatore.conf || exit 1; done'
check "the host table loads before the network, and host-quiet after it (ADR-0063 decision 8)" \
  'u=/etc/systemd/system/mediatore-host-nft.service && grep -qx "DefaultDependencies=no" $u && grep -q "^Before=network-pre.target" $u && grep -qx "Wants=network-pre.target" $u && grep -qx "ExecStartPost=/usr/libexec/mediatore/host-quiet" $u && test -x /usr/libexec/mediatore/host-quiet && /usr/libexec/mediatore/host-quiet --list | grep -qx systemd-resolved.service'
check "the datasource reads local devices only, no cloud metadata address (ADR-0063 decision 8)" \
  'test "$(grep -c "providers:" /system/oem/00_datasource.yaml)" = 1 && grep -q "providers: \[\"cdrom\", \"config-drive\", \"vmware\"\]" /system/oem/00_datasource.yaml'
check "no private key material (banlieue ADR-0108 decision 2)" \
  '! grep -rl "PRIVATE KEY" /etc /usr/share/mediatore /var/lib 2>/dev/null | grep -q .'

[ "$fail" -eq 0 ] && echo "image ok" || { echo "image check failed"; exit 1; }
