<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Locking down a sandbox VM's network

**Best practice for every deployment:** a sandbox VM may talk to **one peer, the egress gateway of its own segment**, and to no
other VM on the segment, ever, from power-on to deletion. The workload shares the VM's network namespace (the jail does not give it
one), so the VM's firewall is the only thing between a hostile workload and every other sandbox in the range. Treat the segment as
hostile: sandboxes of different teams, and different claims of the same team, share it.

This guide says what to configure, in the guest's cloud-config, and how to check it. The reference implementation is the
`sc90-agent-sandbox` repository (`sandbox-pool/secret-mediatore-guest-base.yaml`).

## The goal, stated as testable rules

1. A sandbox VM cannot open a connection to any address in the sandbox range except its gateway's listed ports.
2. No other VM in the range can open a connection to it, on any port.
3. No other VM can ride a flow the VM opened (a spoofed gateway source gets nothing).
4. The VM answers and asks ARP for its gateway only.
5. There is no moment in which rules 1 to 4 do not hold: not before the host table loads, not if the host table fails to load.
6. IPv6, forwarding, redirects and source routing are off; nothing listens on a non-loopback address.

## Layers

| Layer | Control | Why it is not optional |
| --- | --- | --- |
| 0 | A deny-all table, loaded before `network-pre.target`, with the host table's name; the host table replaces it in one transaction | Closes the boot window, and a host table that fails to load leaves the VM closed, not open |
| 1 | `inet mediatore_host`: input, forward and output default drop; output only to the gateways' listed address and port pairs; established input only from a gateway address | Rules 1 to 3. One `inet` table covers IPv4 and IPv6 |
| 2 | `arp mediatore_arp`: ARP in and out only for the segment gateway | An `inet` table never sees ARP; this is the layer-2 part of rule 4 |
| 3 | Sysctls (`ip_forward`, redirects, source route, `rp_filter`, IPv6 off), no `rpcbind`, no LLMNR or mDNS, no sshd | Removes listeners and protocols there is no reason to have |
| 4 | The sandbox uid's per-claim `mediatore_sandbox` table, and the gateway's own input filter with forwarding off | A second table for the uid that runs the workload, and a gateway that never routes between sandboxes |

The gateway is the **only** path. Cross-segment gateways may appear in the allow list for failover; a deployment that wants strictly
one address lists one.

## Configure it

All of this goes in the guest's cloud-config layers, not in a script run by hand, because the root is read-only and `/etc` is
rewritten at every boot.

### Layer 0: before the network

Write it in the `initramfs` stage (the `boot` stage runs after `multi-user.target` has started, which is too late):

```
table inet mediatore_host
delete table inet mediatore_host
table inet mediatore_host {
  chain input   { type filter hook input   priority filter; policy drop; iif "lo" accept }
  chain forward { type filter hook forward priority filter; policy drop; }
  chain output  { type filter hook output  priority filter; policy drop; oif "lo" accept }
}
```

loaded by a unit that is `WantedBy=sysinit.target`, `DefaultDependencies=no` and `Before=network-pre.target`. The unit's
`ConditionPathExists=|/run/cos/active_mode` keeps it off the installer's live system, which needs its network. Keep it loaded: the
host table's own unit must not `nft delete table` on stop.

### Layer 1: the host table

`delete table` then `table` in a single `nft -f` transaction, so the replacement has no open instant. Two details that are easy to
get wrong:

```
set allow4    { type ipv4_addr . inet_service; elements = { <gateway> . <port>, ... } }
set gateways4 { type ipv4_addr; elements = { <gateway>, ... } }
chain input {
  type filter hook input priority filter; policy drop;
  iif "lo" accept
  ct state established,related ip saddr @gateways4 accept   # not a bare "established,related accept"
  ct state invalid drop
}
```

A bare `ct state established,related accept` also admits a neighbour that sends packets matching a flow the VM opened. Tying it to the
gateway addresses removes that.

### Layer 2: ARP

```
table arp mediatore_arp
delete table arp mediatore_arp
table arp mediatore_arp {
  chain input  { type filter hook input  priority filter; policy drop; arp saddr ip <segment-gateway> accept; counter drop }
  chain output { type filter hook output priority filter; policy drop; arp daddr ip <segment-gateway> accept; counter drop }
}
```

Load it with the host table, not with layer 0: the address is configured, and the VM resolves its gateway, while layer 0 is loaded.
The segment gateway is the host of `MEDIATORE_URL`; derive it at boot (the network address plus one on the VM's own prefix), do not
hand-write a different value per segment.

### Layer 3: the rest

```
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv6.conf.all.disable_ipv6 = 1
```

(the same for `default`), `LLMNR=no` and `MulticastDNS=no` in a `resolved.conf.d` drop-in, and `systemctl mask rpcbind.service
rpcbind.socket`. The base image's own `sshd` stays masked.

## Check it

On a VM, as root (the table has no exception for root: since ADR-0063 no registry is reached but through a claim's proxy):

```
nft list table inet mediatore_host     # input, forward, output: policy drop
nft list table arp mediatore_arp
ss -tuln                               # no listener on a non-loopback address
ip -6 addr show scope global           # nothing
# a neighbour and the gateway, three seconds each:
timeout 3 bash -c 'echo > /dev/tcp/<neighbour>/22'      # exit 124: blocked
timeout 3 bash -c 'echo > /dev/tcp/<gateway>/<port>'    # exit 0: the listed port
nft list chain inet mediatore_host output | grep counter   # the drop counter rises with each blocked probe
```

Run the same as the workload's uid inside a claim, and from a neighbour towards the VM. `nft -c -f <file>` checks a ruleset without
loading it, which is how to test a change on a live VM first.

## Pitfalls found by testing it

- **Sysctl file order.** The last file read wins, and a base image may ship its own (`99-*-hardening.conf` set `net.ipv4.ip_forward = 1`).
  Name your file so it sorts after them (`999-...`), and read the value back on a booted VM.
- **Directory modes in the cloud-config.** Write modes as decimal (`493` for `0755`). A `directories` entry spelled `0755` produced a mode
  like `d-wxr----x` on a real VM: the `systemd-resolved` user could not read its drop-in directory, so `LLMNR=no` was never applied, and
  an existing system directory was changed too. Do not list a directory that already exists, and check `ls -ld` after the first boot.
- **A listener is a defect even when the input chain drops it.** Read `ss -tuln` on a booted VM, not the unit files.

## What this does not cover

- **A hostile hypervisor or a port group that bridges VMs.** If the virtualisation layer lets sandboxes see each other's frames, rules
  here still hold on the VM, but ask whether the sandbox port groups should also isolate VMs from one another (a private VLAN or a
  distributed firewall). That is a layer under these and is not configured from the guest.
- **A workload with `CAP_NET_ADMIN` or root in the VM.** The jail drops capabilities; the host table is enforceable only against a
  workload that cannot change it.
- **The gateway.** It sees every sandbox's allowed traffic; its filter and its refusal to forward are its own controls (the gateway
  guide).

## Status

Proposed practice with a reference implementation. Run 1 on the infra pools of three clusters passed the neighbour matrix (unprivileged user and root: only the gateway's listed ports connect) and found the two pitfalls above; a repeat as the workload uid inside a real claim (one VM, cluster-01) reached the gateway's two claim ports only and no neighbour. Before that, a dry run (`nft -c`) and a live load on one idle pool VM showed the gateway
reachable and every neighbour, other segment and public address blocked. Not yet proven: the layer-0 unit across a real boot, the
ARP drop side (no neighbour sent a request in the test), and the rules as the workload uid on clusters 02 and 03. The full test is tracked in the
`sc90-agent-sandbox` repository under `testing/network-lockdown/`.
