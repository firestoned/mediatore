<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0068: The cloud platform's host addresses: WireServer root's alone on Azure, the metadata service nobody's

**Status:** Accepted, implemented 2026-11-26 (`image/host-table`, `image/gateway/nftables.conf.in`,
`make host-table-test`, `make gateway-render-check`, `image/check.sh`, `image/gateway/check.sh`; both
images built and checked with podman on the build host; **not yet run on an Azure VM**) · **Date:** 2026-11-26

Amends [ADR-0029](0029-the-pull-on-a-routeless-segment-and-the-pool-vms-root-rules.md) decision 3 (the pool
VM's host table gains three lines on Azure, and refuses a platform address in a pool's files everywhere) and
[ADR-0053](0053-the-gateways-authorizer-has-an-identity-of-its-own.md) decisions 5 and 6 (the gateway's
output chain gains a rule for every user ahead of the per-user rows). Changes nothing about identities, token
shapes, the sandbox uid's per-claim table ([ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md)), or
a direct pool, which still loads no host table (ADR-0029 decision 4).

## Context

banlieue's Azure provider runs mediatore's VM images on Azure VMs (its spike, recorded outside this
repository). Two Azure facts collide with the tables this repository ships:

- **The ready report.** A VM created from a generalized image stays `Creating` until the guest tells the
  platform it is ready: an HTTP `GET ?comp=goalstate` then `POST ?comp=health` to the host-local
  **WireServer**, `168.63.129.16`, TCP 80 (the host plugin listens at TCP 32526 on the same address).
  Without it ARM ends the deployment in `OSProvisioningTimedOut` after about twenty minutes. Kairos carries
  no Azure agent; banlieue's image layer runs one root-only helper (`banlieue-azure-guest ready`) when the
  guest is ready. With gateways the pool VM's host table drops it: output is default drop, open only to the
  gateways' listed address and port pairs.
- **DHCP.** Azure's DHCP server answers as `168.63.129.16`. What the existing rules do to it, read from the
  tables and the client, not assumed:
  - The first lease (DISCOVER, REQUEST) and a rebind (at T2) are broadcasts that `systemd-networkd` sends
    and receives through a packet socket, which no nftables table sees (the same fact R-65 records for the
    initramfs). The tables neither help nor hinder them.
  - The **renewal** at T1 is a unicast UDP datagram from port 68 to `168.63.129.16:67`, sent from an
    ordinary UDP socket owned by `systemd-networkd`'s own user, `systemd-network` (the unit's `User=`). The
    pool table's output policy drops it, and its reply, never tracked, would be dropped on input too. The
    lease then survives only by the broadcast rebind at T2, if that wins. **So no: the existing pool rules
    do not admit the renewal.** The gateway's output policy is accept for every user its table does not
    name, `systemd-network` among them, so there the renewal already passes.

  On a pool with gateways `image/host-quiet` removes the base's DHCP catch-all (ADR-0063 decision 8); on
  Azure the deployment's own network file (DHCP on the synthetic NIC, the accelerated-networking VF left
  unmanaged) is what runs the client, so the renewal is the one DHCP packet a table decides.

Two more things the same address and its neighbour make true:

- **The instance metadata service** (IMDS, `169.254.169.254`) hands out the VM's metadata and, with a
  managed identity, Entra tokens for it. Nothing in mediatore uses it. Today the pool table drops it by
  policy, the gateway's Envoys are kept from all of link-local (ADR-0053 decision 6), but **root and the
  daemons the gateway's table does not name reach it** (output policy accept). The same address is the
  metadata service on other clouds and on OpenStack.
- **A gateway's Envoys could reach WireServer.** It is not in `egress_refused`: a claim's allowlisted name
  that resolves to `168.63.129.16` (a record the name's owner controls) would have the data plane open a
  tunnel to the gateway VM's own WireServer, whose goal state describes that VM. On Azure `168.63.129.16`
  is also the resolver the platform hands out, so its port 53 must stay reachable for whoever resolves.

## Decision

1. **The pool VM's host table admits WireServer to root alone, and only on Azure.** `image/host-table` reads
   the DMI chassis asset tag (`/sys/class/dmi/id/chassis_asset_tag`) when it renders the table, which
   `mediatore-host-nft.service` does before `network-pre.target`. When the tag is Azure's,
   `7783-7084-3265-9085-8269-3286-77` (blanks ignored, as sysfs writes it with a newline), the output chain
   gains, after the gateways' set:

   ```
   ip daddr 168.63.129.16 tcp dport { 80, 32526 } meta skuid 0 accept
   ip daddr 168.63.129.16 udp sport 68 udp dport 67 meta skuid "systemd-network" accept
   ```

   and a comment line naming this ADR. Root reaches WireServer at its two ports and nothing else does: not
   the sandbox uid (the workload and the egress proxy), not the SPIRE agent's or any other daemon's. With any
   other tag, or none, the table is **byte for byte the one rendered before this ADR**.

2. **The DHCP renewal is `systemd-networkd`'s, by its own user.** The client renews as `systemd-network`,
   not as root, so the rule names that user and the one exchange the renewal is: UDP from 68 to 67 at
   `168.63.129.16`. Admitting it as root would mean a DHCP client running as root, which is wider; admitting
   it to every uid would hand the sandbox uid a datagram to the host. The user name resolves when the table
   loads: a base without it fails the load, and with it the agent and the guest, which require the table
   (fail closed); both images' checks assert the user exists and is the one the unit runs as.

3. **IMDS is nobody's, said explicitly.** On Azure the output chain's first rule after loopback is
   `ip daddr 169.254.169.254 log prefix "mediatore-host imds: " counter drop`, ahead of every accept, keyed
   on no uid. Off Azure the policy already drops it and the table is left unchanged (decision 1). On every
   platform `image/host-table` refuses a pool file (the gateway list, `MEDIATORE_URL`, the agent's
   `server_address`, the bundle gateway) that names a link-local address or WireServer: the every-uid set
   can never carry them.

4. **The gateway's output chain keeps both addresses to the one user that needs each, on every platform.**
   Ahead of every per-user row, for every user, root included:

   ```
   ip daddr 169.254.169.254 log prefix "mediatore-gateway out imds: " counter drop
   ip daddr 168.63.129.16 jump output_wireserver

   chain output_wireserver {
     meta l4proto { tcp, udp } th dport 53 return
     meta skuid 0 tcp dport { 80, 32526 } accept
     meta skuid "systemd-network" udp sport 68 udp dport 67 accept
     log prefix "mediatore-gateway out wireserver: " counter drop
   }
   ```

   Port 53 returns to the per-user rows, which treat the address as any resolver (the Envoys reach it, the
   authorizer, the relay and the agent do not). These lines only narrow what the table already admitted, so
   they are not gated: off Azure neither address answers, and root's and `systemd-network`'s accepts there
   are what the policy already gave them.

5. **The gate is the hypervisor's word, and a false one is harmless.** The asset tag is set by the
   hypervisor, not by the image or the deployment. A hypervisor that sets Azure's tag elsewhere only admits
   root to an address that answers nothing there; guest root, which could flush any table anyway, is not
   what the table bounds (ADR-0020 decision 7). The tag file is read once, at render, and is overridable
   (`CHASSIS_ASSET_TAG_FILE`) for tests only.

## Consequences

- An Azure pool member can report ready, and keep its lease, under the host table; the sandbox uid and every
  daemon but `systemd-networkd` are kept from WireServer, and every uid from IMDS, by a rule a test pins.
- The host table's hash differs on Azure: the guest's report (ADR-0029 decision 5) carries the Azure render's
  hash for an Azure member. Two renders per set of pool files, each pinned by `make host-table-test`.
- `make host-table-test` exports a tag file that is absent, because a CI runner may itself be an Azure VM:
  a test that read the real sysfs file there would render the Azure table and fail for the wrong reason.
- A direct pool on Azure (no gateways, no host table) is unchanged: root and system daemons reach WireServer
  and IMDS there as they reach everything (R-13's bound); the sandbox uid's per-claim table admits only its
  listed TCP destinations and, in the direct shape, DNS to the VM's resolvers, which on Azure is
  `168.63.129.16` at port 53 alone.
- Not proven on an Azure VM: the renewal path (networkd's unicast renew from its own socket) and the ready
  report through the table are read from the client and the platform's documentation, and the image checks
  prove the render and the user, not a lease. Recorded as §8 R-67 until a member boots on Azure.

## Alternatives rejected

- **Admit WireServer to every uid on Azure** (an element of the every-uid set): hands the sandbox uid the
  host's goal state and the host plugin, the reach this ADR exists to deny.
- **Gate the rules on a deployment flag** (an env key the cloud-config sets): a second source of truth that a
  deployment can get wrong in both directions; the hypervisor's tag is already there before the network.
- **Run the DHCP client as root to keep the rule root-only**: widens the client's privileges to narrow a
  rule that already names one user and one exchange.
- **Rely on the broadcast rebind at T2** and admit no renewal: a lease that lives on a race, and on Azure a
  route lost when it does not.
