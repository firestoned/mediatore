<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The guest

What runs on a pool VM, in `crates/mediatore-guest`. The guest is the `guest` role of the one binary, started as root
by a systemd unit at boot. It turns a VM that is idle and attested into a jailed, identity-bearing workload for one
claim, and then back into nothing. The jail and the egress proxy have their own page,
[The egress proxy](egress-proxy.md); this page is the sequence and the parts around them.

## The lifecycle, in order

`guest::run` is one straight line of steps, each logged. Anything that fails ends the claim and tears the VM's state
down: there is no partial-trust mode.

1. **Who am I, as a node.** The EK hash (from the vTPM, `identity.rs`) and the DMI UUID. Together they identify the VM
   to the broker and anchor its SPIFFE identity in the hardware.
2. **Register.** `POST /v1/nodes` over SPIFFE mutual TLS, retried until accepted. A `409` is **fatal**: that EK is
   already registered for another VM, which is exactly the cloned-TPM case.
3. **Announce `GuestReady`** (`ready.rs`) on whatever channel the hypervisor reads (a marker under `/run`, guestinfo or
   vsock), only after the VM is attested and registered, so the pool never hands out a member that is not.
4. **Wait for a claim.** Poll `GET /v1/me` (a `404` means none yet) until one is bound to this node. The answer carries
   the subject, the deadline, the workload, the routes, the gateways and any registry credential.
5. **Check what was asked, before building anything.** The workload has a command; the image reference parses; the
   pinned binary exists at its path.
6. **Create the sandbox user** (`user.rs`): a Linux user derived from the subject (`sb-` and twelve hex characters), the
   one the claim's registration entry selects.
7. **`serve_claim`**, below.
8. **Tear down** (`supervise::teardown`), also on an error: the tmpfs is unmounted and the user's processes are gone.

## `serve_claim`: building the sandbox

| Step | Module | What it does |
| --- | --- | --- |
| tmpfs | `sandboxfs.rs` | a fresh tmpfs per claim at the sandbox root, `nosuid,nodev`, mode `0711`, size-bounded (`--sandbox-size`), holding the rootfs, the layers and the proxy's files |
| pull the image | `image.rs` | the workload's rootfs from its registry, **as root**, every blob digest-verified, nothing escaping the rootfs, setuid bits dropped and device nodes skipped (ADR-0021); the manifest digest is logged and reported |
| choose gateways | `net.rs` | the broker's list from `GET /v1/me`, or the pool's bootstrap file when the broker lists none, or none (the proxy then dials directly) |
| the ruleset | `net.rs` | one `nftables` table per claim whose output hook sends the **sandbox uid's** packets to a chain admitting a short list of TCP destinations and DNS to the VM's resolvers; everything else from that uid is dropped |
| the proxy's files | `egress.rs` | the routes, the gateways and a fresh phantom token, written as read-only files of the sandbox user |
| load the ruleset | `net.rs` | `nft` loads the table and its hash is recorded |
| start the egress proxy | `egress.rs` | a second process as the sandbox user, outside the jail, waited on until it says it is ready |
| report | `report.rs` | tell the broker what ran: the image digest, the ruleset's hash, the host table as `nft` lists it (the record, not a gate) |
| the jail | `jail.rs`, `confine.rs` | `nsjail` as the outer layer, then `jail-exec` as the inner layer, applying Landlock to itself and exec-ing the workload |
| supervise | `supervise.rs` | run the workload until the claim's deadline, restart it as its restart policy says, end the claim when the proxy goes, and post the exit when the workload is done by its policy (`POST /v1/me/exit`) |

**The order is the point.** There is no jail without the ruleset (ADR-0020 decision 5), no ruleset without the rootfs
layout, and no workload before its only route out, the proxy, exists (ADR-0025 decision 1).

### A registry the gateway places a credential for

When the image is on a registry that is a gateway-placed audience (ADR-0043), the pull cannot be made as root with a
credential, because the VM must never hold one. The order changes for that claim only:

1. build the tmpfs, choose the gateways, build and **load the ruleset**, and **start the egress proxy**, with a second
   listener for the pull;
2. **then** pull the image, through that listener, with no credential;
3. then report, build the jail spec and run.

The proxy must come first because it holds the claim's identity, and the gateway's inject listener accepts a claim
identity only. The pull goes to `127.0.0.1` on the **pull port** (`MEDIATORE_EGRESS_PULL_PORT`, 18129 by default), a
port that no jail rule lists, so the sandbox cannot reach it; the guest refuses the claim if that port is the proxy's or
a destination's. The puller in this mode sends no credential, answers no challenge (a `401` is the gateway's refusal and
an error, never a call to the realm) and follows no redirect off the VM. Every other claim keeps the older order:
pull as root, then the ruleset, then the proxy.

## What the jail is

The workload runs as the sandbox user in a PID namespace of its own, with `/proc` showing only its own processes
(ADR-0036), a root filesystem that is the pulled image on the tmpfs, the pinned binary mounted read-only, no Workload
API socket and no route to the broker. Landlock, applied by `jail-exec` before the workload runs, bounds what it may
write and which TCP ports it may connect to: **only the proxy's port** (a refusal ends the claim). The environment it
gets carries `MEDIATORE_EGRESS_PROXY` (the proxy's base URL) and `MEDIATORE_TOKEN` (the phantom token, 256 random bits
that mean nothing anywhere but at this proxy during this claim). It holds no credential.

Two firewalls bound the VM. The **claim's table** (above) binds the sandbox uid. The **host table**
(`image/host-table`) binds the VM: output is default-drop, admitting only the broker, the relay legs and, to root alone,
the registry leg; the loopback interface is admitted both ways, which is how root's puller reaches the proxy's pull port.

## The other roles

- `token` (`token.rs`) fetches the claim SVID from a Workload API socket and calls `POST /v1/token`, printing the token.
  It was the workload's way to a credential before the egress proxy. Since ADR-0025 the jail has **neither** the
  socket **nor** a route to the broker, so inside a jail it cannot work by design; the workload's way is the proxy.
  The role remains for a context that does have both.
- `client.rs` is the HTTP client both VM-side roles use to the sandbox listener, over SPIFFE mTLS with the SVID from
  the Workload API; it fails closed without a transport identity.

## Rules this part keeps

- A claim that cannot be fully built is torn down, never run half-built.
- The workload holds a phantom, never a credential, and the jail reaches the proxy's port and nothing else.
- The VM presents no credential for a gateway-placed registry and holds none.
- The jail never starts before the ruleset is loaded and the proxy is ready.
- A cloned TPM is refused at registration.

## Read next

ADR-0014 (one binary), ADR-0019 (`GuestReady`), ADR-0020 (the jail's network), ADR-0021 (the filesystem and the
pull), ADR-0023 (the VM image), ADR-0024 (Landlock), ADR-0029 (the pull on a routeless segment), ADR-0033 (the restart
policy), ADR-0036 (`/proc`), ADR-0038 and ADR-0043 (the registry legs). Threat model TB-6, TB-11, TB-12, TB-15. Roadmap 06.
