<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0021: The sandbox filesystem is a tmpfs per claim, its rootfs pulled from the registry by the guest

**Status:** Accepted · **Date:** 2026-10-26

Roadmap 06, the two filesystem items. Implements the second half of
[ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) decision 8 (the workload comes from
`spec.workload`, an OCI rootfs the guest unpacks after the subject is known). Changes
nothing about the jail's network ([ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md)),
the identities of [ADR-0004](0004-spiffe-identity-scheme.md) or what the jail mounts
([ADR-0014](0014-one-binary-roles-as-subcommands.md)).

## Context

`workload.image` has been an OCI reference since ADR-0008, and every guide says the guest
unpacks it into `/mnt/sandbox/rootfs`. The guest did not: `guest.rs` required a rootfs to
be there already and refused the claim otherwise ("unpacking is not wired yet"). A pool
member therefore ran nothing unless its image had been baked with the workload inside,
which is one VM image per workload and defeats the warm pool.

The sandbox root was whatever `/mnt/sandbox` happened to be on the member's disk: no size
bound, no `nosuid`, no `nodev`, world-traversable, wiped by `remove_dir_all` at teardown.
`work` was created by root with mode 0755, so the `sb-` user the jail runs as could not
write to `/work` at all.

What the guest can rely on: it runs as root on a Kairos member whose disk is the image's
(ADR-0019), the member is destroyed when the claim ends (banlieue owns the lifecycle,
ADR-0008 decision 9), one claim binds to one member, and the member reaches the broker
and the segment's egress but holds no credential for anything else. What the guest cannot
rely on: a container runtime in the VM (none is baked, and none should be, the jail is
`nsjail`), or the image being small.

## Decision

1. **`/mnt/sandbox` is a fresh tmpfs per claim.** Before the rootfs is populated the guest
   mounts `tmpfs` at the sandbox root with `nosuid,nodev,mode=0700` and a size bound
   (`--sandbox-size`, the kernel's `size=` syntax, `50%` of the member's RAM by default,
   the tmpfs default). Root owns the mount point and nothing else traverses it: the jail
   enters the rootfs through `nsjail`'s own mount namespace, where the mount point's mode
   is irrelevant. Inside it `rootfs/` is root's, mode 0755, and `work/` belongs to the
   sandbox user, mode 0700, so `/work` is writable by exactly the uid the jail runs as.
   Anything left mounted there from an earlier attempt is unmounted first. The whole
   tree disappears with one `umount` at teardown; a wipe that fails is logged.

2. **The guest pulls the image itself, over HTTPS, with the distribution API.** No
   `skopeo`, `umoci` or `podman` in the VM: the guest speaks the OCI distribution
   protocol with the `reqwest` it already has, roots from WebPKI (`webpki-roots`, the
   rustls on aws-lc-rs of ADR-0007), as an anonymous client that follows the registry's
   bearer challenge (`WWW-Authenticate: Bearer realm=…,service=…,scope=…`) once. It
   fetches the manifest with both OCI and Docker media types accepted, selects
   `linux/<the member's architecture>` from an index, and downloads the layers in
   order; the config blob, which the jail does not use, is not fetched. Docker Hub
   references (`busybox`, `library/busybox`, `docker.io/...`) go to
   `registry-1.docker.io`; everything else names its registry.
   A registry reached over plain HTTP is named explicitly (`--plain-http-registry
   host[:port]`, repeatable) or it is not reached at all.

3. **Every blob is verified against its digest; the manifest digest is what ran.** The
   manifest bytes are hashed and must equal the digest in the reference when it carries
   one (`name@sha256:…`); a tag resolves to a digest at pull time and that digest is the
   one logged. Each layer is streamed to a file under the sandbox tmpfs while it is
   hashed, and a mismatch in digest or size is an error before the layer is opened. The
   guest logs `claim_uid`, the reference, the manifest digest, the layer count and the
   bytes pulled: the audit says which bytes ran, not which tag was named.

4. **Layers are applied in order, as an OCI image layer must be, and nothing escapes the
   rootfs.** `tar` and `tar+gzip` layers only (an unsupported media type is an error,
   zstd included until a workload needs it). Per entry: a whiteout (`.wh.name`) removes
   that sibling from the lower layers, an opaque whiteout (`.wh..wh..opq`) empties its
   directory, a directory replacing a file or a file replacing a directory replaces it,
   and the rest is unpacked. An entry whose path would land outside the rootfs, by `..`
   or through a symbolic link, is an error, not a skip: the image is refused. setuid,
   setgid and sticky bits are dropped (the mount is `nosuid` as well), device nodes and
   fifos are skipped (`nodev`), ownership is not preserved (root owns the rootfs; the
   jail runs one uid, as the read-only chroot of ADR-0014), extended attributes are not
   unpacked. Hard links and symbolic links are kept; the jail's chroot resolves them
   inside.

5. **The pull is root's, before the ruleset.** The sequence is: user, mount, rootfs,
   ruleset, jail. The registry is a destination of the guest's, not the workload's, so
   nothing in the sandbox uid's chain of ADR-0020 admits it. The root egress chain of
   roadmap 06 will have to admit the registry, which is now a known input to that item.

6. **Any failure fails the claim before the jail.** An unreachable registry, a refused
   pull, a mismatched digest, a tmpfs that fills (`ENOSPC` against `--sandbox-size`), an
   image that escapes: each is an error returned before `nsjail` is spawned, and the
   guest tears down (unloads nothing, since the ruleset is not loaded yet; unmounts the
   tmpfs; removes the user). The unit restarts the guest, which registers, fetches the
   claim again and retries from the start; a claim whose image never pulls fails at the
   watcher's timeout as an unregistered node would.

7. **No pull credentials in this ADR.** The guest holds nothing but its node SVID, and a
   registry that wants a credential refuses the pull. A per-claim pull secret delivered
   by the broker is a roadmap 06 follow-up; the shape it needs (the broker returns it on
   `GET /v1/me`, the guest uses it once and keeps nothing) is a token-shape change and
   gets its own ADR. *Done as
   [ADR-0022](0022-registry-pull-credentials-from-the-broker.md).*

## Consequences

- `crates/mediatore-guest/src/sandboxfs.rs` is decision 1 (the mount arguments as data,
  the layout, the unmount); `crates/mediatore-guest/src/image.rs` is decisions 2 to 4 (the
  reference grammar, the client, the pull, the layer application). `guest.rs` runs the
  sequence of decision 5 and no longer asks for a pre-populated rootfs. Two crates enter
  the graph: `tar` and `flate2` (its Rust back end), both permissive.
- The image needs nothing new: `mount` and `umount` are util-linux, and the pull is the
  one binary's. The segment's firewall (ADR-0010 decision 4) must let the members reach
  the registry, which [the deploying guide](../guides/deploying.md) now lists beside the
  broker and the audiences' endpoints.
- Tests: the reference grammar, the mount arguments and the layout are unit-tested; the
  pull is tested against a fake registry in `mediatore-testkit` on a real listener
  (layers built in the test: order, whiteouts, an escaping entry, a symlink out, setuid
  bits, a device node, a tampered blob, a digest-pinned reference that does not match, an
  index with and without this platform, an unsupported layer, the bearer challenge). Two
  ignored tests run on the build host: the tmpfs mounted for real (`MEDIATORE_SUDO`) and
  an image pulled from a real registry (`MEDIATORE_PULL_IMAGE`); each fails rather than
  skips without its variable. The kind tiers run the guest with `--dev-skip-setup` and
  mount and pull nothing; the live proof is roadmap 06's libvirt item.
- A layer entry that passes through a symbolic link pointing outside the rootfs is
  refused where `umoci` would resolve the link inside. Layers produced by the usual
  builders carry such entries under the link's target, not through the link; an image
  that needs the resolution is the trigger to add it.
- A tag is the registry's word: the guest logs the digest it resolved to, and a reference
  pinned by digest is what makes the record reproducible. Threat model §8 R-14.
- Memory: the tmpfs is RAM, so the image's unpacked size plus its largest compressed
  layer plus `/work` count against the member's memory, bounded by `--sandbox-size`. The
  operator sizes the pool's members for the workloads they run.
- Rejected: `skopeo` and `umoci` in the image (two binaries, a second TLS stack, their
  own trust stores, and the digest logging would be theirs); `podman` (a container runtime
  under a jail that exists so there is none); a dedicated partition instead of a tmpfs
  (a wipe is a reformat, not an unmount, and the member is destroyed with the claim
  anyway); preserving ownership and setuid bits (nothing in the rootfs needs to be owned
  by the sandbox uid, and a setuid binary in a workload image is exactly what `nosuid`
  is for); a pre-baked rootfs in the VM image (one image per workload, a cold pool);
  skipping an escaping entry and unpacking the rest (an image that tries is hostile, not
  partially usable).
