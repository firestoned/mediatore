#!/usr/bin/env python3
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
"""Check a gathered release directory (`make release-assets`): every asset the install needs
is there, the install manifest pins the server image by digest exactly once with no tag
left, the VMImage pins the guest image by digest, and checksums.sha256 covers every file.

    check_release_assets.py <release dir> <version> <pinned server image> <pinned guest image>
"""

import subprocess
import sys
from pathlib import Path

import yaml

# deploy/base, as kustomize renders it. The overlay (config, Secrets, ingress) is the
# operator's and deliberately not in the manifest.
EXPECTED_KINDS = {
    "CustomResourceDefinition": 1,
    "ServiceAccount": 1,
    "ClusterRole": 1,
    "ClusterRoleBinding": 1,
    "Role": 1,
    "RoleBinding": 1,
    "Deployment": 1,
    "Service": 2,
    "ClusterSPIFFEID": 1,
    "ConfigMap": 1,
    "ValidatingAdmissionPolicy": 2,
    "ValidatingAdmissionPolicyBinding": 2,
}


def fail(msg: str) -> None:
    print(f"check_release_assets: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    release, version, server, guest = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
    binary = release / f"mediatore-{version}-linux-amd64"
    darwin = release / f"mediatore-{version}-darwin-arm64"
    manifest = release / f"mediatore-{version}.yaml"
    vmimage = release / f"mediatore-guest-{version}-vmimage.yaml"
    layers = [
        release / f"mediatore-guest-{version}-cloud-config-base.yaml",
        release / f"mediatore-guest-{version}-cloud-config-deployment.example.yaml",
    ]
    checksums = release / "checksums.sha256"
    for p in [binary, darwin, manifest, vmimage, *layers, checksums]:
        if not p.is_file():
            fail(f"missing {p.name}")

    text = manifest.read_text(encoding="utf-8")
    docs = [d for d in yaml.safe_load_all(text) if d]
    kinds: dict[str, int] = {}
    for d in docs:
        kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1
    for kind, n in EXPECTED_KINDS.items():
        if kinds.get(kind, 0) != n:
            fail(f"expected {n} {kind}, found {kinds.get(kind, 0)}")
    images = [
        c["image"]
        for d in docs
        if d["kind"] == "Deployment"
        for c in d["spec"]["template"]["spec"]["containers"]
    ]
    if images != [server]:
        fail(f"expected the server image pinned to {server}, found {images}")
    if text.count(server.split("@")[0] + ":") != 0:
        fail("a tag reference to the server image survived")

    vm = vmimage.read_text(encoding="utf-8")
    if vm.count(guest) != 1 or "@sha256:" + "0" * 64 in vm or "placeholder: a release digest" in vm:
        fail(f"expected the VMImage pinned to {guest} once, with no placeholder digest or its comment left")
    for layer in layers:
        if not layer.read_text(encoding="utf-8").startswith("#cloud-config"):
            fail(f"{layer.name} is not a cloud-config document")

    listed = {line.split("  ", 1)[1].removeprefix("./") for line in checksums.read_text().splitlines() if line}
    present = {p.name for p in release.iterdir() if p.name != checksums.name}
    if listed != present:
        fail(f"checksums.sha256 lists {sorted(listed)}, directory holds {sorted(present)}")
    if subprocess.run(["shasum", "-a", "256", "-c", "--quiet", checksums.name], cwd=release, check=False).returncode != 0:
        fail("checksums.sha256 does not verify")


if __name__ == "__main__":
    main()
