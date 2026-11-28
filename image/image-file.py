# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
"""Print one file as an image's layers hold it, read from `<cli> save` output on stdin.

A container's view of a file is not the image's: Docker bind-mounts its own /etc/resolv.conf,
/etc/hosts and /etc/hostname into a container as soon as it is created, so `docker cp` from a
created container returns the runtime's file, not the layer's (podman mounts them only at
start). This reads the layers themselves, in order, honouring whiteouts, so the answer is the
same under either runtime.

Usage: <cli> save IMAGE | python3 -I image/image-file.py /etc/resolv.conf
Exit 0 with the file on stdout; 1 if no layer holds it (or the last word on it is a whiteout);
2 if the archive cannot be read.
"""

import io
import json
import posixpath
import sys
import tarfile


def blob(digest: str) -> str:
    algo, _, hexd = digest.partition(":")
    return f"blobs/{algo}/{hexd}"


def layer_paths(outer: tarfile.TarFile) -> list:
    """The layers, bottom first: a docker-archive's manifest.json (Docker writes one beside its
    OCI layout too), else an OCI layout's index.json and the image manifest it names."""
    names = set(outer.getnames())
    if "manifest.json" in names:
        return json.load(outer.extractfile("manifest.json"))[0]["Layers"]
    doc = json.load(outer.extractfile("index.json"))
    for _ in range(4):
        if "layers" in doc:
            return [blob(layer["digest"]) for layer in doc["layers"]]
        doc = json.load(outer.extractfile(blob(doc["manifests"][0]["digest"])))
    raise ValueError("no image manifest under index.json")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: image-file.py /path/in/image < saved-image.tar", file=sys.stderr)
        return 2
    want = sys.argv[1].lstrip("/")
    parent, name = posixpath.split(want)
    whiteout = posixpath.join(parent, ".wh." + name)
    opaque = posixpath.join(parent, ".wh..wh..opq")

    data = io.BytesIO(sys.stdin.buffer.read())
    try:
        outer = tarfile.open(fileobj=data, mode="r:")
        layers = layer_paths(outer)
    except (tarfile.TarError, KeyError, IndexError, TypeError, ValueError, AttributeError) as e:
        print(f"image-file: not a saved image: {e}", file=sys.stderr)
        return 2

    found = None
    for layer in layers:
        member = outer.extractfile(layer)
        if member is None:
            print(f"image-file: layer {layer} is missing from the archive", file=sys.stderr)
            return 2
        with tarfile.open(fileobj=io.BytesIO(member.read()), mode="r:*") as t:
            names = {m.name.removeprefix("./").lstrip("/"): m for m in t.getmembers()}
            if opaque in names or whiteout in names:
                found = None
            m = names.get(want)
            if m is not None and m.isfile():
                found = t.extractfile(m).read()
            elif m is not None:
                found = None
    if found is None:
        print(f"image-file: no layer holds /{want}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(found)
    return 0


if __name__ == "__main__":
    sys.exit(main())
