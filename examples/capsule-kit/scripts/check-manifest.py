#!/usr/bin/env python3
"""Check a Bus v1 component capsule's manifest (kit item A3).

Usage: python3 -I check-manifest.py <capsule.json> <elastos-bus-v1.wit> <name>

The manifest must be a component app named <name>, with the entrypoint
<name>.component.wasm, and name the WIT it was built against by its sha256.
Moved here from examples/photo-viewer/verify.sh.
"""
import hashlib
import json
import pathlib
import sys

manifest_path, wit_path, name = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

expected = {
    "schema": "elastos.capsule/v1",
    "name": name,
    "role": "app",
    "type": "wasm",
    "runtime_abi": "elastos.component/v1",
    "bus_contract": "elastos:bus@v1",
    "execution": "component",
    "entrypoint": f"{name}.component.wasm",
}

for key, value in expected.items():
    actual = manifest.get(key)
    if actual != value:
        raise SystemExit(f"{manifest_path}: expected {key}={value!r}, got {actual!r}")

wit_hash = hashlib.sha256(wit_path.read_bytes()).hexdigest()
if manifest.get("wit_world_sha256") != wit_hash:
    raise SystemExit(f"{manifest_path}: wit_world_sha256 does not match {wit_path}")
