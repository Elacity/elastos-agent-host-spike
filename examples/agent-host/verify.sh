#!/usr/bin/env bash
set -euo pipefail

HOST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HOST_DIR}/../.." && pwd)"
MANIFEST="${HOST_DIR}/capsule.json"
WIT="${REPO_ROOT}/elastos/wit/elastos-bus-v1.wit"

python3 - "${MANIFEST}" "${WIT}" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
wit_path = pathlib.Path(sys.argv[2])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

expected = {
    "schema": "elastos.capsule/v1",
    "name": "agent-host",
    "role": "app",
    "type": "wasm",
    "runtime_abi": "elastos.component/v1",
    "bus_contract": "elastos:bus@v1",
    "execution": "component",
    "entrypoint": "agent-host.component.wasm",
}

for key, value in expected.items():
    actual = manifest.get(key)
    if actual != value:
        raise SystemExit(f"{manifest_path}: expected {key}={value!r}, got {actual!r}")

wit_hash = hashlib.sha256(wit_path.read_bytes()).hexdigest()
if manifest.get("wit_world_sha256") != wit_hash:
    raise SystemExit(f"{manifest_path}: wit_world_sha256 does not match {wit_path}")
PY

cargo fmt --manifest-path "${HOST_DIR}/Cargo.toml" -- --check
cargo test --locked --manifest-path "${HOST_DIR}/Cargo.toml"
cargo clippy --locked --manifest-path "${HOST_DIR}/Cargo.toml" --all-targets -- -D warnings
"${REPO_ROOT}/scripts/build-component-capsule.sh" "${HOST_DIR}"
test -f "${HOST_DIR}/agent-host.component.wasm"

echo "agent-host capsule verification: OK"
