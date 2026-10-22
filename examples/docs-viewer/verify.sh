#!/usr/bin/env bash
set -euo pipefail

VIEWER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${VIEWER_DIR}/../.." && pwd)"
MANIFEST="${VIEWER_DIR}/capsule.json"
WIT="${REPO_ROOT}/elastos/wit/elastos-bus-v1.wit"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

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
    "name": "docs-viewer",
    "role": "app",
    "type": "wasm",
    "runtime_abi": "elastos.component/v1",
    "bus_contract": "elastos:bus@v1",
    "execution": "component",
    "entrypoint": "docs-viewer.component.wasm",
}

for key, value in expected.items():
    actual = manifest.get(key)
    if actual != value:
        raise SystemExit(f"{manifest_path}: expected {key}={value!r}, got {actual!r}")

wit_hash = hashlib.sha256(wit_path.read_bytes()).hexdigest()
if manifest.get("wit_world_sha256") != wit_hash:
    raise SystemExit(f"{manifest_path}: wit_world_sha256 does not match {wit_path}")
PY

# Guest and model: logic and refusals against a fake Runtime.
cargo fmt --manifest-path "${VIEWER_DIR}/Cargo.toml" --all -- --check
cargo test --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" --workspace
cargo clippy --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" --workspace --all-targets -- -D warnings

# Component: built with the repository builder.
"${REPO_ROOT}/scripts/build-component-capsule.sh" "${VIEWER_DIR}"
test -f "${VIEWER_DIR}/docs-viewer.component.wasm"

# Host: the component inside the Runtime's ComponentProvider.
cargo fmt --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" -- --check
cargo clippy --locked --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" --all-targets -- -D warnings
cargo test --locked --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" -- --nocapture

# Bundle: both capsules packed, named by CID, claimed and admitted under a policy.
cargo fmt --manifest-path "${VIEWER_DIR}/bundle-test/Cargo.toml" -- --check
cargo clippy --locked --manifest-path "${VIEWER_DIR}/bundle-test/Cargo.toml" --all-targets -- -D warnings
cargo test --locked --manifest-path "${VIEWER_DIR}/bundle-test/Cargo.toml" -- --nocapture

# Surface: the render-only page, against a fake fetch, then in real Chromium
# framed in Home's sandbox against a stand-in server (Playwright's Chromium).
node --test "${VIEWER_DIR}/surface/reader.test.mjs"
node "${VIEWER_DIR}/surface/reader-browser-smoke.mjs"

# Bus v2: the resident reader in the Bus v2 proof's stub host. Run from bus2/
# so rustup picks its toolchain (Rust 1.95.0). The guests are deleted first
# and checked after, so a stale or missing guest is never tested.
(
    cd "${VIEWER_DIR}/bus2"
    guest_dir=target/wasm32-unknown-unknown/release
    for guest in docs_bus2_guest docs_bus2_busy_guest; do rm -f "${guest_dir}/${guest}.wasm"; done
    cargo build --locked --release --target wasm32-unknown-unknown -p docs-bus2-guest -p docs-bus2-busy-guest
    for guest in docs_bus2_guest docs_bus2_busy_guest; do
        if [ ! -f "${guest_dir}/${guest}.wasm" ]; then
            echo "verify: FAILED: the build did not produce ${guest_dir}/${guest}.wasm" >&2
            exit 1
        fi
    done
    cargo fmt --all -- --check
    cargo clippy --locked -p docs-bus2-host-test --all-targets -- -D warnings
    cargo clippy --locked --release --target wasm32-unknown-unknown -p docs-bus2-guest -p docs-bus2-busy-guest -- -D warnings
    cargo test --locked -p docs-bus2-host-test -- --nocapture
)

# Every refusal and every page rule: break it, see its test fail, restore it.
python3 -I "${VIEWER_DIR}/falsify.py" --runtime
python3 -I "${VIEWER_DIR}/falsify-surface.py"

echo "docs-viewer capsule verification: OK"
