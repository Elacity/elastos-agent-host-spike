#!/usr/bin/env bash
# The gba-viewer example's gate (AP4 slice 1a): the by-CID mapping, the staging
# script, the rows that drive both, and this gate's own falsifier.
set -euo pipefail

VIEWER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${VIEWER_DIR}/../.." && pwd)"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

python3 -I "${VIEWER_DIR}/rows_test.py"

# The page's one program: its manifest is the component shape the Runtime
# admits, and its rows drive the real entry against the fake Runtime.
python3 -I "${REPO_ROOT}/examples/capsule-kit/scripts/check-manifest.py" \
    "${VIEWER_DIR}/core/capsule.json" \
    "${REPO_ROOT}/elastos/wit/elastos-bus-v1.wit" \
    gba-viewer-core
cargo test --locked --manifest-path "${VIEWER_DIR}/core/Cargo.toml"

# Each core rule and each derive_manifest rule: break it, see its test fail.
python3 -I "${VIEWER_DIR}/falsify.py"

python3 -I "${VIEWER_DIR}/verify_gate_test.py"
python3 -I "${VIEWER_DIR}/verify_gate_test.py" --falsify

echo "gba-viewer: rows green, gate falsifier caught"
