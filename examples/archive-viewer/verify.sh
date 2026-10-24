#!/usr/bin/env bash
# The archive viewer: the core's fmt, clippy (host and wasm32), tests and
# falsifiers; then the built component in the Runtime's ComponentProvider with
# its admission check, the F35 grant stop and the F36 fuel gate (the host-test
# crate), and their falsifiers under --runtime.
set -euo pipefail

VIEWER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${VIEWER_DIR}/../.." && pwd)"
WIT="${REPO_ROOT}/elastos/wit/elastos-bus-v1.wit"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

python3 -I "${REPO_ROOT}/examples/capsule-kit/scripts/check-manifest.py" \
    "${VIEWER_DIR}/capsule.json" "${WIT}" archive-viewer

cargo fmt --manifest-path "${VIEWER_DIR}/Cargo.toml" --all -- --check
cargo clippy --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" --all-targets -- -D warnings
# The Bus v1 component glue: the same crate built for the guest's target.
cargo clippy --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" \
    --target wasm32-unknown-unknown -- -D warnings
cargo test --locked --manifest-path "${VIEWER_DIR}/Cargo.toml"

# Every rule: break it, see its test fail, restore it.
python3 -I "${VIEWER_DIR}/falsify.py"

# Component: built with the repository builder.
"${VIEWER_DIR}/build.sh"
test -f "${VIEWER_DIR}/archive-viewer.component.wasm"

# Host: the component inside the Runtime's ComponentProvider, its import
# admission and the fuel gate.
cargo fmt --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" -- --check
cargo clippy --locked --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" --all-targets -- -D warnings
cargo test --locked --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" -- --nocapture

# The component falsifiers: each rebuilds the component and runs the host test.
python3 -I "${VIEWER_DIR}/falsify.py" --runtime

echo "archive-viewer verification: OK"
