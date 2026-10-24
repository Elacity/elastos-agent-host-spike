#!/usr/bin/env bash
# The archive viewer core: fmt, clippy for the host tests and the wasm32
# component, its tests, and every falsifier (F6, F6b, F6c, F7 to F17, F19 to
# F25, F29 to F31, F40 to F42, plus the bound and skip-reason cases F6d to F6f,
# F16b, F19b, F21b to F21g, F23b, F23c, F30b, F30c and F41b to F41e).
set -euo pipefail

VIEWER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

cargo fmt --manifest-path "${VIEWER_DIR}/Cargo.toml" --all -- --check
cargo clippy --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" --all-targets -- -D warnings
# The Bus v1 component glue: the same crate built for the guest's target.
cargo clippy --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" \
    --target wasm32-unknown-unknown -- -D warnings
cargo test --locked --manifest-path "${VIEWER_DIR}/Cargo.toml"

# Every rule: break it, see its test fail, restore it.
python3 -I "${VIEWER_DIR}/falsify.py"

echo "archive-viewer core verification: OK"
