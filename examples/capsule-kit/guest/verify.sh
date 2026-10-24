#!/usr/bin/env bash
# The capsule kit's guest crate: fmt, clippy for every feature set it is used
# with (Bus v1 host tests, Bus v1 wasm32 with the WIT glue, and no features
# for a Bus v2 guest), its tests, and every falsifier.
set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"
cd "${KIT_DIR}"

cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --no-default-features -- -D warnings
cargo clippy --locked --features wit --target wasm32-unknown-unknown -- -D warnings
cargo test --locked
python3 -I "${KIT_DIR}/../falsify/test_falsify_kit.py"
python3 -I "${KIT_DIR}/falsify.py"

echo "capsule kit guest crate verification: OK"
