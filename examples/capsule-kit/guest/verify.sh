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
cargo fmt --manifest-path "${KIT_DIR}/../v1-host-test/Cargo.toml" -- --check
# The v1-host-test fuel test runs the built GBA core.
"${KIT_DIR}/../../gba-viewer/core/build.sh"
cargo test --locked --manifest-path "${KIT_DIR}/../v1-host-test/Cargo.toml"
python3 -I "${KIT_DIR}/../v1-host-test/falsify.py"
python3 -I "${KIT_DIR}/../falsify/test_falsify_kit.py"
# Every name in the hash record is checked by some viewer gate.
python3 -I "${KIT_DIR}/../repro/recorded_names_test.py"
python3 -I "${KIT_DIR}/../repro/recorded_names_test.py" --falsify
# The runner's own rules, each broken in a temporary copy: its test must fail.
python3 -I "${KIT_DIR}/../falsify/plant_falsify_kit.py"
python3 -I "${KIT_DIR}/falsify.py"

echo "capsule kit guest crate verification: OK"
