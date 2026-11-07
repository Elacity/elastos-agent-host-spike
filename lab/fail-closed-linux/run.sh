#!/bin/bash
# The full gate on the current source: format, Clippy, the test suite, then
# the falsifier runner. Cargo output stays under this folder's target/.
set -eu
lane=$(cd -- "$(dirname -- "$0")" && pwd -P)
cd "$lane"
export CARGO_TARGET_DIR="$lane/target"
export CARGO_BUILD_BUILD_DIR="$lane/target/build"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python3 falsify.py
