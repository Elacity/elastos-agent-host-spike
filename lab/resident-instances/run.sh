#!/bin/bash
# Harness self-tests first; then the acceptance table, graded only by
# resident_instances::acceptance. Exit status is the table's: 0 when no row
# failed or was skipped (BLOCKED rows stay open in SPEC.md), 1 on a failed row
# or self-test, 4 on a skipped row.
set -eu
if [ "$#" -ne 0 ]; then
    printf 'usage: run.sh\n' >&2
    exit 2
fi
lane=$(cd -- "$(dirname -- "$0")" && pwd -P)
manifest="$lane/Cargo.toml"
export CARGO_TARGET_DIR="$lane/target/host"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
cargo fmt --manifest-path "$manifest" -- --check
cargo test --locked --manifest-path "$manifest"
cargo run --locked --quiet --manifest-path "$manifest" --bin acceptance
