#!/bin/bash
# Cargo supplies both the inventory and results; report owns table grading.
set -eu
lane=$(cd -- "$(dirname -- "$0")" && pwd -P)
cd "$lane/../.."
if [ -L "$lane/target" ]; then
    printf 'test | PASS/FAIL/BLOCKED (id)\ncargo | FAIL\n'
    printf 'lane target must be a directory without symlinks\n' >&2
    exit 1
fi
mkdir -p "$lane/target"
run_dir=$(mktemp -d "$lane/target/run-table.XXXXXX")
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$lane/target/host"
export CARGO_BUILD_BUILD_DIR="$lane/target/host-build"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
export TMPDIR="$run_dir"
manifest="$lane/Cargo.toml"
if ! cargo test --locked --manifest-path "$manifest" -- --list >"$run_dir/list" 2>"$run_dir/build"; then
    printf 'test | PASS/FAIL/BLOCKED (id)\ncargo | FAIL\n'
    printf 'Cargo could not list tests; retained output: %s\n' "$run_dir" >&2
    exit 1
fi
status=0
cargo test --locked --no-fail-fast --manifest-path "$manifest" -- --format pretty --color never --show-output >"$run_dir/results" 2>"$run_dir/build" || status=$?
sed -n '/^elastos sha256:/p; /^localhost-provider sha256:/p' "$run_dir/results"
if "$CARGO_TARGET_DIR/debug/report" "$run_dir/list" "$run_dir/results" "$status"; then
    rm -rf -- "$run_dir"
else
    printf 'retained Cargo output: %s\n' "$run_dir" >&2
    exit 1
fi
