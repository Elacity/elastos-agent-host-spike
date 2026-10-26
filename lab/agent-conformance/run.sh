#!/bin/bash
# Cargo supplies both the inventory and results; report owns table grading.
set -eu
lane=$(cd -- "$(dirname -- "$0")" && pwd -P)
cd "$lane/../.."
if [ -L "$lane/target" ]; then
    printf 'test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\ncargo | FAIL\n'
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
# Prepare this checkout's report before collecting evidence, including failed suites.
if ! cargo build --locked --manifest-path "$manifest" --bin report >"$run_dir/report-build" 2>&1; then
    printf 'versions receipt failure: report build failed; retained output: %s\n' "$run_dir" >&2
    exit 1
fi
"$CARGO_TARGET_DIR/debug/report" --check-earlier-runs
status=0
: >"$run_dir/results"
if cargo test --locked --manifest-path "$manifest" -- --list >"$run_dir/list" 2>"$run_dir/build"; then
    cargo test --locked --no-fail-fast --manifest-path "$manifest" -- --format pretty --color never --show-output >"$run_dir/results" 2>>"$run_dir/build" || status=$?
else
    status=$?
fi
sed -n '/^version identity:/p; /^operator census:/p; /^cleanup census:/p; /^probe refusal effect:/p; /^parallel process isolation:/p; /^instance overlap:/p; /^fixture controller:/p; /^fixture read:/p; /^host key read:/p; /^SKIPPED /p' "$run_dir/results"
printf 'process_isolation rows: process isolation, not capsule isolation; diagnostic results only\n'
if "$CARGO_TARGET_DIR/debug/report" "$run_dir/list" "$run_dir/results" "$status" "$run_dir/VERSIONS.json"; then
    rm -- "$run_dir/list" "$run_dir/results" "$run_dir/build" "$run_dir/report-build"
else
    printf 'retained Cargo output: %s\n' "$run_dir" >&2
    exit 1
fi
