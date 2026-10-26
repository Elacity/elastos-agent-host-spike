#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/a6-a12-evidence-fix/target"
export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0

cargo fmt --manifest-path lab/a6-a12-evidence-fix/Cargo.toml -- --check
cargo test --locked --offline --manifest-path lab/a6-a12-evidence-fix/Cargo.toml --lib -- --nocapture

printf '\nA6/A12 evidence-fix: lib tests finished. See FINDINGS.md for verdicts.\n'
printf 'Full agent-conformance A6/A12 journeys: NOT RUN unless this host builds a throwaway Home.\n'
