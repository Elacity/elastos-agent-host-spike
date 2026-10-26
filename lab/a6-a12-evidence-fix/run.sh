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
printf 'ELASTOS_TMP_ROOT=%s (unset means /tmp/elastos).\n' "${ELASTOS_TMP_ROOT:-}"
printf 'Resident A6/A12 and ThrowawayHome census: NOT RUN unless this host is macOS.\n'
