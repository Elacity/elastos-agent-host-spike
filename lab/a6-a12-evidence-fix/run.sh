#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/a6-a12-evidence-fix/target"
export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0

PACK_TMP=$(mktemp -d "${TMPDIR:-/tmp}/a6-a12-pack.XXXXXX")
cleanup_pack() {
  rm -rf "$PACK_TMP"
}
trap cleanup_pack EXIT
printf 'a6-a12-evidence-fix isolation\n' > "$PACK_TMP/.a6-a12-isolation"
export ELASTOS_TMP_ISOLATION="$PACK_TMP"
export ELASTOS_TMP_ROOT="$PACK_TMP"

cargo fmt --manifest-path lab/a6-a12-evidence-fix/Cargo.toml -- --check
cargo test --locked --offline --manifest-path lab/a6-a12-evidence-fix/Cargo.toml --lib -- --nocapture

printf '\nA6/A12 evidence-fix: lib tests finished. See FINDINGS.md and RA-6.md.\n'
printf 'ELASTOS_TMP_ROOT=%s (isolated mktemp; cleaned on exit).\n' "$ELASTOS_TMP_ROOT"

printf '\nMac pack commands (same isolated ELASTOS_TMP_ROOT):\n'
printf 'ELASTOS_TMP_ROOT=%s ELASTOS_TMP_ISOLATION=%s \\\n' "$ELASTOS_TMP_ROOT" "$ELASTOS_TMP_ISOLATION"
printf '  cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \\\n'
printf '  two_instances_overlap_with_separate_grants -- --nocapture\n'
printf 'ELASTOS_TMP_ROOT=%s ELASTOS_TMP_ISOLATION=%s \\\n' "$ELASTOS_TMP_ROOT" "$ELASTOS_TMP_ISOLATION"
printf '  cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \\\n'
printf '  instance_grant_does_not_authorise_sibling -- --nocapture\n'
printf 'ELASTOS_TMP_ROOT=%s ELASTOS_TMP_ISOLATION=%s \\\n' "$ELASTOS_TMP_ROOT" "$ELASTOS_TMP_ISOLATION"
printf '  cargo test --manifest-path lab/agent-conformance/Cargo.toml --test runtime \\\n'
printf '  cleanup_census_refuses_each_leftover -- --nocapture\n'

if [ "$(uname -s)" = Darwin ]; then
  ELASTOS_TMP_ROOT="$PACK_TMP" ELASTOS_TMP_ISOLATION="$PACK_TMP" \
    cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
    two_instances_overlap_with_separate_grants -- --nocapture
  ELASTOS_TMP_ROOT="$PACK_TMP" ELASTOS_TMP_ISOLATION="$PACK_TMP" \
    cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
    instance_grant_does_not_authorise_sibling -- --nocapture
  ELASTOS_TMP_ROOT="$PACK_TMP" ELASTOS_TMP_ISOLATION="$PACK_TMP" \
    cargo test --manifest-path lab/agent-conformance/Cargo.toml --test runtime \
    cleanup_census_refuses_each_leftover -- --nocapture
else
  printf 'Resident A6/A12 and ThrowawayHome census: NOT RUN (need macOS).\n'
fi
