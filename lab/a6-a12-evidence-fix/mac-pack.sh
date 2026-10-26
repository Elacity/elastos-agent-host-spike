#!/bin/sh
# Mac evidence pack. Always isolates ELASTOS_TMP_ROOT in a fresh mktemp dir
# and cleans only that folder.
set -eu
cd "$(dirname "$0")/../.."
export CARGO_NET_OFFLINE=true
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

printf 'Mac pack isolated ELASTOS_TMP_ROOT=%s\n' "$ELASTOS_TMP_ROOT"

if [ "$(uname -s)" != Darwin ]; then
  printf 'NOT RUN: mac-pack.sh needs macOS. Commands that would run:\n'
  printf 'ELASTOS_TMP_ROOT=%s ELASTOS_TMP_ISOLATION=%s cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects two_instances_overlap_with_separate_grants -- --nocapture\n' "$ELASTOS_TMP_ROOT" "$ELASTOS_TMP_ISOLATION"
  printf 'ELASTOS_TMP_ROOT=%s ELASTOS_TMP_ISOLATION=%s cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects instance_grant_does_not_authorise_sibling -- --nocapture\n' "$ELASTOS_TMP_ROOT" "$ELASTOS_TMP_ISOLATION"
  printf 'ELASTOS_TMP_ROOT=%s ELASTOS_TMP_ISOLATION=%s cargo test --manifest-path lab/agent-conformance/Cargo.toml --test runtime cleanup_census_refuses_each_leftover -- --nocapture\n' "$ELASTOS_TMP_ROOT" "$ELASTOS_TMP_ISOLATION"
  exit 0
fi

cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
  two_instances_overlap_with_separate_grants -- --nocapture
cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
  instance_grant_does_not_authorise_sibling -- --nocapture
cargo test --manifest-path lab/agent-conformance/Cargo.toml --test runtime \
  cleanup_census_refuses_each_leftover -- --nocapture
