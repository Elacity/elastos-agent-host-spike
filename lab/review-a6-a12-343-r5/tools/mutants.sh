#!/bin/sh
# Independently re-apply the two r4 mutants the author now claims are CAUGHT.
# Does not use the author's plant runner. Restores a12.rs after each.
set -eu
SUBJECT=${1:-/tmp/pr343-r5}
export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SUBJECT/lab/a6-a12-evidence-fix/target}"
export CARGO_NET_OFFLINE=true
export A6A12_PLANT_CHILD=1

A12="$SUBJECT/lab/a6-a12-evidence-fix/src/a12.rs"
MANIFEST="$SUBJECT/lab/a6-a12-evidence-fix/Cargo.toml"

PACK_TMP=$(mktemp -d "${TMPDIR:-/tmp}/a6-a12-r5-mutants.XXXXXX")
cleanup_pack() { rm -rf "$PACK_TMP"; }
trap cleanup_pack EXIT
printf 'a6-a12-evidence-fix isolation\n' > "$PACK_TMP/.a6-a12-isolation"
export ELASTOS_TMP_ISOLATION="$PACK_TMP"
export ELASTOS_TMP_ROOT="$PACK_TMP"

run_named() {
  test_name=$1
  cargo test --locked --offline --manifest-path "$MANIFEST" --lib \
    "$test_name" -- --exact --nocapture "$test_name"
}

classify() {
  id=$1
  test_name=$2
  output=$3
  if printf '%s\n' "$output" | grep -q "test ${test_name} ... FAILED"; then
    printf 'MUTANT %s CAUGHT by %s\n' "$id" "$test_name"
  elif printf '%s\n' "$output" | grep -q "test ${test_name} ... ok"; then
    printf 'MUTANT %s SURVIVED against %s\n' "$id" "$test_name"
  else
    printf 'MUTANT %s INCONCLUSIVE against %s\n' "$id" "$test_name"
    printf '%s\n' "$output" | tail -n 30
  fi
}

apply_restore() {
  file=$1
  old=$2
  new=$3
  id=$4
  test_name=$5
  hits=$(python3 -I -c 'import sys; src=sys.stdin.read(); old=sys.argv[1]; print(src.count(old))' "$old" < "$file")
  if [ "$hits" != 1 ]; then
    printf 'MUTANT %s INCONCLUSIVE: old text occurs %s times in %s\n' "$id" "$hits" "$file"
    return 0
  fi
  original=$(cat "$file")
  python3 -I -c 'import sys,pathlib; p=pathlib.Path(sys.argv[1]); old=sys.argv[2]; new=sys.argv[3]; src=p.read_text(); p.write_text(src.replace(old,new,1))' "$file" "$old" "$new"
  set +e
  output=$(run_named "$test_name" 2>&1)
  status=$?
  set -e
  printf '%s\n' "$original" > "$file"
  after=$(sha256sum "$file" | awk '{print $1}')
  printf 'restored %s sha256=%s cargo_exit=%s\n' "$file" "$after" "$status"
  classify "$id" "$test_name" "$output"
}

printf 'r5 mutants at %s\n' "$(git -C "$SUBJECT" rev-parse HEAD)"

# Author claim: dropping isolation-under is CAUGHT by a12_outside_isolation_tmp_root_is_refused.
apply_restore "$A12" \
  '    if !is_under(&canonical, &isolation_canon) {
        return Err(format!(
            "ELASTOS_TMP_ROOT {} is not under isolated mktemp {}",
            path.display(),
            isolation.display()
        ));
    }' \
  '    let _ = isolation_canon;' \
  M-R4-GUARD-NO-ISOLATION tests::a12_outside_isolation_tmp_root_is_refused

# Same mutant still green against the old slash test? Record it.
apply_restore "$A12" \
  '    if !is_under(&canonical, &isolation_canon) {
        return Err(format!(
            "ELASTOS_TMP_ROOT {} is not under isolated mktemp {}",
            path.display(),
            isolation.display()
        ));
    }' \
  '    let _ = isolation_canon;' \
  M-R4-GUARD-NO-ISOLATION-SLASH tests::a12_slash_tmp_root_is_refused

# Author claim: dropping the /tmp/elastos snapshot half is CAUGHT by the live-snap test.
apply_restore "$A12" \
  '    if runtime_wrote_under(watch) || live_runtime_tmp_has_files() {
        return Err(
            "snapshot must be taken before the Runtime starts; Runtime already wrote".into(),
        );
    }' \
  '    if runtime_wrote_under(watch) {
        return Err(
            "snapshot must be taken before the Runtime starts; Runtime already wrote".into(),
        );
    }' \
  M-R4-SNAP-IGNORE-LIVE tests::a12_snapshot_before_runtime_fails_if_live_tmp_elastos_wrote

# Same mutant against the watch-only named test (r4 found this SURVIVED).
apply_restore "$A12" \
  '    if runtime_wrote_under(watch) || live_runtime_tmp_has_files() {
        return Err(
            "snapshot must be taken before the Runtime starts; Runtime already wrote".into(),
        );
    }' \
  '    if runtime_wrote_under(watch) {
        return Err(
            "snapshot must be taken before the Runtime starts; Runtime already wrote".into(),
        );
    }' \
  M-R4-SNAP-IGNORE-LIVE-WATCH tests::a12_snapshot_before_runtime_fails_if_already_wrote

printf 'mutants finished; a12.rs sha256=%s\n' "$(sha256sum "$A12" | awk '{print $1}')"
