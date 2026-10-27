#!/bin/sh
# Re-apply the r5 SURVIVED mutants the author now claims are closed.
set -eu
SUBJECT=${1:-/tmp/pr343-r6}
HERE=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
A6="$SUBJECT/lab/a6-a12-evidence-fix/src/a6.rs"
A12="$SUBJECT/lab/a6-a12-evidence-fix/src/a12.rs"
MANIFEST="$SUBJECT/lab/a6-a12-evidence-fix/Cargo.toml"
export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SUBJECT/lab/a6-a12-evidence-fix/target}"
export CARGO_NET_OFFLINE=true
export A6A12_PLANT_CHILD=1

PACK_TMP=$(mktemp -d "${TMPDIR:-/tmp}/a6-a12-r6-r5.XXXXXX")
cleanup() {
  if [ -f "$A6.r6bak" ]; then mv "$A6.r6bak" "$A6"; fi
  if [ -f "$A12.r6bak" ]; then mv "$A12.r6bak" "$A12"; fi
  rm -rf "$PACK_TMP"
}
trap cleanup EXIT INT TERM
printf 'a6-a12-evidence-fix isolation\n' > "$PACK_TMP/.a6-a12-isolation"
export ELASTOS_TMP_ISOLATION="$PACK_TMP"
export ELASTOS_TMP_ROOT="$PACK_TMP"
cp "$A6" "$A6.r6bak"
cp "$A12" "$A12.r6bak"

printf 'r5-survivor recheck at %s\n' "$(git -C "$SUBJECT" rev-parse HEAD)"

apply_restore() {
  file=$1
  old=$2
  new=$3
  id=$4
  test_name=$5
  bak="${file}.r6plant"
  hits=$(python3 -I -c 'import sys; src=sys.stdin.read(); old=sys.argv[1]; print(src.count(old))' "$old" < "$file")
  if [ "$hits" != 1 ]; then
    printf 'R5 %s INCONCLUSIVE: old text occurs %s times in %s\n' "$id" "$hits" "$file"
    return 0
  fi
  cp "$file" "$bak"
  python3 -I -c 'import sys,pathlib; p=pathlib.Path(sys.argv[1]); old=sys.argv[2]; new=sys.argv[3]; src=p.read_text(); p.write_text(src.replace(old,new,1))' "$file" "$old" "$new"
  set +e
  output=$(cargo test --locked --offline --manifest-path "$MANIFEST" --lib \
    "$test_name" -- --exact --nocapture "$test_name" 2>&1)
  status=$?
  set -e
  mv "$bak" "$file"
  printf '\n== plant %s against %s cargo_exit=%s ==\n' "$id" "$test_name" "$status"
  printf '%s\n' "$output" | tail -n 20
  if printf '%s\n' "$output" | grep -q "test ${test_name} ... FAILED"; then
    printf 'R5 %s CAUGHT by %s\n' "$id" "$test_name"
  elif printf '%s\n' "$output" | grep -q "test ${test_name} ... ok"; then
    printf 'R5 %s SURVIVED against %s\n' "$id" "$test_name"
  else
    printf 'R5 %s INCONCLUSIVE against %s\n' "$id" "$test_name"
  fi
}

printf '\n== r5 survivor: drop /var/tmp and /dev/shm ==\n'
apply_restore "$A12" \
  '    for extra in ["/tmp", "/var/tmp", "/dev/shm"] {' \
  '    for extra in ["/tmp"] {' \
  R5-NO-SYSTEM-TEMPS tests::a12_run_window_watches_var_tmp_and_dev_shm

printf '\n== r5 survivor: ignore inotify create-then-delete ==\n'
apply_restore "$A12" \
  '    for path in drain_live_watch()? {
        if !found.iter().any(|seen| seen == &path) {
            found.push(path);
        }
    }' \
  '    let _ = drain_live_watch();' \
  R5-NO-LIVE-WATCH tests::a12_create_then_delete_between_snapshots_is_found

printf '\n== r5 survivor: hash only first 64 KiB ==\n'
apply_restore "$A12" \
  '    size.hash(hasher);
    let mut pos: i64 = 0;' \
  '    size.hash(hasher);
    let cap = size.min(65536);
    let mut pos: i64 = 0;
    let size = cap;' \
  R5-HASH-CAP-64K tests::a12_large_file_inplace_rewrite_mtime_restored_is_found

printf '\n== r5 survivor: fs::read holes as zeros ==\n'
apply_restore "$A12" \
  '    hash_whole_file_sparse(path, meta, &mut hasher);' \
  '    if let Ok(bytes) = std::fs::read(path) {
        bytes.hash(hasher);
    }' \
  R5-SPARSE-READ tests::a12_sparse_hole_hash_differs_from_written_zeros

printf '\n== r5 survivor: claimed pair skips RA-6 ==\n'
apply_restore "$A6" \
  '    match try_host_two_resident_instances() {
        Err(reason) => JourneyStatus::Blocked {
            ask: RA_6,
            reason: format!("claimed resident pair requires RA-6 runtime proof: {reason}"),
        },
        Ok(_pair) => {
            let session = Session::mint_instance1();
            finish_claimed_evidence(&session, evidence)
        }
    }' \
  '    let session = Session::mint_instance1();
    finish_claimed_evidence(&session, evidence)' \
  R5-CLAIMED-NO-RA6 tests::a6_two_other_live_pids_are_blocked

printf '\n== r5 survivor: empty handle accepted ==\n'
apply_restore "$A12" \
  '    if bytes.is_empty() {
        Err("name_to_handle_at empty handle; FileId NOT RUN".into())
    } else {
        Ok(bytes)
    }' \
  '    Ok(bytes)' \
  R5-HANDLE-EMPTY-OK tests::a12_empty_file_handle_is_not_run

printf '\n== r5 survivor: drop openat2 resolve flags ==\n'
apply_restore "$A12" \
  '        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,' \
  '        resolve: 0,' \
  R5-NO-OPENAT2 tests::a12_parent_dir_swap_after_check_cannot_write_outside

printf '\nr5-survivor recheck finished\n'
