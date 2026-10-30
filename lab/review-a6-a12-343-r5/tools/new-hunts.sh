#!/bin/sh
# Inject r5 probes into the #343 worktree, run them, then apply new plants.
# Restores every edited file.
set -eu
SUBJECT=${1:-/tmp/pr343-r5}
HERE=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
LIB="$SUBJECT/lab/a6-a12-evidence-fix/src/lib.rs"
A6="$SUBJECT/lab/a6-a12-evidence-fix/src/a6.rs"
A12="$SUBJECT/lab/a6-a12-evidence-fix/src/a12.rs"
PROBE_SRC="$HERE/src/probes.rs"
PROBE_DST="$SUBJECT/lab/a6-a12-evidence-fix/src/review_probes.rs"
MANIFEST="$SUBJECT/lab/a6-a12-evidence-fix/Cargo.toml"
MARKER='#[cfg(test)]
mod review_probes;
'
export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SUBJECT/lab/a6-a12-evidence-fix/target}"
export CARGO_NET_OFFLINE=true
export A6A12_PLANT_CHILD=1

PACK_TMP=$(mktemp -d "${TMPDIR:-/tmp}/a6-a12-r5-hunts.XXXXXX")
cleanup() {
  rm -f "$PROBE_DST"
  if [ -f "$LIB.r5bak" ]; then
    mv "$LIB.r5bak" "$LIB"
  fi
  if [ -f "$A6.r5bak" ]; then
    mv "$A6.r5bak" "$A6"
  fi
  if [ -f "$A12.r5bak" ]; then
    mv "$A12.r5bak" "$A12"
  fi
  rm -rf "$PACK_TMP"
}
trap cleanup EXIT INT TERM
printf 'a6-a12-evidence-fix isolation\n' > "$PACK_TMP/.a6-a12-isolation"
export ELASTOS_TMP_ISOLATION="$PACK_TMP"
export ELASTOS_TMP_ROOT="$PACK_TMP"

cp "$LIB" "$LIB.r5bak"
cp "$PROBE_SRC" "$PROBE_DST"
if grep -q 'mod review_probes;' "$LIB"; then
  printf 'lib.rs already names review_probes\n'
else
  printf '\n%s' "$MARKER" >> "$LIB"
fi

printf 'r5 hunts at %s\n' "$(git -C "$SUBJECT" rev-parse HEAD)"

set +e
cargo test --locked --offline --manifest-path "$MANIFEST" --lib -- --nocapture r5_
PROBE_STATUS=$?
set -e
printf 'new-hunts cargo r5_ exit=%s\n' "$PROBE_STATUS"

apply_restore() {
  file=$1
  old=$2
  new=$3
  id=$4
  test_name=$5
  bak="${file}.r5plant"
  hits=$(python3 -I -c 'import sys; src=sys.stdin.read(); old=sys.argv[1]; print(src.count(old))' "$old" < "$file")
  if [ "$hits" != 1 ]; then
    printf 'HUNT %s INCONCLUSIVE: old text occurs %s times in %s\n' "$id" "$hits" "$file"
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
  printf '%s\n' "$output" | tail -n 40
  if printf '%s\n' "$output" | grep -q "test ${test_name} ... FAILED"; then
    printf 'HUNT %s CAUGHT by %s\n' "$id" "$test_name"
  elif printf '%s\n' "$output" | grep -q "test ${test_name} ... ok"; then
    printf 'HUNT %s SURVIVED against %s (named test stayed green)\n' "$id" "$test_name"
  else
    printf 'HUNT %s INCONCLUSIVE against %s\n' "$id" "$test_name"
  fi
  # Probe hunts print HUNT lines even when the cargo test is ok.
  printf '%s\n' "$output" | grep '^HUNT ' || true
}

printf '\n== R5-PROVE-ALWAYS-OK: prove_resident_capsule_instance returns Ok ==\n'
apply_restore "$A6" \
  'pub fn prove_resident_capsule_instance(pid: u32, instance_id: &str) -> Result<(), String> {
    if instance_id.is_empty() {
        return Err("resident instance id is empty".into());
    }' \
  'pub fn prove_resident_capsule_instance(pid: u32, instance_id: &str) -> Result<(), String> {
    let _ = (pid, instance_id);
    return Ok(());
    if instance_id.is_empty() {
        return Err("resident instance id is empty".into());
    }' \
  R5-PROVE-ALWAYS-OK tests::a6_this_process_and_pid1_cannot_pass

apply_restore "$A6" \
  'pub fn prove_resident_capsule_instance(pid: u32, instance_id: &str) -> Result<(), String> {
    if instance_id.is_empty() {
        return Err("resident instance id is empty".into());
    }' \
  'pub fn prove_resident_capsule_instance(pid: u32, instance_id: &str) -> Result<(), String> {
    let _ = (pid, instance_id);
    return Ok(());
    if instance_id.is_empty() {
        return Err("resident instance id is empty".into());
    }' \
  R5-PROVE-ALWAYS-OK-JOURNEY tests::a6_resident_two_instances_is_blocked

apply_restore "$A6" \
  'pub fn prove_resident_capsule_instance(pid: u32, instance_id: &str) -> Result<(), String> {
    if instance_id.is_empty() {
        return Err("resident instance id is empty".into());
    }' \
  'pub fn prove_resident_capsule_instance(pid: u32, instance_id: &str) -> Result<(), String> {
    let _ = (pid, instance_id);
    return Ok(());
    if instance_id.is_empty() {
        return Err("resident instance id is empty".into());
    }' \
  R5-PROVE-ALWAYS-OK-OTHER-PIDS review_probes::r5_two_other_live_pids_claimed

printf '\n== R5-INSPECT-ALWAYS-SOME: inspect_runtime_hosted_resident returns Some(()) ==\n'
apply_restore "$A6" \
  'fn inspect_runtime_hosted_resident(_pid: u32, _instance_id: &str) -> Option<()> {
    None
}' \
  'fn inspect_runtime_hosted_resident(_pid: u32, _instance_id: &str) -> Option<()> {
    Some(())
}' \
  R5-INSPECT-ALWAYS-SOME tests::a6_this_process_and_pid1_cannot_pass

apply_restore "$A6" \
  'fn inspect_runtime_hosted_resident(_pid: u32, _instance_id: &str) -> Option<()> {
    None
}' \
  'fn inspect_runtime_hosted_resident(_pid: u32, _instance_id: &str) -> Option<()> {
    Some(())
}' \
  R5-INSPECT-ALWAYS-SOME-JOURNEY tests::a6_resident_two_instances_is_blocked

apply_restore "$A6" \
  'fn inspect_runtime_hosted_resident(_pid: u32, _instance_id: &str) -> Option<()> {
    None
}' \
  'fn inspect_runtime_hosted_resident(_pid: u32, _instance_id: &str) -> Option<()> {
    Some(())
}' \
  R5-INSPECT-ALWAYS-SOME-OTHER-PIDS review_probes::r5_two_other_live_pids_claimed

printf '\n== R5-NO-RECHECK: skip check_tmp_root in write, then parent swap ==\n'
apply_restore "$A12" \
  '    check_tmp_root(tmp_root)?;
    let root_fd = open_or_create_dir_nofollow(tmp_root)?;' \
  '    let root_fd = open_or_create_dir_nofollow(tmp_root)?;' \
  R5-NO-RECHECK-PARENT-SWAP review_probes::r5_parent_dir_swap_above_checked_root

printf '\n== R5-HASH-CAP-64K: hash only the first 64 KiB ==\n'
apply_restore "$A12" \
  '    match fs::read(path) {
        Ok(bytes) => bytes.hash(&mut hasher),
        Err(_) => return 0,
    }' \
  '    match fs::read(path) {
        Ok(bytes) => bytes.get(..65536).unwrap_or(&bytes).hash(&mut hasher),
        Err(_) => return 0,
    }' \
  R5-HASH-CAP-64K review_probes::r5_last_byte_of_large_file

apply_restore "$A12" \
  '    match fs::read(path) {
        Ok(bytes) => bytes.hash(&mut hasher),
        Err(_) => return 0,
    }' \
  '    match fs::read(path) {
        Ok(bytes) => bytes.get(..65536).unwrap_or(&bytes).hash(&mut hasher),
        Err(_) => return 0,
    }' \
  R5-HASH-CAP-64K-NAMED tests::a12_large_file_inplace_rewrite_mtime_restored_is_found

printf '\n== R5-HANDLE-EMPTY: force name_to_handle_at fallback ==\n'
apply_restore "$A12" \
  '        file_handle: file_handle_bytes(path),' \
  '        file_handle: Vec::new(),' \
  R5-HANDLE-EMPTY review_probes::r5_name_to_handle_at_on_tmpfs

printf 'new-hunts finished; a6.rs sha256=%s\n' "$(sha256sum "$A6" | awk '{print $1}')"
printf 'a12.rs sha256=%s\n' "$(sha256sum "$A12" | awk '{print $1}')"
if [ "$PROBE_STATUS" -ne 0 ]; then
  exit "$PROBE_STATUS"
fi
exit 0
