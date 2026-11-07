#!/bin/sh
# Six-plus r4 mutants of the guard and census. Restore after each.
set -eu
SUBJECT=${1:-/tmp/pr343-r4}
export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SUBJECT/lab/a6-a12-evidence-fix/target}"
export CARGO_NET_OFFLINE=true
export A6A12_PLANT_CHILD=1

A12="$SUBJECT/lab/a6-a12-evidence-fix/src/a12.rs"
MANIFEST="$SUBJECT/lab/a6-a12-evidence-fix/Cargo.toml"

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

printf 'r4 mutants at %s\n' "$(git -C "$SUBJECT" rev-parse HEAD)"

# 1. Drop isolation-under check. Named slash/home tests should still pass.
#    Also probe check_tmp_root("/var/tmp") by running the home test plus a
#    one-off compile of extra_watch is not enough; run a12_slash and note
#    the isolation check is untested by that name.
apply_restore "$A12" \
  '    if !is_under(&canonical, &isolation_canon) {
        return Err(format!(
            "ELASTOS_TMP_ROOT {} is not under isolated mktemp {}",
            path.display(),
            isolation.display()
        ));
    }' \
  '    let _ = isolation_canon;' \
  M-R4-GUARD-NO-ISOLATION tests::a12_slash_tmp_root_is_refused

apply_restore "$A12" \
  '    if !is_under(&canonical, &isolation_canon) {
        return Err(format!(
            "ELASTOS_TMP_ROOT {} is not under isolated mktemp {}",
            path.display(),
            isolation.display()
        ));
    }' \
  '    let _ = isolation_canon;' \
  M-R4-GUARD-NO-ISOLATION-HOME tests::a12_home_and_live_home_tmp_root_are_refused

apply_restore "$A12" \
  '    if !is_under(&canonical, &isolation_canon) {
        return Err(format!(
            "ELASTOS_TMP_ROOT {} is not under isolated mktemp {}",
            path.display(),
            isolation.display()
        ));
    }' \
  '    let _ = isolation_canon;' \
  M-R4-GUARD-NO-ISOLATION-DOTDOT tests::a12_isolation_parent_tmp_root_is_refused

# 2. Skip check_tmp_root entirely.
apply_restore "$A12" \
  '            let path = PathBuf::from(value);
            check_tmp_root(&path)?;
            Ok(path)' \
  '            let path = PathBuf::from(value);
            Ok(path)' \
  M-R4-GUARD-SKIP-CHECK tests::a12_slash_tmp_root_is_refused

# 3. Only inspect the final component for a symlink.
apply_restore "$A12" \
  'fn first_symlink_at_or_under(path: &Path, isolation: &Path) -> Option<PathBuf> {
    let mut acc = PathBuf::new();
    for part in path.components() {
        acc.push(part);
        if acc != isolation && !is_under(&acc, isolation) {
            continue;
        }
        match fs::symlink_metadata(&acc) {
            Ok(meta) if meta.file_type().is_symlink() => return Some(acc),
            _ => {}
        }
    }
    None
}' \
  'fn first_symlink_at_or_under(path: &Path, isolation: &Path) -> Option<PathBuf> {
    let _ = isolation;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Some(path.to_path_buf()),
        _ => None,
    }
}' \
  M-R4-GUARD-LEAF-SYMLINK tests::a12_symlink_to_live_home_tmp_root_is_refused

# 4. FileId content_hash always 0.
apply_restore "$A12" \
  '        content_hash: content_hash(path, meta, size),' \
  '        content_hash: 0,' \
  M-R4-CENSUS-NO-HASH tests::a12_inode_reuse_same_path_is_found

# 5. FileId birth_or_ctime always 0.
apply_restore "$A12" \
  '        birth_or_ctime: birth_or_ctime(meta),' \
  '        birth_or_ctime: 0,' \
  M-R4-CENSUS-NO-CTIME tests::a12_inode_reuse_same_path_is_found

# 6. Identity is only (dev,ino)+path (r3 hide).
apply_restore "$A12" \
  'fn keep_created_path(before: &FsSnapshot, path: &Path, id: &FileId) -> bool {
    match before.ids.get(path) {
        None => true,
        Some(old) => old != id,
    }
}' \
  'fn keep_created_path(before: &FsSnapshot, path: &Path, id: &FileId) -> bool {
    let new_inode = !before.inodes.contains(&(id.dev, id.ino));
    let new_path = !before.paths.contains(path);
    new_inode || new_path
}' \
  M-R4-CENSUS-INO-ONLY tests::a12_inode_reuse_same_path_is_found

# 7. snapshot_before_runtime ignores /tmp/elastos.
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
  M-R4-SNAP-IGNORE-LIVE tests::a12_snapshot_before_runtime_fails_if_already_wrote

printf 'mutants finished; a12.rs sha256=%s\n' "$(sha256sum "$A12" | awk '{print $1}')"
