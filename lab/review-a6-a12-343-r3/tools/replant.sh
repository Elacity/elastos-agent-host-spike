#!/bin/sh
# Independently re-apply every r2 survivor (and the #365 set) to the live
# #343 tree. Does not use the author's plant runner. Restores each file.
set -eu
SUBJECT=${1:-/tmp/pr343-r3}
export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SUBJECT/lab/a6-a12-evidence-fix/target}"
export CARGO_NET_OFFLINE=true
export A6A12_PLANT_CHILD=1

MANAGER="$SUBJECT/elastos/crates/elastos-runtime/src/capability/manager.rs"
A12="$SUBJECT/lab/a6-a12-evidence-fix/src/a12.rs"
A6="$SUBJECT/lab/a6-a12-evidence-fix/src/a6.rs"
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
    printf 'CAUGHT %s by %s\n' "$id" "$test_name"
  elif printf '%s\n' "$output" | grep -q "test ${test_name} ... ok"; then
    printf 'SURVIVED %s against %s\n' "$id" "$test_name"
  else
    printf 'INCONCLUSIVE %s against %s\n' "$id" "$test_name"
    printf '%s\n' "$output" | tail -n 40
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
    printf 'INCONCLUSIVE %s: old text occurs %s times in %s\n' "$id" "$hits" "$file"
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

printf 'independent r2-survivor replants at %s\n' "$(git -C "$SUBJECT" rev-parse HEAD)"

# --- #365 set (r2 said these were CAUGHT; confirm on this head) ---

apply_restore "$MANAGER" \
  '        if token.capsule != caller_capsule_id {' \
  '        if !caller_capsule_id.starts_with(token.capsule.as_str()) {' \
  M-A6-PREFIX-BIND tests::a6_prefix_capsule_id_is_refused

apply_restore "$MANAGER" \
  '        if token.capsule != caller_capsule_id {' \
  '        if !token.capsule.is_empty() && token.capsule != caller_capsule_id {' \
  M-A6-EMPTY-TOKEN tests::a6_empty_token_capsule_is_refused

apply_restore "$MANAGER" \
  '        if token.capsule != caller_capsule_id {
            self.audit_validation_failure(token, caller_capsule_id, "wrong_capsule");
            return Err(ValidationError::WrongCapsule {
                expected: token.capsule.clone(),
                got: caller_capsule_id.to_string(),
            });
        }' \
  '        // step 4 commented out' \
  M-A6-COMMENT-STEP4 tests::a6_sibling_presenting_owner_token_is_refused

apply_restore "$MANAGER" \
  '        if token.capsule != caller_capsule_id {
            self.audit_validation_failure(token, caller_capsule_id, "wrong_capsule");
            return Err(ValidationError::WrongCapsule {
                expected: token.capsule.clone(),
                got: caller_capsule_id.to_string(),
            });
        }' \
  '        // step 4 commented out' \
  M-A6-COMMENT-STEP4-RA6 tests::a6_resident_two_instances_is_blocked

apply_restore "$A12" \
  '    let leftovers = leftovers_under(roots)?;
    if leftovers.is_empty() {
        Ok(format!(
            "runtime-temp census: PASS leftovers:0 roots:{roots:?}"
        ))
    } else {
        Err(format!(
            "runtime-temp census: FAIL leftovers:{} paths:{leftovers:?}",
            leftovers.len()
        ))
    }' \
  '    let _leftovers = leftovers_under(roots)?;
    Err("runtime-temp census: FAIL leftovers:3 paths:[hardcoded]".into())' \
  M-A12-HARDCODE-FAIL tests::a12_clean_isolated_root_passes

apply_restore "$A12" \
  '        if follow_root_symlink {
            let target = fs::canonicalize(root)
                .map_err(|_| format!("could not resolve symlink root {}", root.display()))?;
            found.insert(target.clone());
            walk_resolved(&target, found)?;
        }' \
  '        if follow_root_symlink {
            // hide nested leftovers behind the symlink
        }' \
  M-A12-SYMLINK-ROOT tests::a12_symlink_root_is_scanned_through

apply_restore "$A12" \
  'fn keep_created_path(before: &FsSnapshot, path: &Path, ino: (u64, u64)) -> bool {
    let new_inode = !before.inodes.contains(&ino);
    let new_path = !before.paths.contains(path);
    new_inode || new_path
}' \
  'fn keep_created_path(before: &FsSnapshot, path: &Path, ino: (u64, u64)) -> bool {
    let _ = (before, path, ino);
    false
}' \
  M-A12-RENAME-ROOT tests::a12_renamed_root_is_found_by_created_set

# --- r2 survivors that the author now names ---

apply_restore "$A12" \
  '        if keep_created_path(before, path, ino) && allow_moved_away(path) {
            found.insert(path.to_path_buf());
        }' \
  '        if keep_created_path(before, path, ino) && allow_moved_away(path) {
            match fs::read(path) {
                Ok(bytes) if bytes == LEFTOVER_MARKER => {
                    found.insert(path.to_path_buf());
                }
                _ => {}
            }
        }' \
  M-A12-NO-MARKER tests::a12_leftover_without_marker_is_found

apply_restore "$A12" \
  'fn allow_moved_away(path: &Path) -> bool {
    let _ = path;
    true
}' \
  'fn allow_moved_away(path: &Path) -> bool {
    !path.components().any(|part| part.as_os_str() == "moved-away")
}' \
  M-A12-RENAME-UNRELATED tests::a12_renamed_to_unrelated_name_is_found

apply_restore "$A12" \
  '    if path == Path::new("/") {
        return Err("ELASTOS_TMP_ROOT refuses /".into());
    }' \
  '    if false && path == Path::new("/") {
        return Err("ELASTOS_TMP_ROOT refuses /".into());
    }' \
  M-A12-TMP-SLASH tests::a12_slash_tmp_root_is_refused

apply_restore "$A12" \
  '        Err(_) => Err("ELASTOS_TMP_ROOT is unset; pack must set an isolated mktemp dir".into()),' \
  '        Err(_) => Ok(PathBuf::from("/tmp/elastos")),' \
  M-A12-TMP-UNSET tests::a12_unset_tmp_root_is_refused

apply_restore "$A6" \
  '        Err(reason) => JourneyStatus::Blocked {
            ask: RA_6,
            reason,
        },' \
  '        Err(reason) => JourneyStatus::Pass(reason),' \
  M-A6-CLAIM-RESIDENT tests::a6_resident_two_instances_is_blocked

printf 'replants finished; manager.rs sha256=%s\n' "$(sha256sum "$MANAGER" | awk '{print $1}')"
printf 'a12.rs sha256=%s\n' "$(sha256sum "$A12" | awk '{print $1}')"
printf 'a6.rs sha256=%s\n' "$(sha256sum "$A6" | awk '{print $1}')"
