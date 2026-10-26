#!/bin/sh
# Independently re-apply every #365 surviving mutant to the live #343 tree.
# Does not use the author's plant runner. Restores each file after the test.
set -eu
SUBJECT=${1:-/tmp/pr343-r2}
export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SUBJECT/lab/a6-a12-evidence-fix/target}"
export CARGO_NET_OFFLINE=true
export A6A12_PLANT_CHILD=1

MANAGER="$SUBJECT/elastos/crates/elastos-runtime/src/capability/manager.rs"
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
  original=$(cat "$file")
  count=$(printf '%s\n' "$original" | grep -F -c -- "$old" || true)
  # grep -c counts lines; the old text may be multiline. Use python for exact count.
  hits=$(python3 -I -c 'import sys; src=sys.stdin.read(); old=sys.argv[1]; print(src.count(old))' "$old" < "$file")
  if [ "$hits" != 1 ]; then
    printf 'INCONCLUSIVE %s: old text occurs %s times in %s\n' "$id" "$hits" "$file"
    return 0
  fi
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

printf 'independent #365 replants at %s\n' "$(git -C "$SUBJECT" rev-parse HEAD)"

# M-A6-PREFIX-BIND
apply_restore "$MANAGER" \
  '        if token.capsule != caller_capsule_id {' \
  '        if !caller_capsule_id.starts_with(token.capsule.as_str()) {' \
  M-A6-PREFIX-BIND tests::a6_prefix_capsule_id_is_refused

# M-A6-EMPTY-TOKEN
apply_restore "$MANAGER" \
  '        if token.capsule != caller_capsule_id {' \
  '        if !token.capsule.is_empty() && token.capsule != caller_capsule_id {' \
  M-A6-EMPTY-TOKEN tests::a6_empty_token_capsule_is_refused

# M-A6-COMMENT-STEP4
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

# M-A12-HARDCODE-FAIL
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

# M-A12-SYMLINK-ROOT
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

# M-A12-RENAME-ROOT
apply_restore "$A12" \
  '        walk_root(root, &mut found, true)?;
        scan_parent_for_marker(root, &mut found)?;' \
  '        walk_root(root, &mut found, true)?;' \
  M-A12-RENAME-ROOT tests::a12_renamed_root_is_found_by_marker

printf 'replants finished; manager.rs sha256=%s\n' "$(sha256sum "$MANAGER" | awk '{print $1}')"
printf 'a12.rs sha256=%s\n' "$(sha256sum "$A12" | awk '{print $1}')"
