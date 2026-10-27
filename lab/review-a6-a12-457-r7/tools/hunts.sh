#!/bin/sh
# Inject r7 probes into the #457 worktree, run them, restore every edited file.
set -eu
SUBJECT=${1:-/tmp/pr457-r7}
HERE=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
LIB="$SUBJECT/lab/a6-a12-evidence-fix/src/lib.rs"
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

PACK_TMP=$(mktemp -d "${TMPDIR:-/tmp}/a6-a12-r7-hunts.XXXXXX")
cleanup() {
  rm -f "$PROBE_DST"
  if [ -f "$LIB.r7bak" ]; then mv "$LIB.r7bak" "$LIB"; fi
  if [ -f "$A12.r7bak" ]; then mv "$A12.r7bak" "$A12"; fi
  rm -rf "$PACK_TMP"
}
trap cleanup EXIT INT TERM
printf 'a6-a12-evidence-fix isolation\n' > "$PACK_TMP/.a6-a12-isolation"
export ELASTOS_TMP_ISOLATION="$PACK_TMP"
export ELASTOS_TMP_ROOT="$PACK_TMP"

cp "$LIB" "$LIB.r7bak"
cp "$A12" "$A12.r7bak"
cp "$PROBE_SRC" "$PROBE_DST"
if grep -q 'mod review_probes;' "$LIB"; then
  printf 'lib.rs already names review_probes\n'
else
  printf '\n%s' "$MARKER" >> "$LIB"
fi

printf 'r7 hunts at %s\n' "$(git -C "$SUBJECT" rev-parse HEAD)"

set +e
cargo test --locked --offline --manifest-path "$MANIFEST" --lib -- --nocapture r7_
PROBE_STATUS=$?
set -e
printf 'new-hunts cargo r7_ exit=%s\n' "$PROBE_STATUS"

apply_restore() {
  file=$1
  old=$2
  new=$3
  id=$4
  test_name=$5
  bak="${file}.r7plant"
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
  printf '%s\n' "$output" | tail -n 30
  if printf '%s\n' "$output" | grep -q "test ${test_name} ... FAILED"; then
    printf 'HUNT %s CAUGHT by %s\n' "$id" "$test_name"
  elif printf '%s\n' "$output" | grep -q "test ${test_name} ... ok"; then
    printf 'HUNT %s SURVIVED against %s (named test stayed green)\n' "$id" "$test_name"
  else
    printf 'HUNT %s INCONCLUSIVE against %s\n' "$id" "$test_name"
  fi
}

printf '\n== R7-IGNORE-OVERFLOW: drop IN_Q_OVERFLOW fail-closed ==\n'
apply_restore "$A12" \
  '                if ev.mask & libc::IN_Q_OVERFLOW != 0 {
                    return Err("inotify queue overflow; leftover watch fail closed".into());
                }' \
  '                if ev.mask & libc::IN_Q_OVERFLOW != 0 {
                    // r7 plant: overflow is ignored
                }' \
  R7-IGNORE-OVERFLOW tests::a12_inotify_overflow_check_is_pinned

printf '\n== R7-NO-OPENAT2: resolve 0 ==\n'
apply_restore "$A12" \
  '        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,' \
  '        resolve: 0,' \
  R7-NO-OPENAT2 tests::a12_write_uses_openat2_beneath_no_symlinks

printf '\n== R7-SKIP-HOME-CACHE: drop HOME fallback when XDG is set ==\n'
# Confirm the author plant still matches source.
if grep -n 'if !roots.iter().any(|root| root == \&path)' "$A12"; then
  printf 'HUNT R7-HOME-CACHE-SOURCE CAUGHT: HOME fallback is present\n'
else
  printf 'HUNT R7-HOME-CACHE-SOURCE SURVIVED: HOME fallback missing\n'
fi

printf 'new-hunts finished probe_exit=%s\n' "$PROBE_STATUS"
