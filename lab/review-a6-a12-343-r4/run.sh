#!/bin/sh
# Rerun #343 at 19becdd7, restore check, independent replants, r3+r4 hunts.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
HERE="$ROOT/lab/review-a6-a12-343-r4"
EVIDENCE="$HERE/evidence"
PIN=19becdd74c3f96d5900487051d2e175fd5c06747
SUBJECT="${SUBJECT_WORKTREE:-/tmp/pr343-r4}"

mkdir -p "$EVIDENCE"
export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0

if [ ! -d "$SUBJECT/.git" ] && [ ! -f "$SUBJECT/.git" ]; then
  printf 'NOT RUN: subject worktree %s is absent\n' "$SUBJECT"
  exit 2
fi

head=$(git -C "$SUBJECT" rev-parse HEAD)
if [ "$head" != "$PIN" ]; then
  printf 'REFUSE: subject HEAD %s is not pin %s\n' "$head" "$PIN"
  exit 2
fi

MANAGER="$SUBJECT/elastos/crates/elastos-runtime/src/capability/manager.rs"
before=$(sha256sum "$MANAGER" | awk '{print $1}')
printf '%s\n' "$before" > "$EVIDENCE/manager-before.sha256"
printf 'subject HEAD %s\n' "$head" > "$EVIDENCE/subject-head.txt"

set +e
( cd "$SUBJECT" && ./lab/a6-a12-evidence-fix/run.sh ) \
  > "$EVIDENCE/subject-run.txt" 2>&1
SUBJECT_STATUS=$?
set -e

after=$(sha256sum "$MANAGER" | awk '{print $1}')
printf '%s\n' "$after" > "$EVIDENCE/manager-after.sha256"
git -C "$SUBJECT" status --short --branch > "$EVIDENCE/worktree-after.txt"
ls /tmp/elastos > "$EVIDENCE/tmp-elastos-after.txt" 2>&1 || true
( cd "$SUBJECT" && cargo test --locked --offline \
    --manifest-path lab/a6-a12-evidence-fix/Cargo.toml --lib -- --list ) \
  > "$EVIDENCE/test-list.txt" 2>&1 || true

printf 'subject-run exit=%s manager-before=%s manager-after=%s\n' \
  "$SUBJECT_STATUS" "$before" "$after" | tee "$EVIDENCE/restore-check.txt"

if [ "$before" != "$after" ]; then
  printf 'FALSIFIED: plants did not restore manager.rs byte-identically\n' \
    | tee -a "$EVIDENCE/restore-check.txt"
fi

set +e
"$HERE/tools/replant.sh" "$SUBJECT" > "$EVIDENCE/replant.txt" 2>&1
REPLANT_STATUS=$?
"$HERE/tools/new-hunts.sh" "$SUBJECT" > "$EVIDENCE/new-hunts.txt" 2>&1
HUNT_STATUS=$?
"$HERE/tools/mutants.sh" "$SUBJECT" > "$EVIDENCE/mutants.txt" 2>&1
MUTANT_STATUS=$?
"$HERE/tools/mac-pack-probe.sh" "$SUBJECT" > "$EVIDENCE/mac-pack-probe.txt" 2>&1
MAC_STATUS=$?
set -e

git -C "$SUBJECT" status --short --branch > "$EVIDENCE/worktree-after-hunts.txt"
sha256sum "$MANAGER" | awk '{print $1}' > "$EVIDENCE/restore-after-hunts.txt"

printf '\nreview-a6-a12-343-r4: subject=%s restore=%s replant=%s hunts=%s mutants=%s mac=%s\n' \
  "$SUBJECT_STATUS" \
  "$([ "$before" = "$after" ] && printf OK || printf DRIFT)" \
  "$REPLANT_STATUS" \
  "$HUNT_STATUS" \
  "$MUTANT_STATUS" \
  "$MAC_STATUS"

if [ "$SUBJECT_STATUS" -ne 0 ]; then
  exit "$SUBJECT_STATUS"
fi
if [ "$before" != "$after" ]; then
  exit 1
fi
if [ "$REPLANT_STATUS" -ne 0 ]; then
  exit "$REPLANT_STATUS"
fi
if [ "$HUNT_STATUS" -ne 0 ]; then
  exit "$HUNT_STATUS"
fi
if [ "$MUTANT_STATUS" -ne 0 ]; then
  exit "$MUTANT_STATUS"
fi
exit "$MAC_STATUS"
