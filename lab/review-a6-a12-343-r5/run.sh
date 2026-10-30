#!/bin/sh
# Rerun #343 at 9d55f8fb, restore check, independent replants, r5 hunts.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
HERE="$ROOT/lab/review-a6-a12-343-r5"
EVIDENCE="$HERE/evidence"
PIN=9d55f8fbd670bbaef9cd329fd795b5fb5cb9c04e
SUBJECT="${SUBJECT_WORKTREE:-/tmp/pr343-r5}"

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
"$HERE/tools/mutants.sh" "$SUBJECT" > "$EVIDENCE/mutants.txt" 2>&1
MUTANT_STATUS=$?
"$HERE/tools/new-hunts.sh" "$SUBJECT" > "$EVIDENCE/new-hunts.txt" 2>&1
HUNT_STATUS=$?
"$HERE/tools/mac-pack-probe.sh" "$SUBJECT" > "$EVIDENCE/mac-pack-probe.txt" 2>&1
MAC_STATUS=$?
set -e

git -C "$SUBJECT" status --short --branch > "$EVIDENCE/worktree-after-hunts.txt"
sha256sum "$MANAGER" | awk '{print $1}' > "$EVIDENCE/restore-after-hunts.txt"

# r3 pin refuse (read-only)
if [ -f "$SUBJECT/lab/review-a6-a12-343-r3/run.sh" ]; then
  python3 -I - "$SUBJECT/lab/review-a6-a12-343-r3/run.sh" "$head" > "$EVIDENCE/r3-pin-refuse.txt" 2>&1 <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
head = sys.argv[2]
pins = re.findall(r'PIN=([0-9a-f]{40})', text)
print(f'lab/review-a6-a12-343-r3/run.sh PIN={pins}')
print(f'subject HEAD={head}')
if pins and head not in pins:
    print('REFUSE')
else:
    print('UNEXPECTED: r3 runner would accept this head or has no pin')
PY
else
  printf 'r3 runner absent on this head; pin refuse checked from fetched r3 review\n' \
    > "$EVIDENCE/r3-pin-refuse.txt"
fi

printf '\nreview-a6-a12-343-r5: subject=%s restore=%s replant=%s mutants=%s hunts=%s mac=%s\n' \
  "$SUBJECT_STATUS" \
  "$([ "$before" = "$after" ] && printf OK || printf DRIFT)" \
  "$REPLANT_STATUS" \
  "$MUTANT_STATUS" \
  "$HUNT_STATUS" \
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
if [ "$MUTANT_STATUS" -ne 0 ]; then
  exit "$MUTANT_STATUS"
fi
if [ "$HUNT_STATUS" -ne 0 ]; then
  exit "$HUNT_STATUS"
fi
exit "$MAC_STATUS"
