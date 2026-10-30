#!/bin/sh
# Re-run the #343 subject suite when a worktree is present, then the review.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=true

SUBJECT_STATUS=0
if [ -x /tmp/pr343/lab/a6-a12-evidence-fix/run.sh ]; then
  /tmp/pr343/lab/a6-a12-evidence-fix/run.sh || SUBJECT_STATUS=$?
else
  printf 'NOT RUN: /tmp/pr343 worktree is absent; subject snapshot is lab/review-a6-a12-343/subject/\n'
fi

set +e
CARGO_TARGET_DIR="$ROOT/lab/review-a6-a12-343/target" \
  cargo test --offline --manifest-path lab/review-a6-a12-343/Cargo.toml --lib -- --nocapture
CARGO_STATUS=$?
python3 -I -m unittest discover -s lab/review-a6-a12-343/py -v
PY_STATUS=$?
set -e

printf '\nreview-a6-a12-343: subject=%s cargo=%s python=%s\n' \
  "$SUBJECT_STATUS" "$CARGO_STATUS" "$PY_STATUS"
printf 'Python FALSIFIED tests are expected to fail on this #343 head.\n'

if [ "$CARGO_STATUS" -ne 0 ]; then
  exit "$CARGO_STATUS"
fi
if [ "$PY_STATUS" -ne 0 ]; then
  exit "$PY_STATUS"
fi
exit "$SUBJECT_STATUS"
