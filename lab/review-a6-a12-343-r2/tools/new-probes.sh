#!/bin/sh
# Inject r2 probes into the #343 worktree, run them, restore the tree.
set -eu
SUBJECT=${1:-/tmp/pr343-r2}
HERE=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
LIB="$SUBJECT/lab/a6-a12-evidence-fix/src/lib.rs"
PROBE_SRC="$HERE/src/probes.rs"
PROBE_DST="$SUBJECT/lab/a6-a12-evidence-fix/src/review_probes.rs"
MARKER='#[cfg(test)]
mod review_probes;
'
export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SUBJECT/lab/a6-a12-evidence-fix/target}"
export CARGO_NET_OFFLINE=true
export A6A12_PLANT_CHILD=1

cleanup() {
  rm -f "$PROBE_DST"
  if [ -f "$LIB.r2bak" ]; then
    mv "$LIB.r2bak" "$LIB"
  fi
}
trap cleanup EXIT INT TERM

cp "$LIB" "$LIB.r2bak"
cp "$PROBE_SRC" "$PROBE_DST"
if grep -q 'mod review_probes;' "$LIB"; then
  printf 'lib.rs already names review_probes\n'
else
  printf '\n%s' "$MARKER" >> "$LIB"
fi

set +e
cargo test --locked --offline \
  --manifest-path "$SUBJECT/lab/a6-a12-evidence-fix/Cargo.toml" \
  --lib r2_ -- --nocapture
status=$?
set -e
printf 'new-probes cargo exit=%s\n' "$status"
exit "$status"
