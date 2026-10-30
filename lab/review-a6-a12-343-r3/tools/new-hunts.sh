#!/bin/sh
# Inject r3 hunts into the #343 worktree, run them, restore the tree.
# Also plants try_host -> Ok to see if RA-6 can PASS without resident instances.
set -eu
SUBJECT=${1:-/tmp/pr343-r3}
HERE=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
LIB="$SUBJECT/lab/a6-a12-evidence-fix/src/lib.rs"
A6="$SUBJECT/lab/a6-a12-evidence-fix/src/a6.rs"
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
  if [ -f "$LIB.r3bak" ]; then
    mv "$LIB.r3bak" "$LIB"
  fi
  if [ -f "$A6.r3bak" ]; then
    mv "$A6.r3bak" "$A6"
  fi
}
trap cleanup EXIT INT TERM

cp "$LIB" "$LIB.r3bak"
cp "$PROBE_SRC" "$PROBE_DST"
if grep -q 'mod review_probes;' "$LIB"; then
  printf 'lib.rs already names review_probes\n'
else
  printf '\n%s' "$MARKER" >> "$LIB"
fi

set +e
cargo test --locked --offline \
  --manifest-path "$SUBJECT/lab/a6-a12-evidence-fix/Cargo.toml" \
  --lib r3_ -- --nocapture
probe_status=$?
set -e
printf 'new-hunts cargo exit=%s\n' "$probe_status"

# Can RA-6 report PASS if the hosting stub returns Ok(ResidentPair)?
printf '\n== RA-6 hosting stub flipped to Ok ==\n'
cp "$A6" "$A6.r3bak"
python3 -I -c '
import pathlib, sys
p = pathlib.Path(sys.argv[1])
old = "fn try_host_two_resident_instances() -> Result<ResidentPair, String> {"
new = "fn try_host_two_resident_instances() -> Result<ResidentPair, String> {\n    return Ok(ResidentPair);"
src = p.read_text()
if src.count(old) != 1:
    raise SystemExit(f"INCONCLUSIVE try_host old text occurs {src.count(old)} times")
p.write_text(src.replace(old, new, 1))
' "$A6"

set +e
output=$(cargo test --locked --offline \
  --manifest-path "$SUBJECT/lab/a6-a12-evidence-fix/Cargo.toml" \
  --lib tests::a6_resident_two_instances_is_blocked -- --exact --nocapture \
  tests::a6_resident_two_instances_is_blocked 2>&1)
status=$?
set -e
printf '%s\n' "$output" | tail -n 40
if printf '%s\n' "$output" | grep -q 'must not PASS until RA-6'; then
  printf 'HUNT ra6-stub-ok: SURVIVED journey returned PASS with empty ResidentPair (no Runtime host)\n'
elif printf '%s\n' "$output" | grep -q 'test tests::a6_resident_two_instances_is_blocked ... FAILED'; then
  printf 'HUNT ra6-stub-ok: SURVIVED named test FAILED because journey returned PASS\n'
elif printf '%s\n' "$output" | grep -q 'test tests::a6_resident_two_instances_is_blocked ... ok'; then
  printf 'HUNT ra6-stub-ok: CAUGHT journey stayed BLOCKED even with Ok stub\n'
else
  printf 'HUNT ra6-stub-ok: INCONCLUSIVE cargo_exit=%s\n' "$status"
fi
mv "$A6.r3bak" "$A6"

# Also call the journey function directly after the Ok stub, via a one-off probe.
# Restored above; re-apply briefly and print JourneyStatus via a tiny helper test.
# The named test already proves Pass is reachable. Keep the tree clean.

if [ "$probe_status" -ne 0 ]; then
  exit "$probe_status"
fi
exit 0
