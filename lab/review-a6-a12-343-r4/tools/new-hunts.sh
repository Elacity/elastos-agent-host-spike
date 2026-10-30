#!/bin/sh
# Inject r3+r4 probes into the #343 worktree, run them, restore the tree.
# Also replays the r3 ra6-stub-ok plant and two A6 pid plants.
set -eu
SUBJECT=${1:-/tmp/pr343-r4}
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
  if [ -f "$LIB.r4bak" ]; then
    mv "$LIB.r4bak" "$LIB"
  fi
  if [ -f "$A6.r4bak" ]; then
    mv "$A6.r4bak" "$A6"
  fi
}
trap cleanup EXIT INT TERM

cp "$LIB" "$LIB.r4bak"
cp "$PROBE_SRC" "$PROBE_DST"
if grep -q 'mod review_probes;' "$LIB"; then
  printf 'lib.rs already names review_probes\n'
else
  printf '\n%s' "$MARKER" >> "$LIB"
fi

set +e
cargo test --locked --offline \
  --manifest-path "$SUBJECT/lab/a6-a12-evidence-fix/Cargo.toml" \
  --lib -- --nocapture r3_
r3_status=$?
cargo test --locked --offline \
  --manifest-path "$SUBJECT/lab/a6-a12-evidence-fix/Cargo.toml" \
  --lib -- --nocapture r4_
r4_status=$?
set -e
if [ "$r3_status" -ne 0 ]; then
  probe_status=$r3_status
elif [ "$r4_status" -ne 0 ]; then
  probe_status=$r4_status
else
  probe_status=0
fi
printf 'new-hunts cargo r3=%s r4=%s\n' "$r3_status" "$r4_status"

classify_ra6_output() {
  output=$1
  status=$2
  printf '%s\n' "$output" | tail -n 50
  if printf '%s\n' "$output" | grep -q 'must not PASS until RA-6'; then
    printf 'HUNT ra6-stub-ok: SURVIVED journey returned PASS with empty ResidentPair (no Runtime host)\n'
  elif printf '%s\n' "$output" | grep -q 'empty ResidentPair'; then
    printf 'HUNT ra6-stub-ok: CAUGHT named test FAILED because journey returned FAIL on empty ResidentPair, not PASS\n'
  elif printf '%s\n' "$output" | grep -q 'must be BLOCKED, not FAIL'; then
    printf 'HUNT ra6-stub-ok: CAUGHT named test FAILED because journey returned FAIL, not PASS\n'
  elif printf '%s\n' "$output" | grep -q 'test tests::a6_resident_two_instances_is_blocked ... FAILED'; then
    printf 'HUNT ra6-stub-ok: INCONCLUSIVE named test FAILED without FAIL/PASS panic text cargo_exit=%s\n' "$status"
  elif printf '%s\n' "$output" | grep -q 'test tests::a6_resident_two_instances_is_blocked ... ok'; then
    printf 'HUNT ra6-stub-ok: CAUGHT journey stayed BLOCKED even with Ok stub\n'
  else
    printf 'HUNT ra6-stub-ok: INCONCLUSIVE cargo_exit=%s\n' "$status"
  fi
}

printf '\n== r3 plant: hosting stub flipped to Ok(ResidentPair) ==\n'
cp "$A6" "$A6.r4bak"
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
classify_ra6_output "$output" "$status"
# r3 script wording, for the author's claim that it still prints SURVIVED
if printf '%s\n' "$output" | grep -q 'test tests::a6_resident_two_instances_is_blocked ... FAILED'; then
  printf 'HUNT ra6-stub-ok-r3-script: SURVIVED named test FAILED (r3 script would print this regardless of FAIL vs PASS)\n'
fi
mv "$A6.r4bak" "$A6"

plant_query_and_host() {
  pid2=$1
  python3 -I - "$A6" "$pid2" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
pid2 = sys.argv[2]
src = p.read_text()
start = src.find("pub fn query_runtime_resident_instances()")
end = src.find("fn pid_is_live")
if start < 0 or end < 0:
    raise SystemExit("INCONCLUSIVE query_runtime_resident_instances markers missing")
body = src[start:end]
if body.count("Err(") != 1:
    raise SystemExit(f"INCONCLUSIVE query body unexpected Err count {body.count('Err(')}")
if pid2 == "SAME":
    pid2_expr = "pid"
else:
    pid2_expr = pid2
new = f"""pub fn query_runtime_resident_instances() -> Result<RuntimeResidentEvidence, String> {{
    let pid = std::process::id();
    Ok(RuntimeResidentEvidence {{
        instance_1_id: "instance-1".into(),
        instance_1_pid: pid,
        instance_1_grant: "grant-1".into(),
        instance_2_id: "instance-2".into(),
        instance_2_pid: {pid2_expr},
        instance_2_grant: "grant-2".into(),
    }})
}}

"""
host_old = "fn try_host_two_resident_instances() -> Result<ResidentPair, String> {"
host_new = "fn try_host_two_resident_instances() -> Result<ResidentPair, String> {\n    return Ok(ResidentPair);"
if src.count(host_old) != 1:
    raise SystemExit(f"INCONCLUSIVE try_host old text occurs {src.count(host_old)} times")
updated = src[:start] + new + src[end:]
if updated.count(host_old) != 1:
    raise SystemExit(f"INCONCLUSIVE try_host after query replace occurs {updated.count(host_old)} times")
p.write_text(updated.replace(host_old, host_new, 1))
PY
}

printf '\n== A6 same pid on one process ==\n'
cp "$A6" "$A6.r4bak"
plant_query_and_host SAME

set +e
output=$(cargo test --locked --offline \
  --manifest-path "$SUBJECT/lab/a6-a12-evidence-fix/Cargo.toml" \
  --lib tests::a6_resident_two_instances_is_blocked -- --exact --nocapture \
  tests::a6_resident_two_instances_is_blocked 2>&1)
status=$?
set -e
printf '%s\n' "$output" | tail -n 30
if printf '%s\n' "$output" | grep -q 'must not PASS until RA-6'; then
  printf 'HUNT a6-same-pid: SURVIVED PASS with two ids and one pid from this process\n'
elif printf '%s\n' "$output" | grep -qi 'two distinct live pids\|same pid\|must be BLOCKED, not FAIL\|pids must be two distinct'; then
  printf 'HUNT a6-same-pid: CAUGHT same pid from one process is FAIL, not PASS\n'
elif printf '%s\n' "$output" | grep -q 'test tests::a6_resident_two_instances_is_blocked ... ok'; then
  printf 'HUNT a6-same-pid: INCONCLUSIVE journey stayed BLOCKED cargo_exit=%s\n' "$status"
else
  printf 'HUNT a6-same-pid: INCONCLUSIVE cargo_exit=%s\n' "$status"
  printf '%s\n' "$output" | tail -n 20
fi
mv "$A6.r4bak" "$A6"

printf '\n== A6 two live pids that are not resident capsules ==\n'
cp "$A6" "$A6.r4bak"
plant_query_and_host 1

set +e
output=$(cargo test --locked --offline \
  --manifest-path "$SUBJECT/lab/a6-a12-evidence-fix/Cargo.toml" \
  --lib tests::a6_resident_two_instances_is_blocked -- --exact --nocapture \
  tests::a6_resident_two_instances_is_blocked 2>&1)
status=$?
set -e
printf '%s\n' "$output" | tail -n 40
if printf '%s\n' "$output" | grep -q 'must not PASS until RA-6'; then
  printf 'HUNT a6-reused-live-pids: SURVIVED PASS with this process pid plus pid 1 (not resident capsules)\n'
elif printf '%s\n' "$output" | grep -q 'must be BLOCKED, not FAIL'; then
  printf 'HUNT a6-reused-live-pids: CAUGHT fabricated live pids are FAIL, not PASS\n'
elif printf '%s\n' "$output" | grep -q 'test tests::a6_resident_two_instances_is_blocked ... ok'; then
  printf 'HUNT a6-reused-live-pids: INCONCLUSIVE journey stayed BLOCKED cargo_exit=%s\n' "$status"
else
  printf 'HUNT a6-reused-live-pids: INCONCLUSIVE cargo_exit=%s\n' "$status"
fi
mv "$A6.r4bak" "$A6"

if [ "$probe_status" -ne 0 ]; then
  exit "$probe_status"
fi
exit 0
