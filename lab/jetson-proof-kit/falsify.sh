#!/bin/bash
# Falsifiers for the Jetson proof kit.
# F-JPK-OUTSIDE: accept a planted path outside ~/flint-elastos-test.
# F-JPK-MEM: drop the MemAvailable check.
# F-JPK-ABI: report Landlock ABI 6 for every kernel.
# Each plant is applied to a copy. The named tests must fail on that copy.
# The working tree is left unchanged.
set -eu

kit=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

copy_kit() {
    local dest="$1"
    mkdir -p -- "$dest"
    cp -a -- "$kit/lib.sh" "$kit/run-on-jetson.sh" "$kit/probe_landlock.py" \
        "$kit/probe_host.py" "$kit/decide.py" "$kit/evidence.txt" \
        "$kit/tests" "$kit/fixtures" "$dest/"
}

run_guard_tests() {
    bash "$1/tests/test_guards.sh"
}

run_decision_tests() {
    bash "$1/tests/test_decisions.sh"
}

caught=0

# F-JPK-OUTSIDE: jpk_path_inside accepts every path, including one outside
# the folder.
copy_kit "$scratch/outside"
python3 - "$scratch/outside/lib.sh" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = "jpk_path_inside() {\n"
new = "jpk_path_inside() { return 0; }\njpk_path_inside_planted() {\n"
if old not in text:
    raise SystemExit("F-JPK-OUTSIDE: anchor missing")
path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_guard_tests "$scratch/outside" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL planted_path_outside_folder'; then
    printf 'F-JPK-OUTSIDE CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-JPK-OUTSIDE SURVIVED rc=%s\n' "$rc"
    exit 1
fi

# F-JPK-MEM: jpk_require_memory always succeeds, so a low MemAvailable is accepted.
copy_kit "$scratch/mem"
python3 - "$scratch/mem/lib.sh" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = "jpk_require_memory() {\n"
new = "jpk_require_memory() { return 0; }\njpk_require_memory_planted() {\n"
if old not in text:
    raise SystemExit("F-JPK-MEM: anchor missing")
path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_guard_tests "$scratch/mem" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL memory_below_floor_is_refused'; then
    printf 'F-JPK-MEM CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-JPK-MEM SURVIVED rc=%s\n' "$rc"
    exit 1
fi

# F-JPK-ABI: every kernel is reported as ABI 6, so a 5.15 / ABI 1
# fixture would launch under the single floor.
copy_kit "$scratch/abi"
python3 - "$scratch/abi/decide.py" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = "def landlock_abi_value(facts):\n    return token(facts, \"landlock_abi\")\n"
new = "def landlock_abi_value(facts):\n    return \"6\"\n"
if old not in text:
    raise SystemExit("F-JPK-ABI: anchor missing")
path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_decision_tests "$scratch/abi" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL abi1_did_abi5'; then
    printf 'F-JPK-ABI CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-JPK-ABI SURVIVED rc=%s\n' "$rc"
    exit 1
fi

printf 'summary %s CAUGHT of 3\n' "$caught"
[ "$caught" -eq 3 ]
