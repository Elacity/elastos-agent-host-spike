#!/bin/bash
# Falsifiers for the Jetson proof kit.
# F-JPK-OUTSIDE: accept a planted path outside ~/flint-elastos-test.
# F-JPK-MEM: drop the MemAvailable check.
# F-JPK-ABI: report Landlock ABI 6 for every kernel.
# F-JPK-CAP: treat CAP_SYS_ADMIN (bit 21) as CAP_SETPCAP.
# F-JPK-REASON: print the old kit reason instead of #307's text.
# F-JPK-LIE: decide per_right from measured rights, so a lying ABI 5 refuses.
# F-JPK-ABSENT: stamp an absent right as PASS.
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
        "$kit/probe_host.py" "$kit/decide.py" "$kit/standin.rs" \
        "$kit/evidence.txt" "$kit/tests" "$kit/fixtures" "$dest/"
}

run_guard_tests() {
    bash "$1/tests/test_guards.sh"
}

run_decision_tests() {
    bash "$1/tests/test_decisions.sh"
}

caught=0
expected=7

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

# F-JPK-CAP: bit 21 is treated as CAP_SETPCAP.
copy_kit "$scratch/cap"
python3 - "$scratch/cap/probe_host.py" "$scratch/cap/decide.py" <<'PY'
from pathlib import Path
import sys
for name in sys.argv[1:]:
    path = Path(name)
    text = path.read_text()
    old = "CAP_SETPCAP = 8"
    new = "CAP_SETPCAP = 21"
    if old not in text:
        raise SystemExit(f"F-JPK-CAP: anchor missing in {path}")
    path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_decision_tests "$scratch/cap" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL cap_setpcap_probe_bit'; then
    printf 'F-JPK-CAP CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-JPK-CAP SURVIVED rc=%s\n' "$rc"
    exit 1
fi

# F-JPK-REASON: drop #307's exact missing-right text.
copy_kit "$scratch/reason"
python3 - "$scratch/reason/decide.py" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = '    return "this kernel\'s Landlock ABI {} cannot deny {}".format(\n        abi, "; ".join(names)\n    )\n'
new = '    return "missing TRUNCATE, IOCTL_DEV"\n'
if old not in text:
    raise SystemExit("F-JPK-REASON: anchor missing")
path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_decision_tests "$scratch/reason" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL abi1_did_per_right_reason'; then
    printf 'F-JPK-REASON CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-JPK-REASON SURVIVED rc=%s\n' "$rc"
    exit 1
fi

# F-JPK-LIE: per_right uses measured rights, so a lying ABI 5 refuses.
copy_kit "$scratch/lie"
python3 - "$scratch/lie/decide.py" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = """    abi = landlock_abi_value(facts)
    if not abi.isdigit():
        landlock = [_landlock_absent_reason()]
    else:
        found = int(abi)
        mask = missing_required_mask(found)
        if mask is not None:
            landlock = [missing_rights_reason(found, mask)]
        else:
            landlock = []
"""
new = """    abi = landlock_abi_value(facts)
    if not abi.isdigit():
        landlock = [_landlock_absent_reason()]
    else:
        measured = _measured_missing(facts)
        if measured:
            landlock = ["missing " + ", ".join(name.upper() for name in measured)]
        else:
            landlock = []
"""
if old not in text:
    raise SystemExit("F-JPK-LIE: anchor missing")
path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_decision_tests "$scratch/lie" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL lie_did_per_right'; then
    printf 'F-JPK-LIE CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-JPK-LIE SURVIVED rc=%s\n' "$rc"
    exit 1
fi

# F-JPK-ABSENT: every measurement is stamped PASS, including absent rights.
copy_kit "$scratch/absent"
python3 - "$scratch/absent/lib.sh" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = "jpk_availability_status() {\n"
new = 'jpk_availability_status() { printf "PASS\\n"; }\njpk_availability_status_planted() {\n'
if old not in text:
    raise SystemExit("F-JPK-ABSENT: anchor missing")
path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_decision_tests "$scratch/absent" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL recorded_truncate_absent'; then
    printf 'F-JPK-ABSENT CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-JPK-ABSENT SURVIVED rc=%s\n' "$rc"
    exit 1
fi

printf 'summary %s CAUGHT of %s\n' "$caught" "$expected"
[ "$caught" -eq "$expected" ]
