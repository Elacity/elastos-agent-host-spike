#!/bin/bash
# Review falsifiers for #320 v2. Each plant is applied to a copy under /tmp.
# The #320 worktree is left unchanged.
#
# F-RV-ORACLE: drop the "not the guard" label.
# F-RV-PIN: restore the old ABI 5 default pin.
# F-RV-REASON: print the old kit reason instead of #307's text.
# F-RV-LIE: decide per_right from measured rights.
# F-RV-ENOEXEC: stamp Exec format error as REFUSED.
# F-RV-JOBS: raise cargo jobs to 8.
# F-RV-PC2: name pc2.net in the operator script.
set -eu

review=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
JPK_SRC=${JPK_SRC:-/tmp/jpk-320/lab/jetson-proof-kit}
FCL_SRC=${FCL_SRC:-/tmp/c0-307/lab/fail-closed-linux}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

copy_kit() {
    local dest="$1"
    mkdir -p -- "$dest"
    cp -a -- "$JPK_SRC/." "$dest/"
}

run_check() {
    JPK_SRC="$1" FCL_SRC="$FCL_SRC" python3 -I "$review/check.py"
}

caught=0
expected=7

# F-RV-ORACLE
copy_kit "$scratch/oracle"
python3 - "$scratch/oracle/decide.py" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = "This file is not the guard."
if old not in text:
    raise SystemExit("F-RV-ORACLE: anchor missing")
path.write_text(text.replace(old, "This file is the live guard.", 1))
PY
set +e
out=$(run_check "$scratch/oracle" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL jpk1_labeled_oracle'; then
    printf 'F-RV-ORACLE CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-RV-ORACLE SURVIVED rc=%s\n' "$rc"
    exit 1
fi

# F-RV-PIN
copy_kit "$scratch/pin"
python3 - "$scratch/pin/lib.sh" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = "JPK_C0_PER_RIGHT_SHA=2c70a0d845f9acc15144a2afec889370612cca66"
new = "JPK_C0_PER_RIGHT_SHA=129fdc98428c9029b328976511478c46ebe765a6"
if old not in text:
    raise SystemExit("F-RV-PIN: anchor missing")
path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_check "$scratch/pin" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL jpk2_default_pin'; then
    printf 'F-RV-PIN CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-RV-PIN SURVIVED rc=%s\n' "$rc"
    exit 1
fi

# F-RV-REASON
copy_kit "$scratch/reason"
python3 - "$scratch/reason/decide.py" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = '    return "this kernel\'s Landlock ABI {} cannot deny {}".format(\n        abi, "; ".join(names)\n    )\n'
new = '    return "missing TRUNCATE, IOCTL_DEV"\n'
if old not in text:
    raise SystemExit("F-RV-REASON: anchor missing")
path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_check "$scratch/reason" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL jpk3_reason_abi1'; then
    printf 'F-RV-REASON CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-RV-REASON SURVIVED rc=%s\n' "$rc"
    exit 1
fi

# F-RV-LIE
copy_kit "$scratch/lie"
python3 - "$scratch/lie/decide.py" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = """        found = int(abi)
        mask = missing_required_mask(found)
        if mask is not None:
            landlock = [missing_rights_reason(found, mask)]
        else:
            landlock = []
"""
new = """        measured = _measured_missing(facts)
        if measured:
            landlock = ["missing " + ", ".join(name.upper() for name in measured)]
        else:
            landlock = []
"""
if old not in text:
    raise SystemExit("F-RV-LIE: anchor missing")
path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_check "$scratch/lie" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL jpk4_lie_launches'; then
    printf 'F-RV-LIE CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-RV-LIE SURVIVED rc=%s\n' "$rc"
    exit 1
fi

# F-RV-ENOEXEC
copy_kit "$scratch/enoexec"
python3 - "$scratch/enoexec/lib.sh" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = '        *"Exec format error"* | *"os error 8"*)\n            printf \'NOT RUN\\n\'\n            ;;'
new = '        *"Exec format error"* | *"os error 8"*)\n            printf \'REFUSED\\n\'\n            ;;'
if old not in text:
    raise SystemExit("F-RV-ENOEXEC: anchor missing")
path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_check "$scratch/enoexec" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL jpk6_classify_exec_format'; then
    printf 'F-RV-ENOEXEC CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-RV-ENOEXEC SURVIVED rc=%s\n' "$rc"
    exit 1
fi

# F-RV-JOBS
copy_kit "$scratch/jobs"
python3 - "$scratch/jobs/lib.sh" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = "JPK_BUILD_JOBS=4"
new = "JPK_BUILD_JOBS=8"
if old not in text:
    raise SystemExit("F-RV-JOBS: anchor missing")
path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_check "$scratch/jobs" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL safety_jobs_4'; then
    printf 'F-RV-JOBS CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-RV-JOBS SURVIVED rc=%s\n' "$rc"
    exit 1
fi

# F-RV-PC2
copy_kit "$scratch/pc2"
python3 - "$scratch/pc2/run-on-jetson.sh" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = "# One operator script for the Jetson Orin Nano."
new = "# One operator script for the Jetson Orin Nano. Do not touch pc2.net."
if old not in text:
    raise SystemExit("F-RV-PC2: anchor missing")
path.write_text(text.replace(old, new, 1))
PY
set +e
out=$(run_check "$scratch/pc2" 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'FAIL safety_no_pc2_net'; then
    printf 'F-RV-PC2 CAUGHT\n'
    caught=$((caught + 1))
else
    printf 'F-RV-PC2 SURVIVED rc=%s\n' "$rc"
    exit 1
fi

printf 'summary %s CAUGHT of %s\n' "$caught" "$expected"
[ "$caught" -eq "$expected" ]
