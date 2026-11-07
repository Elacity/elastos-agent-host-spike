#!/bin/bash
# Review gate. Reads the two reviewed trees. Writes only under /tmp and
# this folder's results.txt. Does not register binfmt_misc or qemu.
set -eu
lane=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
export FCL_SRC="${FCL_SRC:-/tmp/review-c0-307-src/fail-closed-linux/lab/fail-closed-linux}"
export JPK_SRC="${JPK_SRC:-/tmp/review-c0-307-src/jetson-proof-kit/lab/jetson-proof-kit}"
results="$lane/results.txt"
{
    printf 'FCL_SRC=%s\n' "$FCL_SRC"
    printf 'JPK_SRC=%s\n' "$JPK_SRC"
    printf 'host=%s %s\n' "$(uname -s)" "$(uname -rm)"
    python3 -I "$lane/check.py"
    python3 -I "$lane/test_review.py" -v
    python3 -I "$lane/falsify.py"
} 2>&1 | tee "$results"
# tee keeps the gate's exit from the last command only; re-run the
# summary line as the exit.
tail -n 1 "$results" | grep -q 'CAUGHT of 3'
