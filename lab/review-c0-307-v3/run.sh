#!/bin/bash
# Review gate. Reads the reviewed crate. Writes only under /tmp and
# this folder's results.txt. Does not edit lab/fail-closed-linux/.
set -eu
lane=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
export FCL_SRC="${FCL_SRC:-/tmp/review-c0-307-v3-src/lab/fail-closed-linux}"
results="$lane/results.txt"
{
    printf 'FCL_SRC=%s\n' "$FCL_SRC"
    printf 'head=%s\n' "$(git -C "$FCL_SRC/../.." rev-parse HEAD 2>/dev/null || echo unknown)"
    printf 'host=%s %s\n' "$(uname -s)" "$(uname -rm)"
    python3 -I "$lane/test_ioctl_dev_is_landlock.py" && echo 'ioctl test: PASS (unexpected on 1894f432)' || echo "ioctl test: FAIL (exit $?)"
} 2>&1 | tee "$results"
# The ioctl test is the finding. A FAIL is the expected result on this head.
tail -n 20 "$results" | grep -q 'FAIL: confined ioctl_dev'
