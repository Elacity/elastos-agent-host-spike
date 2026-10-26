#!/bin/bash
# Run the #320 v2 review against the read-only kit and #307 trees.
set -eu

review=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
JPK_SRC=${JPK_SRC:-/tmp/jpk-320/lab/jetson-proof-kit}
FCL_SRC=${FCL_SRC:-/tmp/c0-307/lab/fail-closed-linux}

printf 'JPK_SRC=%s\n' "$JPK_SRC"
printf 'FCL_SRC=%s\n' "$FCL_SRC"

printf '\n== kit test_guards.sh ==\n'
bash "$JPK_SRC/tests/test_guards.sh"

printf '\n== kit test_decisions.sh ==\n'
bash "$JPK_SRC/tests/test_decisions.sh"

printf '\n== kit falsify.sh ==\n'
bash "$JPK_SRC/falsify.sh"

printf '\n== review check.py ==\n'
JPK_SRC="$JPK_SRC" FCL_SRC="$FCL_SRC" python3 -I "$review/check.py"

printf '\n== review falsify.sh ==\n'
JPK_SRC="$JPK_SRC" FCL_SRC="$FCL_SRC" bash "$review/falsify.sh"
