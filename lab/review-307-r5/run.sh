#!/bin/bash
# Live hunts then F36/F37 replant. Does not edit the #307 worktree.
set -eu
lane=$(cd -- "$(dirname -- "$0")" && pwd -P)
export FCL_SRC="${FCL_SRC:-/tmp/wt-307-r5/candidate/lab/fail-closed-linux}"
python3 "$lane/attack.py"
python3 "$lane/replant.py"
