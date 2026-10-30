#!/bin/bash
# Build stand-ins and run the r4 hunts plus the independent F33-F35 replant.
# Official suite and falsify.py are started separately against FCL_SRC.
set -eu
lane=$(cd -- "$(dirname -- "$0")" && pwd -P)
cd "$lane"
export FCL_SRC="${FCL_SRC:-/tmp/review-c0-307-r4-src/lab/fail-closed-linux}"
export FCL_LAUNCH="${FCL_LAUNCH:-$FCL_SRC/target/debug/fcl-launch}"
python3 attack.py
python3 replant.py
