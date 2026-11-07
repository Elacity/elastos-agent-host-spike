#!/bin/bash
# Host hunts against the built fcl-launch. Does not edit the #307 tree.
set -eu
lane=$(cd -- "$(dirname "$0")" && pwd -P)
export FCL_SRC="${FCL_SRC:-/workspace/lab/fail-closed-linux}"
python3 "$lane/attack.py"
