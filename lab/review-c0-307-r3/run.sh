#!/bin/bash
# Review gate for lab/review-c0-307-r3. Does not edit or push #307.
set -eu
lane=$(cd -- "$(dirname -- "$0")" && pwd -P)
src=${FCL_SRC:-/tmp/review-c0-307-r3-src/lab/fail-closed-linux}
export FCL_LAUNCH=${FCL_LAUNCH:-$src/target/debug/fcl-launch}
export FCL_PROBE=${FCL_PROBE:-$src/target/build/debug/build/fail-closed-linux-1d11d7b03d991c2d/out/fcl-probe}
export STANDIN_DIR=$lane/standins
mkdir -p "$lane/evidence" "$lane/standins"
for name in ignore_sigterm double_fork_setsid inherit_ioctl sleep_forever print_pdeathsig; do
  gcc -static -O2 -o "$STANDIN_DIR/$name.bin" "$lane/standins/$name.c"
done
python3 -u "$lane/attack.py"
python3 -u "$lane/rebreak.py"
