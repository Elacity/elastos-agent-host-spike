#!/bin/bash
# Build the pinned Runtime, start it, run the ignored A2 e2e tests, and
# record the journal journey. A skip is a fail.
set -eu
if [ "$#" -ne 0 ]; then
    printf 'usage: run.sh\n' >&2
    exit 2
fi
lane=$(cd -- "$(dirname -- "$0")" && pwd -P)
cd "$lane/../.."
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"
set +e
python3 -I "$lane/harness.py"
harness=$?
printf '\nFALSIFIER\n' | tee -a "$lane/evidence.txt" >/dev/null
python3 -I "$lane/falsify.py" F-A2-REVISION | tee -a "$lane/evidence.txt"
falsify=${PIPESTATUS[0]}
if [ "$harness" -ne 0 ] || [ "$falsify" -ne 0 ]; then
    exit 1
fi
exit 0
