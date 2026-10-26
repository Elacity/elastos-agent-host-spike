#!/bin/bash
# Run the A2 resume journey through the real bridge and a real process
# restart. Every row is derived from output. A skip is not a pass.
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
printf '\nFALSIFIER\n'
python3 -I "$lane/falsify.py"
falsify=$?
if [ "$harness" -ne 0 ] || [ "$falsify" -ne 0 ]; then
    exit 1
fi
exit 0
