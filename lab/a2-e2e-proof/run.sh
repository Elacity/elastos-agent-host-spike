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
python3 -I "$lane/harness.py"
