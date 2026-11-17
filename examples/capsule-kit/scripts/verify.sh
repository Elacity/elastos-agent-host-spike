#!/usr/bin/env bash
# Verify any capsule with its own verify.sh (kit item A3). Thin on purpose:
# the capsule owns its checks, this only refuses a folder that is not one.
#
# Usage: verify.sh <capsule-dir>
set -euo pipefail

CAPSULE="${1:?usage: verify.sh <capsule-dir>}"

if [[ ! -f "${CAPSULE}/capsule.json" ]]; then
    echo "verify.sh: ${CAPSULE} has no capsule.json, so it is not a capsule folder" >&2
    exit 1
fi
if [[ ! -x "${CAPSULE}/verify.sh" ]]; then
    echo "verify.sh: ${CAPSULE} has no verify.sh to run" >&2
    exit 1
fi
exec "${CAPSULE}/verify.sh"
