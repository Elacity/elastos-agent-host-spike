#!/usr/bin/env bash
# Build any capsule with the one build it already has (kit item A3). This adds
# no build logic: it refuses a folder without capsule.json by name, then hands
# the folder to that capsule's own build, or to the repository builder.
#
# Usage: build.sh <capsule-dir>
set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${KIT_DIR}/../.." && pwd)"
CAPSULE="${1:?usage: build.sh <capsule-dir>}"

if [[ ! -f "${CAPSULE}/capsule.json" ]]; then
    echo "build.sh: ${CAPSULE} has no capsule.json, so it is not a capsule folder" >&2
    exit 1
fi
CAPSULE="$(cd "${CAPSULE}" && pwd)"

# The capsule's own build first: it may copy a kit owner or set a pin, and it
# calls the repository builder itself.
if [[ -x "${CAPSULE}/build.sh" ]]; then
    exec "${CAPSULE}/build.sh"
fi
if [[ -x "${CAPSULE}/repro/build-in-container.sh" ]]; then
    exec "${CAPSULE}/repro/build-in-container.sh"
fi
exec "${REPO_ROOT}/scripts/build-component-capsule.sh" "${CAPSULE}"
