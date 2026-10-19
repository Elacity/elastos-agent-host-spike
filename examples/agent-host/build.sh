#!/usr/bin/env bash
set -euo pipefail

HOST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HOST_DIR}/../.." && pwd)"

"${REPO_ROOT}/scripts/build-component-capsule.sh" "${HOST_DIR}"
