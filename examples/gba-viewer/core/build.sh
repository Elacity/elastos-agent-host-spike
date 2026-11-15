#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${CORE_DIR}/../../.." && pwd)"

"${REPO_ROOT}/scripts/build-component-capsule.sh" "${CORE_DIR}"
