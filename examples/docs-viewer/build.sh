#!/usr/bin/env bash
set -euo pipefail

VIEWER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${VIEWER_DIR}/../.." && pwd)"

# The docs-model renderer has one owner in the capsule kit. A page ships a
# copy in its own browser/ folder (script-src 'self'); the surface test pins
# that copy to the owner's bytes, so this copy is never edited by hand.
cp "${REPO_ROOT}/examples/capsule-kit/surface/docs-render.js" \
   "${VIEWER_DIR}/surface/browser/docs-render.js"

"${REPO_ROOT}/scripts/build-component-capsule.sh" "${VIEWER_DIR}"
