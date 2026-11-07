#!/usr/bin/env bash
set -euo pipefail

VIEWER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${VIEWER_DIR}/../.." && pwd)"

# The docs-model renderer and launch client each have one owner in the kit.
# A page ships copies in its own browser/ folder (script-src 'self'); the
# surface tests pin each copy to its owner's bytes. Edit the owners.
cp "${REPO_ROOT}/examples/capsule-kit/surface/docs-render.js" \
   "${VIEWER_DIR}/surface/browser/docs-render.js"
cp "${REPO_ROOT}/examples/capsule-kit/surface/page-client.js" \
   "${VIEWER_DIR}/surface/browser/page-client.js"

"${REPO_ROOT}/scripts/build-component-capsule.sh" "${VIEWER_DIR}"
