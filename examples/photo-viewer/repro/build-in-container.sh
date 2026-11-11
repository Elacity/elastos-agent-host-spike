#!/usr/bin/env bash
# Build photo-viewer.component.wasm in the capsule kit's pinned Linux container
# (examples/capsule-kit/repro). See README.md here for the expected hash.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
exec "${REPO_ROOT}/examples/capsule-kit/repro/build-in-container.sh" examples/photo-viewer
