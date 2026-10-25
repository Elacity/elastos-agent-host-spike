#!/usr/bin/env bash
# Run the agent-host guest inside the Runtime's Wasmtime, in this process.
# Does not start `elastos serve` and does not open ~/Library/Application Support/elastos.
set -euo pipefail

HOST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HOST_DIR}/../.." && pwd)"

"${HOST_DIR}/build.sh"
# The test-only HTTP client and its single skip-guard run with no model set.
(unset SPARKS_MODEL_URL
 cargo test --locked --manifest-path "${HOST_DIR}/Cargo.toml" sparks_http::)
cd "${REPO_ROOT}/elastos"
cargo test -p elastos-compute --lib agent_host_example_keeps_the_head_across_a_compaction -- --ignored
