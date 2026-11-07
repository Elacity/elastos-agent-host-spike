#!/usr/bin/env bash
# Run the agent-host guest end to end inside a test Runtime, in this process:
# the guest asks for its two journal grants, the test grants or denies them,
# and the guest writes and reads its journal through the real resource bridge.
# Does not start `elastos serve` and does not open the Home data directory.
set -euo pipefail

HOST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HOST_DIR}/../.." && pwd)"

"${HOST_DIR}/build.sh"
cd "${REPO_ROOT}/elastos"
cargo test -p elastos-server --lib runtime::tests::the_agent_host_ -- --ignored
