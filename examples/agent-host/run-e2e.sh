#!/usr/bin/env bash
# Run the agent-host guest end to end inside a test Runtime, in this process:
# the stored Agent guest asks for its journal grants, then one joined test
# carries the planner's exact step through owner approval and settlement.
# Does not start `elastos serve` and does not open the Home data directory.
set -euo pipefail

HOST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HOST_DIR}/../.." && pwd)"

"${HOST_DIR}/build.sh"
cd "${REPO_ROOT}/elastos"
proof_dir="$(mktemp -d "${TMPDIR:-/tmp}/a15r-e2e.XXXXXX")"
trap 'rm -rf "$proof_dir"' EXIT
cargo test --locked -p elastos-server --lib --features prototype-agents \
  runtime::tests::the_agent_host_ -- --ignored | tee "$proof_dir/guest.log"
grep -Eq 'test result: ok\. 3 passed; 0 failed;' "$proof_dir/guest.log"

cargo test --locked -p elastos-server --lib --features prototype-agents \
  api::gateway::gateway_tests::agent_plan::a15r_real_journey_one_step_one_result \
  -- --exact | tee "$proof_dir/joined.log"
grep -Eq 'test result: ok\. 1 passed; 0 failed;' "$proof_dir/joined.log"
