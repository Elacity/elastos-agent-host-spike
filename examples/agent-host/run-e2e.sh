#!/usr/bin/env bash
# Run the agent-host guest end to end inside a test Runtime, in this process:
# the guest asks for its journal grants before the submit grant, and the tests
# exercise the journal and the planner's exact step through the real bridge.
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

preview_step="$proof_dir/preview-step.json"
export A15R_PREVIEW_STEP_PATH="$preview_step"
cargo test --locked --manifest-path "${HOST_DIR}/Cargo.toml" --lib \
  tests::a15r_june_plan_preview_and_submit_keep_the_document_step \
  -- --exact | tee "$proof_dir/preview.log"
grep -Eq 'test result: ok\. 1 passed; 0 failed;' "$proof_dir/preview.log"
test -s "$preview_step"
cargo test --locked -p elastos-server --lib --features prototype-agents \
  resource_bridge::tests::a15r_june_plan_stores_and_shows_the_document_step_bytes \
  -- --ignored --exact | tee "$proof_dir/joined.log"
grep -Eq 'test result: ok\. 1 passed; 0 failed;' "$proof_dir/joined.log"
