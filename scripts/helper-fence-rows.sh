#!/usr/bin/env bash
# Helper fence rows for the source-home jobs.
#
# The debug binaries are the ones those rows spawn. Each build sets
# its own target directory, so this file does not create the job's Cargo
# target directory. The freshness step requires that path to be absent.
# macOS runs the sandbox-exec rows. Linux runs the /proc rows. A zero match
# on the other list would fail the job, so each operating system runs only
# its own names. The shared rows run on both.
set -euo pipefail

root="${GITHUB_WORKSPACE:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$root" || exit 1

localhost="${root}/target/fence-localhost-provider"
helpers="${root}/target/provider-fence-tests"

CARGO_TARGET_DIR="$localhost" \
  CARGO_BUILD_BUILD_DIR="$localhost/build" \
  cargo build --locked \
    --manifest-path elastos/Cargo.toml \
    -p localhost-provider \
    --bin localhost-provider \
    --target-dir "$localhost"
CARGO_TARGET_DIR="$helpers" \
  CARGO_BUILD_BUILD_DIR="$helpers/build" \
  cargo build --locked \
    --manifest-path capsules/object-provider/Cargo.toml \
    --bin object-provider \
    --target-dir "$helpers"
CARGO_TARGET_DIR="$helpers" \
  CARGO_BUILD_BUILD_DIR="$helpers/build" \
  cargo build --locked \
    --manifest-path capsules/chain-provider/Cargo.toml \
    --bin chain-provider \
    --target-dir "$helpers"
CARGO_TARGET_DIR="$helpers" \
  CARGO_BUILD_BUILD_DIR="$helpers/build" \
  cargo build --locked \
    --manifest-path capsules/custody-provider/Cargo.toml \
    --bin custody-provider \
    --target-dir "$helpers"

# One invocation in elastos/. The subcommand is an argument so the build
# and the rows share the localhost target directory.
run_row() {
  local log="$1"
  shift
  (
    cd elastos || exit 1
    CARGO_TARGET_DIR="$localhost" \
      CARGO_BUILD_BUILD_DIR="$localhost/build" \
      cargo "$@"
  ) | tee "$log"
}

require_summary() {
  local log="$1"
  local pattern="$2"
  local message="$3"
  grep -Eq -- "$pattern" "$log" || {
    echo "::error::${message}"
    exit 1
  }
}

log="${RUNNER_TEMP}/helper-fence-confine.log"
run_row "$log" test --locked -p elastos-server --lib confine_helper_tests -- --test-threads=2
require_summary "$log" '^test result: ok\. [1-9][0-9]* passed; 0 failed;' \
  "confine_helper_tests selected no test or failed"

case "$(uname -s)" in
  Darwin)
    names=(
      provider::os_entry::tests::a_root_swapped_between_render_and_sandbox_exec_is_refused_and_starts_nothing
      provider::os_entry::tests::a_symlink_subpath_resolves_outside_and_the_device_key_stays_unread
      provider::os_entry::tests::localhost_object_and_chain_cannot_open_device_key
      provider::os_entry::tests::chain_provider_binary_answers_inside_its_fence
      provider::os_entry::tests::custody_provider_binary_answers_inside_its_fence
      provider::os_entry::tests::custody_provider_cannot_leave_its_root
      provider::os_entry::tests::a_custody_root_swapped_between_render_and_sandbox_exec_is_refused_and_starts_nothing
      provider::landlock_plan::tests::both_builders_use_the_resolved_loader_not_the_static_list
      provider::root_pin::tests::a_loader_swapped_to_another_file_or_a_directory_is_refused
    )
    ;;
  Linux)
    names=(
      provider::os_entry::tests::localhost_object_and_chain_cannot_open_device_key
      provider::os_entry::tests::chain_provider_binary_answers_inside_its_fence
      provider::os_entry::tests::custody_provider_binary_answers_inside_its_fence
      provider::os_entry::tests::custody_provider_cannot_leave_its_root
      provider::landlock_plan::tests::both_builders_use_the_resolved_loader_not_the_static_list
      provider::root_pin::tests::a_loader_swapped_to_another_file_or_a_directory_is_refused
      provider::os_entry::failure_record::tests::an_unconfined_child_is_refused_by_name_and_killed
      provider::os_entry::failure_record::tests::an_add_refusal_names_the_rule_and_its_path
      provider::os_entry::failure_record::tests::installer_failure_crosses_pipe_and_child_is_reaped
      provider::os_entry::failure_record::tests::swapped_storage_root_refuses_and_leaves_the_canary
    )
    ;;
  *)
    echo "::error::helper fence rows have no list for $(uname -s)" >&2
    exit 1
    ;;
esac

for name in "${names[@]}"; do
  log="${RUNNER_TEMP}/helper-fence-${name//:/_}.log"
  run_row "$log" test --locked -p elastos-runtime --lib "$name" -- --exact --test-threads=2
  require_summary "$log" '^test result: ok\. 1 passed; 0 failed;' \
    "${name} selected no test or failed"
done
