#!/usr/bin/env bash
# Provider binaries the process tests spawn.
#
# `just prepare-providers`, the test-elastos CI step, and `just ci-test-elastos`
# all run this file. The fence tests look at the debug paths below and do not
# run Cargo, so they do not download crates.
#
# Each build sets CARGO_TARGET_DIR and --target-dir to the same directory.
# A caller who exported CARGO_TARGET_DIR cannot move the binaries.
set -euo pipefail
cd "$(dirname "$0")/.."

build_release() {
  local manifest="$1"
  local target="$2"
  CARGO_TARGET_DIR="$target" \
    CARGO_BUILD_BUILD_DIR="$target/build" \
    cargo build --release --manifest-path "$manifest" --target-dir "$target"
}

build_release \
  capsules/protected-content-protect-provider/Cargo.toml \
  capsules/protected-content-protect-provider/target
build_release \
  capsules/protected-content-decrypt-provider/Cargo.toml \
  capsules/protected-content-decrypt-provider/target
build_release \
  capsules/custody-provider/Cargo.toml \
  capsules/custody-provider/target

# Debug helpers. line-tables-only matches the workspace dev profile.
# localhost is a workspace member and keeps its own target dir.
# object and chain share one target dir, so chain reuses object's crates.
export CARGO_PROFILE_DEV_DEBUG=line-tables-only

localhost="target/fence-localhost-provider"
CARGO_TARGET_DIR="$localhost" \
  CARGO_BUILD_BUILD_DIR="$localhost/build" \
  cargo build --locked \
    --manifest-path elastos/Cargo.toml \
    -p localhost-provider \
    --bin localhost-provider \
    --target-dir "$localhost"

helpers="target/provider-fence-tests"
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
