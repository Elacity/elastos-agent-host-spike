#!/usr/bin/env bash
# Start the release musl localhost, object, and chain helpers under the real
# path-allow fence. Run this after scripts/check-release-musl.sh on the same
# target. The step fails when a helper cannot be started.
set -euo pipefail

target="${1:?usage: musl-helper-fence.sh <target>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"

build_one() {
  local manifest_dir="$1"
  local package="$2"
  local name="$3"
  local base="${CARGO_TARGET_DIR:-$manifest_dir/target}"
  (
    cd "$manifest_dir"
    cargo build --locked --release --target "$target" -p "$package" --bin "$name"
  ) >&2
  echo "$base/$target/release/$name"
}

localhost="$(build_one "$root/elastos" localhost-provider localhost-provider)"
object="$(build_one "$root/capsules/object-provider" object-provider object-provider)"
chain="$(build_one "$root/capsules/chain-provider" chain-provider chain-provider)"

for binary in "$localhost" "$object" "$chain"; do
  if [ ! -f "$binary" ]; then
    echo "musl helper fence: missing $binary" >&2
    exit 1
  fi
done

log="$(mktemp)"
set +e
(
  cd "$root/elastos"
  export ELASTOS_MUSL_HELPER_FENCE=1 ELASTOS_MUSL_LOCALHOST="$localhost"
  export ELASTOS_MUSL_OBJECT="$object" ELASTOS_MUSL_CHAIN="$chain"
  cargo test --locked -p elastos-server --lib -- --exact --nocapture confine_helper_tests::musl_release_helpers_start_under_the_fence
) >"$log" 2>&1
status=$?
set -e
cat "$log"
if [ "$status" -ne 0 ]; then
  exit "$status"
fi
grep -q "musl helper fence: started" "$log"
