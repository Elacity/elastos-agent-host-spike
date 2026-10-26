#!/usr/bin/env bash
# Repeated lab runs plus a planted falsifier. Restores every edit.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
MANIFEST="$ROOT/lab/runtime-asks/grant-error-swallow/Cargo.toml"
LIB="$ROOT/lab/runtime-asks/grant-error-swallow/src/lib.rs"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/workspace/target-lab-grant-error}"
RUNS="${RUNS:-20}"

cd "$ROOT"

echo "machine: $(uname -s) $(uname -m) $(uname -r)"
echo "rustc: $(rustc --version)"
echo "head: $(git rev-parse HEAD)"
echo "guest: $(git hash-object examples/agent-host/src/lib.rs)"
echo "compute: $(git hash-object elastos/crates/elastos-compute/src/providers/component.rs)"

pass=0
for i in $(seq 1 "$RUNS"); do
  echo "=== run $i / $RUNS ==="
  cargo test --locked --manifest-path "$MANIFEST"
  pass=$((pass + 1))
done
echo "lab suite: $pass of $RUNS"

echo "=== unpatched trial property (shipped_mapping_fails_the_trial_property) ==="
cargo test --locked --manifest-path "$MANIFEST" shipped_mapping_fails_the_trial_property -- --nocapture --exact

echo "=== planted falsifier SWALLOW_INTERNAL=true ==="
python3 - <<'PY'
from pathlib import Path
path = Path("lab/runtime-asks/grant-error-swallow/src/lib.rs")
text = path.read_text()
old = "pub const SWALLOW_INTERNAL: bool = false;"
new = "pub const SWALLOW_INTERNAL: bool = true;"
if text.count(old) != 1:
    raise SystemExit(f"plant anchor missing: {old!r}")
path.write_text(text.replace(old, new, 1))
PY
set +e
cargo test --locked --manifest-path "$MANIFEST" trial_propagates_internal_and_keeps_deny -- --nocapture --exact
plant=$?
set -e
python3 - <<'PY'
from pathlib import Path
path = Path("lab/runtime-asks/grant-error-swallow/src/lib.rs")
text = path.read_text()
path.write_text(text.replace(
    "pub const SWALLOW_INTERNAL: bool = true;",
    "pub const SWALLOW_INTERNAL: bool = false;",
    1,
))
PY
if [[ "$plant" -eq 0 ]]; then
  echo "falsifier: SURVIVED (trial still passed with SWALLOW_INTERNAL=true)"
  exit 1
fi
echo "falsifier: CAUGHT (trial_propagates_internal_and_keeps_deny failed, constant restored)"

echo "=== restore check ==="
git diff --exit-code -- lab/runtime-asks/grant-error-swallow/src/lib.rs
git apply --check lab/runtime-asks/grant-error-swallow/trial.patch
echo "done: lab $pass/$RUNS, falsifier CAUGHT, trial.patch checks clean"
