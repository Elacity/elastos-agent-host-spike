#!/bin/sh
# Plant one bug in a scratch copy: the per-row guard ignores a missing
# required right and returns a confined start. The copy's tests must fail.
# A compile error is not a catch. This script does not change the repo.
set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

cp -a "$here/." "$scratch/crate"
cp "$root/rust-toolchain.toml" "$scratch/crate/rust-toolchain.toml"

python3 - "$scratch/crate/src/lib.rs" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
source = path.read_text()
old = """    let missing = missing_required(abi);
    if missing.is_empty() {
        Decision::RunConfined
    } else {
        Decision::Refuse {
            reason: format!("the Landlock ABI cannot express {}", join_names(&missing)),
        }
    }
"""
new = """    let missing = missing_required(abi);
    // Planted bug: ignore a missing required right and start anyway.
    let missing: Vec<&RequiredRight> = Vec::new();
    if missing.is_empty() {
        Decision::RunConfined
    } else {
        Decision::Refuse {
            reason: format!("the Landlock ABI cannot express {}", join_names(&missing)),
        }
    }
"""
if old not in source:
    raise SystemExit("plant anchor not found")
path.write_text(source.replace(old, new, 1))
PY

# Own build dir, and a cwd outside this repo. The repo's .cargo/config.toml
# sets a shared build-dir; a scratch build that lands there overwrites the
# real test binary.
log="$scratch/test.log"
set +e
(
    cd "$scratch/crate"
    CARGO_TARGET_DIR="$scratch/target" \
        cargo test --locked --manifest-path "$scratch/crate/Cargo.toml" \
        --test decisions -- --test-threads=2
) >"$log" 2>&1
status=$?
set -e

cat "$log"
if grep -q "could not compile" "$log"; then
    echo "NOT CAUGHT: the planted copy did not compile"
    exit 2
fi
if grep -q "test per_row_refuses_below_abi_5 ... FAILED" "$log" \
    && grep -q "test guards_and_per_row_never_start_with_a_missing_required_right ... FAILED" "$log"
then
    echo "CAUGHT: per_row_refuses_below_abi_5 and the silent-weaken check failed on the planted copy"
    exit 0
fi
echo "NOT CAUGHT: cargo status $status"
exit 1
