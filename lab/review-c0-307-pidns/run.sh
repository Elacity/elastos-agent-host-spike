#!/bin/sh
# Review checks. They read FCL_SRC (default: the 637345ac extract).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
LANE="$ROOT/lab/review-c0-307-pidns"
export FCL_SRC="${FCL_SRC:-/tmp/fcl-637345ac/lab/fail-closed-linux}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.91.0}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$LANE/target}"
export CARGO_BUILD_BUILD_DIR="${CARGO_BUILD_BUILD_DIR:-$LANE/build}"

cd "$LANE"
cargo fmt -- --check
cargo test --locked
python3 attack_pidns.py
python3 check.py
python3 falsify.py
python3 -m unittest -v tests/test_review.py
