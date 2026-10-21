#!/usr/bin/env bash
# Every test and falsifier of the Bus v2 guest-side proof, in one command.
# Uses this folder's rust-toolchain.toml (Rust 1.95.0) and Cargo.lock.
set -euo pipefail
cd "$(dirname "$0")"
export RUST_TEST_THREADS=2

echo "== toolchain"
rustc --version
cargo --version

echo "== guests (wasm32-unknown-unknown, release)"
# The tests read the guests from here. Delete them first, so a stale or
# missing guest can never be tested silently.
GUEST_DIR=target/wasm32-unknown-unknown/release
GUEST_FILES="bus2_photo_guest bus2_resident_guest bus2_busy_guest bus2_start_loop_guest"
for guest in $GUEST_FILES; do
  rm -f "$GUEST_DIR/$guest.wasm"
done
cargo build --locked --release --target wasm32-unknown-unknown -p bus2-photo-guest -p bus2-resident-guest -p bus2-busy-guest -p bus2-start-loop-guest
for guest in $GUEST_FILES; do
  if [ ! -f "$GUEST_DIR/$guest.wasm" ]; then
    echo "verify: FAILED: the build did not produce $GUEST_DIR/$guest.wasm" >&2
    exit 1
  fi
done

echo "== fmt and clippy"
cargo fmt --all -- --check
cargo clippy --locked -p bus2-host --all-targets -- -D warnings
cargo clippy --locked --release --target wasm32-unknown-unknown -p bus2-photo-guest -p bus2-resident-guest -p bus2-busy-guest -p bus2-start-loop-guest -- -D warnings

echo "== tests"
cargo test --locked --no-fail-fast -p bus2-host

echo "== falsifiers"
python3 -I falsify.py

echo "verify: ok"
