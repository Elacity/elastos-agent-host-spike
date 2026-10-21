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
cargo build --locked --release --target wasm32-unknown-unknown -p bus2-photo-guest -p bus2-resident-guest -p bus2-busy-guest

echo "== fmt and clippy"
cargo fmt --all -- --check
cargo clippy --locked -p bus2-host --all-targets -- -D warnings
cargo clippy --locked --release --target wasm32-unknown-unknown -p bus2-photo-guest -p bus2-resident-guest -p bus2-busy-guest -- -D warnings

echo "== tests"
cargo test --locked --no-fail-fast -p bus2-host

echo "== falsifiers"
python3 -I falsify.py

echo "verify: ok"
