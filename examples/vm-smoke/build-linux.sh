#!/bin/sh
# Build the aarch64 Linux test program the small machine runs.
# On a Mac the system linker cannot link musl, so use Rust's bundled lld.
set -eu
cd "$(dirname "$0")"
if [ "$(uname -s)" = "Darwin" ]; then
  sysroot="$(rustc --print sysroot)"
  host="$(rustc -vV | awk '/^host:/ { print $2 }')"
  linker="${sysroot}/lib/rustlib/${host}/bin/gcc-ld/ld.lld"
  export RUSTFLAGS="-C linker=${linker} ${RUSTFLAGS:-}"
fi
cargo test --target aarch64-unknown-linux-musl --release --no-run
