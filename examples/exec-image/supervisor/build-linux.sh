#!/bin/sh
# Build the static aarch64 Linux supervisor the exec image runs as root.
# On a Mac the system linker cannot link musl, so use Rust's bundled lld
# (the same way examples/vm-smoke/build-linux.sh does).
set -eu
cd "$(dirname "$0")"
if [ "$(uname -s)" = "Darwin" ]; then
  sysroot="$(rustc --print sysroot)"
  host="$(rustc -vV | awk '/^host:/ { print $2 }')"
  linker="${sysroot}/lib/rustlib/${host}/bin/gcc-ld/ld.lld"
  export RUSTFLAGS="-C linker=${linker} ${RUSTFLAGS:-}"
fi
cargo build --locked --release --target aarch64-unknown-linux-musl
echo "$(pwd)/target/aarch64-unknown-linux-musl/release/exec-supervisor"
