# Reproducible build of photo-viewer.component.wasm

One pinned Linux container, so a Mac, a cloud session and CI produce the same
bytes for the same commit.

```bash
examples/photo-viewer/repro/build-in-container.sh
```

It needs Docker, and nothing else on the host. The recipe itself is the capsule kit's
(`examples/capsule-kit/repro/build-in-container.sh`, shared with the documents viewer); this script runs it for
this folder. The last line is the sha256
and the artifact, written to `examples/photo-viewer/photo-viewer.component.wasm`.

## What is pinned

| Input | Pin |
| --- | --- |
| Image | `rust:1.91.0-slim-bookworm@sha256:81c97592d519ba7397e8adccb0345fb5a91965c0a44b82af83bd1ef06c36cef5` |
| Platform | `linux/amd64`, also on Apple Silicon (Docker runs it emulated) |
| Toolchain | Rust 1.91.0 (image and `rust-toolchain.toml`), target `wasm32-unknown-unknown` |
| Crates | `Cargo.lock` of the guest and of `elastos/tools/componentize`, built `--locked` |
| Paths | Repository mounted at `/src/elastos-runtime`, the path the builder remaps to; `HOME=/home/builder` |
| `python3` | `3.11.2-1+b1` from `snapshot.debian.org/archive/debian/20261015T000000Z` (bookworm main only) |
| Builder | The repository's own `scripts/build-component-capsule.sh`: `SOURCE_DATE_EPOCH=0`, no incremental, path remapping, componentize |

`python3` runs the builder's manifest checks and prints the hash; it does not
touch the artifact bytes. It is pinned all the same, as `python3=3.11.2-1+b1`
from the Debian snapshot `20261015T000000Z`. The snapshot is immutable, so its
dependencies are fixed too.

## Why one platform

A native Mac build and a native Linux build of the same commit differ. The
reviewer's Mac built P1 (`ca5560aa`) to `e2a4c798…638a`, 221,287 bytes, while
cloud built `9cf68749…`, 221,286 bytes.

Cargo hashes `rustc -vV` into each crate's `-C metadata`, and that output
names the host triple (`aarch64-apple-darwin` on the Mac,
`x86_64-unknown-linux-gnu` in cloud). The metadata hash is part of every mangled
symbol, and symbol names decide how LTO orders functions. The difference
therefore reaches the code and data sections, not only the debug `name` section.

To show this without a Mac, build the same commit twice in cloud, the second
time with only the metadata changed (`__CARGO_DEFAULT_LIB_METADATA=x`). The
type, element, code (141,735 bytes in both) and data sections all change
hashes, and the file grows by 13 bytes. Stripping `name` would not be enough;
the host triple has to be the same, so the platform is pinned.

## Expected hashes

| Commit | Slice | sha256 |
| --- | --- | --- |
| `ca5560aa` | P1 | `9cf6874985454b5be310a68ea28493d8b3cac6a7a914d5831c4500bb3d17bade` |
| `8fc30615` | P1b (guest unchanged since) | `add93842bb7253bdab18d27067d0976558913fda6bd354f772f04c5e9fc9dd22` |

Both were built in this container in cloud. The P1 build also ran with
`CARGO_BUILD_JOBS=1` and gave the same hash. Both equal the cloud-native
builds, as expected: cloud is already `x86_64-unknown-linux-gnu`.

## Behind a proxy

A host that reaches the network through a proxy with its own CA (the cloud
sessions) passes both in. The script then uses `--network host` and points
apt, rustup and Cargo at the CA:

```bash
HTTPS_PROXY="$HTTPS_PROXY" ELASTOS_REPRO_CA=/root/.ccr/ca-bundle.crt \
  examples/photo-viewer/repro/build-in-container.sh
```

apt reads the snapshot over HTTPS, because some proxies refuse plain HTTP. A
plain host such as a Mac sets neither variable.

Docker Hub limits anonymous pulls. The image is pulled once per machine and
then cached.
