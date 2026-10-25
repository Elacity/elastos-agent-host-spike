# wasm-capsule lab — wc-001

The lab's foundation: one minimal **core Wasm** capsule that anyone can rebuild
byte for byte on this one Mac. Later tasks hash-name it (wc-003), sign that name
(wc-004) and run it on two engines (wc-005). This is lab tooling Anders may
adopt; it is not a second Runtime.

## What the capsule is

`capsule/src/lib.rs` compiles to a core Wasm module for `wasm32-unknown-unknown`
with **no imports**. It exports one pure function:

```wat
(func (export "digest") (param i32) (result i64))
```

`digest` is a splitmix64-style mix: total (no panics), deterministic, `core`
only. It is the whole capsule — a small self-contained computer that traps down
to nothing (Rong's DigitCapsule; PRINCIPLES P3, P18). `digest_impl` is the
single shared implementation the Wasm export and the host test both call, so
there is one path for the behaviour (P10).

## Layout

```
Cargo.toml            root package `capsule` + member `audit`, its own [workspace]
Cargo.lock            committed; the one lockfile for both members
capsule/src/lib.rs    the guest (no_std on wasm32) + the digest host test
audit/                the `wasm-capsule-audit` crate (owned by the cx-wasm-audit lane)
tools/build           the reproducible build script (bash)
tests/                host-side named tests + the shape reader (never in the capsule)
  common/             build driver + minimal wasm shape reader
falsifiers.json       planted bugs, each caught by a named test (provider format)
rust-toolchain.toml   pins rustc 1.91.0 + the wasm target (for adoption)
```

The lane is a Cargo workspace whose root is the package `capsule` (not a virtual
workspace), so the lane gates — `cargo fmt`/`cargo test --manifest-path
.../Cargo.toml` — act on `capsule` without `--all`/`--workspace`. Its other
member is `audit/`, the `wasm-capsule-audit` crate: the one import-audit path
(P10) that wc-004's verifier will call through a path dependency. The
cx-wasm-audit lane owns it; this lane does not edit it. Test it from this
directory with `cargo test -p wasm-capsule-audit --locked`.

`capsule` itself has **no dependencies**. `Cargo.lock` also pins the audit's
crates: `wasmparser` 0.258.0, the dev-only `wat` 1.258.0, and their transitive
dependencies. `tools/build` compiles only `capsule`, so none of them is in the
artifact. But Cargo resolves the whole workspace, so every build, `tools/build`
included, needs those crates in the local cargo cache. They are cached on this
Mac, so the lane builds offline here; on a machine with an empty cargo cache the
first build needs the network.

## Build

```bash
tools/build [OUT_DIR]     # default OUT_DIR is the lane root
```

writes `OUT_DIR/capsule.wasm` and `OUT_DIR/receipt.txt`. The build is pinned:
one codegen unit, LTO, a stripped binary and `panic = "abort"` (the release
profile in `Cargo.toml`), a fixed `SOURCE_DATE_EPOCH`, no incremental cache, a
fresh isolated target dir, and `--remap-path-prefix` for the source tree,
`CARGO_HOME` and the toolchain sysroot.

### Receipt

```
schema: wc-001.receipt/v1
artifact: capsule.wasm
artifact_sha256: <sha256 of capsule.wasm>
rustc_version: rustc 1.91.0 (f8297e351 2025-10-28)
target: wasm32-unknown-unknown
lockfile_sha256: <sha256 of Cargo.lock>
source_date_epoch: 1700000000
```

The receipt binds the artifact to the exact toolchain and inputs so a rebuild
can be checked (P13).

## Claim scope (narrow, on purpose)

Reproducible on **this one Mac**, across paths and clean caches only.
Cross-machine reproduction is **unverified**: Cargo's symbol hashes depend on
the build machine (same note as the agent-host guest hash). Reference values
from two clean builds at different temp paths on 2026-10-25:

- rustc: `rustc 1.91.0 (f8297e351 2025-10-28)`, host `aarch64-apple-darwin`
- target: `wasm32-unknown-unknown`
- `capsule.wasm` sha256 (both builds): `6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13`
- size: 178 bytes

On this stripped, zero-dependency release cdylib nothing absolute leaks, so
`--remap-path-prefix` is defensive (it would neutralise a leak from debug info
or a dependency). F-WC1 is realised by embedding `env!("CARGO_MANIFEST_DIR")`,
an absolute path `--remap-path-prefix` does not rewrite, which is why the two
builds then differ.

## Named tests

`cargo test --manifest-path lab/wasm-capsule/Cargo.toml`:

- `digest_returns_the_fixed_value` — the shared impl returns the pinned value.
- `two_clean_builds_in_different_paths_are_byte_identical` — the foundation claim.
- `the_receipt_names_the_exact_toolchain` — receipt rustc/target match the build.
- `receipt_hashes_match_artifact_and_lockfile` — receipt hashes match the files.
- `built_capsule_has_the_required_wasm_shape` — core Wasm, zero imports, digest sig.
- plus crafted-byte coverage of the shape reader.

## Falsifiers

`falsifiers.json` holds seven planted bugs in the provider format
(`command: "lab"`). Each requires its named test to fail. The canonical runner
`examples/agent-host/falsify.py` has no `lab` command yet (ask **R1**), so each
is proved by the repo's break → named test fails → revert method with
`cargo test` in this workspace until R1 lands.
