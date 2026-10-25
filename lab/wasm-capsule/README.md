# wasm-capsule lab — wc-001, wc-003a

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
Cargo.toml            root package `capsule` + members `audit`, `tools`; its own [workspace]
Cargo.lock            committed; the one lockfile for every member
capsule/src/lib.rs    the guest (no_std on wasm32) + the digest host test
audit/                the `wasm-capsule-audit` crate (owned by the cx-wasm-audit lane)
tools/build           the reproducible build script (bash)
tools/Cargo.toml      the `wasm-capsule-tools` crate: the lab's host-side library
tools/src/lab_name.rs the one rule that names a lab bundle (wc-003a)
tests/                host-side named tests + the shape reader (never in the capsule)
  common/             build driver + minimal wasm shape reader
falsifiers.json       planted bugs, each caught by a named test (provider format)
rust-toolchain.toml   pins rustc 1.91.0 + the wasm target (for adoption)
```

The lane is a Cargo workspace whose root is the package `capsule` (not a virtual
workspace), so the lane gates — `cargo fmt`/`cargo test --manifest-path
.../Cargo.toml` — act on `capsule` without `--all`/`--workspace`. Its other
members are `audit/` and `tools/`. `audit/` is the `wasm-capsule-audit` crate:
the one import-audit path (P10) that wc-004's verifier will call through a path
dependency. The cx-wasm-audit lane owns it; this lane does not edit it. Test it
from this directory with `cargo test -p wasm-capsule-audit --locked`. `tools/`
is the `wasm-capsule-tools` crate, the lab's host-side library (wc-003a below).

`capsule` itself has **no dependencies**: it has no `[dependencies]`, and its
tests' one dev-dependency, `wasm-capsule-tools`, is built only for tests.
`Cargo.lock` also pins the members' crates: the audit's `wasmparser` 0.258.0 and
dev-only `wat` 1.258.0, the tools crate's `sha2` 0.10.9 and `libc` 0.2.189
(exact pins at the versions the Runtime locks), and their transitive
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

## wc-003a: the lab name, as a library

`tools/src/lab_name.rs`, in the member crate `wasm-capsule-tools`, holds the one
rule that names a lab bundle (P10). It is a library only: no command, no
argument parsing, and it writes nothing. Every lab tool names a bundle through
one entry point:

```rust
wasm_capsule_tools::lab_name::name_bundle(dir: &Path) -> Result<String, Refusal>
```

`name_bundle` is `read_bundle` (read the directory as a closure and fail
closed), then `lab_name` (hash its canonical closure). `canonical_closure` gives
the exact bytes that are hashed. A `Refusal` holds the offending path and a
plain reason, and displays as `<path>: <reason>`.

### A lab name, not a CID

The name is `lab-sha256:` followed by 64 lowercase hex digits. It is a **lab
name**. It is **not a CID** and never a package identity: the Runtime names an
artifact by the CID its IPFS provider gets from Kubo, and this rule does not
reproduce that (ADOPTION.md has the discovery and the decision). No Runtime
admission or launch path reads a lab name.

### The closure

A lab bundle is a directory that holds exactly two regular files:

| Path | What it is |
| --- | --- |
| `capsule.json` | the lab manifest |
| `capsule.wasm` | the core Wasm module |

Anything else is refused, and each refusal names the path and gives its own
reason: an extra entry (even a `.DS_Store`), a missing closure file, a symlink
(never followed), a directory, FIFO or device (refused at once, never waited
on), a directory that cannot be listed, and a file that cannot be opened or
read. The last two carry the cause the OS gave. The name covers the manifest's
exact bytes; it does not check that the manifest is valid (its schema is a
later task).

Each closure file is opened once, by `open_regular`, with
`O_NOFOLLOW | O_NONBLOCK` from `libc`: the open itself refuses a link, so no
moment passes between a check and the open, and it never waits on a FIFO or a
device. Then it checks the handle it opened, never the path again: only a
regular file is accepted, and the bytes are read from that same handle. This is
the Runtime's own pattern
(`elastos/crates/elastos-runtime/src/provider/bridge.rs:118-124`). The listing
decides the closure before any file is opened, so a link put at a closure path
before the open is refused, and one put there after the open is never looked
at.

What this does not cover: the bundle directory is used as given, so a link in
its own path is followed, and a swap of that directory by another process while
it is read is not covered. That needs directory-relative opens (`openat`, as
`capsules/ipfs-provider/src/directory_hash.rs` does), which this library does
not do.

### The bytes that are hashed

```
"wc-003.lab-closure/v1\n"
then, for each file in ascending byte order of its path:
  <path length> SP <path> SP <content length> SP <content>
```

A length is the byte count in decimal ASCII with no leading zeros, and SP is one
space (0x20). Every field is length-framed, so two different closures never
give the same bytes, and the tag keeps a lab name apart from the plain sha256
of any file. Only paths and exact contents are read: no mtime, mode, owner,
write or listing order, or directory name.

The lab name is `lab-sha256:` and the lowercase hex SHA-256 of these bytes,
computed in-process by the exact-pinned `sha2` crate. Naming starts no process,
reads no PATH and uses no system hash tool, so once the bytes are read it cannot
fail: `lab_name` returns a `String`, not a `Result`. (`tools/build`'s receipt
still hashes with the system `sha256sum` or `shasum -a 256`.)

Test vector, pinned in `bundle_name_is_the_hash_of_the_canonical_closure`: a
bundle whose `capsule.wasm` is the 8-byte empty module `00 61 73 6d 01 00 00 00`
and whose `capsule.json` is the 175-byte `FIXTURE_MANIFEST` in
`tests/lab_name.rs` hashes these 243 bytes

```
wc-003.lab-closure/v1\n12 capsule.json 175 <manifest bytes>12 capsule.wasm 8 <module bytes>
```

to `lab-sha256:0cb69f7b3bd515d31b4b1ad0c50b56a4036e341b359cd5d09cb2ce9b1f3481e1`.
That value was computed outside the lab code, with `printf` piped into
`shasum -a 256` (and checked with `openssl dgst -sha256`), and then pinned.

### Why the tests live in the root package

The lane gate `cargo test --locked --manifest-path lab/wasm-capsule/Cargo.toml`
runs only the root package `capsule` (there is no `--workspace`), so a test
inside `tools/` would never run in the gate. So every named test is in
`tests/lab_name.rs`, and `capsule` reaches the tools crate through its one
dev-dependency. The gate's `cargo fmt` also covers only `capsule`; check the
tools crate with
`cargo fmt -p wasm-capsule-tools --manifest-path lab/wasm-capsule/Cargo.toml -- --check`.

## Named tests

`cargo test --manifest-path lab/wasm-capsule/Cargo.toml`:

- `digest_returns_the_fixed_value` — the shared impl returns the pinned value.
- `two_clean_builds_in_different_paths_are_byte_identical` — the foundation claim.
- `the_receipt_names_the_exact_toolchain` — receipt rustc/target match the build.
- `receipt_hashes_match_artifact_and_lockfile` — receipt hashes match the files.
- `built_capsule_has_the_required_wasm_shape` — core Wasm, zero imports, digest sig.
- plus crafted-byte coverage of the shape reader.

wc-003a, in `tests/lab_name.rs` (through `wasm_capsule_tools::lab_name`):

- `bundle_name_is_the_hash_of_the_canonical_closure` — the documented bytes and
  the pinned vector, through `lab_name` and `name_bundle`.
- `changing_one_wasm_byte_changes_the_name`
- `changing_the_manifest_changes_the_name` — only the declared imports change.
- `file_order_mtime_and_mode_do_not_change_the_name`
- `an_extra_file_in_the_bundle_is_refused` — the path and the exact reason.
- `a_missing_closure_file_is_refused` — the manifest, then the module.
- `a_symlink_in_the_bundle_is_refused`
- `a_closure_file_replaced_by_a_symlink_before_it_is_opened_is_refused` — a
  test seam swaps the file for a link after the listing; the open refuses it.
- `a_closure_file_replaced_after_it_is_checked_is_read_from_its_handle` — the
  seam swaps the path for a link to other bytes after the handle check; the
  name still covers the bytes that were opened.
- `a_fifo_in_the_bundle_is_refused_without_blocking` — refused within a
  deadline, never waited on.
- `directory_in_bundle_is_refused`
- `device_is_refused` — `/dev/null` through the one open (only root can make a
  device node).
- `unlistable_bundle_reports_path_and_cause` — a missing directory, and a file
  where the directory should be.
- `open_failure_reports_path_and_cause` — the seam removes a listed file before
  its open.
- `read_failure_reports_path_and_cause` — a write-only handle, whose read fails.
- `lab_name_carries_the_lab_prefix_never_cid`

## Falsifiers

`falsifiers.json` holds nine wc-001 and twenty wc-003a planted bugs in the
provider format (`command: "lab"`). Each requires all its named tests to fail at
an assertion. The canonical runner
`examples/agent-host/falsify.py` has no `lab` command yet (ask **R1**), so each
is proved by the repo's break → named test fails → revert method with
`cargo test` in this workspace until R1 lands.
