# wasm-capsule lab — wc-001, and its lab name (task 010)

The lab's foundation: one minimal **core Wasm** capsule that anyone can rebuild
byte for byte on this one Mac. A lab bundle of it is named by
cc-capsule-identity's lab CID (task 010); later tasks sign that name (wc-004) and
run it on two engines (wc-005). This is lab tooling Anders may adopt; it is not
a second Runtime.

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
Cargo.lock            committed; the one lockfile for every member and path dependency
capsule/src/lib.rs    the guest (no_std on wasm32) + the digest host test
capsule/capsule.json  this capsule's `elastos.capsule/v1` manifest
audit/                the `wasm-capsule-audit` crate (owned by the cx-wasm-audit lane)
tools/build           the reproducible build script (bash)
tools/Cargo.toml      the `wasm-capsule-tools` crate: the lab's host-side library
tools/src/lib.rs      `bundle_identity` (the shared lab CID, one re-export) + the manifest bytes
tests/                host-side named tests + the shape reader (never in the capsule)
  common/             build driver (and the copy layout) + minimal wasm shape reader
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
is the `wasm-capsule-tools` crate, the lab's host-side library (the lab name,
below).

`capsule` itself has **no dependencies**: it has no `[dependencies]` (P18). Its
tests' dev-dependencies are built only for tests: `wasm-capsule-tools`, and the
Runtime's `elastos-common` (a read-only path dependency, for its
`CapsuleManifest`) with `serde_json` to read it. `tools/` path-depends on
`lab/capsule-identity/` (the cc-capsule-identity lane's crate, read-only here),
which path-depends on `elastos/crates/elastos-common` and
`elastos/crates/elastos-identity`. `Cargo.lock` pins all their crates: the
audit's `wasmparser` 0.258.0 and dev-only `wat` 1.258.0, capsule-identity's
`ed25519-dalek` 2.2.0, `rustix` 1.1.4, `sha2` 0.10.9, `hex` 0.4.3 and
`serde_json` 1.0.151, the Runtime crates' own dependencies, and their transitive
dependencies: 135 registry crates. `tools/build` compiles only `capsule`, so
none of them is in the artifact. But Cargo resolves the whole workspace, so
every build, `tools/build` included, needs those crates in the local cargo
cache. They are cached on this Mac, so the lane builds offline here; on a
machine with an empty cargo cache the first build needs the network.

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

## The lab name: cc-capsule-identity's lab CID

### What a lab bundle is

A lab bundle of this capsule is a folder holding this capsule's manifest as
`capsule.json` and the module as `capsule.wasm`. Its name is
cc-capsule-identity's **lab CID**, `lab-cid:sha256:<64 lowercase hex>`. The lab
CID covers every regular file in the folder, so a file added beside the two
changes the name; the shared walk refuses links, FIFOs, sockets, devices and
names that are not UTF-8.

### One export

Every lab tool names a bundle through one function:

```rust
wasm_capsule_tools::bundle_identity(bundle: &Path) -> Result<LabCid, Refusal>
```

It is cc-capsule-identity's `lab_cid`, re-exported once and unchanged in
`tools/src/lib.rs` (`pub use ... lab_cid as bundle_identity;`). Its `LabCid`
result and `Refusal` are that lane's. This lane adds no function body and no
identity rule: that lane owns the hash, the walk and the manifest check (the
Runtime's `CapsuleManifest` parse, then `validate()`). Callers treat a
`LabCid` as an opaque value: they compare it and print it, and leave the
prefix, the hash and any CID codec to that lane. The encoding and the walk's
rules are in `lab/capsule-identity/README.md` ("The encoding").

The direction is cc-capsule-identity's too. Anders has proposed a CIDv1
SHA-256 UnixFS directory root as the bundle identity; that lane owns it, and
its reproducibility tests are the gate before that profile is frozen. It also
owns the separate signed record kept outside the package. A future switch
changes this one export to that lane's replacement function, with the same call
contract and the same name, `bundle_identity`. This lane keeps one identity
path: no UnixFS code, fallback or choice of rule of its own.

### A lab CID, not a CID

The lab CID is a lab value. It is not the Runtime's CID: the Runtime names a
published capsule by the CID its IPFS provider gets for the capsule archive
(ADOPTION.md, the wc-003 discovery). No Runtime admission or launch path reads a
lab CID.

This lane's pinned vector, in `this_capsule_bundle_has_the_pinned_lab_cid`: the
bundle of this capsule's 277-byte `capsule/capsule.json` and the 8-byte empty
module `00 61 73 6d 01 00 00 00` is

```
lab-cid:sha256:dd6673dafaf1a3180310d3207cccc59b3e414b584b2d93002bb81c8d293a3c47
```

It was computed outside the lab code, with Python's `hashlib` over
capsule-identity's README encoding, and then pinned. It also guards this lane:
if the shared rule changes under it, this test fails.

### This capsule's manifest

`capsule/capsule.json` is an `elastos.capsule/v1` manifest with only fields of
the Runtime's `CapsuleManifest`: `schema`, `name` and `version` (the root
package's own, kept equal by a test), `description`, `role` `app`, `type`
`wasm` and `entrypoint` `capsule.wasm`. The tools crate compiles its bytes in
as `wasm_capsule_tools::CAPSULE_MANIFEST`, so nothing reads the file by a path
at run time. Nothing in the lane parses it except the Runtime's type, inside
`bundle_identity` and in `lab_manifest_passes_runtime_validate`.

It lists no Wasm imports, and the Runtime's type has no field for them. Rong's
ruling (26 Oct): the module's own import section is the declaration. It sits
inside the lab CID, and the audit crate's import list is its one reader. This
module's import section is empty.

### The lockfile coupling

The tools crate path-depends on `lab/capsule-identity/`, so this workspace's
`Cargo.lock` holds that crate's dependencies. A dependency change in
`lab/capsule-identity/Cargo.toml` therefore breaks `cargo test --locked` here
(and in cx-wasm-audit's gate, which runs in this workspace) until this lane
re-locks. It also breaks capsule-identity's own
`wc001_capsule_bundle_gets_a_stable_lab_cid`, which runs this lane's
`tools/build --locked`. Such a change needs a coordinated owner and order
(BACKLOG ask C3).

The reproducibility copy (`tests/common/build.rs`) lays each copy out as
`<root>/lab/wasm-capsule/...`, and reaches `<root>/lab/capsule-identity` and
`<root>/elastos` through symbolic links to the real folders. Cargo loads their
manifests to resolve the lockfile, even though `tools/build` compiles only
`capsule`, and writes into neither. Without the links,
`two_clean_builds_in_different_paths_are_byte_identical` fails with cargo's
"failed to load manifest" error (F-WC3-COPY-DEPS).

**C4.** A copy of `lab/wasm-capsule/` alone no longer builds: its
`tools/build` stops with cargo's "failed to load manifest" error for
`capsule-identity`. cc-redteam's probe
`lab/redteam/py/test_wasm_capsule_receipt.py` makes such copies. The fix is
cc-redteam's: lay its copies out the same way. It is finding C4, owned by
cc-redteam.

### History

007's lane-own name rule (PR #105) was retired by task 010, on Rong's one-rule
note: one bundle-identity rule for the two lab lanes. Its library, its 18 tests
and its 24 falsifiers are deleted. cc-capsule-identity's own tests and
falsifiers cover the walk and the encoding.

### Why the tests live in the root package

The lane gate `cargo test --locked --manifest-path lab/wasm-capsule/Cargo.toml`
runs only the root package `capsule` (there is no `--workspace`), so a test
inside `tools/` would never run in the gate. So every named test is in
`tests/`, and `capsule` reaches the tools crate through a dev-dependency. The
gate's `cargo fmt` also covers only `capsule`; check the tools crate with
`cargo fmt -p wasm-capsule-tools --manifest-path lab/wasm-capsule/Cargo.toml -- --check`.

## Named tests

`cargo test --manifest-path lab/wasm-capsule/Cargo.toml`:

- `digest_returns_the_fixed_value` — the shared impl returns the pinned value.
- `two_clean_builds_in_different_paths_are_byte_identical` — the foundation claim.
- `the_receipt_names_the_exact_toolchain` — receipt rustc/target match the build.
- `receipt_hashes_match_artifact_and_lockfile` — receipt hashes match the files.
- `built_capsule_has_the_required_wasm_shape` — core Wasm, zero imports, digest sig.
- plus crafted-byte coverage of the shape reader.

The lab name, in `tests/lab_cid.rs` (through `wasm_capsule_tools::bundle_identity`):

- `lab_manifest_passes_runtime_validate` — `bundle_identity` accepts this
  capsule's bundle, and the manifest, read with the Runtime's `CapsuleManifest`,
  validates, is `type` `wasm` with `entrypoint` `capsule.wasm`, and has the root
  package's `name` and `version`.
- `this_capsule_bundle_has_the_pinned_lab_cid` — the pinned vector above.
- `the_lane_keeps_no_bundle_name_rule_of_its_own` — the lane's own files (from
  `git ls-files`, without `audit/`, the docs and `falsifiers.json`) hold none of
  007's retired names, and the shared crate is imported by the one export line
  only. If git cannot run, it fails.

## Falsifiers

`falsifiers.json` holds nine wc-001 and seven task-010 planted bugs in the
provider format (`command: "lab"`). Each requires all its named tests to fail at
an assertion. The canonical runner
`examples/agent-host/falsify.py` has no `lab` command yet (ask **R1**), so each
is proved by the repo's break → named test fails → revert method with
`cargo test` in this workspace until R1 lands. Runner-caught: none yet.

Task 010's seven, each hand-proven, pending R1:

- F-WC3-LABCID-SCHEMA — the manifest's `schema` becomes a lab schema; the
  Runtime's `validate()` refuses it inside the lab CID.
- F-WC3-LABCID-ENTRYPOINT — `entrypoint` becomes `module.wasm`.
- F-WC3-LABCID-VERSION — `version` becomes `0.1.1`.
- F-WC3-LABCID-PIN — one byte of the `description` changes the lab CID.
- F-WC3-SECOND-RULE — a naming function of the lane's own comes back.
- F-WC3-SECOND-IMPORT — the tools crate imports the shared function twice.
- F-WC3-COPY-DEPS — the reproducibility copy stops reaching the out-of-lane
  path dependencies, so the child `tools/build` fails with cargo's "failed to
  load manifest" error and the named test fails at its assertion that the build
  succeeded.
