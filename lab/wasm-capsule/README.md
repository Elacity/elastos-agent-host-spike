# wasm-capsule lab — wc-001, wc-003

The lab's foundation: one minimal **core Wasm** capsule that anyone can rebuild
byte for byte on this one Mac (wc-001), put in a bundle that is named by the
hash of its whole closure (wc-003). Later tasks sign that name (wc-004) and run
the capsule on two engines (wc-005). This is lab tooling Anders may adopt; it
is not a second Runtime.

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
Cargo.toml            one package `capsule`, its own [workspace] + Cargo.lock
capsule/src/lib.rs    the guest (no_std on wasm32) + the digest host test
tools/build           the reproducible build script (bash)
tools/bundle          the lab bundle command (wc-003); runs the `bundle` binary
tools/bundle.rs       the `bundle` binary (host-side, never in the capsule)
tools/lab_name.rs     the one closure rule that names a bundle
tests/                host-side named tests + the shape reader (never in the capsule)
  common/             build driver, minimal wasm shape reader, strict JSON reader
falsifiers.json       planted bugs, each caught by a named test (provider format)
rust-toolchain.toml   pins rustc 1.91.0 + the wasm target (for adoption)
```

The lane is a single Cargo package (not a virtual workspace) so the lane gates —
`cargo fmt`/`cargo test --manifest-path .../Cargo.toml` — act on it without
`--all`/`--workspace`. It has **no external dependencies**, so `Cargo.lock` holds
only this package and `cargo build --locked` needs no network. The package's
library is the capsule; its `bundle` binary is the wc-003 tool. `tools/build`
builds `--lib`, so the capsule build compiles only the capsule (its bytes are
the same either way).

## Build

```bash
tools/build [OUT_DIR]     # default OUT_DIR is the lane root
```

writes `OUT_DIR/capsule.wasm` and `OUT_DIR/receipt.txt`. Each output replaces
the entry at its path (`rm -f`, then a noclobber `>` that creates the file new),
so a symlink or hard link there is replaced, never written through. The build
is pinned:
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

## wc-003: the hash-named lab bundle

```bash
tools/bundle [OUT_DIR]            # build with tools/build, write OUT_DIR/bundle/, print its lab name
tools/bundle --name BUNDLE_DIR    # print the lab name of an existing bundle
```

`tools/bundle` runs the lane's `bundle` binary (`tools/bundle.rs`). Both modes
name a bundle through one rule, `tools/lab_name.rs`, which the tests compile
from the same file (P10). The build mode reuses `tools/build`: its
`OUT_DIR/capsule.wasm` and `OUT_DIR/receipt.txt` stay outside the closure.
stdout carries only the name. A refusal goes to stderr with the path and the
reason, and the exit status is 1.

The build mode writes a **new** bundle only. Anything already at
`OUT_DIR/bundle` (a directory, a file or a link) is refused before a byte is
written. To bundle again into the same `OUT_DIR`, remove its `bundle/` first.

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
| `capsule.json` | the lab manifest (below) |
| `capsule.wasm` | the core Wasm module `tools/build` made |

Anything else is refused, and the refusal names the path: an extra file (even a
`.DS_Store`), a missing closure file, a symlink (never followed), or a
directory, FIFO or device (refused at once, never waited on). The name is over
bytes; it does not check that the manifest is valid.

### No link is followed, to read or to write

Every capsule file `tools/bundle` reads or writes goes through one check,
`open_regular` in `tools/lab_name.rs` (P10). It opens the path with
`O_NOFOLLOW`, so the open itself refuses a link and no moment passes between a
check and the open, and with `O_NONBLOCK`, so it never waits on a FIFO or a
device. Then it checks the handle it opened, never the path again: only a
regular file is accepted. The caller reads or writes that same handle, so the
file that was checked is the file that is used. This is the pattern the
Runtime uses (`elastos/crates/elastos-runtime/src/provider/bridge.rs:118-138`).

- **Reading** (both modes): the listing decides the closure before any file is
  opened. Each closure file is opened once and read from its handle, so a link
  put at its path before the open is refused, and one put there after the
  open is never looked at.
- **Writing** (build mode): `OUT_DIR/bundle` is created new (`mkdir` never
  follows a link), and each closure file is created new (`create_new`) through
  `open_regular`, so nothing is written into or through what was there. The
  module is read from `tools/build`'s `OUT_DIR/capsule.wasm` through the same
  check.
- **`tools/build`** replaces each of its two outputs (see Build), so a symlink
  or hard link at `OUT_DIR/capsule.wasm` or `OUT_DIR/receipt.txt` is replaced,
  never written through.

The lane has no dependencies, so no `libc` crate: `tools/lab_name.rs` writes
out the macOS values of `O_NOFOLLOW`, `O_NONBLOCK` and `ELOOP`, checked against
the system headers. On any other OS the lab tools do not compile, rather than
guess a value.

What this does not cover: the directory you name with `--name`, and `OUT_DIR`,
are used as you give them, so a link in their own path is followed. A swap of
that directory by another process while the tool runs is not covered either:
that needs directory-relative opens (`openat`), which stable Rust's std does
not have, and the lane takes no dependency.

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
write or listing order, or directory name. The lab name is `lab-sha256:` and
the lowercase hex sha256 of these bytes, from the system `sha256sum` or
`shasum -a 256` (the tools `tools/build` uses; no crate).

Test vector, pinned in `bundle_name_is_the_hash_of_the_canonical_closure`: a
bundle whose `capsule.wasm` is the 8-byte empty module `00 61 73 6d 01 00 00 00`
and whose `capsule.json` is the 175-byte `FIXTURE_MANIFEST` in `tests/bundle.rs`
hashes

```
wc-003.lab-closure/v1\n12 capsule.json 175 <manifest bytes>12 capsule.wasm 8 <module bytes>
```

to `lab-sha256:0cb69f7b3bd515d31b4b1ad0c50b56a4036e341b359cd5d09cb2ce9b1f3481e1`.
That value was computed once outside the lab code, with `printf` and
`shasum -a 256`, and then pinned.

### Lab manifest (`capsule.json`)

Schema `wc-003.lab-manifest/v1`. A JSON object with exactly these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Always `wc-003.lab-manifest/v1`. It marks a lab manifest, not a Runtime capsule manifest. |
| `name` | string | A human label, the Cargo package name. Never identity: the bundle's identity is its lab name. |
| `version` | string | The Cargo package version, `MAJOR.MINOR.PATCH`. |
| `entrypoint` | string | The closure path of the core Wasm module an engine instantiates: always `capsule.wasm`. A file, not a function, and not a Component. |
| `imports` | array | The imports the module declares it needs, each `{ "module": "...", "name": "..." }` (the audit API's `DeclaredImport`). This capsule declares `[]`. wc-004 audits the module against it. |
| `resources` | object | Exactly `max_memory_pages`: the linear-memory ceiling, a whole number of Wasm pages of 65,536 bytes, from 1 to 65,536 (the 4 GiB wasm32 limit). This capsule declares 16 (1 MiB), the initial memory its module declares. Declared only: nothing in wc-003 enforces it. |

`tools/bundle` writes it in one byte layout (this key order, two-space indent,
LF line ends), so the same capsule always gives the same bytes. Because the
name hashes exact bytes, any change to the manifest, even whitespace, is a new
name. This capsule's manifest:

```json
{
  "schema": "wc-003.lab-manifest/v1",
  "name": "capsule",
  "version": "0.1.0",
  "entrypoint": "capsule.wasm",
  "imports": [],
  "resources": { "max_memory_pages": 16 }
}
```

### Reference value

On this Mac on 2026-10-25, `tools/bundle` over the wc-001 capsule (sha256
`6dd9af1a…` above) printed
`lab-sha256:11ae0c0cd21c120c216aef1f15ef4178e30371a46e51b26ec95849b43bc8cbcc`.
It is reproducible on this one Mac only, like the module it covers.

## Named tests

`cargo test --manifest-path lab/wasm-capsule/Cargo.toml`:

- `digest_returns_the_fixed_value` — the shared impl returns the pinned value.
- `two_clean_builds_in_different_paths_are_byte_identical` — the foundation claim.
- `the_receipt_names_the_exact_toolchain` — receipt rustc/target match the build.
- `the_receipt_names_an_overridden_compiler` — an explicit `RUSTC` reaches the receipt.
- `receipt_hashes_match_artifact_and_lockfile` — receipt hashes match the files.
- `built_capsule_has_the_required_wasm_shape` — core Wasm, zero imports, digest sig.
- plus crafted-byte coverage of the shape reader.

wc-003, in `tests/bundle.rs`:

- `bundle_name_is_the_hash_of_the_canonical_closure` — the documented bytes and
  the pinned vector, through the rule and the real command; the build mode
  prints the rule's name of the bundle it wrote, and its module is the artifact
  `tools/build` receipted.
- `changing_one_wasm_byte_changes_the_name`
- `changing_the_manifest_changes_the_name` — only the declared imports change.
- `file_order_mtime_and_mode_do_not_change_the_name`
- `an_extra_file_in_the_bundle_is_refused` — names the path and the reason; the
  command prints no name.
- `a_missing_closure_file_is_refused`
- `a_symlink_in_the_bundle_is_refused`
- `a_closure_file_replaced_by_a_symlink_before_it_is_opened_is_refused` — a
  test seam swaps the file for a link after the listing; the open refuses it.
- `a_closure_file_replaced_after_it_is_checked_is_read_from_its_handle` — the
  seam swaps the path for a link to other bytes after the handle check; the
  name still covers the bytes that were opened.
- `a_fifo_in_the_bundle_is_refused_without_blocking` — refused within a
  deadline, never waited on.
- `tools_bundle_never_writes_through_a_link` — the real command, with symlinks
  at `OUT_DIR/bundle`, `OUT_DIR/bundle/capsule.json` and `OUT_DIR/capsule.wasm`
  and a hard link at `OUT_DIR/receipt.txt`: every sentinel behind them stays
  unchanged.
- `bundle_manifest_matches_lab_schema`
- `bundle_output_uses_the_lab_name_prefix`

## Falsifiers

`falsifiers.json` holds nine wc-001 and seventeen wc-003 planted bugs in the
provider format (`command: "lab"`). Each requires its named tests to fail. The
canonical runner `examples/agent-host/falsify.py` has no `lab` command yet (ask
**R1**), so each is proved by the repo's break → named test fails → revert
method with `cargo test` in this workspace until R1 lands.
