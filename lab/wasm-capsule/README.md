# wasm-capsule lab — wc-001, its lab name (task 010), `tools/bundle` (task 009), the verifier (wc-004) and the bare-capsule ABI gap (wc-008)

The lab's foundation: one minimal **core Wasm** capsule that anyone can rebuild
byte for byte on this one Mac. A lab bundle of it is named by
cc-capsule-identity's lab CID (task 010); wc-004 verifies a test-key signature
over that name and audits its module; wc-005a runs it on one engine,
wc-005b (task 015) on two, and wc-005c (task 016) writes a receipt of that run
with the engine versions as the engines printed them. This is lab tooling
Anders may adopt; it is not a second Runtime.

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
tools/bundle          writes a new lab bundle and prints its lab CID (bash wrapper)
tools/Cargo.toml      the `wasm-capsule-tools` crate: the lab's host-side library
tools/src/lib.rs      `bundle_identity` (the shared lab CID, one re-export) + the manifest bytes
tools/src/bundle.rs   `tools/bundle`'s rules: `parse_args` and `run`
tools/src/verify.rs   wc-004's one verify path: `verify_checked` and `verify_bundle`
tools/src/run.rs      wc-005a's `run_engine` (one host engine on the verified entrypoint) and
                      wc-005b's `run` (verify once, ask both `--version`, then wasmtime,
                      then wasmer, same stdout)
tools/src/receipt.rs  wc-005c's run receipt: `render` and `write_receipt`
tools/src/bin/bundle.rs  the `bundle` binary: parse, run, print, exit status
tests/                host-side named tests + the shape reader (never in the capsule)
  common/             build driver (and the copy layout) + minimal wasm shape reader
  bundle_builds/      small stand-in build scripts for `tools/bundle`'s tests
falsifiers.json       planted bugs, each caught by a named test (provider format)
rust-toolchain.toml   pins rustc 1.91.0 + the wasm target (for adoption)
```

The lane is a Cargo workspace whose root is the package `capsule` (not a virtual
workspace), so the lane gates — `cargo fmt`/`cargo test --manifest-path
.../Cargo.toml` — act on `capsule` without `--all`/`--workspace`. Its other
members are `audit/` and `tools/`. `audit/` is the `wasm-capsule-audit` crate:
the one import-audit path (P10), which wc-004's verifier calls through a path
dependency. The cx-wasm-audit lane owns it; this lane does not edit it. Test it
from this directory with `cargo test -p wasm-capsule-audit --locked`. `tools/`
is the `wasm-capsule-tools` crate, the lab's host-side library (the lab name
the verifier and the runner, below).

`capsule` itself has **no dependencies**: it has no `[dependencies]` (P18). Its
tests' dev-dependencies are built only for tests: `wasm-capsule-tools`, the
Runtime's `elastos-common` (a read-only path dependency, for its
`CapsuleManifest`) with `serde_json` to read it, and for wc-004's tests
`capsule-identity`, `wasm-capsule-audit`, the Runtime's `elastos-identity`
(read-only, for `encode_signing_key_did`), `ed25519-dalek` and `rand` (fresh
test keys in memory). `tools/` path-depends on `lab/capsule-identity/` (the
cc-capsule-identity lane's crate, read-only here), on `wasm-capsule-audit`
(`../audit`), and on `elastos-common` with `serde_json` (the Runtime's
manifest reader). `capsule-identity` path-depends on `elastos/crates/elastos-common` and
`elastos/crates/elastos-identity`. `Cargo.lock` pins all their crates: the
audit's `wasmparser` 0.258.0 and dev-only `wat` 1.258.0, capsule-identity's
`ed25519-dalek` 2.2.0, `rustix` 1.1.4, `sha2` 0.10.9, `hex` 0.4.3 and
`serde_json` 1.0.151, the Runtime crates' own dependencies, and their transitive
dependencies: 135 registry crates (wc-004 added none: every crate it uses
was already locked). `tools/build` compiles only `capsule`, so
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

Task 017: the retired name label is checked in every git-listed lane file,
docs, `falsifiers.json` and `audit/` included (falsifier
F-WC3-RETIRED-LABEL-DOC); the code names keep the docs exemption.

### Why the tests live in the root package

The lane gate `cargo test --locked --manifest-path lab/wasm-capsule/Cargo.toml`
runs only the root package `capsule` (there is no `--workspace`), so a test
inside `tools/` would never run in the gate. So every named test is in
`tests/`, and `capsule` reaches the tools crate through a dev-dependency. The
gate's `cargo fmt` also covers only `capsule`; check the tools crate with
`cargo fmt -p wasm-capsule-tools --manifest-path lab/wasm-capsule/Cargo.toml -- --check`.

## tools/bundle

```bash
tools/bundle OUT_DIR             # build, write OUT_DIR/bundle/, print its lab CID
tools/bundle --name BUNDLE_DIR   # print the lab CID of an existing bundle
```

On success stdout is exactly the lab CID and a newline, and the exit status is
0. An argument refusal prints `bundle: <reason>` and the usage line on stderr,
exit status 2. A run refusal prints `bundle: refused: <path>: <reason>` on
stderr, exit status 1. A refusal prints nothing to stdout. The wrapper execs
`cargo run --quiet --locked` for the tools crate's `bundle` binary, which only
parses, runs, prints and sets the status. The rules are library functions in
`tools/src/bundle.rs`, tested in-process.

**One name rule (P10).** Both modes name a bundle only with
`wasm_capsule_tools::bundle_identity` and print its Display form. Its
refusals pass through unchanged (for example, a link in a bundle gets the
shared walk's own link reason).

**A new OUT_DIR.** OUT_DIR is required (there is no default) and must not
exist. The build mode:

1. makes OUT_DIR with `create_dir`, which refuses anything already there: a
   folder, a file or a link;
2. runs `tools/build OUT_DIR` by its path (never a PATH lookup), with its
   stdout sent to stderr, so stdout carries only the name;
3. makes `OUT_DIR/bundle/` with `create_dir`, so a link planted there during
   the build is refused;
4. makes `bundle/capsule.json` with `create_new`, which refuses any entry
   already there (a link included), and writes this capsule's manifest bytes
   (`CAPSULE_MANIFEST`);
5. moves the module in with `rename(OUT_DIR/capsule.wasm,
   OUT_DIR/bundle/capsule.wasm)`. A rename moves a folder entry: it reads and
   writes no file content and never follows a link. A link at the source moves
   as a link, and step 6 refuses it;
6. names `OUT_DIR/bundle` with `bundle_identity` and prints the name.

So `bundle/` holds exactly `capsule.json` and `capsule.wasm`, and nothing is
written through a link at OUT_DIR or under it. A refused run leaves what it
made in OUT_DIR, to look at; it removes nothing.

**The receipt.** `OUT_DIR/receipt.txt` stays where `tools/build` wrote it.
Its `artifact_sha256` describes `bundle/capsule.wasm`: the same file, moved
there unchanged (its `artifact: capsule.wasm` line names the file before the
move). The receipt is outside the bundle, so it is not in the lab CID (P13:
the bundle carries the artifact `tools/build` receipted).

**Not covered.** The guarantee is for the OUT_DIR leaf and the entries under
it. Links in OUT_DIR's parent folders are followed as usual by `create_dir`
and `rename`. Another process changing OUT_DIR during the run is not covered
either: that needs folder-relative opens. The retired lane-own name had the
same limit.

**Reference lab CID on this Mac** (2026-10-26), for this capsule's 277-byte
manifest beside `capsule.wasm` `6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13`:

```
lab-cid:sha256:9ca715378b264e54614d2a231ee4d8e58e6a145873c55291fd02066aaf57f930
```

`tools_bundle_builds_a_new_bundle_and_prints_its_lab_cid` pins it. It was
also recomputed outside the lab code, with Python's `hashlib` over
capsule-identity's encoding. It is a lab CID, not the Runtime's CID.

**The test seam.** `run(mode, build_script)` takes the build script's path, so
the tests pass small stand-in scripts from `tests/bundle_builds/` (one plants a
link during the build, one fails with status 3, and so on). They change no
environment, working folder or resource limit. Exactly one test spawns the
real `tools/bundle`. Its child `cargo run` gets its own `CARGO_TARGET_DIR` and
`CARGO_BUILD_BUILD_DIR` under that test's own temp dir, set on the child only,
so it never waits on the outer `cargo test`'s build lock and writes nothing in
the checkout. Each run builds the command fresh there.

## Verify (wc-004)

```rust
wasm_capsule_tools::verify::verify_checked(checked: CheckedBundle, signature: Option<&NameSignature>,
    accepted: &[String], granted: &[DeclaredImport]) -> Result<VerifiedBundle, VerifyRefusal>
wasm_capsule_tools::verify::verify_bundle(bundle: &Path, signature: Option<&NameSignature>,
    accepted: &[String], granted: &[DeclaredImport]) -> Result<VerifiedBundle, VerifyRefusal>
```

**One call, four checks, in order.** `verify_checked` takes a
`CheckedBundle` from cc-capsule-identity's `checked_bundle` (the lab CID with
the bytes its one walk read), the bundle's in-memory `NameSignature`, the
accepted signer DIDs and the granted imports. The first refusal is the answer:

1. no signature (`None`): refused as unsigned;
2. cc-capsule-identity's `verify_checked_signature` on the checked value: a
   canonical `did:key`, the accepted list, the signed name against the checked
   bytes, then Ed25519;
3. the manifest's `entrypoint`, read from the checked `capsule.json` with the
   Runtime's `CapsuleManifest` (the one reader of that file), names the module
   among the checked entries;
4. the cx-wasm-audit crate's `audit(module, granted)` on that module's checked
   bytes.

`verify_bundle` is `checked_bundle` and then `verify_checked`, with no check of
its own, so the walk's refusals come first. The tools crate has exactly one
`verify_checked_signature` call and one `audit` call, and no name, walk, hash,
signature or import code of its own (no `wasmparser`).

**The reasons.** Each has its own exact text:

- unsigned: `the bundle has no signature: an unsigned bundle is refused`;
- the entrypoint is not in the bundle:
  `the manifest's entrypoint "<path>" is not a file in the bundle`;
- every cc-capsule-identity refusal (the walk's, a malformed signer DID, a
  signer not in the accepted list, which an empty list gives every signer,
  bytes that do not match the signed name, naming both values, and a
  signature that does not verify), carried unchanged and printed exactly as
  that lane prints it;
- every audit refusal (`undeclared import {module}.{name}`, `malformed module`,
  `code in custom section`), carried unchanged.

A fifth reason, `the Runtime's CapsuleManifest could not read the checked
capsule.json: <reason>`, cannot happen for a value `checked_bundle` made: the
walk runs the same parse and refuses first. It is kept so the verifier fails
closed with a reason rather than a panic, and no test can reach it.

**The value.** `VerifiedBundle` holds the checked bundle, which of its
entries is the entrypoint (found by step 3, the one manifest read) and the
audit's own import list, read through `cid()`, `entries()`, `entrypoint()` and
`imports()`. `entrypoint()` returns the checked entry the manifest's
`entrypoint` names, the module the audit read, so no caller reads the manifest
again. Its fields are private, and it has no public constructor, no `&mut`
access and no `Deserialize`, so a value exists only as `verify_checked` made
it. wc-005a's runner (task 014) writes `entrypoint()`'s bytes.

**The checked bytes, never the folder again.** The audit reads the module
bytes the signed name covers, from the checked value. The verifier reads no
file by a path. If the folder changes after `checked_bundle`, `verify_checked`
on the held value still judges the held bytes, and `verify_bundle` on the
changed folder is refused with the identity lane's mismatch reason.

**No command and no signature file.** cc-capsule-identity's answer to ask C2:
reuse its `sign_bundle`, `verify_checked_signature` and `NameSignature`, and
keep the signature in memory only. So there is no `tools/sign` or
`tools/verify`, no signature file and no serialized signature here. Signing and
verifying are library calls, tested in process with keys made fresh in memory
inside each test. If a file form is ever wanted, cc-capsule-identity owns it.

**Granted imports.** The module's own import section is the declaration
(Rong, 26 Oct, ruling (c)). The granted list goes to `audit` unchanged, and the
result is exactly the module's imports. Ordinary callers pass an empty list
until wc-009, which will pass the lab grants file's list to this same call;
only the grant tests here pass a non-empty list. The granted list is a lab
stand-in, not admission.

**Claim scope.** An offline lab check, on this one Mac with test keys only,
that a bundle's bytes match a signed lab CID, that an accepted test key signed
it, and that every import of its entrypoint module is granted. It answers
nothing about "may this run": it makes no admission, launch or
publisher-trust decision and sits in no admission or launch path. The signed
name is a lab CID, not the Runtime's CID.

## Run one engine (wc-005a)

```rust
wasm_capsule_tools::run::run_engine(bundle: &VerifiedBundle, engine: Engine, program: &Path,
    work_root: &Path) -> Result<EngineRun, Refusal>

pub struct EngineRun { pub status: ExitStatus, pub stdout: Vec<u8> }
```

A library function; there is no command and no binary. It runs one host
engine (`Engine::Wasmtime` or `Engine::Wasmer`) once on the verified
entrypoint and returns its exit status (as the OS reported it; only a success
is returned) and its stdout. In order, the first refusal is the answer:

1. `program` must be absolute (`./wasmtime` or a bare `wasmtime` is refused),
   so it is never looked up on PATH; the same path is the one started;
2. `work_root` must be absolute, resolve, be byte for byte its own
   `std::fs::canonicalize` result, so no link is anywhere in it (an
   option-like `--env=X` is relative, so it is refused), and be a folder by
   its own `fs::metadata` (`work_root_folder`; a failed metadata read keeps
   its OS cause, never reported as "not a folder");
3. one new folder, `<work_root>/<engine name>`, is made with `create_dir`
   and mode `0o700`; a name already there is refused, never reused;
4. `entrypoint()`'s checked bytes are written from memory as
   `<run folder>/module.wasm` with the shared `bundle::write_new_file`
   (`create_new`, never through a link);
5. the engine starts as one process:
   `<program> run --invoke digest <absolute module path> 1592590337`
   (`1592590337` is `FIXED_INPUT`, `0x5EED_0001`), with stdin null and an
   empty environment (`engine_command`, the one place these two rules are
   set, which task 016's version query uses too). The module argument is absolute, so it is never read as
   an option. There is no `--dir`, `--mapdir`, `--env` or `--net` flag.

That argv is the one wc-005's discovery recorded for `wasmtime` 45.0.1 and
`wasmer` 7.5.0 (task 006's LOG); both engines take it unchanged.

**The reasons.** Each has its own exact text, after `<path>: `:

- `the engine program path is not absolute: an engine is started only by an absolute path`;
- `the work root is not an absolute path`;
- `the work root cannot be resolved: <OS error>`;
- `the work root is not canonical: it resolves to <canonical path>`;
- `the work root's metadata cannot be read: <OS error>`;
- `the work root is not a folder`;
- `the run folder already exists: the runner makes a new one and never reuses it`;
- `the run folder cannot be created: <OS error>`;
- `the verified entrypoint cannot be created: <OS error>` and
  `the verified entrypoint cannot be written: <OS error>` (the shared writer's
  two refusals, with their path and cause kept; any other writer reason is
  carried unchanged as `the shared writer refused: <reason>`);
- `<engine> did not start: <OS error>` (for example a missing program);
- `<engine> failed (exit status: <n>): <its stderr>`.

**The claim.** The bytes the engine is given come from the verified value,
`entrypoint()`, never from a second read of the bundle on disk: the verified
`cid()` is the name, and the bytes written are exactly the bytes that name
covers. The runner reads no environment variable and no file, parses no
manifest or module, and writes nothing outside the new folder. The engine gets
no folder, env or network flag, and an empty environment. This is a behaviour
proof on one core module, not the Component ABI. `wasmtime` and `wasmer` are
test-only host engines; neither is endorsed.

**Scope of the isolation claim.** It covers the argv, the empty environment
and what the guest is given: with no folder, env or network flag, the guest
gets no host resource. The engine itself is a native process with the user's
own authority, and this runner does not confine it.

**Known limit, not claimed.** A host engine CLI opens the module by its path.
A concurrent process running as the same user could replace the file, or swap
the run folder or the work root, between the runner's write and the engine's
open; the folder and file writes are path-based too. This runner does not
defend against that. Binding launch to verified bytes is the Runtime's launch
path, not lab tooling. The runner makes no admission or launch decision.

The two-engine comparison with `verify_bundle` is the next section (task 015);
the receipt with engine versions is the section after it (task 016).

## Same output on two engines (wc-005b)

```rust
wasm_capsule_tools::run::run(input: &RunInput) -> Result<TwoEngineRun, TwoEngineRefusal>

pub struct RunInput<'a> {
    pub bundle: &'a Path,                       // the bundle folder
    pub signature: Option<&'a NameSignature>,   // in memory only
    pub accepted: &'a [String],                 // accepted signer DIDs
    pub wasmtime: &'a Path,                     // absolute program paths
    pub wasmer: &'a Path,
    pub work_root: &'a Path,
}
```

A library function; there is no command, no binary and no signature file. Every
input is in the struct; nothing is read from the environment. In order, the
first refusal is the answer:

1. wc-004's `verify_bundle(input.bundle, input.signature, input.accepted, &[])`
   is called once, with no grants. A refusal comes back unchanged as
   `TwoEngineRefusal::Verify`, printing exactly as the verifier prints it;
   nothing is written and no engine is started;
2. task 016: each engine is asked `--version`, `wasmtime` and then `wasmer`
   (the next section). A refusal comes back as `TwoEngineRefusal::Version`, and
   no module run starts;
3. `run_engine` (above) runs `wasmtime` on the verified value and returns;
4. only then `run_engine` runs `wasmer` on the same value. The two are separate
   processes, one after the other, never nested or overlapping. `run_engine` is
   the one module run path;
5. both stdouts must be byte-identical (never trimmed).

**Wasmer is not started after Wasmtime is refused.** A refusal of either engine
(a failed exit, a program that does not start, a run folder already there, any
of `run_engine`'s reasons) comes back unchanged as `TwoEngineRefusal::Engine`,
with its own path and cause. So two engines that would fail the same way are
refused with the first failure's own reason
(`<path>: wasmtime failed (exit status: <n>): <stderr>`), never as equal
outputs. Two successful runs with different stdout are refused with
`the engines' outputs differ: wasmtime printed "<stdout>", wasmer printed "<stdout>"`.

On success `TwoEngineRun` holds the verified `cid()` (the lab CID the signature
was checked against, taken from the verified value, never by naming the folder
again), both raw stdouts, `wasmtime()` and `wasmer()` (or `stdout(engine)`), and
from task 016 each engine's observed `version(engine)` and `status(engine)`.
Its fields are private, so only `run` makes one. `run` writes no receipt; the
caller writes one with `receipt::write_receipt` (next section).

**The claim.** On this Mac, the capsule `tools/build` makes, bundled, signed
with a fresh test key and verified, printed `230101071268130872`
(`FIXED_OUTPUT`) for `1592590337` (`FIXED_INPUT`) on both `wasmtime` 45.0.1 and
`wasmer` 7.5.0, byte for byte (`same_name_same_output_on_wasmtime_and_wasmer`).
This is a behaviour proof on one **core module** on this one Mac, not the
Component ABI. Both engines are test-only host engines; neither is endorsed.
This is separate from Wasmer's role inside a capsule as the POSIX RTOS PoC. The
run makes no admission or launch decision, and its lab CID is not the Runtime's
CID. The known limit of `run_engine` above holds for both runs.

## Run receipt (wc-005c)

```rust
wasm_capsule_tools::receipt::render(run: &TwoEngineRun) -> String
wasm_capsule_tools::receipt::write_receipt(run: &TwoEngineRun, path: &Path) -> Result<(), bundle::RunRefusal>
```

**The versions are observed, not configured.** After verification and before
any module run, `run` asks each engine `--version`: one process each, by the
same absolute program path the module run starts, through the same
`engine_command` (an empty environment, stdin null), `wasmtime` first. It keeps
the first line of stdout as printed, without its newline. An engine upgrade
therefore changes the receipt with no code change; nothing in the lane names
a version it expects. A version query is refused, with its own reason after
`<path>: `, and no module run starts:

- a relative program: the module run's own reason, `the engine program path is not absolute: ...`;
- `<engine> --version did not start: <OS error>` (for example a missing program);
- `<engine> --version failed (exit status: <n>): <its stderr>`;
- `<engine> --version printed no version: its first stdout line is empty`.

**The receipt.** `render` gives `key: value` lines in the shape of wc-001's
build receipt (`tools/build:82`), under its own schema line. Every value comes
from the run. The real receipt from this Mac, from
`real_receipt_names_both_installed_engines` on 26 Oct 2026 (the capsule
`tools/build` makes, bundled, signed with a fresh test key, verified and run
on Homebrew's `/opt/homebrew/bin/wasmtime` and `/opt/homebrew/bin/wasmer`):

```
schema: wc-005.run-receipt/v1
bundle: lab-cid:sha256:9ca715378b264e54614d2a231ee4d8e58e6a145873c55291fd02066aaf57f930
function: digest
argument: 1592590337
wasmtime_version: "wasmtime 45.0.1 (83166ba31 2026-06-05)"
wasmtime_status: exit status: 0
wasmtime_stdout: "230101071268130872\n"
wasmer_version: "wasmer 7.5.0"
wasmer_status: exit status: 0
wasmer_stdout: "230101071268130872\n"
```

`bundle` is the verified `cid()`'s Display form, treated as opaque; it is the
pinned lab CID of this capsule's bundle. The engine versions sit beside it and
are no part of it: the same bundle run under other versions has the same name
(P15: the hash names the content; versions are provenance beside it).
`function` and `argument` are the runner's own `DIGEST_EXPORT` and
`DIGEST_ARGUMENT`, the values its argv passes. Quoted values are the printed
bytes through `escape_ascii`, so every byte is kept and no value can add a
line. The status is the module run's `ExitStatus` as the OS reported it; a
passing run always exited 0, because `run_engine` refuses any other status.

**Writing it.** `write_receipt` writes `render`'s text to a caller-given path
with the shared `bundle::write_new_file` (`create_new`). An existing file, a
live link or a dangling link at that path is refused with that writer's own
reason and cause, unchanged, and nothing at or behind the path changes. The
writer's text names `capsule.json`, its first use (`<path>: capsule.json cannot
be created: File exists (os error 17)`); the path before it is the receipt's.

**The claim, unchanged from task 015.** One core module, on this one Mac,
with both engines test-only and neither endorsed; not the Component ABI. The
receipt is lab text: it is not signed, it is no admission or launch value,
and its lab CID is not the Runtime's CID.

## Runtime ABI for a bare capsule (wc-008)

**Decision: `NO_ABI_FOR_BARE_CAPSULE`.** `elastos.capsule/v1` has no
`runtime_abi` for this capsule, a zero-import core Wasm module that is not a
Component. Each of the seven `CapsuleRuntimeAbi` values needs Component,
projection, provider, shell, microVM or data metadata, or is refused outright;
with no `runtime_abi` the manifest validates, but both Runtime run paths refuse
a `wasm` capsule that is not a Component. The file:line facts are in
ADOPTION.md ("Runtime ABI for a bare capsule (wc-008)"), and both gaps are in
its "Gaps for Anders". `capsule/capsule.json` and the pinned lab CID are
unchanged: the lane picks no near-fit ABI and invents no field.

The tests, in `tests/runtime_abi.rs`:

- `bare_capsule_runtime_abi_is_recorded_as_skipped` — **SKIPPED**, not
  passed: `#[ignore = "NO_ABI_FOR_BARE_CAPSULE: ..."]` with the gap and
  https://github.com/Elacity/elastos-runtime/issues/463, and a body that
  panics with the same text. Cargo lists it as `ignored`.
- `no_runtime_abi_names_a_bare_core_module` — evidence of the gap, not a
  passed capability. It puts each ABI value into this capsule's manifest bytes
  in memory and checks that `validate()` refuses it with that value's own
  reason (an exact string, so a manifest broken some other way does not pass
  as the gap). Its `match` on `CapsuleRuntimeAbi` has no wildcard arm, so a
  new value in the Runtime fails the build. It also checks that the committed
  manifest has no `runtime_abi` and is not a Component. It prints
  `NO_ABI_FOR_BARE_CAPSULE` and the seven results.
- `an_unknown_manifest_field_is_refused_by_name` — adding `lab_imports` to the
  manifest bytes is refused by the Runtime's `CapsuleManifest` with an error
  that names `lab_imports`, and `bundle_identity` refuses a bundle of those
  bytes with the same manifest-parse reason. This is the guard against
  inventing a field, and the evidence for the gap "No summary of Wasm imports
  in the manifest".

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
- `the_lane_keeps_no_bundle_name_rule_of_its_own` — no lane file listed by
  `git ls-files` holds the retired name label; the same files without `audit/`,
  the docs and `falsifiers.json` hold none of 007's retired code names (the
  runner's `*.falsify-original` backups are left out), and the shared crate's
  naming functions (`lab_cid`,
  `lab_cid_observed`, `checked_bundle_observed`, `encode_entries`) are named by
  the one export line only. wc-004's imports of the checked bundle and the name
  signature are allowed. If git cannot run, it fails.

`tools/bundle`, in `tests/bundle.rs`:

- `tools_bundle_builds_a_new_bundle_and_prints_its_lab_cid` — the one test
  that spawns the real wrapper. A fresh OUT_DIR gives one stdout line, equal to
  `bundle_identity(OUT_DIR/bundle)` and to the reference lab CID; the bundle
  holds exactly the two regular files; `capsule.wasm`'s sha256 is the
  receipt's `artifact_sha256` and the pinned `6dd9af1a…`; `capsule.json` is
  `CAPSULE_MANIFEST`; `--name` prints the same name. Then the same OUT_DIR
  again, an empty folder for `--name` (the shared reason, unchanged) and
  `--unknown` are each refused with the right status, the path and reason on
  stderr, and an empty stdout.
- `tools_bundle_name_mode_prints_the_lab_cid` — in-process, on this capsule's
  manifest and the 8-byte module: 010's pinned vector.
- `bundle_arguments_are_refused_with_their_reason` — every argument rule's
  exact reason.
- `bundle_arguments_preserve_non_utf8_paths` — both modes keep every byte.
- `an_existing_out_dir_is_refused_and_nothing_is_written` — a folder, a file
  and a link to a sentinel folder; the sentinel stays byte-identical.
- `a_link_planted_during_the_build_is_never_written_through` — a link at
  `OUT_DIR/bundle` to a sentinel folder, and a link at `OUT_DIR/capsule.wasm` to
  a sentinel file (the shared link reason); both sentinels stay unchanged.
- `a_failed_build_is_refused_with_its_cause` — exit status 3 and a missing
  script give two different reasons.
- `bundle_io_refusals_keep_path_and_cause` — OUT_DIR, `bundle/`, the
  manifest's creation and write, and the module's move each keep their path
  and the system's cause.

The verifier, in `tests/verify.rs`. "The fixture" is this capsule's manifest
and the 8-byte module in a temp folder; every key is fresh in memory:

- `signed_bundle_verifies_against_its_key` — the fixture, signed and verified
  with its key's DID accepted and no grants, passes; `cid()` is
  `bundle_identity` of the folder, `imports()` is empty, `entries()` hold
  exactly the folder's two files.
- `unsigned_bundle_is_refused` — `None` gets the unsigned reason, in both
  forms.
- `bundle_signed_by_an_unlisted_key_is_refused` — key B signs, only key A is
  accepted, and an empty list: the identity lane's accepted-list refusal.
- `wasm_changed_after_signing_is_refused`,
  `manifest_changed_after_signing_is_refused` (one `description` byte) and
  `extra_file_after_signing_is_refused` — the identity lane's mismatch
  refusal, naming both values.
- `bundle_with_undeclared_import_is_refused_even_if_signed` — a module that
  imports `env.f`, validly signed, no grants: `undeclared import env.f`.
- `a_grant_reaches_the_audit_unchanged` — `env.f` granted passes, and
  `imports()` is the audit's own list, `[env.f]`.
- `verifier_audits_the_checked_bytes` — a held `CheckedBundle` still passes
  with no imports after `capsule.wasm` on disk becomes the importing module;
  `verify_bundle` on the changed folder gets the mismatch refusal.
- `the_real_capsule_passes_the_verifier` — the capsule `tools/build` makes,
  bundled with this capsule's manifest, signed and verified with no grants,
  passes with no imports; its sha256 is the receipt's `artifact_sha256` and
  the pinned `6dd9af1a…`.
- `missing_entrypoint_is_refused` — an entrypoint no entry has gets its own
  reason; `capsule.wasm` beside it does not stand in.
- `verifier_uses_manifest_entrypoint` — with the entrypoint `main.wasm` (the
  importing module) beside the 8-byte `capsule.wasm`, the audit reads
  `main.wasm`.
- `verified_entrypoint_is_the_audited_module` — in that same layout,
  `entrypoint()` is the checked `main.wasm` entry itself (its path, its bytes,
  and the audit of it gives `imports()`), not `capsule.wasm`.
- `verifier_preserves_upstream_refusals` — the walk's (no manifest, a link),
  the signature check's (a malformed DID, a name that is not a lab CID, a
  signature that does not verify) and the audit's (a malformed module, code in
  a custom section) refusals each come back equal to the owning lane's own,
  with the same text.
- `verifier_preserves_check_order` — inputs with two faults each: the walk
  before unsigned, unsigned before the audit, the signature before the
  entrypoint and the audit, the name before the audit.
- `verified_bundle_is_sealed` — the source, comments stripped: no public
  field, exactly six public functions (`verify_checked`, `verify_bundle` and
  the four accessors), no `&mut self`, no `Deserialize`, `Default` or trait
  impl for the value, and one literal that makes it, in `verify_checked`.
- `verifier_has_one_check_path` — the tools crate calls
  `verify_checked_signature` once and `audit` once, parses a manifest once
  (one `from_slice`, one call of `manifest_entrypoint`), uses neither
  `verify_name_signature` nor `audit_component`, `verify_bundle` only walks
  and delegates, and `entrypoint()` reads no manifest.
- `verifier_uses_audit_api_v1` — `wasm_capsule_audit::AUDIT_API` is 1.
- `verifier_has_no_import_parser_of_its_own` — `tools/Cargo.toml` and
  `tools/src`, comments stripped, name no `wasmparser`.
- `verifier_reads_no_bundle_file_by_path` — the verifier, comments stripped,
  has no `fs::read`, `File::open`, `OpenOptions`, `read_dir`, `metadata` or
  `read_to_end`.
- `no_key_material_is_tracked_in_the_lane` — every file `git ls-files
  --cached --others --exclude-standard -z` lists in the lane: no `.key` or
  `.seed` name, no PEM private-key line, no 32-byte file that is not UTF-8.
  The name is checked before any read, and a listed file that cannot be read
  is a finding with its path and cause, never skipped: a key file still in
  git's index but gone from the worktree fails the scan. Four planted items, in
  memory, are each reported, and so is a listed file that is absent (a `.seed`
  by name and as unreadable). If git cannot run, it fails.
- `key_and_seed_files_are_ignored_by_git` — `git check-ignore` reports
  `x.key`, `tools/x.key`, `x.seed` and `tools/x.seed`. `*.key` is the root
  `.gitignore`'s rule; `*.seed` is this lane's (`.gitignore`). If git cannot
  run, it fails.

The runner, in `tests/run.rs`. Stand-in engines are shell scripts written into
each test's own temp dir; work roots are the temp dir's canonical path (macOS
puts it under the `/var` link):

- `run_writes_only_the_verified_entrypoint_bytes` — the bundle's
  `capsule.wasm` is changed on disk after verification; a stand-in that prints
  the file it was given prints the verified bytes, the run folder holds exactly
  `module.wasm`, and the work root holds only the bundle and the run folder.
- `engine_path_must_be_absolute` — `./wasmtime`, `wasmtime` and
  `engines/wasmtime` are refused with their own reason; nothing is written.
- `work_root_must_be_absolute_and_canonical` — `work`, `--env=X` and `./work`
  (relative), and a root through a folder link, a link plus `.`, a `..` and a
  trailing `/` (not canonical) are each refused with their own reason; nothing
  is written and no engine starts.
- `run_directory_is_private_and_new` — the run folder's mode is `0o700`; a
  second run in the same root and a planted folder at a run folder's name are
  each refused, the folder is unchanged, and no engine starts.
- `runner_io_refusals_keep_path_and_cause` — a missing root (`NotFound`), a
  root that is a file, and a root the user may not write (`PermissionDenied`
  on the run folder) each keep their path and cause; the shared writer's
  create and write refusals become the runner's own two reasons with path and
  cause kept, and another writer reason is carried unchanged.
- `runner_passes_no_directory_env_or_network_flags` — an **argv proof**, not
  behaviour: for each engine, a stand-in prints its argv, which is exactly
  `run`, `--invoke`, `digest`, the absolute module path and `1592590337`
  (`FIXED_INPUT`), with no `--dir`, `--mapdir`, `--env` or `--net`.
- `engine_starts_with_an_empty_environment` — a stand-in sees no `HOME`,
  which the test process has.
- `engine_failures_keep_their_cause` — a stand-in that exits 3 with a stderr
  line gives the engine, the status and that line; a missing program gives the
  OS error. Two different reasons, for each engine, through `run_engine`.
- `each_engine_prints_the_fixed_output` — the capsule `tools/build` makes,
  bundled, signed and verified, run on the real `wasmtime` and `wasmer` found
  on PATH: each prints `230101071268130872` (`FIXED_OUTPUT`) for `1592590337`.
  An engine not found prints `SKIPPED` and gives no result, never a PASS.
- `runner_uses_only_explicit_inputs` — the runner's source, comments
  stripped: no environment read, no file read, no manifest or module parse, no
  walk or lower-level verify call, exactly one `verify_bundle` call (task 015's
  `run`, with no grants), and `entrypoint()` is its one source of module bytes.
- `runner_reuses_shared_writer` — the runner writes through
  `bundle::write_new_file` once and has no writer of its own (`OpenOptions`,
  `fs::write`, `create_new` and the like).

The two-engine runner (task 015), in `tests/run.rs`. Each test signs its bundle
in memory with a fresh key; stand-in engines are shell scripts as above, and
from task 016 each one `run` starts answers `--version` on its own branch,
apart from its module run (a marking stand-in leaves one marker for a version
query and another for a module run):

- `same_name_same_output_on_wasmtime_and_wasmer` — the capsule `tools/build`
  makes, bundled, signed and run through `run` on the real `wasmtime` and
  `wasmer` found on PATH: both stdouts are exactly `230101071268130872\n`
  (`FIXED_OUTPUT` for `FIXED_INPUT`), the returned `cid()` is the bundle's lab
  CID, and the work root holds the two run folders. If either engine is not
  found it prints `SKIPPED` and gives no result, never a PASS.
- `runner_refuses_an_unverified_bundle` — an unsigned bundle and a bundle
  signed by a key not on the accepted list: each is refused with exactly the
  verifier's own refusal and text, the work root stays empty, and marking
  stand-ins prove no engine started, not even for `--version` (task 016).
- `differing_engine_outputs_are_reported_as_a_failure` — `1\n` against `2\n`,
  and `7\n` against `7`: each is refused, naming both outputs, with both raw
  outputs kept.
- `matching_engine_failures_are_refused` — both stand-ins fail the same way
  (exit 3, the same stderr, empty stdout): the run is refused with
  `wasmtime`'s own failure, path and cause, and `wasmer` is not started.
- `runner_preserves_engine_refusals` — `wasmtime`'s module run fails,
  `wasmer`'s fails, and a folder planted at `wasmer`'s run folder name: each
  comes back as `run_engine`'s refusal, unchanged, and nothing starts after it.
  A missing program is now refused at its version query, before any module
  run (`version_query_failures_keep_their_cause`, task 016).
- `runner_calls_engines_in_order` — recording stand-ins log their version
  query, and their start (with the module path they were given), wait, and log
  their end: the log is both version queries, `wasmtime` then `wasmer`, then
  `wasmtime` start and end, then `wasmer` start and end, each with its own
  `<work root>/<engine>/module.wasm`, and both run folders hold the verified
  bytes.
- `run_returns_the_verified_name_and_both_outputs` — the `wasmtime` stand-in
  changes the bundle's `capsule.wasm` while it runs; `run` still returns the
  lab CID it verified, not the changed folder's, and both raw outputs.

The run receipt (task 016), in `tests/run.rs`:

- `receipt_records_observed_engine_versions` — two runs of one bundle by
  stand-ins that print made-up versions (each with a second line): the run
  holds exactly those first lines, never 45.0.1 or 7.5.0, and `render` gives
  the whole receipt exactly (schema, the verified lab CID, `digest`,
  `1592590337`, both versions, both `exit status: 0` and both stdouts). Both
  runs have the same lab CID, which holds no version number.
- `version_query_failures_keep_their_cause` — for each engine, a version
  query that exits 4 with a stderr line, prints nothing, prints an empty first
  line, or whose program is missing: each is refused with its own reason,
  engine and cause (exact text), no module run starts, nothing is written,
  `wasmtime` is asked first and `wasmer` is not asked after it is refused.
- `version_queries_use_explicit_inputs` — each stand-in's version answer is
  its `$0`, `HOME` and whether its stdin is `/dev/null`: the run keeps
  `<absolute program> unset null` for both. A relative program for either
  engine is refused with the module run's own reason, and no module run starts.
- `receipt_write_refuses_an_existing_path` — the receipt is written once,
  byte for byte; then the same path, a planted file, a live link and a
  dangling link are each refused with `write_new_file`'s own reason and cause
  (equal to the writer's own refusal for that path), the bytes and links stay
  unchanged, and nothing is written through the dangling link.
- `real_receipt_names_both_installed_engines` — the real `wasmtime` and
  `wasmer` found on PATH: the versions start with `wasmtime ` and `wasmer `,
  each is the first line the engine prints for `--version`, both stdouts are
  `FIXED_OUTPUT`, and the receipt written to a new file is `render`'s text. It
  prints the receipt. If either engine is not found it prints `SKIPPED` and
  gives no result, never a PASS.

## Falsifiers

`falsifiers.json` holds nine wc-001, seven task-010, 23 task-009, one task-012,
one task-017, 21 wc-004, four wc-008, 20 wc-005a (task 014), 11 wc-005b
(task 015) and 20 wc-005c (task 016) planted bugs in the provider format (`command: "lab"`). Each requires
all its named tests to fail at an assertion. The canonical runner
`examples/agent-host/falsify.py` now has a `lab` command (`cargo test
--workspace` on this workspace), but its recovery targets (`PROVIDER_TARGETS`)
still name the retired `tools/src/lab_name.rs` and none of `tools/src/lib.rs`,
`tools/src/bundle.rs`, `tools/src/verify.rs`, `capsule/capsule.json`,
`tests/common/build.rs`, `.gitignore` or `README.md`, so a killed run cannot
restore those files (ask **R1**, pending). So each falsifier is proved by the
repo's break → named test fails → revert method with `cargo test` in this
workspace, and is listed as hand-proven, pending R1. Runner-caught: one,
task 012's F-WC3-CREATE-NEW (below).

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

Task 009's 23, each hand-proven, pending R1 (every named test failed at its
assertion with the bug in, and passed again after the revert):

- F-WC3-CMD-BYPASS — the command names `capsule.wasm` alone with the shared
  encoder, not the bundle with `bundle_identity`.
- F-WC3-REUSE-OUT — `create_dir_all` for OUT_DIR, so an existing one is used.
- F-WC3-FOLLOW-WRITE — `create_dir_all` for `bundle/`, so a planted link is
  followed.
- F-WC3-MODULE-COPY — `fs::copy` instead of `rename`, so a linked file's bytes
  enter the bundle.
- F-WC3-ARGS-UNKNOWN, -ARGS-MISSING, -ARGS-NONE, -ARGS-EXTRA and -ARGS-EMPTY —
  each argument rule falls back to the usage line only.
- F-WC3-ARGS-UTF8 — a lossy UTF-8 conversion loses a path's bytes.
- F-WC3-BUILD-CAUSE — both build failures give one shared reason.
- F-WC3-BUILD-STDOUT — `tools/build`'s stdout reaches the command's stdout.
- F-WC3-IO-PATH — a run refusal drops its path.
- F-WC3-IO-MOVE-PATH — a failed move names the destination, not the module.
- F-WC3-IO-CAUSE-OUT, -BUNDLE, -MANIFEST, -WRITE and -MOVE — each I/O refusal
  drops the system's cause.
- F-WC3-CMD-REASON — `bundle_identity`'s refusal is replaced by the command's
  own text.
- F-WC3-CMD-STATUS — a run refusal exits 2.
- F-WC3-CMD-STDOUT — a run refusal goes to stdout.
- F-WC3-ARTIFACT-PIN — the capsule source changes, so `tools/build` makes
  another module with a matching receipt; only the pinned sha256 catches it.

Task 012's one, runner-caught (the canonical runner run
`python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC3-CREATE-NEW`
reported `summary: 1 CAUGHT of 1` and restored `tools/src/bundle.rs`; by hand,
the named test failed at its assertion with the bug in and passed after the
revert). `tools/src/bundle.rs` is still not a recovery target, so a killed run
cannot restore it:

- F-WC3-CREATE-NEW — `capsule.json` is opened with `create` and `truncate`
  instead of `create_new`, so an existing file or a link at its path is written
  over or through. `bundle_io_refusals_keep_path_and_cause` fails at its
  `expect_err("an entry is there")`.

Task 017's one, runner-caught (the canonical runner reported
`summary: 3 CAUGHT of 3` for it, F-WC3-SECOND-RULE and F-WC3-SECOND-IMPORT):

- F-WC3-RETIRED-LABEL-DOC — a line holding the retired name label is appended
  to `LOG.md`. `the_lane_keeps_no_bundle_name_rule_of_its_own` fails at its
  `found.is_empty()` assertion and names the line as `LOG.md:<line>`.

wc-004's 21, each hand-proven, pending R1 (every named test failed at its
assertion with the bug in, and passed again after the revert). Task 010's
F-WC3-SECOND-IMPORT and F-WC3-SECOND-RULE were proved again against the
updated `the_lane_keeps_no_bundle_name_rule_of_its_own`.

- F-WC4a — the verifier skips `verify_checked_signature` and trusts the
  signature's `name`: changed bytes, a changed manifest and an extra file pass
  or reach the audit.
- F-WC4b — a `None` signature passes.
- F-WC4c — the verifier skips the `audit` call.
- F-WC4d — the path form audits `capsule.wasm` read again by its path.
- F-WC4e — the verifier passes an empty list to `audit`, not the caller's
  grants.
- F-WC4f — `*.seed` is removed from the lane's `.gitignore`.
- F-WC4g — a PEM private-key header line is appended to this README.
- F-WC4-SCAN-SKIP-MISSING — the key scan skips a listed file that is gone
  from the worktree but still in git's index.
- F-WC4-SCAN-NAME-AFTER-READ — the key scan checks a listed name only after
  the file reads.
- F-WC4-ENTRY-SUBSTITUTE — a missing entrypoint falls back to another bundled
  module.
- F-WC4-ENTRY-HARDCODED — the verifier audits `capsule.wasm`, not the
  manifest's entrypoint.
- F-WC4-WALK-REASON, -SIG-REASON and -AUDIT-REASON — the walk's, the signature
  check's or the audit's refusal is replaced by another reason.
- F-WC4-ORDER-AUDIT-FIRST — the audit runs before the signature check.
- F-WC4-ORDER-UNSIGNED-FIRST — the path form refuses an unsigned bundle before
  the walk.
- F-WC4-SEALED-FIELD, -SEALED-NEW and -SEALED-MUT — a public field, a public
  constructor, or mutable access to the verified value.
- F-WC4-SECOND-SIG and F-WC4-SECOND-AUDIT — a second signature check or a
  second audit call in the tools crate.

wc-008's four, and one reused entry, each hand-proven, pending R1 (every named
test failed at its assertion with the bug in, and passed again after the
revert). They are not in the runner-caught count. A canonical runner run,
`python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC8 F-WC3-LABCID-PIN`,
reported `summary: 5 CAUGHT of 5`; it stays pending R1 (the recovery targets
name neither `capsule/capsule.json` nor `tools/src/lib.rs`), not a PASS.

- F-WC8-UNKNOWN-FIELD — hand-proven, pending R1. The committed manifest gains
  `"lab_imports": []`: `lab_manifest_passes_runtime_validate` fails with the
  Runtime's "unknown field `lab_imports`" error, and
  `this_capsule_bundle_has_the_pinned_lab_cid` fails too.
- F-WC8-NEAR-FIT — hand-proven, pending R1. The committed manifest declares
  `runtime_abi` `elastos.component/v1`: the Runtime refuses a Component ABI
  without Component metadata (`lab_manifest_passes_runtime_validate`), and
  `no_runtime_abi_names_a_bare_core_module` sees the manifest is no longer bare.
- F-WC8-INVALID-BASELINE — hand-proven, pending R1. The committed manifest
  gains `execution` `component`, so six ABIs are refused for the manifest's
  fault, not their own rule: `no_runtime_abi_names_a_bare_core_module` fails
  at its exact-reason check, and `lab_manifest_passes_runtime_validate` fails.
- F-WC8-NAME-WITHOUT-MANIFEST — hand-proven, pending R1. The tools crate's
  `bundle_identity` names the two files with the shared encoder and skips the
  Runtime's manifest check: `an_unknown_manifest_field_is_refused_by_name`
  sees the `lab_imports` bundle named, not refused.
- F-WC3-LABCID-PIN (task 010's, reused, counted once) — hand-proven, pending
  R1. It is the proof of "changing one manifest byte changes the lab CID":
  one `description` byte changes, and
  `this_capsule_bundle_has_the_pinned_lab_cid` fails. wc-008 adds no second
  entry for it (F-WC8-ONE-BYTE).

wc-005a's 23 (task 014), runner-caught. The canonical runner run
`python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC5 F-WC4`
reported `summary: 44 CAUGHT of 44` (these 23 and wc-004's 21, re-run because
`tools/src/verify.rs` changed), exit 0, and restored every file. Each named test
passed unmutated first. `tools/src/run.rs` is not in the runner's recovery
targets (`PROVIDER_TARGETS`, the provider lane's), so a killed run cannot
restore it for the F-WC5 entries (ask R2):

- F-WC5c — the runner adds `--dir .` to the argv
  (`runner_passes_no_directory_env_or_network_flags`).
- F-WC5d — the runner passes `--env WC5=1 --dir .` to `wasmer` only (the same
  test, on its `wasmer` run).
- F-WC5-DISK-REREAD — the runner writes the bundle's module read again from
  disk, not `entrypoint()`'s bytes (`run_writes_only_the_verified_entrypoint_bytes`
  sees the changed bytes; `runner_uses_only_explicit_inputs` sees the read).
- F-WC5-RELATIVE-ENGINE — the absolute-path check is removed
  (`engine_path_must_be_absolute`).
- F-WC5-WORK-ROOT-LINK — the canonical check is removed
  (`work_root_must_be_absolute_and_canonical`).
- F-WC5-RUN-DIR-MODE and F-WC5-RUN-DIR-REUSE — the run folder is made `0o755`,
  or an existing one is reused by a recursive create
  (`run_directory_is_private_and_new`).
- F-WC5-IO-ROOT-CAUSE, -IO-RUN-DIR-CAUSE, -IO-MODULE-CREATE, -IO-MODULE-WRITE
  and -IO-MODULE-PATH — the work root's, the run folder's, or the module file's
  refusal loses its cause or path (`runner_io_refusals_keep_path_and_cause`).
- F-WC5-IO-ROOT-METADATA and -IO-ROOT-IS-DIR — a failed metadata read of the
  work root is reported as "not a folder", in `work_root_folder` or by a
  `Path::is_dir` check in its place (`runner_io_refusals_keep_path_and_cause`).
- F-WC5-STDIN-PIPED — the engine's stdin is a pipe, not `/dev/null`
  (`engine_stdin_is_null`).
- F-WC5-ENV-READ — the engine program comes from an environment variable when
  set (`runner_uses_only_explicit_inputs`).
- F-WC5-LOCAL-WRITER — the module is written with `fs::write`, not the shared
  writer (`runner_reuses_shared_writer`).
- F-WC5-ENGINE-ENV — the engine inherits the test process's environment
  (`engine_starts_with_an_empty_environment`).
- F-WC5-FAIL-STDERR, -START-CAUSE and -EXIT-IGNORED — a failed engine's
  stderr is dropped, a start failure loses its OS error, or a nonzero exit is
  accepted (`engine_failures_keep_their_cause`).
- F-WC4-ENTRYPOINT-ACCESSOR — `entrypoint()` returns `capsule.wasm`, not the
  manifest's entrypoint (`verified_entrypoint_is_the_audited_module`).
- F-WC4-ENTRYPOINT-REPARSE — `entrypoint()` reads the manifest again
  (`verifier_has_one_check_path`).

Task 014 also re-anchored six wc-004 entries to the moved verifier code, each
the same bug as before: F-WC4-ENTRY-SUBSTITUTE, -ENTRY-HARDCODED,
-ORDER-AUDIT-FIRST, -SEALED-FIELD, -SEALED-NEW (now with the `entrypoint`
field) and -SECOND-AUDIT. All six are in the 44 above.

wc-005b's 11 (task 015), runner-caught. The canonical runner run
`python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC5 F-WC4`
reported `summary: 55 CAUGHT of 55` (these 11, wc-005a's 21 F-WC5 entries and
the 23 F-WC4 entries), exit 0, with every named test passing unmutated first
(its baseline line) and no backup left. Both engines were found on PATH, so
F-WC5-BOTH-ARGS ran; on a machine without both, the real-engine test prints
`SKIPPED` and passes, so leave F-WC5-BOTH-ARGS out of the run and report it
NOT RUN. `tools/src/run.rs` is still not a recovery target (ask R2):

- F-WC5a — `run` skips `verify_bundle` and starts both engines on the bundle's
  `capsule.wasm` from disk (`runner_refuses_an_unverified_bundle` sees the
  engines start; `runner_uses_only_explicit_inputs` sees no verify call).
- F-WC5b — `run` compares only exit statuses, not stdout
  (`differing_engine_outputs_are_reported_as_a_failure`).
- F-WC5-EQUAL-FAILURES — a failed exit is taken as an empty stdout, so two
  equal failures compare equal and pass (`matching_engine_failures_are_refused`).
- F-WC5-BOTH-ARGS — the fixed argument becomes `1` for both engines: equal but
  wrong output (`same_name_same_output_on_wasmtime_and_wasmer`, at its
  `FIXED_OUTPUT` assertion).
- F-WC5-VERIFY-TWICE — `run` calls `verify_bundle` a second time
  (`runner_uses_only_explicit_inputs`).
- F-WC5-WASMTIME-REFUSAL-DROPPED and -WASMER-REFUSAL-DROPPED — an engine's
  refusal is discarded and its stdout taken as empty
  (`runner_preserves_engine_refusals`).
- F-WC5-ENGINES-REVERSED, -ENGINES-OVERLAP and -BYPASS-RUN-ENGINE — `wasmer`
  runs first, both run at once on two threads, or `wasmer` is started on the
  bundle's module path without `run_engine` (`runner_calls_engines_in_order`).
- F-WC5-OTHER-CID — the returned name is the folder named again after the run,
  not the verified value's (`run_returns_the_verified_name_and_both_outputs`).

wc-005c's 20 (task 016), runner-caught. The canonical runner run
`python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC5`
reported `summary: 52 CAUGHT of 52` (these 20, wc-005a's 21 F-WC5 entries and
wc-005b's 11, re-run because `tools/src/run.rs` changed), exit 0, with its
baseline line `baseline: 22 named tests pass without an edit, 0 do not` and no
backup left. Both engines were found on PATH, so F-WC5-BOTH-ARGS ran.
Neither `tools/src/run.rs` nor `tools/src/receipt.rs` is a recovery target, so
a killed run cannot restore them (ask R2):

- F-WC5-HARDCODED-VERSIONS — the receipt prints this Mac's installed versions,
  not what the engines printed (`receipt_records_observed_engine_versions`).
- F-WC5-VERSION-CAUSE, -VERSION-START-CAUSE and -VERSION-STDERR — a nonzero
  query becomes the generic empty-version reason, a start failure loses its OS
  error, or the stderr is dropped (`version_query_failures_keep_their_cause`).
- F-WC5-VERSION-EMPTY-ACCEPTED — an empty first line is taken as the version
  (`version_query_failures_keep_their_cause`).
- F-WC5-VERSION-WHOLE-STDOUT — the whole stdout is kept, not its first line
  (`receipt_records_observed_engine_versions` and
  `version_query_failures_keep_their_cause`).
- F-WC5-QUERY-BEFORE-VERIFY — the queries run before `verify_bundle`
  (`runner_refuses_an_unverified_bundle` sees a version marker).
- F-WC5-VERSION-AFTER-RUN — the queries run after both module runs
  (`version_query_failures_keep_their_cause` and `runner_calls_engines_in_order`).
- F-WC5-VERSION-RELATIVE, -VERSION-ENV and -VERSION-STDIN — the query skips
  the absolute-path check, is started without `engine_command` and inherits the
  environment, or gets a piped stdin (`version_queries_use_explicit_inputs`).
- F-WC5-RECEIPT-OVERWRITE — the receipt is written with `fs::write` (create +
  truncate) (`receipt_write_refuses_an_existing_path`).
- F-WC5-RECEIPT-CAUSE — the writer's refusal is replaced by another reason
  (`receipt_write_refuses_an_existing_path`).
- F-WC5-RECEIPT-SCHEMA, -CID, -FUNCTION, -ARGUMENT, -VERSION-SWAP, -STATUS and
  -STDOUT — one receipt field is tampered with
  (`receipt_records_observed_engine_versions`).

Task 016 also re-anchored four entries, each the same bug as before, all in the
52 above: F-WC5-ENGINE-ENV and F-WC5-STDIN-PIPED (the empty environment and
null stdin moved into `engine_command`, shared by the module run and the
version query), F-WC5a (the queries now sit between verification and the
module runs, so its one edit became two) and F-WC5-EQUAL-FAILURES (`run_engine`
returns an `EngineRun`, so the planted empty result is `EngineRun::default()`).
No falsifier plants a fixed exit status: a passing run always exited 0, so a
hard-coded 0 would print the same text and no test could tell them apart.
