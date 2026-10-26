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

The runner (`tools/src/run.rs`) starts two host engines. Rong's ruling (26 Oct):
Both engines, wasmtime and wasmer, are test-only and not endorsed. The engine choice is Anders's.

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
`CARGO_HOME` and the toolchain sysroot. Since task 032 it also passes
`-Clink-arg=--max-memory=67108864`, so the capsule declares its own memory
maximum, 1024 pages ("Module memory maximum discovery (wc-010d0)", "The capsule
declares its maximum (task 032)").

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
- `capsule.wasm` sha256 (both builds): `2002429e73ee1a5e983df008f5b53728882646f109d55a9d1a93e831690631e1`
  (27 Oct 2026, re-pinned by task 032: two `tools/build` builds and a
  `python3 -I` `hashlib` recomputation agree, LOG.md task 032; it was
  `6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13`, 178
  bytes, with no memory maximum)
- size: 180 bytes (one memory: minimum 16 pages, maximum 1024 pages)

On this stripped, zero-dependency release cdylib nothing absolute leaks, so
`--remap-path-prefix` is defensive (it would neutralise a leak from debug info
or a dependency). F-WC1 is realised by embedding `env!("CARGO_MANIFEST_DIR")`,
an absolute path `--remap-path-prefix` does not rewrite, which is why the two
builds then differ.

## The lab name: cc-capsule-identity's lab CID

### What a lab bundle is

A lab bundle of this capsule is a folder holding this capsule's manifest as
`capsule.json` and the module as `capsule.wasm`. Its name is
cc-capsule-identity's **lab CID**: the CIDv1 SHA-256 UnixFS directory root of
the bundle, printed as 59 characters that start `bafybei` (that lane's task
018 swapped the printed form to this root; the rules are in
`lab/capsule-identity/README.md`, "The encoding"). The lab CID covers every regular file in the folder, so a file added beside the two
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

The direction is cc-capsule-identity's too. Anders proposed a CIDv1 SHA-256
UnixFS directory root as the bundle identity, and that lane's task 018 made
`lab_cid` print it; `bundle_identity` needed no change. The root is still a
prototype: that lane owns it, and its reproducibility tests are the gate before
that profile is frozen. It also owns the separate signed record kept outside
the package. This lane keeps one identity path: no UnixFS code, fallback or
choice of rule of its own. When a test needs to read a printed lab CID, it uses
that lane's one parse (`str::parse::<capsule_identity::LabCid>`), never a
format check of its own.

### A lab CID, not a CID

The lab CID is a lab value. It is not the Runtime's CID: the Runtime names a
published capsule by the CID its IPFS provider gets for the capsule archive
(ADOPTION.md, the wc-003 discovery). No Runtime admission or launch path reads a
lab CID.

This lane's pinned vector, `MODULE_BUNDLE_LAB_CID` in `tests/common/mod.rs`,
used by `this_capsule_bundle_has_the_pinned_lab_cid` and
`tools_bundle_name_mode_prints_the_lab_cid`: the bundle of this capsule's
277-byte `capsule/capsule.json` and the 8-byte empty module
`00 61 73 6d 01 00 00 00` is

```
bafybeihtyzfql54i7irft23lg2mk44toqdww53ryuhs2psrknfjw4qhpcy
```

Task 024 recomputed it outside the lab code, with a `python3 -I` script
(standard library only) written from cc-capsule-identity's README rules, not
from its Rust code. The script first gave that lane's committed
`content-sample` pin, and a different value after one byte of that fixture
changed. It was pinned only because it equals what `bundle_identity` prints for
the same folder. The script is not committed; LOG quotes its full text and the
runs. It also guards this lane: if the shared rule changes under it, this test
fails.

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
Task 018: `lane_files_reads_names_git_would_quote` lists a temp git repo
holding `review"note.md`; dropping `-z` fails it (runner-caught as
F-WC3-LANE-FILES-QUOTED, task 029; counted in "## Falsifiers").

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

**Reference lab CID on this Mac** (2026-10-27, re-pinned by task 032), for
this capsule's 277-byte manifest beside `capsule.wasm`
`2002429e73ee1a5e983df008f5b53728882646f109d55a9d1a93e831690631e1`:

```
bafybeiebyzg55l4s6kb6daroty4prlkximwp6uvo32ovacfzdx7cahywqm
```

`tools_bundle_builds_a_new_bundle_and_prints_its_lab_cid` pins it
(`REFERENCE_LAB_CID`). Task 024 recomputed it with the same outside
`python3 -I` script, over the bundle `tools/bundle` wrote on this Mac, and
pinned it only because it equals what `bundle_identity` prints for that folder.
Task 032 did the same for the new `capsule.wasm` (LOG.md, task 032); the value
before it was `bafybeib34owcqffbwkntlhvbjngcj7eyeqqxx7aoefehqt2dqm2yu5jwse`.
It is a lab CID, not the Runtime's CID.

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

**One call, five checks, in order.** `verify_checked` takes a
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
   bytes;
5. since task 031, each import on the audit's returned list has a typed entry
   in `LAB_OPERATIONS` ("Typed lab operations (M1 B4 lab half)", below).

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
  `code in custom section`), carried unchanged;
- a granted import with no typed lab operation (task 031):
  `no typed lab operation for import <module>.<name>`.

A fifth reason, `the Runtime's CapsuleManifest could not read the checked
capsule.json: <reason>`, cannot happen for a value `checked_bundle` made: the
walk runs the same parse and refuses first. It is kept so the verifier fails
closed with a reason rather than a panic, and no test can reach it.

**The value.** `VerifiedBundle` holds the checked bundle, which of its
entries is the entrypoint (found by step 3, the one manifest read) and the
audit's own import list, read through `cid()`, `entries()`, `entrypoint()` and
`imports()`; since wc-009a also the grants the module does not import, through
`unused_grants()`. `entrypoint()` returns the checked entry the manifest's
`entrypoint` names, the module the audit read, so no caller reads the manifest
again. Its fields are private, and it has no public constructor, no `&mut`
access and no `Deserialize`, so a value exists only as `verify_checked` made
it. wc-005a's runner (task 014) writes `entrypoint()`'s bytes.

**The checked bytes, never the folder again.** The audit reads the module
bytes the signed name covers, from the checked value. The verifier reads no
bundle file by a path; its one file read is the caller's lab grants file, in
`read_grants` (wc-009a, below), which is never part of the bundle. If the
folder changes after `checked_bundle`, `verify_checked`
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
result is exactly the module's imports. Since wc-009a (task 020) the two-engine
`run` passes the list `read_grants` read from the lab grants file to this same
call ("Granted imports only (wc-009a)", below). The granted list is a lab
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
test-only host engines, not endorsed.

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
    pub granted: &'a [DeclaredImport],          // wc-009a: from read_grants
    pub wasmtime: &'a Path,                     // absolute program paths
    pub wasmer: &'a Path,
    pub work_root: &'a Path,
}
```

A library function; there is no command, no binary and no signature file. Every
input is in the struct; nothing is read from the environment. In order, the
first refusal is the answer:

1. wc-004's `verify_bundle(input.bundle, input.signature, input.accepted, input.granted)`
   is called once, with the caller's granted imports unchanged (wc-009a). A
   refusal comes back unchanged as `TwoEngineRefusal::Verify`, printing exactly
   as the verifier prints it; nothing is written and no engine is started;
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
from task 016 each engine's observed `version(engine)` and `status(engine)`,
and from task 020 `linked()` and `unused_grants()`, the verifier's own lists.
Its fields are private, so only `run` makes one. `run` writes no receipt; the
caller writes one with `receipt::write_receipt` (next section).

**The claim.** On this Mac, the capsule `tools/build` makes, bundled, signed
with a fresh test key and verified, printed `230101071268130872`
(`FIXED_OUTPUT`) for `1592590337` (`FIXED_INPUT`) on both `wasmtime` 45.0.1 and
`wasmer` 7.5.0, byte for byte (`same_name_same_output_on_wasmtime_and_wasmer`).
This is a behaviour proof on one **core module** on this one Mac, not the
Component ABI. Both engines are test-only host engines, not endorsed.
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
`real_receipt_names_both_installed_engines` on 26 Oct 2026, task 028 (the
capsule `tools/build` makes, bundled, signed with a fresh test key, verified
and run on Homebrew's `/opt/homebrew/bin/wasmtime` and `/opt/homebrew/bin/wasmer`;
its `bundle` line re-pinned by task 032 on 27 Oct 2026: the test asserts
`bundle: <bundle_identity of the run's bundle>`, which holds the same two files
as `REFERENCE_LAB_CID`'s bundle; the other lines are task 028's):

```
schema: wc-005.run-receipt/v2
bundle: bafybeiebyzg55l4s6kb6daroty4prlkximwp6uvo32ovacfzdx7cahywqm
function: digest
argument: 1592590337
wasmtime_version: "wasmtime 45.0.1 (83166ba31 2026-06-05)"
wasmtime_status: exit status: 0
wasmtime_stdout: "230101071268130872\n"
wasmer_version: "wasmer 7.5.0"
wasmer_status: exit status: 0
wasmer_stdout: "230101071268130872\n"
memory_mb: 64
memory_cap_bytes: 67108864
wasmtime_memory_cap: ENFORCED max-memory-size=67108864,max-memories=1,trap-on-grow-failure=y
wasmer_memory_cap: SKIPPED: no memory cap flag in wasmer run --help or wasmer --help (wc-010a)
```

`bundle` is the verified `cid()`'s Display form, treated as opaque; it is the
pinned lab CID of this capsule's bundle, the reference value above (same
manifest, same `capsule.wasm`); every line is that run's. The engine versions sit beside it and
are no part of it: the same bundle run under other versions has the same name
(P15: the hash names the content; versions are provenance beside it).
`function` and `argument` are the runner's own `DIGEST_EXPORT` and
`DIGEST_ARGUMENT`, the values its argv passes. Quoted values are the printed
bytes through `escape_ascii`, so every byte is kept and no value can add a
line. The status is the module run's `ExitStatus` as the OS reported it; a
passing run always exited 0, because `run_engine` refuses any other status.

**The memory lines (wc-010c, task 028; schema v2).** After the v1 lines,
`render` adds, in this order:

- `memory_mb: <declared>`: the manifest's `resources.memory_mb` the module runs
  were given (this capsule declares no `resources`, so the Runtime's default 64);
- `memory_cap_bytes: <declared × 1048576>`, by the same conversion that makes
  `wasmtime`'s cap argument (no second MB to bytes rule);
- per engine, `wasmtime` then `wasmer`, `<engine>_memory_cap: ENFORCED
  <argument>` with the exact cap argument that engine's module run was started
  with, or `<engine>_memory_cap: SKIPPED: no memory cap flag in <engine> run
  --help or <engine> --help (wc-010a)` when it was started with none.

The cap argument is not configured beside the run: `start_engine` reads it back
from the argv the engine process was started with (the argument after `-W`),
so a receipt cannot say ENFORCED for an argv without the cap, and the line
never follows the engine's name or a constant. On this base `wasmtime` gets
`max-memory-size=<bytes>,max-memories=1,trap-on-grow-failure=y` and `wasmer`
gets none ("Memory cap (wc-010b)").

The receipt records no peak memory: `/usr/bin/time -l` gives the engine
process's resident memory, not the capsule's linear memory (wc-010a); which
number belongs here waits for Flint.

**Writing it.** `write_receipt` writes `render`'s text to a caller-given path
with the shared `bundle::write_new_file` (`create_new`). An existing file, a
live link or a dangling link at that path is refused with that writer's own
reason and cause, unchanged, and nothing at or behind the path changes. The
writer's text names `capsule.json`, its first use (`<path>: capsule.json cannot
be created: File exists (os error 17)`); the path before it is the receipt's.

**The claim, unchanged from task 015.** One core module, on this one Mac,
with both engines test-only and not endorsed; not the Component ABI. The
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

## Granted imports only (wc-009a)

```rust
wasm_capsule_tools::verify::read_grants(path: &Path) -> Result<Vec<DeclaredImport>, GrantsRefusal>
```

**The link rule, in Rong's words (W2 (c), through Flint, 26 Oct 08:27).** "The
module's own import section in the signed capsule.wasm IS the declaration; it is
in the lab-cid closure and covered by the signature, and cx-wasm-audit's cwa-001
import list is the one reader for it (P10). Link rule: link an import only if it
is in the signed module AND in the lab grants file; the grants file stays
outside the bundle, labelled 'lab stand-in, not admission'. No unsigned
declaration file."

So there is no declaration file here. The declaration is the module's own
import section, inside `capsule.wasm`, so inside the lab CID and under the
signature. The grants file is the caller's input, like the bundle path; it sits
outside the bundle and is never part of the lab CID.

**The grants file.** JSON, read once with `fs::read` and parsed from memory,
exactly (task 031 made it v2: each grant names a right):

```json
{"schema": "wc-009.lab-grants/v2", "label": "lab stand-in, not admission", "imports": [{"module": "env", "name": "f", "right": "call"}]}
```

An empty `imports` list is valid. A v1 file (grants with no `right`) is refused
by the schema check. The label is exactly "lab stand-in, not
admission": the file stands in for the Runtime's grant decision
(https://github.com/Elacity/elastos-runtime/issues/464), and is never
admission. `read_grants` returns the grants in file order, without their
rights. It is the one grants
reader and lives in `tools/src/verify.rs`, beside the verifier input it feeds;
no other code in the tools crate reads grants or imports. Each refusal has its
own reason, after `<path>: `:

- `the grants file cannot be read: <OS error>`;
- `the grants file is not JSON: <serde_json's reason>`;
- `the grants file is not a JSON object`;
- `the grants file has an unknown key "<key>"`;
- `the grants file has no "<schema|label|imports>" key`;
- `the grants file's schema is <value as JSON>, not "wc-009.lab-grants/v2"`;
- `the grants file's label is <value as JSON>, not "lab stand-in, not admission"`;
- `the grants file's imports is not a list`;
- `grant <index> is not an object of exactly three strings, module, name and right`;
- `the grant <module>.<name> is listed twice`;
- `the grant <module>.<name> names the right "<granted>", but its typed lab
  operation needs "<needed>"` (task 031: the grant of an import that has a
  typed lab operation names any right but the one it needs).

A key written twice in one JSON object is not refused: `serde_json` keeps its
last value, so the file reads as that value. This is a known limit of the lab
reader, not a claim.

**How it links.** The caller passes `read_grants`'s list as
`RunInput::granted`, and `run` passes it unchanged to its one `verify_bundle`
call, so to the verifier's one `audit(module, granted)` call. There is no
second import check, parser or walk. A module with an import that is not
granted is refused there, `undeclared import <module>.<name>`, and never
reaches an engine: no run folder is made and neither engine is started, not
even for `--version`. Task 031: a module import that is granted but has no
typed lab operation (below) is refused the same way, right after that `audit`
call, on the audit's own list, `no typed lab operation for import
<module>.<name>`. On success the run reports:

- `linked()`: the audit's own list, the imports both in the signed module and
  granted, in section order;
- `unused_grants()`: the grants the module does not import, in file order.
  They link nothing; they are reported. The verifier works them out once from
  the audit's list and the grants, with no second import read.

**Allowed through, not hosted (wc-009b).** The runner gives the engines no host
function of its own yet. A granted import is only let through verification; no
engine is given a function for it. This capsule has zero imports, so its run
needs none. Hosting a granted import in both engines is wc-009b, after this
task, and starts with a read-only discovery.

**Who decides (Q8, Flint, 26 Oct 10:40).** The Runtime's launch path verifies
the accepted record, the selected platform variant and the installed contents.
Those checks are Runtime work, outside this lane. The grants file is "lab
stand-in, not admission" everywhere: this lane decides no admission, launch or
publisher trust, and its lab name is not the Runtime's CID.

### Typed lab operations (M1 B4 lab half)

Task 031 (Flint, INBOX 26 Oct 23:50, "one permission model"). Each import the
lab runner can link is listed once as a typed operation in `pub const
LAB_OPERATIONS` (`tools/src/verify.rs`): its module and name, its inputs and
outputs (Wasm value type names), the one right a grant of it must name, and its
effect (`none`, `read` or `write`). It is the only copy of the table in code,
and `readme_lists_each_typed_lab_operation` fails if this list and the table
differ:

- `env.f`: inputs `()`, outputs `()`, right `call`, effect `none`

Two refusals use it, both before any engine starts:

- The grants reader, `read_grants`, refuses a grant whose `right` is not its
  operation's right (`env.f` granted `write`: `the grant env.f names the right
  "write", but its typed lab operation needs "call"`). A grant of an import
  with no typed operation names no needed right; it is read, and it links
  nothing unless the module imports it.
- The verifier, `verify_checked`, refuses a module import with no typed
  operation, even when granted: `no typed lab operation for import env.g`. The
  check runs on the audit's own returned list, right after the one `audit`
  call, so it reads no import of its own (P10), and a grant the module does
  not import stays an unused grant, reported as before. A module importing
  `env.g` with no grant is still refused by the audit first, `undeclared import
  env.g`.

No manifest field is added: the module's own import section stays the
declaration (https://github.com/Elacity/elastos-runtime/issues/464). The lab
does not check an import's Wasm type against its entry, since the audit's v1
API returns names only. The table and the grants are a lab stand-in, not
admission: input for Anders's typed-operations model, not the Runtime's rights
model.

## Memory cap discovery (wc-010a)

Read-only discovery for wc-010 ("fixed bare memory with a host-enforced
limit"). No runner, argv, receipt, test or `falsifiers.json` change; `run.rs`
still passes no memory flag. (26 Oct, task 027: no longer so; wc-010b gives
`wasmtime` the cap from the manifest, see "Memory cap (wc-010b)" below.) Facts are what each engine's CLI does on this Mac
only, at base `a5b4e8a105fca181469ce15b2b84c03b86f0266d`, with
`/opt/homebrew/bin/wasmtime --version` = `wasmtime 45.0.1 (83166ba31
2026-06-05)` and `/opt/homebrew/bin/wasmer --version` = `wasmer 7.5.0`. Each
engine ran as its own process from a shell (no engine inside an engine, no
VM, no Docker). This is not the ~4 GB DigitCapsule and not any-RTOS loading.

**The declared size.** `elastos/crates/elastos-common/src/manifest.rs` at this
base: `CapsuleManifest` has `#[serde(default)] pub resources: ResourceLimits`
(lines 102-103); `ResourceLimits` has `#[serde(default = "default_memory")]
pub memory_mb: u32` (lines 1167-1169), and `fn default_memory() -> u32 { 64 }`
(lines 1188-1190). `capsule/capsule.json` has no `resources` key
(`grep -n resources lab/wasm-capsule/capsule/capsule.json` prints nothing,
exit 1), so this capsule declares the default, 64 MB. The manifest does not say
whether MB is 10^6 or 2^20 bytes; the probes read it as 64 × 2^20 =
67108864 bytes = 1024 Wasm pages of 64 KiB. wc-010b must state the same
reading. No field was invented and `capsule.json` is unchanged.

**The probe modules** (WAT text under the git-ignored `target/wc010a/`, never
committed; both engines took the `.wat` file directly, so no `wat` crate step
was needed):

```wat
(module
  (memory (export "memory") 1)
  (func (export "grow") (param i32) (result i32)
    local.get 0
    memory.grow))
```

`grow.wat` starts at 1 page and has no declared maximum. `memory.grow` returns
the old size in pages (1) on success and -1 on failure. Growing by 1023 pages
reaches exactly 1024 pages (64 MB, at the cap); growing by 1024 reaches 1025
pages (67174400 bytes, past it). `big-min.wat` is
`(module (memory (export "memory") 1025) (func (export "size") (result i32) memory.size))`:
its own minimum is one page above the cap.

### wasmtime 45.0.1: FOUND

The flag, from `wasmtime -W help`:

```text
  -W                         max-memory-size=N -- Maximum size, in bytes, that a linear memory is allowed to reach.
  -W                trap-on-grow-failure[=y|n] -- Force a trap to be raised on `memory.grow` and `table.grow` failure instead of returning -1 from these instructions.
```

Unit: bytes, so 64 MB is `-W max-memory-size=67108864`. Runs from
`lab/wasm-capsule/target/wc010a/`, engine path `/opt/homebrew/bin/wasmtime`
(each first stderr line is the CLI's own `--invoke` warning, quoted as
printed):

| Run | Command | Exit | stdout | stderr |
|---|---|---|---|---|
| (i) within the cap | `wasmtime run -W max-memory-size=67108864 --invoke grow grow.wat 1023` | 0 | `1` | ``warning: using `--invoke` with a function that takes arguments is experimental and may break in the future`` |
| (ii) past the cap | `wasmtime run -W max-memory-size=67108864 --invoke grow grow.wat 1024` | 0 | `-1` | the same warning |
| (ii-t) past the cap, trap flag | `wasmtime run -W max-memory-size=67108864,trap-on-grow-failure=y --invoke grow grow.wat 1024` | 1 | (none) | the same warning, then ``Error: failed to run main module `grow.wat` `` and, last, `2: forcing trap when growing memory to 67174400 bytes` |
| (i-t) within the cap, trap flag | `wasmtime run -W max-memory-size=67108864,trap-on-grow-failure=y --invoke grow grow.wat 1023` | 0 | `1` | the same warning |
| (iii) past 64 MB, no flag | `wasmtime run --invoke grow grow.wat 1024` | 0 | `1` | the same warning |
| start, above-cap minimum | `wasmtime run -W max-memory-size=67108864 --invoke size big-min.wat` | 1 | (none) | ``Error: failed to run main module `big-min.wat` ``, then `0: failed to instantiate "big-min.wat"` and `1: memory minimum size of 1025 pages exceeds memory limits` |
| start, no flag | `wasmtime run --invoke size big-min.wat` | 0 | `1025` | ``warning: using `--invoke` with a function that returns values is experimental and may break in the future`` |

(iii) returning `1` where (ii) returned `-1`, on the same module and argument,
shows the flag, not the module, made the grow fail.

### wasmer 7.5.0: SKIPPED

No memory cap flag in its help. Searched `wasmer run --help` and
`wasmer --help` (both exit 0) case-insensitively for `memory`, `grow`, `trap`,
`limit`, `pages`, `max`, `heap`, `size`, `resource`, `rlimit` and `bytes`.
`wasmer --help` matched none. `wasmer run --help` matched only lines about
other things: `--enable-experimental-unaligned-memory-accesses`,
`--enable-bulk-memory`, `--enable-multi-memory`, `--enable-memory64` (Wasm
features), `--with-compact-on-growth` (journal compaction), a CPU back-off
"maximum amount of time", and `--stack-size <STACK_SIZE>` with "Set the default
stack size (default is 1048576)" (the stack, not linear memory). So this CLI
gives no way to cap a module's linear memory, and a cap cannot be claimed for
wasmer. The contrast and start runs, engine path `/opt/homebrew/bin/wasmer`,
from the same folder (stderr empty, 0 bytes, on each):

| Run | Command | Exit | stdout |
|---|---|---|---|
| (iii) past 64 MB, no flag | `wasmer run --invoke grow grow.wat 1024` | 0 | `1` |
| grow to 65536 pages (the wasm32 limit), no flag | `wasmer run --invoke grow grow.wat 65535` | 0 | `1` |
| start, above-cap minimum | `wasmer run --invoke size big-min.wat` | 0 | `1025` |

### The answer for wc-010b

- wasmtime: **grow returns -1** with `-W max-memory-size=67108864`; adding
  `-W trap-on-grow-failure=y` turns that -1 into a **trap** (exit 1,
  "forcing trap when growing memory to 67174400 bytes"); a module whose own
  minimum is above the cap is **start refused** ("memory minimum size of 1025
  pages exceeds memory limits").
- wasmer: **SKIPPED** (no memory cap flag in `wasmer run --help` or
  `wasmer --help`); no flag turns a failed grow into a trap, and with no cap
  the grow past 64 MB succeeds.
- The two engines differ. Rong's draft name
  `memory_grow_past_limit_traps_on_both` is not right: only wasmtime traps,
  and only with the extra flag. wc-010b's wasmer memory test must report
  SKIPPED with the reason above, never PASS.

**Peak memory for wc-010's receipt.** `/usr/bin/time -l` prints a "maximum
resident set size" line. This is the **engine process's resident memory**, not
the capsule's linear memory:

- `/usr/bin/time -l /opt/homebrew/bin/wasmtime run -W max-memory-size=67108864 --invoke grow grow.wat 1023`
  printed `            14696448  maximum resident set size` (and
  `             5538248  peak memory footprint`).
- `/usr/bin/time -l /opt/homebrew/bin/wasmer run --invoke grow grow.wat 1023`
  printed `            19218432  maximum resident set size` (and
  `             5374408  peak memory footprint`).

Both runs grew linear memory to 64 MB, yet each process's resident size is
below that: untouched pages are not resident. So this number is no measure of
the capsule's declared or used linear memory.

## Memory cap (wc-010b)

[Proposal] The claim, exactly: "a self-contained capsule in a fixed flat space
with a host-enforced cap", on wasmtime only, on this one Mac; not the ~4 GB
DigitCapsule, not any-RTOS loading. The memory flag is a test-only limit, never an engine choice; the engine choice is Anders's.
Phase 2 groundwork; it claims no spike grade row.

**The declared size.** The cap is the Runtime manifest's existing
`resources.memory_mb` (`CapsuleManifest.resources: ResourceLimits`,
`#[serde(default)]`; `memory_mb: u32`, default 64). No field is invented.
`tools/src/verify.rs`'s one manifest read (`manifest_entrypoint`, the one
`CapsuleManifest` parse) keeps it in the sealed `VerifiedBundle`, read through
one accessor, `memory_mb()`. The runner takes it from that value only, never
from a file or the environment. This capsule's `capsule.json` has no
`resources` key, so it declares the default, 64; `capsule.json` and the lab
CID pins are unchanged. The declared size is an allowance (a resource budget),
kept apart from identity (the lab CID) and from admission, which this lane
never decides.

**MB is read as 2^20 bytes**, as wc-010a's probes read it: the runner's cap is
`memory_mb × 1048576` bytes, in `u64`, so no `u32` overflows (`u32::MAX` MB is
4503599626321920 bytes). This capsule's 64 MB = 64 × 2^20 = 67108864 bytes =
1024 Wasm pages of 64 KiB.

**wasmtime 45.0.1: ENFORCED.** Its module run gets exactly one more argument
pair, after `run --invoke digest` and before the module path: `-W` and
`max-memory-size=<bytes>,max-memories=1,trap-on-grow-failure=y`. The unit is
bytes (`wasmtime -W help`, wc-010a). `max-memory-size` caps each linear
memory on its own, so the declared size is the capsule's whole linear memory
only with `max-memories=1` ("Maximum number of WebAssembly linear memories
allowed to be created", `wasmtime -W help`): a module with a second memory is
refused at start with "resource limit exceeded: memory count too high at 2"
(task 027 round 2, from the Codex review; the verifier's import audit accepts
such a module). With `trap-on-grow-failure=y` a `memory.grow`
past the cap traps (exit 1, "forcing trap when growing memory to 67174400
bytes") instead of returning -1, so the runner refuses the run with
`EngineFailed` and wasmtime's stderr. The `--version` query is unchanged.
Checked once by hand in this order before the code (LOG.md, task 027): `run
--invoke grow -W max-memory-size=67108864,trap-on-grow-failure=y grow.wat 1024`
exits 1 with that trap line, and `... 1023` exits 0 and prints `1`. Round 2,
by hand with `max-memories=1` added: the same two results, and the two-memory
module under a 2 MB cap exits 1 with the memory count line (exit 0 and `64`
without it).

**wasmer 7.5.0: SKIPPED.** No memory cap flag in `wasmer run --help` or
`wasmer --help` (wc-010a), so its argv is unchanged and no cap is claimed for
wasmer. `memory_cap_on_wasmer_is_skipped` is an `#[ignore]` test with that
reason, never counted as a PASS. No other route (an rlimit, a wrapper, an
engine inside an engine, a VM) is used. No test name says "on_both" for the
cap.

Not in this task: the receipt's cap lines (wc-010c, task 028, in "Run receipt
(wc-005c)") and measured peak memory, a maximum inside `capsule.wasm`, and any
admission or launch decision.

## Module memory maximum discovery (wc-010d0)

Read-only discovery for the C0 refusal (Flint, 26 Oct 23:50: refuse to start
an engine that cannot apply the capsule's declared memory cap, never run it
uncapped). wasmer 7.5.0 has no cap flag (wc-010a), so the question here is
the other route: the cap written into the module itself, as its memory's
declared maximum, which a Wasm engine must apply with no flag. No runner,
argv, receipt, test, `falsifiers.json`, `capsule/`, `tools/build` or pin
change; `capsule.wasm` is not re-pinned. Facts are what each engine's CLI does
on this Mac only, at base `a541cd7ba8e656ddc07466b3fc533118c5771ac7`, with
`/opt/homebrew/bin/wasmtime --version` = `wasmtime 45.0.1 (83166ba31
2026-06-05)` and `/opt/homebrew/bin/wasmer --version` = `wasmer 7.5.0` (both
exit 0). Each engine ran by its absolute path as its own process from a shell
(no engine inside an engine, no VM, no Docker), with **no cap flag** (no
`max-memory-size`). Both engines stay test-only; this picks neither.

**The probe modules** (WAT text under the git-ignored `target/wc010d/r1/`,
never committed; both engines took the `.wat` files directly). The maximum
1024 pages is 64 × 2^20 bytes, the capsule's declared default, read as
wc-010a reads MB.

`grow-max.wat`:

```wat
(module (memory (export "memory") 1 1024) (func (export "grow") (param i32) (result i32) local.get 0 memory.grow))
```

`bad-max.wat` (its minimum, 1025, is above its own maximum, 1024):

```wat
(module (memory (export "memory") 1025 1024) (func (export "size") (result i32) memory.size))
```

`grow-nomax.wat` is the contrast: `grow-max.wat` with no maximum,
`(module (memory (export "memory") 1) (func (export "grow") (param i32) (result i32) local.get 0 memory.grow))`.
`memory.grow` returns the old size in pages (1) on success and -1 on failure;
growing by 1023 reaches exactly 1024 pages (at the maximum), by 1024 reaches
1025 (past it). Runs from `lab/wasm-capsule/target/wc010d/r1/`.

### wasmtime 45.0.1

Each successful `grow` run's stderr is the CLI's own two `--invoke` warnings,
``warning: using `--invoke` with a function that takes arguments is experimental and may break in the future``
and the same for "returns values".

| Run | Command | Exit | stdout | stderr |
|---|---|---|---|---|
| (w1) at the maximum | `/opt/homebrew/bin/wasmtime run --invoke grow grow-max.wat 1023` | 0 | `1` | the two warnings |
| (w2) past the maximum | `/opt/homebrew/bin/wasmtime run --invoke grow grow-max.wat 1024` | 0 | `-1` | the two warnings |
| (w2-t) past the maximum, trap flag only | `/opt/homebrew/bin/wasmtime run -W trap-on-grow-failure=y --invoke grow grow-max.wat 1024` | 1 | (none) | the first warning, ``Error: failed to run main module `grow-max.wat` ``, then ``0: failed to invoke `grow` ``, `1: error while executing at wasm backtrace:` and, last, `2: forcing trap when growing memory to 67174400 bytes` |
| (w1-t) at the maximum, trap flag only | `/opt/homebrew/bin/wasmtime run -W trap-on-grow-failure=y --invoke grow grow-max.wat 1023` | 0 | `1` | the two warnings |
| (w3) start, minimum above maximum | `/opt/homebrew/bin/wasmtime run --invoke size bad-max.wat` | 1 | (none) | `Error: failed to parse WebAssembly module`, then `size minimum must not be greater than maximum (at offset 0x16)` |
| (w4) contrast, no maximum | `/opt/homebrew/bin/wasmtime run --invoke grow grow-nomax.wat 1024` | 0 | `1` | the two warnings |

(w4) returning `1` where (w2) returned `-1`, with the same argument and no
flag on either, shows the module's own maximum made the grow fail. (w2-t)
shows `trap-on-grow-failure=y` alone, with no `max-memory-size`, turns that
failure into a trap.

### wasmer 7.5.0

stderr is empty (0 bytes) on each run that exits 0.

| Run | Command | Exit | stdout | stderr |
|---|---|---|---|---|
| (m1) at the maximum | `/opt/homebrew/bin/wasmer run --invoke grow grow-max.wat 1023` | 0 | `1` | (none) |
| (m2) past the maximum | `/opt/homebrew/bin/wasmer run --invoke grow grow-max.wat 1024` | 0 | `-1` | (none) |
| (m3) start, minimum above maximum | `/opt/homebrew/bin/wasmer run --invoke size bad-max.wat` | 1 | (none) | `error: Unable to compile "bad-max.wat"`, then `╰─▶ 1: compile error: Validate("size minimum must not be greater than maximum (at offset 0x16)")` |
| (m4) contrast, no maximum | `/opt/homebrew/bin/wasmer run --invoke grow grow-nomax.wat 1024` | 0 | `1` | (none) |

(m4) against (m2) is the same contrast: wasmer applies the module's own
maximum with no flag. wasmer has no flag that turns the -1 into a trap
(wc-010a), so on wasmer a grow past the maximum returns -1 and the capsule
keeps running.

### The capsule's memory section

Read by a `python3 -I` script written from the Wasm core binary format
(section id 5; limits flag 0x00 = minimum only, 0x01 = minimum and maximum),
never committed; its full text is in LOG.md, task 030. The audit crate's v1
API returns imports only (`audit/INTERFACE.md`), so it cannot answer this.

- Today's capsule, `tools/build target/wc010d/r1/today` (exit 0): sha256
  `6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13` (the
  pinned value), 178 bytes, one memory: **minimum 16 pages, maximum none**.
- A control build by hand, `tools/build`'s recipe (its `SOURCE_DATE_EPOCH`,
  `CARGO_INCREMENTAL=0`, the three `--remap-path-prefix` flags in
  `CARGO_ENCODED_RUSTFLAGS`, `cargo build --locked --package capsule --release
  --target wasm32-unknown-unknown`) with `CARGO_TARGET_DIR` set to
  `target/wc010d/r1/build-control`: the same sha256, `6dd9af1a…`, so the hand
  recipe is `tools/build`'s.
- The scratch build, that recipe plus `-C link-arg=--max-memory=67108864`, with
  `CARGO_TARGET_DIR` set to `target/wc010d/r1/build-max`: sha256
  `2002429e73ee1a5e983df008f5b53728882646f109d55a9d1a93e831690631e1`, 180 bytes,
  one memory: **minimum 16 pages, maximum 1024 pages**. It is not committed,
  and `capsule.wasm`, `tools/build` and every pin are unchanged.

`--invoke digest 1592590337` on each, as `env -i <engine> run --invoke digest
<absolute module path> 1592590337 < /dev/null`, `<D>` = the absolute path of
`lab/wasm-capsule/target/wc010d/r1`:

| Module | Engine | Exit | stdout | stderr |
|---|---|---|---|---|
| `<D>/capsule-max.wasm` (scratch, maximum 1024) | `/opt/homebrew/bin/wasmtime` | 0 | `230101071268130872` | the two warnings |
| `<D>/capsule-max.wasm` (scratch, maximum 1024) | `/opt/homebrew/bin/wasmer` | 0 | `230101071268130872` | (none) |
| `<D>/today/capsule.wasm` (pinned, no maximum) | `/opt/homebrew/bin/wasmtime` | 0 | `230101071268130872` | the two warnings |
| `<D>/today/capsule.wasm` (pinned, no maximum) | `/opt/homebrew/bin/wasmer` | 0 | `230101071268130872` | (none) |

`230101071268130872` is `FIXED_OUTPUT` (`0x0331_7BB4_875F_B038`,
`capsule/src/lib.rs`) for `FIXED_INPUT` `0x5EED_0001` = 1592590337. `digest`
never grows memory, so these runs show the same output, not a grow refusal in
the capsule.

### The answer for the C0 refusal

- (a) FOUND: wasmtime refuses a grow past the module's own maximum with no
  flag: (w2) returns `-1`, against (w4)'s `1`; with only
  `trap-on-grow-failure=y` it traps, (w2-t).
- (b) FOUND: wasmer does: (m2) returns `-1`, against (m4)'s `1`. It returns
  -1 only; it has no trap flag.
- (c) FOUND: both refuse a module whose minimum is above its maximum at start,
  before any call: (w3) and (m3), each exit 1 with "size minimum must not be
  greater than maximum".
- (d) NOT FOUND: `capsule.wasm` declares no maximum today: minimum 16 pages,
  maximum none ("The capsule's memory section", today's capsule).
- (e) FOUND: the `--max-memory=67108864` build gives the capsule a maximum of
  exactly 1024 pages (sha256 `2002429e…`) with the same digest output,
  `230101071268130872`, on both engines (the `capsule-max.wasm` rows).

What the C0 refusal still needs that this lane cannot write: a reader of the
module's memory maximum (each memory's maximum, and that there is only one
memory), and the audit crate (cx-wasm-audit) is the one module reader, so that
ask goes to cx-wasm-audit through Flint, not into a second reader here.

### The capsule declares its maximum (task 032)

[Proposal] Since task 032 (27 Oct), `tools/build` passes
`-Clink-arg=--max-memory=67108864`, so `capsule.wasm` declares a maximum of
1024 pages, its declared `memory_mb` (64) × 2^20 bytes; its minimum is still 16
pages and its `digest` output is unchanged. Both engines apply a module's own
maximum with no flag ((w2) and (m2) above): wasmer returns -1 to a grow past
it, where wasmtime with `run`'s flag traps. `run` does not yet check a
module's maximum (C0 step iii waits for the audit crate's reader), and its
argv and the receipt's cap lines are unchanged, so wasmer's receipt line still
says SKIPPED: it reports the flag `run` passed. The claim stays "a
self-contained capsule in a fixed flat space with a host-enforced cap", on
this one Mac only: not the ~4 GB DigitCapsule and not any-RTOS loading.

## Granted import hosting discovery (wc-009b0)

Read-only discovery for wc-009b. wc-009a lets a granted import through the
verifier, but `run` gives the engines no host function, so a granted import is
allowed, not hosted. This section records whether each engine's CLI can supply
a named core-module import from a second Wasm module file (no host code of the
engine's own, no WASI flag), the exact flag, and what happens without it. It is
what each CLI does on this Mac only, not a choice of import path, and no
Component Model or Bus claim. No runner, argv, receipt, test or
`falsifiers.json` change; `run.rs` still passes no such flag. Base
`3a4d2812aa71fce5a92e6bf7b314aee9844c7293`, with
`/opt/homebrew/bin/wasmtime --version` = `wasmtime 45.0.1 (83166ba31
2026-06-05)` and `/opt/homebrew/bin/wasmer --version` = `wasmer 7.5.0`. Each
engine ran as its own process from a shell (no engine inside an engine, no VM,
no Docker), in the runner's shape: `env -i` (an empty environment), stdin from
`/dev/null`, and `run --invoke digest <absolute module path> 1592590337` plus
only the flag under test.

Rong's ruling (26 Oct), which every answer below is read under:
Discovery only: no engine-specific host-function route (a preload module or a CLI flag) becomes the lab's import path; granted imports stay a stand-in for the Runtime/provider contract (P10, P18).

**The probe modules** (WAT text under the git-ignored `target/wc009b0/`, never
committed; both engines took the `.wat` files directly, so no `wat` crate step
was needed). `main.wat` uses the import name of `IMPORTING_MODULE`, `env.f`:

```wat
(module
  (import "env" "f" (func $f (param i32) (result i32)))
  (func (export "digest") (param i32) (result i32)
    local.get 0
    call $f))
```

`host.wat` has no imports and exports `f`, which returns its argument plus 1:

```wat
(module
  (func (export "f") (param i32) (result i32)
    local.get 0
    i32.const 1
    i32.add))
```

`host-wasi.wat` is `host.wat` plus
`(import "wasi_snapshot_preview1" "proc_exit" (func (param i32)))`, never
called. `host-unknown.wat` is `host.wat` plus
`(import "nope" "g" (func (param i32)))`, never called: a contrast for (iv). In
the commands, `<D>` is the absolute path of
`lab/wasm-capsule/target/wc009b0` and each module path is absolute. Each
table row gives its complete command as run, from a shell; each was run again
once by task 026 with exactly that command and gave the same exit and stdout.

### wasmtime 45.0.1: FOUND, `--preload env=<path>`

The flag, from `/opt/homebrew/bin/wasmtime run --help`:

```text
      --preload <NAME=MODULE_PATH>
          Load the given WebAssembly module before the main module
```

`NAME` is the import module name the preloaded module's exports answer, so
`env.f` is supplied by `--preload env=<D>/host.wat`. The runs (each successful
run's stderr is the CLI's own two `--invoke` warnings, the first being
``warning: using `--invoke` with a function that takes arguments is experimental and may break in the future``):

| Run | Complete command as run | Exit | stdout | stderr (first line, then the cause) |
|---|---|---|---|---|
| (i) `host` as `env` | `env -i /opt/homebrew/bin/wasmtime run --preload env=<D>/host.wat --invoke digest <D>/main.wat 1592590337 < /dev/null` | 0 | `1592590338` | the warnings |
| (ii) nothing supplied | `env -i /opt/homebrew/bin/wasmtime run --invoke digest <D>/main.wat 1592590337 < /dev/null` | 1 | (none) | ``Error: failed to run main module `<D>/main.wat` ``; last: ``1: unknown import: `env::f` has not been defined`` |
| (iii) `host` as `other` | `env -i /opt/homebrew/bin/wasmtime run --preload other=<D>/host.wat --invoke digest <D>/main.wat 1592590337 < /dev/null` | 1 | (none) | the same as (ii), word for word |
| (iv) `host-wasi` as `env` | `env -i /opt/homebrew/bin/wasmtime run --preload env=<D>/host-wasi.wat --invoke digest <D>/main.wat 1592590337 < /dev/null` | 0 | `1592590338` | the warnings |
| (iv-c) `host-unknown` as `env` | `env -i /opt/homebrew/bin/wasmtime run --preload env=<D>/host-unknown.wat --invoke digest <D>/main.wat 1592590337 < /dev/null` | 1 | (none) | ``Error: failed to process preload `env` at `<D>/host-unknown.wat` ``; last: ``unknown import: `nope::g` has not been defined`` |

(ii) is the contrast: the same `main.wat` and argument, without the flag, is
refused at start, and the message names both `env` and `f`. (iii) shows the
name matters: a module preloaded under another name supplies nothing.

**(iv): a supplied module can bring WASI in.** wasmtime did not refuse
`host-wasi.wat`: it linked the supplied module's `wasi_snapshot_preview1`
import with no WASI flag on the command line, and the run printed
`1592590338`. (iv-c) shows the import was really resolved, not skipped: an
import wasmtime has no definition for is refused when the preload is
processed. So on this CLI, a module supplied with `--preload` can bring
wasmtime's own WASI into the run by its own imports. wc-009b must not treat a
preloaded module as authority-free.

**The flag on a zero-import module.** The real `tools/build` capsule (built
into `<D>/build/`, sha256
`6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13`, the pinned
value): without the flag, exit 0, stdout `230101071268130872`; with
`--preload env=<D>/host.wat`, exit 0, stdout `230101071268130872`, the same
two warnings on stderr each time. Both equal `FIXED_OUTPUT` for `1592590337`,
so with the preload, this capsule's output for `1592590337` was unchanged; this one comparison says nothing about any other effect of a preloaded module.

### wasmer 7.5.0: SKIPPED

No flag in its help supplies a core-module import from another module file.
Searched `/opt/homebrew/bin/wasmer run --help` and
`/opt/homebrew/bin/wasmer --help` (both exit 0) case-insensitively for
`preload`, `import`, `link`, `module`, `host`, `use` and `env`. `wasmer --help`
matched none of `preload`, `import`, `link`, `module` or `host`; its `use` and
`env` matches are about logs, config and the registry login. In
`wasmer run --help` no line matched `preload`; `import` matched only "Require
WASI modules to only import 1 version of WASI" and "Enable experimental N-API
imports for modules that require them"; the `module`, `host`, `use` and `env`
matches are about other things (compile threads, folders and the CWD, network,
journals, the cache, the webc entrypoint, and `--env <KEY=VALUE>`, "Pass
custom environment variables", which is ambient, not an import). Two lines
look close, and each was tried once:

```text
      --enable-module-linking
          Enable support for the module linking proposal
      --use <USE>
          List of other containers this module depends on
```

`--use` names containers (webc packages), not a module that answers an import
name, and `--enable-module-linking` is a Wasm feature switch that takes no
module. Neither supplies `env.f`:

| Run | Complete command as run | Exit | stdout | stderr |
|---|---|---|---|---|
| (ii) nothing supplied | `env -i /opt/homebrew/bin/wasmer run --invoke digest <D>/main.wat 1592590337 < /dev/null` | 1 | (none) | `error: Unable to instantiate the WebAssembly module`, then `╰─▶ 1: Error while importing "env"."f": unknown import. Expected Function(FunctionType { params: [I32], results: [I32] })` |
| `--use` | `env -i /opt/homebrew/bin/wasmer run --use <D>/host.wat --offline --invoke digest <D>/main.wat 1592590337 < /dev/null` | 1 | (none) | the same two lines as (ii) |
| `--enable-module-linking` | `env -i /opt/homebrew/bin/wasmer run --enable-module-linking --invoke digest <D>/main.wat 1592590337 < /dev/null` | 1 | (none) | `error: No backends support the required features for the Wasm module. Feel free to open an issue at https://github.com/wasmerio/wasmer/issues` |

(`--offline` keeps `--use` from asking a registry: "Resolve only from local
sources ... never the registry".) The (ii) refusal names both `env` and `f`.
So wasmer 7.5.0's CLI cannot host `env.f` from a second module file, and
hosting cannot be claimed for wasmer.

### The answer for wc-009b

- wasmtime: hosts by flag `--preload env=<path>` (the name before `=` is the
  import module name); without it, start is refused naming `env::f`; a
  preloaded module gets wasmtime's WASI linked in by its own imports, with no
  flag.
- wasmer: SKIPPED: neither `wasmer run --help` nor `wasmer --help` has a flag
  that supplies a core-module import from another module; `--use` and
  `--enable-module-linking` were tried and do not.
- The engines differ. Only wasmtime's (i) printed `1592590338`. So "same
  results on both engines" cannot be tested for a hosted granted import with
  these two CLIs; both refuse an unsupplied `env.f` at start, naming it, which
  is the only result they share. wc-009b's wasmer hosting test must report
  SKIPPED with this reason, never PASS.

## Named tests

`cargo test --manifest-path lab/wasm-capsule/Cargo.toml`:

- `digest_returns_the_fixed_value` — the shared impl returns the pinned value.
- `two_clean_builds_in_different_paths_are_byte_identical` — the foundation claim.
- `the_receipt_names_the_exact_toolchain` — receipt rustc/target match the build.
- `receipt_hashes_match_artifact_and_lockfile` — receipt hashes match the files.
- `built_capsule_has_the_required_wasm_shape` — core Wasm, zero imports, digest sig.
- plus crafted-byte coverage of the shape reader. Task 032 adds three, in
  `tests/wasm_shape.rs`: `reads_a_memory_maximum_from_a_crafted_module`
  (flag 0x01: minimum 16, maximum 1024 pages),
  `reads_a_memory_with_no_maximum_from_a_crafted_module` (flag 0x00: minimum
  16, maximum none) and `fails_closed_on_a_truncated_memory_section` (flag 0x01
  with no maximum: exactly `memory section: unexpected end of module`).

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
  receipt's `artifact_sha256` and the pinned `2002429e…` (task 032);
  `capsule.json` is
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
  the pinned `2002429e…` (task 032). One `PINNED_ARTIFACT_SHA256`, in
  `tests/common/mod.rs`, serves this test and the one above.
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
  field, exactly eight public functions (`verify_checked`, `verify_bundle`,
  `read_grants` and the five accessors, `unused_grants()` among them), no
  `&mut self`, no `Deserialize`, `Default` or trait impl for the value, and one
  literal that makes it, in `verify_checked`.
- `verifier_has_one_check_path` — the tools crate calls
  `verify_checked_signature` once and `audit` once, parses JSON twice (one
  `from_slice` in `manifest_entrypoint`, one in `parse_grants`), calls
  `manifest_entrypoint` once, reads one file with `fs::read` (in
  `read_grants`), calls `parse_grants` once and `read_grants` never (the caller
  does), uses neither `verify_name_signature` nor `audit_component`,
  `verify_checked` reads no grants, `verify_bundle` only walks and delegates,
  and `entrypoint()` reads no manifest.
- `verifier_uses_audit_api_v1` — `wasm_capsule_audit::AUDIT_API` is 1.
- `verifier_has_no_import_parser_of_its_own` — `tools/Cargo.toml` and
  `tools/src`, comments stripped, name no `wasmparser`.
- `verifier_reads_no_bundle_file_by_path` — the verifier, comments stripped,
  has no `fs::read`, `File::open`, `OpenOptions`, `read_dir`, `metadata` or
  `read_to_end` outside `read_grants`, and `read_grants` has exactly one
  `fs::read` and none of the others.
- `grants_file_refusals_keep_their_reason` (wc-009a; v2 since task 031) —
  `GRANTS_SCHEMA` and `GRANTS_LABEL` are exactly `wc-009.lab-grants/v2` and
  `lab stand-in, not admission`; an empty list and two grants read in file
  order; a missing file keeps `NotFound` and its OS text; and 21 malformed
  files (not JSON, a list or a string document, an unknown key, each missing
  key, a v1 file or a number schema, another label and one with a trailing
  space, imports as an object, eight bad entries among them the v1 pair with
  no right and a number right, the same pair twice) each give their exact text.
- `grant_naming_a_right_the_operation_does_not_need_is_refused` (task 031) —
  `LAB_OPERATIONS` is exactly the one entry `env.f`, inputs and outputs none,
  right `call`, effect `none`; `env.f` granted `call` reads, and `env.g` (no
  typed operation) granted `write` reads; `env.f` granted `write`, `read`,
  `Call`, `call ` or the empty string is refused as `RightNotNeeded` with the
  import, the right granted and `call`, and its exact text after the path.
- `unused_grants_excludes_linked_and_preserves_file_order` (wc-009a) — the
  module that imports `env.f`, granted `z.last`, `env.f`, `a.first`:
  `imports()` is `[env.f]`, `unused_grants()` is `[z.last, a.first]`, and the
  lab CID and the entries are the bundle's own two files.
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
  (`FIXED_INPUT`), with no `--dir`, `--mapdir`, `--env` or `--net`. From task
  027 `wasmtime`'s argv also has `-W` and
  `max-memory-size=67108864,max-memories=1,trap-on-grow-failure=y` (this capsule's declared 64
  MB) before the module path; `wasmer`'s is unchanged. Stand-ins that read the
  module path take their second-to-last argument.
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
  walk or lower-level verify call, no grants read or parse, exactly one
  `verify_bundle` call (task 015's `run`, passing `input.granted`, task 020),
  `input.granted` used nowhere else, and `entrypoint()` is its one source of
  module bytes.
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
  `1592590337`, both versions, both `exit status: 0` and both stdouts; task
  028: the v2 schema and the four memory lines, 64 MB = 67108864 bytes). Both
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
  `FIXED_OUTPUT`, and the receipt written to a new file is `render`'s text
  (task 028: its schema line is v2, and its last four lines are the memory
  lines for 64 MB, `wasmtime` ENFORCED and `wasmer` SKIPPED). It prints the
  receipt. If either engine is not found it prints `SKIPPED` and
  gives no result, never a PASS.

Task 019's two:

- `run_engine_starts_its_engine_exactly_once` (`tests/run.rs`) — counting
  stand-ins append one line per start to `<their own path>.starts` (found from
  `$0`; the engine has no environment). One `run_engine` call per engine
  records exactly one module run and no `--version`; one `run` call records
  exactly one module run per engine (two in all) and, counted apart, one
  `--version` query each.
- `readme_falsifier_total_matches_falsifiers_json` (`tests/docs.rs`) — counts
  the `"falsifiers"` entries with `serde_json`, finds the total sentence that
  opens "## Falsifiers" exactly once, and fails naming both numbers when they
  differ.

wc-009a's run tests (task 020), in `tests/run.rs`. Each signs its bundle with a
fresh key, writes a lab grants file beside the bundle, reads it with
`read_grants` and runs `run` on task 019's counting stand-ins. "Each engine
once" is exactly one `--version` query and one module run per engine; a refusal
is zero of both:

- `zero_grants_zero_imports_runs` — the capsule `tools/build` makes, with an
  empty grants file: it runs, each engine once, `linked()` and
  `unused_grants()` are empty.
- `zero_grants_zero_imports_runs_on_both_real_engines` — the same on the real
  `wasmtime` and `wasmer` found on PATH: both print `FIXED_OUTPUT`, nothing is
  linked. If either is not found it prints `SKIPPED`, never a PASS.
- `declared_not_granted_import_refuses_instantiation_by_name` — the signed
  module that imports `env.f`, with an empty grants file: refused as
  `TwoEngineRefusal::Verify(VerifyRefusal::Audit(Undeclared { module: "env",
  name: "f" }))`, text exactly `undeclared import env.f`; no run folder, and
  zero starts of either kind.
- `valid_signature_with_empty_grants_file_links_nothing` — the zero-import
  8-byte module, validly signed, with an empty grants file: `linked()` is empty.
- `grant_for_an_import_the_module_does_not_have_links_nothing_and_is_reported`
  (Rong's rename of `granted_but_undeclared_is_refused`) — the zero-import
  module, grants `[env.f]` (right `call`): it runs, `linked()` is empty,
  `unused_grants()` is exactly `[env.f]`.
- `granted_import_is_linked` — the module that imports `env.f`, grants
  `[env.f]` (right `call`): it passes verification, `linked()` is exactly
  `[env.f]`, each engine once, and both run folders hold the verified module.
- `module_import_with_no_typed_operation_is_refused` (task 031) — the module
  that imports `env.g` (no typed lab operation), granted `env.g`: refused as
  `TwoEngineRefusal::Verify(VerifyRefusal::UntypedImport { module: "env", name:
  "g" })`, text exactly `no typed lab operation for import env.g`; with no
  grant, refused by the audit as `undeclared import env.g`. Both: no run
  folder, and zero starts of either kind.

Task 026's two, in `tests/docs.rs`. Each holds one of Rong's two rulings
(26 Oct) as one exact sentence, read through `lane_file`:

- `engines_are_labelled_test_only_not_endorsed` — the label "not endorsed":
  README and ADOPTION each hold the engine ruling exactly once; README's copy
  sits in the first section that names wasmtime and wasmer ("Layout"); both
  engine doc comments in `tools/src/run.rs` (the module doc and the one on
  `pub enum Engine`) say "test-only, not endorsed"; and each line of README,
  ADOPTION or `run.rs` that mentions endorsement also says "not endorsed". It
  fails naming the file, and for the last check each `file:line` with its text.
- `hosting_discovery_is_not_the_import_path` — README holds the discovery-only
  ruling exactly once, inside "Granted import hosting discovery (wc-009b0)" and
  before its first per-engine answer line (a line starting `### wasmtime`,
  `### wasmer`, `- wasmtime:` or `- wasmer:`), and ADOPTION holds it exactly
  once on one line. It fails naming what is missing or out of place.

Task 031's README guard, in `tests/docs.rs`:

- `readme_lists_each_typed_lab_operation` — README has the heading "### Typed
  lab operations (M1 B4 lab half)" once, and its lines that start ``- ` `` are,
  in order, exactly one line per `LAB_OPERATIONS` entry, rendered from the
  table's own fields. It fails showing both lists.

wc-010b's run tests (task 027), in `tests/run.rs`. The grow modules are
hand-written bytes: one memory of 1 page with no maximum, no import, and one
export `digest (i32) -> i32` that ignores its argument and runs `memory.grow`
by a constant. Each bundle is signed with a fresh key and verified. A real
engine not found prints SKIPPED and gives no result, never PASS:

- `declared_memory_cap_comes_from_the_manifest` — stand-in argv: a bundle whose
  `capsule.json` adds `"resources": {"memory_mb": 2}` gives `wasmtime`
  `max-memory-size=2097152`, and one that declares `u32::MAX` gives
  `max-memory-size=4503599626321920`; `memory_mb()` returns each as declared,
  and `wasmer`'s argv has no cap.
- `capsule_grows_within_the_declared_cap_on_wasmtime` — the real `wasmtime`:
  a grow by 1023 pages, to exactly 64 MB, succeeds and prints `1`.
- `memory_grow_past_the_declared_cap_traps_on_wasmtime` — the real `wasmtime`:
  a grow by 1024 pages is refused with `EngineFailed`, and its stderr holds
  `forcing trap when growing memory to 67174400 bytes`.
- `second_memory_cannot_double_the_declared_cap_on_wasmtime` — the real
  `wasmtime`: a hand-written module with two memories of 32 pages (2 MB) each,
  no maximum and no import, whose `digest` returns the two sizes added, in a
  bundle that declares `"memory_mb": 2`, is verified and then refused with
  `EngineFailed`, and its stderr holds `resource limit exceeded: memory count
  too high at 2`. Without `max-memories=1` it runs and prints `64` pages, 4 MB.
- `built_capsule_runs_under_the_declared_cap_on_wasmtime` — the real
  `tools/build` capsule through `run` on both real engines prints
  `FIXED_OUTPUT` on both. A recording program at `wasmtime`'s path appends its
  arguments to a file and then `exec`s the real `wasmtime` (one process, the
  shell is replaced), so the test sees the cap on `wasmtime`'s module-run argv.
- `memory_cap_on_wasmer_is_skipped` — `#[ignore = "SKIPPED: wasmer 7.5.0 has no
  memory cap flag in wasmer run --help or wasmer --help (wc-010a); no cap is
  claimed for wasmer"]`, never run, never counted as a PASS.

`runner_passes_no_directory_env_or_network_flags` and `verified_bundle_is_sealed`
(the new private field and its accessor) were updated for the cap.

Task 032's one, in `tests/run.rs`:

- `built_capsule_declares_the_manifest_memory_as_its_maximum` — the
  `tools/build` capsule, signed and verified: its module, from
  `entrypoint()`, read by the test-only shape reader, imports nothing (no
  memory either) and defines exactly one memory, with minimum 16 pages and a
  maximum whose bytes (pages × 65536) equal `memory_mb()` × 2^20 from the
  verifier's one manifest read: 1024 pages for 64.

wc-010c's two (task 028), in `tests/run.rs`, on stand-in engines, with a
bundle signed by `signed_bundle_declaring` (the signing half of 027's
`verified_bundle_declaring`, which now calls it):

- `receipt_records_the_declared_memory_cap` — a bundle declaring `memory_mb: 2`
  run through `run`: the receipt is the v2 schema, 14 lines, ending in
  `memory_mb: 2`, `memory_cap_bytes: 2097152`, `wasmtime_memory_cap: ENFORCED
  max-memory-size=2097152,max-memories=1,trap-on-grow-failure=y` and the
  `wasmer` SKIPPED line, exactly.
- `receipt_cap_line_matches_the_argv_the_engine_got` — `recording` stand-ins
  (which now also write each module run's whole argv to `<name>.argv`): the
  receipt's `wasmtime_memory_cap` is ENFORCED with exactly the one argument
  after `-W` in `wasmtime`'s logged argv; `wasmer`'s logged argv has no `-W`
  and no `max-memory-size`, and its receipt line is the exact SKIPPED line.

`receipt_records_observed_engine_versions` and
`real_receipt_names_both_installed_engines` were updated to the v2 text.

## Falsifiers

`falsifiers.json` holds 161 planted bugs in the provider format (`command: "lab"`).
By task: nine wc-001, seven task 010, 23 task 009, one task 012, one task 017,
21 wc-004, four wc-008, 23 wc-005a (task 014), 11 wc-005b (task 015), 20
wc-005c (task 016), two task 019, 17 wc-009a (task 020), seven task 026,
seven wc-010b (task 027), two wc-010c (task 028), two task 029, two task
031 and two task 032.
Each requires all its named tests to fail at an assertion.
`readme_falsifier_total_matches_falsifiers_json` holds the total to the file.
This section is the one place for evidence labels and counts, and
`falsifiers_about_states_no_evidence_status` keeps the `"about"` text of
`falsifiers.json` free of them.

Two kinds of evidence, kept apart. Runner-caught: 97, the sections below
marked runner-caught (tasks 012, 017, 014, 015, 016, 019, 020, 026, 027, 028,
029, 031 and 032: 1 + 1 + 23 + 11 + 20 + 2 + 17 + 7 + 7 + 2 + 2 + 2 + 2), each
run by the canonical runner with its summary line quoted.
Hand-proven, pending R1: 64, the sections marked so (wc-001, tasks 010 and 009,
wc-004 and wc-008: 9 + 7 + 23 + 21 + 4), each proved by the repo's break →
named test fails → revert method with `cargo test` in this workspace. Their
labels stay until each is run by the canonical runner and its summary line is
quoted.

R1 is done: the canonical runner `examples/agent-host/falsify.py` has a `lab`
command (`cargo test --workspace` on this workspace). Its recovery targets
(`PROVIDER_TARGETS`, the provider lane's) name every lane file a falsifier
edits, so a killed run can restore each one. Ask **R2** is done: provider 026
(PR #242) added `tools/src/run.rs`, `tools/src/receipt.rs` and
`tests/lab_cid.rs` to `PROVIDER_TARGETS`.

wc-001's nine, each hand-proven, pending R1 (README "Claim scope" has F-WC1):

- F-WC1 — an embedded `CARGO_MANIFEST_DIR` breaks the byte-identical build.
- F-WC1-SPACED-PATH — whitespace-split `RUSTFLAGS` break the build when the
  path has a space. Task 032 re-anchored it, the same bug as before: a second
  edit turns the new link-argument line into the same `RUSTFLAGS` form. Without
  it, the planted script stops at an unbound `CARGO_ENCODED_RUSTFLAGS`, and
  `tools/build` then exits 0 with no capsule (LOG.md, task 032), so the test
  would fail for another reason. By hand after the re-anchor, the named test
  fails at its "tools/build failed" assertion with rustc's
  `--remap-path-prefix must contain '=' between FROM and TO`. The canonical
  runner reads it NOT RUN: the child cargo's `process didn't exit
  successfully` line is a Cargo failure marker even inside the test's own
  output, so it stays hand-proven.
- F-WC1-DIGEST — the digest result changes, so the fixed value no longer holds.
- F-WC1-IMPORT — the capsule keeps a host import.
- F-WC1-SIG — the `digest` export takes a second parameter.
- F-WC1-TOOLCHAIN and F-WC1-RUSTC-OVERRIDE — the receipt records a compiler
  the build did not use, or queries a bare `rustc`.
- F-WC1-ARTIFACT-HASH and F-WC1-LOCK-HASH — the receipt swaps the artifact
  and lockfile hashes.

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
revert). `tools/src/bundle.rs` was not a recovery target at that run; it is
one now:

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
reported `summary: 5 CAUGHT of 5`; it stays pending R1 (at that run the
recovery targets named neither `capsule/capsule.json` nor `tools/src/lib.rs`;
both are recovery targets now), not a PASS.

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

Task 019's two, runner-caught (the canonical runner's summary line is in
LOG.md, task 019). `tools/src/run.rs` is not a recovery target (ask R2), so a
killed run cannot restore it for F-WC5-START-TWICE; `README.md` is one:

- F-WC5-START-TWICE — `run_engine` starts the engine twice, drops the first
  result and returns the second (`run_engine_starts_its_engine_exactly_once`,
  at its count assertion).
- F-WC-README-COUNT — the total in this section's first sentence becomes one
  less than the file holds (`readme_falsifier_total_matches_falsifiers_json`,
  at its comparison).

wc-009a's 17 (task 020), runner-caught (the canonical runner's summary line is
in LOG.md, task 020). Every anchor is in `tools/src/verify.rs`, a recovery
target:

- F-WC9-LINK-ALL — the verifier drops the audit's `Undeclared` refusal, so a
  module with an import that is not granted reaches both engines
  (`declared_not_granted_import_refuses_instantiation_by_name`).
- F-WC9-GRANT-INJECT — the linked list is the grants list, not the audit's
  result, so a grant for an import the module does not have is reported as
  linked (`grant_for_an_import_the_module_does_not_have_links_nothing_and_is_reported`).
- F-WC9-GRANTS-LABEL — the reader stops checking the label
  (`grants_file_refusals_keep_their_reason`).
- F-WC9-GRANTS-SCHEMA, -UNKNOWN-KEY, -IMPORTS-NOT-LIST, -ENTRY-EXTRA-KEY,
  -ENTRY-NOT-STRING and -DUPLICATE — the reader drops one more check, so a
  wrong schema, an unknown key, a non-list `imports` (read as empty), an entry
  with a third key, a number name (taken as its JSON text) or a pair granted
  twice is read (`grants_file_refusals_keep_their_reason`).
- F-WC9-GRANTS-CAUSE, -NOT-JSON, -NOT-OBJECT and -MISSING-KEY — an unreadable
  file loses its OS cause, a file that is not JSON is read as no grants, a
  document that is not an object is refused as a missing key, or a missing key
  is read as null and refused as a wrong value
  (`grants_file_refusals_keep_their_reason`).
- F-WC9-UNUSED-KEEPS-USED and -UNUSED-REORDER — the unused grants keep the
  linked one, or come back in reverse file order
  (`unused_grants_excludes_linked_and_preserves_file_order`).
- F-WC9-GRANTS-READ-TWICE and -PARSE-TWICE — the reader reads the file, or
  parses its bytes, a second time (`verifier_has_one_check_path`, and for the
  read also `verifier_reads_no_bundle_file_by_path`).

Task 020 also re-anchored four entries, each the same bug as before:
F-WC5a, F-WC5-VERIFY-TWICE and F-WC5-QUERY-BEFORE-VERIFY (`run` now passes
`input.granted`, not `&[]`, to `verify_bundle`; F-WC5a, which removes the
verified value, gains a fourth edit that fills `linked` and `unused_grants`
empty, so it still builds) and F-WC4-SEALED-NEW (the
planted constructor fills the new `unused` field, so it still compiles and is
caught by `verified_bundle_is_sealed`). That `run` forwards `input.granted` is
held by `runner_uses_only_explicit_inputs` and `granted_import_is_linked`; its
planted bug (`&[]` in place of `input.granted`, in `tools/src/run.rs`) was
hand-proven when task 020 ran (LOG.md, task 020), and is now runner-caught as
F-WC9-RUN-DROPS-GRANTS (task 029, below), counted in the totals above.

Task 023's eight planted bugs in the `"about"` text, each hand-proven
(`falsifiers.json` is the canonical runner's own input and not a recovery
target, so they have no `falsifiers.json` entry and are outside every count
above; LOG.md, task 023). Each makes
`falsifiers_about_states_no_evidence_status` fail at its assertion: the base's
evidence sentence put back, each of the five evidence words planted alone, and
the pointer losing `README.md` or `## Falsifiers`.

Task 026's seven, runner-caught (the canonical runner's summary line is in
LOG.md, task 026). Every anchor is in `README.md`, a recovery target, and each
entry's one named test fails at its assertion:

- F-WC-ENGINE-ENDORSED — the engine ruling's "not endorsed" loses its "not"
  (`engines_are_labelled_test_only_not_endorsed`, which says "not endorsed",
  at its count assertion).
- F-WC-ENGINE-MOVED — the engine ruling moves from "Layout" to the two-engine
  section (that test, at its placement assertion).
- F-WC-ENGINE-TWICE — a second copy of the engine ruling (that test, at its
  count assertion).
- F-WC-ENDORSE-LINE — the two-engine section's "not endorsed" line goes back to
  the base's wording (that test, at its line assertion).
- F-WC9B0-IMPORT-PATH — the discovery-only ruling is removed from the 022
  section (`hosting_discovery_is_not_the_import_path`, at its count assertion).
- F-WC9B0-AFTER-ANSWERS — the discovery-only ruling moves after the
  per-engine answers (that test, at its placement assertion).
- F-WC9B0-TWICE — a second copy of the discovery-only ruling (that test, at its
  count assertion).

Task 026 also re-anchored F-WC-README-COUNT to the new total, the same bug as
before.

Task 026's five planted bugs outside `README.md`, each hand-proven, pending R1
(`ADOPTION.md` and `tools/src/run.rs` are not recovery targets, so they have no
`falsifiers.json` entry and are outside every count above; LOG.md, task 026):

- F-WC-ENGINE-ADOPTION — ADOPTION loses the engine ruling
  (`engines_are_labelled_test_only_not_endorsed`, which says "not endorsed",
  at its count assertion).
- F-WC-ENDORSE-ADOPTION — ADOPTION's "not endorsed" claim-scope line goes back
  to the base's wording (that test, at its line assertion).
- F-WC-ENGINE-RUN-MODULE-DOC and F-WC-ENGINE-RUN-ENUM-DOC — the module doc, or
  the doc on `pub enum Engine`, in `tools/src/run.rs` goes back to the base's
  wording, so it no longer says "test-only, not endorsed" (that test, at its
  module-doc or enum-doc assertion).
- F-WC9B0-ADOPTION — ADOPTION loses the discovery-only ruling
  (`hosting_discovery_is_not_the_import_path`, at its ADOPTION assertion).

wc-010b's seven (task 027), runner-caught (the canonical runner's summary line is
in LOG.md, task 027). Every anchor is in `tools/src/run.rs` or
`tools/src/verify.rs`, both recovery targets, and each named test fails at its
assertion:

- F-WC10-CAP-IGNORED — the runner drops the cap argument, so it ignores the
  declared limit (Rong's falsifier)
  (`runner_passes_no_directory_env_or_network_flags` and
  `declared_memory_cap_comes_from_the_manifest` at their argv comparison;
  `memory_grow_past_the_declared_cap_traps_on_wasmtime`, where wasmtime is
  present, because the grow past 64 MB succeeds and the run is not refused;
  `second_memory_cannot_double_the_declared_cap_on_wasmtime`, because the
  two-memory module runs).
- F-WC10-CAP-FIXED — the runner caps at a fixed 64 MB, not the declared
  `memory_mb` (`declared_memory_cap_comes_from_the_manifest`, at its 2 MB argv
  comparison).
- F-WC10-NO-TRAP — `trap-on-grow-failure=y` is dropped, so a grow past the cap
  returns -1 and the run exits 0 (the argv test and
  `declared_memory_cap_comes_from_the_manifest` at their argv comparison;
  `memory_grow_past_the_declared_cap_traps_on_wasmtime`, not refused).
- F-WC10-TWO-MEMORIES — `max-memories=1` is dropped, so the cap holds each
  linear memory on its own and a module with a second memory gets twice its
  declared size (round 2 of task 027, from the Codex review) (the argv test
  and `declared_memory_cap_comes_from_the_manifest` at their argv comparison;
  `second_memory_cannot_double_the_declared_cap_on_wasmtime`, where wasmtime
  is present, because the module runs and is not refused).
- F-WC10-CAP-OVERFLOW — the MB to bytes product is taken in `u32`
  (`wrapping_mul`), so `u32::MAX` MB wraps
  (`declared_memory_cap_comes_from_the_manifest`, at its `u32::MAX` argv
  comparison).
- F-WC10-CAP-NOT-READ — the verifier keeps a fixed 64 in place of the
  manifest's `resources.memory_mb` (`declared_memory_cap_comes_from_the_manifest`,
  at its `memory_mb()` assertion).
- F-WC10-WASMER-FLAG — `wasmer` is given a cap flag its CLI does not have (the
  argv test and `declared_memory_cap_comes_from_the_manifest`, at `wasmer`'s
  argv comparison).

Task 027 also re-anchored seven entries, each the same bug as before:
F-WC5-START-TWICE (`start_engine` now takes the declared `memory_mb`, so both
of its anchors carry the new argument), F-WC5a (its direct engine starts pass
the default 64, since it removes the verified value) and
F-WC5-BYPASS-RUN-ENGINE (its direct start passes the verified `memory_mb`);
F-WC4-ORDER-AUDIT-FIRST (the manifest read returns the entrypoint and
`memory_mb` together) and F-WC4-ENTRYPOINT-REPARSE (its second manifest read
keeps only the entrypoint); F-WC4-SEALED-NEW (the planted constructor fills
the new `memory_mb` field, so it still compiles and is caught by
`verified_bundle_is_sealed`); and F-WC-README-COUNT (the new total). Each
re-anchored entry keeps its own evidence label above.

wc-010c's two (task 028), runner-caught (the canonical runner's summary line is
in LOG.md, task 028). Both anchors are in `tools/src/receipt.rs`, a recovery
target, and each named test fails at its assertion:

- F-WC10C-WASMER-ENFORCED — `render` prints every engine's cap line from
  `wasmtime`'s recorded argument, so `wasmer`, started with none, reads ENFORCED
  (`receipt_records_the_declared_memory_cap`, at its memory lines comparison;
  `receipt_cap_line_matches_the_argv_the_engine_got`, at its exact `wasmer`
  SKIPPED line).
- F-WC10C-CAP-FIXED — `render` prints a fixed `67108864` in place of the
  declared bytes (`receipt_records_the_declared_memory_cap`, at its 2 MB memory
  lines comparison).

Task 028 also adds `receipt_cap_line_matches_the_argv_the_engine_got` to
027's F-WC10-CAP-IGNORED (anchor and mutation unchanged; with no `-W` in
`wasmtime`'s argv the test fails at its one `-W` argument assertion) and
re-anchors F-WC-README-COUNT to the new total, the same bug as before. Both
keep their runner-caught label above.

Task 029's two, runner-caught (the canonical runner's summary line is in
LOG.md, task 029). Each bug was first planted by hand in an earlier task; it
gets its entry now that its file is a recovery target (R2 done). Each named
test fails at its assertion:

- F-WC3-LANE-FILES-QUOTED — `lane_files` in `tests/lab_cid.rs` drops `-z`
  and splits git's listing by line, so a name git quotes (`review"note.md`) is
  read under its quoted form and skipped (task 018's bug;
  `lane_files_reads_names_git_would_quote`, "lane_files did not list every file
  under its real name").
- F-WC9-RUN-DROPS-GRANTS — `run` in `tools/src/run.rs` passes `&[]` in place
  of `input.granted` to `verify_bundle`, so a granted import is refused (task
  020's bug; `runner_uses_only_explicit_inputs` and
  `granted_import_is_linked`).

Task 029 also re-anchors F-WC-README-COUNT to the new total, the same bug as
before.

Task 031's two, runner-caught (the canonical runner's summary line is in
LOG.md, task 031). Both anchors are in `tools/src/verify.rs`, a recovery
target, and each named test fails at its assertion:

- F-WC-B4-UNTYPED-LINKED — `verify_checked` drops the typed-entry check, so a
  granted import with no typed lab operation is linked and the module runs
  (`module_import_with_no_typed_operation_is_refused`, at its refusal).
- F-WC-B4-RIGHT-IGNORED — `parse_grants` drops the right comparison, so
  `env.f` granted `write` is read
  (`grant_naming_a_right_the_operation_does_not_need_is_refused`, at its
  refusal).

Task 031 also re-anchors F-WC-README-COUNT to the new total, the same bug as
before.

Task 032's two, runner-caught (the canonical runner's summary line is in
LOG.md, task 032). Both anchors are on `tools/build`'s new link-argument line,
and each named test fails at its assertion:

- F-WC10D-NO-MODULE-MAX — the line is removed, so the capsule declares no
  memory maximum (`built_capsule_declares_the_manifest_memory_as_its_maximum`,
  "the capsule declares no memory maximum";
  `tools_bundle_builds_a_new_bundle_and_prints_its_lab_cid` and
  `the_real_capsule_passes_the_verifier`, at `PINNED_ARTIFACT_SHA256`).
- F-WC10D-MAX-WRONG — the line passes `--max-memory=134217728`, 2048 pages
  (the same three tests: the maximum's bytes are not `memory_mb()` × 2^20, and
  the sha256 is not the pin).

Task 032 also re-anchors F-WC1-SPACED-PATH (above, still hand-proven) and
F-WC-README-COUNT to the new total, each the same bug as before.
