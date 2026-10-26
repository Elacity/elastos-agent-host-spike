# wasm-capsule lab — wc-001, its lab name (task 010), `tools/bundle` (task 009) and the verifier (wc-004)

The lab's foundation: one minimal **core Wasm** capsule that anyone can rebuild
byte for byte on this one Mac. A lab bundle of it is named by
cc-capsule-identity's lab CID (task 010); wc-004 verifies a test-key signature
over that name and audits its module, and a later task runs it on two engines
(wc-005). This is lab tooling Anders may adopt; it is not
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
tools/bundle          writes a new lab bundle and prints its lab CID (bash wrapper)
tools/Cargo.toml      the `wasm-capsule-tools` crate: the lab's host-side library
tools/src/lib.rs      `bundle_identity` (the shared lab CID, one re-export) + the manifest bytes
tools/src/bundle.rs   `tools/bundle`'s rules: `parse_args` and `run`
tools/src/verify.rs   wc-004's one verify path: `verify_checked` and `verify_bundle`
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
and the verifier, below).

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

**The value.** `VerifiedBundle` holds the checked bundle and the audit's own
import list, read through `cid()`, `entries()` and `imports()`. Its fields are
private, and it has no public constructor, no `&mut` access and no
`Deserialize`, so a value exists only as `verify_checked` made it. wc-005
(task 006) stages its `entries()`.

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
  007's retired names, and the shared crate's naming functions (`lab_cid`,
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
- `verifier_preserves_upstream_refusals` — the walk's (no manifest, a link),
  the signature check's (a malformed DID, a name that is not a lab CID, a
  signature that does not verify) and the audit's (a malformed module, code in
  a custom section) refusals each come back equal to the owning lane's own,
  with the same text.
- `verifier_preserves_check_order` — inputs with two faults each: the walk
  before unsigned, unsigned before the audit, the signature before the
  entrypoint and the audit, the name before the audit.
- `verified_bundle_is_sealed` — the source, comments stripped: no public
  field, exactly five public functions (`verify_checked`, `verify_bundle` and
  the three accessors), no `&mut self`, no `Deserialize`, `Default` or trait
  impl for the value, and one literal that makes it, in `verify_checked`.
- `verifier_has_one_check_path` — the tools crate calls
  `verify_checked_signature` once and `audit` once, uses neither
  `verify_name_signature` nor `audit_component`, and `verify_bundle` only walks
  and delegates.
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

## Falsifiers

`falsifiers.json` holds nine wc-001, seven task-010, 23 task-009 and 21
wc-004 planted bugs in the provider format (`command: "lab"`). Each requires
all its named tests to fail at an assertion. The canonical runner
`examples/agent-host/falsify.py` now has a `lab` command (`cargo test
--workspace` on this workspace), but its recovery targets (`PROVIDER_TARGETS`)
still name the retired `tools/src/lab_name.rs` and none of `tools/src/lib.rs`,
`tools/src/bundle.rs`, `tools/src/verify.rs`, `capsule/capsule.json`,
`tests/common/build.rs`, `.gitignore` or `README.md`, so a killed run cannot
restore those files (ask **R1**, pending). So each falsifier is proved by the
repo's break → named test fails → revert method with `cargo test` in this
workspace, and is listed as hand-proven, pending R1. Runner-caught: none.

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
