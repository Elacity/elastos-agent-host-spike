# Adoption notes (for Anders, after 0.8.0)

This lane is falsifiable lab tooling, not a second Runtime. It claims no
Agent-Host grade row (Rong spec, section 3). wc-001 gives a reproducible
zero-import core-Wasm capsule and a receipt; wc-003..005 build on it (wc-005,
the two-engine runner, is below). wc-002,
the static import audit, moved to the cx-wasm-audit lane as the `audit/` crate.

## What you can take

- `tools/build` — a pinned, reproducible build of a core-Wasm capsule, with a
  receipt that binds the artifact to the exact toolchain, lockfile and inputs
  (PRINCIPLES P13). The knobs (one codegen unit, LTO, strip, `panic = "abort"`,
  fixed `SOURCE_DATE_EPOCH`, isolated target dir, `--remap-path-prefix`) are the
  reproducible-build recipe.
- `tests/common/wasm_shape.rs` — a tiny dependency-free reader that checks an
  artifact is core Wasm, imports nothing, and has an expected export signature.
  It is NOT a validator, and it is not grown into an import audit. Moving its
  zero-import check onto `audit/` after cwa-001 is an open item for Flint.
- `audit/` — the `wasm-capsule-audit` crate, owned by the cx-wasm-audit lane and
  a member of this workspace (wc-000). It is the one static import-audit path
  (PRINCIPLES P10): wc-004's verifier calls `wasm_capsule_audit::audit`
  through a path dependency and parses no imports itself. cwa-001 implemented
  its API v1 (`audit/INTERFACE.md`).
- `tools/bundle` — the lab bundle command (task 009). `tools/bundle OUT_DIR`
  builds with `tools/build` into a new OUT_DIR and writes a new `bundle/` of
  exactly `capsule.json` and `capsule.wasm` (moved in with `rename`), then
  prints its lab CID; `tools/bundle --name BUNDLE_DIR` prints an existing
  bundle's lab CID. Each entry is made new, so nothing is written through a
  link at OUT_DIR or under it; every refusal has its own reason, and stdout
  carries only the name (README.md, "tools/bundle"). Its rules are library
  functions (`wasm_capsule_tools::bundle`); the binary is thin.
- `tools/` — the `wasm-capsule-tools` crate, the lab's host-side library. Its
  only writes are `tools/bundle`'s new bundle. It names a lab bundle through one function,
  `wasm_capsule_tools::bundle_identity`: cc-capsule-identity's `lab_cid`,
  re-exported once and unchanged (task 010). That lane owns the hash, the walk
  (only checked handles; links, FIFOs, sockets, devices and non-UTF-8 names
  refused, each with its own reason) and the manifest check (the Runtime's own
  `CapsuleManifest` parse and `validate()`). Take that crate for the rule; this
  crate shows one caller using it through one export.
- `wasm_capsule_tools::verify` — wc-004's one verify path, as library calls.
  `verify_checked(checked, signature, accepted, granted)` refuses a missing
  signature, checks the in-memory name signature on the `CheckedBundle` with
  cc-capsule-identity's `verify_checked_signature`, finds the manifest's
  `entrypoint` among the checked entries (read with the Runtime's
  `CapsuleManifest`), and runs `wasm_capsule_audit::audit` on those checked
  bytes with the granted imports, unchanged. `verify_bundle(bundle, ...)` is
  `checked_bundle` and then `verify_checked`. It returns a sealed
  `VerifiedBundle` (`cid()`, `entries()`, `entrypoint()`, `imports()`) that
  wc-005 stages and runs.
  It is a lab check of name, signer and imports; it is no admission or launch
  decision (README.md, "Verify (wc-004)").
- `wasm_capsule_tools::run` — wc-005's runner, a library function (no
  command: the signature is in memory only). `run(bundle, signature,
  accepted, engines, out_dir)` calls `verify_bundle` with no grants, stages
  the verified `entries()` into a new `OUT_DIR/staged/` through folder handles
  (never through a link, never outside OUT_DIR), seals the module (inode and
  change time of each step on its path), checks the copy's lab CID against the
  verified `cid()`, then runs the verified `entrypoint()` with `wasmtime run
  --invoke digest` and `wasmer run --invoke digest` and the fixed argument, as
  two separate processes with no directory, environment or network flag. Each
  engine starts in the sealed staged folder and gets `./<entrypoint>`, so no
  part of OUT_DIR reaches its command line; the seal is checked before each
  engine and after the last, so the engines run the checked bytes or the run
  is refused. Both must exit successfully with byte-identical stdout; a receipt
  records the lab CID, both observed engine versions, the argument and both
  outputs. The engine programs are inputs by path (README.md, "Two engines
  (wc-005)").
- `capsule/capsule.json` — this capsule's `elastos.capsule/v1` manifest, with
  only fields of the Runtime's `CapsuleManifest`. The tools crate compiles its
  bytes in (`CAPSULE_MANIFEST`). It lists no Wasm imports: the module's own
  import section is the declaration (Rong, 26 Oct), and this one is empty.

## Requirements (what the claim rests on)

- rustc **1.91.0** with the `wasm32-unknown-unknown` target (pinned in
  `rust-toolchain.toml`). The receipt records the exact version.
- `bash`, and a sha256 tool for `tools/build`'s receipt: `sha256sum` or
  `shasum -a 256` (both present on the Mac). `tools/build` and the tests that
  check its receipt prefer `sha256sum`, then `shasum`. The lab CID needs no
  system tool: cc-capsule-identity's crate hashes it in-process.
- The path dependencies: `tools/` path-depends on `lab/capsule-identity/`,
  which path-depends on `elastos/crates/elastos-common` and
  `elastos/crates/elastos-identity` (both inherit `version.workspace`, so Cargo
  also reads `elastos/Cargo.toml`). The root package's tests dev-depend on
  `elastos-common` too, for its `CapsuleManifest`. So the lane builds only
  where `lab/capsule-identity/` and `elastos/` sit beside it as in this repo: a
  copy of `lab/wasm-capsule/` alone does not build (finding C4, cc-redteam's
  probe; README, "The lockfile coupling").
- The cargo cache: `capsule` has no `[dependencies]`; keep it that way (P18).
  The committed `Cargo.lock` holds every crate of the members and the path
  dependencies, 135 registry crates, resolved offline from this Mac's cargo
  cache. The ones capsule-identity brings carry the versions its own
  `Cargo.lock` has, where this workspace had none of that name already. The
  `audit` member pins `wasmparser` 0.258.0 and the dev-only `wat` 1.258.0.
  Cargo resolves the whole workspace, so every build, `tools/build` included,
  needs those crates in the local cargo cache. On an empty cache the first build
  needs the network. The audit's versions and features are the cx-wasm-audit
  lane's to change; capsule-identity's are that lane's, and a change there needs
  this lockfile re-locked (BACKLOG ask C3).
- Unix for the lab CID: capsule-identity's walk opens relative to folder
  handles with `rustix`. It is tested on this Mac only.

## Claim scope — do not overstate

- Reproducible on **this one Mac**, across paths and clean caches only.
  Cross-machine reproduction is **unverified**: symbol hashes depend on the
  build machine. Do not call a cross-machine match proven without a test.
- The capsule is a **core** module, not a Component. It declares no
  `elastos:bus` world and uses no `wit-bindgen`.
- The lab does not reproduce the Runtime's content-identity rule (the
  discovery below), so a bundle's name is a **lab CID**,
  `lab-cid:sha256:<hex>`, cc-capsule-identity's rule. It is a lab CID, not a
  CID: never call it the Runtime's CID, and never use it as a package identity.
  wc-004 checks a test-key signature over it (below).
- What the walk covers, and what it does not, is cc-capsule-identity's claim
  (`lab/capsule-identity/README.md`); this lane claims only that it names
  bundles through that one function.
- wc-005's two-engine result is a behaviour proof on one **core module**, on
  this one Mac: the same verified bytes print the same `digest` output under
  `wasmtime` 45.0.1 and `wasmer` 7.5.0. Both are **test-only host engines,
  neither endorsed** — separate from Wasmer's role inside a capsule as the
  POSIX RTOS PoC. It is not about the Component ABI and claims no Component
  portability. Never call Wasmer "supported", and never say the capsule "runs
  anywhere". Engine upgrades can change behaviour, so every receipt records the
  versions the engines printed, and never puts them in the lab CID.
- `digest` is a placeholder pure function to anchor identity and portability
  work. It is not a product capability.

## wc-003 discovery: how the Runtime names an artifact

A proposal for Anders, not a contract. First written for wc-003 (task 003).
Every fact below was re-checked, read-only, for wc-003a on base `a8cfd6494`
(2026-10-26), and each still holds at the cited lines.

**What the docs say.** `docs/CAPSULE_MODEL.md:53` (the Artifact row): an
artifact is an "Immutable manifest-and-payload closure, normally named by
content ID". `docs/CAPSULE_MODEL.md:67-71`: the "canonical package identity is
the CID of the complete manifest-and-payload closure", and catalog entries,
availability receipts and installed inventories "must not become competing
package identities". `docs/CONTENT_CAPSULE_DISTRIBUTION.md:49-52` adds that
payload hashes in the manifest "do not create a second package identity", and
`:94-96` that the hashed closure does not contain its own CID.
`docs/GLOSSARY.md:318-320` defines a CID only as "a content-addressed identifier
(hash of the content)". None of them gives a byte canonicalization, a codec or a
hash profile.

**What the code does (read only).** The Runtime does not compute the CID itself.
`elastos/crates/elastos-runtime/src/provider/registry.rs:1492-1507`
(`hash_local_ipfs_directory`) sends the staged closure to the IPFS provider as
`runtime_hash_staged_directory`, and `:150-165` accepts only "a CIDv1 dag-pb
sha2-256 in base32" root (`bafybei…`, 59 characters). The provider,
`capsules/ipfs-provider/src/directory_hash.rs:19-43` (`ADD_OPTIONS`), sends the
files to Kubo's `/api/v0/add` (`:820-829`) under a pinned UnixFS import
profile: CIDv1, sha2-256, raw leaves, 256 KiB chunks, a balanced DAG with at
most 174 links per file node, a wrapping directory, and no mode or mtime.
`:526-546` refuses any Kubo but v0.40.1 and checks the two HAMT settings that
have no flag, and `:275-282` requires an `_elastos_object.json` index beside
`capsule.json` in every closure.

**Reproducible lab-side without touching `elastos/`?** No. The exact rule is
Kubo v0.40.1's UnixFS importer under that profile. Reproducing it in lab code
means porting that importer (the chunker, the balanced DAG layout, dag-pb and
UnixFS encoding, the HAMT thresholds, multihash and base32 CIDs), which is the
porting the task rules out. Running Kubo from a lab test would put an IPFS
daemon and its repository into the lane. And the lab closure has no
`_elastos_object.json`, so it is not a Runtime closure anyway.

**Decision.** One lab rule: the lab names a bundle by cc-capsule-identity's
**lab CID**, `lab-cid:sha256:<hex>` over the whole `elastos.capsule/v1`
bundle, through `wasm_capsule_tools::bundle_identity` (README.md, "The lab
name"). 007's lane-own name rule (PR #105) was retired by task 010 on Rong's
one-rule note. The discovery's facts above still hold. This is a proposal to
Anders, not a contract. The value is labelled a lab CID in code and docs, never
the Runtime's CID, and it is never a package identity.

No lab tool sits in any admission or launch path. Checked at base `5751f887d`
(2026-10-26) with `git grep -n -I -F -e <pattern> -- ':!lab/'` for each of
`lab-cid`, `capsule_identity`, `capsule-identity`, `bundle_identity`,
007's retired name label (not spelled out here, so the lane's retirement grep
stays empty), `wasm-capsule-tools`, `wasm_capsule_tools`, `lab_name`,
`name_bundle`, `lab-closure`, `lab/wasm-capsule` and `tools/bundle`. The hits:

- `capsule-identity` in `examples/agent-host/falsify.py` (its
  `capsule-identity` command row and recovery targets),
  `capsules/model-provider/falsifiers.json` (the provider lane's falsifiers for
  that row) and `examples/agent-host/handoff/LOG.md` (provider 018's log line).
  All are the canonical falsifier runner and its records, test tooling only.
- `lab/wasm-capsule` in that same `handoff/LOG.md` line, a record.
- `tools/bundle` in `elastos/crates/elastos-server/src/setup.rs:4919`, a path
  in a temp data directory in the Setup test
  `replacement_suffix_is_reserved_for_scratch`, unrelated to the lab.

None is an admission or launch path.

**Proposal.**

1. The identity direction is cc-capsule-identity's: Anders's proposed CIDv1
   SHA-256 UnixFS directory root, frozen only after that lane's
   reproducibility tests, with the separate signed record kept outside the
   package. When it lands, this lane changes its one export,
   `bundle_identity`, to that function, so there is still one package identity
   (P10, P13). wc-004's signature would then cover that name.
2. Until then, keep the `lab-cid:sha256:` label, so a lab CID can never pass as
   the Runtime's CID.
3. For a verifier to recompute the Runtime's CID without Kubo, the import
   profile above (and the required files) would need a byte-level spec in
   `docs/`. Today it lives only in code.

## Signature (wc-004)

Discovery, read only at base `be952af5f` (2026-10-26).

**What the docs say.** `docs/CAPSULE_INSPECTOR.md:23` lists "CID, signature
presence, and a signature fingerprint" among what the Inspector may return,
and `:26-27` says it "reports manifest signature evidence as declared but
unverified: `verified=false`, while `verified_by` and `signed_by` are `null`".
`docs/CAPSULE_MODEL.md:53` (the Artifact row): "A valid signature proves
control of its signing key; Runtime publisher policy establishes publisher
trust." So a signature is evidence of key control, and trust is a separate
Runtime policy; neither doc gives a lab signature format.

**What the Runtime has.** `elastos/crates/elastos-server/src/crypto.rs:133`
(`verify_signed_json_envelope_against_dids`) verifies a signed JSON envelope
`{ payload, signature, signer_did }` under a domain separator. This lane does
not reproduce it: no envelope, no JSON signature and no copy of that function.

**Decision (C2).** This lane uses cc-capsule-identity's in-memory name
signature, a lab proposal: `sign_bundle`, `verify_checked_signature` and
`NameSignature`, Ed25519 over SHA-256(`lab.capsule-identity.name-signature/v1`
|| 0x00 || the printed lab CID). It adds no signature format, file or command
of its own: no `tools/sign`, no `tools/verify`, no signature file and no
serialized signature. Signing and verifying are library calls, tested in
process. If a file form is wanted, cc-capsule-identity owns it.

**"Unsupported signature version" has no input here.** Rong's wc-004 listed
that refusal. The in-memory `NameSignature` has no version field, and the
fixed domain string is checked by cc-capsule-identity's own tests, so there is
no version for this verifier to read or refuse.

**Who verifies what (Q8, Flint, 26 Oct 10:40).** The Runtime launch path owns
verification of the accepted record, the selected platform variant and the
installed contents. This lab verifier checks the signed test bundle in memory,
and nothing more. cc-capsule-identity owns the future separate signed record,
kept outside the package.

**The function.** `wasm_capsule_tools::verify::verify_checked` and
`verify_bundle` (README.md, "Verify (wc-004)"). Claim scope: an offline lab
check, on this one Mac with test keys only, that the bytes match a signed lab
CID, that an accepted test key signed it, and that every import is granted. It
makes no admission, launch or publisher-trust decision, and the granted list
(empty for ordinary callers until wc-009) is a lab stand-in, not admission.

## Not yet wired

The canonical falsifier runner (`examples/agent-host/falsify.py`) now has a
`lab` command for this workspace (`cargo test --workspace`). Its recovery
targets (`PROVIDER_TARGETS`) still name the retired `tools/src/lab_name.rs` and
not this lane's current edit files (`tools/src/lib.rs`, `tools/src/bundle.rs`,
`tools/src/verify.rs`, `tools/src/run.rs`, `capsule/capsule.json`,
`tests/common/build.rs`, `.gitignore`, `README.md`), so a killed run cannot
restore them (ask **R1**, pending, owned by the model-provider lane). The
falsifiers up to wc-004 were proved by hand (break → named test fails →
revert); wc-005's were run by the canonical runner. Do not add a second runner
or edit `falsify.py`.
