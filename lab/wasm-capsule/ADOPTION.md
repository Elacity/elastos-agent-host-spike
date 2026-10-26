# Adoption notes (for Anders, after 0.8.0)

This lane is falsifiable lab tooling, not a second Runtime. It claims no
Agent-Host grade row (Rong spec, section 3). wc-001 gives a reproducible
zero-import core-Wasm capsule and a receipt; wc-003..005 build on it. wc-002,
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
  (PRINCIPLES P10): wc-004's verifier will call `wasm_capsule_audit::audit`
  through a path dependency and parse no imports itself. cwa-001 implemented
  its API v1 (`audit/INTERFACE.md`).
- `tools/` — the `wasm-capsule-tools` crate, a library with no command and no
  writes. It names a lab bundle through one function,
  `wasm_capsule_tools::bundle_identity`: cc-capsule-identity's `lab_cid`,
  re-exported once and unchanged (task 010). That lane owns the hash, the walk
  (only checked handles; links, FIFOs, sockets, devices and non-UTF-8 names
  refused, each with its own reason) and the manifest check (the Runtime's own
  `CapsuleManifest` parse and `validate()`). Take that crate for the rule; this
  crate shows one caller using it through one export.
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
  wc-004 is to sign it.
- What the walk covers, and what it does not, is cc-capsule-identity's claim
  (`lab/capsule-identity/README.md`); this lane claims only that it names
  bundles through that one function.
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

## Not yet wired

The canonical falsifier runner (`examples/agent-host/falsify.py`) has no `lab`
command or recovery target for this workspace (ask **R1**, owned by the
model-provider lane). Until that one-line addition lands, run the lane's
falsifiers by hand (break → named test fails → revert); do not add a second
runner or edit `falsify.py`.
