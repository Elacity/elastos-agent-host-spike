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
  `VerifiedBundle` (`cid()`, `entries()`, `imports()`, `unused_grants()`) for
  wc-005 to stage. It is a lab check of name, signer and imports; it is no
  admission or launch decision (README.md, "Verify (wc-004)").
  wc-009a (task 020): `read_grants(path)` is the one reader of the lab grants
  file (`wc-009.lab-grants/v1`, labelled "lab stand-in, not admission"), and its
  list is the `granted` input (README.md, "Granted imports only (wc-009a)").
- `wasm_capsule_tools::run` — the lab's engine runner, as library calls.
  `run_engine` (wc-005a, task 014) runs one test-only host engine on
  `entrypoint()`'s verified bytes, written from memory into a new `0o700`
  folder, with a fixed argv, stdin null and an empty environment. `run`
  (wc-005b, task 015) takes a `RunInput` (bundle path, in-memory signature,
  accepted signer DIDs, the granted imports from the lab grants file (task
  020), both engine program paths, work root), calls `verify_bundle` once with
  those grants unchanged, then `run_engine` for `wasmtime` and
  then for `wasmer`, one after the other, and requires both to succeed with
  byte-identical stdout. It returns the verified `cid()`, both outputs, and
  (task 020) `linked()` and `unused_grants()` (README.md, "Same output on two
  engines (wc-005b)").
  `wasm_capsule_tools::receipt` (wc-005c, task 016) renders that run as
  `schema: wc-005.run-receipt/v1` lines (the lab CID, `digest`, `1592590337`,
  each engine's version, exit status and stdout), and writes it only with
  `bundle::write_new_file`. The versions are observed, not configured: each is
  the first line the engine printed for `--version` before the module ran, so
  an engine upgrade shows in the receipt, and none is part of the lab CID
  (README.md, "Run receipt (wc-005c)").
  The two-engine result is a behaviour proof on one **core module** on this
  Mac, not the Component ABI. Rong's ruling (26 Oct):
  Both engines, wasmtime and wasmer, are test-only and not endorsed. The engine choice is Anders's.
  This is separate from Wasmer's role inside a capsule as the POSIX RTOS PoC.
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
  discovery below), so a bundle's name is a **lab CID**, cc-capsule-identity's
  rule: the 59-character CIDv1 SHA-256 UnixFS directory root of the bundle,
  printed `bafybei...` (`lab/capsule-identity/README.md`, "The encoding"). It
  is a lab value, not the Runtime's CID: never call it the Runtime's CID, and
  never use it as a package identity or an admission.
  wc-004 checks a test-key signature over it (below).
- What the walk covers, and what it does not, is cc-capsule-identity's claim
  (`lab/capsule-identity/README.md`); this lane claims only that it names
  bundles through that one function.
- `digest` is a placeholder pure function to anchor identity and portability
  work. It is not a product capability.
- The two-engine run (wc-005b) shows that one verified core module printed the
  same `FIXED_OUTPUT` for `FIXED_INPUT` on `wasmtime` 45.0.1 and `wasmer` 7.5.0
  on this one Mac. It says nothing about the Component ABI, other engines,
  other machines or other modules; both engines are test-only, not endorsed.

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
**lab CID**, the 59-character CIDv1 SHA-256 UnixFS directory root
(`bafybei...`) of the whole `elastos.capsule/v1` bundle, through
`wasm_capsule_tools::bundle_identity` (README.md, "The lab name";
`lab/capsule-identity/README.md` has the rules). 007's lane-own name rule
(PR #105) was retired by task 010 on Rong's one-rule note. This lane keeps one
identity path and no UnixFS code of its own. Its two pins (README.md, "The lab
name" and "tools/bundle") were recomputed by task 024 outside the lab code,
with a `python3 -I` script written from that README's rules (quoted in LOG),
and pinned only where they equal `bundle_identity`'s output:
`bafybeihtyzfql54i7irft23lg2mk44toqdww53ryuhs2psrknfjw4qhpcy` (the manifest
beside the 8-byte empty module) and
`bafybeib34owcqffbwkntlhvbjngcj7eyeqqxx7aoefehqt2dqm2yu5jwse` (the manifest
beside `tools/bundle`'s `capsule.wasm` on this Mac). The discovery's facts above still hold. This is a proposal to
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
   package. That lane's task 018 made its one `lab_cid` print that root, and
   this lane's one export, `bundle_identity`, needed no change, so there is
   still one package identity (P10, P13). wc-004's signature covers that name.
2. A lab CID still never passes as the Runtime's CID, now by what it covers
   rather than by a label (`lab/capsule-identity/README.md`, "Why a lab CID
   and not the Runtime's CID"). The Runtime's CID is what its IPFS provider
   returns for the capsule's archive, a gzip PAX tar that also holds the
   folder's name, folder entries, modes and links. The lab CID is the UnixFS
   root over the bundle's regular files alone, so it never equals the
   archive's CID. It is called "lab CID" in code, output and docs, and no
   Runtime code reads it.
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
(from the lab grants file since wc-009a, task 020) is a lab stand-in, not
admission.

**The grants file (wc-009a, task 020).** The lab grants file is a lab stand-in
for the Runtime's grant decision
(https://github.com/Elacity/elastos-runtime/issues/464), not admission.

**Hosting discovery (wc-009b0, task 022).** README.md, "Granted import
hosting discovery (wc-009b0)", records how each engine's CLI could supply a
granted import. Rong's ruling (26 Oct):
Discovery only: no engine-specific host-function route (a preload module or a CLI flag) becomes the lab's import path; granted imports stay a stand-in for the Runtime/provider contract (P10, P18).

## Runtime ABI for a bare capsule (wc-008)

Discovery, read only at base `f9d2b48f8160398e843e0d656d2771fefc4fef29`
(`git rev-parse HEAD` at task start, 2026-10-26), for M1 check B2. The
question: which `runtime_abi` in `elastos.capsule/v1` fits this lane's
zero-import core Wasm module, which is not a Component? Lines are in
`elastos/crates/elastos-common/src/manifest.rs` (last changed in `f4b7236d4`)
unless a file is named. `runtime_abi` is optional (`:36-41`): "Runtime uses
this field to select the execution provider". `validate()` (`:432`) calls
`validate_execution_metadata()` (`:494`, defined at `:731`). This capsule's
manifest is `role` `app`, `type` `wasm`, `entrypoint` `capsule.wasm`.

The seven `CapsuleRuntimeAbi` values (`:1050-1067`), each put into this
capsule's manifest and run through `validate()` by
`no_runtime_abi_names_a_bare_core_module`:

| Value | Fits a bare core module? | Why (file:line) |
|---|---|---|
| `native-host` | no | only the trusted shell helper: `role` `shell`, `name`/`entrypoint` `shell` (`:866-881`) |
| `elastos.provider-stdio/v1` | no | a native provider: `role` `provider`, `type`/`execution` `native-provider` (`:848-865`) |
| `wasi-preview1` | no | refused outright: "WASI Preview 1 is not a supported product capsule ABI" (`:738-743`) |
| `elastos.runtime-projection/v1` | no | a web projection: `execution` `web-projection`, its bus contract, a web projection (`:802-846`) |
| `elastos.component/v1` | no (a near fit, not a fit) | a Component: `type` `wasm`, `execution` `component`, `bus_contract` `elastos:bus@v1`, the bus WIT's sha256 (`:775-801`) |
| `microvm-linux` | no | needs `type` `microvm` (`:882-888`) |
| `data` | no | needs `type` `data` (`:889-894`) |

**No `runtime_abi` (this capsule today).** The manifest passes `validate()`
(`lab_manifest_passes_runtime_validate`), but no run path takes it. Both run
paths, re-read at the base above, branch on `type` `wasm` and refuse anything
that is not a Component. `is_component_capsule()` (`:674-678`) is true only for
`runtime_abi` `elastos.component/v1`, `execution` `component` or
`bus_contract` `elastos:bus@v1`, and this manifest has none of them.

- `elastos/crates/elastos-server/src/run_cmd.rs`, `run_capsule` (`:3`): the
  manifest is parsed and validated (`load_valid_manifest_if_present`,
  `:149-163`); `match manifest.execution_type()` (`:35`) reaches
  `CapsuleType::Wasm` (`:51`); the condition is
  `if !manifest.is_component_capsule()` (`:52`), refused at `:53-56` with
  "WASI Preview 1 capsules are not supported; '{}' must use
  runtime_abi=\"elastos.component/v1\"". Only a Component goes on, to
  `run_component_via_operator_runtime` (`:58`).
- `elastos/crates/elastos-server/src/capsule_cmd.rs`, `run_capsule` (`:184`):
  after `load_capsule_manifest` (`:255`), the condition is
  `if manifest.capsule_type == elastos_common::CapsuleType::Wasm` (`:267`) and
  then `if !manifest.is_component_capsule()` (`:268`), refused at `:269-272`
  with "WASI Preview 1 capsules are not supported; '{}' must use
  runtime_abi=\"elastos.component/v1\" (Runtime projections open through
  Home)". Only a Component goes on, to `run_component_capsule` (`:274`).

The planner's hint (a run needs `runtime_abi="elastos.component/v1"`) holds in
both files at this base. A manifest that passes `validate()` is not proof that
a run path accepts a bare module, and here none does.

**Decision: `NO_ABI_FOR_BARE_CAPSULE`.** No value fits. `capsule/capsule.json`
keeps no `runtime_abi`, and the pinned lab CID does not change. Declaring
`elastos.component/v1` on a module that is not a Component would be a near
fit, and the Runtime refuses it anyway (falsifier F-WC8-NEAR-FIT). The lane
records the gap as SKIPPED in `bare_capsule_runtime_abi_is_recorded_as_skipped`,
never PASS, and invents no field and no ABI value.

## Gaps for Anders

Facts only; nothing here is proposed as a contract.

1. **No runtime ABI for a bare core module.** Rong's design question (26 Oct),
   in his words: "Component-only admission means a bare core module (the
   closest thing to a self-contained DigitCapsule) has no path in v1. Is that
   intended, or should v1 have a bare-module ABI?" The facts are in the section
   above: none of the seven `CapsuleRuntimeAbi` values (`manifest.rs:1050-1067`)
   describes a core module that is not a Component, and both run paths
   (`run_cmd.rs:51-57`, `capsule_cmd.rs:267-273`) refuse a `type` `wasm`
   capsule unless `is_component_capsule()` (`manifest.rs:674-678`). Tied to
   https://github.com/Elacity/elastos-runtime/issues/463 ("make Bus v2 the one
   app ABI").
2. **No summary of Wasm imports in the manifest.** Rong's words (26 Oct): "v1
   has no manifest summary of Wasm imports for user review or approval; the lab
   treats the module's import section as the declaration." The facts:
   `CapsuleManifest` has `#[serde(deny_unknown_fields)]` (`manifest.rs:20`), so
   a field the lab invents is refused by name (`an_unknown_manifest_field_is_refused_by_name`
   adds `lab_imports` and sees the Runtime refuse it, and `bundle_identity`
   refuse the bundle with its manifest-parse reason). No field lists imports:
   `requires` (`:76-80`) names capsules and external tools, `interfaces`
   (`:94-100`) are exposed interfaces, `providers` (`:112-114`) map schemes to
   sources, and `capabilities` (`:90-92`) take only `elastos://` and
   `localhost://` URIs (the check at `:616-622`, its message at `:619`), not
   module and name pairs. The module's import section is inside the lab CID,
   so a signature over that name covers it. The import rule at link time is a
   later lane task (wc-009); this task adds no import check. Tied to
   https://github.com/Elacity/elastos-runtime/issues/463 and
   https://github.com/Elacity/elastos-runtime/issues/464.

## Not yet wired

The canonical falsifier runner (`examples/agent-host/falsify.py`) now has a
`lab` command for this workspace (`cargo test --workspace`). Its recovery
targets (`PROVIDER_TARGETS`) still name the retired `tools/src/lab_name.rs` and
not this lane's current edit files (`tools/src/lib.rs`, `tools/src/bundle.rs`,
`tools/src/verify.rs`, `capsule/capsule.json`, `tests/common/build.rs`,
`.gitignore`, `README.md`), so a killed run cannot restore them (ask **R1**,
pending, owned by the model-provider lane). Until that lands, the lane's
falsifiers are proved by hand (break → named test fails → revert); do not add
a second runner or edit `falsify.py`. The runner itself does run lab entries:
`--from lab/wasm-capsule/falsifiers.json F-WC8 F-WC3-LABCID-PIN` reported
`summary: 5 CAUGHT of 5` for wc-008's four and the reused entry, which still count as hand-proven, pending R1, until the
recovery targets name `capsule/capsule.json` and `tools/src/lib.rs`.
