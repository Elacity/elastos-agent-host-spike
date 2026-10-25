# Adoption notes (for Anders, after 0.8.0)

This lane is falsifiable lab tooling, not a second Runtime. It claims no
Agent-Host grade row (Rong spec, section 3). wc-001 gives a reproducible
zero-import core-Wasm capsule and a receipt; wc-003 puts it in a bundle named by
a lab hash of its whole closure; wc-004 and wc-005 build on both.

## What you can take

- `tools/build` — a pinned, reproducible build of a core-Wasm capsule, with a
  receipt that binds the artifact to the exact toolchain, lockfile and inputs
  (PRINCIPLES P13). The knobs (one codegen unit, LTO, strip, `panic = "abort"`,
  fixed `SOURCE_DATE_EPOCH`, isolated target dir, `--remap-path-prefix`) are the
  reproducible-build recipe.
- `tests/common/wasm_shape.rs` — a tiny dependency-free reader that checks an
  artifact is core Wasm, imports nothing, and has an expected export signature.
  It is NOT a validator; wc-002 grows it into the static import audit.
- `tools/bundle` with its one rule, `tools/lab_name.rs` (wc-003) — a closure
  check that fails closed (exactly `capsule.json` and `capsule.wasm`, regular
  files only; an extra, missing or symlinked file, a FIFO or a directory is
  refused with its path), a length-framed canonical byte stream over sorted
  paths and exact bytes, and a pinned test vector. Every capsule file read and
  write of `tools/bundle` goes through one no-follow open that checks, then
  uses, the same handle (`open_regular`, the Runtime's own pattern in
  `elastos/crates/elastos-runtime/src/provider/bridge.rs:118-138`), and the
  build mode writes only a new bundle. Take the closure check and the refusals;
  replace the hash with the Runtime's CID rule (see the wc-003 discovery below).

## Requirements (what the claim rests on)

- rustc **1.91.0** with the `wasm32-unknown-unknown` target (pinned in
  `rust-toolchain.toml`). The receipt records the exact version.
- `bash`, and a sha256 tool: `sha256sum` or `shasum -a 256` (both present on the
  Mac). `tools/build` and the tests prefer `sha256sum`, then `shasum`.
- No network: the lane has no external crates, so `cargo build --locked` builds
  from clean caches offline. Keep it that way — a dependency would put the
  lockfile on the network and widen the surface.
- macOS for the lab tools: with no `libc` crate, `tools/lab_name.rs` writes out
  the macOS values of `O_NOFOLLOW`, `O_NONBLOCK` and `ELOOP` (checked against
  the system headers). Any other OS is a compile error until its values are
  added and the symlink and FIFO tests pass there. In the Runtime, take these
  from `libc` as the rest of the tree does.

## Claim scope — do not overstate

- Reproducible on **this one Mac**, across paths and clean caches only.
  Cross-machine reproduction is **unverified**: symbol hashes depend on the
  build machine. Do not call a cross-machine match proven without a test.
- The capsule is a **core** module, not a Component. It declares no
  `elastos:bus` world and uses no `wit-bindgen`.
- wc-003 did not reproduce the Runtime's content-identity rule (the discovery
  below), so the bundle's name is a **lab name**, `lab-sha256:<hex>`. Never
  call it a CID, and never use it as a package identity. wc-004 signs it.
- `digest` is a placeholder pure function to anchor identity and portability
  work. It is not a product capability.
- The no-follow open covers each closure file's own path. The bundle directory
  named with `--name`, and `OUT_DIR`, are used as given (a link in their own
  path is followed), and a swap of that directory by another process while the
  tool runs is not covered: that needs directory-relative opens (`openat`),
  which stable Rust's std lacks. The Runtime would get them from `libc`, as
  `capsules/ipfs-provider/src/directory_hash.rs` does.

## wc-003 discovery: how the Runtime names an artifact

A proposal for Anders, not a contract.

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
`capsules/ipfs-provider/src/directory_hash.rs:19-43` (`ADD_OPTIONS`), streams
the files to Kubo's `/api/v0/add` under a pinned UnixFS import profile: CIDv1,
sha2-256, raw leaves, 256 KiB chunks, a balanced DAG with at most 174 links per
file node, a wrapping directory, and no mode or mtime. `:526-546` refuses any
Kubo but v0.40.1 and checks the two HAMT settings that have no flag, and
`:275-282` requires an `_elastos_object.json` index beside `capsule.json` in
every closure.

**Reproducible lab-side without touching `elastos/`?** No. The exact rule is
Kubo v0.40.1's UnixFS importer under that profile. Reproducing it in lab code
means porting that importer (the chunker, the balanced DAG layout, dag-pb and
UnixFS encoding, the HAMT thresholds, multihash and base32 CIDs), which is the
porting this task rules out. Running Kubo from a lab test would put an IPFS
daemon and its repository into the lane. And the lab closure has no
`_elastos_object.json`, so it is not a Runtime closure anyway.

**Decision.** The lab names a bundle `lab-sha256:<hex>` over its own documented
closure (README.md, "wc-003"). It is labelled a lab name in code, output and
docs, never a CID, and it is never a package identity. No lab tool sits in any
admission or launch path: nothing in `elastos/`, `capsules/`, `scripts/`,
`examples/` or `docs/` refers to the lab tools or to `lab-sha256` (grep,
2026-10-25; the one hit, a `tools/bundle` string in a test fixture in
`elastos/crates/elastos-server/src/setup.rs:4919`, is unrelated).

**Proposal.**

1. If the Runtime adopts this tool, keep the closure check and its fail-closed
   refusals, and swap the hash: name the same closure through the IPFS
   provider's directory hash, so there is one package identity (P10, P13).
   wc-004's signature would then cover that CID, not a lab name.
2. Until then, keep the `lab-sha256:` label, so a lab name can never pass as a
   CID.
3. For a verifier to recompute the Runtime's CID without Kubo, the import
   profile above (and the required files) would need a byte-level spec in
   `docs/`. Today it lives only in code.

## Not yet wired

The canonical falsifier runner (`examples/agent-host/falsify.py`) has no `lab`
command or recovery target for this workspace (ask **R1**, owned by the
model-provider lane). Until that one-line addition lands, run the lane's
falsifiers by hand (break → named test fails → revert); do not add a second
runner or edit `falsify.py`.
