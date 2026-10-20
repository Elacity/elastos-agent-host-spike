# P4 design: the photo viewer bundle named by CID and signed by a publisher DID

Slice P4, **design only**. No code, and nothing outside this file changed. Every claim cites `file:line` on
`spike/photo-viewer` (6fd0756e). Paths under `elastos/crates/` are shortened to the crate name.

The bundle is the two capsules from P3:

- the `photo-viewer` Component, the core (`examples/photo-viewer`, on the P1 to P2b branches);
- the planned `image-viewer` surface, a web projection.

In Phase 2 the surface manifest names its core by CID (P3 design, section 4, on `claude/photo-p3`). Roadmap
milestone 2.2.

## 1. What exists today

### 1.1 Signature check at launch

1. **Admission setup.** `Runtime::configure_capsule_admission` builds one `SignatureVerifier`
   (`elastos-server/src/runtime.rs:188-228`, called from `elastos-server/src/main.rs:2330-2336`).
   - Its keys are the `trusted_keys` hex list from the runtime config (`runtime.rs:197-199`), plus the
     `did:key` publisher DIDs of the installed release source, decoded to Ed25519 keys (`runtime.rs:200-204`).
   - Unsigned capsules are allowed in three ways (`runtime.rs:206-210`):
     - with an installed release, only if that release lists them (`InstalledRelease`);
     - with no release and `dev_mode`, freely (`Allowed`);
     - otherwise they are refused (`Refused`).
2. **The check.** `verify_capsule_signature` runs before every local launch (`runtime.rs:282`, body `:351-408`).
   - An unsigned capsule goes through the rule above (`:356-379`).
   - A signed one: Runtime hashes **only the entrypoint file** (`:389-397`) and calls `verify_capsule`
     (`:400`).
3. **What is signed.** `verify_capsule` checks the manifest's base64 `signature` against **any** trusted key
   (`elastos-runtime/src/signature/verifier.rs:79-103`). The signed message is
   `SHA256(serde_json::to_string(manifest without signature)) || SHA256(entrypoint)`
   (`verifier.rs:117-136`; signer `:138-153`).
4. **The trust model.** A flat list of Ed25519 keys (`verifier.rs:16-51`). No key is tied to a publisher name,
   a role or a capsule name. Any trusted key admits any capsule.

What this does not cover:

- **Only the entrypoint is hashed.** Other files in the capsule (icons, and for a web projection the
  scripts its `browser/index.html` loads) are outside the signed bytes.
- **The manifest bytes are not canonical.** They are whatever `serde_json::to_string` of the Rust struct gives
  (`verifier.rs:125-129`): struct field order, with defaults filled in. Two Runtime versions whose struct
  differs would sign different bytes for the same file.
- **No CID.** Nothing names the capsule; the signature is embedded in the very manifest it covers
  (`elastos-common/src/manifest.rs:130-132`).

### 1.2 The installed release: signed CID receipts

SECURITY.md:16-20 says installed Homes admit only release-path capsules matched by signed CID receipts, and
capsules signed by the release publisher.

- **The check.** `verify_installed_release_capsule` (`elastos-server/src/setup.rs:1596-1625`) reads the
  release's signed `components.json` (`:1603-1605`). It requires an entry with a non-empty `cid` and the
  capsule at its release install path (`:1606-1617`), then requires install state `Installed` (`:1618-1624`).
- **An entry** is `{cid, sha256, size, repository, platforms}` (`setup.rs:158-167`). The checked-in
  `components.json` leaves them empty; release fills them.
- **The release artifact** is a `<name>-<platform>.capsule.tar.gz` with a `sha256:` checksum
  (`scripts/components-release-integrity-check.py:215-216`), plus a separate `entrypoint_sha256`
  (`:93`, `:425-431`). Publish gets each CID back from the IPFS provider's `add_path` and checks it against
  the signed reference (`elastos-server/src/publish.rs:699-708`, `:511-517`).
- **Not canonical either.** A tar.gz carries file order, timestamps and a gzip header. The same capsule can
  pack to different bytes, so this CID names the archive, not the capsule.

### 1.3 The documented target

- **The artifact.** An immutable manifest-and-payload closure, normally named by content ID. A signature
  proves control of a key; Runtime publisher policy establishes trust (`docs/CAPSULE_MODEL.md:53`).
- **The identity.** The CID of the complete closure, manifest and payload. Payload hashes inside the manifest
  do not create a second identity (`docs/CONTENT_CAPSULE_DISTRIBUTION.md:49-54`, `docs/CAPSULE_MODEL.md:68`).
- **The signature.** A publisher DID signs a **detached** claim for the exact CID; the closure does not
  contain its own CID (`docs/CONTENT_CAPSULE_DISTRIBUTION.md:94-96`). Runtime verifies the CID and the
  signature under configured trust before admitting (`:97-99`, `:106-109`).

### 1.4 How one capsule names another today

- **Content to viewer.** A content capsule names its viewer by **name**: `"viewer": "gba-emulator"`
  (`capsules/gba-ucity/capsule.json:11`, `capsules/gba-nonogram/capsule.json:10`). The field is documented as
  "path or CID" (`manifest.rs:126-128`), but it is matched by name (`elastos-server/src/api/browser_capsules.rs:455-480`,
  check at `:469`). It is only valid on content capsules (`manifest.rs:583-586`).
- **`requires`.** Entries are `{name, kind}` only, with `deny_unknown_fields` (`manifest.rs:273-287`).
- **Result.** Nothing lets a viewer or app name another capsule by CID.

### 1.5 Tying a CID to source

The P2 container build is reproducible. The same commit gives the same entrypoint bytes on any machine that
runs `examples/photo-viewer/repro/build-in-container.sh`: `add93842…dd22` for P1b and later, `9cf68749…`
for P1 (P2 report). So "this CID was built from that commit" can be checked by rebuilding, not just claimed.
`docs/CAPSULE_MODEL.md:53` already has the slot for this: "Provenance records describe claimed lineage."

## 2. Design

### 2.1 What the CID covers

One CID per capsule. Each capsule keeps one role (P13). The surface and the core are two closures.

- **The closure** is every file the capsule ships, and nothing else:
  - `capsule.json` (with no `signature` field, see 2.3);
  - the entrypoint;
  - every other shipped file, such as icons, or for the surface its `browser/` assets.

  Source, `Cargo.*`, tests and build outputs are not in it.
- **The listing.** One canonical JSON document, `elastos.capsule.closure/v1`: the sorted list of
  `{path, size, sha256}` for every file, with paths relative, `/`-separated and no `..`. It is encoded with
  RFC 8785 (JCS), so the bytes do not depend on a Rust struct.
- **The CID** is CIDv1, raw codec (`0x55`), sha2-256 multihash over the listing bytes, base32 `b…`. That is
  the form the publication tests already build (`elastos-server/src/publish.rs:2433`).
  - It needs no IPFS node to compute.
  - Distribution may still put the files on IPFS. Their IPFS CIDs are delivery details; the listing CID is
    the identity (P2, P15).
- **Why not tar.gz or a UnixFS directory CID:**
  - tar.gz is not canonical (1.2).
  - A UnixFS CID depends on chunker, CID version and raw-leaves settings, so every tool must agree on them.
    The listing has one rule.

### 2.2 Who signs, and what

- **Signer.** The publisher DID, `did:key` Ed25519, the form the release publisher already uses
  (`runtime.rs:200-204`).
- **Detached.** The signature goes in a separate claim, `elastos.capsule.claim/v1`, not in `capsule.json`:
  `{cid, name, version, role, publisher_did, provenance?}`, JCS-encoded.
- **Domain-separated.** It is signed with a domain string, `elastos.capsule.claim/v1`, the way launch tokens
  are (`elastos-server/src/api/gateway_home_token.rs:312-316` calling `domain_separated_sign`,
  `elastos-server/src/crypto.rs:92`).
- **Optional provenance.** `{source_commit, recipe, image_digest}`, using the P2 recipe. It is a claim
  (`CAPSULE_MODEL.md:53`): anyone can check it by rebuilding. Admission does not depend on it.

### 2.3 How Runtime admits by CID

At install, and again at launch from the staged directory:

1. Read the claim. Recompute the listing from the directory. Every listed file must exist with its size and
   hash, and **no unlisted file** may be present.
2. Recompute the CID. It must equal the claim's `cid`.
3. Verify the signature against `publisher_did`.
4. **Trust policy:** look up the publisher DID. A policy entry names the roles, and optionally the capsule
   names, that publisher may ship. This is roadmap correction 1, "per-publisher trust policy by role". Today's
   flat key list (1.1) becomes this table: the release publisher may ship every first-party role, and a
   development key may ship only what the developer lists.
5. Record the install receipt `{principal, cid, publisher, result, time}`
   (`docs/CONTENT_CAPSULE_DISTRIBUTION.md:73`).

Every step fails closed. Each reason names the item and what was expected:

| Reason | When |
|---|---|
| `claim_missing` | No claim next to the capsule |
| `closure_mismatch` | A listed file is missing or has a different size or hash; or an unlisted file is present |
| `cid_mismatch` | The recomputed CID differs from the claim |
| `signature_invalid` | The signature does not verify for the claim's DID |
| `publisher_untrusted` | No trust policy entry for the DID |
| `publisher_role_refused` | The policy does not allow this role or name for that DID |

This does **not** lift SECURITY.md:16-20. A signed third-party *executable* capsule still waits for key-free,
confined workers (#285). For the spike, the publisher is the release publisher or a development key.

### 2.4 How the surface names its core

The surface manifest adds the core's CID to its requirement:

```json
"requires": [{ "name": "photo-viewer", "kind": "capsule", "cid": "bafkrei…" }]
```

- That is a schema change: `requires` refuses unknown fields today (`manifest.rs:273-287`).
- The surface's own closure contains its `capsule.json`, so **the surface CID pins the core CID**. Opening the
  surface by its CID fixes both capsules.

At launch, the P3 Phase 2 steps 4 to 6 run **exactly** that core:

| Reason | When |
|---|---|
| `core_missing` | No admitted capsule with that CID |
| `core_mismatch` | The installed `photo-viewer` is a different CID; the message names both |

A name alone never selects the core. The same field later replaces the content `viewer` name, for
`gba-ucity` and `gba-nonogram` (ROADMAP "content capsules" table).

### 2.5 What is a shipping change

All of these need Sasha's yes. All are Phase 2, after 0.8.0 (ROADMAP "Phases").

1. The closure listing and CID, and detached claim verification, in `runtime.rs`, `verifier.rs` and setup.
   They replace the entrypoint-only hash and the in-manifest `signature`.
2. The publisher trust policy table, in place of the flat `trusted_keys` list.
3. `requires[].cid` in `elastos-common/src/manifest.rs`, and Runtime resolving the core by CID.
4. Publish tooling that emits the listing and the claim, instead of only `components.json` archive checksums.

**Without a shipping change** the spike can prove the format. An offline tool in `examples/photo-viewer/`
would compute the listing and CID for both capsules, sign a claim with a test DID, and verify it. Tests and
falsifiers would cover each refusal reason above. The tool's verify function can later become the Runtime
one.

## Principles checked

- **2 (stable identity over transport).** A capsule is named by the CID of its closure listing, not by its
  name, its archive or an IPFS delivery CID.
- **3 (no ambient authority).** A key admits only the roles and names its policy lists, not every capsule.
- **10 (one path).** One identity per capsule (the listing CID). Archive checksums and payload hashes stay
  delivery and format details (`CONTENT_CAPSULE_DISTRIBUTION.md:49-52`).
- **11 (fail closed, then explain).** Six admission reasons and two core-resolution reasons, each naming what
  was expected.
- **13 (objects, capsules and spaces distinct).** The CID covers the complete closure, manifest and payload;
  each capsule keeps one role.
- **15 (trust travels with content).** A detached publisher-DID claim signs the exact CID. Provenance ties the
  CID to a source commit through the P2 recipe.
- **16 (UI is not authority).** The surface cannot choose its core; its own signed bytes fix it.
- **18 (isolated instances).** Admission binds an instance to an exact artifact. Third-party executables
  still wait for confined workers (#285).

## Roadmap milestone

2.2 (signed bundles named by CID). Roadmap correction 1 (per-publisher trust policy by role). The provenance
link uses 2.2 and 2.4 (reproducible builds). Content `viewer` by CID is in the ROADMAP app table.

## Questions for Sasha

1. **Identity encoding.** Is the closure listing, CIDv1 raw over JCS, the identity you want? Or should it be a
   UnixFS directory CID with pinned chunking settings? I lean to the listing: it needs no IPFS to compute,
   and has one rule.
2. **Moving the signature out of `capsule.json`.** It would become a detached claim. Is that acceptable, and
   how should the existing release capsules migrate (today they are unsigned and admitted by release
   receipts)?
3. **Trust policy.** Is a table of publisher DID to roles (and optional names) the shape? Should it live in
   the runtime config, replacing `trusted_keys`, or in the signed release source?
4. **Naming the core.** Should the surface name it with `requires[].cid`, or with a new dedicated field?
5. **Provenance.** Should the claim carry the P2 provenance (commit, recipe, image digest), or should it be a
   separate record?
6. **Next slice.** May the spike build the offline tool in `examples/photo-viewer/` (listing, CID, claim,
   verify, with tests and falsifiers per reason) as P4b? It needs no Runtime change.

## Next slice

P4b, the offline closure, CID and claim tool with tests and falsifiers, if question 6 is yes. The P3 seam
review comes first, per the review order.
