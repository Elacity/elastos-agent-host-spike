# P4b report: the bundle tool, named by CID, signed by a publisher DID

Slice P4b, as approved (review answer 9): **spike only**, after the seam fixes. It is an offline tool in
`examples/photo-viewer/bundle/` (crate `capsule-bundle`) that proves the P4 design format. **No Runtime
change.** It reuses the Runtime's own did:key codec (`elastos-identity`) and its domain-separated signing
construction.

Branch `claude/photo-p4b`, from `claude/photo-p4` (the design note).

## Decisions recorded (review answers 4 to 8)

| # | Decision | Where in the tool |
|---|---|---|
| 4 | A capsule is named by the CID of its closure listing | `listing.rs`, `cid.rs` |
| 5 | A detached claim. Release capsules keep release receipts until one cut-over release, with no long period accepting both | `claim.rs`; the cut-over is a shipping change, not built |
| 6 | A DID-to-roles table in the signed release source. Local config may only add a dev key, only in dev mode | `policy.rs` |
| 7 | `requires[].cid` on the existing requirement entry | `admit::resolve_requires` |
| 8 | Provenance is a separate record naming the CID. Independent rebuilders add their own. The claim stays minimal | `provenance.rs`; `Claim` has five fields |

## What it does

1. **Closure listing**, `elastos.capsule.closure/v1`: `{"files":[{"path","sha256","size"}…],"schema"}`. It has
   every file under the capsule directory, sorted by path bytes, with sorted keys and no whitespace. That is
   also the RFC 8785 form, because every key is ASCII and no path may hold a control character. The walk
   uses `lstat` and never follows a link. Refusals:
   - `path_invalid`: an empty, `.` or `..` segment, a `\`, a control character, or a non-UTF-8 name;
   - `path_not_nfc`: a non-ASCII name that is not NFC;
   - `path_case_collision`: two paths equal under full Unicode case folding (`A`/`a`, `ß`/`ss`, `σ`/`ς`);
   - `special_file`: a symlink (to a file, to a directory, dangling, or in place of `capsule.json`), a socket
     or a FIFO;
   - `manifest_missing`: no `capsule.json` at the root.
2. **CID**: CIDv1, raw (`0x55`), sha2-256, base32 `b…`, over the listing bytes. Checked against the RFC 4648
   vectors and the well-known CID of `hello`.
3. **Claim**, `elastos.capsule.claim/v1`: `{cid, name, version, role, publisher_did}`, strict (unknown fields
   refused). It is signed as `Ed25519(SHA256("elastos.capsule.claim/v1" || 0x00 || canonical claim))`, the
   construction of `elastos-server/src/crypto.rs:88-128`. The signer is `publisher_did`, a did:key decoded by
   `elastos_identity::decode_did_key`.
4. **Trust policy**, `elastos.release.trust-policy/v1`:
   - `{publishers: [{did, roles, names?}], revoked_dids, revoked_cids}`, signed by a **pinned** release root
     DID. The DID the document names for itself is not trusted.
   - `LocalConfig` is `{dev_mode, dev_keys}` and nothing else (unknown fields refused). It cannot add
     revocations, lift them or widen a release publisher.
   - A dev key is refused outside dev mode. In dev mode, a dev key that is the release root, a release
     publisher, a revoked DID, or listed twice is refused.
5. **Admission** (`admit`), in order. Each step fails closed:

   | Step | Refusal |
   |---|---|
   | List the closure | the listing refusals above |
   | Recompute the CID, compare with the claim | `cid_mismatch` (also an unlisted extra file) |
   | Verify the claim's signature | `signature_invalid` (another key, a changed field, another domain, malformed hex, not a did:key) |
   | The claim's name, version and role are the manifest's | `claim_manifest_mismatch`; `claim_malformed` for bad JSON or a non-semver version |
   | Revocations | `cid_revoked`, `publisher_revoked` |
   | Publisher, roles and names | `publisher_untrusted`, `publisher_role_refused` |
   | Inventory | `version_downgrade` (a lower semver of an installed name, pre-release ordering included); `version_conflict` (the same version with another CID) |
   | Stage | `staged_mismatch` |

   The stage step copies the listed files into `store/.staging-<random>`, then re-lists and re-hashes the
   **copy**, so a source changed after verification is caught. It then seals it (files `0444`, directories
   `0555`) and renames it to `store/<cid>`. A failed copy is removed. The same CID again is idempotent.
6. **Load** (`load(store, cid)`) is the only way in after admission:
   - it takes only a CID-shaped name (`path_invalid`);
   - every file and directory must be read-only (`staged_not_read_only`);
   - the copy is re-hashed to its CID (`staged_mismatch`).

   Admission also goes through `load`, so a planted `store/<cid>` is refused too.
7. **The core by CID** (`resolve_requires`). Every `requires[]` entry of kind `capsule` must carry a `cid`
   (`core_unpinned`). The installed capsule must have that name **and** that CID (`core_mismatch`, which names
   both); none at all is `core_missing`. A name alone never selects the core. The surface's own closure
   holds its `capsule.json`, so its CID pins the core CID (tested).
8. **Provenance**, `elastos.capsule.provenance/v1`: `{cid, source_commit, recipe, image_digest,
   rebuilder_did}`, signed by the rebuilder. It verifies only for the CID it names
   (`provenance_cid_mismatch`). Two rebuilders can each add one. Admission takes none.

CLI: `cargo run -- cid <dir>` prints the CID; `cargo run -- listing <dir>` prints the listing.

## Tests run and results

`export RUST_TEST_THREADS=2`, in `examples/photo-viewer/bundle`:

| Suite | Result |
|---|---|
| `cargo test` | 30 passed (3 unit, 27 integration) |
| `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` | clean |

Tests asked for in answer 9, and where:

| Asked | Test |
|---|---|
| ASCII or NFC | `the_listing_takes_ascii_or_nfc_names_only` (file and directory names) |
| names unique under case folding | `names_must_be_unique_under_case_folding` |
| no symlinks or special files | `the_listing_refuses_symlinks_and_special_files` |
| verify, then load from a read-only copy staged by CID | `admission_stages_a_read_only_copy_by_cid_and_loads_only_from_it`, `load_refuses_a_staged_copy_that_is_writable`, `load_refuses_a_staged_copy_that_no_longer_hashes_to_its_cid`, `load_takes_only_a_cid`, `admit::tests::a_source_changed_after_verification_is_not_staged` |
| a lower version of the same name | `admission_refuses_a_lower_version_of_an_installed_name`, `one_version_of_a_name_has_one_cid` |
| revoked DID or revoked CID | `admission_refuses_a_revoked_publisher_or_a_revoked_cid` |

Others: `the_listing_is_canonical_and_names_every_shipped_file` (the exact bytes),
`the_listing_is_sorted_by_path_bytes_not_by_walk_order`, `any_change_to_the_closure_changes_the_cid`,
`the_listing_refuses_a_closure_with_no_manifest`, `the_listing_refuses_control_characters_and_backslashes`,
`a_claim_parses_strictly`, `admission_refuses_a_closure_that_is_not_the_claimed_cid`,
`admission_refuses_a_claim_its_publisher_did_not_sign`, `admission_refuses_a_claim_that_is_not_what_the_manifest_says`,
`the_release_policy_must_be_signed_by_the_pinned_root`, `local_config_adds_a_dev_key_only_in_dev_mode`,
`a_dev_key_cannot_stand_in_for_a_release_key`, `admission_refuses_an_untrusted_publisher_or_a_role_it_may_not_ship`,
`an_installed_version_that_is_not_semver_is_refused`, `a_surface_resolves_its_core_by_cid_only`,
`the_surface_cid_pins_its_core_cid`, `provenance_is_a_separate_record_that_names_the_cid`.

**On the Mac:** the default APFS volume is case-insensitive, so it cannot hold `Photo.png` and `photo.png`
together. The walk test then checks that one file is listed and says so; the pure check still covers every
pair. The tests restore write permission on the sealed store before the temp directory is removed, so a
non-root run cleans up.

## Falsifiers

`RUST_TEST_THREADS=2 python3 -I examples/photo-viewer/falsify-bundle.py`: **33 of 33 caught**. Each
mutant must compile, each named test must exist and fail, and the file is restored from saved bytes;
`git status` after the run was clean.

| Group | Falsifiers |
|---|---|
| Listing (7) | non-NFC names listed; case folding as plain lower-casing (misses `ς`/`σ` and `ß`/`ss`); the walk follows symlinks; special files skipped, not refused; control characters and backslashes allowed; no manifest needed; walk order kept |
| Claim (6) | CID not checked; signature not checked; no signing domain; claim need not match the manifest; unknown claim fields taken; another claim schema taken |
| Policy (5) | checked against the DID it names, not the pinned root (both checks removed together, since either alone still refuses); signature not checked; dev keys outside dev mode; a dev key may be a release key; local config takes more than dev keys |
| Trust (5) | revoked CIDs admit; revoked publishers admit; any publisher trusted; any role; any name |
| Inventory (2) | a lower version admits; one version may have two CIDs |
| Staging and load (5) | the copy not re-hashed; the copy left writable; load skips the read-only check; load skips the re-hash; load takes any path |
| Core and provenance (3) | a requirement with no CID skipped; the core found by name; provenance for another CID verifies |

Not falsified separately, and said plainly:

- **`verify_strict` over `verify`.** The tool refuses small-order keys and non-canonical signatures, where
  the Runtime's verify does not. No test makes such a signature.
- **The pinned-root check and the signature check overlap.** Removing one alone still refuses, so they are
  falsified together.

## The photo-viewer closure CID

For a directory with this branch's base `capsule.json` (from `claude/photo-p3-seam`) and the
`photo-viewer.component.wasm` in this container (sha256 `add93842…`, the P2 cloud-container build):

```
bafkreib5ajecj6s7yfqxiyzfqpxkv74ytvzpyue7366yzauxqfmq5kg4na
```

That CID holds only for those bytes. The Mac reproducible build (`e2a4c798…`) gives another component, and so
another CID. The release CID comes from the P2 recipe output, once the P2 Mac exit closes.

## Known limits (spike)

1. **No policy rollback check.** An older signed policy, one from before a revocation, still verifies.
   Phase 2 needs a sequence number in the policy, and Runtime refusing one lower than it has seen.
2. **The inventory is an input.** Runtime would hold the installed list and record install receipts (P4
   design 2.3 step 5). Not built.
3. **Read-only is mode bits.** Root ignores them, and so do the tests in this container. The re-hash at every
   `load` is the check that holds. A file changed between `load` and the launch reading it is not caught;
   Phase 2 should hash what it reads.

## Principles checked

- **3 (no ambient authority).** Trust comes only from the signed release table or a dev key in dev mode; a
  name, a path or a self-named signer grants nothing.
- **10 (one path).** Load from `store/<cid>` is the only way in; admission itself goes through it.
- **11 (fail closed, then explain).** 25 refusal codes, each naming what was expected and each with a
  test; 33 falsifiers over the checks behind them.
- **13 (objects vs capsules).** One CID per capsule closure; the surface pins its core by CID.
- **15 (content-addressed).** Identity is the closure listing CID; IPFS CIDs stay delivery details.
- **16 (UI is not authority).** Nothing here is set from a UI; local config cannot widen release trust.
- **18 (isolated instances).** Each CID stages to its own read-only directory.

## Roadmap milestone

Phase 2 prerequisite: correction 1 (per-publisher trust policy by role), proven offline. The Runtime port
(P4 design 2.5) needs Sasha's yes.

## Questions for Sasha

1. Policy rollback (limit 1): a monotonic `sequence` in the signed policy, refused below the highest seen?
2. Should a dev key be required to list `names`, so it can never ship a whole role?
3. Keep `verify_strict` (stricter than the Runtime) when this moves to Runtime, or match the Runtime?

## Next slice

None until the review. Then, with a yes, the Runtime port (P4 design 2.5), or the surface page first.
