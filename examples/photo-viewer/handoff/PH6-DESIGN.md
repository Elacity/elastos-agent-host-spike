# PH6 design: open a photo content capsule by CID in a stand-in

This is a design, not an implementation or installed-product result. The PH6
stand-in will take a content closure CID, check its signed package and pinned
viewer, bind its images to one test run, and run the photo core through the kit.
The Photos page and the Runtime seam stay outside this work.

**Required label:** “This test code stands in for the Runtime's launch by CID,
which does not exist yet.” Use that sentence in each new stand-in source file,
each stand-in test's doc comment, and the stand-in falsifier file. Add it beside
the stand-in extension in an existing file. Reports call the result a **PH6
stand-in result**. Running the existing ComponentProvider proves component
execution; it does not prove Runtime launch by CID.

Paths and line numbers below refer to the source read for this design. Future
functions and tests are explicitly described as planned. For compact citations,
`photo/` means `examples/photo-viewer/`, and `kit/` means `examples/capsule-kit/`.

## Owners and scope

| Decision | One owner | Existing evidence |
|---|---|---|
| Which bytes a CID names | Bundle listing and `load` | `photo/bundle/src/listing.rs:39`, `:467`; `photo/bundle/src/admit.rs:162` |
| Whether the package is admitted | Bundle `admit`, with the current policy, detached claim and inventory | `photo/bundle/src/admit.rs:42`, `:77`, `:125` |
| Which viewer and core are required | Bundle `resolve_requires`, extended below | `photo/bundle/src/admit.rs:185` |
| Which objects this test launch may use | The named PH6 stand-in binding, enforced at the kit Bus hostcall | `kit/v1-host-test/src/lib.rs:90`, `:196` are the extension points |
| How images are checked | The photo core and kit guest calls | `photo/src/lib.rs:123`, `:154`; `kit/guest/src/read.rs:89` |
| How the component runs and is limited | Kit `run`, using ComponentProvider | `kit/v1-host-test/src/lib.rs:196`; fuel measurement at `:335` |

Identity, admission and allowance remain separate decisions. A matching CID
proves bytes. `admit` checks publisher, role, policy and version. A launch binding
allows specific effects; the component runner supplies resource limits. Success
at one step supplies none of the later decisions. A passive content capsule
receives neither an execution instance nor a grant.

This follows `docs/CAPSULE_MODEL.md:53`, `:79` and
`docs/CONTENT_CAPSULE_DISTRIBUTION.md:47`, `:65`. The security boundary for future
product integration remains the one in `SECURITY.md:129`: Runtime owns checks of
caller, action, resource, session and revocation. The lab adds test code only.

## 1. Three closures and a passive photo set

Use three distinct closure CIDs:

- `K`: the `photo-viewer` core, role `app`, execution `component`
  (`photo/capsule.json:3`, `:7`, `:12`).
- `V`: the `image-viewer` surface, role `viewer`, execution `web-projection`
  (`photo/surface/capsule.json:3`, `:7`, `:11`). Its packed manifest requires `K`.
- `C`: the photo set, role `content`, type `data`. Its manifest pins `V`.

The source fixture folder is planned at
`examples/photo-viewer/host-test/fixtures/stand-in-photo-set/`. Its shipped files
are `capsule.json`, `images/01.png`, `images/02.jpg`, and `images/03.webp`.
Use small, generated test images with their provenance beside the fixture.
Provenance and the required stand-in label belong in a source `README.md`, which
the packer leaves outside the closure. Tests can generate negative sets in their
owned temporary directory. Claims and policy records stay outside each closure;
temporary fixture signing material stays in memory and out of reports.

The planned source `capsule.json` has this lab format. `<V>` below means the
actual closure CID returned after packing the surface, not a literal placeholder
in a usable fixture:

```json
{
  "schema": "elastos.capsule/v1",
  "name": "stand-in-photo-set",
  "version": "0.1.0",
  "description": "This test code stands in for the Runtime's launch by CID, which does not exist yet.",
  "role": "content",
  "type": "data",
  "entrypoint": "images/01.png",
  "viewer": { "name": "image-viewer", "cid": "<V>" }
}
```

**`viewer.cid` is the sole content-to-viewer identity field.** `viewer.name` is
an assertion about the selected package's metadata. It cannot select a package
without the CID. The content profile has no `requires`, execution, permissions
or capability declarations. The surface retains the existing
`requires: [{name: "photo-viewer", kind: "capsule", cid: K}]`. Thus `C` pins `V`,
and `V` pins `K`, without a cycle or a self-CID inside the content.

Today's viewer binding is a name string in
`templates/capsules/viewer-content/content.capsule.json:10`; the viewer template
also matches that name at `templates/capsules/viewer-content/viewer.capsule.json:35`.
The binding is documented in `docs/CAPSULE_INTERFACE_CONTRACT.md:21`. The object
form above is a **lab format extension**, not a claim that the Runtime accepts
it. The templates stay unchanged. A content capsule remains passive, as required
by `docs/CONTENT_CAPSULE_DISTRIBUTION.md:48`.

### Pack through the existing tool

Pack in dependency order, using physical paths under the test's temporary root:

```text
capsule-bundle pack <core-source> <packed-core>                         -> K
capsule-bundle pack <surface-source> <packed-surface> \
  --require photo-viewer=<K>                                         -> V
# Write V into the temporary content source's viewer.cid before packing.
capsule-bundle pack <content-source> <packed-content>                  -> C
```

The CLI already delegates to `pack` (`photo/bundle/src/main.rs:16`). Extend that
one packer for `role=content`, `type=data`: pack the entrypoint's containing
folder and `capsule.json`. The entrypoint must be a regular file below a
non-root folder. Reuse the page packer's directory-handle walk and planned-file
checks, rather than add a content copier (`photo/bundle/src/pack.rs:209`, `:265`,
`:279`). The existing component branch currently copies only its entrypoint
(`:253`); without this extension the siblings would be absent.

For this photo profile the payload folder is exactly `images/`. Every regular
file below it is an album candidate, in canonical listing order. File extensions
do not decide image type. The entrypoint is a member of this set, not a separate
execution target or a preference that changes the order. The packed fixture
ships exactly the four files above. A source README, tests and source code stay
outside it. Changed manifest or image bytes change `C`; a source README change
does not. Existing symlink, special-file, path, case-fold, exclusive-destination
and race checks continue to apply.

No album containing its own CID is shipped. The stand-in builds the album from
the loaded listing after `C` exists. The listing and manifest remain the package
truth; the album is a per-run projection of them.

### Extend one resolver

Extend `resolve_requires` in `photo/bundle/src/admit.rs`, retaining its public
role as the one resolver. For a content manifest, validate the strict `viewer`
object (`name` and `cid` only), then normalize it internally to one capsule
requirement. Send that requirement through the existing name-and-CID matching
loop (`:199-225`). For other manifests, keep the existing `requires[]` path.
Do not add a viewer lookup in the stand-in, a name fallback, or a second copy of
the matching loop. Reject a content manifest with `requires` or conflicting
binding fields. A legacy string or missing CID receives `core_unpinned`.

For the PH6 test launch, the caller's fixture context contains the explicitly
approved `V` and `K`, obtained from their successful admissions. Resolution must
return exactly one viewer and then exactly one core. Check the resolved CIDs
against those two selections and check the loaded roles/execution types. A
different, otherwise valid installed viewer is `viewer_mismatch`; an unavailable
dependency keeps the resolver's `core_missing` or `core_mismatch`. This checks
an explicit selection; it is neither a built-in name whitelist nor an automatic
choice of the newest installed version.

Keep both existing docs-viewer tests intact:
`the_surface_names_its_core_by_cid_and_nothing_else_selects_it`
(`examples/docs-viewer/bundle-test/tests/bundle.rs:237`) and
`the_runtime_manifest_type_takes_the_core_but_not_a_core_named_by_cid` (`:361`).
The latter must still assert that `CapsuleManifest` rejects `requires[].cid`.
The stand-in parses content and surface manifests as bundle values. Only the
unchanged core manifest is converted to `CapsuleManifest` for `run`; stripping
CID fields to make the other two manifests parse is outside the design.

## 2. Stand-in launch and content reads

Planned orchestration lives in
`examples/photo-viewer/host-test/tests/support/ph6_stand_in.rs`, used by
`examples/photo-viewer/host-test/tests/ph6_stand_in.rs`. Its entry point is
`open_content_stand_in`. It takes `C`, the isolated store, the fixture's claims,
current verified policy and inventory, and the explicit `V`/`K` selection.
These are host test inputs, never inputs from a page.

1. Call bundle `load(store, C)` before making grants or starting the core.
   Preserve its CID-form, read-only and closure-hash checks
   (`photo/bundle/src/admit.rs:160-180`). Extend `load` to give a typed
   `staged_missing` for an absent root instead of matching text in an `io` error.
   Other I/O errors retain their cause. A planted directory without an admission
   claim is `claim_missing`, even if its bytes hash correctly.
2. Re-admit the loaded content with its detached claim and the current policy:
   `admit(loaded.path, claim, policy, inventory, store, now)`. Its existing stage
   operation reuses the staged copy and calls `load` again (`:147`, `:263`). This
   reuses signature, claim, expiry, sequence-floor, revocation, role and downgrade
   checks. Put the claim lookup and this call in one
   `admit_staged_for_stand_in` helper, reused by the per-effect callback below.
   `load` alone is an integrity check, not permission to use content.
3. Validate the passive photo profile, then call the extended `resolve_requires`
   on that loaded manifest. Load and re-admit the returned viewer, check it is
   the selected `V` with role `viewer` and execution `web-projection`. Resolve
   its core through the same function, then load and re-admit `K`, which must be
   the selected component app. Refuse before making a binding on any failure.
4. Obtain the content bytes from the same verified load pass. The small bundle
   extension is to retain the bytes already read by `read_closure` in `Loaded`,
   beside `entries` and `manifest`. Refactor the internal reader once so listing
   and loading share its walk and hash calculation (`photo/bundle/src/listing.rs:50-75`);
   `load` returns retained bytes only after its usual checks. The stand-in uses
   this snapshot, not `fs::read` of a path after checking it. Replacing source
   files or later changing the staged content cannot change bytes in a prepared
   binding. This is a lab snapshot, not a production streaming-store design.
5. Make one `StandInLaunchBinding` for `(C, V, K, test principal, run instance)`.
   For each listing entry below `images/`, form exactly
   `localhost://Users/self/Pictures/Capsules/<C>/<entry.path>` and pair it with
   that entry's retained bytes. For example, `.../<C>/images/01.png`. Check the
   URI with the kit's existing `check_object_uri`; use exact strings as map
   keys, with no URL decoding, path normalization or host-path fallback. `C`
   plus the closure-relative path identifies the member; its listing SHA-256
   supplies the member integrity fact, not a second package identity.
6. Use `Bridge::with_list(ALBUM_URI, ALBUM_SCHEMA, PLAYLIST_URI, objects)` to
   generate the normal album and exact read/write grant set
   (`kit/v1-host-test/src/lib.rs:45`). The one bridge belongs to this run. Its
   read set is the album plus those member URIs; its write set is only the
   playlist. Fixed AppData URIs are private aliases in that bridge, not files
   placed in a person's Home. The kit supplies the JSON shape; the core owns
   validation, count and size limits. A filename that cannot form a valid URI
   causes `content_binding_invalid`; it is never silently omitted.
7. Validate the selected core's imports with the existing kit `admission`
   function, validate its unmodified `CapsuleManifest`, and pass its **loaded
   staged path** to kit `run`. The harness already starts ComponentProvider
   (`kit/v1-host-test/src/lib.rs:194-218`). Keep this single runner. A small
   optional stand-in guard, described below, runs at its existing Bus callback.
   Register the actual loaded instance ID before `provider.start`; do not let
   the guest supply it.
8. The component requests grants, reads headers, and writes its playlist. The
   stand-in returns the run result and redacted evidence: `C`, `V`, `K`, checked
   playlist, requested operations and byte counts. An `Ok` alone is insufficient:
   a successful test requires the expected playlist and actual Bus reads. On
   success or failure, close the binding and discard its grants and output.
   Unseal and remove only the owned fixture store via `testing::unseal`
   (`photo/bundle/src/testing.rs:9`). No app page or HTTP service starts here.

### The per-run guard and revocation

Put the kit extension in `examples/capsule-kit/v1-host-test/src/stand_in.rs`,
with a labelled hook in `src/lib.rs`. Keep `Bridge` as the one implementation of
capability issuance, token/resource/action checking, provider body checking and
window reads (`kit/v1-host-test/src/lib.rs:103-165`). The optional guard adds
launch-context checks to this path; it does not implement another bridge.

The guard receives the callback's actual instance/principal and checks that the
binding is active and the requested resource/action belongs to it. Kit `run`
currently discards these callback arguments (`:204`); the stand-in extension
uses them. Give stand-in grant handles a per-binding namespace so a handle from
another run fails even when both runs request the same fixed AppData URI. Keep
test handles out of evidence. A grant request and every subsequent invocation
both pass through the guard, including the final playlist write.

Before each effect the guard calls a supplied PH6 re-admission callback, which
uses **bundle `admit`** for the three staged packages with the fixture's current
policy. The callback is supplied by `ph6_stand_in.rs`; the kit has no dependency
on the bundle or its policy types. This deliberately simple test mechanism
reuses policy rules, even though re-hashing at each call is expensive. A newer
revoking policy stops both new grants and previously issued handles. Retaining
an older policy gets `policy_stale` from the same owner. The binding lock covers
the current-policy check and the in-memory effect; test revocation waits for
that operation and takes effect on the next one. This makes the test's ordering
explicit. It is not a product revocation protocol or durable authority store.

A named test hook changes the policy after an image grant and before its first
read. Another closes the binding at that point. Neither test accepts a playlist
write after the refusal. Removing a URI from `Bridge.allowed` alone is
insufficient: existing `invoke` checks an issued handle, so the guard must run
there too (`kit/v1-host-test/src/lib.rs:130`).

### The core stays unchanged

The grant remains one `read` action for the exact image URI. Every read remains
`providers.invoke` with that grant and an explicit offset/length window. These
are rooted object bindings behind the Bus seam, not direct capsule-file reads
by the guest. The proposed change needs **zero photo core changes**, zero WIT
changes and zero storage-bound widening: the URIs fit `PICTURES_PREFIX`
(`photo/src/lib.rs:35-51`, `photo/capsule.json:15`).

Keep the album rules, wherever task 012 places their implementation: the exact
schema, strict fields, a nonempty list of at most 64 items, a 16 KiB input cap,
valid object URIs and duration limits. Current owners are the kit list and URI
rules (`kit/guest/src/list.rs:32`, `kit/guest/src/uri.rs:7`) plus the photo
duration rule (`photo/src/album.rs:50`). The design does not import a private
album parser or copy it into the stand-in.

The core still checks type from magic bytes, probes one byte at 64 MiB, reads
bounded image headers, and checks side/pixel limits (`photo/src/lib.rs:160-185`).
It skips bad content and records a reason. A grant, provider or input failure
stops the run before any playlist write (`:123-149`;
`kit/guest/src/read.rs:67`). The stand-in neither pre-filters bad images nor
turns denied reads into empty bytes or skipped items. Existing header, stop,
skip and fuel tests remain gates (`photo/host-test/tests/component.rs:191`,
`:207`, `:258`, `:270`, `:343`, `:359`).

## 3. Refusals, tests and planted bugs

The following are **planned** tests and falsifiers. Each test asserts its code,
the reason text (with fixture values), and that denied work has no effect.
Launch refusals mean zero component starts and zero playlist writes. Bus
refusals mean zero bytes for the denied read and zero later playlist writes.
Existing bundle codes retain their owner; the stand-in can add the stated
context sentence without changing the underlying code. Each falsifier names
only tests that must actually fail under that mutation.

| Case and owner | Code and reason text | Named test | Falsifier |
|---|---|---|---|
| Unknown or unstaged content CID; `load` | `staged_missing`: “Content CID {C} is absent from the staged store; admit that exact capsule first.” | `stand_in_refuses_unknown_or_unstaged_content_cid` (absent CID and admitted-then-removed copy) | F1: replace `open_content_stand_in` with an immediate `Ok` and empty evidence, without loading or checking any CID; this test must FAIL on the returned result itself |
| Staged content has changed; `load` | `staged_mismatch`: “Staged content {C} hashes to {computed}; admit a verified copy.” | `stand_in_refuses_changed_staged_content` (change bytes, then restore read-only mode) | F2: suppress the computed-CID comparison in `load` |
| Staged content is writable; `load` | `staged_not_read_only`: “Staged content {C} has writable entry {path}; restore a sealed admitted copy.” | `stand_in_refuses_writable_staged_content` (file and directory cases) | F3: skip `load`'s read-only check |
| Content pins another installed viewer; stand-in selection check after resolution | `viewer_mismatch`: “Content {C} requires viewer {actual}; this launch selected {expected}.” | `stand_in_refuses_another_viewer_cid` (both viewers are valid and staged) | F4: omit the resolved-viewer versus selected-viewer CID comparison |
| Viewer named only by name; extended resolver | `core_unpinned`: “Content {C} must pin its viewer with viewer.cid; a name alone cannot select it.” | `stand_in_refuses_a_viewer_named_only_by_name` (legacy string and object missing cid) | F5: resolve those cases by the installed viewer name |
| Read outside the bound content; stand-in guard | `denied`: “Read {uri} is outside content {C} bound to this stand-in launch.” | `stand_in_denies_a_read_outside_bound_content` | F6: bypass the guard's exact member check; plant the outside object and an ordinary Bridge grant so downstream absence cannot mask the bug |
| Content revoked before open or after grant; `admit` through the guard | `cid_revoked`: “Content CID {C} is revoked by the current policy; this launch is stopped.” | `stand_in_refuses_revoked_content_at_open`; `stand_in_stops_when_content_is_revoked_after_grant` | F7: disable the existing revoked-CID refusal in `admit`; BOTH named tests must FAIL |
| Old held policy after a newer one; `admit` | `policy_stale`: “The held policy is older than the accepted policy; use the current policy.” | `stand_in_refuses_a_policy_held_before_revocation` | F8: skip the existing policy-floor check in `admit` |
| Exact-CID directory with no retained claim; stand-in lookup | `claim_missing`: “Content {C} has no admission claim; admit the signed capsule first.” | `stand_in_refuses_a_staged_capsule_without_a_claim` | F9: let the shared `admit_staged_for_stand_in` return success when the claim lookup is absent, at launch and on subsequent calls |
| Malformed passive profile or viewer object; bundle profile/resolver validation | `content_binding_invalid`: “Content {C} needs the passive photo profile and one viewer CID: {detail}.” | `stand_in_refuses_invalid_content_bindings` | F10: bypass profile validation; table cases cover executable content, extra viewer fields, content requires, wrong entrypoint folder and URI-invalid filenames |
| Missing dependency or same name with another CID; existing resolver | `core_missing`: “Required {name} at {cid} is absent; admit that exact dependency.” / `core_mismatch`: “Required {name} at {required} differs from installed {installed}.” | `stand_in_refuses_unresolved_dependencies` | F11: return the selected fixture dependency when resolution fails; test both the content-to-viewer and viewer-to-core edges |
| Wrong role, execution or selected core; stand-in dependency validation | `launch_binding_invalid`: “Resolved {cid} does not match the selected {role} for this stand-in launch.” | `stand_in_checks_resolved_roles_and_core_selection` | F12: omit the post-resolution role/execution/core-selection checks |
| Closed binding or wrong caller; guard | `denied`: “This stand-in launch is closed or belongs to another instance/principal.” | `stand_in_denies_closed_or_foreign_launches` | F13: skip the active/instance/principal guard; use otherwise valid grants |
| Handle from a different run; Bridge | `capability_denied`: “The grant belongs to another stand-in launch.” | `stand_in_grants_are_specific_to_one_run` | F14: issue the old local-counter-only handles in both bridges, then replay a handle on the same AppData URI |

F2's test must reach `staged_mismatch` before re-admission, so a later
`cid_mismatch` still fails the exact-code assertion when `load` is broken. F6
exercises an outside member of `C`, a member of another `C2`, a plain Pictures
object and a traversal spelling through the same guard. The traversal is a
raw Bus request, since the core's parser correctly rejects it earlier.

Keep the remaining existing refusals, including CID form (`path_invalid`),
closure paths, signature/claim, expired policy, publisher, version, import,
manifest, malformed input and provider errors. Pass through the owner's code
and diagnostic; each remains covered by its owner's current tests and
falsifiers. For import/manifest/run failures that are strings in today's kit,
the stand-in outcome records the stage and original reason instead of returning
success. It supplies no substitute package or transport.

## 4. Three ordered code slices

Each slice is one concern for one builder, with at most three review rounds.
These are specifications for later queue tasks, not claims of completed work.
All new files, test names, fixture labels and result headings use `stand_in` or
`stand-in` and the required sentence above. Reused general bundle functions
keep their existing names; their added PH6 sections carry the label.

### Slice 1: pack passive content and resolve its pinned viewer

Paths: `photo/bundle/src/{pack,admit,lib}.rs`,
`photo/bundle/tests/ph6_stand_in.rs`, `photo/falsify-bundle.py`, and the source
fixture/README under `photo/host-test/fixtures/stand-in-photo-set/`.
Extend `pack` and `resolve_requires` as specified. Keep all schema and profile
validation in the bundle owner and export that validation for the later
stand-in to call. Add no crate version or registry dependency change.

| New rule | Named test | Planted bug |
|---|---|---|
| Manifest plus the whole payload folder is the closure | `stand_in_pack_ships_the_complete_photo_set` | F15: use the old entrypoint-only branch for content; test asserts all four paths |
| Source-only files stay outside package identity | `stand_in_content_cid_covers_payload_and_viewer_only` | F16: include the source README; the test changes it and requires an unchanged CID, then changes payload/viewer and requires changed CIDs |
| Both dependency edges use the existing resolver | `stand_in_content_and_surface_resolve_by_exact_cid` | F17: change its matching loop to match by name alone; test uses two CIDs with the same name |
| Existing pack safety also covers passive content | `stand_in_content_pack_preserves_path_safety` | F18: replace content planning AND copying with a path-following walk/copy, so the mutant actually follows file/folder links; each fixture must refuse before output exists |

Implement the bundle-level cases needed for F5, F10 and F11 here; slice 2 calls
them through the launch and adds the named end-to-end tests in section 3.
Keep the docs-viewer compatibility tests unchanged. Run bundle tests and
falsifiers plus those existing docs-viewer bundle tests. This slice produces
sealed packages and dependency decisions; it does not claim a PH6 launch.

### Slice 2: load, admit, bind and run through the kit

Paths: `photo/bundle/src/{admit,listing,lib}.rs`, the bundle PH6 tests,
`photo/host-test/tests/{ph6_stand_in.rs,support/ph6_stand_in.rs}`,
`photo/host-test/Cargo.toml` and its lock file, `photo/falsify-ph6-stand-in.py`,
and `photo/verify.sh`. The manifest change may add local test dependencies on
the existing bundle and photo crates and fixture-signing crates at versions
already used by the bundle tests; it must preserve existing version pins.

Add `staged_missing`, retain verified content bytes in `Loaded`, and implement
`open_content_stand_in` through kit `run`. Exercise F1-F5, F9-F12 through the
real entry point. Reuse `testing::unseal` for owned fixture cleanup. Add these
positive and integration checks:

| New rule | Named test | Planted bug |
|---|---|---|
| Success requires the selected component's real work | `stand_in_opens_content_cid_and_writes_checked_playlist` | F19: return `Ok` without calling kit `run`; test requires exact C/V/K, sorted member URIs, image facts and Bus read trace |
| The binding uses the bytes `load` verified | `stand_in_binds_verified_content_bytes` | F20: reopen the content path after load; replace a staged image between load and binding and inspect the prepared snapshot, which must retain the original checked bytes |
| The kit runs the staged core | `stand_in_runs_the_staged_core` | F21: pass the source core folder to `run`; remove the source after admission and require successful staged execution |
| Content failures still skip; authority still stops | `stand_in_preserves_content_skip_and_authority_stop` | F22: grant a deliberately denied image in stand-in setup; assert the authority case stops before output, while a separate malformed-image case is listed as skipped |

The generated album uses the existing parser. Add over-count and over-size
content projections to the existing core regression inputs; retain their
existing parser/read falsifiers, with no copied schema checks. The successful
fixture checks default duration and the explicit read windows as well as output.
F20 stops at inspection of the prepared binding: once the per-effect guard is
added, it correctly refuses to execute from the changed store. The test must
not expect a run to succeed after that change.

Wire the new tests and falsifiers into `photo/verify.sh`. Until slice 3 passes,
this is a stand-in launch with grant-scope/revocation work still pending.

### Slice 3: enforce binding lifetime and current policy on every Bus effect

Paths: `kit/v1-host-test/src/{lib,stand_in}.rs`, the PH6 host tests/support,
`photo/falsify-ph6-stand-in.py`, and the existing verification entry points
under `examples/photo-viewer/`. Add the optional guard to the existing kit
runner and Bridge path, with per-binding handles and the re-admission callback.
Implement F6-F8 and F13-F14. Test a revoked content CID both before launch and
between grant and invoke, including the final output-write boundary.

Add `stand_in_rechecks_authority_on_each_invoke`, with F23 removing the invoke
guard while leaving the grant guard in place. It issues a valid grant, closes
the binding, then attempts a read and a write; each must deny. This detects the
specific bug of checking revocation only when granting. Keep F7 focused on the
bundle's revoked-CID rule so all its named tests fail for the same planted bug.

Run the kit users' existing host tests and all PH6 tests/falsifiers. Verify that
the optional test guard leaves ordinary `Bridge` users working. The final
stand-in result requires the full success journey, every refusal and cleanup,
with author checks and independent review stated separately.

For every slice, use `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0` and the lane gate.
Each mutant must compile, each named test must execute and **every named test
must fail**; a survivor, missing test or build failure is a failed falsifier
run. Use the kit runner and its restoration/self-tests, not a new mutation
engine (`kit/PATTERNS.md:252-265`, `kit/README.md:16`). Restore saved source bytes
after every mutation. F1 is mandatory even though F19 also plants an empty
success: F1 proves denial, while F19 proves that success includes execution.

## 5. Principles grade and Runtime gaps

The grades assess this proposed lab design. “Met” means the design preserves
that constraint within its stated scope; it is not a test result. A missing
Runtime part is marked **not met** and linked to a gap below. Code tasks and
their falsifiers remain pending.

| Principle | Grade | Reason and source |
|---|---|---|
| P1 Local first | met | Rooted Pictures/AppData views stay local to the stand-in run (`PRINCIPLES.md:7`; section 2). |
| P2 Stable identity over transport | met | C/V/K are closure CIDs; member URIs bind C and a closure path, with no URL selection (`PRINCIPLES.md:15`; section 1). |
| P3 No ambient authority | not met | Exact per-app, revocable test grants are planned, but Runtime principal/session authority and durable revocation are G3 (`PRINCIPLES.md:24`). |
| P4 Carrier is not the capsule contract | met | The guest keeps typed Bus calls; local in-process test delivery stays below that contract (`PRINCIPLES.md:32`; section 2). |
| P5 Small trusted core | met | Changes stay in bundle tooling, the kit harness and tests; Runtime core growth is zero (`PRINCIPLES.md:54`; section 4). |
| P6 User/operator/developer boundaries | met | The entry point, fixtures and reports say stand-in; the product UI gains no developer flow (`PRINCIPLES.md:63`; required label). |
| P7 Shared human/agent authority model | not applicable | PH6 adds no human or agent interface; their product enforcement remains a Runtime responsibility (`PRINCIPLES.md:71`). |
| P8 WebSpaces resolve dynamically | not applicable | This local fixture exposes no WebSpace resolver (`PRINCIPLES.md:81`). |
| P9 HTTP is edge transport | not applicable | The stand-in launches no HTTP server or route (`PRINCIPLES.md:93`). |
| P10 One canonical path | met | One packer, one resolver, one admission owner, one load reader and one kit runner; guard composes with that path (`PRINCIPLES.md:102`; owners table). |
| P11 Fail closed, then explain | met | Section 3 denies with codes and reasons; success needs real reads and output (`PRINCIPLES.md:111`). |
| P12 Docs/code/tests/operations agree | not met | This is a future design; code, falsifier runs and stand-in acceptance are pending G7 (`PRINCIPLES.md:119`). |
| P13 Objects/capsules/spaces distinct | met | Passive C, executable K, render-only V and per-run rooted views have separate jobs (`PRINCIPLES.md:129`; section 1). |
| P14 Names match human models | not applicable | Product copy and visible app names are unchanged (`PRINCIPLES.md:148`). |
| P15 Trust/access travel with signed content | not met | Bundle claims and policy are reused in the lab; Runtime admission and protected-content entitlement are G2/G6 (`PRINCIPLES.md:157`). |
| P16 UI is not authority | not met | The lab gives UI no role; real opened-object and output binding still require G1/G4 (`PRINCIPLES.md:186`). |
| P17 Design tokens are contracts | not applicable | This work changes no visual surface (`PRINCIPLES.md:196`). |
| P18 Isolated execution environments | not met | Component execution is bounded, but full identity/session binding, store lifetime and target isolation proof are G3/G5 (`PRINCIPLES.md:207`). |
| P19 Consequences govern effects | not applicable | No new consequential operation contract is introduced; the lab uses existing read/write test effects (`PRINCIPLES.md:221`). |

Gaps, with their future owner:

1. **G1 — Manifest and selection, Runtime/Anders after 0.8.0.** Runtime must
   accept and validate `requires[].cid` and a pinned viewer CID in its manifest
   contract. The lab's `viewer.cid` object is a design input for that decision,
   not an adopted Runtime field. Keep the existing rejecting manifest test.
2. **G2 — Launch by CID and admission, Runtime/Anders after 0.8.0.** The
   stand-in composes the bundle tool's local functions. Runtime still owns a
   real launch-by-CID entry point, verified inventory/claims, current trust
   policy and installed acceptance. Fixture selections and policy inputs are
   substitutes for those owners, not equivalent evidence.
3. **G3 — Authority and lifetime, Runtime.** The kit has fake grant handles and
   a fixed test principal. Its new guard models per-app scope and revocation;
   Runtime must verify the actual principal/session independently, issue real
   per-instance capabilities, audit them and end them with the launch. Fixture
   locking and re-admission callbacks prove only the specified test ordering.
4. **G4 — Opened object and output, Runtime; Home only requests/displays.**
   Runtime must bind the opened C to the launch, its core input and its output,
   and constrain seam reads to the input/output intersection. The stand-in's
   private AppData aliases stand in for that binding. The page/seam journey is
   outside this task. This preserves the direction in `photo/handoff/P3-DESIGN.md:152`
   and kit missing items 1, 2, 4 and 6 (`kit/KIT-REPORT.md:134-171`).
5. **G5 — Store and allowance, Runtime with providers.** Retained content bytes
   bind the lab's reads, but production bounded loading/streaming, concurrent
   mutation protection through component instantiation, protected policy state,
   and target isolation still need their own acceptance. The kit runner opens
   K by staged path after `load`; PH6 does not prove that interval against a
   hostile host. Repeated re-admission and retained bytes are test mechanisms,
   not a hundreds-of-capsules resource design. See the prior load caveat in
   `photo/handoff/P4b-REPORT.md:194-207` and kit limits at
   `kit/v1-host-test/src/lib.rs:335`, `:450`.
   The kit import-admission check is still a copy of private Runtime code
   (`kit/v1-host-test/src/lib.rs:239`); exporting the Runtime owner is outside
   this lane. Its local result alone is not Runtime admission evidence.
6. **G6 — Entitlement, capsule/provider work outside PH6.** These free test
   photos need no paid-content token. Publisher admission is not the capsule's
   entitlement check. Rong's signed-token double check, dKMS and measured
   hardware remain separate work (`kit/PATTERNS.md:59-85`).
7. **G7 — Evidence, later lab slices.** This design supplies test names, not
   passing counts. PH5 cross-machine execution, a production page journey and
   independent review are separate evidence. The current design adds only
   Markdown and one LOG line; its acceptance is the docs-only lane gate.

No Runtime code change is proposed in these slices. Archive, tar, GBA, payments,
hardware, container builds and public-repository work remain outside PH6.

## 6. Mission check

Answers preserve the polarity of the mission questions: “no” is the desired
answer where the question asks whether a boundary is crossed. Evidence here is
design/source evidence, not an assertion that the future tests have passed.

| Question | Answer | Evidence |
|---|---|---|
| 1. New name/URL where a code/content hash belongs? | no | `viewer.cid` and `requires[].cid` select closures; names only constrain metadata (`photo/bundle/src/admit.rs:204-225`; section 1). |
| 2. Added ambient access or Home/UI authority? | no | The guest retains only Bus imports and exact read grants; the stand-in owns bindings (`photo/host-test/tests/component.rs:102`; section 2). Runtime authority remains G3/G4. |
| 3. A second path or copied rule? | no | Extend existing pack/load/resolver and kit run/Bridge; the core keeps the shared parser (`kit/README.md:13-18`; owners table). |
| 4. Does the trusted Runtime core grow? | no | All proposed edits stay in the lane's examples; Runtime ownership is deferred (`kit/CRATE-REPORT.md:229`; section 4). |
| 5. Every new refusal fails closed with a reason? | yes, by design | Section 3 maps each planned refusal to an exact code, text, test and mutation; bundle codes already have one owner (`photo/bundle/src/lib.rs:151`). |
| 6. Capsule logic stays inside and traps down by grant? | yes | Image decisions remain in the guest, using kit calls (`photo/src/lib.rs:123`, `:160`; `kit/guest/src/read.rs:89`). Entitlement is G6. |
| 7. Tests and falsifiers already prove every new rule? | no | Sections 3–4 specify the pending proof; G7 stays open. All named tests must fail under their mutant (`kit/PATTERNS.md:258-265`). |
| 8. Identity, admission and allowance separate? | yes, by design | `load`, `admit`, the binding and ComponentProvider limits have distinct decisions (`photo/bundle/src/admit.rs:42`, `:162`; `kit/v1-host-test/src/lib.rs:196`). G3/G5 qualify the product claim. |
