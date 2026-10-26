# capsule-identity lab: one lab CID over a whole bundle

Lab tooling for the cc-capsule-identity lane (ci-1: tasks 001 and 005; ci-2:
task 003; ci-8: task 009; ci-3: task 004). It names a capsule bundle by one
deterministic **lab CID** over all of its bytes: the manifest and every
payload file (PRINCIPLES 13 and 15). It checks a claimed name against the
bytes and never trusts it. It also returns the name together with the bytes
it covers, so a caller never needs to read a bundle twice. A test key can
sign that printed lab CID, and a check can say whether that key did.

## What it is, and what it is not

- It answers two questions: do these bytes match this name, and did this test
  key sign that name?
- It never answers "may this run?". It makes no trust, admission or launch
  decision. It sits in no admission or launch path, and no Runtime code calls
  it. Admission stays a separate decision under each Runtime's trust policy.
  A signature check that returns `Ok(())` is not a permission to run.
- Its value is a **lab CID**, printed `lab-cid:sha256:<64 lowercase hex>`. It
  is not the Runtime's CID and is never used as a package identity (see
  [Why a lab CID](#why-a-lab-cid-and-not-the-runtimes-cid)).
- The one schema check is the Runtime's own. `capsule.json` at the bundle root
  is parsed as `elastos_common::CapsuleManifest`, which refuses an unknown
  field, and then checked with its `validate()`. Each refusal keeps the
  Runtime's own text. The lab adds no field, no schema and no parser.

## The encoding

To recompute a lab CID by hand:

1. Start the stream with the framing tag: the 30 bytes
   `lab.capsule-identity.bundle/v1` and one newline byte, 31 bytes in all.
2. Take every regular file under the bundle root. Its bundle path is its path
   below the root, parts joined with `/`, in UTF-8. Folders add nothing
   themselves.
3. Sort the files by their bundle path's UTF-8 bytes.
4. For each file in that order, append: the path's length in bytes as 8 bytes
   big-endian, the path bytes, the content's length as 8 bytes big-endian, and
   the content bytes.
5. Take SHA-256 of the whole stream. Print `lab-cid:sha256:` and the digest as
   64 lowercase hex characters.

Nothing else enters the stream: no folder name, no absolute path, no file
time, mode or owner. The two length prefixes keep every boundary clear, so two
different bundles never make the same stream.

The same rule in a few lines of Python, which gives every pin below from the
committed fixture files:

```python
import hashlib

def lab_cid(files):  # {bundle path: bytes}
    h = hashlib.sha256(b"lab.capsule-identity.bundle/v1\n")
    for path in sorted(files, key=lambda p: p.encode("utf-8")):
        p, data = path.encode("utf-8"), files[path]
        h.update(len(p).to_bytes(8, "big") + p)
        h.update(len(data).to_bytes(8, "big") + data)
    return "lab-cid:sha256:" + h.hexdigest()
```

In Rust, the walk (`checked_bundle`, which `lab_cid` runs too) reads a bundle
and `encode_entries` is the encoder. They are the only code that names a
bundle; tests call them and copy neither. `check_name` checks a claimed name by
calling `lab_cid`; it computes no name of its own.

## Fixtures and their pinned lab CIDs

Each fixture is a bundle in the existing `elastos.capsule/v1` schema. Tests
assemble a bundle from exactly its listed files in a fresh temp dir, so a stray
local file (such as `.DS_Store`) never reaches a pin. The pins are in
`tests/common/mod.rs`.

| Fixture | Files | Where the bytes come from | Pinned lab CID |
| --- | --- | --- | --- |
| `content-sample` | `capsule.json`, `sample.example` | `templates/capsules/viewer-content/content.capsule.json` and `sample.example`, byte for byte | `lab-cid:sha256:99cf6c7b9b4489f3a565cca47e1e30f2b4e7752bf0e8824806e7036f7a681d51` |
| `web-app` | `capsule.json`, `browser/app.js`, `browser/index.html` | `templates/capsules/web-app/`, byte for byte | `lab-cid:sha256:5559e5e3fe8f8e31006c035af0367d87810e214d987d1e8548d1bac03ca82066` |
| `wc001-core` | `capsule.json` | written for this lab | not pinned (below) |
| `agent-host` | `capsule.json`, `asks.json` | `examples/agent-host/capsule.json` (git blob `3395c59fab00816109d5dd471ccbceaf5d59e191`) and `examples/agent-host/asks.json` (git blob `3f004896c68aa7097d02505920afc6c178b065ff`) at `e11fdafce`, byte for byte; the module is not in the fixture (below) | `lab-cid:sha256:43a918a50818e6f6ec81543a6dd423c796b03db028d0c7a4222f354c2afdc054` |

`agent-host` holds the agent-host capsule's own manifest and its declared asks
(M1 check B2). `git hash-object` of each copy equals the blob id in the table.
The agent-host lane may change its files later; these copies stay as they are,
so the pin holds. The manifest's entrypoint, `agent-host.component.wasm`, is
build output and is never committed (HANDOFF rule 7), so the module is not in
the fixture: this lab CID covers the two files only and is not the whole
capsule's name. The lab never parses `asks.json`: to the lab CID it is one more
payload file. The manifest is a component manifest, so the Runtime's
`validate()` also requires its `wit_world_sha256` to equal the SHA-256 of
`elastos/wit/elastos-bus-v1.wit`, which `elastos-common` compiles in
(`elastos/crates/elastos-common/src/manifest.rs:412` and `:794-800`).

`wc001-core` holds only the manifest. Its entrypoint `capsule.wasm` is wc-001's
module: each test builds it with `lab/wasm-capsule/tools/build` into a temp dir
and checks it against wc-001's own receipt. It is never committed (HANDOFF rule
7). wc-001's hash is that lane's value and differs per machine, so this lane
does not pin it: the test shows two bundles around it, each named twice, agree.

## What the lab CID ignores and what it covers

PRINCIPLES 13 names a capsule by its complete bundle CID, and says a web URL or
Store row is not its identity. Here that has two halves. Each rule has a named
test on bundles assembled in temp dirs, and a falsifier. Each test names the
bundle before and after one change. So a byte the name left out could not hide
behind a pin that differs anyway.

**Where a bundle lives is not its identity.** The lab CID stays the same when
(`tests/location.rs`):

| Change | Named test | Falsifier |
| --- | --- | --- |
| The bundle folder is renamed | `renaming_the_bundle_folder_keeps_the_lab_cid` | F-CI3a |
| The bundle moves to another parent, at another depth | `moving_the_bundle_to_another_parent_keeps_the_lab_cid` | F-CI3b |
| The URL it came from changes, and so do two Store rows beside it: their `release_path`, and the record's `name` | `changing_the_url_or_store_row_keeps_the_lab_cid` | F-CI3c |
| Every file and folder gets another mtime and mode | `file_times_and_modes_do_not_change_the_lab_cid` | F-CI3d (mtime), F-CI3j (mode) |

In the URL test the bundle folder sits in a listing folder, next to a
`source.url` file and two rows copied from the Runtime as test data: the
`payload` of `elastos/crates/elastos-server/tests/fixtures/capsule-record.json`
(an `elastos.capsule.record/v1` row) and one `external` platform row of
`components.json`. All three are outside the bundle folder. The test adds no
field to the rows and writes no lab CID into their `cid` field. `check_name`
with the first lab CID passes before and after the change.

**Every byte of a bundle is its identity.** The lab CID changes when
(`tests/bytes.rs`):

| Change | Named test | Falsifier |
| --- | --- | --- |
| One byte inside a JSON string value of `capsule.json`; the manifest still parses and validates | `one_byte_change_in_the_manifest_changes_the_lab_cid` | F-CI1k |
| One byte in each web-app payload file in turn, `browser/app.js` included, which is not the entrypoint | `one_byte_change_in_any_payload_file_changes_the_lab_cid` | F-CI1l |
| A file is added (an empty one too) or removed | `adding_or_removing_a_payload_file_changes_the_lab_cid` | F-CI1l |
| One byte inside a JSON string value of agent-host's `asks.json`; it is still JSON | `one_byte_change_in_asks_json_changes_the_lab_cid` | F-CI3i, F-CI1l |

So the asks a capsule declares in `asks.json` are inside its lab CID. After
each change, `check_name` with the old lab CID is refused with both values.

**A claimed name is checked, never trusted.** A name that a URL, a Store row
or any other record claims meets the bytes through `check_name(bundle,
claimed)` (`tests/check_name.rs`):

1. A claim that is not `lab-cid:sha256:` and 64 lowercase hex characters is
   refused before the bundle is read, for example
   `the claim "5559e5e3…2066" is not a lab CID: a lab CID is lab-cid:sha256: and 64 lowercase hex characters`.
   Bare hex, another label, uppercase hex, a character that is not hex, 63 or
   65 characters and a trailing newline are each refused this way, even with
   the bundle's own digits.
2. The name is recomputed from the bytes with `lab_cid`, the one naming path,
   and compared. A lab CID the bytes do not give is refused with both values:
   `bundle bytes name <actual>; the claim is <claimed>`.
3. `lab_cid`'s own refusals pass through unchanged, variant and text.
4. Success returns nothing, so a claim never comes back as a checked name. A
   refusal keeps the claimed text only to say what was refused.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| A wrong lab CID is refused with both values; a claim that is not a lab CID is refused as one, before any bundle is read | `claimed_name_is_checked_never_trusted` | F-CI3g (no comparison), F-CI3h (label), F-CI3k (length), F-CI3l (hex digits), F-CI3m (lowercase), F-CI3p (order) |
| `lab_cid`'s refusals pass through | `check_name_preserves_lab_cid_refusals` | F-CI3n |
| `check_name` names the bundle only by calling `lab_cid` | `check_name_uses_the_single_naming_path` | F-CI3o |

There are no entries F-CI3e (leave `capsule.json` out of the stream) and
F-CI3f (name only the manifest and the entrypoint): they would plant exactly
the edits of F-CI1k and F-CI1l. Those two entries carry this task's tests
instead, so no edit has two entries (P10). F-CI3g also names the four byte
tests, since each ends with that same refusal.

## How the walk reads a bundle

The walk reads only handles it has checked.

**The root.** The walk opens the bundle root once, by the path the caller
gives, as a folder, with the same flags as every other open: no-follow and
non-blocking. No-follow covers only the path's last part. If that part is a
link, the open fails and the bundle is refused (on this Mac:
`could not read .: Not a directory (os error 20)`); the link is not followed.
Links in folders above the root are followed, as for any path (on macOS,
`/var` and `/tmp` are links). If the path cannot resolve, for example through a
link loop above the root, the refusal keeps the system's reason and does not
call the root a link.

**Every entry.** After the root, the walk never uses a path. For each folder:

1. It reads the folder's whole listing from the folder's handle before it opens
   anything in it. It skips `.` and `..`: opening them would walk the same
   folder forever or climb out of the bundle.
2. It refuses a link, FIFO, socket or device from the listing's own type, with
   its bundle path and kind, for example
   `browser/alias.js is a symbolic link: the lab CID covers only regular files and never follows a link`.
   Such an entry is never opened, read or followed.
3. It opens each regular file or folder relative to its folder's handle
   (`openat`), never by a path joined under the root. Every open uses the
   no-follow and non-blocking flags; a folder is also opened as a folder.
4. It checks the open handle with `fstat`. A handle that is not a regular file
   or a folder is refused as that kind. A handle that is not the kind its
   listing said is refused with
   `browser/app.js changed while the bundle was named`. An entry that became a
   link before its open fails the no-follow open and is refused as a link. A
   refused handle is never read.
5. It reads a file's bytes from that same handle, and lists a folder from that
   same handle.

**One walk.** `lab_cid(bundle)` is `lab_cid_observed(bundle, observer)` with an
observer that does nothing, and `lab_cid_observed` is the lab CID of
`checked_bundle_observed(bundle, observer)`, which runs the walk (see
[the checked bundle](#checked-bundle-the-name-and-the-bytes-it-covers)). The
observer is the tests' seam: the walk tells it
about each entry at two moments, `BeforeOpen` (name and listed kind known,
nothing open) and `AfterCheck` (handle open and checked, nothing read or listed
yet). It returns nothing, so it cannot steer the walk. No other code walks a
bundle (P10).

So a bundle changed while it is named is either refused, or named exactly as
the bytes its checked handles held. The tests in `tests/walk.rs` change web-app
at each moment and show both outcomes.

### What these rules do not cover

- The bytes inside a file are not frozen. If another process writes to a file
  while the walk reads it, the name covers the bytes the walk read. The walk
  takes no snapshot and no lock.
- A file swapped for another regular file before its open is read and named:
  the name covers the bytes its checked handle held.
- Between the listing and the open, a file swapped for a device would be opened
  (non-blocking, no-follow) before `fstat` refuses it. Only root can make a
  device node. A folder is opened as a folder, so its open never opens a
  device.
- A root path that ends in `/` or `/.` makes the system resolve its last part
  through a link before the open. Give the root without a trailing `/`.
- Listing a folder re-opens it as `.` relative to its own handle (rustix's
  `Dir::read_from`). `.` is never a link.
- A hard-linked file is a regular file and is named. A mount point inside the
  bundle is walked like a folder.
- There is no size or count limit: every file is read into memory. The walk
  goes depth first and holds one handle per folder level.
- A filesystem whose listing does not report entry types gets every entry
  refused as a `special file`. APFS reports them.
- A name that is not UTF-8 is refused, never converted.

## Checked bundle: the name and the bytes it covers

`checked_bundle(bundle)` returns a `CheckedBundle`. It holds the bundle's lab
CID and every regular file the walk read: each file's bundle path and the
bytes read from its checked handle. One walk and one manifest check make it.
`lab_cid` is that same walk and returns only the value's `cid()`, so a bundle
is still walked, checked and named in one place (P10).

**Use the entries; never read the folder again.** A caller that audits, stages
or signs a bundle takes the bytes from `entries()` of the same value. A path
form reads the folder a second time, and a file changed between the two reads
would be used under a name that does not cover it. The value closes that gap:
the bytes it hands out are the bytes its lab CID names.

- Its fields are private. Only `checked_bundle` and `checked_bundle_observed`
  make one, and nothing changes one: there is no public constructor, no `&mut`
  access and no `Deserialize`. So its lab CID always names its entries:
  `encode_entries(entries())` gives `cid()`.
- It holds a name and bytes, never a decision. It is no trust, admission or
  launch value. Holding one means only "these bytes give this lab CID".
- The entries come in the walk's order. The encoder sorts them; a caller that
  needs an order sorts them by path.
- It lives in memory only. It has no file or serialized form, and nothing
  writes or stages its entries anywhere.

**The checked name check.** `checked.check_name(claimed)` is the checked form
of `check_name(bundle, claimed)`. Both run the one claim check (the
`lab-cid:sha256:` label and 64 lowercase hex characters) and the one compare,
with the same refusals and texts. The checked form judges the lab CID the value
holds and reads nothing, so it judges exactly the bytes in `entries()`, even
after the folder has changed. `check_name(bundle, claimed)` reads the folder as
it is now, so after a change the two answer differently, and each is right
about the bytes it judged.

The public API another lab may call:

| Call | Gives |
| --- | --- |
| `checked_bundle(bundle: &Path) -> Result<CheckedBundle, Refusal>` | the lab CID and the bytes it names; a refusal is exactly `lab_cid`'s, variant and text |
| `CheckedBundle::cid(&self) -> LabCid` | the lab CID of the entries |
| `CheckedBundle::entries(&self) -> &[BundleEntry]` | every regular file the walk read, as `path` and `content` |
| `CheckedBundle::check_name(&self, claimed: &str) -> Result<(), Refusal>` | `Ok(())` when `claimed` is this lab CID; otherwise `NotALabCid` or `NameMismatch` |

`checked_bundle_observed(bundle, observe)` is the tests' seam, as
`lab_cid_observed` is. `lab_cid`, `lab_cid_observed` and `check_name` reach the
walk only through it.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| The value's lab CID names its entries, and they are each fixture's committed files with their bytes | `checked_bundle_returns_the_bytes_its_lab_cid_names` | F-CI9b |
| A file swapped for a link after its handle is checked: the value keeps the checked bytes, never the outside file's | `checked_entries_are_the_bytes_the_walk_checked` (`tests/walk.rs`) | F-CI9a |
| A bundle `lab_cid` refuses gets the same refusal, variant and text, and no value | `checked_bundle_refuses_what_lab_cid_refuses` | F-CI9c |
| One manifest check, in the seam | `checked_bundle_checks_the_manifest_once` | F-CI9c (moved out), F-CI9g (a second one) |
| Private fields; the seam is the one place that builds one; no `&mut` | `checked_bundle_fields_are_private` | F-CI9d (public field), F-CI9e (constructor), F-CI9f (`&mut` lab CID) |
| The checked form judges the bytes it holds; the path form reads the folder now | `checked_name_check_judges_the_checked_bytes` | F-CI3g, F-CI9h (no compare), F-CI9i (bare hex), F-CI9j (walks again) |
| The checked form refuses a lab CID its bytes do not give | `checked_name_check_refuses_a_mismatch` | F-CI3g, F-CI9h |
| The checked form calls the one claim check and the one compare, and reads nothing | `checked_name_check_shares_the_claim_check_and_the_compare` | F-CI9h, F-CI9i, F-CI9j |

The tests are in `tests/checked_bundle.rs` unless the table names another
file. F-CI3g skips the one compare, so it lists the checked form's two tests
too: a checked form with a compare of its own would leave
`checked_name_check_refuses_a_mismatch` passing, and F-CI3g would not count.

## Test-key publisher signature (lab proposal)

A test key can sign a bundle's printed lab CID. The check answers only "did
this test key sign this lab CID?". It does not answer "may this run?".

**The message.** `name_signature_message` is SHA-256 over three parts, in
order:

1. the domain `lab.capsule-identity.name-signature/v1`
   (`NAME_SIGNATURE_DOMAIN`);
2. one `0x00` byte;
3. the UTF-8 bytes of the printed lab CID, label included
   (`lab-cid:sha256:<64 lowercase hex>`).

That is the three-step digest in `domain_separated_sign`
(`elastos/crates/elastos-server/src/crypto.rs:88-128`): SHA-256 of
`domain || 0x00 || payload`, then Ed25519 over that digest. The form lives
only in the Runtime server. This lab does not link that crate, so it keeps
one marked copy under its own domain and calls the copy a lab proposal.
Moving the form next to `decode_did_key` in `elastos-identity` is a question
for Anders. Signing and verifying both call `name_signature_message`. Nothing
else builds the message.

**In memory only.** `NameSignature` is a plain struct: `name`, `signer_did`
and a 64-byte `signature`. It has no serde derive, no file and no envelope.
This document proposes none. Nothing writes a signature to disk. The
signature never goes into `capsule.json`'s `signature` field. That file is
inside the bytes the lab CID covers, so a signature written there would
change the name it signs.

**Not the Runtime's capsule signature.** The Runtime verifies a capsule
signature in `elastos/crates/elastos-runtime/src/signature/verifier.rs:76-136`.
This lab does not reproduce that check and does not extend it.

**One DID path.** The signer is an Ed25519 `did:key` from
`elastos_identity::encode_signing_key_did`. Verification decodes it with
`elastos_identity::decode_did_key`. This lab copies no base58 and no
multicodec code.

**Sign.** `sign_bundle(key, bundle)` names the bundle with `lab_cid`. A
refusal from that walk passes through unchanged, and a refused bundle gets
no signature. It signs the message of the printed name and sets `signer_did`
from the key. Success returns the signature. It writes nothing.

**Verify, one form.** `verify_checked_signature(checked, sig, accepted)`
checks 009's `CheckedBundle` in this order. The first refusal is the answer.
`Ok(())` means all four passed, and it returns no trust, admission or launch
value.

1. Decode `sig.signer_did`. On error: `signer DID <did> is not a canonical Ed25519 did:key: <the decoder's own text>`.
2. The DID is an exact member of `accepted`. The list is an explicit input.
   It is not a trust policy. An empty list refuses every signer:
   `signer <did> is not in the accepted list`.
3. 009's checked name check of `sig.name` on `checked` (003's rule and
   texts). Its refusals pass through unchanged. A mismatch names both
   values (`bundle bytes name <actual>; the claim is <claimed>`). A claim
   that is not a lab CID says so. This step reads nothing from disk.
4. Ed25519 verification of the 64 signature bytes over
   `name_signature_message` of `sig.name`, with the key from step 1. On
   failure: `signature by <did> does not verify over <name>`. Ed25519 gives
   a wrong key, a changed signature and a name moved onto other bytes this
   one reason. Another bundle and a tampered bundle byte both fail step 3,
   because both mean these bytes do not match the signed name.

`verify_name_signature(bundle, sig, accepted)` is `checked_bundle(bundle)`
and then `verify_checked_signature`. It holds no check of its own. A bundle
the walk refuses is refused first, with the walk's own reason. The path form
is the walk plus the checked form, so a caller checks the signature on the
bytes it then audits or stages.

**Pinned message digest.** For `content-sample`'s pinned lab CID, the digest
is `650c3b5baeb1e1e2f3cf1e87ded48ee496090c863d11afb9c80fbf07efb59f11`.

```python
import hashlib

name = b"lab-cid:sha256:99cf6c7b9b4489f3a565cca47e1e30f2b4e7752bf0e8824806e7036f7a681d51"
digest = hashlib.sha256(
    b"lab.capsule-identity.name-signature/v1" + b"\x00" + name
).hexdigest()
```

**Keys.** Every test key is made fresh in memory by `fresh_signing_key` in
`tests/common/mod.rs`, which calls `SigningKey::generate` on the operating
system's generator. No key or seed is written, printed or kept as a constant,
and there is no fixed seed. This lane's `.gitignore` ignores `*.seed`. The
root `.gitignore` line 52 already ignores `*.key`; this lane does not repeat
that pattern.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| A fresh test key's signature over `content-sample` and `web-app` verifies | `test_key_signature_over_the_lab_cid_verifies` | F-CI4j |
| The message is the domain-separated printed lab CID | `signed_message_is_the_domain_separated_lab_cid` | F-CI4a, F-CI4b |
| A signature for another bundle is the name check's mismatch | `signature_for_another_bundle_is_refused` | F-CI4c |
| One changed payload byte is the name check's mismatch | `tampered_bundle_byte_is_refused` | F-CI4c |
| A signature relabelled onto another lab CID does not verify | `relabelled_signature_is_refused` | F-CI4a, F-CI4d |
| One flipped signature bit does not verify | `tampered_signature_byte_is_refused` | F-CI4d |
| Another key's signature under an accepted DID does not verify | `signature_by_another_key_is_refused` | F-CI4d |
| A signer outside the list, and an empty list, are refused | `signer_not_in_the_accepted_list_is_refused` | F-CI4e, F-CI4f |
| The checked form judges the bytes it holds; the path form reads the folder now | `checked_signature_judges_the_checked_bytes` | F-CI4c, F-CI4k |
| A malformed DID is refused with the decoder's text, even when listed | `malformed_signer_did_is_refused` | F-CI4g |
| The checked form runs every check, not only the path form | `checked_signature_runs_all_checks` | F-CI4l, F-CI4m, F-CI4n |
| Both wrappers keep the walk's refusal, including bad signature inputs | `signature_paths_preserve_walk_refusals` | F-CI4o, F-CI4p, F-CI4q, F-CI4r, F-CI4s |
| Two faults at once: the earlier check answers | `signature_refusal_order_is_stable` | F-CI4t, F-CI4u, F-CI4v |
| One message, one verification, and the path form holds no check of its own | `signature_paths_share_one_implementation` | F-CI4w, F-CI4x |
| Test keys come from the operating system's generator | `test_keys_use_fresh_os_randomness` | F-CI4y |
| No key material is in what git would stage | `no_key_material_is_tracked` | F-CI4i |
| `*.key` and `*.seed` are ignored | `key_and_seed_files_are_ignored_by_git` | F-CI4h |

The tests are in `tests/name_signature.rs`. F-CI4h drops `*.seed` from this
lane's `.gitignore`. F-CI4i appends a private-key header line to this file.
Neither file is in the runner's recovery list
(`examples/agent-host/falsify.py`, `PROVIDER_TARGETS`). The runner still runs
them. The provider lane adds those two recovery lines after this task merges.

## Why a lab CID and not the Runtime's CID

The Runtime names a published capsule by the CID its IPFS provider returns when
it imports the capsule's archive. `elastos/crates/elastos-server/src/publish.rs:366-385`
imports each artifact (`preflight.import_file`) and requires the returned CID to
equal the artifact's signed pin (`require_import_cid`). The per-capsule record
`elastos.capsule.record/v1` names that archive's `sha256`, `size` and `cid`
(`elastos/crates/elastos-server/src/capsule_record.rs:1-4` and `:24-34`). The
archive is a gzip PAX tar made by `create_capsule_tar`
(`scripts/publish-release.sh:621-655`): it holds the capsule folder's name,
folder entries, normalized modes and symbolic links. This harness hashes a
plain framed stream of regular files instead, so its value never equals the
Runtime's CID, and it does not try to reproduce it. To keep the two apart, the
value prints as `lab-cid:sha256:` and is called "lab CID" in code, output and
docs. Lines read at `c6709039d`; they are the same at `1e5f33d34`.

## Claim scope

One Mac, these fixtures: macOS 26.5.2 on arm64 (APFS), rustc 1.91.0
(f8297e351 2025-10-28). The swap tests make each change happen at a chosen
moment through the observer; they do not prove the walk against every timing
on every filesystem. Not checked here: Linux, and the Runtime's IPFS CID.

## Run

```bash
cargo fmt --manifest-path lab/capsule-identity/Cargo.toml -- --check
RUST_TEST_THREADS=2 cargo test --locked --offline --manifest-path lab/capsule-identity/Cargo.toml
```

The package is its own workspace (empty `[workspace]` table) with its own
`Cargo.lock`, so the Runtime's workspace never grows for it. Dependencies:
`elastos-common` by path (read only, for `CapsuleManifest`), `elastos-identity`
by path (read only, for the one `did:key` encoder and decoder), `hex`,
`serde_json`, `sha2`, `ed25519-dalek` 2.1 with its `rand_core` feature, and
`rustix` 1.1.4 with its `fs` feature, for safe `openat`, `fstat` and listing
from a handle (`std` cannot open relative to a handle, and the crate forbids
`unsafe`). Dev-dependencies: `tempfile` and `rand` 0.8 (the operating system's
generator in tests). There is no dependency on `elastos-server` or
`elastos-runtime`. All resolve offline from the local cargo cache.
`zerocopy` is locked at 0.8.62 because 0.8.63's derive crate is not in that
cache. `wc001_capsule_bundle_gets_a_stable_lab_cid` runs
`lab/wasm-capsule/tools/build`, so it also needs that lane's toolchain.

## Layout

```
Cargo.toml, Cargo.lock   the package, its own workspace and lockfile
src/lib.rs               checked_bundle, lab_cid, check_name and its checked form,
                         the encoder, the walk, and the test-key signature
fixtures/                content-sample, web-app, wc001-core, agent-host
tests/common/mod.rs      assembly, pins, the bounded call, observers, wc-001 driver,
                         the library's code for tests that read it, fresh test keys
tests/bytes.rs           every byte is the name: manifest, payload, asks.json, files
tests/check_name.rs      a claimed name is checked, never trusted; one naming path
tests/checked_bundle.rs  the name and the bytes it covers; the checked name check
tests/encoding.rs        order, boundaries, label, one file per path
tests/fixtures.rs        Runtime manifest checks, pins, the wc-001 bundle
tests/location.rs        folder name, place, URL, Store rows, times, modes: not the name
tests/name_signature.rs  a test key signs the printed lab CID; verification only
tests/refusals.rs        each refusal and its reason
tests/walk.rs            changes made while a bundle is named; one walk
falsifiers.json          planted bugs, each caught by named tests
```

## Falsifiers

`falsifiers.json` holds 81 planted bugs in the provider format: round 1's
F-CI1a to F-CI1u, task 005's F-CI5a to F-CI5k, task 003's F-CI3a to F-CI3p
(no F-CI3e or F-CI3f: see
[above](#what-the-lab-cid-ignores-and-what-it-covers)), task 009's F-CI9a
to F-CI9j (see [the checked bundle](#checked-bundle-the-name-and-the-bytes-it-covers)),
and task 004's F-CI4a to F-CI4y (see
[the test-key signature](#test-key-publisher-signature-lab-proposal)).
Each has `"command": "capsule-identity"` and `expect: "caught"`, and counts
only when every named test fails for its stated reason, never from a build
error. Every entry except F-CI4h and F-CI4i edits a file the runner restores
after a killed run: `src/lib.rs`, `tests/common/mod.rs` or
`fixtures/wc001-core/capsule.json`. F-CI4h edits this lane's `.gitignore` and
F-CI4i edits this file. Those two are not in the runner's recovery list. The
runner still runs them. The provider lane adds both lines after this task
merges.

Task 009 moved code without changing an older entry. The root manifest check
and the encoder call moved from `lab_cid_observed` into
`checked_bundle_observed`, and 003's compare moved into `compare_name`, each
byte for byte, so every older edit's text is still found exactly once. The
comment line after `encode_entries(&entries)` in `checked_bundle_observed`
keeps that call on its own line, as the edits of F-CI1k, F-CI1l, F-CI3a,
F-CI3b and F-CI3i expect; without it, rustfmt joins the call and the line
after it.

The canonical runner runs the list. Its `capsule-identity` command builds and
tests `lab/capsule-identity/Cargo.toml`, runs each named test alone with
`--exact`, and puts each file back byte for byte:

```bash
python3 -I examples/agent-host/falsify.py --from lab/capsule-identity/falsifiers.json
```

At task 009, on this Mac, it reported `summary: 56 CAUGHT of 56` (at task 003:
46 of 46). At task 004 it reported `summary: 81 CAUGHT of 81`. The runner
does not print why a test failed. Tasks 003, 009 and 004 prove each of their
falsifiers by break, named test fails, revert.

The signature answers only whether this test key signed this lab CID.
