# capsule-identity lab: one lab CID over a whole bundle

Lab tooling for the cc-capsule-identity lane (ci-1: tasks 001 and 005; ci-2:
task 003). It names a capsule bundle by one deterministic **lab CID** over all
of its bytes: the manifest and every payload file (PRINCIPLES 13 and 15). It
checks a claimed name against the bytes and never trusts it.

## What it is, and what it is not

- It answers one question: do these bytes match this name?
- It never answers "may this run?". It makes no trust, admission or launch
  decision. It sits in no admission or launch path, and no Runtime code calls
  it. Admission stays a separate decision under each Runtime's trust policy.
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

In Rust, `lab_cid` walks a bundle and `encode_entries` is the encoder. They are
the only code that names a bundle; tests call them and copy neither.
`check_name` checks a claimed name by calling `lab_cid`; it computes no name of
its own.

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
observer that does nothing. The observer is the tests' seam: the walk tells it
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
`elastos-common` by path (read only, for `CapsuleManifest`), `hex`,
`serde_json`, `sha2`, and `rustix` 1.1.4 with its `fs` feature, for safe
`openat`, `fstat` and listing from a handle (`std` cannot open relative to a
handle, and the crate forbids `unsafe`). Dev-dependency: `tempfile`. All
resolve offline from the local cargo cache. `wc001_capsule_bundle_gets_a_stable_lab_cid`
runs `lab/wasm-capsule/tools/build`, so it also needs that lane's toolchain.

## Layout

```
Cargo.toml, Cargo.lock   the package, its own workspace and lockfile
src/lib.rs               lab_cid, lab_cid_observed, check_name, the encoder and the walk
fixtures/                content-sample, web-app, wc001-core, agent-host
tests/common/mod.rs      assembly, pins, the bounded call, observers, wc-001 driver,
                         the library's code for tests that read it
tests/bytes.rs           every byte is the name: manifest, payload, asks.json, files
tests/check_name.rs      a claimed name is checked, never trusted; one naming path
tests/encoding.rs        order, boundaries, label, one file per path
tests/fixtures.rs        Runtime manifest checks, pins, the wc-001 bundle
tests/location.rs        folder name, place, URL, Store rows, times, modes: not the name
tests/refusals.rs        each refusal and its reason
tests/walk.rs            changes made while a bundle is named; one walk
falsifiers.json          planted bugs, each caught by named tests
```

## Falsifiers

`falsifiers.json` holds 46 planted bugs in the provider format: round 1's
F-CI1a to F-CI1u, task 005's F-CI5a to F-CI5k, and task 003's F-CI3a to
F-CI3p (no F-CI3e or F-CI3f: see
[above](#what-the-lab-cid-ignores-and-what-it-covers)). Each has
`"command": "capsule-identity"` and `expect: "caught"`, and counts only when
every named test fails for its stated reason, never from a build error. Each
edits one of the files the runner restores after a killed run: `src/lib.rs`,
`tests/common/mod.rs` or `fixtures/wc001-core/capsule.json`.

The canonical runner runs the list. Its `capsule-identity` command builds and
tests `lab/capsule-identity/Cargo.toml`, runs each named test alone with
`--exact`, and puts each file back byte for byte:

```bash
python3 -I examples/agent-host/falsify.py --from lab/capsule-identity/falsifiers.json
```

At task 003, on this Mac, it reported `summary: 46 CAUGHT of 46`. The runner
does not print why a test failed. Task 003 also proved each of its
falsifiers by hand: plant the edit, run each named test alone, read its failure
message, restore the file and compare its SHA-256.
