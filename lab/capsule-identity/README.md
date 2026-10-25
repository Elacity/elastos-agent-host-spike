# capsule-identity lab: one lab CID over a whole bundle

Lab tooling for the cc-capsule-identity lane (ci-1: tasks 001 and 005). It
names a capsule bundle by one deterministic **lab CID** over all of its bytes:
the manifest and every payload file (PRINCIPLES 13 and 15).

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

1. Start the stream with the 31 bytes `lab.capsule-identity.bundle/v1` and one
   newline byte (the framing tag).
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

The same rule in a few lines of Python, which gives both pins below from the
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

`wc001-core` holds only the manifest. Its entrypoint `capsule.wasm` is wc-001's
module: each test builds it with `lab/wasm-capsule/tools/build` into a temp dir
and checks it against wc-001's own receipt. It is never committed (HANDOFF rule
7). wc-001's hash is that lane's value and differs per machine, so this lane
does not pin it: the test shows two bundles around it, each named twice, agree.

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
src/lib.rs               lab_cid, lab_cid_observed, the encoder and the walk
fixtures/                content-sample, web-app, wc001-core
tests/common/mod.rs      assembly, pins, the bounded call, observers, wc-001 driver
tests/encoding.rs        order, boundaries, label, one file per path
tests/fixtures.rs        Runtime manifest checks, pins, the wc-001 bundle
tests/refusals.rs        each refusal and its reason
tests/walk.rs            changes made while a bundle is named; one walk
falsifiers.json          planted bugs, each caught by named tests
```

## Falsifiers

`falsifiers.json` holds 32 planted bugs in the provider format: round 1's
F-CI1a to F-CI1u and this task's F-CI5a to F-CI5k. Each has
`"command": "capsule-identity"` and `expect: "caught"`, and counts only when
every named test fails for its stated reason, never from a build error.
`examples/agent-host/falsify.py` has no `capsule-identity` command yet
(provider BACKLOG item 8c: the row `capsule-identity` ->
`lab/capsule-identity/Cargo.toml`; Flint routes it), so the runner refuses this
list as unknown. Until it lands, each falsifier is proved by hand: plant its
edit, run each named test alone with `cargo test --locked -- --exact <name>`,
see it fail for the stated reason, and revert the file byte for byte. A
falsify.py run of this list is reported as not run, never as PASS.
