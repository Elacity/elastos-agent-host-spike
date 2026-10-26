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
- Its value is a **lab CID**, a lab package CID: the CIDv1 SHA-256 UnixFS
  directory root of the bundle, printed as 59 characters that start
  `bafybei`. It is a prototype, not an admission, and it defines no shared
  capsule identity. It is not the Runtime's published name (see
  [Why a lab CID](#why-a-lab-cid-and-not-the-runtimes-cid)).
- The one schema check is the Runtime's own. `capsule.json` at the bundle root
  is parsed as `elastos_common::CapsuleManifest`, which refuses an unknown
  field, and then checked with its `validate()`. Each refusal keeps the
  Runtime's own text. The lab adds no field, no schema and no parser.

## The encoding

The lab CID is the CID of the bundle's UnixFS root directory, made the way
Anders's answer (Q3) asks: CIDv1, SHA-256, the model package profile. The
profile is Kubo v0.40.1's import flags as
`capsules/ipfs-provider/src/directory_hash.rs` sends them (`ADD_OPTIONS`,
lines 21-43, and the HAMT defaults at lines 507-517): CIDv1, `sha2-256`, raw
leaves, chunker `size-262144`, trickle off (balanced layout), `max-file-links`
174, `max-directory-links` 0, HAMT fanout 256 and size threshold 256KiB, no
inline (inline limit 32 unused), no preserved mode or mtime, no empty
directories. This crate runs no Kubo, and no Kubo is installed on this Mac.
So the lab CID follows the Kubo v0.40.1 profile, computed by the lab: no Kubo has
computed any pin, and [Claim scope](#claim-scope) states the gate before the
lab CID may be called more than that.
The tests pin only the single-block, non-sharded subset of that profile: one
raw leaf per file and one block per directory. Anything bigger is refused, not
named another way.

To recompute a lab CID by hand:

1. Take every regular file under the bundle root. Its bundle path is its path
   below the root, parts joined with `/`, in UTF-8.
2. Each file of at most 262144 bytes is one **raw leaf**. Its block is the
   file's bytes (an empty file is an empty block). Its CID is the 36 bytes
   `01 55 12 20` and the SHA-256 of the block: CID version 1, the raw codec
   `0x55`, the multihash code `0x12` (sha2-256) and length `0x20` (32). Its
   Tsize is its length. A file of 262145 bytes or more is refused with its
   path, its length and the limit: there is no chunked file DAG.
3. Each path part but the last is a **directory**: `browser/app.js` is a
   directory `browser` with a link named `app.js`. The root is the directory
   of the bundle's entries. No empty directory is ever made.
4. A directory's **block** is dag-pb. Sort its children by name bytes. For each
   child, write protobuf field 2 (tag `0x12`, then the length as a varint)
   holding a link: field 1 (`0x0a`, length) the child's CID bytes, field 2
   (`0x12`, length) its name in UTF-8, field 3 (`0x18`) its Tsize as a varint.
   Then write field 1 (`0x0a 0x02`) holding the UnixFS data `08 01`: type
   (field 1) = 1, a directory. Lengths and Tsizes are ordinary unsigned
   varints: 7 bits per byte, low bits first, so a value over 127 takes two
   bytes. A block over 262144 bytes is refused with the directory's path (`.`
   is the root) and the limit: there is no HAMT shard. Kubo shards later, by
   an estimate of its links' size, so this refusal comes first and fails
   closed.
5. A directory's CID is `01 70 12 20` and the SHA-256 of its block (the dag-pb
   codec `0x70`). The Tsize of a link to a directory is the length of its
   block plus the Tsizes of its own links. Every varint inside a CID here is
   one byte.
6. **Print** the root's 36 CID bytes as `b` (the multibase prefix) and their
   RFC 4648 base32, in the lowercase alphabet
   `abcdefghijklmnopqrstuvwxyz234567`, with no `=` padding: 288 bits make 58
   characters, the last one padded with two zero bits. The result is 59
   characters, and `01 70 12 20` always prints as `bafybei`.

For example, `content-sample`'s `sample.example` is 16 bytes, so its leaf CID
is `bafkreieigdqewmuwbhvduqyyc5lg2eromsgdbnezmrdxmi62lux26qflgy` (`bafkrei` is
`01 55 12 20`). The root block lists `capsule.json` (895 bytes, Tsize `ff 06`)
and then `sample.example` (Tsize `10`), and prints as the pin below.

Nothing else enters a block: no folder name, no absolute path, no file time,
mode, owner or symlink target. Every name and every byte string is written
with its length, and each file's bytes are their own block, named by hash, so
two different bundles never make the same root.

The same rule in a few lines of Python, which gives every pin below from the
committed fixture files. This block is the committed outside check: the test
`readme_python_recomputes_every_lab_cid_pin` runs it (see
[the cross-implementation check](#the-cross-implementation-check)), so it
cannot drift from the Rust encoder without a test failing:

```python
import hashlib

B32 = "abcdefghijklmnopqrstuvwxyz234567"

def varint(n):
    out = b""
    while n >= 0x80:
        out, n = out + bytes([n & 0x7F | 0x80]), n >> 7
    return out + bytes([n])

def field(number, data):  # protobuf, wire type 2
    return bytes([number << 3 | 2]) + varint(len(data)) + data

def cid(codec, block):
    return bytes([0x01, codec, 0x12, 0x20]) + hashlib.sha256(block).digest()

def directory(tree):  # {name: bytes or a dict}; returns (CID bytes, Tsize)
    links = b""
    total = 0
    for name in sorted(tree, key=lambda n: n.encode("utf-8")):
        child = tree[name]
        if isinstance(child, dict):
            child_cid, tsize = directory(child)
        else:
            assert len(child) <= 262144
            child_cid, tsize = cid(0x55, child), len(child)
        link = field(1, child_cid) + field(2, name.encode("utf-8"))
        links += field(2, link + b"\x18" + varint(tsize))
        total += tsize
    block = links + field(1, b"\x08\x01")
    assert len(block) <= 262144
    return cid(0x70, block), len(block) + total

def lab_cid(files):  # {bundle path: bytes}
    root = {}
    for path, data in files.items():
        *folders, name = path.split("/")
        node = root
        for folder in folders:
            node = node.setdefault(folder, {})
        node[name] = data
    bits = "".join(f"{byte:08b}" for byte in directory(root)[0]) + "00"
    return "b" + "".join(B32[int(bits[i:i + 5], 2)] for i in range(0, 290, 5))
```

In Rust, the walk (`checked_bundle`, which `lab_cid` runs too) reads a bundle
and `encode_entries` is the encoder. They are the only code that names a
bundle; tests call them and copy neither. `encode_entries` holds the one
naming hash, and leaves and directory blocks share it. It also refuses what
the walk can never give but a caller of the encoder could: a path with an
empty, `.` or `..` part, two entries with one path, and one path that is both
a file and a directory (`a` and `a/b`, in either order). `check_name` checks a
claimed name by calling `lab_cid`; it computes no name of its own.

The CIDv1 bytes and the base32 text are one marked lab copy inside
`src/lib.rs` (`cid_bytes`, one encoder, one decoder). The Runtime's `cid`
0.11 crate lives only in `elastos-server` and `elastos-namespace`, which the
lab does not link, and any new crate here would make the locks of
`lab/wasm-capsule` and `lab/agent-conformance` (both path-depend on this
crate) stale. So the lab adds no crate.

Each profile setting has a named test and a falsifier (`tests/encoding.rs`;
every pin is also recomputed by the Python block above, written from these
rules and not from the Rust code, in
`readme_python_recomputes_every_lab_cid_pin`):

| Setting | Named test | Falsifier |
| --- | --- | --- |
| CID version 1 for directories | `lab_cid_matches_the_pinned_value_for_each_fixture` | F-CI18a (CIDv0) |
| Multihash code `0x12`, sha2-256 | `lab_cid_matches_the_pinned_value_for_each_fixture` | F-CI18b (`0x13`) |
| Raw leaves, codec `0x55` | `lab_cid_matches_the_pinned_value_for_each_fixture` | F-CI18c (`0x70`) |
| Directory codec `0x70`, dag-pb | `lab_cid_matches_the_pinned_value_for_each_fixture` | F-CI18r (`0x71`) |
| Chunk size 262144: a file of exactly that size is one block | `single_block_at_the_chunk_limit_has_the_pinned_cid` | F-CI18d (262143) |
| A larger file is refused | `file_over_the_chunk_limit_is_refused` | F-CI18e (no refusal) |
| Links sorted by name bytes | `lab_cid_matches_the_pinned_value_for_each_fixture`, `lab_cid_does_not_depend_on_listing_order` | F-CI18f (reverse), F-CI1a (no sort) |
| Directory type 1 | `lab_cid_matches_the_pinned_value_for_each_fixture` | F-CI18g (5) |
| A directory block over 262144 bytes is refused, no HAMT | `directory_over_the_hamt_threshold_is_refused` | F-CI18h (no refusal) |
| No inline: no identity multihash | `lab_cid_matches_the_pinned_value_for_each_fixture` | F-CI18i (inline at most 32 bytes) |
| The printed form, `b` and lowercase base32 | `lab_cid_prints_with_the_lab_label`, `the_library_names_a_bundle_one_way`, `lab_cid_matches_the_pinned_value_for_each_fixture` | F-CI18j (old prefix), F-CI18k (uppercase), F-CI1d (no `b`) |
| A directory link's Tsize includes its child's links | `lab_cid_matches_the_pinned_value_for_each_fixture` (`web-app` has `browser/`) | F-CI18m |
| An empty file is an empty raw leaf | `empty_file_has_the_pinned_cid` | F-CI18n (dag-pb file node) |
| Lengths over 127 take two varint bytes | `long_utf8_name_has_the_pinned_cid` (a 154-byte name) | F-CI18o (one byte) |
| A name and a file's length are written with their lengths | `path_and_content_boundaries_cannot_collide` | F-CI1b, F-CI1p (name), F-CI1q (Tsize) |
| A file and a directory at one path are refused | `encoder_refuses_file_directory_conflict` | F-CI18p, F-CI18q (one silently replaces the other) |
| An empty, `.` or `..` path part is refused | `encoder_refuses_a_path_with_an_empty_or_dot_part` | F-CI18s |
| Two entries with one path are refused | `encoder_refuses_a_duplicate_path` | F-CI1r |

The three pins these tests add are in `tests/common/mod.rs`, and the Python
block gives each of them too (the first is also blocked task 010's pin): the
chunk-limit bundle (`content-sample`'s `capsule.json` and
`sample.example` as 262144 zero bytes, built in a temp dir and never
committed) is `bafybeibt53faomuek2j4yihvseuib2h6fosmkzympgilbnay2xevciasb4`;
`content-sample` with an added empty file `empty` is
`bafybeic2y3c3met6txd62reatxwqjnodhfejchfmltmd6dnpyhtah7l5we`; and
`content-sample` with a file named fifty `名` and `.txt` holding `long name`
and a newline is `bafybeih6g5cy7asndjexb7bazovwryqyj4faxvababcjrbe4jxayhzvgmy`.
The directory-block test builds 1100 empty files with 200-byte names in a temp
dir.

### The cross-implementation check

`readme_python_recomputes_every_lab_cid_pin` (`tests/cross_implementation.rs`)
makes the Python block above a second implementation under test (Rong's DR-2:
"one non-Kubo checker that recomputes the CID"; Anders's Q2 and Q3:
cross-implementation tests). The code that runs it is in `tests/common/mod.rs`:

1. `readme_python_block` takes the one ```` ```python ```` block of this
   section from the committed README, as it is. A missing section, no block,
   two blocks or an unclosed block is refused with its reason.
2. A short driver, `README_PYTHON_DRIVER`, follows it. It reads
   `{bundle path: hex}` JSON from stdin, calls the block's `lab_cid` and prints
   its answer. It holds no part of the rule: the test checks that it has no
   `hashlib`, `sha256`, `varint`, `base64`, `B32`, base32 alphabet, `def` or
   `lambda`, and calls `lab_cid(` once. So this block stays the only Python
   copy of the rule (P10).
3. Each bundle is its own `python3 -I -c` run from a fresh, empty temp
   folder. The driver first checks that it runs under `-I` and that its folder
   is empty, or it exits with its reason.
4. It never skips. A `python3` that cannot start
   (`python3 -I could not run: <error>`), a non-zero exit (even after it
   printed a valid CID), no output, or more than one line is refused with its
   own reason, and the test asserts each of these reasons.
5. For each of the 11 pins, the Python answer, the pin constant and the
   printed `encode_entries` result for the same files must be equal, and the
   test asserts that it checked exactly 11 bundles. The 11 are the seven
   pinned fixtures (`content-sample`, `web-app`, `agent-host`, `provider`,
   `model`, `provider-variant-a`, `provider-variant-b`), the recipe, and the
   chunk-limit, empty-file and long-name bundles above, which are built as
   entries in memory. `wc001-core` has no pin, because its `capsule.wasm` is
   built on each machine, so it is not checked here.

| Rule | Named test | Falsifier |
| --- | --- | --- |
| README's rule agrees with the pins | `readme_python_recomputes_every_lab_cid_pin` | F-CI19a (the block's `0x55` becomes `0x70` before it runs) |
| Rust agrees with README's rule, not only with the pins | `readme_python_recomputes_every_lab_cid_pin` | F-CI19b (the encoder's `RAW_CODEC` becomes `0x56`) |
| A missing block is no pass: exactly 11 bundles are checked | `readme_python_recomputes_every_lab_cid_pin` | F-CI19c (no block found, no answers) |
| An interpreter that cannot start fails the test | `readme_python_recomputes_every_lab_cid_pin` | F-CI19d (a program that does not exist) |
| A non-zero exit is refused | `readme_python_recomputes_every_lab_cid_pin` | F-CI19e (exit status not checked) |
| No output is refused | `readme_python_recomputes_every_lab_cid_pin` | F-CI19f (empty answer taken) |
| More than one line is refused | `readme_python_recomputes_every_lab_cid_pin` | F-CI19g (first line taken) |
| The driver holds no rule | `readme_python_recomputes_every_lab_cid_pin` | F-CI19h (`import hashlib`) |
| It runs isolated | `readme_python_recomputes_every_lab_cid_pin` | F-CI19i (no `-I`) |
| It runs from a fresh, empty folder | `readme_python_recomputes_every_lab_cid_pin` | F-CI19j (the lane folder) |

Task 020 runs README's two digest blocks the same way (Anders's Q2: the
record encoding and the signature domain under cross-implementation tests):
the block under "Pinned message digest" in
[the test-key signature](#test-key-publisher-signature-lab-proposal) and the
one under "The digest" in
[the lab package record](#lab-package-record-outside-the-bundle). The same
extractor (`python_block_under`, one section heading per block) takes each
block as committed, and the same `run_python` runs it. Each block has its own
short driver (`NAME_DIGEST_DRIVER`, `RECORD_DRIVER`), and each test checks
that its driver holds no hash, domain or function of its own. Neither test
skips. A missing section, a section with no block, a section with more than
one block, a block that is never closed before the next section, and a block
that does not define its function are each refused with their own reason,
which the test asserts (task 024 added the third and fourth, through
`assert_bad_block_refused`, which both tests call with their own heading). A
record answer that is not two words is refused with its text. Each test
asserts how many inputs it checked (7 names, 2 records), so a run that returns
no answers fails.

| Rule | Named test | Falsifier |
| --- | --- | --- |
| Rust's digest agrees with both README blocks | `readme_python_matches_the_name_signature_digest`, `readme_python_matches_the_package_record_bytes` | F-CI20a (the separator byte becomes `0x01`) |
| Rust's record payload agrees with README's, byte for byte | `readme_python_matches_the_package_record_bytes` | F-CI20b (`schema` written before `cid`) |
| The test runs README's record block: a drifted record domain fails | `readme_python_matches_the_package_record_bytes` | F-CI20c (the block's `package-record/v1` becomes `/v2`; the schema keeps `/v1`) |
| The test runs README's name block: a drifted name domain fails | `readme_python_matches_the_name_signature_digest` | F-CI20d (the block's `name-signature/v1` becomes `/v2`) |
| A missing name block is no pass: exactly 7 names are checked | `readme_python_matches_the_name_signature_digest` | F-CI20e (no block found, no answers) |
| A missing record block is no pass: exactly 2 records are checked | `readme_python_matches_the_package_record_bytes` | F-CI20f (no block found, no answers) |
| A record answer of one word is refused | `readme_python_matches_the_package_record_bytes` | F-CI24a (one word taken, with an empty digest) |
| A missing section is refused | `readme_python_matches_the_name_signature_digest`, `readme_python_matches_the_package_record_bytes`, `the_adoption_list_is_read_strictly`, `the_claim_wording_check_names_each_gap` | F-CI24b (the search falls back to the start of the text) |
| A section with no block is refused | `readme_python_matches_the_name_signature_digest`, `readme_python_matches_the_package_record_bytes`, `the_adoption_list_is_read_strictly` | F-CI24c (an empty block taken) |
| A section with more than one block is refused | `readme_python_matches_the_name_signature_digest`, `readme_python_matches_the_package_record_bytes` | F-CI24d (the first block taken) |
| A block never closed before the next section is refused | `readme_python_matches_the_name_signature_digest`, `readme_python_matches_the_package_record_bytes` | F-CI24e (the block runs to the end of its section) |
| An interpreter that cannot start fails all three tests | all three tests above | F-CI19d (a program that does not exist) |

Not shown: Kubo itself, and Python on another machine. The check is two
implementations on one Mac (Python 3.9.6 here), not an outside IPFS tool.

## Fixtures and their pinned lab CIDs

Each fixture is a bundle in the existing `elastos.capsule/v1` schema. Tests
assemble a bundle from exactly its listed files in a fresh temp dir, so a stray
local file (such as `.DS_Store`) never reaches a pin. The pins are in
`tests/common/mod.rs`.

| Fixture | Files | Where the bytes come from | Pinned lab CID |
| --- | --- | --- | --- |
| `content-sample` | `capsule.json`, `sample.example` | `templates/capsules/viewer-content/content.capsule.json` and `sample.example`, byte for byte | `bafybeieahlroxjdalpmglh227eikmodrjhrlelvzlhylvyt3s65ackiybi` |
| `web-app` | `capsule.json`, `browser/app.js`, `browser/index.html` | `templates/capsules/web-app/`, byte for byte | `bafybeibc5wcwbtdmjt7qbwbi2rfqvfcfzumivqsoct2ekdqeec2yodqy7q` |
| `wc001-core` | `capsule.json` | written for this lab | not pinned (below) |
| `agent-host` | `capsule.json`, `asks.json` | `examples/agent-host/capsule.json` (git blob `3395c59fab00816109d5dd471ccbceaf5d59e191`) and `examples/agent-host/asks.json` (git blob `3f004896c68aa7097d02505920afc6c178b065ff`) at `e11fdafce`, byte for byte; the module is not in the fixture (below) | `bafybeicesxlwcolv5hifwotsyafyyaclaq23gyzwl7esuvhwlownrhatym` |
| `provider` | `capsule.json`, `ipfs-provider` | the manifest's fields are those of the JSON in `test_parse_v1_manifest` (`elastos/crates/elastos-common/src/manifest.rs`, about lines 2443-2458); `ipfs-provider` is the ASCII `lab fixture` and a newline, a lab stand-in | `bafybeicmpw5zf373ogbziqix2mj2bagmn5imgj3hy7347nulpmx32kooxe` |
| `model` | `capsule.json`, `weights.gguf`, `LICENSE`, `LICENSE.base`, `PROVENANCE.md` | the manifest's fields are those of `model_content_fixture` (same file, about lines 1265-1283; synthetic, not a published model package); the four other files are one line of ASCII each, lab stand-ins | `bafybeifh6dj5r5wc2j5kqxz6ukga74y3gi56woglqdzmmcdhqvy7qtljzq` |
| `provider-variant-a` | `capsule.json`, `ipfs-provider` | `capsule.json` is `provider`'s, byte for byte; `ipfs-provider` is the ASCII `lab fixture aarch64-darwin` and a newline, a lab stand-in | `bafybeig77gyxfd7lldgueo5qtn2o7sjvwdr6txm3f7fc4dl4pyjsuvgoc4` |
| `provider-variant-b` | `capsule.json`, `ipfs-provider` | `capsule.json` is `provider`'s, byte for byte; `ipfs-provider` is the ASCII `lab fixture x86_64-linux` and a newline, a lab stand-in | `bafybeieh6wqfmuqdn3nv7eu4vyd7j3tpxnt3mefzj2hmreumyazd4uzhr4` |
| recipe (not a fixture) | `recipes/provider-variant.recipe` | written for this lab: four lines of ASCII, a lab stand-in; named as one entry, `provider-variant.recipe` | `bafybeicgxv53aweiky6lfkoin7iqf5pc6eggehxv4fjnqmmwrfedyhskxm` |

`provider` and `model` are task 012's (see [three kinds](#three-kinds-share-the-package-rules)).
The two provider variants and the recipe are task 015's (see
[the variant binding](#lab-variant-binding-outside-the-bundles)); the recipe
lives in `recipes/`, outside `fixtures/`, so it is no bundle.
Their manifests are re-indented copies of the Runtime's test JSON, with the same
fields and values; the Runtime's own `CapsuleManifest` parses and validates
both. No provider binary, rootfs, Kubo, GGUF, model URL or model hash is
copied.

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

1. A claim that is not a lab CID is refused before the bundle is read, for
   example
   `the claim "BAFYBEIBC5…DQY7Q" is not a lab CID: a lab package CID is a 59-character CIDv1 bafybei... directory root`.
   A lab CID is `b` and base32 whose bytes are `01 70 12 20` and 32 bytes,
   and those bytes must print as exactly the claim. So a raw leaf's
   `bafkrei...` CID, the uppercase form, the root without its `b`, 58 or 60
   characters, the old `lab-cid:sha256:` and 64 hex form, a `Qm...` CIDv0, a
   `bafybei` text whose 8th character is outside `a`-`h` (its bytes do not
   start `01 70 12 20`), the right root with unused low bits set in its last
   character (a second spelling of the same bytes), a character outside the
   base32 alphabet, a trailing newline and the empty string are each refused
   this way, even when they carry the bundle's own root. The list is one
   function, `not_lab_cids()` in `tests/common/mod.rs`, which the parse and
   both name checks are tested on.
2. The name is recomputed from the bytes with `lab_cid`, the one naming path,
   and compared. A lab CID the bytes do not give is refused with both values:
   `bundle bytes name <actual>; the claim is <claimed>`.
3. `lab_cid`'s own refusals pass through unchanged, variant and text.
4. Success returns nothing, so a claim never comes back as a checked name. A
   refusal keeps the claimed text only to say what was refused.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| A wrong lab CID is refused with both values; a claim that is not a lab CID is refused as one, before any bundle is read | `claimed_name_is_checked_never_trusted` | F-CI3g (no comparison), F-CI3h (no `b`), F-CI3k (any CID bytes), F-CI3l (characters outside the alphabet dropped), F-CI3m (uppercase), F-CI3p (order), F-CI18l (no re-encode) |
| `lab_cid`'s refusals pass through | `check_name_preserves_lab_cid_refusals` | F-CI3n |
| `check_name` names the bundle only by calling `lab_cid` | `check_name_uses_the_single_naming_path` | F-CI3o |

There are no entries F-CI3e (leave `capsule.json` out of the name) and
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
- Since task 016 it also keeps, in a private field, whether the one manifest
  check found the manifest's `type` to be `wasm`. Only the variant binding's
  check (e2) reads it, and no accessor hands it out.
- The entries come in the walk's order. The encoder sorts each directory's
  links by name; a caller that needs an order sorts the entries by path.
- It lives in memory only. It has no file or serialized form, and nothing
  writes or stages its entries anywhere.

**The checked name check.** `checked.check_name(claimed)` is the checked form
of `check_name(bundle, claimed)`. Both run the one claim check (`b` and the
canonical base32 of `01 70 12 20` and a 32-byte root) and the one compare,
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

| `str::parse::<LabCid>(printed)` | the `LabCid` a printed lab CID names; otherwise `NotALabCid` (see [Reading a printed lab CID](#reading-a-printed-lab-cid)) |

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
| The checked form judges the bytes it holds; the path form reads the folder now | `checked_name_check_judges_the_checked_bytes` | F-CI3g, F-CI9h (no compare), F-CI9i (no `b`, its own reading), F-CI9j (walks again) |
| The checked form refuses a lab CID its bytes do not give | `checked_name_check_refuses_a_mismatch` | F-CI3g, F-CI9h |
| The checked form calls the one claim check and the one compare, and reads nothing | `checked_name_check_shares_the_claim_check_and_the_compare` | F-CI9h, F-CI9i, F-CI9j |

The tests are in `tests/checked_bundle.rs` unless the table names another
file. F-CI3g skips the one compare, so it lists the checked form's two tests
too: a checked form with a compare of its own would leave
`checked_name_check_refuses_a_mismatch` passing, and F-CI3g would not count.

## Reading a printed lab CID

`str::parse::<LabCid>()` is the one way to check a printed value's form and
read it back (`impl FromStr for LabCid`, task 013). It runs the same claim
check the two name checks make, `lab_cid_digits`, and keeps the root digest it
gives: the parse decodes nothing itself. Text the name checks refuse as not a
lab CID gets the same `Refusal::NotALabCid { claimed }`, with the same text. A
consumer calls it and never copies the base32 or the CID bytes.

- Parsing is not a name check. A parsed value names no bytes until
  `check_name` or `CheckedBundle::check_name` compares it with a bundle.
- A consumer that needs a well-formed synthetic value names synthetic entries
  with `encode_entries(&[BundleEntry { .. }])` and prints the result. It never
  writes the printed form by hand.
- The printed form changed when task 018 (the carry of blocked task 010)
  swapped it to the `bafybei...` root. Code that reads a printed value with
  this parse, and makes values with `encode_entries`, kept working unchanged.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| A printed lab CID parses back to the same value and prints the pin; two values never parse to one | `printed_lab_cid_parses_back_to_the_same_value` | F-CI13b (bytes reversed), F-CI13c (all zero) |
| The parse refuses each claim the name check refuses, with the same refusal and text | `parse_refuses_what_the_name_check_refuses` | F-CI13a |
| The parse calls the one claim check once and holds no copy of it | `parse_shares_the_one_claim_check` | F-CI13a |

The tests are in `tests/parse.rs`.

## For a lab that uses the lab CID

Three lab crates outside this lane have a path dependency on this crate. Each
manifest is listed below with what that crate uses: `pins` (its tests pin a
printed lab CID), `parse` (it reads a printed lab CID with `LabCid`'s parse, or
makes values with `encode_entries`), or `both`.

```text
lab/agent-conformance/Cargo.toml  parse
lab/wasm-capsule/Cargo.toml  both
lab/wasm-capsule/tools/Cargo.toml  pins
```

- `lab/agent-conformance` (cx-agent-conformance) reads `bundle_lab_cid` with
  `parse::<LabCid>()` (`src/report.rs`), makes its synthetic values with
  `encode_entries`, and names bundles with `checked_bundle`. It pins no lab
  CID.
- `lab/wasm-capsule` (wasm-capsule-lab), the `capsule` package, a
  dev-dependency: its tests pin two lab CIDs (`tests/common/mod.rs`,
  `tests/bundle.rs`) and parse a printed one (`tests/run.rs`).
- `lab/wasm-capsule/tools` (`wasm-capsule-tools`) names every lab bundle with
  `lab_cid` (re-exported as `bundle_identity`). The two pins above are of what
  it prints, so a change in what `lab_cid` prints reaches it through them.

Read at `b75ffefdb`. `every_lab_cid_consumer_is_in_the_adoption_note`
(`tests/adoption.rs`) keeps the list true, and it reads no TOML itself. It
lists every git-tracked `Cargo.toml` under `lab/`, at any depth, outside this
lane (`git ls-files`), and asks Cargo's own reader about each one:
`cargo metadata --no-deps --offline --format-version 1 --manifest-path <it>`,
run with the cargo that built the tests, from a fresh empty temp folder. From
its JSON (read with `serde_json`) it takes the package whose `manifest_path` is
that manifest, and keeps it when any dependency, of any kind (normal, dev or
build), has the package name `capsule-identity` and a `path` that resolves to
this lane's folder. So a quoted key and a `package = "capsule-identity"` rename
are found, and the same name with no path, or at another path, is not. A
manifest Cargo cannot read fails the test with the manifest and Cargo's own
message, and so do JSON that does not parse, no package for that manifest and a
path that does not resolve, each with its own reason. That set must equal the
list, both ways, and the failure names each path that is missing or extra. The
test also compares every scanned crate's folder, ignored files included, before
and after the scan: `--no-deps` writes no `Cargo.lock` and no `target/`. When
a lab crate adds a path dependency on this crate, this lane's tests fail until
the list names it.

**The pin rule.** A consumer's pin comes from its own `python3 -I` script,
written only from [the encoding](#the-encoding) and Python's standard library,
or from this README's block run as it is. The script is checked first on
`fixtures/content-sample/`, where it must print
`bafybeieahlroxjdalpmglh227eikmodrjhrlelvzlhylvyt3s65ackiybi`
(`CONTENT_SAMPLE_LAB_CID`), and on a one-byte change there, where it must
print a different value. Only then is it run on the consumer's bundle and
compared with the code's output for the same folder, and only then is the
value pinned. A pin is never copied from the code's output. A mismatch is a
`FINDING: lab CID mismatch` for this lane, cc-capsule-identity; the consumer
never edits its pin to fit the code.

**The change rule.** A task in this lane that changes what `lab_cid` prints,
what `LabCid` parses, or what `encode_entries` returns names one follow-up for
each consumer listed above, in its report and in this lane's BACKLOG, before
it merges.

**The example.** Task 018 (PR #226) changed what `lab_cid` prints from
`lab-cid:sha256:<hex>` to the 59-character `bafybei...` root. wasm-capsule-lab
pinned the old form, and its tests went red on the base until its task 024
(PR #231) recomputed its pins: one `python3 -I` script written only from this
README's rules and the standard library, kept under its git-ignored `target/`
and quoted in its LOG, checked on `content-sample` and on a one-byte change,
then compared with the code's output, and only then pinned.
agent-conformance needed no code change, because it parses with `LabCid` and
makes its values with `encode_entries`.

A pin is a lab CID, a lab package CID (see
[why a lab CID](#why-a-lab-cid-and-not-the-runtimes-cid)), not the Runtime's
CID. Adopting it is an identity check only: it adds no admission, grant or
launch step.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| The list is every lab crate with a path dependency on this crate, and only those; the scan changes no scanned crate's folder | `every_lab_cid_consumer_is_in_the_adoption_note` | F-CI25a (only `lab/*/Cargo.toml` is listed), F-CI25b (the name `capsule_identity`), F-CI25e (the heading the helper looks for) |
| Cargo's reader decides: a manifest it cannot read is refused with Cargo's message; a quoted key, a rename, a dev- and a build-dependency are found; no path, or another path, is not | `the_consumer_scan_uses_cargos_reader` | F-CI25b, F-CI25c (a non-zero cargo exit reads as no dependency), F-CI25d (a dependency with no path counts), F-CI25f (any path counts), F-CI25g (build-dependencies are dropped) |
| Cargo's JSON is read strictly: not JSON, no package for the manifest and a path that does not resolve are each refused with their own reason | `the_consumer_scan_refuses_bad_metadata` | F-CI25h (JSON that does not parse reads as no dependency), F-CI25i (no package for the manifest reads as no dependency), F-CI25j (a path that does not resolve reads as no dependency) |
| Cargo's JSON with no packages list is refused with that reason, never read as no dependency | `the_consumer_scan_refuses_bad_metadata` | F-CI27a (no packages list reads as no dependency) |
| A package with no `manifest_path` is refused with that reason, never read as no dependency | `the_consumer_scan_refuses_bad_metadata` | F-CI27b (no `manifest_path` reads as no dependency) |
| A package with no dependencies list is refused with that reason, never read as no dependency | `the_consumer_scan_refuses_bad_metadata` | F-CI27c (no dependencies list reads as no dependency) |
| A dev-dependency counts: `lab/wasm-capsule` uses this crate only under `[dev-dependencies]` | `the_consumer_scan_uses_cargos_reader`, `every_lab_cid_consumer_is_in_the_adoption_note` | F-CI27d (dev-dependencies are dropped, so `lab/wasm-capsule/Cargo.toml` is missing from the scan) |
| The scan writes nothing beside a manifest, ignored files included | `the_consumer_scan_writes_nothing` | F-CI25k (a `target/` is left beside a manifest outside the repo), F-CI25l (`--no-deps` is dropped, so Cargo resolves and writes a `Cargo.lock`) |
| The list is read strictly: a missing note, no list and a line it cannot read each fail with their reason | `the_adoption_list_is_read_strictly` | F-CI25m (a line it cannot read is skipped) |
| The note states the outside recomputation | `the_adoption_note_states_the_outside_recomputation` | F-CI25e |

## Test-key publisher signature (lab proposal)

A test key can sign a bundle's printed lab CID. The check answers only "did
this test key sign this lab CID?". It does not answer "may this run?".

**The message.** `name_signature_message` is SHA-256 over three parts, in
order:

1. the domain `lab.capsule-identity.name-signature/v1`
   (`NAME_SIGNATURE_DOMAIN`);
2. one `0x00` byte;
3. the UTF-8 bytes of the whole printed lab CID, its `b` included (the
   59-character `bafybei...` text).

That is the three-step digest in `domain_separated_sign`
(`elastos/crates/elastos-server/src/crypto.rs:88-128`): SHA-256 of
`domain || 0x00 || payload`, then Ed25519 over that digest. The form lives
only in the Runtime server. This lab does not link that crate, so it keeps
one marked copy, `domain_separated_digest(domain, payload)`, and calls the
copy a lab proposal. `name_signature_message` is that digest with the
name-signature domain; the package record (below) uses the same digest with
its own domain. Moving the form next to `decode_did_key` in
`elastos-identity` is a question for Anders. Signing and verifying both call
`name_signature_message`. Nothing else builds the message.

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

**Pinned message digest.** The block below is a second implementation of the
message: `name_digest(name)` takes a printed lab CID and returns the digest as
hex. For `content-sample`'s pinned lab CID,
`bafybeieahlroxjdalpmglh227eikmodrjhrlelvzlhylvyt3s65ackiybi`, it gives
`e04c241b58d424a79e9c4308dc611216890d528ee098646acef7a836dbf4fbb9`.

```python
import hashlib


def name_digest(name):
    return hashlib.sha256(
        b"lab.capsule-identity.name-signature/v1" + b"\x00" + name.encode()
    ).hexdigest()
```

`readme_python_matches_the_name_signature_digest`
(`tests/cross_implementation.rs`) runs this block as committed, with
`python3 -I`, on the printed lab CID of each of the seven pinned fixtures
(see [the cross-implementation check](#the-cross-implementation-check)). For
each, `name_digest` and the hex of `name_signature_message` must be equal, and
for `content-sample` both must be the pin above
(`CONTENT_SAMPLE_NAME_DIGEST` in `tests/common/mod.rs`). A short driver
(`NAME_DIGEST_DRIVER`) reads the CID from stdin and calls `name_digest`; the
test checks that the driver holds no hash, domain or function of its own.

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
| Both wrappers keep the walk's refusal, including bad signature inputs | `signature_paths_preserve_walk_refusals` | F-CI4o, F-CI4p, F-CI4q, F-CI4r |
| The walk's refusal precedes a bad signature from a canonical accepted signer | `signature_walk_refusal_precedes_bad_signature` | F-CI4s |
| Two faults at once: the earlier check answers | `signature_refusal_order_is_stable` | F-CI4t, F-CI4u, F-CI4v |
| One message, one verification, and the path form holds no check of its own | `signature_paths_share_one_implementation` | F-CI4w, F-CI4x |
| Test keys come from the operating system's generator, never from fixed or raw key bytes | `test_keys_use_fresh_os_randomness` | F-CI4y, F-CI14c |
| No key material is in what git would stage | `no_key_material_is_tracked` | F-CI4i |
| Private-key header lines are found even when a file has invalid UTF-8 | `key_material_scan_finds_headers_in_non_utf8_files` | F-CI4z |
| `*.key` and `*.seed` are ignored | `key_and_seed_files_are_ignored_by_git` | F-CI4h |
| README's `name_digest` gives `name_signature_message`'s digest for every pinned fixture, and the pin for `content-sample` | `readme_python_matches_the_name_signature_digest` (`tests/cross_implementation.rs`) | F-CI20a, F-CI20d, F-CI20e, F-CI19d |

The tests are in `tests/name_signature.rs`. The key-material scan they call
(`key_material_findings`) is in `tests/common/mod.rs`, a file the runner
restores after a killed run, so F-CI4z's edit cannot outlive its run.
`test_keys_use_fresh_os_randomness` bans, in every `.rs` file of the lane,
`SigningKey::from_bytes`, `from_seed`, `from_keypair_bytes`,
`StdRng::from_seed`, `SigningKey::from(` and `SecretKey`, so a key made from
fixed bytes (such as a constant array) fails it. F-CI4h drops `*.seed` from this
lane's `.gitignore`. F-CI4i appends a private-key header line to this file.
Neither file is in the runner's recovery list
(`examples/agent-host/falsify.py`, `PROVIDER_TARGETS`). The runner still runs
them. The provider lane adds those two recovery lines after this task merges.

## Verify is not admit (M1 check B1)

The rule: a valid signature grants nothing by itself. A bundle whose test-key
signature verifies is still not admitted, and it gets no grant. This library
checks identity only, and it sits in no admission or launch path.

What the tests show, on the `agent-host` fixture. Its manifest asks for a grant
through `capabilities`, and it has its `asks.json`. A fresh in-memory test key
signs it:

- The signature is valid: `verify_name_signature` returns `Ok(())` when that
  key's DID is accepted.
- After signing, and again after verifying, the bundle's lab CID is still
  `bafybeices…hatym`, and the parent folder still holds only the bundle folder.
  So no byte the lab CID covers changed, and no file appeared next to the
  bundle. The tests compare before and after. They cannot see a file that
  was written and then removed in between.
- After verifying, the bundle's `capsule.json`, parsed with the Runtime's own
  `CapsuleManifest`, still has no `signature`. So no lab signature reaches
  the field the Runtime's own capsule check reads
  (`elastos/crates/elastos-runtime/src/signature/verifier.rs:79-83`).
- Each check stands alone. Right after that success, the same signature is
  refused with an empty accepted list, and with a list that holds only
  another fresh key's DID. Both refusals give the accepted-list reason. A
  success leaves no standing approval.
- The library's public functions are exactly the identity checks: `lab_cid`,
  `lab_cid_observed`, `checked_bundle`, `checked_bundle_observed`,
  `check_name` and its checked form `CheckedBundle::check_name`,
  `CheckedBundle::cid`, `CheckedBundle::entries`, `encode_entries`,
  `entry_kind`, `entry_path`, `name_signature_message`, `sign_bundle`,
  `verify_checked_signature` and `verify_name_signature`, and task 011's
  package record: `domain_separated_digest`,
  `PackageRecord::package_record_payload`, `sign_package_record`,
  `verify_checked_package_record` and `verify_package_record`. Each answers
  "do these bytes match this name" or "did this key sign this name or this
  record". None takes
  or returns a grant, an admission or a launch value. A test keeps the list:
  a new public function fails it until someone lists it on purpose. The test
  reads the declaration after every `pub` word token by token, across line
  breaks, so it also reads a function declared with any of `async`, `const`,
  `unsafe` or `extern` (with or without an ABI string) before `fn`, in any
  order and split over any lines. A `pub(crate)` or `pub(super)` function is
  not exported, so it is not counted. A `pub` declaration the test cannot read
  fails it with its own reason; it is never skipped.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| A valid signature verifies, and signing and verifying change no covered byte, add no entry next to the bundle, and leave no lab signature in `capsule.json`; a success approves nothing for the next check | `valid_signature_grants_nothing_by_itself` | F-CI7a, F-CI7b, F-CI7c |
| The library exports only identity checks | `the_harness_exports_only_identity_checks` | F-CI7d, F-CI14a, F-CI14b, F-CI14d, F-CI14e |
| The export check reads `async`, `const`, `unsafe` and `extern` functions split over any lines, and not `pub(crate)` or `pub(super)` ones | `every_exported_function_form_is_read` | by hand (see below) |
| The export check refuses a `pub` declaration it cannot read, each with its own reason | `an_unreadable_pub_declaration_is_refused_with_its_reason` | by hand (see below) |

The tests are in `tests/not_admission.rs`. F-CI7a makes `sign_bundle` write
the signature's hex into `capsule.json`'s `signature` field, the way the
Runtime's own signer fills that field (`verifier.rs:139-150`). F-CI7b makes a
successful verify write `<bundle>.admitted`. F-CI7c makes verify remember each
name and signer it passed, and pass them again with no accepted-list check.
F-CI7d adds a public `admit` step. F-CI14a adds `pub async fn admit() {}` and
F-CI14b adds `pub const fn grant() {}`; before task 014 the export check read
only lines that start with `pub fn `, so both passed it. F-CI14d adds
`pub async` and `fn admit() {}` on two lines (under `#[rustfmt::skip]`, so
rustfmt keeps them split); a check that read one line at a time passed it.
F-CI14e adds `pub struct Opaque(pub u8);`, whose `pub u8` the check cannot
read, so the test fails with "`pub u8` is not a declaration this check
reads" instead of skipping it. The reader (`token`, `declared_after_pub`,
`exported_functions`) sits in `tests/not_admission.rs`, which the runner does
not restore, so its falsifiers are proved by hand only. With `"unsafe"`
dropped from its qualifiers, `every_exported_function_form_is_read` fails on
`pub unsafe fn launch()`. With `token` skipping only spaces, not line breaks,
it fails on `pub async` and `fn admit() {}` split over two lines. With the end
of the code read as no item, `an_unreadable_pub_declaration_is_refused_with_its_reason`
fails on `pub`.

What the tests cannot show. Admission and grants are the Runtime's, not this
lab's. PRINCIPLES.md 13 (lines 134-135): "admission is a separate decision
made under each Runtime's trust policy". PRINCIPLES.md 8 (lines 88-91):
"every operation still requires its Runtime-verified capability". The
manifest's `capabilities` are only upper bounds that the Runtime may
authorize (`CapsuleManifest::resource_authority_bounds`,
`elastos/crates/elastos-common/src/manifest.rs:418-429`). Moving grant
decisions into Runtime policy is Runtime issue 464,
https://github.com/Elacity/elastos-runtime/issues/464. So these tests say
nothing about what the Runtime would decide. They do not run the Runtime, and
they model no admission or grant, not even in a test.

Claim scope: one Mac, these fixtures, test keys only.

## Lab package record (outside the bundle)

Anders's answer splits the package CID from the publisher. The CID names
the bytes. A separate signed record names the signer and binds that CID.
`PackageRecord` is that record, in the lab. It stays outside the bundle.

**The record.** `PackageRecord` has three fields: `cid` (the printed lab
CID, exactly as `LabCid`'s `Display` prints it), `signer_did` (a canonical
Ed25519 `did:key`) and a 64-byte `signature`. Like `NameSignature`, it has
no serde derive and no file form. Nothing writes it to disk.

**The payload.** `package_record_payload` is the only builder of the signed
bytes. They are compact JSON, keys in this order, no spaces and no trailing
newline:

```
{"cid":"<printed CID>","schema":"lab.capsule-identity.record/v1","signer_did":"<did:key>"}
```

The schema is `lab.capsule-identity.record/v1` (`PACKAGE_RECORD_SCHEMA`). It
is the lab's own name, not the Runtime's `elastos.capsule.record/v1`. The
signature is not a field of the payload. There is no name field. So the
record binds a CID and never a capsule name, and a grant or a token built on
it would bind a CID too, not a name.

**The digest.** The signature is Ed25519 over
`domain_separated_digest("lab.capsule-identity.package-record/v1", payload)`
(`PACKAGE_RECORD_DOMAIN`): SHA-256 of the domain, one `0x00` byte and the
payload. It is the same one digest function the name signature uses, under
another domain, so a name signature can never pass as a record. The domain
and the schema both carry `/v1`, so a later encoding gets a new version, not
a silent change. The block below is a second implementation of the
encoding: `record_payload(cid, did)` returns the payload's bytes as hex, and
`record_digest(cid, did)` returns the digest as hex.

```python
import hashlib


def record_payload(cid, did):
    return ('{"cid":"%s","schema":"lab.capsule-identity.record/v1","signer_did":"%s"}' % (cid, did)).encode().hex()


def record_digest(cid, did):
    payload = bytes.fromhex(record_payload(cid, did))
    return hashlib.sha256(b"lab.capsule-identity.package-record/v1" + b"\x00" + payload).hexdigest()
```

`readme_python_matches_the_package_record_bytes`
(`tests/cross_implementation.rs`) runs this block as committed, with
`python3 -I`. A fresh test key signs a record for `content-sample` and one for
`web-app`, and each record's `cid` and `signer_did` go to Python as JSON on
stdin; no key byte leaves Rust. For each record, `record_payload` must equal
`package_record_payload` byte for byte, `record_digest` must equal
`domain_separated_digest(PACKAGE_RECORD_DOMAIN, payload)`, and the record's
signature must verify, in Rust, over Python's digest. A short driver
(`RECORD_DRIVER`) calls the two functions; the test checks that it holds no
hash, domain, schema, JSON layout or function of its own.

**Sign.** `sign_package_record(key, bundle)` names the bundle with `lab_cid`.
A refusal from that walk passes through unchanged, and a refused bundle gets
no record. It sets `signer_did` with the one DID encoder
(`elastos_identity::encode_signing_key_did`, the same call `sign_bundle`
uses) and signs the digest above. It writes no file and changes no bundle
byte. The manifest's `signature` field stays empty.

**Verify.** `verify_checked_package_record(checked, record, accepted)` checks
009's `CheckedBundle` in this order. The first refusal is the answer, and it
reads nothing from disk:

1. Decode `record.signer_did` with the one DID decoder. On error: `signer DID <did> is not a canonical Ed25519 did:key: <the decoder's own text>`.
2. The DID is an exact member of `accepted`, the explicit list (no trust
   policy). An empty list refuses every signer: `signer <did> is not in the
   accepted list`.
3. `record.cid` equals `checked.cid()`'s printed form. Otherwise: `record
   names <record cid>; the bundle names <bundle cid>`.
4. Ed25519 over the digest of the record domain and
   `package_record_payload(record)`, with the key from step 1. On failure:
   `signature by <did> does not verify over <record cid>`.

Steps 1, 2 and 4 are the name signature's own checks and reasons, from the
same functions (`decode_signer`, `require_accepted` and one shared Ed25519
check). Step 3 runs before step 4, so when the payload is hashed its CID is a
printed lab CID and its DID is canonical: neither holds a character JSON
would escape. `verify_package_record(bundle, record, accepted)` is
`checked_bundle(bundle)` and then the checked form. It holds no check of its
own, so a bundle the walk refuses is refused first, with the walk's reason.
`Ok(())` grants nothing: it is no trust, admission or launch value.

**What stays.** `NameSignature`, `sign_bundle`, `verify_checked_signature`
and `verify_name_signature` stay as they are: the in-memory name signature
that wasm-capsule-lab already calls. The record is the outside encoding. It is
not a second crypto stack: one digest, one DID encoder, one DID decoder, one
accepted-list check and one Ed25519 verification serve both.

**What it does not do.** No key rotation, no delegation, no publisher policy
beyond the explicit accepted list. Publisher rotation and delegation are the
Runtime's, issue 213 (https://github.com/Elacity/elastos-runtime/issues/213).
Grants are the Runtime's, issue 464
(https://github.com/Elacity/elastos-runtime/issues/464). One record signs
one closure, the one bundle its CID names: signing each capsule's whole
closure is issue 465 (https://github.com/Elacity/elastos-runtime/issues/465),
and each capsule being signed on its own is issue 274
(https://github.com/Elacity/elastos-runtime/issues/274). No record groups
several CIDs.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| The record binds the fixture's pinned CID, its payload is the rule's exact JSON, and both verifiers pass | `package_record_binds_the_cid_and_verifies` | F-CI11a, F-CI11f |
| Signing and both verifiers leave the lab CID, `capsule.json`, the parent folder and the manifest's `signature` as they were | `package_record_stays_outside_the_bundle` | F-CI11e |
| A record signed under the name-signature domain is refused; the same bytes under the record domain verify | `record_signed_under_the_wrong_domain_is_refused` | F-CI11b, F-CI11s, F-CI11x |
| A record rebound to another CID is refused naming both CIDs | `record_rebound_to_another_cid_is_refused` | F-CI11c, F-CI11r |
| Another key's signature, an unlisted signer and an empty list are refused | `record_by_another_signer_is_refused` | F-CI11d, F-CI11q |
| The checked form judges the bytes it holds; the path form reads the folder now | `checked_record_judges_the_checked_bytes` | F-CI11c |
| A malformed DID is refused with the decoder's text, even when listed | `record_malformed_signer_did_is_refused` | F-CI11g, F-CI11p |
| Two faults at once: the earlier check answers | `record_refusal_order_is_stable` | F-CI11h, F-CI11i, F-CI11j |
| Signing and the path verifier keep the walk's refusal, whatever the record | `record_paths_preserve_walk_refusals` | F-CI11k, F-CI11l, F-CI11m, F-CI11n, F-CI11o |
| One payload builder, one digest, one DID encoder and decoder, one Ed25519 check; the path form holds no check of its own | `record_paths_share_one_implementation` | F-CI11t, F-CI11u, F-CI11v, F-CI11w |
| README's `record_payload` and `record_digest` give `package_record_payload`'s bytes and the signed digest for test-key records over `content-sample` and `web-app` | `readme_python_matches_the_package_record_bytes` (`tests/cross_implementation.rs`) | F-CI20a, F-CI20b, F-CI20c, F-CI20f, F-CI19d |

The tests are in `tests/package_record.rs`. Every refusal test runs both
verifiers, so a check that lives only in the path form fails it (F-CI11p to
F-CI11s move one check each into the path form). Every expected CID comes
from the pins in `tests/common/mod.rs`, never from a literal, so a change of
the printed form changes the pins in one place. The domains in these tests
are written out, not read from the library, so a changed domain constant
fails them (F-CI11x). F-CI11u, F-CI11v and F-CI11w also fail 004's
`signature_paths_share_one_implementation`.

Claim scope: one Mac, these fixtures, test keys only.

## Three kinds share the package rules

Anders's Q10 asks whether the package rules hold for more than one capsule
kind. Task 012 tries them on three small kinds: an app (`web-app`, a
web-projection app: role `app`, type `web-projection`), a provider
(`provider`: role `provider`, type `microvm`) and a model (`model`: role
`content`, type `data`, with `model_content`).

- **One CID rule.** All three are named by the one `lab_cid`, with the byte
  rule [above](#the-encoding). Renaming a bundle's folder keeps its CID. One
  byte changed in a payload file (`browser/app.js`, `ipfs-provider`,
  `weights.gguf`) changes it, and `check_name` with the old pin is refused
  with both values.
- **One record.** Task 011's `sign_package_record` and `verify_package_record`
  serve all three the same way. The record is signed over the committed bytes,
  before any change, so its CID is the fixture's pin. Signing and verifying
  leave the bundle's bytes and its parent's listing as they were, and the
  record still verifies after the folder is renamed. No kind gets its own
  encoder or its own record builder.
- **Lab stand-ins, never launched.** `ipfs-provider` is not a provider
  binary, and `weights.gguf`, `LICENSE`, `LICENSE.base` and `PROVENANCE.md`
  are not a model, its licenses or its provenance. Nothing here launches,
  loads or admits them. The test holds them tiny: each manifest at most 1024
  bytes, each provider and model stand-in at most 64 bytes, and every
  web-app file at most 1024 bytes. No file is big enough to chunk or shard.
- **A WASM app here has one closure.** `wc001-core` (role `app`, type
  `wasm`) is the WASM app. Its committed fixture is the manifest alone: its
  entrypoint `capsule.wasm` is built separately by wc-001's `tools/build` in
  each test and never committed. `web-app` is one closure too: its manifest
  and its two `browser/` files. No fixture has a second `capsule.json`, a
  second file named like its entrypoint, or a path part or entrypoint that
  names a platform (an architecture or an OS word, such as `aarch64-darwin`).
  The test reads the fixture tree; it defines no variant type.
- **A name is not the identity.** The CID covers the manifest's `name` as
  bytes and nothing more. The record has no name field (see
  [the lab package record](#lab-package-record-outside-the-bundle)), so a
  grant or a token built on it would bind the CID, never the manifest's
  `name`.
- **Not defined here.** This task does not define a shared capsule identity
  across kinds or across platform variants; that phrase is still undefined.
  Variant bindings are task 015's (see
  [the variant binding](#lab-variant-binding-outside-the-bundles)).

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| App, provider and model: the folder name does not change the CID, one payload byte does and the old pin is refused with both values, a fresh key's record binds the pin and verifies, and signing changes no byte and no listing | `three_kinds_share_the_package_rules` | F-CI1l, F-CI12a |
| A WASM app has one closure: one manifest per fixture, no platform directory or platform entrypoint, no second entrypoint | `a_wasm_app_has_one_closure` | F-CI12b |
| The provider and model pins | `lab_cid_matches_the_pinned_value_for_each_fixture` (`tests/fixtures.rs`) | F-CI1l, F-CI12a |

The first two tests are in `tests/kinds.rs`. F-CI12a leaves `weights.gguf`
out of the name while the walk still reads it. F-CI1l (name only the
manifest and the entrypoint) does not drop `weights.gguf`, because that is
the model's entrypoint, so F-CI12a is a different edit, not a second entry
for one edit. F-CI1l also names `three_kinds_share_the_package_rules`, which
it fails on `web-app`'s pin. F-CI12b turns `wc001-core`'s entrypoint into
`aarch64-darwin/capsule.wasm`, in a file the runner restores. The runner
cannot add a file, so a platform folder added to the fixture tree is proved
by hand only: with `fixtures/web-app/aarch64-darwin/app.js` added,
`a_wasm_app_has_one_closure` fails with `web-app: aarch64-darwin names a
platform variant`, and with a copy of `capsule.json` in `browser/`, it fails
on the manifest list.

Claim scope: one Mac, these three fixtures. It is not a claim for every
capsule kind.

## Lab variant binding (outside the bundles)

Anders's Q4 asks for one closure per platform variant, and an authenticated
binding that groups the variant CIDs, with a pinned build recipe (issue 285,
https://github.com/Elacity/elastos-runtime/issues/285). Task 015 builds that
binding in the lab. It is the lab's own proposal, not the Runtime's format.

**The variants.** `provider-variant-a` and `provider-variant-b` are two
bundles, each its own closure with its own lab CID. Both hold `provider`'s
`capsule.json`, byte for byte, and one stand-in `ipfs-provider` whose bytes
differ (`lab fixture aarch64-darwin` and `lab fixture x86_64-linux`, each
with a newline), so their CIDs differ. Each variant is still signed as its
own closure, with its own package record (see
[the lab package record](#lab-package-record-outside-the-bundle); issue 465,
https://github.com/Elacity/elastos-runtime/issues/465). The binding adds to
those records and replaces none.

**The platform label lives only in the binding.** `CapsuleManifest` has no
platform field, and the lab adds none. No manifest, folder name or path holds
a platform label, so 012's `a_wasm_app_has_one_closure` still passes as it
was. (The stand-ins' bytes hold the words, only so the two CIDs differ: that
is payload content, not platform metadata.) The labels are the three the
Runtime's release script uses, `aarch64-darwin`, `aarch64-linux` and
`x86_64-linux` (`scripts/publish-release.sh:1629-1631`), and, since task 016,
the portable label `*` (`PORTABLE_PLATFORM`); the Runtime's own record keeps
one `platform` per archive
(`elastos/crates/elastos-server/src/capsule_record.rs:27`) and writes `"*"` for
a capsule that is not per platform (`capsule_record.rs:582`). The lab reads
both, edits neither, and does not use the Runtime's schema name. A label is
not identity: each variant is named by its complete bundle CID (PRINCIPLES 13).

**A label is the signer's claim.** The lab does not check that a variant's
bytes were built for its label. It never reads a label from a manifest, path
or payload: the signer asserts it, and the pinned recipe (issue 285,
https://github.com/Elacity/elastos-runtime/issues/285) stands in for the
build that would back it. So `provider-variant-a`, whose payload says
`aarch64-darwin`, verifies under `x86_64-linux` if the signer bound it there
(`a_variant_label_is_the_signers_claim`, task 017). That test pins a limit,
not a feature.

**The recipe.** `recipes/provider-variant.recipe` is a few lines of ASCII
that say which fixture files make each variant. It is a lab stand-in, not a
build recipe: the lab never runs it, and it holds no build command, URL or
hash. It sits outside `fixtures/`, so it is no bundle. Its lab CID is the one
encoder, `encode_entries`, over one entry with the path
`provider-variant.recipe` (`VARIANT_RECIPE_ENTRY`) and the file's bytes,
printed by `LabCid`'s `Display`: the same encoder, not a second naming rule.
The library never reads the recipe from disk; the caller gives its bytes.

**The binding.** `VariantBinding` has four fields: `recipe` (the recipe's
printed lab CID), `variants` (the `(platform, cid)` pairs, in the order
signing was given them), `signer_did` (a canonical Ed25519 `did:key`) and a
64-byte `signature`. Like `PackageRecord`, it has no serde derive and no file
form. Nothing writes it. It has no name and no group identity field.

**The payload.** `variant_binding_payload` is the only builder of the signed
bytes, and the one place the pairs are sorted. They are compact JSON, keys in
this order, no spaces and no trailing newline, the variants sorted by
platform label in byte order:

```
{"recipe":"<printed CID>","schema":"lab.capsule-identity.variant-binding/v1","signer_did":"<did:key>","variants":[{"cid":"<printed CID>","platform":"<label>"},...]}
```

The schema is `lab.capsule-identity.variant-binding/v1`
(`VARIANT_BINDING_SCHEMA`). The signature is not a field. So the order the
pairs are given in never changes the bytes. For the test's binding (a under
`aarch64-darwin`, b under `x86_64-linux`), with the signer's DID written in:

```
{"recipe":"bafybeicgxv53aweiky6lfkoin7iqf5pc6eggehxv4fjnqmmwrfedyhskxm","schema":"lab.capsule-identity.variant-binding/v1","signer_did":"<the signer's did:key>","variants":[{"cid":"bafybeig77gyxfd7lldgueo5qtn2o7sjvwdr6txm3f7fc4dl4pyjsuvgoc4","platform":"aarch64-darwin"},{"cid":"bafybeieh6wqfmuqdn3nv7eu4vyd7j3tpxnt3mefzj2hmreumyazd4uzhr4","platform":"x86_64-linux"}]}
```

**The digest.** The signature is Ed25519 over
`domain_separated_digest("lab.capsule-identity.variant-binding/v1", payload)`
(`VARIANT_BINDING_DOMAIN`), the same one digest function the name signature
and the record use, under its own domain. So a record or a name signature
never passes as a binding.

**Sign.** `sign_variant_binding(key, variants, recipe)` takes the bundles as
`(platform, path)` pairs and the recipe's bytes. It first refuses the shapes
verification refuses (check (c) below, for the `given` list). Then it checks
each bundle with `checked_bundle`, the one walk, which gives both the
bundle's lab CID and whether its manifest `type` is `wasm`; a refusal from
that walk passes through unchanged, and a refused bundle gets no binding.
Then it refuses what check (e2) below refuses, with the same function
(`require_portable_wasm`). It names the recipe as above, sets `signer_did`
with the one DID encoder and signs the digest. It writes no file and changes
no bundle byte.

**Verify.** `verify_checked_variant_binding(binding, variants, recipe,
accepted)` takes `(platform, &CheckedBundle)` pairs. It checks in this order;
the first refusal is the answer, and it reads nothing from disk:

1. (a) Decode `binding.signer_did` with the one DID decoder. On error: `signer DID <did> is not a canonical Ed25519 did:key: <the decoder's own text>`.
2. (b) The DID is an exact member of `accepted`, the explicit list. An empty
   list refuses every signer: `signer <did> is not in the accepted list`.
3. (c) The shape of the binding's own pairs (`binding`), then of the pairs
   given (`given`). Each list holds at least one variant: `the <list>
   variant list is empty: a binding holds at least one variant`. Every label
   is one of the four: `the <list> variant list holds the platform
   "<label>", which is not one of *, aarch64-darwin, aarch64-linux,
   x86_64-linux`. No label is there twice: `the <list> variant list holds
   the platform <label> twice: one CID per platform`. The portable label
   stands alone: a list that holds `*` and another label is refused naming
   all its labels, sorted: `the <list> variant list holds the labels
   [<sorted labels>]: the portable label * stands alone`.
4. (d) The given platforms are the binding's: `the binding holds the
   platforms [<sorted labels>]; the given variants are [<sorted labels>]`.
5. (e) Each given bundle, taken in label byte order, has the printed CID the
   binding names for its label: `the binding names <binding cid> for
   <label>; the bundle given for <label> names <bundle cid>`.
6. (e2) A given bundle whose manifest `type` is `wasm` is bound only under
   `*`. Of the bundles under another label, the first in label byte order is
   refused: `the bundle <bundle cid> is a WASM app bound under <label>: a
   WASM app has one portable variant, bound under *`.
7. (f) The recipe bytes' lab CID is the binding's: `the binding names the
   recipe <binding cid>; the recipe bytes name <recipe cid>`.
8. (g) Ed25519 over the digest of the binding domain and the payload, with
   the key from step 1: `signature by <did> does not verify over <payload>`.
   The signed name in this shared reason is the whole payload, as text.

Steps (a), (b) and (g) are the name signature's own checks and reasons, from
the same functions (`decode_signer`, `require_accepted` and the one shared
Ed25519 check). Steps (c) to (f) run before (g), so when the payload is
hashed, every label is a known one, every CID equals a printed lab CID and
the DID is canonical: none holds a character JSON would escape.
`verify_variant_binding(binding, variants, recipe, accepted)` takes
`(platform, path)` pairs. It is `checked_bundle` for each path, in the order
given, and then the checked form. It holds no check of its own, so a bundle
the walk refuses is refused first, with the walk's reason. `Ok(())` grants
nothing: it is no trust, admission or launch value.

**A WASM app has one variant (task 016).** Rong's 26 Oct note says a WASM
app gets exactly one variant. `*` is the portable label, and it stands alone
in a binding (check (c)). A bundle whose manifest `type` is `wasm` is bound
only under `*` (check (e2), and signing refuses the same with the same
function). So a WASM app has one variant and one CID, and can never get a
second, platform-specific CID through a binding (PRINCIPLES 13). The rule
keys on the manifest type, not on the label: a `type: data` bundle such as
`content-sample` binds under `*` or under a platform label. Whether a bundle
is `wasm` comes from the one manifest check: `check_manifest` returns it
from its one `CapsuleManifest` parse, and the walk keeps it in the
`CheckedBundle` it makes. Nothing else parses `capsule.json` (P10). The
payload bytes, the schema and the domain are 015's: `*` is written into the
payload like any other label. Only "`*` for `wasm`" is a rule; other capsule
types get no rule here.

**What it does not do.** The binding groups CIDs. It defines no shared
capsule identity: Rong's 26 Oct note says that phrase is still undefined, so
the lab does not define it. It holds no group name, and no grant, token,
admission, launch, rotation or delegation. It runs no build.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| a under `aarch64-darwin` and b under `x86_64-linux`: the payload is the JSON the test formats from the pins, both verifiers pass, the two CIDs differ, and each variant's own record verifies on its own bundle only | `variant_binding_binds_each_variant_cid_and_verifies` | F-CI15g, F-CI15i, F-CI15ae |
| The pairs in either order give the same payload | `variant_binding_payload_ignores_input_order` | F-CI15d |
| b's bundle given as `aarch64-darwin` is refused naming the label and both CIDs | `variant_swapped_between_platforms_is_refused` | F-CI15a |
| Only a given, or a third label added, is refused naming both lists | `variant_missing_or_extra_is_refused` | F-CI15b |
| No variant, `darwin-arm64`, and one label twice: each its own reason, at signing, in the given list and in the binding's list | `variant_binding_shape_is_refused` | F-CI15e, F-CI15f, F-CI15k, F-CI15l, F-CI15m |
| One changed recipe byte is refused naming both CIDs | `variant_binding_recipe_is_pinned` | F-CI15c |
| A binding signed under the record domain is refused with the signature reason | `variant_binding_signed_under_another_domain_is_refused` | F-CI15g |
| The signer signs the literal domain's digest of the test's own payload | `variant_binding_signature_uses_its_domain` | F-CI15ad |
| Key B's signature with A's DID, B's DID with only A accepted, and an empty list are refused | `variant_binding_by_another_signer_is_refused` | F-CI15h, F-CI15o |
| A malformed DID is refused with the decoder's text, even when listed | `variant_binding_malformed_signer_did_is_refused` | F-CI15n |
| Two faults at once, at each pair of adjacent checks: the earlier check answers | `variant_binding_refusal_order_is_stable` | F-CI15p to F-CI15u |
| Signing and the path verifier keep the walk's refusal, whatever the binding, the list or the recipe | `variant_binding_paths_preserve_walk_refusals` | F-CI15v, F-CI15w, F-CI15x |
| Signing and both verifiers leave each bundle's lab CID, `capsule.json`, its listing and the parent folder as they were | `variant_binding_stays_outside_the_bundles` | F-CI15j |
| The payload's keys are `recipe`, `schema`, `signer_did` and `variants`, each variant's `cid` and `platform`, and nothing names a group | `variant_binding_has_no_group_name` | F-CI15i |
| One payload builder, one sort, one shape rule, one recipe naming call, the shared digest, DID encoder and decoder and Ed25519 check; the path form holds no check of its own; signing walks each bundle once with `checked_bundle` and runs check (e2) with the one shared function | `variant_binding_paths_share_one_implementation` | F-CI15y, F-CI15z, F-CI15aa, F-CI15ab, F-CI15ac, F-CI15af, F-CI16e |
| `agent-host` (`type: wasm`) alone under `*`: signing and both verifiers pass, and its CID is the pin | `a_wasm_app_binds_one_portable_variant` | F-CI16i |
| `agent-host` under `aarch64-darwin` is refused with reason (e2), at signing and in both verifiers | `a_wasm_app_under_a_platform_label_is_refused` | F-CI16a, F-CI16h |
| `*` with `x86_64-linux` is refused with reason (c), at signing, in the given list and in the binding's list; `*` alone passes | `the_portable_label_stands_alone` | F-CI16b, F-CI16i |
| `content-sample` (`type: data`) binds under `*` and under `aarch64-darwin`: the rule keys on the manifest type | `a_portable_data_capsule_binds_under_the_portable_label` | F-CI16c |
| The WASM type comes from the one `CapsuleManifest` parse in `check_manifest`, kept by the seam | `wasm_type_comes_from_the_one_manifest_check` | F-CI16d |
| Two faults at once, at (e2) and each check next to it ((e), (f), (g)): the earlier check answers | `wasm_variant_refusal_order_is_stable` | F-CI16f, F-CI16g |
| A limit, not a feature: a signed under `x86_64-linux` and b under `aarch64-darwin`, against the words in their payloads, pass both verifiers with the pinned CIDs | `a_variant_label_is_the_signers_claim` | F-CI17a |

The tests are in `tests/variant_binding.rs`. Every refusal test runs both
verifiers and checks the refusal's value and its exact text. Every expected
CID comes from the pins in `tests/common/mod.rs`, never from a literal, so
the later UnixFS swap (BACKLOG ci-10b) changes pins in one place. The domains
and the expected payload are written out in the test, not read from the
library. Test keys come only from `fresh_signing_key()`.

Three older shape tests count calls across the whole library, so they now
count the binding's too, and still refuse a second copy: 003's
`check_name_uses_the_single_naming_path` allows a third `encode_entries(`
call, the one in `recipe_cid`, and checks that it is there; 011's
`record_paths_share_one_implementation` counts each JSON key once in each of
the two payload builders, and one more call each of the shared digest, DID
encoder and Ed25519 check, each in its one place; 007's export list gains the
binding's payload, signer and two verifiers (24 identity functions).
F-CI15y, F-CI15z, F-CI15aa, F-CI15ab and F-CI15af also fail those older
tests.

Task 016 changed two of 015's tests, as its spec check allowed. The
unknown-label text now lists `*` too, so `variant_binding_shape_is_refused`'s
expected text gains it. `variant_binding_paths_share_one_implementation` now
asks signing for one `checked_bundle(` call (it asked for one `lab_cid(` and
forbade `checked_bundle`) and one `require_portable_wasm(` call, and asks the
checked form for that call between check (e) and check (f).
`a_portable_data_capsule_binds_under_the_portable_label` uses the committed
provider recipe only as recipe bytes: the binding checks their CID, nothing
else.

Claim scope: one Mac, these two variant fixtures and this recipe, test keys
only. It is not a claim about real binaries, real builds or the Runtime's
release records.

## Why a lab CID and not the Runtime's CID

The Runtime names a published capsule by the CID its IPFS provider returns when
it imports the capsule's archive. `elastos/crates/elastos-server/src/publish.rs:366-385`
imports each artifact (`preflight.import_file`) and requires the returned CID to
equal the artifact's signed pin (`require_import_cid`). The per-capsule record
`elastos.capsule.record/v1` names that archive's `sha256`, `size` and `cid`
(`elastos/crates/elastos-server/src/capsule_record.rs:1-4` and `:24-34`). The
archive is a gzip PAX tar made by `create_capsule_tar`
(`scripts/publish-release.sh:621-655`): it holds the capsule folder's name,
folder entries, normalized modes and symbolic links. Lines read at
`c6709039d`; they are the same at `1e5f33d34`. The archive's hash and CID are
a delivery check of those archive bytes, not this CID.

This harness names the bundle's own files instead: the CIDv1 SHA-256 UnixFS
directory root of the model package profile (Anders's answer, Q3; see
[the encoding](#the-encoding)), over the regular files alone. Modes, mtimes,
owners, the folder's name and symlink targets stay outside it, and a symlink
is refused by the walk, never named as a UnixFS symlink. So its value never
equals the archive's CID, and it does not try to reproduce it. It is printed
as the `bafybei...` text and called "lab CID" (a lab package CID) in code,
output and docs. It is a prototype, not an admission: no Runtime code reads
it, and it defines no shared capsule identity. Rong's DR-1 put the swap from
the old framed `lab-cid:sha256:` value inside the one `lab_cid` path, so no
second identity scheme sits beside it (task 018, the carry of blocked task
010).

## Claim scope

One Mac, these fixtures: macOS 26.5.2 on arm64 (APFS), rustc 1.91.0
(f8297e351 2025-10-28). The swap tests make each change happen at a chosen
moment through the observer; they do not prove the walk against every timing
on every filesystem. Not checked here: Linux, the Runtime's IPFS CID, and
Kubo itself (none is installed on this Mac). The outside check is the
README's Python block, written from the byte rules: the committed test
`readme_python_recomputes_every_lab_cid_pin` runs it with `python3 -I` (Python
3.9.6 on this Mac) and requires it to give every pin and the Rust encoder's
value for the same files. The tests pin the single-block, non-sharded subset
of the profile only.

The claim is "Kubo v0.40.1 profile, computed by the lab", and nothing more.
No offline Kubo cross-check has been run (Kubo v0.40.1, the same profile
flags, hash-only import, no network). Until one prints the same value as a
committed pin, the lab CID is not called equal to the Runtime's CID or to
Kubo's output. The Runtime's CID names a release archive, not the bundle's
files (see [Why a lab CID](#why-a-lab-cid-and-not-the-runtimes-cid)). The test
`the_lab_cid_claim_stays_computed_by_the_lab` keeps this: these two sections
and the module doc of `src/lib.rs` say the claim word for word, this section
states the gate, and no `*.md` file of the lane outside `tests/` and no file
under `src/` holds a phrase from its list of equality claims (`EQUALITY_CLAIMS` in
`tests/common/mod.rs`), in any case and across line breaks.

## Run

```bash
cargo fmt --manifest-path lab/capsule-identity/Cargo.toml -- --check
RUST_TEST_THREADS=2 cargo test --locked --offline --manifest-path lab/capsule-identity/Cargo.toml
```

The package is its own workspace (empty `[workspace]` table) with its own
`Cargo.lock`, so the Runtime's workspace never grows for it. Dependencies:
`elastos-common` by path (read only, for `CapsuleManifest`), `elastos-identity`
by path (read only, for the one `did:key` encoder and decoder), `hex` (since
task 018 only the tests use it), `serde_json`, `sha2`, `ed25519-dalek` 2.1 with its `rand_core` feature, and
`rustix` 1.1.4 with its `fs` feature, for safe `openat`, `fstat` and listing
from a handle (`std` cannot open relative to a handle, and the crate forbids
`unsafe`). Dev-dependencies: `tempfile` and `rand` 0.8 (the operating system's
generator in tests). There is no dependency on `elastos-server` or
`elastos-runtime`. All resolve offline from the local cargo cache.
`zerocopy` is locked at 0.8.62 because 0.8.63's derive crate is not in that
cache. `wc001_capsule_bundle_gets_a_stable_lab_cid` runs
`lab/wasm-capsule/tools/build`, so it also needs that lane's toolchain.
`readme_python_recomputes_every_lab_cid_pin`,
`readme_python_matches_the_name_signature_digest` and
`readme_python_matches_the_package_record_bytes` run `python3` from `PATH`;
with no `python3` they fail, they do not skip. The tests in
`tests/adoption.rs` run `git ls-files` and the cargo that built them
(`cargo metadata --no-deps --offline`); a git or cargo that cannot run fails
them with its cause.

## Layout

```
Cargo.toml, Cargo.lock   the package, its own workspace and lockfile
src/lib.rs               checked_bundle, lab_cid, check_name and its checked form,
                         the encoder, the walk, the test-key signature, the shared
                         digest, the lab package record and the lab variant binding
fixtures/                content-sample, web-app, wc001-core, agent-host, provider,
                         model, provider-variant-a, provider-variant-b
recipes/                 provider-variant.recipe, the variants' lab stand-in recipe
tests/common/mod.rs      assembly, pins, the bounded call, observers, wc-001 driver,
                         the library's code for tests that read it, fresh test keys,
                         the refusal asserts both signature checks share, the
                         key-material scan, the python3 -I run of README's blocks,
                         the cargo metadata scan for lab crates that use this one,
                         the claim scan of the lane's docs and src/
tests/adoption.rs        the adoption note lists every lab CID consumer; Cargo's
                         reader decides; the scan writes nothing
tests/bytes.rs           every byte is the name: manifest, payload, asks.json, files
tests/check_name.rs      a claimed name is checked, never trusted; one naming path
tests/checked_bundle.rs  the name and the bytes it covers; the checked name check
tests/claims.rs          the claim stays "Kubo v0.40.1 profile, computed by the lab"
tests/cross_implementation.rs
                         README's Python rule, the pins and the encoder agree;
                         README's two digest blocks and the signed bytes agree
tests/encoding.rs        order, boundaries, the printed form, one file per path,
                         each UnixFS profile setting
tests/fixtures.rs        Runtime manifest checks, pins, the wc-001 bundle
tests/kinds.rs           app, provider and model share the package rules; one closure
tests/location.rs        folder name, place, URL, Store rows, times, modes: not the name
tests/name_signature.rs  a test key signs the printed lab CID; verification only
tests/not_admission.rs   verify is not admit: a valid signature grants nothing
tests/package_record.rs  the lab package record outside the bundle binds the CID
tests/parse.rs           a printed lab CID is read with the one claim check
tests/refusals.rs        each refusal and its reason
tests/variant_binding.rs the signed variant binding outside the bundles
tests/walk.rs            changes made while a bundle is named; one walk
falsifiers.json          planted bugs, each caught by named tests
```

## Falsifiers

`falsifiers.json` holds 231 planted bugs in the provider format: round 1's
F-CI1a to F-CI1u, task 005's F-CI5a to F-CI5k, task 003's F-CI3a to F-CI3p
(no F-CI3e or F-CI3f: see
[above](#what-the-lab-cid-ignores-and-what-it-covers)), task 009's F-CI9a
to F-CI9j (see [the checked bundle](#checked-bundle-the-name-and-the-bytes-it-covers)),
task 004's F-CI4a to F-CI4z (see
[the test-key signature](#test-key-publisher-signature-lab-proposal)),
task 007's F-CI7a to F-CI7d (see
[verify is not admit](#verify-is-not-admit-m1-check-b1)), task 013's
F-CI13a to F-CI13c (see [reading a printed lab CID](#reading-a-printed-lab-cid)),
and task 014's F-CI14a to F-CI14e (see
[the test-key signature](#test-key-publisher-signature-lab-proposal) and
[verify is not admit](#verify-is-not-admit-m1-check-b1)), and task 011's
F-CI11a to F-CI11x (see
[the lab package record](#lab-package-record-outside-the-bundle)), and task 012's
F-CI12a and F-CI12b (see [three kinds](#three-kinds-share-the-package-rules)), and task 015's
F-CI15a to F-CI15z and F-CI15aa to F-CI15af, task 016's F-CI16a to
F-CI16i, and task 017's F-CI17a (all three: see
[the variant binding](#lab-variant-binding-outside-the-bundles)), and task
018's F-CI18a to F-CI18s (see [the encoding](#the-encoding)), and task
019's F-CI19a to F-CI19j, and task 020's F-CI20a to F-CI20f (both: see
[the cross-implementation check](#the-cross-implementation-check)), and task
025's F-CI25a to F-CI25m (see
[for a lab that uses the lab CID](#for-a-lab-that-uses-the-lab-cid)), and task
023's F-CI23a to F-CI23l (see [claim scope](#claim-scope)), and task 024's
F-CI24a to F-CI24e (see
[the cross-implementation check](#the-cross-implementation-check)), and task
027's F-CI27a to F-CI27d (see
[for a lab that uses the lab CID](#for-a-lab-that-uses-the-lab-cid)).
Each has `"command": "capsule-identity"` and `expect: "caught"`, and counts
only when every named test fails for its stated reason, never from a build
error. Every entry edits a file the runner restores after a killed run. Its
recovery list (`PROVIDER_TARGETS` in `examples/agent-host/falsify.py`) names
five files of this lane: `src/lib.rs`, `tests/common/mod.rs`,
`fixtures/wc001-core/capsule.json`, `.gitignore` and `README.md`. F-CI4h
edits this lane's `.gitignore`, F-CI4i edits this file, and every other entry
edits one of the first three. Task 014 moved the key-material scan, byte for
byte except for `pub(super)`, from `tests/name_signature.rs` into
`tests/common/mod.rs`, so F-CI4z now edits a restored file, with its `old`,
`new` and tests unchanged. Task 019's entries edit only `src/lib.rs`
(F-CI19b) and `tests/common/mod.rs`, which holds the code that takes the
Python block out of this file and runs it, so no entry edits this file.
Task 020's entries do the same: F-CI20a and F-CI20b edit `src/lib.rs`, and
F-CI20c to F-CI20f edit `tests/common/mod.rs`. F-CI19d now also names
020's two tests. Task 020 made the block extractor take a section heading
(`python_block_under`), and moved `CONTENT_SAMPLE_NAME_DIGEST` from
`tests/name_signature.rs` into `tests/common/mod.rs` with its value unchanged;
every older edit's text is still found exactly once.
Task 025's entries all edit `tests/common/mod.rs`, which holds the consumer
scan and the adoption note's reader. Task 025 made the README block reader
take a block's language (`fenced_block_under`; `python_block_under` is that
with `python`, with the same refusal text), so the note's ```text list has no
second reader, and every older edit's text is still found exactly once.
F-CI25k leaves its `target/` only beside a manifest outside the repository, so
it never writes in a consumer.
Task 023's entries edit `src/lib.rs` (F-CI23a plants a doc comment that makes
the equality claim over a line break; F-CI23b drops `, computed by the lab`
from the module doc) and `tests/common/mod.rs` (F-CI23c to F-CI23l weaken the
claim scan or the wording check). Task 023 moved `one_line` from
`tests/adoption.rs` into `tests/common/mod.rs`, unchanged, so the adoption
note and the claim share one white-space rule, and every older edit's text is
still found exactly once.
Task 024's entries all edit `tests/common/mod.rs`: F-CI24a plants its bug in
`python_records`, F-CI24b in `section_under`, and F-CI24c to F-CI24e in
`fenced_block_under`, which `python_block_under` calls. Each anchor holds its
refusal's own message text, so it is found exactly once and apart from
F-CI19g's. The README reader is shared, so F-CI24b and F-CI24c also name
`the_adoption_list_is_read_strictly`, and F-CI24b also names
`the_claim_wording_check_names_each_gap`: each asserts the same refusal.
Task 024 changed no older edit's text.
Task 027's entries all edit `tests/common/mod.rs`, in `consumer_in_metadata`:
F-CI27a to F-CI27c each turn one refusal into `Ok(false)`, and each anchor
holds that refusal's own message text, so it is found exactly once. F-CI27d
shares F-CI25g's anchor, the name-match line, and drops `dev` where F-CI25g
drops `build`. Task 027 changed no code and no older edit's text.

Task 018 swapped the framed stream for the UnixFS root, so 23 older entries
whose text it removed are re-targeted in place: the same id, the same bug in
the new form, the same named tests. The framing and its two length prefixes
are now a link's name length and its Tsize: F-CI1b drops both, F-CI1p the
name's length, F-CI1q the Tsize, and `path_and_content_boundaries_cannot_collide`
now also pins its two bundles so it catches them. F-CI1a drops each
directory's link sort; F-CI1c folds the time into every directory block;
F-CI1d prints without the `b`; F-CI1r keeps a second link of one name. F-CI3b
joins absolute paths as folders (a leading `/` would be refused, not named).
F-CI3d and F-CI3j keep their edits, with titles that no longer say stream.
The hex claim check is now the base32 one: F-CI3g skips the compare, F-CI3h
takes the claim without its `b`, F-CI3k drops the CID-bytes check, F-CI3l
drops characters outside the alphabet first, F-CI3m lowercases the claim
first, F-CI9i reads the claim itself without the `b`, F-CI4j signs the text
without the `b`, and F-CI13a to F-CI13c plant their bugs in the parse, which
now keeps the claim check's root. F-CI14d and F-CI14e anchor on
`MANIFEST_FILE` and `NAME_SIGNATURE_DOMAIN`, since the two constants they
anchored on are gone. F-CI15ae compares only the `bafybei` start.

Task 016 moved seventeen older edits, each with its same bug and the same
tests. The seam now keeps `check_manifest`'s answer
(`let wasm = check_manifest(&manifest.content)?;`), so F-CI1k, F-CI1l,
F-CI3a, F-CI3b, F-CI3i and F-CI12a anchor on that line, F-CI1f keeps the flag
`false` when it skips a missing manifest, and F-CI9c's seam keeps no flag.
`check_manifest` now ends `validate()...?;` and `Ok(wasm)`, so F-CI1h drops
the `validate()` line and F-CI1g's fallback returns `Ok(false)`.
`CheckedBundle` gained its `wasm` field, so F-CI9a, F-CI9b, F-CI9d, F-CI9e and
F-CI9j build or define it with that field. Check (e2) sits between (e) and
(f), so F-CI15t swaps (e) and (f) with (e2) after them. Signing now walks with
`checked_bundle`, so F-CI15x replaces that walk's refusal.

Task 011 moved three of 004's edits. The body of `name_signature_message`
moved into `domain_separated_digest`, so F-CI4a and F-CI4b now plant their
same two bugs there (the payload left out; the domain and `0x00` dropped),
with their tests unchanged. The Ed25519 check moved into `verify_ed25519`,
which both signatures call, so F-CI4d now ignores its result there, with its
tests unchanged. F-CI4j stays at `sign_bundle`. Every other older edit's
text is still found exactly once.

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
46 of 46). At task 004's round 1 it reported `summary: 81 CAUGHT of 81`; the repair
that followed added F-CI4z, so 004 merged 82 entries. At task 007
it reported `summary: 86 CAUGHT of 86` (with the id prefix `F-CI7`: 4 of 4).
At task 013 it reported `summary: 89 CAUGHT of 89`. At task 014 it reported
`summary: 94 CAUGHT of 94`. At task 011 it reported
`summary: 118 CAUGHT of 118` (with the id prefix `F-CI11`: 24 of 24).
At task 012 it reported `summary: 120 CAUGHT of 120`. At task 015 it reported
`summary: 152 CAUGHT of 152` (with the id prefix `F-CI15`: 32 of 32). At
task 016 it reported `summary: 161 CAUGHT of 161` (with the id prefix
`F-CI16`: 9 of 9). At task 017, with the id prefix `F-CI17`, it reported
`summary: 1 CAUGHT of 1`. At task 018 it reported
`summary: 181 CAUGHT of 181` (`baseline: 112 named tests pass without an edit,
0 do not`; with the id prefix `F-CI18`: 19 of 19). At task 019 it reported
`summary: 191 CAUGHT of 191` (`baseline: 113 named tests pass without an edit,
0 do not`; F-CI19a to F-CI19j each CAUGHT). At task 020 it reported
`summary: 197 CAUGHT of 197` (`baseline: 115 named tests pass without an edit,
0 do not`; F-CI20a to F-CI20f and the widened F-CI19d each CAUGHT). At task
025 it reported `summary: 210 CAUGHT of 210` (`baseline: 121 named tests pass
without an edit, 0 do not`; F-CI25a to F-CI25m each CAUGHT). At task 023,
it reported `summary: 222 CAUGHT of 222` (`baseline: 124 named tests pass
without an edit, 0 do not`; with the id prefix `F-CI23`: 12 of 12). At task
024 it reported `summary: 227 CAUGHT of 227` (`baseline: 124 named tests pass
without an edit, 0 do not`; F-CI24a to F-CI24e each CAUGHT). At task
027 it reported `summary: 231 CAUGHT of 231` (`baseline: 124 named tests pass
without an edit, 0 do not`; F-CI27a to F-CI27d each CAUGHT).
The runner does not print why a test failed. Tasks 003, 009, 004, 007, 013,
014, 011, 012, 015, 016, 017, 018, 019, 020, 025, 023, 024 and 027 prove each of their falsifiers by break, named test fails, revert.

The signature answers only whether this test key signed this lab CID.
