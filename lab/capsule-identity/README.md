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
  decision. It sits in no Runtime admission or launch path, and no Runtime
  code calls it; the lab's stand-in launcher, in test code, calls it (see [the
  stand-in launcher](#lab-stand-in-launcher-m1-check-b1)). Admission stays a
  separate decision under each Runtime's trust policy. A signature check that
  returns `Ok(())` is not a permission to run.
- Its value is a **lab CID**, a lab package CID: the CIDv1 SHA-256 UnixFS
  directory root of the bundle, printed as 59 characters that start
  `bafybei`. It is a prototype, not an admission, and it defines no shared
  capsule identity. It is not the Runtime's published name (see
  [Why a lab CID](#why-a-lab-cid-and-not-the-runtimes-cid)).
- The one schema check is the Runtime's own. `capsule.json` at the bundle root
  is parsed as `elastos_common::CapsuleManifest`, which refuses an unknown
  field, and then checked with its `validate()`. Each refusal keeps the
  Runtime's own text. The lab adds no field, no schema and no parser.
- The provider's encoder names deployed content. The lab encoder is a test oracle only.

## The encoding

The lab CID is the CID of the bundle's UnixFS root directory, made the way
Anders's answer (Q3) asks: CIDv1, SHA-256, the model package profile. The
profile is Kubo v0.40.1's import flags as
`capsules/ipfs-provider/src/directory_hash.rs` sends them (`ADD_OPTIONS`,
lines 21-43, and the HAMT defaults at lines 507-517): CIDv1, `sha2-256`, raw
leaves, chunker `size-262144`, trickle off (balanced layout), `max-file-links`
174, `max-directory-links` 0, HAMT fanout 256 and size threshold 256KiB, no
inline (inline limit 32 unused), no preserved mode or mtime, no empty
directories. This crate runs no Kubo; the offline cross-check named in
[Claim scope](#claim-scope) runs one separately. So the lab CID follows the
Kubo v0.40.1 profile, computed by the lab: one offline Kubo v0.40.1
hash-only import, with the Runtime's profile flags, was run on this Mac and
printed every committed pin, and the lab CID is not called equal to the
Runtime's CID or to Kubo's output.
The tests pin the balanced file layout at one and two levels (a file of one
raw leaf; a file of 2 to 174 raw leaves under one balanced file root, trickle
off and `max-file-links` 174, task 048; and a file of 175 leaves under a
two-level root, task 076), a basic directory on both sides of the 256KiB
links estimate, and the HAMT shard above it (task 077). The same grouping
gives the file layout at any deeper depth, which no pin covers.

To recompute a lab CID by hand:

1. Take every regular file under the bundle root. Its bundle path is its path
   below the root, parts joined with `/`, in UTF-8.
2. Each file of at most 262144 bytes is one **raw leaf**. Its block is the
   file's bytes (an empty file is an empty block). Its CID is the 36 bytes
   `01 55 12 20` and the SHA-256 of the block: CID version 1, the raw codec
   `0x55`, the multihash code `0x12` (sha2-256) and length `0x20` (32). Its
   Tsize is its length.
3. A file of more than 262144 bytes is split into 262144-byte chunks, the
   last one shorter, and each chunk is a raw leaf as in step 2. The leaves
   make a balanced dag-pb **file tree** (trickle off). Each level groups its
   nodes left to right into groups of up to 174 (`max-file-links`), each full
   before the next starts, so only a level's last group can be short, and
   wraps each group in one **file node**; a group of one child is still a
   node with one link. The depth is the smallest `d` with `174^d` at least
   the leaf count: a file of 175 leaves is a root of two depth-1 nodes, the
   first over 174 leaves and the second over one leaf. A file node's block
   is, for each child in order, field 2 (`0x12`, length) holding a link:
   field 1 (`0x0a`, length) the child's CID bytes, field 2 with an empty name
   (`12 00`), field 3 (`0x18`) the child's Tsize as a varint. Then field 1
   (`0x0a`, length) holds the UnixFS data: `08 02` (type 2, a file), `18` and
   the bytes under the node as a varint (filesize, field 3), and for each
   child `20` and its file size as a varint (blocksizes, field 4, one tag per
   value, not packed). A raw leaf's file size is its length; a file node's is
   the bytes under it, not its Tsize. There is no Data field (field 2). A
   node's CID is `01 70 12 20` and the SHA-256 of its block, and the Tsize of
   a link to it is its block's length plus its children's Tsizes. A file of
   one leaf stays that raw leaf, never a file node.
   `file_past_174_leaves_keeps_a_second_tree_level` pins the 175-leaf bundle
   (`SECOND_LEVEL_FILE_LAB_CID`) and catches F-CI76a (a one-child group
   linked directly) and F-CI76b (a child's Tsize as its blocksize). A file of
   30277 leaves (30276 of 262144 bytes and one of 1 byte, 7936671745 bytes)
   is the smallest at depth 3: 175 depth-1 nodes (174 over 174 leaves, and the
   node of one link over the single leaf), then 2 depth-2 nodes (one over
   those 174 nodes, and one over that node of one link), then the root's two
   children. `file_past_174_squared_leaves_keeps_a_third_tree_level` pins that
   file (`THREE_LEVEL_FILE_LAB_CID`) and catches F-CI72a (the level loop stops
   after two passes).
4. Each path part but the last is a **directory**: `browser/app.js` is a
   directory `browser` with a link named `app.js`. The root is the directory
   of the bundle's entries. No empty directory is ever made.
5. Each directory's **links estimate** is the sum, over its direct children,
   of the child's name in bytes plus 36. It is not the block's length and not
   a child's Tsize; a child directory counts through its own name and is
   judged on its own estimate. An estimate of at most 262144 is one **basic
   directory block**, dag-pb: sort its children by name bytes, and for each
   child write protobuf field 2 (tag `0x12`, then the length as a varint)
   holding a link: field 1 (`0x0a`, length) the child's CID bytes, field 2
   (`0x12`, length) its name in UTF-8, field 3 (`0x18`) its Tsize as a
   varint. Then write field 1 (`0x0a 0x02`) holding the UnixFS data `08 01`:
   type (field 1) = 1, a directory. That block may be longer than 262144
   bytes; the estimate alone decides. Lengths and Tsizes are ordinary
   unsigned varints: 7 bits per byte, low bits first, so a value over 127
   takes two bytes.
6. An estimate greater than 262144 is a **HAMT shard**, fanout 256: bucket
   `n` is byte `n` of the name's murmur3 x64-128 digest (seed 0, its first
   64 bits big-endian; `hello` gives `cb d8 a7 b3 41 bd 9b 02`). A bucket
   with one child is one link whose name is the bucket's two uppercase hex
   digits and then the child's own name, to that child. A bucket with two or
   more children is one link whose name is only the prefix, to a child shard
   built the same way from the next digest byte; that child shard may itself
   hold one link. Links go out in bucket order, each as field 2 holding the
   same link shape as a basic directory. Then field 1 (`0x0a`, length) holds
   the UnixFS data: `08 05` (type 5, a HAMT shard directory), field 2
   (`0x12`, length) the bitmap with bucket `i` set in byte `31 - i/8` at mask
   `1 << (i % 8)` after its leading zero bytes are dropped, `28 22` (hash
   type `0x22`) and `30 80 02` (fanout 256). There is no filesize,
   blocksizes, mode or mtime. A ninth digest byte is refused: the murmur
   digest has eight. One table, `shared_prefix_rows`, still gives a child
   shard from the sixth digest byte and from the seventh: its six-byte row
   and seven-byte row each keep the next shard, and
   `shared_digest_prefixes_keep_the_next_shard` pins both (F-CI71a puts a
   leaf at depth 5, F-CI71b at depth 6). Each level takes one digest byte.
7. A directory's CID is `01 70 12 20` and the SHA-256 of its block (the dag-pb
   codec `0x70`). The Tsize of a link to a directory, basic or shard, is the
   length of its block plus the Tsizes of its own links. A link to a child
   shard stores that shard's Tsize, the child block's length plus its
   children's Tsizes: the six-byte pair's two 1-byte files add 2 beyond the
   child block. `child_shard_link_keeps_the_files_tsizes` pins that bundle
   (`CHILD_SHARD_TWO_FILE_LAB_CID`), catching F-CI84a (the link stores only
   its child block's length). Every varint inside a CID here is one byte.
8. **Print** the root's 36 CID bytes as `b` (the multibase prefix) and their
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

def cid(codec, block):  # a CIDv1 sha2-256 of a block
    return cid_for(codec, hashlib.sha256(block).digest())

def cid_for(codec, digest):  # the same CID from the block's digest
    return bytes([0x01, codec, 0x12, 0x20]) + digest

def total(block, tsizes):  # the Tsize of a node's block
    return len(block) + sum(tsizes)

def file_tree(level):  # (CID, Tsize, filesize) nodes of one level; the root
    while len(level) > 1:
        groups = [level[at:at + 174] for at in range(0, len(level), 174)]
        level = []
        for group in groups:
            filesize = sum(child[2] for child in group)
            links = b""
            unixfs = b"\x08\x02\x18" + varint(filesize)
            for child in group:
                link = field(1, child[0]) + field(2, b"")
                links += field(2, link + b"\x18" + varint(child[1]))
                unixfs += b"\x20" + varint(child[2])
            block = links + field(1, unixfs)
            level.append((cid(0x70, block), total(block, [child[1] for child in group]), filesize))
    return level[0][0], level[0][1]

def file_from_digests(leaves):  # (digest, size) pairs; returns (CID bytes, Tsize)
    return file_tree([(cid_for(0x55, digest), size, size) for digest, size in leaves])

def file_node(data):  # a file's bytes; returns (CID bytes, Tsize)
    if len(data) <= 262144:
        return cid(0x55, data), len(data)
    leaves = []
    for at in range(0, len(data), 262144):
        chunk = data[at:at + 262144]
        leaves.append((hashlib.sha256(chunk).digest(), len(chunk)))
    return file_from_digests(leaves)

def murmur(data):  # murmur3 x64-128, seed 0; its first 64 bits, big-endian
    mask = (1 << 64) - 1
    c1, c2 = 0x87C37B91114253D5, 0x4CF5AD432745937F
    def rotl(value, bits):
        return ((value << bits) | (value >> (64 - bits))) & mask
    def fmix(value):
        value ^= value >> 33
        value = value * 0xFF51AFD7ED558CCD & mask
        value ^= value >> 33
        value = value * 0xC4CEB9FE1A85EC53 & mask
        return value ^ (value >> 33)
    h1 = h2 = 0
    for at in range(0, len(data) // 16 * 16, 16):
        k1 = int.from_bytes(data[at:at + 8], "little")
        k2 = int.from_bytes(data[at + 8:at + 16], "little")
        k1 = k1 * c1 & mask
        h1 ^= rotl(k1, 31) * c2 & mask
        h1 = ((rotl(h1, 27) + h2) * 5 + 0x52DCE729) & mask
        k2 = k2 * c2 & mask
        h2 ^= rotl(k2, 33) * c1 & mask
        h2 = ((rotl(h2, 31) + h1) * 5 + 0x38495AB5) & mask
    tail = data[len(data) // 16 * 16:]
    k1 = int.from_bytes(tail[:8].ljust(8, b"\x00"), "little")
    k2 = int.from_bytes(tail[8:].ljust(8, b"\x00"), "little")
    if len(tail) > 8:
        h2 ^= rotl(k2 * c2 & mask, 33) * c1 & mask
    if tail:
        h1 ^= rotl(k1 * c1 & mask, 31) * c2 & mask
    h1 ^= len(data)
    h2 ^= len(data)
    h1 = (h1 + h2) & mask
    h2 = (h2 + h1) & mask
    return ((fmix(h1) + fmix(h2)) & mask).to_bytes(8, "big")

def shard(links, level):  # links of one directory; returns (CID bytes, Tsize)
    if level == 8:
        raise ValueError("a HAMT shard needs a ninth digest byte")
    buckets = {}
    for name, child, tsize in links:
        buckets.setdefault(murmur(name.encode("utf-8"))[level], []).append((name, child, tsize))
    bitmap = bytearray(32)
    written = b""
    tsizes = []
    for bucket in sorted(buckets):
        bitmap[31 - bucket // 8] |= 1 << (bucket % 8)
        prefix = f"{bucket:02X}"
        group = buckets[bucket]
        if len(group) == 1:
            name, child, tsize = group[0]
            link = field(1, child) + field(2, (prefix + name).encode("utf-8"))
        else:
            child, tsize = shard(group, level + 1)
            link = field(1, child) + field(2, prefix.encode("utf-8"))
        tsizes.append(tsize)
        written += field(2, link + b"\x18" + varint(tsize))
    first = next((at for at, byte in enumerate(bitmap) if byte), 32)
    unixfs = b"\x08\x05" + field(2, bytes(bitmap[first:])) + b"\x28\x22" + b"\x30" + varint(256)
    block = written + field(1, unixfs)
    return cid(0x70, block), total(block, tsizes)

def directory(tree):  # {name: bytes or a dict}; returns (CID bytes, Tsize)
    links = []
    for name in sorted(tree, key=lambda n: n.encode("utf-8")):
        child = tree[name]
        if isinstance(child, dict):
            child_cid, tsize = directory(child)
        elif isinstance(child, list):
            child_cid, tsize = file_from_digests(child)
        else:
            child_cid, tsize = file_node(child)
        links.append((name, child_cid, tsize))
    if sum(len(name.encode("utf-8")) + 36 for name, _, _ in links) > 262144:
        return shard(links, 0)
    written = b""
    for name, child_cid, tsize in links:
        written += field(2, field(1, child_cid) + field(2, name.encode("utf-8")) + b"\x18" + varint(tsize))
    block = written + field(1, b"\x08\x01")
    return cid(0x70, block), total(block, [tsize for _, _, tsize in links])

def printed(cid_bytes):  # the root's CID bytes as the 59-character text
    bits = "".join(f"{byte:08b}" for byte in cid_bytes) + "00"
    return "b" + "".join(B32[int(bits[i:i + 5], 2)] for i in range(0, 290, 5))

def lab_cid(files):  # {bundle path: bytes}
    root = {}
    for path, data in files.items():
        *folders, name = path.split("/")
        node = root
        for folder in folders:
            node = node.setdefault(folder, {})
        node[name] = data
    return printed(directory(root)[0])
```

In Rust, the walk (`checked_bundle`, which `lab_cid` runs too) reads a bundle,
and `encode_entries` makes each file's node from its bytes with `file_node`
(one raw leaf, or `file_root` over its leaves) and hands the nodes to
`encode_tree`, the one tree builder. `encode_listed_files` (task 047; see
[naming a closure listing](#naming-a-closure-listing)) makes one raw leaf per
listed file and hands them to the same `encode_tree` (task 048). Every leaf is
made by `raw_leaf`, and directory blocks, file roots and shard blocks write
their links with one `put_links`. They are the only code that names a bundle;
tests call them and copy none. `naming_hash` holds the one naming hash, and
leaves, file roots, directory blocks and shard blocks share it. `tsize` holds
the one Tsize rule, block length plus children's Tsizes. `encode_directory`
is the one directory encoder: `links_estimate` decides a basic block or a
`hamt_shard`, and `hamt_digest` holds the one marked copy of the HAMT hash.
The encoder also
refuses what the walk can never give but a caller of the encoder could: a path
with an empty, `.` or `..` part, two entries with one path, and one path that
is both a file and a directory (`a` and `a/b`, in either order). `check_name` checks a
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
| A file over one leaf is a balanced root of raw leaves: empty link names, type 2, filesize, blocksizes, and a Tsize of its block and its leaves | `file_over_one_leaf_has_the_pinned_cid` | F-CI48a (no name field), F-CI48b (no blocksizes), F-CI48c (no filesize), F-CI48d (Tsize without the root block) |
| The file tree's depth is the smallest `d` with `174^d` at least the leaf count: each level groups up to 174 children, left to right, each group full before the next starts, one file node per group, and a group of one child is a one-link node | `file_past_174_leaves_keeps_a_second_tree_level`, `file_past_174_squared_leaves_keeps_a_third_tree_level` | F-CI18e (the level loop runs only once), F-CI48e (the limit is 175), F-CI76a (a one-child group linked directly), F-CI76b (a child's Tsize as its blocksize), F-CI72a (the level loop stops after two passes) |
| A file of 30277 leaves needs a third tree level: 175 depth-1 nodes, then 2, then the root's two children; 30276 full leaves still finish in two passes | `file_past_174_squared_leaves_keeps_a_third_tree_level` | F-CI72a (the level loop stops after two passes) |
| The listing call names a file of at most one leaf; a listed file over one chunk is refused and named from its bytes instead | `listed_file_over_the_chunk_limit_is_refused`, `listed_file_over_one_leaf_names_the_bytes_call` | F-CI47c (`encode_listed_files` has no size refusal) |
| Links sorted by name bytes | `lab_cid_matches_the_pinned_value_for_each_fixture`, `lab_cid_does_not_depend_on_listing_order` | F-CI18f (reverse), F-CI1a (no sort) |
| Directory type 1 | `lab_cid_matches_the_pinned_value_for_each_fixture` | F-CI18g (5) |
| The links estimate decides a directory's block: at most 262144 is one basic directory, which may be larger than 262144 bytes; a greater estimate is a HAMT shard | `directory_at_the_hamt_threshold_stays_basic`, `directory_over_the_hamt_threshold_is_a_shard` | F-CI77i (`>=`), F-CI18h (never shards; retargeted by task 077) |
| A HAMT shard takes digest byte `n` as bucket `n`: a one-child bucket is one link named the prefix and the child's name; a bucket of two or more is one prefix link to a child shard over the next byte; links in bucket order | `directory_over_the_hamt_threshold_is_a_shard`, `tests::two_names_in_one_bucket_get_a_child_shard` | F-CI77a (little-endian digest), F-CI77b (a one-child bucket named by its prefix only), F-CI77c (a one-child bucket wrapped in a child shard), F-CI77d (the child's Tsize in the estimate), F-CI77h (a multi-child bucket as leaf links) |
| A shared digest prefix still makes a child shard from the sixth byte and from the seventh: `shared_prefix_rows` holds the six-byte and seven-byte pairs | `shared_digest_prefixes_keep_the_next_shard` | F-CI71a (a leaf at depth 5), F-CI71b (a leaf at depth 6) |
| The shard's bitmap is 32 bytes with bucket `i` in byte `31 - i/8`, leading zeros dropped, then `28 22` and `30 80 02` | `tests::hamt_bitmap_drops_leading_zero_bytes`, `directory_over_the_hamt_threshold_is_a_shard` | F-CI77f (byte at `i/8`), F-CI77g (all 32 bitmap bytes kept) |
| A shard's Tsize is its block plus the Tsizes of the links it writes; a link to a child shard stores the child's Tsize, so two 1-byte files add 2 beyond its block | `directory_over_the_hamt_threshold_is_a_shard`, `child_directory_over_the_hamt_threshold_is_a_shard`, `child_shard_link_keeps_the_files_tsizes` | F-CI48d (the shared Tsize rule without the block), F-CI84a (a child-shard link stores only its block's length) |
| A child directory is judged on its own estimate; its parent counts only its name | `child_directory_over_the_hamt_threshold_is_a_shard` | F-CI77e (shards only at the bundle root) |
| A ninth digest byte is refused | `tests::hamt_depth_exhaustion_is_refused` | F-CI77j (exhaustion returns success) |
| The HAMT hash is murmur3 x64-128, seed 0, first 64 bits big-endian | `hamt_digest_is_the_marked_murmur3_copy` | F-CI77a (little-endian bytes) |
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
Task 048 adds two more, also built in a temp dir and in memory and never
committed: `content-sample` with `sample.example` as 262145 zero bytes (two
leaves, 262144 and 1 bytes) is
`bafybeidbd7gfhommypeks66twpnbbb3lwovdqe6iwtmdxptgcq5jqbaaby`; and
`content-sample` with an added `core/big.bin` of 600000 bytes, byte `i` being
`i % 251` (three leaves, 262144, 262144 and 75712 bytes, one directory down),
is `bafybeidpgwbsi22cbsmthqupvn37xphujhs6fnzyuy64uc6nsauc6bftqe`. Both were
first computed by a `python3 -I` script written from the hand rules above,
before any Rust code named them; that script used Python's own `base64` for
the printed form and gave `content-sample`'s pin too. Task 076 adds one more,
in memory and never committed: `content-sample` with `sample.example` as
45613057 zero bytes (175 leaves, 174 of 262144 bytes and one of 1 byte, so a
root of two depth-1 file nodes) is
`bafybeifdbtqkw5q2ayypyajkbxd4wrctavgxpagjbugk5nddz53igm6xta`, first printed
by README's Python rule before any Rust code named it. The 174-leaf file of
45613056 zero bytes still encodes, with another CID, and is not pinned.
Task 072 adds one more, in memory and never written: one file `sample.example`
whose 30277 leaves are leaf `i`'s SHA-256 of `i` as 8 little-endian bytes,
30276 of 262144 bytes and one of 1 byte (7936671745 bytes), is
`bafybeig3p6lebveuwcqolitt4bzbmr2mbidjzw3tqzmq6vrc5otgrp5bea`, first printed
by README's Python rule before any Rust code named it. The 30276-leaf file of
262144-byte chunks still finishes in two passes, with another CID, and is not
pinned.
Task 077 adds three more, built in a temp dir and never committed; the one
helper measures the name it lengthens, so no length is hardcoded:
`content-sample` plus empty files whose links estimate is exactly 262144 (one
name lengthened to 210 bytes, and the block 279500 bytes, so a basic
directory may be larger than the threshold) is
`bafybeidofifnoh4qecocbt2qksv2bbvg5ocyggix6gdsr5wvnlxlw6erui`; the same with
an estimate of 262145 (211 bytes) is
`bafybeiapjks5bqeaeeuhrestfwx3tskokvzjvy5kltdidb24gnyyzkn2rm`; and the
262145 file set under `photos/`, with `content-sample`'s two files left at the
root (whose own estimate is 140), is
`bafybeihmck6tdzcctrlvqlyl35xkja36ogb2qwts7qofk5abrlzb7jr3zi`. Each was first
printed by README's Python rule before any Rust code named it. The helper
builds the empty files from `content-sample`'s entries and one measured
lengthened name.
Task 071 adds two more, built in a temp dir and never committed: one table,
`shared_prefix_rows` holds both pairs. Its six-byte row replaces two 100-byte
fillers of the 077 file set at estimate 261945 with the 200-byte names
`format!("f6-{:0>197}", 67_618_900)` and
`format!("f6-{:0>197}", 192_452_893)`, whose digests share bytes 0 through 5,
so the estimate is 262145 and the bundle is
`bafybeihe5tbuj3b3bh76xcrd4hklsombul7skdeurbuwb5steypvasqrjm`. Its
seven-byte row does the same with `format!("f7-{:0>197}", 2_731_584_490)` and
`format!("f7-{:0>197}", 3_825_277_504)`, whose digests share bytes 0 through
6, and its bundle is
`bafybeie2vvrtsognxi7rnvjpzbzerrk73zfzakxdr6eoxmzgkzvtphnmeu`. Each was first
printed by README's Python rule before any Rust code named it; the one helper
reads a row from that table and replaces the two fillers the row names.

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
5. For each of the 21 pins, the Python answer, the pin constant and the
   printed `encode_entries` result for the same files must be equal, and the
   test asserts that it checked exactly 21 bundles. The 21 are the seven
   pinned fixtures (`content-sample`, `web-app`, `agent-host`, `provider`,
   `model`, `provider-variant-a`, `provider-variant-b`), the recipe, the
   chunk-limit, empty-file and long-name bundles above, which are built as
   entries in memory, the photo stand-in consumer copy (task 047, see
   [naming a closure listing](#naming-a-closure-listing)), the two-leaf
   and three-leaf file bundles (task 048), the second-level file bundle
   (task 076), the three HAMT-threshold bundles (task 077), the two
   shared-prefix bundles (task 071) and the two-file child-shard bundle
   (task 084), also built in memory. `wc001-core` has
   no pin, because its `capsule.wasm` is built on each machine, so it is not
   checked here. Task 072's third-level file is not one of the 21 either: it
   is 7936671745 bytes and is never written, so
   `file_past_174_squared_leaves_keeps_a_third_tree_level` runs the second
   driver, `THREE_LEVEL_FILE_DRIVER`, which builds its 30277 leaves and calls
   the block's `directory` and `printed`; that test holds the driver to no
   grouping, varint, CID prefix or base32 of its own.

| Rule | Named test | Falsifier |
| --- | --- | --- |
| README's rule agrees with the pins | `readme_python_recomputes_every_lab_cid_pin` | F-CI19a (the block's `0x55` becomes `0x70` before it runs) |
| Rust agrees with README's rule, not only with the pins | `readme_python_recomputes_every_lab_cid_pin` | F-CI19b (the encoder's `RAW_CODEC` becomes `0x56`) |
| A missing block is no pass: exactly 21 bundles are checked | `readme_python_recomputes_every_lab_cid_pin` | F-CI19c (no block found, no answers) |
| README states the count this test checks, and three sentences say one count | `readme_python_recomputes_every_lab_cid_pin` | F-CI71c (the pins sentence drifts), F-CI71d (the checked sentence drifts), F-CI71e (the rows sentence drifts) |
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

Not shown: Python on another machine. The check is two implementations on one
Mac (Python 3.9.6 here), and a third one runs only when asked: the ignored
test `kubo_hash_only_import_prints_every_lab_cid_pin` names the Kubo binary in
`LAB_KUBO`, makes a fresh temp repo, writes the provider's `Import` HAMT
values, and runs one `add --offline --only-hash --recursive=true
--wrap-with-directory=false` with the profile flags for each pinned bundle.
Kubo's root, the pin and `encode_entries` are one value for all 21, and the
test asserts it checked 21. A missing `LAB_KUBO`, a binary that is not
0.40.1, and any row that differs are refused with their reason;
`kubo_helper_refuses_bad_setup` checks the setup refusals with local stubs,
including a version command that prints `0.40.1` and then fails.
`kubo_run_refuses_failed_commands` checks command refusals, including
`/usr/bin/false` with empty stderr. Both helpers report startup errors or
the failed command's exit status or signal and stderr, with exact-message
assertions for each refusal.

| Rule | Named test | Falsifier |
| --- | --- | --- |
| A missing `LAB_KUBO` is refused with its reason | `kubo_helper_refuses_bad_setup` | F-CI77k (an unset name becomes `kubo`) |
| A Kubo that is not 0.40.1 is refused with its reason | `kubo_helper_refuses_bad_setup` | F-CI77l (the version compare removed) |

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
capsule's name. The lab CID encoder never parses `asks.json`: to the lab CID it
is one more payload file. The manifest is a component manifest, so the Runtime's
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
- Since task 036 it also keeps, in a private field, the manifest's `name`
  from that same check, and `manifest_name()` hands it out. `check_manifest`
  returns both values from its one `CapsuleManifest` parse, so a caller that
  needs the name never parses `capsule.json` again (P10). The name is identity
  data the manifest states, not a decision.
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
| `CheckedBundle::manifest_name(&self) -> &str` | the `name` of the bundle's `capsule.json`, as the one manifest check read it |
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
| `manifest_name()` answers each committed fixture's manifest `name`, as the test states it | `checked_bundle_hands_out_the_manifest_name` | F-CI36a (an empty string) |

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
| A dev-dependency counts: `lab/wasm-capsule` uses this crate only under `[dev-dependencies]` | `the_consumer_scan_uses_cargos_reader`, `every_lab_cid_consumer_is_in_the_adoption_note` | F-CI27d (dev-dependencies are dropped, so `lab/wasm-capsule/Cargo.toml` is missing from the scan; see the note below the table) |
| The scan writes nothing beside a manifest, ignored files included | `the_consumer_scan_writes_nothing` | F-CI25k (a `target/` is left beside a manifest outside the repo), F-CI25l (`--no-deps` is dropped, so Cargo resolves and writes a `Cargo.lock`) |
| The list is read strictly: a missing note, no list and a line it cannot read each fail with their reason | `the_adoption_list_is_read_strictly` | F-CI25m (a line it cannot read is skipped) |
| The note states the outside recomputation | `the_adoption_note_states_the_outside_recomputation` | F-CI25e |

A note on F-CI27d: `every_lab_cid_consumer_is_in_the_adoption_note` catches
it only while `lab/wasm-capsule/Cargo.toml` holds this crate under
`[dev-dependencies]` and under no other kind. If that consumer moves it to
`[dependencies]`, the real scan finds it with or without F-CI27d, so that test
stops failing and the runner reads F-CI27d as not caught; the entry's test
names must then change. `the_consumer_scan_uses_cargos_reader` catches it
either way, on synthetic metadata with no consumer file involved.

## Naming a closure listing

A lab whose own walk already lists each file's path, size and SHA-256 gets the
lab CID from `encode_listed_files(&[ListedFile])` (task 047). `ListedFile` is
`{ path: String, size: u64, sha256: [u8; 32] }`. A raw leaf needs only the
SHA-256 and the length of its bytes (step 2 of [the encoding](#the-encoding)),
so such a listing is enough for a file of one leaf. It is no second
encoder: `encode_listed_files` makes each leaf with `raw_leaf`, the leaf rule
`encode_entries` uses too, and both hand their nodes to `encode_tree`, the one
tree builder, and `lab_cid` is the walk and then `encode_entries`, so the
directory encoding exists once (`check_name_uses_the_single_naming_path`
checks it). It reads no file and
checks no manifest. So the lab CID names the bytes only if each `sha256` and
`size` are those of the bytes: the caller's walk owns that. A `size` over
262144 is refused with `FileOverChunkLimit` and the file's path, and the path
refusals are the ones `encode_entries` gives. Since task 048 a file over one
leaf has a lab CID, but only from its bytes: a listed file's one SHA-256 names
a single raw leaf, and a file root needs each leaf's SHA-256. So the refusal's
text says to name such a file with `encode_entries` (or `lab_cid`), which take
the bytes; `ListedFile` keeps its three fields. There is no hex form: a caller
decodes its own hex.

It is for the photo lane (Flint's 28 Oct note; Rong's DR-1, one identity rule;
Anders's Q3). On `spike/spike/photo-viewer` at `d047a069a`, the photo bundle
tool names a closure by a second rule, a raw CIDv1 over a JSON listing of
`{path, size, sha256}` (`examples/photo-viewer/bundle/src/listing.rs:478-485`,
`cid.rs:5`), so one bundle gets two lab names. The photo lane switches its
`cid_of` to this call itself; this lane edits none of its files.

**Signing the name.** A listing-named closure is signed with
`sign_cid_record(key, cid)` and checked with `verify_cid_record(cid, record,
accepted)` (task 049), the one package record
([below](#lab-package-record-outside-the-bundle)) that the folder and checked
record calls also make and check, so the photo lane needs no signed record of
its own.

**The pin.** `consumer-fixtures/photo-stand-in-photo-set/` is a byte-for-byte
copy of the photo lane's PH6 fixture folder
`examples/photo-viewer/host-test/fixtures/stand-in-photo-set/` at `d047a069a`.
`git hash-object` of each copy equals its blob id there:

| File | Bytes | Git blob |
| --- | --- | --- |
| `README.md` | 1585 | `1b4548402e4618ca21569d918fe1914b8692e7f4` |
| `capsule.json` | 387 | `5ec198ec721267ce8b629b78f7bd6b9462a4b60c` |
| `images/01.png` | 180 | `1ec336b5402de32a9d9969bb7a718bf744b1e8b1` |
| `images/02.jpg` | 293 | `58d489a1eb0e4a24bb517f8d6345372a8e416aaa` |
| `images/03.webp` | 350 | `c4ecc5b848a405c1a79f02fd53ada7da7c1aeb97` |

The lab CID of the five files is
`bafybeiepelczjykxjbhpwaqjnmxx346l52alcxfzgg52ip2ejf5yijiuna`
(`PHOTO_STAND_IN_LAB_CID`). It was first computed by this README's Python block
run on the five copied files, before any Rust code named them, and
`readme_python_recomputes_every_lab_cid_pin` recomputes it. The pin is of this
five-file folder. The photo lane's own pack keeps `README.md` out of the packed
closure (its README says so), so a packed PH6 bundle holds four files and gets
another name by the same rule.

**The snag.** The copy sits outside `fixtures/`. Its `capsule.json` has
`"viewer": {"name": ..., "cid": ...}`, an object, while the Runtime's
`CapsuleManifest` has `viewer: Option<String>` and refuses what does not fit
(`deny_unknown_fields`; `elastos/crates/elastos-common/src/manifest.rs:126-128`).
So `lab_cid` on the exact folder refuses with `ManifestUnparsed`, and the copy
cannot be a fixture: every folder in `fixtures/` must pass that parse. The
photo lane's switch reaches this lane's name through `encode_listed_files`, and
through `lab_cid` only once its `viewer` fits the Runtime type. The lab does
not loosen, skip or copy the manifest check.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| The listing of the copy's five files gets the pin, the value `encode_entries` gives for the same files; on a temp copy whose `viewer` is the Runtime type's string, `lab_cid` of the folder equals `encode_listed_files` of that folder's listing | `photo_listing_gets_the_lab_cid_of_its_folder` | F-CI47a (the root is the photo rule's raw-listing CID: the SHA-256 of a `{path,size,sha256}` JSON listing, not of the directory block), F-CI47b (every leaf's Tsize is 0) |
| README's Python rule recomputes the photo pin | `readme_python_recomputes_every_lab_cid_pin` | F-CI47a |
| `lab_cid` refuses the exact PH6 folder with `ManifestUnparsed`, as the Runtime type does | `lab_cid_refuses_the_photo_manifest_the_runtime_type_refuses` | F-CI1g (a manifest the Runtime type refuses is read as plain JSON) |
| A listed file over one chunk is refused with its path; one of exactly one chunk is a leaf | `listed_file_over_the_chunk_limit_is_refused` | F-CI47c (`encode_listed_files` has no size refusal) |
| A listed file over one leaf is still refused, its text names its path, its length and `encode_entries`, and `encode_entries` names the same file from its bytes (task 048) | `listed_file_over_one_leaf_names_the_bytes_call` | F-CI47c |
| The listing's lab CID gets the one package record from `sign_cid_record`, with the record's exact payload, and `verify_cid_record` passes it; no folder is walked (task 049) | `a_closure_listing_gets_a_package_record_by_its_cid` | F-CI49c |

The tests are in `tests/closure_listing.rs`. Task 047 also named
`lab_cid_refuses_the_photo_manifest_the_runtime_type_refuses` on F-CI1g, task
005's entry. The listing names bytes; it is no admission, grant or launch step.

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
checks identity only, and it sits in no Runtime admission or launch path; the
lab's stand-in launcher, in test code, calls it
([below](#lab-stand-in-launcher-m1-check-b1)).

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
  `CheckedBundle::cid`, `CheckedBundle::entries`,
  `CheckedBundle::manifest_name` (task 036: the checked manifest's `name`,
  identity data), `encode_entries`, `entry_kind`, `entry_path`,
  `name_signature_message`, `sign_bundle`,
  `verify_checked_signature` and `verify_name_signature`, and task 011's
  package record: `domain_separated_digest`,
  `PackageRecord::package_record_payload`, `sign_package_record`,
  `verify_checked_package_record` and `verify_package_record`, and task
  049's `sign_cid_record` and `verify_cid_record`, the record's one signer
  and one verifier over a lab CID. Each answers
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
they model no grant. The lab's stand-in launcher, in test code, models only a
launch route's refusals before launch and a grant view that a launch leaves
empty ([below](#lab-stand-in-launcher-m1-check-b1)); it is not the Runtime's
admission, and a launch there grants nothing.

Claim scope: one Mac, these fixtures, test keys only.

## Lab package record (outside the bundle)

Anders's answer splits the package CID from the publisher. The CID names
the bytes. A separate signed record names the signer and binds that CID.
`PackageRecord` is that record, in the lab. It stays outside the bundle.
The record binds a lab CID however it was computed: a folder walk
(`lab_cid`), a checked bundle (`checked_bundle`), entries (`encode_entries`)
or a closure listing (`encode_listed_files`). Since task 049 one call signs it
and one call checks it, both over a `LabCid`: `sign_cid_record` and
`verify_cid_record`. The folder and checked calls are the walk, or the checked
bundle's CID, and then those calls.

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

**Sign.** `sign_cid_record(key, cid)` is the one place a record is built and
signed. It sets `cid` to the `LabCid`'s printed form and `signer_did` with the
one DID encoder (`elastos_identity::encode_signing_key_did`, the same call
`sign_bundle` uses), and signs the digest above. It reads and writes no file.
`sign_package_record(key, bundle)` is `lab_cid(bundle)` and then
`sign_cid_record`. A refusal from that walk passes through unchanged, and a
refused bundle gets no record. Neither call changes a bundle byte, and the
manifest's `signature` field stays empty.

**Verify.** `verify_cid_record(cid, record, accepted)` is the one place a
record is checked. It checks in this order. The first refusal is the answer,
and it reads nothing from disk:

1. Decode `record.signer_did` with the one DID decoder. On error: `signer DID <did> is not a canonical Ed25519 did:key: <the decoder's own text>`.
2. The DID is an exact member of `accepted`, the explicit list (no trust
   policy). An empty list refuses every signer: `signer <did> is not in the
   accepted list`.
3. `record.cid` equals `cid`'s printed form. Otherwise: `record names
   <record cid>; the bundle names <cid>`.
4. Ed25519 over the digest of the record domain and
   `package_record_payload(record)`, with the key from step 1. On failure:
   `signature by <did> does not verify over <record cid>`.

Steps 1, 2 and 4 are the name signature's own checks and reasons, from the
same functions (`decode_signer`, `require_accepted` and one shared Ed25519
check). Step 3 runs before step 4, so when the payload is hashed its CID is a
printed lab CID and its DID is canonical: neither holds a character JSON
would escape. `verify_checked_package_record(checked, record, accepted)` is
`verify_cid_record` over 009's `checked.cid()`, and
`verify_package_record(bundle, record, accepted)` is `checked_bundle(bundle)`
and then the checked form. Neither holds a check of its own, so a bundle the
walk refuses is refused first, with the walk's reason.
`Ok(())` grants nothing: it is no trust, admission or launch value.

**A name, not bytes.** `sign_cid_record` and `verify_cid_record` sign and
check a name. They read no byte, so the `LabCid` must come from
`encode_listed_files`, `encode_entries`, `lab_cid` or `checked_bundle`, which
name the bytes they read or were given. For a closure listing, the caller's
walk owns that each `sha256` and `size` are those of the bytes
([naming a closure listing](#naming-a-closure-listing)).

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
| One payload builder, one digest, one DID encoder and decoder, one Ed25519 check; the record is built and signed only in `sign_cid_record` and checked only in `verify_cid_record`; the folder and checked calls hold no build or check of their own | `record_paths_share_one_implementation` | F-CI11t, F-CI11u, F-CI11v, F-CI11w, F-CI49b |
| A closure listing's lab CID (the PH6 copy's pin) gets a record with the exact payload, and `verify_cid_record` passes it | `a_closure_listing_gets_a_package_record_by_its_cid` (`tests/closure_listing.rs`) | F-CI49c |
| For every pinned fixture, `sign_package_record` of the folder equals `sign_cid_record` of its `lab_cid`; on the PH6 copy with `viewer` as a string, a record over the listing's CID passes `verify_package_record` of the folder, and a record from the folder passes `verify_cid_record` over the listing's CID | `the_folder_record_is_the_cid_record` (`tests/closure_listing.rs`) | F-CI49b |
| `verify_cid_record` refuses as `verify_checked_package_record` does, with the same refusal and text: a record over the PH6 listing checked against the listing with one `sha256` byte changed (naming both CIDs), and the other way round; a signer not listed; an empty list; a flipped signature byte; a malformed DID | `cid_record_refuses_as_the_checked_record_does` (`tests/closure_listing.rs`) | F-CI49a |
| README's `record_payload` and `record_digest` give `package_record_payload`'s bytes and the signed digest for test-key records over `content-sample` and `web-app` | `readme_python_matches_the_package_record_bytes` (`tests/cross_implementation.rs`) | F-CI20a, F-CI20b, F-CI20c, F-CI20f, F-CI19d |

The tests are in `tests/package_record.rs`. Every refusal test runs both
verifiers, so a check that lives only in the path form fails it (F-CI11p to
F-CI11s move one check each into the path form). Every expected CID comes
from the pins in `tests/common/mod.rs`, never from a literal, so a change of
the printed form changes the pins in one place. The domains in these tests
are written out, not read from the library, so a changed domain constant
fails them (F-CI11x). F-CI11u, F-CI11v and F-CI11w also fail 004's
`signature_paths_share_one_implementation`. Task 049's three tests are in
`tests/closure_listing.rs`, beside the listing they sign. Every key in them is
generated in memory.

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

## Lab stand-in launcher (M1 check B1)

The shared `StandIn` in `lab/agent-conformance/standin-runtime/mod.rs` owns
instances, session ids, lifecycle and grants. `StandInRuntime` in
`tests/common/mod.rs` is this lane's fixture store and CID entry point; it
keeps the identity check and the planted seams, and it holds no instance list,
no grant list, no status string and no session counter (P10).
`tests/stand_in.rs` imports the shared module once, with
`#[path = "../../agent-conformance/standin-runtime/mod.rs"]`, and passes
closures that call `post_capsules`, `get_capability_list` and
`delete_capsule` on that one value. The shared module's own tests compile only
into that one test binary.

A launch names the bundle by its lab CID only. The shared `post_capsules`
takes `path`; this lane's `cid` body is a lab fixture entry point, not that
route. `commit_launch` runs the checks below, then calls the closure with
`{"path": <the stored folder>}`. A fixture registration through
`admit_resident` supplies a `Start` outcome; it neither verifies a publisher
nor executes the bundle. The lane holds a store (printed lab CID -> bundle
folder, filled at publish time by `published`, from `lab_cid` of the folder),
the package records and an explicit list of accepted publisher DIDs.

The checks run in this order, and the first refusal is the answer, with status
400 and nothing launched. Each library refusal is its `Refusal`'s own text,
unchanged, and the lane calls the lane's one parse, one walk, one name compare
and one record check, never a copy (P10):

| Check | Refused when | Reason | Named test |
| --- | --- | --- | --- |
| (a) `pre-CID, not B1 evidence` | the body is not a JSON object whose only key is `cid` with a string value; `path` is never a fallback | names the extra, missing or wrong-typed field, or says "an object" | `standin_launches_by_cid_only` |
| (b) `pre-CID, not B1 evidence` | `cid` does not parse as `LabCid` (`impl FromStr for LabCid`) | the parse's own reason | `standin_refuses_an_unsigned_or_mismatched_bundle_before_launch` |
| (c) `pre-CID, not B1 evidence` | the store holds no bundle under that CID | "no bundle is stored under" the CID | `standin_refuses_an_unsigned_or_mismatched_bundle_before_launch` |
| (d) | `checked_bundle` of the stored folder refuses (here: `capsule.json` removed after publish) | the walk's own refusal | `standin_refuses_an_unsigned_or_mismatched_bundle_before_launch` |
| (e) | `CheckedBundle::check_name(cid)` refuses: the stored bytes changed after publish (here: one byte of `asks.json`) | the compare's own refusal, naming both CIDs | `standin_refuses_an_unsigned_or_mismatched_bundle_before_launch` |
| (f) | no record's `cid` equals the requested CID | starts "unsigned:" and names the CID | `standin_refuses_an_unsigned_or_mismatched_bundle_before_launch` |
| (g) | `verify_checked_package_record` refuses every record that binds the CID: a signer not accepted, an empty accepted list, a flipped signature byte | the first such record's own refusal, in store order | `standin_refuses_an_unsigned_or_mismatched_bundle_before_launch`, `standin_launch_does_not_depend_on_record_order` |

**Several records for one CID.** More than one package record can bind the
same CID, for example one by a signer the stand-in does not accept and one by
a signer it does. Checks (f) and (g) take every record that binds the
requested CID, in store order, and the launch goes on when at least one of
them passes `verify_checked_package_record`. So the answer does not depend on
the records' order. When none passes, the answer is the first such record's
own refusal, unchanged, so a single record is refused with exactly its own
text; with no record at all, the answer is the "unsigned:" text.
`standin_launch_does_not_depend_on_record_order` launches one instance from
`[unaccepted signer, accepted signer]` and from the reverse, and refuses two
records by two unaccepted signers with the first one's "not in the accepted
list" text, listing no instance.

Only then `commit_launch` calls the shared `post_capsules` with the stored
folder as `path`, and the answer is the shared answer, unchanged: `id`,
`name`, `status: starting` and `session_id`, with `session_id` equal to `id`.
The shared `finish_start` applies the registered `Start` and moves that
instance to `running`; `Start::Ok` is the test's supplied outcome, so it
proves no real start and no execution. `get_capsules` answers
`{"capsules": [...]}` with `id`, `name`, `status`, `session_id` and `cause`
(`""` while the instance starts or runs), sorted by `id`. The stopped cause is
`stopped: <reason>`. A refused launch leaves the shared instance and grant
lists unchanged. `standin_launches_a_signed_bundle_by_its_cid` runs the
journey on the `agent-host` fixture: published under its pin, its record
signed by a fresh test key whose DID is accepted, registered once at its path,
launched by CID, listed once as `starting`, then moved to `running` by
`finish_start`. Its lab CID and its parent's listing stay unchanged, and a
repeat of the same signed CID uses the same registered path and creates a
second shared instance.

A valid signature alone yields no grant. The shared shell grant view,
`get_capability_list(Caller::Shell, Some("all_sessions_live"))`, answers
`{"scope": "all_sessions_live", "capabilities": [...]}`, one entry per held
live grant with `request_id`, `session_id`, `resource`, `action`, `duration`
and `granted_at`. No launch adds a grant, although the `agent-host` manifest
asks for one in `capabilities` and its record verifies. The lane calls that
view and the shared seed through one seam each: `live_grants` answers the
closure's value unchanged, and `grant_request_id(n)` gives the shared
`seed_grant` its `grant-{n}` request id. A stop through `apply_stop` calls the
shared `delete_capsule`, which stores `stopped` and revokes that session's
live grants; the sibling instance and its grant stay.
`standin_valid_signature_alone_yields_no_grant` launches the signed bundle
twice: each launch gives its own instance and session, and the view lists no
entry. `standin_grant_view_lists_a_seeded_grant` seeds one grant for the
launched session and finds it listed with all six keys and the seeded values.
`standin_shared_stop_updates_the_same_instances_and_grants` launches two,
seeds one live grant for each, stops one through `apply_stop`, and reads the
same shared object: the stopped instance is listed as `stopped` with its
reason, its grant has gone, and the sibling stays `running` with its grant.
Task 007's `valid_signature_grants_nothing_by_itself` shows the library leaves
no standing approval; these tests show the shared stand-in's launch adds no
grant and its stop removes one.

Each route, field and state, and where it comes from. #309 is draft PR #309,
`lab/runtime-asks/` at `513988ebd` (branch `cursor/runtime-asks-ad52`);
`routes.rs` is `elastos/crates/elastos-server/src/api/routes.rs`, read only.

| Route, field or state | Source |
| --- | --- |
| `POST /api/capsules` (`post_capsules` on the shared `StandIn`) | #309 `06-resident-instances-core.md:24` (RI-2) |
| `GET /api/capsules` (`get_capsules` on the shared `StandIn`) | #309 `06-resident-instances-core.md:25` (RI-3); today's `list_capsules`, `routes.rs:47` |
| request field `cid` | lab fixture entry point, not the shared route; the shared body's only field is `path`, and today's Runtime route also takes `path` (`routes.rs:65-66`) |
| answer `id`, `name`, `status`, `session_id` | shared `post_capsules`, which answers `starting` before `finish_start`; `LaunchResponse`, `routes.rs:74-78` |
| answer and list `session_id` | #309 `06-resident-instances-core.md:24` (RI-2); the shared instance id |
| list `status` and `cause` | #309 `06-resident-instances-core.md:25` (RI-3) |
| states `starting`, `running`, `stopped`, `failed` | shared `StandIn`; `finish_start` moves a started instance to `running` |
| state "refused": status 400 and the reason | the lane's CID checks; `routes.rs:116`, `Err((StatusCode::BAD_REQUEST, e.to_string()))` |
| grant view `GET /api/capability/list?scope=all_sessions_live` (`get_capability_list(Caller::Shell, Some("all_sessions_live"))` on the shared `StandIn`): `scope` `all_sessions_live`, `capabilities` entries with `request_id`, `resource`, `action`, `duration`, `granted_at` and `session_id` | #309 `01-live-grant-view.md:11` (a shell session reads every session's live grants) and `:83` (the `scope` marker and the session id per entry), at `513988ebd`; entry keys and `capabilities` from `CapabilityOutput` and `ListCapabilitiesOutput`, `elastos/crates/elastos-server/src/api/handlers/capability.rs:411-423` |
| grant seed `seed_grant` | shared lab test seam, not a route; #309 and this lab model no shell approval |
| asks read `asks_of` | lane lab test seam, not a route; #309 has no asks field on any route (RA-1 to RA-7) |
| CID launch `commit_launch` | lane lab test seam, not a route: the fixture-only composition from a verified CID to the shared `path` body |
| grant view seam `live_grants` | lane lab test seam, not a route |
| request id `grant_request_id` | lane lab test seam, not a route |
| stop `apply_stop` | lane lab test seam, not a route; the shared `delete_capsule` does the work |

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| A launch runs every check; a stub that answers a launch at once fails | `standin_launches_by_cid_only`, `standin_refuses_an_unsigned_or_mismatched_bundle_before_launch` | F-CI32a (the planted stub) |
| (e) bytes changed after publish are refused by the name compare | `standin_refuses_an_unsigned_or_mismatched_bundle_before_launch` | F-CI32b ((e) removed; the case then fails at (g) with another reason) |
| (g) the record check refuses before launch | `standin_refuses_an_unsigned_or_mismatched_bundle_before_launch` | F-CI32c ((g) removed) |
| (f) a CID with no record is refused as unsigned | `standin_refuses_an_unsigned_or_mismatched_bundle_before_launch` | F-CI32d (a missing record launches) |
| (f) and (g) every record for the CID is checked, so the launch does not depend on the records' order | `standin_launch_does_not_depend_on_record_order` | F-CI36b (only the first record for the CID is checked) |
| (a) `path` is never a fallback | `standin_launches_by_cid_only` | F-CI32e (a body with `path` is looked up by its folder) |
| A refused launch leaves the shared list with no instance | `standin_launches_by_cid_only`, `standin_refuses_an_unsigned_or_mismatched_bundle_before_launch` | F-CI32f (a fixture is launched before the checks) |
| A launch answer has its listed shared instance | `standin_launches_a_signed_bundle_by_its_cid` | F-CI32g (answers a launch body, calls no shared launch) |
| A valid signature alone yields no grant: no launch adds one, and the answer and the list hold no grant key | `standin_valid_signature_alone_yields_no_grant` | shared-owned: the shared `StandIn` creates no grant on launch; F-CI33a is retired with that disposition |
| The grant view lists every held grant of every session, so it is not a constant | `standin_grant_view_lists_a_seeded_grant`, `standin_grant_view_lists_every_held_grant_of_every_session` | F-CI33b (the view answers no entries whatever is held), F-CI37a (only the first held grant), F-CI37b (only the first held grant's session), F-CI37c (one `request_id` for every grant) |
| The grant view answers under the `all_sessions_live` marker | `standin_valid_signature_alone_yields_no_grant`, `standin_grant_view_lists_a_seeded_grant` | F-CI33c (the marker dropped) |
| A stop through the seam updates the same shared instances and grants: the stopped entry carries its reason, its grant goes, and the sibling stays running with its own grant | `standin_shared_stop_updates_the_same_instances_and_grants` | F-CI59a (the seam answers null and calls no shared stop) |

Not shown:

- The real Runtime ran nothing here, and it still launches by path
  (`routes.rs:65-66`, `LaunchRequest { path, ... }`). No sentence here says
  the Runtime launched, checked, refused or granted anything. The empty grant
  view is the shared stand-in's, not the Runtime's.
- No code is executed: a launched instance is a record. There is no HTTP
  server, socket, process start or wasm execution. `Start::Ok` is supplied by
  the test at registration and applied by `finish_start`; it proves no start,
  no publisher verification and no execution.
- No shell approval is modelled; a grant exists only through the shared test
  seam `seed_grant`. A stop revokes that session's live grants. There is no
  pending request, token, expiry or capability check, and no grant route.
- `principal_id` and `launch_grant` (`routes.rs:65-71`) are left out.

Claim scope: one Mac, the `agent-host` fixture, test keys only, records in
memory.

### Asks come only from the signed bytes (M1 check B2, no-schema part)

A launched instance is handed its asks only as the `asks.json` bytes of the
checked bundle that passed every check above. `checked_launch` takes the
content of the `asks.json` entry (`CheckedBundle::entries()`) from the one
`CheckedBundle`, the one walk (P10), and `commit_launch` keeps that content
under the shared launch's `session_id`, once: `Some(bytes)`, or `None` when
the bundle has no `asks.json`. Nothing reads the folder again. Task 044 shows
that for the launch itself: `set_after_walk`, a lab test seam, not a route,
gives `checked_launch` a hook that it calls once on the stored folder, right
after the one walk and before (e), so a test can change the bytes on disk
between the walk and the launch. With no hook set, nothing is called.
`asks_of(session_id)`, a lab test seam, not a route (#309 has no asks field on
any route), answers that snapshot, and `None` for an unknown session.
The launch answer, the shared list entry and the grant view keep exactly the
keys above, with no asks key, and the CID launch body stays `{"cid"}`.

After those checks and before the shared launch, `commit_launch` parses those
bytes once with `provisional_asks`, the lane's provisional lab stand-in schema,
not the Runtime manifest: a JSON object whose only keys are `schema`
(`elastos.agent-host.asks/v1`) and `asks`, an array whose elements are objects
with only `kind` and `resource`, both non-empty strings. It keeps the
`(kind, resource)` pairs in file order beside the bytes under the same
`session_id`. `declared_asks_of(session_id)`, a lab test seam, not a route,
answers those pairs without parsing again or reading the folder. A declaration
that fails this parse refuses the launch with its own reason and status 400, so
the shared instance and grant lists do not change. The library encoder still
does not parse those bytes: for the lab CID, `asks.json` is one more payload
file. A matching signature adds no grant; the declaration is part of the named
artifact, not a permission.

`standin_hands_an_instance_only_its_signed_asks_bytes` launches the signed
`agent-host` bundle as in the journey above: its session answers the
committed `fixtures/agent-host/asks.json` bytes. Then one byte of the stored
`asks.json` changes. The session still answers the signed bytes, and a second
launch of the same CID is refused by (e), the name compare's own refusal, with
no new instance and an empty grant view.
`standin_gives_each_session_its_own_asks` launches `agent-host` and `web-app`
(which has no `asks.json`), each signed by a fresh test key, in both orders:
the `agent-host` session answers its bytes, the `web-app` session answers
`None`, and so does an unknown session.
`standin_takes_the_asks_from_the_walk_not_the_folder` launches the same signed
bundle with a hook that changes one byte of the stored `asks.json`: the launch
answers `starting`, the stored `asks.json` no longer equals the committed
fixture bytes (so the hook ran), and the session answers the committed fixture
bytes, which the test reads itself. Before task 044, a launch that read
`asks.json` from the folder after the walk passed both tests above, because
neither changes the folder between the walk and the launch.
`standin_reads_declared_asks_from_the_signed_manifest` launches the signed
`agent-host` bundle through the same entry point: the answer is the shared
`starting` status, `declared_asks_of` equals the pairs read from the committed
`fixtures/agent-host/asks.json` with `serde_json::Value`, in file order, with
`read` and `<principal>/` first, `asks_of` equals those fixture bytes, and the
grant view's `capabilities` is empty. Changing the stored `read` kind to `reed`
leaves the first session's declaration and refuses the same CID by (e). Signed
sibling bundles from one fresh accepted test key refuse each malformed
declaration with its own reason and no instance: a wrong schema, an extra root
field, an extra ask field, an empty kind, an empty resource, JSON that does not
parse, a missing or untyped `schema`, a missing or non-array `asks`, a
non-object ask, and a missing or untyped `kind` or `resource`. A signed unknown
kind launches and is declared as it is, a signed `web-app` bundle launches and
declares nothing, and an unknown session declares nothing.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| The instance keeps the signed bytes from launch; a change on disk after launch does not reach it | `standin_hands_an_instance_only_its_signed_asks_bytes` | F-CI35a (the planted accept-anything stub: `asks_of` reads `asks.json` from the stored folder at call time) |
| Each session answers its own asks | `standin_gives_each_session_its_own_asks` | F-CI35b (`asks_of` ignores the session and answers the first snapshot's asks) |
| A bundle with no `asks.json` is handed `None`, not empty bytes | `standin_gives_each_session_its_own_asks` | F-CI35c (`Some(Vec::new())` for a bundle with no `asks.json`) |
| A change on disk between the walk and the launch does not reach the instance | `standin_takes_the_asks_from_the_walk_not_the_folder` | F-CI44a (the 041 review's stub: `checked_launch` reads `asks.json` from the stored folder at launch), F-CI44b (the hook is never called), F-CI44c (the hook runs before the walk, so (e) refuses) |
| The declaration is parsed once from the checked bytes with the provisional schema, refusing each wrong shape | `standin_reads_declared_asks_from_the_signed_manifest` | F-CI78a (the schema id is never compared), F-CI78b (an empty kind counts as present), F-CI78c (the root unknown-field check is skipped) |

Not shown:

- The stand-in parses the provisional declaration described above; the library
  encoder still does not parse `asks.json` for the lab CID, where it is one
  more payload file.
- No mapping of an ask to an operation; that is `lab/bus-v2-proposal/`, and
  this lane writes no B2 encoding.
- No grant from an ask: a launch still adds none (the grant view above).
- The Runtime hands no asks to anything here; `asks_of` is the lane's.

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
on every filesystem. Not checked here: Linux and the Runtime's IPFS CID. The outside check is the
README's Python block, written from the byte rules: the committed test
`readme_python_recomputes_every_lab_cid_pin` runs it with `python3 -I` (Python
3.9.6 on this Mac) and requires it to give every pin and the Rust encoder's
value for the same files. The tests pin the balanced file layout at one and
two levels (one raw leaf; a balanced file root over 2 to 174 raw leaves since
task 048; and since task 076 a two-level root, such as the 175-leaf file of a
174-leaf node and a one-leaf node), a basic directory on both sides of the
256KiB links estimate and the HAMT shard above it (task 077).

The claim is "Kubo v0.40.1 profile, computed by the lab", and nothing more.
One offline Kubo v0.40.1 hash-only import, with the Runtime's profile flags,
was run on this Mac and printed every committed pin, and the lab CID is not
called equal to the Runtime's CID or to Kubo's output. The Runtime's CID names a release archive, not the bundle's
files (see [Why a lab CID](#why-a-lab-cid-and-not-the-runtimes-cid)). The test
`the_lab_cid_claim_stays_computed_by_the_lab` keeps this: these two sections
and the module doc of `src/lib.rs` say the claim word for word, this section
states the gate, and no `*.md` file of the lane outside `tests/` and no file
under `src/` holds a phrase from its list of equality claims (`EQUALITY_CLAIMS` in
`tests/common/mod.rs`), in any case and across line breaks. The scan reads
every such file that git tracks or would track: an untracked file that git
does not ignore counts, so a new doc is read before it is committed, and an
ignored one such as `target/` does not. Quote and comment markers and word
emphasis do not hide a claim: a line loses its leading `//!`, `///` or `//`
and then any run of leading `>` (so `> > text` reads as `text`), and each word
loses every `` ` ``, `*` and `_` at its ends (`*the*` reads as `the`; a mark
inside a word, such as the hyphen of a hyphenated word, stays). A word that was only marks,
such as the `*` that starts a block-comment line, is dropped, so it never
splits a phrase. Other Markdown forms (links, HTML, tables, headings, escapes)
are not read through. A known limit, not a rule: trimming stops at
punctuation, so a mark next to a comma or a full stop inside a phrase
(`*Runtime's*,`) is not trimmed, nor is a mark after an opening bracket
(`(*Runtime's*`), and a claim written that way is not found.
Matching is by substring, so this matters only when the marked word is not
the phrase's last word. No test asserts this limit.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| A run of leading `>` is removed, so a claim over two blockquote lines is found | `the_claim_scan_finds_a_claim_however_it_is_written` | F-CI28a (`>` kept) |
| A word that was only marks is dropped, so a claim over two ` * ` block-comment lines is found | `the_claim_scan_finds_a_claim_however_it_is_written` | F-CI28b (the empty word kept) |
| `*` is trimmed from a word's ends, so emphasis inside a claim (`*the*`) does not hide it | `the_claim_scan_finds_a_claim_however_it_is_written` | F-CI28c (`*` not trimmed) |
| `` ` `` is trimmed from a word's ends, so a word in code marks inside a claim (`` `Runtime's` ``) does not hide it | `the_claim_scan_finds_a_claim_however_it_is_written` | F-CI28d (`` ` `` not trimmed) |
| `_` is trimmed from a word's ends, so underscore emphasis inside a claim (`_Runtime's_`) does not hide it | `the_claim_scan_finds_a_claim_however_it_is_written` | F-CI30a (`_` not trimmed) |
| A run of leading `>` is removed, not only one, so a claim over two nested blockquote lines (`> > text`) is found | `the_claim_scan_finds_a_claim_however_it_is_written` | F-CI30b (only one `>` removed; the one-`>` case still passes) |

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
consumer-fixtures/       photo-stand-in-photo-set: the photo lane's PH6 fixture,
                         byte for byte from examples/photo-viewer/host-test/
                         fixtures/stand-in-photo-set/ at d047a069a; not a
                         fixture (its manifest fails the Runtime parse)
recipes/                 provider-variant.recipe, the variants' lab stand-in recipe
tests/common/mod.rs      assembly, pins, the bounded call, observers, wc-001 driver,
                         the library's code for tests that read it, fresh test keys,
                         the refusal asserts both signature checks share, the
                         key-material scan, the python3 -I run of README's blocks,
                         the cargo metadata scan for lab crates that use this one,
                         the claim scan of the lane's docs and src/, the check
                         of the falsifier list's inventory, and the lab stand-in
                         launcher's fixture store and CID entry point (the seams
                         commit_launch, live_grants, grant_request_id and
                         apply_stop; the shared StandIn owns instances, sessions,
                         lifecycle and grants)
tests/adoption.rs        the adoption note lists every lab CID consumer; Cargo's
                         reader decides; the scan writes nothing
tests/bytes.rs           every byte is the name: manifest, payload, asks.json, files
tests/check_name.rs      a claimed name is checked, never trusted; one naming path
tests/checked_bundle.rs  the name and the bytes it covers; the checked name check
tests/claims.rs          the claim stays "Kubo v0.40.1 profile, computed by the lab"
tests/closure_listing.rs a closure listing gets the lab CID of its folder; the PH6
                         manifest is refused; a listed file over one chunk is refused;
                         the listing's CID gets the one package record
tests/cross_implementation.rs
                         README's Python rule, the pins and the encoder agree;
                         README's two digest blocks and the signed bytes agree
tests/encoding.rs        order, boundaries, the printed form, one file per path,
                         each UnixFS profile setting
tests/fixtures.rs        Runtime manifest checks, pins, the wc-001 bundle
tests/inventory.rs       falsifiers.json's task list and README's count match
                         the list
tests/kinds.rs           app, provider and model share the package rules; one closure
tests/location.rs        folder name, place, URL, Store rows, times, modes: not the name
tests/name_signature.rs  a test key signs the printed lab CID; verification only
tests/not_admission.rs   verify is not admit: a valid signature grants nothing
tests/package_record.rs  the lab package record outside the bundle binds the CID
tests/parse.rs           a printed lab CID is read with the one claim check
tests/refusals.rs        each refusal and its reason
tests/stand_in.rs        the shared StandIn, imported once; a launch by CID after
                         the publisher check; a valid signature alone yields no
                         grant; an instance keeps only its signed asks.json bytes;
                         a stop updates the same instances and grants
tests/variant_binding.rs the signed variant binding outside the bundles
tests/walk.rs            changes made while a bundle is named; one walk
falsifiers.json          planted bugs, each caught by named tests
```

## Falsifiers

`falsifiers.json` holds 302 planted bugs in the provider format: round 1's
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
[for a lab that uses the lab CID](#for-a-lab-that-uses-the-lab-cid)), and task
028's F-CI28a to F-CI28d (see [claim scope](#claim-scope)), and task
029's F-CI29a to F-CI29e (see [the inventory check](#the-inventory-check)),
and task 030's F-CI30a and F-CI30b (see [claim scope](#claim-scope)), and
task 031's F-CI31a and F-CI31b (see [the inventory check](#the-inventory-check)),
and task 032's F-CI32a to F-CI32g, task 033's F-CI33b and F-CI33c and task
035's F-CI35a to F-CI35c (all three: see
[the stand-in launcher](#lab-stand-in-launcher-m1-check-b1)), and task 036's
F-CI36a (see [the checked bundle](#checked-bundle-the-name-and-the-bytes-it-covers))
and F-CI36b (see [the stand-in launcher](#lab-stand-in-launcher-m1-check-b1)),
and task 037's F-CI37a to F-CI37c (see
[the stand-in launcher](#lab-stand-in-launcher-m1-check-b1)), and task 044's
F-CI44a to F-CI44c (see
[asks come only from the signed bytes](#asks-come-only-from-the-signed-bytes-m1-check-b2-no-schema-part)),
and task 047's F-CI47a to F-CI47c (see
[naming a closure listing](#naming-a-closure-listing)), and task 048's
F-CI48a to F-CI48e (see [the encoding](#the-encoding)), and task 049's
F-CI49a to F-CI49c (see
[the lab package record](#lab-package-record-outside-the-bundle)), and task
059's F-CI59a to F-CI59c (F-CI59a: see
[the stand-in launcher](#lab-stand-in-launcher-m1-check-b1); F-CI59b and
F-CI59c: see [what it is](#what-it-is-and-what-it-is-not)), and task 076's
F-CI76a and F-CI76b (see [the encoding](#the-encoding)), and task 077's
F-CI77a to F-CI77l (see [the encoding](#the-encoding); F-CI77k and F-CI77l:
see [the cross-implementation check](#the-cross-implementation-check)), and
task 071's F-CI71a and F-CI71b (see [the encoding](#the-encoding)) and
F-CI71c to F-CI71e (see
[the cross-implementation check](#the-cross-implementation-check)), and task
072's F-CI72a (see [the encoding](#the-encoding)), and task 084's F-CI84a
(see [the encoding](#the-encoding)).
Task 077 moves F-CI18h to the links estimate, F-CI18m to the shared Tsize
rule, F-CI19c to the missing-block empty result caught by the 21-bundle count,
F-CI23b to the new module-doc sentence,
and F-CI48c and F-CI48d to the shared Tsize rule's one place.
Each has `"command": "capsule-identity"` and `expect: "caught"`, and counts
only when every named test fails for its stated reason, never from a build
error. Every entry edits a file the runner restores after a killed run. Its
recovery list (`PROVIDER_TARGETS` in `examples/agent-host/falsify.py`) names
five files of this lane: `src/lib.rs`, `tests/common/mod.rs`,
`fixtures/wc001-core/capsule.json`, `.gitignore` and `README.md`. F-CI4h
edits this lane's `.gitignore`, F-CI4i, F-CI59b and F-CI59c edit this file,
and every other entry
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
Task 028's entries all edit `tests/common/mod.rs`, in the claim scan: F-CI28a
in `comment_body`, F-CI28b in `equality_claims_in`, and F-CI28c and F-CI28d in
`WORD_MARKS`, which `claim_word` trims. Each anchor is a line task 028 added,
found exactly once. Task 028 kept the anchor lines of F-CI23e to F-CI23h byte
for byte and changed no older edit's text.
Task 030's entries also edit `tests/common/mod.rs`, in the claim scan, which
it does not change: F-CI30a removes the `'_'` line of `WORD_MARKS`, and
F-CI30b shares F-CI28a's anchor, the `>`-run line of `comment_body`, and
removes one `>` where F-CI28a removes none. Each anchor is found exactly once.
Task 030 added two cases to the named test and changed no older edit's text.
Task 032's entries all edit `tests/common/mod.rs`, in the lane's stand-in:
F-CI32a and F-CI32f in `post_capsules`, F-CI32b to F-CI32d in
`checked_launch`, F-CI32e in `launch_cid` and F-CI32g in `launch`. Each anchor
is a line task 032 added, found exactly once (F-CI32a and F-CI32f share the
check line, and F-CI32c and F-CI32d the record-check line). Task 032 changed no
older edit's text. Task 059 moved F-CI32a, F-CI32f and F-CI32g onto
`commit_launch`; their ids, bugs and named tests stay.
Task 033's entries also edit `tests/common/mod.rs`, in the lane's stand-in:
F-CI33a in `post_capsules` (its anchor, the `Ok(self.launch(name))` line, was
part of F-CI32f's anchor and found exactly once), and F-CI33b and F-CI33c in
`get_capability_list_all_sessions_live`, each anchor a line task 033 added,
found exactly once. Task 033 changed no older edit's text. Task 059 retired
F-CI33a, because the shared `StandIn` now owns the rule it broke, and moved
F-CI33b and F-CI33c onto `live_grants`; their ids, bugs and named tests stay.
Task 035's entries also edit `tests/common/mod.rs`, in the lane's stand-in:
F-CI35a and F-CI35b in `asks_of`, and F-CI35c in `signed_asks`, each anchor a
line task 035 added, found exactly once. Task 035 made `checked_launch` answer
the name and the asks together, so `post_capsules` read
`let (name, asks) = ...` and `Ok(self.launch(name, asks))`. The anchors and
replacements of F-CI32a, F-CI32f and F-CI33a changed only by that: F-CI32a's
stub was `(String::from("stub"), None)`, and F-CI32f's and F-CI33a's
`launch` calls took `asks` (F-CI32f's early call took `None`). Their titles
and tests were unchanged, and each anchor was still found exactly once. Task
059 changed F-CI35a's and F-CI35b's anchors with the asks map; both keep their
bug and named test.
Task 036's F-CI36a edits `src/lib.rs`, in `CheckedBundle::manifest_name`, and
F-CI36b edits `tests/common/mod.rs`, in the stand-in's `check_records`; each
anchor is a line task 036 added, found exactly once. Task 036 moved seventeen
older edits, each with its same bug and the same tests. `check_manifest` now
returns the WASM flag and the manifest's `name`, and the seam reads
`let (wasm, name) = check_manifest(&manifest.content)?;`, so F-CI1k, F-CI1l,
F-CI3a, F-CI3b, F-CI3i and F-CI12a anchor on that line, F-CI1f and F-CI9c
set an empty name beside the `false` flag, and F-CI1g's fallback returns
`Ok((false, String::new()))`. `CheckedBundle` gained its `name` field, so
F-CI9a, F-CI9b, F-CI9d, F-CI9e and F-CI9j build or define it with that field.
The stand-in's record lookup moved into `check_records`, so F-CI32c now
replaces the record check there and F-CI32d answers `Ok(())` where no record
binds the CID. The stand-in imports neither `CapsuleManifest` nor
`MANIFEST_FILE`.
Task 037's entries also edit `tests/common/mod.rs`, in the lane's stand-in:
F-CI37a and F-CI37b in `get_capability_list_all_sessions_live`, on F-CI33b's
anchor line (found exactly once; entries may share an anchor), and F-CI37c in
`seed_grant`, its anchor a line task 033 added, found exactly once. Task 037
changed no older edit's text. Task 059 moved F-CI37a and F-CI37b onto
`live_grants` and F-CI37c onto `grant_request_id`; their ids, bugs and named
tests stay.
Task 044's entries also edit `tests/common/mod.rs`, in `checked_launch`:
F-CI44a on the answer line, F-CI44b on the hook call, and F-CI44c on the walk
line and the hook call together. Each anchor is found exactly once (F-CI44b's
line is part of F-CI44c's anchor). Task 044 changed no older edit's text, and
F-CI35a to F-CI35c's anchor lines stay byte for byte.
Task 059's entries move the stand-in plants onto the lane's four seams and
record one retirement. F-CI32a, F-CI32f and F-CI32g edit `commit_launch`;
F-CI33b, F-CI33c, F-CI37a and F-CI37b edit `live_grants`; F-CI37c edits
`grant_request_id`; F-CI59a edits `apply_stop`; and F-CI35a and F-CI35b edit
the asks map lookup in `asks_of`. F-CI59b and F-CI59c edit this file, each
deleting one of the two encoder sentences, and both name only
`the_lab_encoder_is_a_test_oracle`. F-CI33a is retired: the shared `StandIn`
now owns the rule that a launch adds no grant, so this lane has no seam where
that old bug could be planted; `standin_valid_signature_alone_yields_no_grant`
still checks the rule, and this paragraph is the disposition, outside the
count below. F-CI32b to F-CI32e, F-CI36b, F-CI35c and F-CI44a to F-CI44c keep
their ids, bugs and named tests; F-CI44a's answer line text changed with the
shared `path`, and F-CI35a's and F-CI35b's anchors changed with the asks map.
Task 047's entries all edit `src/lib.rs`, in `encode_listed_files`: F-CI47a on
the root line (`encode_directory(&root, "", &naming_hash)`), F-CI47b on the
leaf's `tsize` line, and F-CI47c on the size refusal. Each anchor is a line
task 047 added, found exactly once; F-CI47c shares F-CI18e's anchor (entries
may share one) and names its own test. Task 047 moved the leaf and the size
refusal from `encode_entries` into `encode_listed_files`, so four of task
018's edits anchor there now, each with its same tests: F-CI18c gives the leaf
the dag-pb codec, F-CI18e removes the size refusal, and F-CI18n makes an empty
file a dag-pb file node, each as before. F-CI18i still gives a file of at most
32 bytes an inline CID (identity multihash `0x00` and its length), but the
encoder holds a digest and no bytes now, so the first bytes of the digest stand
in for the file's bytes; its title says so. F-CI1g (task 005's) also names
`lab_cid_refuses_the_photo_manifest_the_runtime_type_refuses`. Every other
older edit's text is still found exactly once.
Task 048's entries all edit `src/lib.rs`: F-CI48a on the link-name line of
`put_links` (F-CI1b's and F-CI1p's anchor; entries may share one), which it
skips for an empty name, so only a file root's links change; F-CI48b and
F-CI48c in `file_root_block`; F-CI48d on `file_root`'s Tsize line; F-CI48e on
`MAX_FILE_LINKS`. Each anchor is found exactly once. Task 048 moved the leaf
into one `raw_leaf`, which `encode_listed_files`, `file_node` and `file_root`
all call, so the leaf's line is now `(cid_bytes(RAW_CODEC, sha256), size)`.
Four edits anchor there now, each with its same bug and tests: F-CI18c (the
dag-pb codec), F-CI18i (an inline CID for at most 32 bytes), F-CI18n (an empty
file as a dag-pb file node) and F-CI47b (every leaf's Tsize 0). Without the
move they would plant only in the listing call, and `lab_cid` would no longer
see them. The root line F-CI47a anchors on is now in `encode_tree`, where no
`ListedFile` is in scope, so its planted code lists the tree's files (path,
the leaf CID's digest, Tsize) itself; its title, bug and tests are the same.
The one-leaf refusal F-CI18e removed is now only the listing call's (F-CI47c
removes it). Task 076 removed the 174-leaf refusal and made the file tree any
depth, so F-CI18e, keeping its id, is retargeted: it changes the level loop to
run once (`if` in place of `while`) and names
`file_past_174_leaves_keeps_a_second_tree_level`; its title says so. F-CI48e's
`MAX_FILE_LINKS` edit stays and names that test. Task 076 moved
`file_root_block`'s blocksize write from a leaf's Tsize to its file size, so
F-CI48b's anchor is that loop. F-CI47c also names
`listed_file_over_one_leaf_names_the_bytes_call`.
Task 048 split `directory_block`'s link loop into `put_links` with the same
lines, so F-CI1b, F-CI1p and F-CI1q keep their text, and every other older
edit's text is still found exactly once.
Task 049's entries all edit `src/lib.rs`: F-CI49a removes the CID compare
call from `verify_cid_record`, F-CI49b makes `sign_package_record` build and
sign its own record under the name-signature domain, and F-CI49c makes
`sign_cid_record` sign the payload of a record with an empty `cid`. Each
anchor is found exactly once (F-CI49a shares F-CI11r's first anchor, and
F-CI49b F-CI11e's; entries may share one). Task 049 moved the record's build
into `sign_cid_record` and its four checks into `verify_cid_record`, and
`require_record_cid` now takes the `LabCid`. So six edits anchor on lines
whose text changed, each with its same bug and tests: F-CI11c, F-CI11i,
F-CI11j, F-CI11p and F-CI11r read `require_record_cid(cid, record)` (F-CI11c's
rebound record takes `cid.to_string()`, and F-CI11r's path form compares
against `held.cid()`), and F-CI15ae's anchor is the compare line
`if record.cid != cid.to_string() {`. `sign_package_record` is now
`lab_cid(bundle)?` and then `sign_cid_record`, so F-CI11k drops the
walk's refusal on `let cid = lab_cid(bundle)?;`, and F-CI11e writes the record
next to the bundle after that call. The titles of F-CI11p to F-CI11v name
`verify_cid_record`, and F-CI11w's names `sign_cid_record`, where their bug
is planted now. Every other older edit's text is the same and still found
exactly once.

### The inventory check

Two places say what this list holds: the `about` text names, in a
"(tasks ...)" list, every task that added entries, in the order the list
holds them, and the first sentence of this section gives the number of
entries. `the_falsifier_inventory_matches_the_list` (`tests/inventory.rs`)
checks both against the list's ids, so neither drifts when a task adds
entries. An id's task is the number after `F-CI`, as three digits (`F-CI1a` is
round 1 of task 001, which 005 carried). `falsifier_inventory_findings` in
`tests/common/mod.rs` reads one form only: one "(tasks NNN, NNN and NNN)" list
of three-digit items, ids `F-CI<n><letters>` (one to three digits, no leading
zero, lowercase letters), and one "holds N planted bugs" here, read word by
word. Anything else is refused with its own reason, never read as no
mismatch. The order is checked too: when every task is named and no task is
named without entries, `about`'s tasks must come in the order the list first
holds each task's entries, or that is finding (d), which gives both orders.
A task named twice in `about` is refused, not read as a mismatch. A repeated
id is not this check's: the runner's loader refuses the whole list with "an
id is used twice" (`examples/agent-host/falsify.py`), so the lane keeps no
second check for it (P10). It does not check the per-task paragraph above or
the tables row by row. Task 029's entries all edit `tests/common/mod.rs`, in
that helper, each anchor found exactly once; no entry edits
`falsifiers.json`, which the runner does not restore. Task 031's entries also
edit `tests/common/mod.rs`, in that helper: F-CI31a in the order compare of
`falsifier_inventory_findings`, F-CI31b in the repeat refusal of
`about_tasks`. Each anchor is a line task 031 added, found exactly once. Task
031 kept the anchor lines of F-CI29a to F-CI29e byte for byte and changed no
older edit's text.

| Rule | Named test | Falsifiers |
| --- | --- | --- |
| `about` and this section's count match the committed list | `the_falsifier_inventory_matches_the_list` | F-CI29d (an id's task is read from its first digit, so F-CI27d reads as task 002) |
| (a) a task with entries that `about` does not name is found | `the_falsifier_inventory_finds_each_mismatch` | F-CI29a (check (a) dropped) |
| (b) a task `about` names with no entry is found | `the_falsifier_inventory_finds_each_mismatch` | F-CI29b (check (b) dropped) |
| (c) a count that differs from the number of ids is found, with both numbers | `the_falsifier_inventory_finds_each_mismatch` | F-CI29c (the count compare dropped) |
| (d) `about`'s tasks out of the list's order are found, with both orders, when (a) and (b) find nothing | `the_falsifier_inventory_finds_each_mismatch` | F-CI31a (the order compare never reports) |
| No "(tasks ...)" list, two lists, an unclosed list, an item that is not three digits, an id of another form, and no or two count sentences are each refused with their own reason | `the_falsifier_inventory_refuses_what_it_cannot_read` | F-CI29e (no "(tasks ...)" list reads as naming no task) |
| A task named twice in `about` is refused, not read as an order finding | `the_falsifier_inventory_refuses_what_it_cannot_read` | F-CI31b (the repeat refusal removed) |

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
without an edit, 0 do not`; F-CI27a to F-CI27d each CAUGHT). At task
028 it reported `summary: 235 CAUGHT of 235` (`baseline: 124 named tests pass
without an edit, 0 do not`; F-CI28a to F-CI28d and F-CI23e to F-CI23h each
CAUGHT). At task 029 it reported `summary: 240 CAUGHT of 240` (`baseline: 127
named tests pass without an edit, 0 do not`; F-CI29a to F-CI29e each CAUGHT).
At task 030 it reported `summary: 242 CAUGHT of 242` (`baseline: 127 named
tests pass without an edit, 0 do not`; F-CI30a and F-CI30b, F-CI28a to
F-CI28d and F-CI23e to F-CI23h each CAUGHT). At task 031 it reported
`summary: 244 CAUGHT of 244` (`baseline: 127 named tests pass without an
edit, 0 do not`; F-CI31a and F-CI31b and F-CI29a to F-CI29e each CAUGHT).
At task 032 it reported `summary: 251 CAUGHT of 251` (`baseline: 130 named
tests pass without an edit, 0 do not`; with the id prefix `F-CI32`: 7 of 7).
At task 036 it reported `summary: 259 CAUGHT of 259` (`baseline: 136 named
tests pass without an edit, 0 do not`; with the id prefix `F-CI36`: 2 of 2,
and the seventeen moved edits each CAUGHT). At task 037 it reported
`summary: 262 CAUGHT of 262` (`baseline: 137 named tests pass without an
edit, 0 do not`; with the id prefix `F-CI37`: 3 of 3). At task 044 it
reported `summary: 265 CAUGHT of 265` (`baseline: 138 named tests pass
without an edit, 0 do not`; with the id prefix `F-CI44`: 3 of 3, and with
`F-CI35`: 3 of 3).
At task 047, run with the ids `F-CI47 F-CI18 F-CI1g` (the new entries, the
four task 018 entries it moved, with the rest of task 018's, and F-CI1g, which
gained a test), it reported `summary: 23 CAUGHT of 23` (`baseline: 16 named
tests pass without an edit, 0 do not`). The whole list was not run at task 047.
At task 048, run with the ids `F-CI48 F-CI18e F-CI47c`, it reported
`summary: 7 CAUGHT of 7` (`baseline: 4 named tests pass without an edit, 0 do
not`); run with the prefixes `F-CI1 F-CI18 F-CI19 F-CI47 F-CI48` (every edit in
`src/lib.rs`'s encoder and every entry task 048 moved, with F-CI10 to F-CI17,
which the prefix `F-CI1` also selects), it reported
`summary: 134 CAUGHT of 134` (`baseline: 80 named tests pass without an edit,
0 do not`). The whole list was not run at task 048.
The runner does not print why a test failed. Tasks 003, 009, 004, 007, 013,
014, 011, 012, 015, 016, 017, 018, 019, 020, 025, 023, 024, 027, 028, 029,
030, 031 and 032 prove each of their falsifiers by break, named test fails, revert.

The signature answers only whether this test key signed this lab CID.
