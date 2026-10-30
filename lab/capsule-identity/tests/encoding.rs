//! The lab CID encoding: entry order, path and content boundaries, the
//! printed form, one file per path, and the UnixFS profile settings, each
//! with its own test.
mod common;

use capsule_identity::{
    encode_chunked_files, encode_entries, encode_listed_files, lab_cid, BundleEntry, ChunkedFile,
    ListedFile, Refusal,
};
use common::*;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn entry(path: &str, content: &[u8]) -> BundleEntry {
    BundleEntry {
        path: path.to_owned(),
        content: content.to_vec(),
    }
}

/// A content-sample bundle with `extra` files added.
fn content_sample_with(extra: &[(&str, &[u8])]) -> TempDir {
    let bundle = assemble(&CONTENT_SAMPLE);
    for (path, content) in extra {
        write_file(bundle.path(), path, content);
    }
    bundle
}

fn name(bundle: &TempDir) -> String {
    lab_cid(bundle.path())
        .unwrap_or_else(|refusal| panic!("{refusal}"))
        .to_string()
}

#[test]
fn lab_cid_does_not_depend_on_listing_order() {
    // The encoder is given web-app's entries in every order. A directory
    // listing cannot be trusted to differ between two folders, so the
    // orders are made here.
    let entries: Vec<BundleEntry> = WEB_APP
        .files
        .iter()
        .map(|file| entry(file, &read_fixture(&WEB_APP, file)))
        .collect();
    let orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for order in orders {
        let listed: Vec<BundleEntry> = order.iter().map(|&i| entries[i].clone()).collect();
        let named = encode_entries(&listed).expect("name web-app's entries");
        // Every order gives web-app's pinned value, which lab_cid gives too.
        assert_eq!(named.to_string(), WEB_APP_LAB_CID, "order {order:?}");
    }
}

#[test]
fn path_and_content_boundaries_cannot_collide() {
    // `a` holding `bc` against `ab` holding `c`. A path is a link name
    // written with its protobuf length, and a file's bytes are its own leaf
    // block, named in the link by CID and with its length as Tsize, so no
    // name runs into bytes. Each side is pinned (both values recomputed by a
    // python3 -I check from the byte rules), so a name or a length written
    // another way fails here.
    let a_holding_bc = name(&content_sample_with(&[("a", b"bc")]));
    let ab_holding_c = name(&content_sample_with(&[("ab", b"c")]));
    assert_ne!(a_holding_bc, ab_holding_c);
    assert_eq!(
        a_holding_bc,
        "bafybeihll4iwwckjxiredqzpnkgeff53cxilm3sm5ks3ttk7wvc2xfem6m"
    );
    assert_eq!(
        ab_holding_c,
        "bafybeieuilb4vofk4f2lalufn3z6yzfght2zyw6qia57acxpc7bnt46msm"
    );

    // One file's bytes cannot carry the next entry's framing: `a` holding
    // `X`, the length 1, `b`, `Y`, against `a` holding `X` and `b` holding
    // `Y`.
    let mut carries_framing = b"X".to_vec();
    carries_framing.extend_from_slice(&1u64.to_be_bytes());
    carries_framing.extend_from_slice(b"bY");
    assert_ne!(
        name(&content_sample_with(&[("a", &carries_framing)])),
        name(&content_sample_with(&[("a", b"X"), ("b", b"Y")]))
    );

    // A path cannot carry its own framing: `a` holding `X`, the length 1,
    // `Y`, against a path made of `a`, the length 10 and `X`, holding `Y`.
    // No folder can hold that name (it has NUL bytes), so the encoder is
    // given the entries directly.
    let mut content = b"X".to_vec();
    content.extend_from_slice(&1u64.to_be_bytes());
    content.push(b'Y');
    let mut path = b"a".to_vec();
    path.extend_from_slice(&(content.len() as u64).to_be_bytes());
    path.push(b'X');
    let path = String::from_utf8(path).expect("NUL and newline bytes are UTF-8");
    assert_ne!(
        encode_entries(&[entry("a", &content)]).expect("name one entry"),
        encode_entries(&[entry(&path, b"Y")]).expect("name one entry")
    );
}

#[test]
fn lab_cid_prints_with_the_lab_label() {
    // The printed form is the root's CIDv1 in base32: `b`, then 58 lowercase
    // base32 characters, and `bafybei` is the base32 of `01 70 12 20` and the
    // digest's first 3 bits.
    let printed = name(&assemble(&CONTENT_SAMPLE));
    assert_eq!(printed.len(), 59, "{printed}");
    assert!(printed.starts_with("bafybei"), "{printed}");
    assert!(
        printed
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7')),
        "{printed}"
    );
    assert_eq!(printed, CONTENT_SAMPLE_LAB_CID);
}

#[test]
fn the_library_names_a_bundle_one_way() {
    // DR-1: the swap leaves no second scheme. No old printed form and no
    // framed stream remain, and the base32 alphabet is written once, in the
    // one lab copy that prints and reads a CID.
    let code = library_code();
    for old in ["lab-cid:sha256", "FRAMING_TAG", "LAB_CID_PREFIX"] {
        assert!(!code.contains(old), "the library still holds {old:?}");
    }
    assert_eq!(
        code.matches("abcdefghijklmnopqrstuvwxyz234567").count(),
        1,
        "the base32 alphabet is not in one place"
    );
}

#[test]
fn single_block_at_the_chunk_limit_has_the_pinned_cid() {
    // 262144 bytes is the largest file one raw leaf holds: it is named, as
    // one block. The big file is made here and never committed.
    let bundle = assemble(&CONTENT_SAMPLE);
    write_file(bundle.path(), "sample.example", &vec![0; 262_144]);
    assert_eq!(name(&bundle), CHUNK_LIMIT_LAB_CID);
}

#[test]
fn file_over_one_leaf_has_the_pinned_cid() {
    // One byte over the chunk limit: a balanced file root over two raw
    // leaves (262144 and 1 bytes), with empty link names, filesize and
    // blocksizes. Then a 600000-byte file one directory down: three leaves,
    // and the file root's Tsize reaches the root through `core/`. Both are
    // named through the walk and through the encoder, and both pins are
    // recomputed by README's Python rule. The big files are made here and
    // never committed.
    let manifest = entry(
        "capsule.json",
        &read_fixture(&CONTENT_SAMPLE, "capsule.json"),
    );
    let sample = read_fixture(&CONTENT_SAMPLE, "sample.example");
    let zeros = vec![0; 262_145];
    let big = big_bin_bytes();
    let two_leaves = assemble(&CONTENT_SAMPLE);
    write_file(two_leaves.path(), "sample.example", &zeros);
    let three_leaves = content_sample_with(&[(BIG_BIN, &big)]);
    for (bundle, entries, pin) in [
        (
            &two_leaves,
            vec![manifest.clone(), entry("sample.example", &zeros)],
            TWO_LEAF_FILE_LAB_CID,
        ),
        (
            &three_leaves,
            vec![
                manifest,
                entry("sample.example", &sample),
                entry(BIG_BIN, &big),
            ],
            THREE_LEAF_NESTED_LAB_CID,
        ),
    ] {
        let encoded = encode_entries(&entries)
            .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
            .to_string();
        assert_eq!(
            (name(bundle), encoded.as_str()),
            (pin.to_owned(), pin),
            "(lab_cid, encode_entries) against the pin"
        );
        assert!(pin.starts_with("bafybei"), "{pin}");
    }
}

#[test]
fn two_full_chunks_keep_both_leaves() {
    // 524288 bytes is exactly two 262144-byte chunks, so the one splitter in
    // `file_root` keeps two full raw leaves and the last leaf is full, not
    // short. The pin was first printed by README's Python rule; the file is
    // made here and never committed. A splitter that chunks all but the last
    // byte when the length is an exact multiple gets another CID, which this
    // pin refuses.
    let manifest = read_fixture(&CONTENT_SAMPLE, "capsule.json");
    let zeros = vec![0; 524_288];
    let bundle = content_sample_with(&[("sample.example", &zeros)]);
    let entries = vec![
        entry("capsule.json", &manifest),
        entry("sample.example", &zeros),
    ];
    let pin = TWO_FULL_CHUNK_LAB_CID;
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    assert_eq!(
        (name(&bundle), encoded),
        (pin.to_owned(), pin.to_owned()),
        "(lab_cid, encode_entries) against the pin"
    );
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");
    for other in [
        CHUNK_LIMIT_LAB_CID,
        TWO_LEAF_FILE_LAB_CID,
        THREE_LEAF_NESTED_LAB_CID,
    ] {
        assert_ne!(pin, other, "the two-full-chunk pin is another bundle's");
    }

    // A listed file names one raw leaf by one SHA-256, so 524288 bytes is over
    // its limit and is refused with its path rather than named by that digest.
    let listed = ListedFile {
        path: "sample.example".to_owned(),
        size: 524_288,
        sha256: Sha256::digest(&zeros).into(),
    };
    assert_eq!(
        encode_listed_files(&[listed]),
        Err(Refusal::FileOverChunkLimit {
            path: "sample.example".to_owned(),
            length: 524_288,
        })
    );
}

#[test]
fn exactly_174_leaves_stay_one_file_node() {
    // 45350913 bytes is exactly 174 raw leaves: 173 of 262144 bytes and a
    // last of 1 byte, so one depth-1 file node groups them all and the loop
    // in `file_from_digests` runs one pass. The length is not an exact
    // multiple of 262144, so a splitter that fires only on an exact multiple
    // still splits this file. The pin was first printed by README's Python
    // rule; the file is made here and never committed. A loop that skips a
    // full group of 174 leaves names the first leaf instead, which this pin
    // refuses.
    let manifest = read_fixture(&CONTENT_SAMPLE, "capsule.json");
    let zeros = vec![0; 45_350_913];
    assert_eq!(zeros.len().div_ceil(262_144), 174, "the leaf count");
    assert_eq!(zeros.len() % 262_144, 1, "the last leaf's size");
    let bundle = content_sample_with(&[("sample.example", &zeros)]);
    let entries = vec![
        entry("capsule.json", &manifest),
        entry("sample.example", &zeros),
    ];
    let pin = EXACT_174_LEAF_LAB_CID;
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    let mut chunks = Vec::with_capacity(174);
    let full = Sha256::digest(vec![0; 262_144]);
    for _ in 0..173 {
        chunks.push((full.into(), 262_144));
    }
    chunks.push((Sha256::digest([0u8]).into(), 1));
    let by_chunks = encode_chunked_files(&[
        ChunkedFile {
            path: "capsule.json".to_owned(),
            chunks: vec![(Sha256::digest(&manifest).into(), manifest.len() as u64)],
        },
        ChunkedFile {
            path: "sample.example".to_owned(),
            chunks,
        },
    ])
    .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
    .to_string();
    assert_eq!(
        (name(&bundle), encoded, by_chunks),
        (pin.to_owned(), pin.to_owned(), pin.to_owned()),
        "(lab_cid, encode_entries, encode_chunked_files) against the pin"
    );
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");
    for other in [
        SECOND_LEVEL_FILE_LAB_CID,
        TWO_LEAF_FILE_LAB_CID,
        THREE_LEAF_NESTED_LAB_CID,
        CHUNK_LIMIT_LAB_CID,
        TWO_FULL_CHUNK_LAB_CID,
    ] {
        assert_ne!(pin, other, "the 174-leaf pin is another bundle's");
    }

    // A listed file names one raw leaf by one SHA-256, so this file is over
    // its limit and is refused with its path rather than named by that digest.
    let listed = ListedFile {
        path: "sample.example".to_owned(),
        size: 45_350_913,
        sha256: Sha256::digest(&zeros).into(),
    };
    assert_eq!(
        encode_listed_files(&[listed]),
        Err(Refusal::FileOverChunkLimit {
            path: "sample.example".to_owned(),
            length: 45_350_913,
        })
    );
}

#[test]
fn a_file_of_174_full_leaves_has_the_pinned_cid() {
    // 45613056 bytes is exactly 174 full raw leaves of 262144 bytes, so one
    // depth-1 file node groups them all and its links name every leaf. The
    // length is an exact multiple of 262144, so a splitter that drops one
    // full chunk only at 174 times 262144 names another bundle here. The pin
    // was first printed by README's Python rule; the file is made here and
    // never committed.
    let manifest = read_fixture(&CONTENT_SAMPLE, "capsule.json");
    let zeros = vec![0; 45_613_056];
    assert_eq!(zeros.len(), 174 * 262_144, "174 full leaves");
    assert_eq!(zeros.len() % 262_144, 0, "the last leaf is full");
    let bundle = content_sample_with(&[("sample.example", &zeros)]);
    let entries = vec![
        entry("capsule.json", &manifest),
        entry("sample.example", &zeros),
    ];
    let pin = FULL_174_LEAF_LAB_CID;
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    let full = Sha256::digest(vec![0; 262_144]);
    let chunks = vec![(full.into(), 262_144); 174];
    let by_chunks = encode_chunked_files(&[
        ChunkedFile {
            path: "capsule.json".to_owned(),
            chunks: vec![(Sha256::digest(&manifest).into(), manifest.len() as u64)],
        },
        ChunkedFile {
            path: "sample.example".to_owned(),
            chunks,
        },
    ])
    .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
    .to_string();
    assert_eq!(
        (name(&bundle), encoded, by_chunks),
        (pin.to_owned(), pin.to_owned(), pin.to_owned()),
        "(lab_cid, encode_entries, encode_chunked_files) against the pin"
    );
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");
    for other in [
        TWO_FULL_CHUNK_LAB_CID,
        EXACT_174_LEAF_LAB_CID,
        SECOND_LEVEL_FILE_LAB_CID,
        TWO_LEAF_FILE_LAB_CID,
        CHUNK_LIMIT_LAB_CID,
    ] {
        assert_ne!(pin, other, "the 174-full-leaf pin is another bundle's");
    }

    // A listed file names one raw leaf by one SHA-256, so this file is over
    // its limit and is refused with its path rather than named by that digest.
    let listed = ListedFile {
        path: "sample.example".to_owned(),
        size: 45_613_056,
        sha256: Sha256::digest(&zeros).into(),
    };
    assert_eq!(
        encode_listed_files(&[listed]),
        Err(Refusal::FileOverChunkLimit {
            path: "sample.example".to_owned(),
            length: 45_613_056,
        })
    );
}

/// The leaves of task 072's file, in order: leaf `i`'s digest is the SHA-256
/// of `i` as 8 little-endian bytes; the 30276 full leaves are 262144 bytes
/// and the last is 1 byte.
fn three_level_leaves() -> Vec<([u8; 32], u64)> {
    (0..30_277u64)
        .map(|index| {
            let size = if index < 30_276 { 262_144 } else { 1 };
            (Sha256::digest(index.to_le_bytes()).into(), size)
        })
        .collect()
}

/// One [`ChunkedFile`] at `sample.example` over `chunks`.
fn chunked(chunks: Vec<([u8; 32], u64)>) -> ChunkedFile {
    ChunkedFile {
        path: "sample.example".to_owned(),
        chunks,
    }
}

#[test]
fn file_past_174_leaves_keeps_a_second_tree_level() {
    // One leaf past 174: 45613057 bytes (174 leaves of 262144 bytes and one
    // of 1 byte) needs a second tree level, a root of two depth-1 file nodes,
    // the first over 174 leaves and the second over one leaf. The pin was
    // first printed by README's Python rule. 174 leaves (45613056 bytes)
    // still encode, as one depth-1 root, with another CID. The file is made
    // in memory and never committed.
    let manifest = entry(
        "capsule.json",
        &read_fixture(&CONTENT_SAMPLE, "capsule.json"),
    );
    let mut file = vec![0; 45_613_057];
    let pin = SECOND_LEVEL_FILE_LAB_CID;
    let named = encode_entries(&[manifest.clone(), entry("sample.example", &file)])
        .unwrap_or_else(|refusal| panic!("175 leaves: {refusal}"));
    assert_eq!(named.to_string(), pin, "encode_entries against the pin");
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");

    file.truncate(45_613_056);
    let one_level = encode_entries(&[manifest, entry("sample.example", &file)])
        .unwrap_or_else(|refusal| panic!("174 leaves: {refusal}"));
    assert_ne!(one_level.to_string(), pin, "174 leaves has another CID");
}

#[test]
fn file_past_174_squared_leaves_keeps_a_third_tree_level() {
    // 30277 leaves: 30276 of 262144 bytes then one of 1 byte, 7936671745
    // bytes. 174^2 is 30276, so a third level is needed: 175 depth-1 nodes
    // (174 over 174 leaves, one over the single leaf), then 2 (one over the
    // 174 nodes, one over the single node), then the root. The pin was first
    // printed by README's Python rule through THREE_LEVEL_FILE_DRIVER; Kubo is
    // not run, because the file is 7936671745 bytes and is never written.
    let leaves = three_level_leaves();
    assert_eq!(leaves.len(), 30_277, "the file's leaf count");
    assert_eq!(
        leaves.iter().map(|(_, size)| *size).sum::<u64>(),
        7_936_671_745,
        "the file's size"
    );
    assert_eq!(
        leaves.last().map(|(_, size)| *size),
        Some(1),
        "the last leaf"
    );
    // The driver holds no part of the rule: no grouping limit, varint, CID
    // prefix or base32 alphabet of its own.
    for rule in [
        "174",
        "varint",
        "0x55",
        "0x70",
        "B32",
        "abcdefghijklmnopqrstuvwxyz234567",
        "base64",
        "def ",
        "lambda",
    ] {
        assert!(
            !THREE_LEVEL_FILE_DRIVER.contains(rule),
            "the driver holds {rule:?}: {THREE_LEVEL_FILE_DRIVER}"
        );
    }
    assert_eq!(THREE_LEVEL_FILE_DRIVER.matches("directory(").count(), 1);
    assert_eq!(THREE_LEVEL_FILE_DRIVER.matches("printed(").count(), 1);

    let pin = THREE_LEVEL_FILE_LAB_CID;
    let python = readme_python_three_level_file().unwrap_or_else(|reason| panic!("{reason}"));
    assert_eq!(python, pin, "README's Python rule against the pin");
    let named = encode_chunked_files(&[chunked(leaves.clone())])
        .unwrap_or_else(|refusal| panic!("30277 leaves: {refusal}"));
    assert_eq!(
        named.to_string(),
        pin,
        "encode_chunked_files against the pin"
    );
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");

    // 30276 full leaves still finish in two passes, with another CID. That
    // CID is pinned by `exactly_174_squared_leaves_stay_two_levels`.
    let mut full = leaves;
    full.pop();
    assert_eq!(full.len(), 30_276, "the two-pass file's leaf count");
    let two_levels = encode_chunked_files(&[chunked(full)])
        .unwrap_or_else(|refusal| panic!("30276 leaves: {refusal}"));
    assert_ne!(two_levels.to_string(), pin, "30276 leaves has another CID");
}

#[test]
fn exactly_174_squared_leaves_stay_two_levels() {
    // 30276 leaves, every one a full 262144 bytes (7936671744 bytes): 174
    // squared. Two passes: 174 depth-1 nodes, each over 174 leaves, then one
    // root over those 174 nodes. The pin was first printed by README's Python
    // rule through the same driver; Kubo is not run, because the file is
    // 7936671744 bytes and is never written.
    let mut leaves = three_level_leaves();
    leaves.pop();
    assert_eq!(leaves.len(), 174 * 174, "the file's leaf count");
    assert_eq!(
        leaves.iter().map(|(_, size)| *size).sum::<u64>(),
        7_936_671_744,
        "the file's size"
    );
    assert!(
        leaves.iter().all(|(_, size)| *size == 262_144),
        "every leaf is full"
    );
    let pin = SQUARE_174_LAB_CID;
    let python = readme_python_square_file().unwrap_or_else(|reason| panic!("{reason}"));
    assert_eq!(python, pin, "README's Python rule against the pin");
    let named = encode_chunked_files(&[chunked(leaves)])
        .unwrap_or_else(|refusal| panic!("30276 leaves: {refusal}"));
    assert_eq!(
        named.to_string(),
        pin,
        "encode_chunked_files against the pin"
    );
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");
    for other in [
        THREE_LEVEL_FILE_LAB_CID,
        SECOND_LEVEL_FILE_LAB_CID,
        EXACT_174_LEAF_LAB_CID,
        TWO_FULL_CHUNK_LAB_CID,
        FULL_174_LEAF_LAB_CID,
    ] {
        assert_ne!(pin, other, "the square-leaf pin is another bundle's");
    }
}

#[test]
fn chunked_file_without_leaves_is_refused() {
    // An empty file is one empty raw leaf, so no leaf names nothing.
    let refusal = encode_chunked_files(&[chunked(Vec::new())]).expect_err("no leaves");
    assert_eq!(
        refusal,
        Refusal::ChunkedFileWithoutLeaves {
            path: "sample.example".to_owned()
        }
    );
    assert_eq!(
        refusal.to_string(),
        "sample.example is a chunked file with no leaves: an empty file is one empty raw leaf, so it holds one chunk of 0 bytes"
    );
}

#[test]
fn chunked_file_with_a_bad_chunk_size_is_refused() {
    // Every chunk but the last is 262144 bytes, the last is 1 to 262144
    // bytes, and only a one-chunk file may be 0 bytes. Each bad chunk names
    // its own position and size.
    let digest: [u8; 32] = Sha256::digest(b"chunk").into();
    // Valid splits, so the refusals below are the size rule alone.
    for chunks in [
        vec![(digest, 0)],
        vec![(digest, 1)],
        vec![(digest, 262_144)],
        vec![(digest, 262_144), (digest, 1)],
        vec![(digest, 262_144), (digest, 262_144), (digest, 3)],
    ] {
        encode_chunked_files(&[chunked(chunks)]).expect("a chunk the split can give");
    }
    let mut three = vec![(digest, 262_144u64), (digest, 262_144)];
    three.push((digest, 0));
    for (chunks, index, length) in [
        (vec![(digest, 262_145)], 0, 262_145),
        (vec![(digest, 1), (digest, 262_144)], 0, 1),
        (three, 2, 0),
        (vec![(digest, 262_144), (digest, 262_145)], 1, 262_145),
    ] {
        let refusal = encode_chunked_files(&[chunked(chunks)]).expect_err("a bad chunk");
        assert_eq!(
            refusal,
            Refusal::BadChunkSize {
                path: "sample.example".to_owned(),
                index,
                length,
            }
        );
    }
    assert_eq!(
        Refusal::BadChunkSize {
            path: "sample.example".to_owned(),
            index: 1,
            length: 0,
        }
        .to_string(),
        "sample.example chunk 1 is 0 bytes: each chunk but the last is 262144 bytes, the last is 1 to 262144, and only a one-chunk file may be 0"
    );
}

#[test]
fn one_chunk_chunked_file_names_the_bytes_call() {
    // The digest-input path is the same file rule: one empty leaf and one
    // full chunk name what `encode_entries` names for the same bytes.
    let empty: &[u8] = b"";
    let full = vec![0; 262_144];
    for content in [empty, &full[..]] {
        let digest: [u8; 32] = Sha256::digest(content).into();
        let by_digests = encode_chunked_files(&[chunked(vec![(digest, content.len() as u64)])])
            .unwrap_or_else(|refusal| panic!("one leaf: {refusal}"));
        let by_bytes = encode_entries(&[entry("sample.example", content)])
            .unwrap_or_else(|refusal| panic!("one leaf: {refusal}"));
        assert_eq!(by_digests, by_bytes, "{} bytes", content.len());
    }
}

fn estimate(names: impl IntoIterator<Item = usize>) -> usize {
    names.into_iter().map(|length| length + 36).sum()
}

/// The estimate of content-sample's own two files at a bundle root.
fn content_sample_estimate() -> usize {
    estimate(CONTENT_SAMPLE.files.iter().map(|name| name.len()))
}

#[test]
fn directory_at_the_hamt_threshold_stays_basic() {
    // Kubo's estimate is the sum, over a directory's direct children, of the
    // child's name plus 36. At exactly 262144 the directory stays one basic
    // block, even though that block is 279500 bytes; only a greater estimate
    // is a HAMT shard. The helper measures the one name it lengthens.
    let (entries, names, extra) = flat_bundle_at("", 262_144);
    assert_eq!(
        content_sample_estimate() + estimate(names.iter().map(String::len)),
        262_144,
        "the bundle's links estimate"
    );
    assert_eq!(
        names.iter().map(String::len).max(),
        Some(100 + extra),
        "the helper measured the lengthened name"
    );
    let pin = HAMT_THRESHOLD_LAB_CID;
    let bundle = bundled(&entries);
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    assert_eq!(
        (name(&bundle), encoded.as_str()),
        (pin.to_owned(), pin),
        "(lab_cid, encode_entries) against the at-threshold pin"
    );
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");
}

#[test]
fn basic_block_of_exactly_262144_bytes_is_named() {
    // content-sample's two files plus the first 5575 empty three-byte names:
    // the links estimate is 217523, under the threshold, so the root stays
    // one basic directory block. That block is exactly 262144 bytes long, so
    // the exact length must not decide a shard; only the estimate does.
    // README's Python rule printed the length and the pin first.
    let entries = three_byte_bundle(5_575);
    assert_eq!(entries.len(), 5_577, "two files and 5575 empty names");
    assert_eq!(
        estimate(entries.iter().map(|entry| entry.path.len())),
        217_523,
        "the bundle's links estimate"
    );
    let pin = EXACT_BASIC_BLOCK_LAB_CID;
    let bundle = bundled(&entries);
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    let listed: Vec<ListedFile> = entries
        .iter()
        .map(|entry| ListedFile {
            path: entry.path.clone(),
            size: entry.content.len() as u64,
            sha256: Sha256::digest(&entry.content).into(),
        })
        .collect();
    let by_listing = encode_listed_files(&listed)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    assert_eq!(
        (name(&bundle), encoded.as_str(), by_listing.as_str()),
        (pin.to_owned(), pin, pin),
        "(lab_cid, encode_entries, encode_listed_files) against the exact-length pin"
    );
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");
    for other in [
        HAMT_THRESHOLD_LAB_CID,
        HAMT_OVER_THRESHOLD_LAB_CID,
        HAMT_CHILD_LAB_CID,
        CONTENT_SAMPLE_LAB_CID,
    ] {
        assert_ne!(pin, other, "the exact-length pin is another bundle's");
    }
}

#[test]
fn directory_over_the_hamt_threshold_is_a_shard() {
    // One byte more in one name takes the estimate to 262145, so the same
    // directory is a HAMT shard with another pin.
    let (entries, names, extra) = flat_bundle_at("", 262_145);
    assert_eq!(
        content_sample_estimate() + estimate(names.iter().map(String::len)),
        262_145,
        "the bundle's links estimate"
    );
    assert_eq!(
        names.iter().map(String::len).max(),
        Some(100 + extra),
        "the helper measured the lengthened name"
    );
    let pin = HAMT_OVER_THRESHOLD_LAB_CID;
    let bundle = bundled(&entries);
    let encoded = encode_entries(&entries);
    assert_eq!(
        encoded.as_ref().map(ToString::to_string),
        Ok(pin.to_owned()),
        "encode_entries returns the over-threshold pin"
    );
    let encoded = encoded
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    assert_eq!(
        (name(&bundle), encoded.as_str()),
        (pin.to_owned(), pin),
        "(lab_cid, encode_entries) against the over-threshold pin"
    );
    assert_ne!(pin, HAMT_THRESHOLD_LAB_CID, "a shard names another value");
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");
}

#[test]
fn child_directory_over_the_hamt_threshold_is_a_shard() {
    // The 262145 file set under `photos/`: the child is judged on its own
    // estimate and is a shard, while the root counts only its three direct
    // children and stays basic.
    let (entries, names, _extra) = flat_bundle_at("photos/", 262_145);
    assert_eq!(
        estimate(names.iter().map(String::len)),
        262_145,
        "the child directory's estimate"
    );
    let root = content_sample_estimate() + estimate(["photos".len()]);
    assert_eq!(root, 140, "the root's three direct children");
    assert!(root < 262_144, "the root stays basic");
    let pin = HAMT_CHILD_LAB_CID;
    let bundle = bundled(&entries);
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    assert_eq!(
        (name(&bundle), encoded.as_str()),
        (pin.to_owned(), pin),
        "(lab_cid, encode_entries) against the child pin"
    );
    assert_ne!(
        pin, HAMT_OVER_THRESHOLD_LAB_CID,
        "the root adds three links"
    );
    assert_ne!(pin, HAMT_THRESHOLD_LAB_CID);
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");
}

#[test]
fn shard_with_a_file_root_has_the_pinned_cid() {
    // The 262145-name set is a shard; its first name holds 262145 zero
    // bytes, one over the chunk limit, so that name's link is a file root
    // over two raw leaves (262144 and 1 bytes). A one-child shard link
    // stores the child's node Tsize, so the file contributes its file-root
    // Tsize and not its byte length. The name and the estimate stay those
    // of the empty file it replaces.
    let (entries, replaced) = shard_with_a_file_root();
    assert_eq!(
        estimate(entries.iter().map(|entry| entry.path.len())),
        262_145,
        "the bundle's links estimate"
    );
    let file = entries
        .iter()
        .find(|entry| entry.path == replaced)
        .expect("the replaced file is in the bundle");
    assert_eq!(file.content.len(), 262_145, "the replaced file");
    let (_, names, _extra) = flat_bundle_at("", 262_145);
    assert_eq!(
        replaced, names[0],
        "the replaced path is the first name the helper returns"
    );
    let pin = FILE_ROOT_SHARD_LAB_CID;
    let bundle = bundled(&entries);
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    assert_eq!(
        (name(&bundle), encoded.as_str()),
        (pin.to_owned(), pin),
        "(lab_cid, encode_entries) against the file-root shard pin"
    );
    let chunked_files: Vec<ChunkedFile> = entries
        .iter()
        .map(|entry| ChunkedFile {
            path: entry.path.clone(),
            chunks: if entry.path == replaced {
                vec![
                    (Sha256::digest(&entry.content[..262_144]).into(), 262_144),
                    (Sha256::digest(&entry.content[262_144..]).into(), 1),
                ]
            } else {
                vec![(
                    Sha256::digest(&entry.content).into(),
                    entry.content.len() as u64,
                )]
            },
        })
        .collect();
    let by_chunks = encode_chunked_files(&chunked_files)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    assert_eq!(by_chunks, pin, "encode_chunked_files against the pin");
    assert_ne!(
        pin, HAMT_OVER_THRESHOLD_LAB_CID,
        "a file root names another value"
    );
    assert_ne!(pin, TWO_LEAF_FILE_LAB_CID, "the shard adds a link");
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");
}

#[test]
fn empty_file_has_the_pinned_cid() {
    // A zero-byte file is a raw leaf whose block is empty, with Tsize 0,
    // never a dag-pb file node.
    let bundle = assemble(&CONTENT_SAMPLE);
    write_file(bundle.path(), "empty", b"");
    assert_eq!(name(&bundle), EMPTY_FILE_LAB_CID);
}

#[test]
fn long_utf8_name_has_the_pinned_cid() {
    // A link name over 127 bytes: its length, its link's length and the
    // root block's lengths are varints of two bytes. No folder is needed,
    // so the encoder is given the entries directly.
    let mut entries: Vec<BundleEntry> = CONTENT_SAMPLE
        .files
        .iter()
        .map(|file| entry(file, &read_fixture(&CONTENT_SAMPLE, file)))
        .collect();
    let long = long_utf8_name();
    assert_eq!(long.len(), 154, "{long}");
    entries.push(entry(&long, b"long name\n"));
    let named = encode_entries(&entries).expect("name content-sample and the long name");
    assert_eq!(named.to_string(), LONG_UTF8_NAME_LAB_CID);
}

#[test]
fn a_value_of_127_stays_one_varint_byte() {
    // content-sample plus one file `b127` of 127 zero bytes. Its link Tsize
    // is 127, the largest value one varint byte holds (`0x7f`): a condition
    // of `>= 0x7f` writes it as two bytes and names another bundle, which
    // this pin refuses. `sample.example` stays 16 bytes, and no other varint
    // is 127. The pin was first printed by README's Python rule; the file is
    // made here and never committed.
    let manifest = read_fixture(&CONTENT_SAMPLE, "capsule.json");
    let sample = read_fixture(&CONTENT_SAMPLE, "sample.example");
    assert_eq!(sample.len(), 16, "sample.example stays 16 bytes");
    let zeros = vec![0; 127];
    assert_eq!(zeros.len(), 127, "the file's length is 127");
    let bundle = content_sample_with(&[("b127", &zeros)]);
    let entries = vec![
        entry("capsule.json", &manifest),
        entry("sample.example", &sample),
        entry("b127", &zeros),
    ];
    let pin = VARINT_127_LAB_CID;
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    // The same files as a closure listing: one raw leaf each, handed to the
    // one tree builder, so a Tsize of 127 reaches the root there too.
    let listed: Vec<ListedFile> = entries
        .iter()
        .map(|entry| ListedFile {
            path: entry.path.clone(),
            size: entry.content.len() as u64,
            sha256: Sha256::digest(&entry.content).into(),
        })
        .collect();
    let by_listing = encode_listed_files(&listed)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    assert_eq!(
        (name(&bundle), encoded, by_listing),
        (pin.to_owned(), pin.to_owned(), pin.to_owned()),
        "(lab_cid, encode_entries, encode_listed_files) against the pin"
    );
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");
    for other in [
        CONTENT_SAMPLE_LAB_CID,
        EMPTY_FILE_LAB_CID,
        LONG_UTF8_NAME_LAB_CID,
        CHUNK_LIMIT_LAB_CID,
        TWO_FULL_CHUNK_LAB_CID,
    ] {
        assert_ne!(pin, other, "the 127 pin is another bundle's");
    }
}

#[test]
fn a_value_of_128_takes_two_varint_bytes() {
    // content-sample plus one file `b128` of 128 zero bytes. Its link Tsize
    // is 128, the first value two varint bytes hold (`0x80 0x01`): a
    // condition of `> 0x80` writes it as one byte and names another bundle,
    // which this pin refuses. `sample.example` stays 16 bytes, and no other
    // varint is 128. The pin was first printed by README's Python rule; the
    // file is made here and never committed.
    let manifest = read_fixture(&CONTENT_SAMPLE, "capsule.json");
    let sample = read_fixture(&CONTENT_SAMPLE, "sample.example");
    assert_eq!(sample.len(), 16, "sample.example stays 16 bytes");
    let zeros = vec![0; 128];
    assert_eq!(zeros.len(), 128, "the file's length is 128");
    let bundle = content_sample_with(&[("b128", &zeros)]);
    let entries = vec![
        entry("capsule.json", &manifest),
        entry("sample.example", &sample),
        entry("b128", &zeros),
    ];
    let pin = VARINT_128_LAB_CID;
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    // The same files as a closure listing: one raw leaf each, handed to the
    // one tree builder, so a Tsize of 128 reaches the root there too.
    let listed: Vec<ListedFile> = entries
        .iter()
        .map(|entry| ListedFile {
            path: entry.path.clone(),
            size: entry.content.len() as u64,
            sha256: Sha256::digest(&entry.content).into(),
        })
        .collect();
    let by_listing = encode_listed_files(&listed)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    assert_eq!(
        (name(&bundle), encoded, by_listing),
        (pin.to_owned(), pin.to_owned(), pin.to_owned()),
        "(lab_cid, encode_entries, encode_listed_files) against the pin"
    );
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");
    for other in [
        VARINT_127_LAB_CID,
        CONTENT_SAMPLE_LAB_CID,
        EMPTY_FILE_LAB_CID,
        LONG_UTF8_NAME_LAB_CID,
        CHUNK_LIMIT_LAB_CID,
    ] {
        assert_ne!(pin, other, "the 128 pin is another bundle's");
    }
}

#[test]
fn a_value_of_16384_takes_three_varint_bytes() {
    // content-sample plus one file `b16384` of 16384 zero bytes. Its link
    // Tsize is 16384, the first value three varint bytes hold
    // (`0x80 0x80 0x01`): a stop once the shifted remainder is below 256
    // writes it as two bytes and names another bundle, which this pin
    // refuses. `sample.example` stays 16 bytes, and no other varint is 16384.
    // The pin was first printed by README's Python rule; the file is made
    // here and never committed.
    let manifest = read_fixture(&CONTENT_SAMPLE, "capsule.json");
    let sample = read_fixture(&CONTENT_SAMPLE, "sample.example");
    assert_eq!(sample.len(), 16, "sample.example stays 16 bytes");
    let zeros = vec![0; 16384];
    assert_eq!(zeros.len(), 16384, "the file's length is 16384");
    let bundle = content_sample_with(&[("b16384", &zeros)]);
    let entries = vec![
        entry("capsule.json", &manifest),
        entry("sample.example", &sample),
        entry("b16384", &zeros),
    ];
    let pin = VARINT_16384_LAB_CID;
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    // The same files as a closure listing: one raw leaf each, handed to the
    // one tree builder, so a Tsize of 16384 reaches the root there too.
    let listed: Vec<ListedFile> = entries
        .iter()
        .map(|entry| ListedFile {
            path: entry.path.clone(),
            size: entry.content.len() as u64,
            sha256: Sha256::digest(&entry.content).into(),
        })
        .collect();
    let by_listing = encode_listed_files(&listed)
        .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
        .to_string();
    assert_eq!(
        (name(&bundle), encoded, by_listing),
        (pin.to_owned(), pin.to_owned(), pin.to_owned()),
        "(lab_cid, encode_entries, encode_listed_files) against the pin"
    );
    assert!(pin.starts_with("bafybei"), "{pin}");
    assert_eq!(pin.len(), 59, "{pin}");
    for other in [
        VARINT_128_LAB_CID,
        VARINT_127_LAB_CID,
        CONTENT_SAMPLE_LAB_CID,
        EMPTY_FILE_LAB_CID,
        LONG_UTF8_NAME_LAB_CID,
        CHUNK_LIMIT_LAB_CID,
    ] {
        assert_ne!(pin, other, "the 16384 pin is another bundle's");
    }
}

#[test]
fn encoder_refuses_file_directory_conflict() {
    // `a` and `a/b` make `a` a file and a directory. A UnixFS directory holds
    // one link per name, so the encoder refuses, in either order, rather
    // than keep one and drop the other.
    for (file, below, conflict) in [("a", "a/b", "a"), ("x/a", "x/a/b", "x/a")] {
        let both = [entry(file, b"file"), entry(below, b"below")];
        let reversed = [both[1].clone(), both[0].clone()];
        for entries in [&both, &reversed] {
            let refusal = encode_entries(entries).expect_err("a file and a directory at one path");
            assert_eq!(
                refusal,
                Refusal::FileAndDirectory {
                    path: conflict.into()
                },
                "{entries:?}"
            );
            assert_eq!(
                refusal.to_string(),
                format!("{conflict} is both a file and a directory: a bundle path names one or the other")
            );
        }
    }
}

#[test]
fn encoder_refuses_a_path_with_an_empty_or_dot_part() {
    // Each part of a path is one link name, so an empty part, `.` or `..`
    // would make a link no folder holds. The walk never gives one.
    for path in ["", "/a", "a/", "a//b", ".", "./a", "a/..", "a/../b"] {
        let refusal = encode_entries(&[entry(path, b"x")]).expect_err("a bad path part");
        assert_eq!(
            refusal,
            Refusal::BadPathPart { path: path.into() },
            "{path:?}"
        );
        assert_eq!(
            refusal.to_string(),
            format!(
                "the path {path:?} has an empty, . or .. part: each part names one UnixFS link"
            )
        );
    }
}

#[test]
fn encoder_refuses_a_duplicate_path() {
    // A folder holds one file per path. Two entries with one path would
    // otherwise be named in the order they were given.
    let first = entry("capsule.json", b"{}");
    let second = entry("capsule.json", b"[]");
    let other = entry("sample.example", b"x");
    for entries in [
        vec![first.clone(), second.clone()],
        vec![second, other, first],
    ] {
        let refusal = encode_entries(&entries).expect_err("a duplicate path must be refused");
        assert_eq!(
            refusal,
            Refusal::DuplicatePath {
                path: "capsule.json".into()
            }
        );
        assert_eq!(
            refusal.to_string(),
            "two entries have the path capsule.json: a bundle holds one file per path"
        );
    }
}

#[test]
fn a_hidden_name_is_refused_with_its_reason() {
    // A path part that starts with `.` is a hidden name. Kubo v0.40.1 with
    // the Runtime's import flags (`empty-dirs` false and no hidden flag)
    // leaves that name out of the CID, so the lab refuses the bundle instead
    // of naming it as if the name were absent. A dot inside or at the end of
    // a name (`a.b`, `x.`) is a normal name. The normal names are encoded
    // first, before any walk of a fixture, so a check that refuses them fails
    // at that assertion.
    for path in ["a.b", "x."] {
        let named = encode_entries(&[entry(path, b"x")]);
        assert!(
            named.is_ok(),
            "{path:?} is a normal name, not a hidden one: {:?}",
            named.err()
        );
    }

    fn reason(path: &str) -> String {
        format!(
            "{path} starts with '.': Kubo v0.40.1 with the Runtime import flags leaves a leading-dot name out of the CID, and the lab refuses that bundle"
        )
    }

    for path in [".DS_Store", ".well-known/a.txt", "browser/.hidden"] {
        let refusal = encode_entries(&[entry(path, b"x")]).expect_err("a hidden name");
        assert_eq!(
            refusal,
            Refusal::HiddenName {
                path: path.to_owned()
            },
            "{path:?}"
        );
        assert_eq!(refusal.to_string(), reason(path), "{path:?}");
    }

    // The listing call reaches the same one path check.
    let listed = ListedFile {
        path: ".x".to_owned(),
        size: 1,
        sha256: Sha256::digest(b"x").into(),
    };
    let refusal = encode_listed_files(&[listed]).expect_err("a hidden name");
    assert_eq!(
        refusal,
        Refusal::HiddenName {
            path: ".x".to_owned()
        }
    );
    assert_eq!(refusal.to_string(), reason(".x"));

    // Through the walk: web-app's committed files plus a root `.DS_Store`.
    let bundle = assemble(&WEB_APP);
    write_file(bundle.path(), ".DS_Store", b"x");
    let refusal = lab_cid(bundle.path()).expect_err("a hidden name at the root");
    assert_eq!(
        refusal,
        Refusal::HiddenName {
            path: ".DS_Store".to_owned()
        }
    );
    assert_eq!(refusal.to_string(), reason(".DS_Store"));

    // One path check: `Directory::insert` holds the one `starts_with('.')`
    // over the path parts, and the library holds no second one.
    let code = library_code();
    let insert = library_item(&code, "fn insert(");
    assert_eq!(
        insert.matches(".starts_with('.')").count(),
        1,
        "the one hidden-name rule:\n{insert}"
    );
    assert_eq!(
        code.matches(".starts_with('.')").count(),
        1,
        "a second hidden-name check"
    );
}
