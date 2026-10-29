//! The lab CID encoding: entry order, path and content boundaries, the
//! printed form, one file per path, and the UnixFS profile settings, each
//! with its own test.
mod common;

use capsule_identity::{
    encode_chunked_files, encode_entries, lab_cid, BundleEntry, ChunkedFile, Refusal,
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
fn file_of_174_leaves_is_named_and_one_byte_more_is_refused() {
    // 174 leaves of 262144 bytes (45613056 bytes) is the most one file root
    // links (`max-file-links`). One byte more needs a 175th leaf and so a
    // second tree level, which the lab refuses. In memory: no folder.
    let limit = 174 * 262_144;
    assert_eq!(limit, 45_613_056);
    let mut file = vec![0; limit];
    let named = encode_entries(&[entry("full.bin", &file)])
        .unwrap_or_else(|refusal| panic!("174 leaves: {refusal}"));
    assert!(named.to_string().starts_with("bafybei"), "{named}");

    file.push(0);
    let refusal = encode_entries(&[entry("full.bin", &file)])
        .expect_err("a file of 175 leaves must be refused");
    assert_eq!(
        refusal,
        Refusal::FileOverLeafLimit {
            path: "full.bin".into(),
            length: 45_613_057
        }
    );
    assert_eq!(
        refusal.to_string(),
        "full.bin is 45613057 bytes, over the 174-leaf limit of one file root (45613056 bytes): the lab names no deeper file tree"
    );
}

#[test]
fn chunked_files_are_checked_and_named_by_the_one_file_rule() {
    // The digest path makes the same node as the byte path: a one-leaf file
    // (empty, or exactly one chunk), a two-leaf and a three-leaf file. The
    // two multi-leaf pins are recomputed by README's Python rule from the
    // byte rules, so the shared file rule's CID and Tsize are checked here
    // through the digests alone. The big files are made here, never
    // committed.
    fn chunked(path: &str, content: &[u8]) -> ChunkedFile {
        let digests: Vec<[u8; 32]> = if content.is_empty() {
            vec![Sha256::digest(content).into()]
        } else {
            content
                .chunks(262_144)
                .map(|chunk| Sha256::digest(chunk).into())
                .collect()
        };
        ChunkedFile {
            path: path.to_owned(),
            size: content.len() as u64,
            chunk_sha256: digests,
        }
    }

    for content in [&b""[..], &vec![7; 262_144][..]] {
        let bytes = encode_entries(&[entry("one.bin", content)])
            .unwrap_or_else(|refusal| panic!("{refusal}"));
        let digests = encode_chunked_files(&[chunked("one.bin", content)])
            .unwrap_or_else(|refusal| panic!("{refusal}"));
        assert_eq!(bytes, digests, "one leaf, {} bytes", content.len());
    }

    let manifest = entry(
        "capsule.json",
        &read_fixture(&CONTENT_SAMPLE, "capsule.json"),
    );
    let sample = read_fixture(&CONTENT_SAMPLE, "sample.example");
    let zeros = vec![0; 262_145];
    let big = big_bin_bytes();
    for (files, entries, pin) in [
        (
            vec![
                chunked(
                    "capsule.json",
                    &read_fixture(&CONTENT_SAMPLE, "capsule.json"),
                ),
                chunked("sample.example", &zeros),
            ],
            vec![manifest.clone(), entry("sample.example", &zeros)],
            TWO_LEAF_FILE_LAB_CID,
        ),
        (
            vec![
                chunked(
                    "capsule.json",
                    &read_fixture(&CONTENT_SAMPLE, "capsule.json"),
                ),
                chunked("sample.example", &sample),
                chunked(BIG_BIN, &big),
            ],
            vec![
                manifest,
                entry("sample.example", &sample),
                entry(BIG_BIN, &big),
            ],
            THREE_LEAF_NESTED_LAB_CID,
        ),
    ] {
        let from_digests = encode_chunked_files(&files)
            .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
            .to_string();
        let from_bytes = encode_entries(&entries)
            .unwrap_or_else(|refusal| panic!("{pin}: {refusal}"))
            .to_string();
        assert_eq!(
            (from_digests.as_str(), from_bytes.as_str()),
            (pin, pin),
            "chunked and byte paths against the pin"
        );
        assert!(pin.starts_with("bafybei"), "{pin}");
    }

    // A digest count its size does not give is refused with its own reason,
    // and the text names the file, its size, the count its size gives and the
    // count supplied. An empty file needs one digest: an empty leaf.
    for (path, size, supplied, expected, text) in [
        (
            "empty.bin",
            0_u64,
            Vec::new(),
            1_usize,
            "empty.bin is 0 bytes and holds 0 chunk digests: its size gives 1 chunks of at most 262144 bytes, one for an empty file",
        ),
        (
            "half.bin",
            262_145,
            vec![[3; 32]],
            2,
            "half.bin is 262145 bytes and holds 1 chunk digests: its size gives 2 chunks of at most 262144 bytes, one for an empty file",
        ),
        (
            "full.bin",
            262_144,
            vec![[4; 32], [4; 32]],
            1,
            "full.bin is 262144 bytes and holds 2 chunk digests: its size gives 1 chunks of at most 262144 bytes, one for an empty file",
        ),
    ] {
        let refused = encode_chunked_files(&[ChunkedFile {
            path: path.to_owned(),
            size,
            chunk_sha256: supplied.clone(),
        }]);
        assert!(
            refused.is_err(),
            "{path}: a digest count the size does not give must be refused, got {refused:?}"
        );
        let refusal = refused.expect_err("a digest count the size does not give must be refused");
        assert_eq!(
            refusal,
            Refusal::ChunkCountMismatch {
                path: path.to_owned(),
                size,
                expected,
                supplied: supplied.len(),
            }
        );
        assert_eq!(refusal.to_string(), text);
    }

    // The leaf limit is the byte path's, through the one file rule: 174
    // digests are named and a 175th is refused with its own reason.
    let limit = 174 * 262_144;
    let named = encode_chunked_files(&[ChunkedFile {
        path: "full.bin".to_owned(),
        size: limit,
        chunk_sha256: vec![[0; 32]; 174],
    }])
    .unwrap_or_else(|refusal| panic!("174 leaves: {refusal}"));
    assert!(named.to_string().starts_with("bafybei"), "{named}");
    let refusal = encode_chunked_files(&[ChunkedFile {
        path: "full.bin".to_owned(),
        size: limit + 1,
        chunk_sha256: vec![[0; 32]; 175],
    }])
    .expect_err("a file of 175 leaves must be refused");
    assert_eq!(
        refusal,
        Refusal::FileOverLeafLimit {
            path: "full.bin".into(),
            length: 45_613_057,
        }
    );
    assert_eq!(
        refusal.to_string(),
        "full.bin is 45613057 bytes, over the 174-leaf limit of one file root (45613056 bytes): the lab names no deeper file tree"
    );
}

#[test]
fn directory_over_the_hamt_threshold_is_refused() {
    // 1100 empty files with 200-byte names give the root about 270 KB of
    // links: over the 262144-byte block limit, where Kubo would shard. The
    // lab refuses it rather than name a HAMT, and returns no CID.
    let bundle = assemble(&CONTENT_SAMPLE);
    for number in 0..1100 {
        write_file(bundle.path(), &format!("{number:0>200}"), b"");
    }
    let refusal = lab_cid(bundle.path()).expect_err("a root block over the limit must be refused");
    let Refusal::DirectoryOverBlockLimit { path, length } = &refusal else {
        panic!("another refusal: {refusal}");
    };
    assert_eq!(path, ".", "the refusal does not name the root");
    assert!(*length > 262_144, "{refusal}");
    assert_eq!(
        refusal.to_string(),
        format!(
            "the directory . encodes to {length} bytes, over the 262144-byte block limit: the lab names no HAMT-sharded directory"
        )
    );
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
