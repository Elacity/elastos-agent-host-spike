//! The lab CID encoding: entry order, path and content boundaries, the
//! printed form, one file per path, and the UnixFS profile settings, each
//! with its own test.
mod common;

use capsule_identity::{
    encode_chunked_files, encode_entries, encode_listed_files, lab_cid, BundleEntry, ChunkedFile,
    ListedFile, Refusal,
};
use common::*;
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
fn file_over_174_leaves_gets_a_second_tree_level() {
    // 174 leaves of 262144 bytes (45613056 bytes) is the most one file node
    // links (`max-file-links`). One byte more is a 175th leaf, so Kubo's
    // balanced layout puts a root over two nodes: one of 174 leaves and one
    // of a single leaf, still a node of one link. Its pin was recomputed by
    // README's Python rule and printed by Kubo v0.40.1 (task 051). In memory:
    // no folder.
    let limit = 174 * 262_144;
    assert_eq!(limit, 45_613_056);
    let manifest = entry(
        "capsule.json",
        &read_fixture(&CONTENT_SAMPLE, "capsule.json"),
    );
    let file = two_level_bytes();
    assert_eq!(file.len(), limit + 1);
    let named = |content: &[u8]| {
        encode_entries(&[manifest.clone(), entry("sample.example", content)])
            .unwrap_or_else(|refusal| panic!("{} bytes: {refusal}", content.len()))
            .to_string()
    };
    let two_levels = named(&file);
    assert_eq!(two_levels, TWO_LEVEL_FILE_LAB_CID);
    assert!(two_levels.starts_with("bafybei"), "{two_levels}");

    // 174 leaves still get one file node, so a name that is not the
    // two-level one.
    let one_level = named(&file[..limit]);
    assert!(one_level.starts_with("bafybei"), "{one_level}");
    assert_ne!(one_level, two_levels, "174 and 175 leaves got one name");
}

/// A fresh temp bundle holding exactly `entries`, with its name by the walk
/// and by the encoder.
fn walk_and_encode(entries: &[BundleEntry]) -> (TempDir, String, String) {
    let bundle = temp_dir();
    for entry in entries {
        write_file(bundle.path(), &entry.path, &entry.content);
    }
    let walked = name(&bundle);
    let encoded = encode_entries(entries)
        .unwrap_or_else(|refusal| panic!("{refusal}"))
        .to_string();
    (bundle, walked, encoded)
}

#[test]
fn directory_at_the_hamt_threshold_stays_basic() {
    // content-sample plus the measured empty files of the flat helper, whose
    // links estimate is exactly 262144: a basic directory, not a shard. Its
    // pin was recomputed by README's Python rule and printed by Kubo v0.40.1
    // with the provider's HAMT config (task 056).
    let entries = directory_at_hamt_threshold_bundle(0);
    let estimate: usize = entries
        .iter()
        .map(|entry| entry.path.len() + LINKED_CID_LENGTH)
        .sum();
    assert_eq!(estimate, HAMT_LINKS_LIMIT, "the links estimate");
    // Each link still adds its field-2 tag and length, the CID's tag and
    // length, the name's length, and the Tsize's tag and zero: at least 8
    // bytes beyond the estimate's name and 36, and the UnixFS data adds 4.
    // So this basic directory's block is longer than 262144 bytes.
    let lowest_block = estimate + 8 * entries.len() + 4;
    assert!(
        lowest_block > HAMT_LINKS_LIMIT,
        "the basic block's lower bound {lowest_block} does not exceed the threshold"
    );
    let (_bundle, walked, encoded) = walk_and_encode(&entries);
    assert_eq!(
        (walked.as_str(), encoded.as_str()),
        (
            DIRECTORY_AT_HAMT_THRESHOLD_LAB_CID,
            DIRECTORY_AT_HAMT_THRESHOLD_LAB_CID
        ),
        "(lab_cid, encode_entries) against the pin"
    );
    assert!(walked.starts_with("bafybei"), "{walked}");
}

#[test]
fn directory_over_the_hamt_threshold_is_a_shard() {
    // One name byte more makes the links estimate 262145: past the threshold,
    // so the directory is a HAMT shard, and its pin differs from the basic
    // one. The pin was recomputed by README's Python rule and printed by
    // Kubo v0.40.1 with the provider's HAMT config (task 056).
    let entries = directory_at_hamt_threshold_bundle(1);
    let estimate: usize = entries
        .iter()
        .map(|entry| entry.path.len() + LINKED_CID_LENGTH)
        .sum();
    assert_eq!(estimate, HAMT_LINKS_LIMIT + 1, "the links estimate");
    let (_bundle, walked, encoded) = walk_and_encode(&entries);
    assert_eq!(
        (walked.as_str(), encoded.as_str()),
        (
            DIRECTORY_OVER_HAMT_THRESHOLD_LAB_CID,
            DIRECTORY_OVER_HAMT_THRESHOLD_LAB_CID
        ),
        "(lab_cid, encode_entries) against the pin"
    );
    assert!(walked.starts_with("bafybei"), "{walked}");
    assert_ne!(
        walked, DIRECTORY_AT_HAMT_THRESHOLD_LAB_CID,
        "262144 and 262145 estimates got one name"
    );
}

#[test]
fn directory_with_a_one_link_hamt_shard_has_the_pinned_cid() {
    // Task 061: two 200-byte names replace two fillers of the 262145-estimate
    // bundle. Their digest bytes 0 and 1 are equal and byte 2 differs, and no
    // other name has their first digest byte, so the first byte's bucket
    // holds only those two names and the child shard from the next digest
    // byte holds one link. The parent still links that child shard, named
    // only the first byte's two digits. The pin was recomputed by README's
    // Python rule and printed by Kubo v0.40.1 with the provider's HAMT
    // config.
    let entries = directory_with_a_one_link_hamt_shard_bundle();
    let estimate: usize = entries
        .iter()
        .map(|entry| entry.path.len() + LINKED_CID_LENGTH)
        .sum();
    assert_eq!(estimate, HAMT_LINKS_LIMIT + 1, "the links estimate");
    let (_bundle, walked, encoded) = walk_and_encode(&entries);
    assert_eq!(
        (walked.as_str(), encoded.as_str()),
        (
            DIRECTORY_WITH_A_ONE_LINK_HAMT_SHARD_LAB_CID,
            DIRECTORY_WITH_A_ONE_LINK_HAMT_SHARD_LAB_CID
        ),
        "(lab_cid, encode_entries) against the pin"
    );
    assert!(walked.starts_with("bafybei"), "{walked}");
    assert_ne!(
        walked, DIRECTORY_OVER_HAMT_THRESHOLD_LAB_CID,
        "a one-link child shard got the same name as a two-link one"
    );
}

#[test]
fn file_root_inside_a_hamt_has_the_pinned_cid() {
    // Task 062: one 200-byte filler of the 262145-estimate bundle holds a
    // file of 262145 bytes, a file root over two raw leaves. A HAMT leaf
    // link stores the child node's Tsize, which for a file over one leaf is
    // the file root's block and its leaves, not the file's byte length. The
    // pin was recomputed by README's Python rule and printed by Kubo v0.40.1
    // with the provider's HAMT config.
    let entries = file_root_inside_a_hamt_bundle();
    let estimate: usize = entries
        .iter()
        .map(|entry| entry.path.len() + LINKED_CID_LENGTH)
        .sum();
    assert_eq!(estimate, HAMT_LINKS_LIMIT + 1, "the links estimate");
    let files: Vec<&BundleEntry> = entries
        .iter()
        .filter(|entry| entry.content.len() > 262_144)
        .collect();
    assert_eq!(files.len(), 1, "one file over one leaf");
    assert_eq!(files[0].content.len(), 262_145, "the replaced file's bytes");
    let chunked: Vec<ChunkedFile> = entries
        .iter()
        .map(|entry| chunked_file(&entry.path, &entry.content))
        .collect();
    let (_bundle, walked, encoded) = walk_and_encode(&entries);
    let from_chunks = encode_chunked_files(&chunked)
        .unwrap_or_else(|refusal| panic!("{refusal}"))
        .to_string();
    assert_eq!(
        (walked.as_str(), encoded.as_str(), from_chunks.as_str()),
        (
            FILE_ROOT_INSIDE_A_HAMT_LAB_CID,
            FILE_ROOT_INSIDE_A_HAMT_LAB_CID,
            FILE_ROOT_INSIDE_A_HAMT_LAB_CID
        ),
        "(lab_cid, encode_entries, encode_chunked_files) against the pin"
    );
    assert!(walked.starts_with("bafybei"), "{walked}");
    assert_ne!(
        walked, DIRECTORY_OVER_HAMT_THRESHOLD_LAB_CID,
        "the file root got the empty fillers' name"
    );
    assert_ne!(
        walked, TWO_LEAF_FILE_LAB_CID,
        "a file root in a shard got a basic directory's name"
    );
}

#[test]
fn multibyte_name_over_the_hamt_threshold_is_a_shard() {
    // Task 063: one 200-byte filler of the 262145-estimate bundle is replaced
    // by a 200-byte name of 66 名 (U+540D) and `aa`, which is 68 Unicode
    // scalars. The byte estimate keeps the directory a HAMT shard; a scalar
    // count would be 262013 and stay a basic directory. The pin was
    // recomputed by README's Python rule and printed by Kubo v0.40.1 with the
    // provider's HAMT config.
    let entries = multibyte_name_over_the_hamt_threshold_bundle();
    let bytes: usize = entries
        .iter()
        .map(|entry| entry.path.len() + LINKED_CID_LENGTH)
        .sum();
    let scalars: usize = entries
        .iter()
        .map(|entry| entry.path.chars().count() + LINKED_CID_LENGTH)
        .sum();
    assert_eq!(bytes, HAMT_LINKS_LIMIT + 1, "the byte estimate");
    assert_eq!(scalars, 262_013, "the scalar estimate");
    assert!(
        scalars <= HAMT_LINKS_LIMIT,
        "the scalar estimate {scalars} does not stay a basic directory"
    );
    let multibyte: Vec<&BundleEntry> = entries
        .iter()
        .filter(|entry| !entry.path.is_ascii())
        .collect();
    assert_eq!(multibyte.len(), 1, "one multibyte name");
    assert_eq!(multibyte[0].path.len(), 200, "the replaced path's bytes");
    assert_eq!(
        multibyte[0].path.chars().count(),
        68,
        "the replaced path's scalars"
    );
    assert_eq!(multibyte[0].path, format!("{}aa", "\u{540d}".repeat(66)));
    let (_bundle, walked, encoded) = walk_and_encode(&entries);
    assert_eq!(
        (walked.as_str(), encoded.as_str()),
        (
            MULTIBYTE_NAME_OVER_HAMT_THRESHOLD_LAB_CID,
            MULTIBYTE_NAME_OVER_HAMT_THRESHOLD_LAB_CID
        ),
        "(lab_cid, encode_entries) against the pin"
    );
    assert!(walked.starts_with("bafybei"), "{walked}");
    assert_ne!(
        walked, DIRECTORY_OVER_HAMT_THRESHOLD_LAB_CID,
        "a multibyte name got the ASCII shard's name"
    );
}

#[test]
fn child_directory_over_the_hamt_threshold_is_a_shard() {
    // The 262145-estimate flat bundle sits under `photos/`, and
    // content-sample's own two files stay at the root, so `photos/capsule.json`
    // is not the root `capsule.json`. Each directory is judged on its own
    // estimate: `photos` is a shard, and the root's three children are far
    // below the threshold, so the root stays a basic directory. Its pin was
    // recomputed by README's Python rule and printed by Kubo v0.40.1 with the
    // provider's HAMT config (task 056).
    let entries = child_directory_at_hamt_threshold_bundle(1);
    let child: usize = entries
        .iter()
        .filter_map(|entry| entry.path.strip_prefix("photos/"))
        .map(|name| name.len() + LINKED_CID_LENGTH)
        .sum();
    assert_eq!(child, HAMT_LINKS_LIMIT + 1, "photos' links estimate");
    let root: usize = entries
        .iter()
        .filter(|entry| !entry.path.starts_with("photos/"))
        .map(|entry| entry.path.len() + LINKED_CID_LENGTH)
        .sum::<usize>()
        + "photos".len()
        + LINKED_CID_LENGTH;
    assert_eq!(root, 140, "the root's links estimate");
    assert!(root < HAMT_LINKS_LIMIT, "{root}");
    assert!(
        entries.iter().any(|entry| entry.path == "capsule.json"),
        "the root lost content-sample's capsule.json"
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.path == "photos/capsule.json"),
        "photos/capsule.json is not under photos"
    );
    let (_bundle, walked, encoded) = walk_and_encode(&entries);
    assert_eq!(
        (walked.as_str(), encoded.as_str()),
        (
            CHILD_DIRECTORY_OVER_HAMT_THRESHOLD_LAB_CID,
            CHILD_DIRECTORY_OVER_HAMT_THRESHOLD_LAB_CID
        ),
        "(lab_cid, encode_entries) against the pin"
    );
    assert!(walked.starts_with("bafybei"), "{walked}");
    assert_ne!(walked, DIRECTORY_AT_HAMT_THRESHOLD_LAB_CID);
    assert_ne!(walked, DIRECTORY_OVER_HAMT_THRESHOLD_LAB_CID);
}

#[test]
fn directory_block_of_262144_bytes_is_named_and_one_byte_more_is_refused() {
    // content-sample and the 1065 empty files of `directory_at_limit_files`,
    // whose names bring the root block to exactly 262144 bytes: the largest
    // directory block task 053 named. Since task 056 the links estimate, not
    // the block length, decides, and this bundle's estimate stays far below
    // 262144, so it is a basic directory. Its pin was recomputed by README's
    // Python rule and printed by Kubo v0.40.1 with the provider's HAMT
    // config. The name kept task 053's words; no refusal remains. The files
    // are made here and never committed.
    let at_limit = |longer: usize| {
        let files = directory_at_limit_files(longer);
        let bundle = assemble(&CONTENT_SAMPLE);
        for file in &files {
            write_file(bundle.path(), &file.path, &file.content);
        }
        let mut entries: Vec<BundleEntry> = CONTENT_SAMPLE
            .files
            .iter()
            .map(|file| entry(file, &read_fixture(&CONTENT_SAMPLE, file)))
            .collect();
        entries.extend(files);
        (bundle, entries)
    };
    let (bundle, entries) = at_limit(0);
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("{refusal}"))
        .to_string();
    assert_eq!(
        (name(&bundle), encoded.as_str()),
        (
            DIRECTORY_AT_LIMIT_LAB_CID.to_owned(),
            DIRECTORY_AT_LIMIT_LAB_CID
        ),
        "(lab_cid, encode_entries) against the pin"
    );
    let estimate: usize = entries
        .iter()
        .map(|entry| entry.path.len() + LINKED_CID_LENGTH)
        .sum();
    assert!(estimate <= HAMT_LINKS_LIMIT, "{estimate}");

    // One name one byte longer makes a root block of 262145 bytes. Its
    // estimate is still at most 262144, so it is still a basic directory:
    // the walk and the encoder name it, and the name differs from the pin.
    // This value is not pinned.
    let (bundle, entries) = at_limit(1);
    let walked = name(&bundle);
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("{refusal}"))
        .to_string();
    assert_eq!(walked, encoded, "the walk and the encoder disagree");
    let estimate: usize = entries
        .iter()
        .map(|entry| entry.path.len() + LINKED_CID_LENGTH)
        .sum();
    assert!(estimate <= HAMT_LINKS_LIMIT, "{estimate}");
    assert!(walked.starts_with("bafybei"), "{walked}");
    assert_ne!(walked, DIRECTORY_AT_LIMIT_LAB_CID);
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

/// The exact text of a [`Refusal::HiddenName`] for `path`.
fn hidden_name_text(path: &str) -> String {
    format!(
        "the path {path:?} has a part that starts with .: Kubo's import with the Runtime's flags (no --hidden) leaves a name starting with . out of the CID, and the lab names every byte or refuses"
    )
}

#[test]
fn a_hidden_name_is_refused_with_its_reason() {
    // Kubo's `add` without `--hidden` leaves a name starting with `.` out of
    // the CID, and the lab never leaves bytes out of a name, so it refuses:
    // a hidden file at the root, a hidden folder, a hidden file one folder
    // down, a listed hidden file, and a walked bundle with a `.DS_Store`.
    let refused = |path: &str, refusal: Refusal| {
        assert_eq!(
            refusal,
            Refusal::HiddenName { path: path.into() },
            "{path:?}"
        );
        assert_eq!(refusal.to_string(), hidden_name_text(path), "{path:?}");
    };
    for path in [".DS_Store", ".well-known/a.txt", "browser/.hidden"] {
        let refusal = encode_entries(&[entry("capsule.json", b"{}"), entry(path, b"x")])
            .expect_err("a hidden name must be refused");
        refused(path, refusal);
    }
    let listed = ListedFile {
        path: ".x".into(),
        size: 1,
        sha256: [0; 32],
    };
    refused(
        ".x",
        encode_listed_files(&[listed]).expect_err("a listed hidden name must be refused"),
    );
    let bundle = assemble(&WEB_APP);
    write_file(bundle.path(), ".DS_Store", b"Bud1");
    refused(
        ".DS_Store",
        lab_cid(bundle.path()).expect_err("a walked .DS_Store must be refused"),
    );

    // A dot inside or at the end of a name is a plain name.
    for path in ["a.b", "x."] {
        encode_entries(&[entry(path, b"x")])
            .unwrap_or_else(|refusal| panic!("{path:?} must be named: {refusal}"));
    }

    // P10: the rule is in the one path check, once.
    assert_eq!(
        library_code().matches("part.starts_with('.')").count(),
        1,
        "the hidden-name rule is not in one place"
    );
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
