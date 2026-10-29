//! A claimed name is checked, never trusted: `check_name` refuses a claim
//! that is not a lab CID, recomputes the name from the bytes with `lab_cid`,
//! the one naming path, and refuses a lab CID the bytes do not give.
mod common;

use std::os::unix::fs::symlink;

use capsule_identity::{check_name, lab_cid, Refusal};
use common::*;

#[test]
fn claimed_name_is_checked_never_trusted() {
    let bundle = assemble(&WEB_APP);
    check_name(bundle.path(), WEB_APP_LAB_CID)
        .unwrap_or_else(|refusal| panic!("the bundle's own lab CID was refused: {refusal}"));

    // A wrong labelled claim, such as a Store row that names another bundle,
    // is refused with both values.
    assert_name_mismatch(bundle.path(), CONTENT_SAMPLE_LAB_CID, named(bundle.path()));

    // A claim that is not a lab CID is refused as one, even when it carries
    // the bundle's own root.
    for claim in not_lab_cids() {
        let refusal = check_name(bundle.path(), &claim)
            .expect_err("a claim that is not a lab CID must be refused");
        assert_eq!(
            refusal,
            Refusal::NotALabCid {
                claimed: claim.clone()
            },
            "{claim:?}"
        );
        assert_eq!(refusal.to_string(), not_a_lab_cid_text(&claim));
    }

    // The claim is checked before any bundle is read: where no bundle
    // exists, a claim that is not a lab CID is still refused as one.
    let nowhere = bundle.path().join("no-bundle-here");
    let uppercase = WEB_APP_LAB_CID.to_uppercase();
    assert_eq!(
        check_name(&nowhere, &uppercase),
        Err(Refusal::NotALabCid { claimed: uppercase }),
        "check_name read the bundle before it checked the claim"
    );
}

#[test]
fn check_name_preserves_lab_cid_refusals() {
    // Three bundles lab_cid refuses, each for its own reason. A well-formed
    // claim gets exactly lab_cid's refusal: the same variant and text.
    let no_manifest = temp_dir();
    let sample = read_fixture(&CONTENT_SAMPLE, "sample.example");
    write_file(no_manifest.path(), "sample.example", &sample);

    let invalid = assemble(&CONTENT_SAMPLE);
    let manifest = String::from_utf8(read_fixture(&CONTENT_SAMPLE, "capsule.json"))
        .expect("UTF-8 manifest")
        .replacen("elastos.capsule/v1", "elastos.capsule/v2", 1);
    write_file(invalid.path(), "capsule.json", manifest.as_bytes());

    let linked = assemble(&WEB_APP);
    symlink("app.js", linked.path().join("browser/alias.js")).expect("link a payload");

    for bundle in [&no_manifest, &invalid, &linked] {
        let own = lab_cid(bundle.path()).expect_err("lab_cid refuses this bundle");
        let checked = check_name(bundle.path(), CONTENT_SAMPLE_LAB_CID)
            .expect_err("check_name refuses this bundle");
        assert_eq!(checked, own, "check_name changed lab_cid's refusal");
        assert_eq!(checked.to_string(), own.to_string());
    }
    // Each is the refusal that bundle has, not one shared reason.
    assert_eq!(
        lab_cid(no_manifest.path()).expect_err("no capsule.json"),
        Refusal::NoManifest
    );
    assert!(
        matches!(
            lab_cid(invalid.path()).expect_err("schema v2"),
            Refusal::ManifestInvalid(_)
        ),
        "the v2 manifest is not refused by validate()"
    );
    assert_eq!(
        lab_cid(linked.path()).expect_err("a link"),
        Refusal::NotRegularFile {
            path: "browser/alias.js".into(),
            kind: "symbolic link"
        }
    );
}

#[test]
fn check_name_uses_the_single_naming_path() {
    // P10: check_name names the bundle only by calling lab_cid, and computes
    // no name of its own. The library creates a SHA-256 hasher in exactly two
    // places: once in naming_hash (the one naming hash, which the encoder
    // calls for every leaf, file root block and directory block) and once in
    // domain_separated_digest (the one message hash, which the name
    // signature and the package record share).
    let code = library_code();
    let start = code
        .find("pub fn check_name(")
        .expect("the library defines check_name");
    let end = code[start..].find("\n}\n").expect("check_name's body ends");
    let body = &code[start..start + end];
    assert_eq!(
        body.matches("lab_cid(bundle)").count(),
        1,
        "check_name does not name the bundle with one lab_cid call:\n{body}"
    );
    for own_naming in [
        "lab_cid_observed(",
        "collect_entries(",
        "encode_entries(",
        "check_manifest(",
        "Sha256",
    ] {
        assert!(
            !body.contains(own_naming),
            "check_name names the bundle by itself ({own_naming}):\n{body}"
        );
    }
    // The encoder's definition, the seam's call, and task 015's one call that
    // names a variant recipe as one entry: the same encoder, not a second.
    assert_eq!(code.matches("encode_entries(").count(), 3, "encode_entries");
    assert_eq!(
        library_item(&code, "fn recipe_cid(")
            .matches("encode_entries(")
            .count(),
        1,
        "the recipe is not named by the one encoder"
    );
    assert_eq!(code.matches("Sha256::new()").count(), 2, "Sha256::new()");
    assert_eq!(
        library_item(&code, "fn naming_hash(")
            .matches("Sha256::new()")
            .count(),
        1,
        "naming_hash is not the one naming hash"
    );
    // Task 048: one file rule and one tree builder. encode_entries makes each
    // file's node with file_node and hands the nodes to encode_tree;
    // encode_listed_files makes each listed file's leaf with raw_leaf and
    // hands the leaves to the same encode_tree. Only encode_tree builds the
    // directories, and only it and the recursion call encode_directory, so a
    // second copy of the directory encoding fails here.
    let entries = library_item(&code, "pub fn encode_entries(");
    for (call, count) in [("file_node(", 1), ("encode_tree(", 1)] {
        assert_eq!(entries.matches(call).count(), count, "{call}\n{entries}");
    }
    let listed = library_item(&code, "pub fn encode_listed_files(");
    for (call, count) in [("raw_leaf(", 1), ("encode_tree(", 1)] {
        assert_eq!(listed.matches(call).count(), count, "{call}\n{listed}");
    }
    let chunked = library_item(&code, "pub fn encode_chunked_files(");
    for (call, count) in [("chunked_file_node(", 1), ("encode_tree(", 1)] {
        assert_eq!(chunked.matches(call).count(), count, "{call}\n{chunked}");
    }
    for (name, body) in [
        ("encode_entries", entries),
        ("encode_listed_files", listed),
        ("encode_chunked_files", chunked),
    ] {
        for own_encoding in [
            "Sha256",
            "naming_hash(",
            "Directory",
            "encode_directory(",
            "cid_bytes(",
            "_block(",
        ] {
            assert!(
                !body.contains(own_encoding),
                "{name} encodes by itself ({own_encoding}):\n{body}"
            );
        }
    }
    let tree = library_item(&code, "fn encode_tree(");
    for call in ["Directory::default()", ".insert(", "encode_directory("] {
        assert_eq!(tree.matches(call).count(), 1, "{call}\n{tree}");
    }
    assert_eq!(code.matches("encode_tree(").count(), 4, "encode_tree");
    assert_eq!(code.matches("encode_listed_files(").count(), 1);
    assert_eq!(code.matches("encode_chunked_files(").count(), 1);
    assert_eq!(code.matches("encode_directory(").count(), 3);
    assert_eq!(code.matches("Directory::default()").count(), 2);
    // One leaf rule: every raw leaf, a listed file's, a one-leaf file's and
    // each leaf of a file root, is made by raw_leaf.
    assert_eq!(code.matches("cid_bytes(RAW_CODEC").count(), 1, "RAW_CODEC");
    assert_eq!(
        library_item(&code, "fn raw_leaf(")
            .matches("cid_bytes(RAW_CODEC")
            .count(),
        1,
        "raw_leaf is not the one leaf rule"
    );
    assert_eq!(code.matches("raw_leaf(").count(), 6, "raw_leaf");
    // One file rule: file_node makes a file's node from its bytes, and
    // chunked_file_node makes the same node from a caller's leaf digests;
    // only they call file_root and file_root_block.
    let node = library_item(&code, "fn file_node(");
    for (call, count) in [("raw_leaf(", 1), ("file_root(", 1), ("naming_hash(", 1)] {
        assert_eq!(node.matches(call).count(), count, "{call}\n{node}");
    }
    let chunked_node = library_item(&code, "fn chunked_file_node(");
    for (call, count) in [
        ("raw_leaf(", 2),
        ("file_root_block(", 1),
        ("chunk_length(", 1),
        ("naming_hash(", 1),
        ("cid_bytes(DAG_PB_CODEC", 1),
    ] {
        assert_eq!(
            chunked_node.matches(call).count(),
            count,
            "{call}\n{chunked_node}"
        );
    }
    assert_eq!(code.matches("file_root(").count(), 2, "file_root");
    let root = library_item(&code, "fn file_root(");
    for (call, count) in [
        ("raw_leaf(", 1),
        ("file_root_block(", 1),
        ("naming_hash(", 2),
        ("cid_bytes(DAG_PB_CODEC", 1),
    ] {
        assert_eq!(root.matches(call).count(), count, "{call}\n{root}");
    }
    assert_eq!(code.matches("file_root_block(").count(), 3);
    assert_eq!(code.matches("FILE_TYPE").count(), 2, "FILE_TYPE");
    // One link encoding: directory blocks and file roots write their links
    // only through put_links.
    assert_eq!(code.matches("put_links(").count(), 3, "put_links");
    assert_eq!(code.matches("let mut pb_link").count(), 1, "pb_link");
    for block in ["fn directory_block(", "fn file_root_block("] {
        assert_eq!(
            library_item(&code, block).matches("put_links(").count(),
            1,
            "{block}"
        );
    }
    assert_eq!(
        library_item(&code, "pub fn domain_separated_digest(")
            .matches("Sha256::new()")
            .count(),
        1,
        "domain_separated_digest is not the one message hash"
    );
}
