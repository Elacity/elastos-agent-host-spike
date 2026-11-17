//! Pinned vectors for the one encoder, and one committed bundle whose CID must
//! not move.
//!
//! The three folder vectors below were produced by Kubo, not by this crate, so
//! they are a producer the verifier is independent of. Each was made with
//! Kubo 0.42.0 installed on this Mac:
//!
//! ```text
//! ipfs add -Q -r -n --pin=false --cid-version=1 --raw-leaves \
//!   --chunker=size-262144 --hash=sha2-256 --max-file-links=174 \
//!   --max-directory-links=0 --trickle=false <folder>
//! ```
//!
//! Those are the import flags the Runtime's IPFS provider sends
//! (`capsules/ipfs-provider/src/directory_hash.rs`, `ADD_OPTIONS`): CIDv1,
//! sha2-256, raw leaves, 262144-byte chunks, balanced layout, 174 file links.
//! The test runs no Kubo; it pins Kubo's output as a constant and requires the
//! encoder to reproduce it from the same bytes. A change to the encoding, or to
//! any byte of a committed bundle, is red here.

use std::path::Path;

use elastos_bundle_identity::{checked_bundle, encode_entries, lab_cid, BundleEntry};

fn entry(path: &str, content: impl Into<Vec<u8>>) -> BundleEntry {
    BundleEntry {
        path: path.to_owned(),
        content: content.into(),
    }
}

/// The CID of `entries` as the one encoder names them.
fn name(entries: &[BundleEntry]) -> String {
    encode_entries(entries)
        .unwrap_or_else(|refusal| panic!("the encoder refused these entries: {refusal}"))
        .to_string()
}

/// A 300000-byte file, byte `i` is `i % 251`: two raw leaves, 262144 and 37856
/// bytes, under one file root.
fn two_leaf_bytes() -> Vec<u8> {
    (0..300_000u32).map(|i| (i % 251) as u8).collect()
}

#[test]
fn kubo_folder_vectors_are_reproduced_by_the_one_encoder() {
    // v1: one folder, one file of one raw leaf.
    let v1 = vec![entry("a.txt", b"hello\n")];
    assert_eq!(
        name(&v1),
        "bafybeihm2fwylxiush5wrtgc2kxhfwffodhjhfdickb6qc6zufwiu6uwty",
        "Kubo folder vector v1: a folder with one raw-leaf file"
    );
    // The listing order never enters the value: the encoder sorts each block.
    let mut reversed = v1.clone();
    reversed.reverse();
    assert_eq!(name(&reversed), name(&v1), "listing order changed the CID");

    // v2: a folder with a manifest-sized file and a nested chunked file. The
    // nested file is over one leaf, so its file root and Tsize reach the root
    // through the folder: the whole tree is named, not just the root block.
    let v2 = vec![
        entry("capsule.json", b"{\"name\":\"vector\"}\n"),
        entry("nested/big.bin", two_leaf_bytes()),
    ];
    assert_eq!(
        name(&v2),
        "bafybeiev3jfyxo3vp7a6ewoz4ofzliv3czurnee3qic27qix5haphemwom",
        "Kubo folder vector v2: a folder with a two-leaf file one level down"
    );

    // v3: an empty file, a one-byte file and a text file: an empty raw leaf and
    // three links in one directory block.
    let v3 = vec![
        entry("empty", Vec::new()),
        entry("one", b"x"),
        entry("two.txt", b"second file\n"),
    ];
    assert_eq!(
        name(&v3),
        "bafybeihfcglzgp3l2men7wtpcvgtggzsvb7x4i6ovh3zegi7kzatpn4fsm",
        "Kubo folder vector v3: an empty file and two files in one folder"
    );
}

#[test]
fn the_committed_asks_nothing_bundle_keeps_its_recorded_cid() {
    // The bundle the start-by-CID rows stage: its two files, as committed.
    let bundle = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/components/asks-nothing/bundle");
    let checked =
        checked_bundle(&bundle).unwrap_or_else(|refusal| panic!("{}: {refusal}", bundle.display()));
    let mut paths: Vec<&str> = checked
        .entries()
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        ["asks-nothing.component.wasm", "capsule.json"],
        "the committed bundle's file set moved"
    );
    assert_eq!(
        checked.cid().to_string(),
        // The same value `bundle_start_tests.rs` records for this bundle.
        "bafybeifg5dmvip4scwenuyzleucrl4zl2fwfrma7xi7y3pmt544driy4fi",
        "the committed bundle's CID moved: an existing package identity changed"
    );
    assert_eq!(
        lab_cid(&bundle).unwrap().to_string(),
        checked.cid().to_string()
    );
}
