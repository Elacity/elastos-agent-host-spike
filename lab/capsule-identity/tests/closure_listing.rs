//! Naming a closure listing (task 047): a walk that already lists each
//! file's path, size and SHA-256 gets the lab CID from
//! `encode_listed_files`, the one encoder `encode_entries` and `lab_cid` use.
//! The listing under test is the photo lane's PH6 stand-in photo set, a byte
//! copy outside `fixtures/`.
mod common;

use std::fs;
use std::path::Path;

use capsule_identity::{
    encode_entries, encode_listed_files, lab_cid, BundleEntry, ListedFile, Refusal,
};
use common::*;
use sha2::{Digest, Sha256};

/// The PH6 manifest's `viewer`, an object, as committed.
const VIEWER_OBJECT: &str = "\"viewer\": {
    \"name\": \"image-viewer\",
    \"cid\": \"bafkreih2r3y7kst2gylz5miex5wptz2iqzfap2g53xmy27q2y6s6niurhe\"
  }";

/// The same `viewer` as the string the Runtime's manifest type takes.
const VIEWER_STRING: &str =
    "\"viewer\": \"bafkreih2r3y7kst2gylz5miex5wptz2iqzfap2g53xmy27q2y6s6niurhe\"";

/// The listing the photo walk makes of `entries`: each file's path, length
/// and the SHA-256 of its bytes, computed here and not by the library.
fn listing_of(entries: &[BundleEntry]) -> Vec<ListedFile> {
    entries
        .iter()
        .map(|entry| ListedFile {
            path: entry.path.clone(),
            size: entry.content.len() as u64,
            sha256: Sha256::digest(&entry.content).into(),
        })
        .collect()
}

/// Every regular file under `root`, each with its `/`-joined path below it,
/// as the photo walk lists a folder.
fn folder_entries(root: &Path, parent: &str, out: &mut Vec<BundleEntry>) {
    for item in fs::read_dir(root.join(parent)).expect("list a folder") {
        let item = item.expect("read a listing entry");
        let name = item.file_name().into_string().expect("a UTF-8 name");
        let path = if parent.is_empty() {
            name
        } else {
            format!("{parent}/{name}")
        };
        let kind = item.file_type().expect("an entry's type");
        if kind.is_dir() {
            folder_entries(root, &path, out);
        } else {
            assert!(kind.is_file(), "{path} is not a regular file");
            let content = fs::read(root.join(&path)).expect("read a file");
            out.push(BundleEntry { path, content });
        }
    }
}

/// A temp folder holding `entries`.
fn folder_of(entries: &[BundleEntry]) -> tempfile::TempDir {
    let bundle = temp_dir();
    for entry in entries {
        write_file(bundle.path(), &entry.path, &entry.content);
    }
    bundle
}

#[test]
fn photo_listing_gets_the_lab_cid_of_its_folder() {
    // The copy's five files, listed as the photo walk lists them.
    let entries = photo_stand_in_entries();
    let listing = listing_of(&entries);
    assert_eq!(listing.len(), PHOTO_STAND_IN_FILES.len());
    let from_listing =
        encode_listed_files(&listing).unwrap_or_else(|refusal| panic!("the listing: {refusal}"));
    let from_entries =
        encode_entries(&entries).unwrap_or_else(|refusal| panic!("the entries: {refusal}"));
    assert_eq!(
        (from_listing.to_string(), from_entries.to_string()),
        (
            PHOTO_STAND_IN_LAB_CID.to_owned(),
            PHOTO_STAND_IN_LAB_CID.to_owned()
        ),
        "(encode_listed_files, encode_entries) against the pin"
    );

    // The folder case: a temp copy whose `viewer` is the Runtime type's
    // string, so `lab_cid`'s walk and manifest check accept it. Its lab CID
    // equals the encoder's answer for the listing of that same folder.
    let mut entries = entries;
    let manifest = entries
        .iter_mut()
        .find(|entry| entry.path == "capsule.json")
        .expect("the copy holds capsule.json");
    let text = String::from_utf8(manifest.content.clone()).expect("a UTF-8 manifest");
    assert_eq!(text.matches(VIEWER_OBJECT).count(), 1, "{text}");
    manifest.content = text.replace(VIEWER_OBJECT, VIEWER_STRING).into_bytes();
    let bundle = folder_of(&entries);
    let mut listed = Vec::new();
    folder_entries(bundle.path(), "", &mut listed);
    assert_eq!(
        listed.len(),
        PHOTO_STAND_IN_FILES.len(),
        "the folder's files"
    );
    let walked = lab_cid(bundle.path()).unwrap_or_else(|refusal| panic!("the folder: {refusal}"));
    let from_folder_listing = encode_listed_files(&listing_of(&listed))
        .unwrap_or_else(|refusal| panic!("the folder's listing: {refusal}"));
    assert_eq!(walked, from_folder_listing, "lab_cid against the listing");
    assert_ne!(
        walked.to_string(),
        PHOTO_STAND_IN_LAB_CID,
        "the string viewer changed no byte"
    );
}

#[test]
fn lab_cid_refuses_the_photo_manifest_the_runtime_type_refuses() {
    // The exact five files: the Runtime's `CapsuleManifest` takes `viewer`
    // as a string, so the one manifest check refuses the object.
    let bundle = folder_of(&photo_stand_in_entries());
    let refusal = lab_cid(bundle.path()).expect_err("the PH6 manifest must be refused");
    assert!(
        matches!(refusal, Refusal::ManifestUnparsed(_)),
        "another refusal: {refusal}"
    );
}

#[test]
fn listed_file_over_the_chunk_limit_is_refused() {
    // 262144 is CHUNK_SIZE, the largest file one raw leaf holds.
    let mut listing = listing_of(&photo_stand_in_entries());
    let at_limit = ListedFile {
        path: "images/at-limit.raw".to_owned(),
        size: 262_144,
        sha256: [7; 32],
    };
    listing.push(at_limit);
    encode_listed_files(&listing).expect("a file of exactly one chunk is one raw leaf");

    let over = ListedFile {
        path: "images/over.raw".to_owned(),
        size: 262_144 + 1,
        sha256: [7; 32],
    };
    listing.push(over);
    let refusal = encode_listed_files(&listing).expect_err("a file over one chunk is refused");
    assert_eq!(
        refusal,
        Refusal::FileOverChunkLimit {
            path: "images/over.raw".into(),
            length: 262_145
        }
    );
}
