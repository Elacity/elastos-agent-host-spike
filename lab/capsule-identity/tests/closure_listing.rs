//! Naming a closure listing (task 047): a walk that already lists each
//! file's path, size and SHA-256 gets the lab CID from
//! `encode_listed_files`, the one encoder `encode_entries` and `lab_cid` use.
//! The listing under test is the photo lane's PH6 stand-in photo set, a byte
//! copy outside `fixtures/`.
//!
//! Signing a closure listing (task 049): the lab CID the listing gets is
//! signed and checked by the one package record, through `sign_cid_record`
//! and `verify_cid_record`, which the folder and checked record calls use.
mod common;

use std::fs;
use std::path::Path;

use capsule_identity::{
    encode_entries, encode_listed_files, lab_cid, sign_cid_record, sign_package_record,
    verify_checked_package_record, verify_cid_record, verify_package_record, BundleEntry,
    CheckedBundle, LabCid, ListedFile, PackageRecord, Refusal,
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

/// `entries` with the PH6 manifest's `viewer` object swapped for the string
/// the Runtime's manifest type takes, so `lab_cid`'s walk accepts the folder.
fn with_string_viewer(mut entries: Vec<BundleEntry>) -> Vec<BundleEntry> {
    let manifest = entries
        .iter_mut()
        .find(|entry| entry.path == "capsule.json")
        .expect("the copy holds capsule.json");
    let text = String::from_utf8(manifest.content.clone()).expect("a UTF-8 manifest");
    assert_eq!(text.matches(VIEWER_OBJECT).count(), 1, "{text}");
    manifest.content = text.replace(VIEWER_OBJECT, VIEWER_STRING).into_bytes();
    entries
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
    let entries = with_string_viewer(entries);
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

#[test]
fn listed_file_over_one_leaf_names_the_bytes_call() {
    // Task 048: a file over one leaf now has a lab CID, but only from its
    // bytes. A listed file's one SHA-256 names a single raw leaf, and a file
    // root needs each leaf's digest, so the listing call keeps its refusal
    // and its text points to the call that names the bytes.
    let bytes = vec![0; 262_145];
    let over = ListedFile {
        path: "core/docs.wasm".to_owned(),
        size: bytes.len() as u64,
        sha256: Sha256::digest(&bytes).into(),
    };
    let refusal = encode_listed_files(&[over]).expect_err("a listed file over one leaf");
    assert_eq!(
        refusal,
        Refusal::FileOverChunkLimit {
            path: "core/docs.wasm".into(),
            length: 262_145
        }
    );
    let text = refusal.to_string();
    for part in ["core/docs.wasm", "262145 bytes", "encode_entries"] {
        assert!(text.contains(part), "{part}: {text}");
    }
    encode_entries(&[BundleEntry {
        path: "core/docs.wasm".to_owned(),
        content: bytes,
    }])
    .expect("the bytes call names the same file");
}

/// The canonical `did:key` of `key`, from the Runtime's own encoder.
fn did_of(key: &ed25519_dalek::SigningKey) -> String {
    elastos_identity::encode_signing_key_did(key)
}

/// The lab CID of `listing`. A refusal fails the test with its reason.
fn listed_cid(listing: &[ListedFile]) -> LabCid {
    encode_listed_files(listing).unwrap_or_else(|refusal| panic!("the listing: {refusal}"))
}

/// The PH6 copy with `viewer` as a string, as a temp folder, and the lab CID
/// of the listing the photo walk makes of that folder.
fn string_viewer_folder() -> (tempfile::TempDir, LabCid) {
    let bundle = folder_of(&with_string_viewer(photo_stand_in_entries()));
    let mut listed = Vec::new();
    folder_entries(bundle.path(), "", &mut listed);
    assert_eq!(
        listed.len(),
        PHOTO_STAND_IN_FILES.len(),
        "the folder's files"
    );
    let cid = listed_cid(&listing_of(&listed));
    (bundle, cid)
}

/// `verify_cid_record` over `cid` and `verify_checked_package_record` over
/// `held`, whose CID is `cid`, both refuse `record`, with one refusal and one
/// text. That refusal is returned for the caller to judge.
fn refused_alike(
    cid: LabCid,
    held: &CheckedBundle,
    record: &PackageRecord,
    accepted: &[String],
) -> Refusal {
    assert_eq!(held.cid(), cid, "the checked bundle names another CID");
    let by_cid = verify_cid_record(cid, record, accepted)
        .expect_err("verify_cid_record passed a record it must refuse");
    let by_checked = verify_checked_package_record(held, record, accepted)
        .expect_err("verify_checked_package_record passed a record it must refuse");
    assert_eq!(
        by_cid, by_checked,
        "the two record checks refuse differently"
    );
    assert_eq!(by_cid.to_string(), by_checked.to_string());
    by_cid
}

/// The refusal is check (c)'s: the record names `record_cid`, and the CID it
/// was checked against is `against`. Both values are in the text.
fn assert_names_another_cid(refusal: Refusal, record_cid: LabCid, against: LabCid) {
    assert_eq!(
        refusal,
        Refusal::RecordNamesAnotherCid {
            record: record_cid.to_string(),
            bundle: against,
        }
    );
    assert_eq!(
        refusal.to_string(),
        format!("record names {record_cid}; the bundle names {against}")
    );
}

#[test]
fn a_closure_listing_gets_a_package_record_by_its_cid() {
    // The copy's five files, listed as the photo walk lists them. No folder
    // is walked for the signed name: `lab_cid` refuses this folder (047).
    let listing = listing_of(&photo_stand_in_entries());
    assert_eq!(listing.len(), PHOTO_STAND_IN_FILES.len());
    let cid = listed_cid(&listing);
    assert_eq!(cid.to_string(), PHOTO_STAND_IN_LAB_CID);

    let key = fresh_signing_key();
    let did = did_of(&key);
    let record = sign_cid_record(&key, cid);
    assert_eq!(record.cid, PHOTO_STAND_IN_LAB_CID);
    assert_eq!(record.signer_did, did);
    // The one record's rule, written out: no second schema, no name field.
    let expected = format!(
        "{{\"cid\":\"{PHOTO_STAND_IN_LAB_CID}\",\"schema\":\"lab.capsule-identity.record/v1\",\"signer_did\":\"{did}\"}}"
    );
    let payload =
        String::from_utf8(record.package_record_payload()).expect("the payload is UTF-8 JSON");
    assert_eq!(payload, expected);
    verify_cid_record(cid, &record, &[did])
        .unwrap_or_else(|refusal| panic!("the listing's record was refused: {refusal}"));
}

#[test]
fn the_folder_record_is_the_cid_record() {
    // Ed25519 is deterministic, so one key gives one record per CID however
    // the CID was computed.
    let key = fresh_signing_key();
    for (fixture, pin) in [
        (&CONTENT_SAMPLE, CONTENT_SAMPLE_LAB_CID),
        (&WEB_APP, WEB_APP_LAB_CID),
        (&AGENT_HOST, AGENT_HOST_LAB_CID),
        (&PROVIDER, PROVIDER_LAB_CID),
        (&MODEL, MODEL_LAB_CID),
        (&PROVIDER_VARIANT_A, PROVIDER_VARIANT_A_LAB_CID),
        (&PROVIDER_VARIANT_B, PROVIDER_VARIANT_B_LAB_CID),
    ] {
        let bundle = assemble(fixture);
        let cid = named(bundle.path());
        assert_eq!(cid.to_string(), pin, "{}", fixture.name);
        let from_folder = sign_package_record(&key, bundle.path())
            .unwrap_or_else(|refusal| panic!("{}: {refusal}", fixture.name));
        assert_eq!(
            from_folder,
            sign_cid_record(&key, cid),
            "{}: the folder record is not the CID record",
            fixture.name
        );
    }

    // 047's copy with `viewer` as a string: its folder and its listing name
    // one CID, so a record made from either passes the other's check.
    let (bundle, cid) = string_viewer_folder();
    let accepted = [did_of(&key)];
    let by_listing = sign_cid_record(&key, cid);
    verify_package_record(bundle.path(), &by_listing, &accepted)
        .unwrap_or_else(|refusal| panic!("the folder refused the listing's record: {refusal}"));
    let by_folder = sign_package_record(&key, bundle.path())
        .unwrap_or_else(|refusal| panic!("the folder: {refusal}"));
    verify_cid_record(cid, &by_folder, &accepted)
        .unwrap_or_else(|refusal| panic!("the listing refused the folder's record: {refusal}"));
    assert_eq!(by_folder, by_listing);
}

#[test]
fn cid_record_refuses_as_the_checked_record_does() {
    let (bundle, cid) = string_viewer_folder();
    let held = checked(bundle.path());
    let key = fresh_signing_key();
    let did = did_of(&key);
    let other_did = did_of(&fresh_signing_key());
    assert_ne!(did, other_did, "two fresh test keys have one DID");
    let record = sign_cid_record(&key, cid);
    verify_cid_record(cid, &record, &[did.clone()])
        .unwrap_or_else(|refusal| panic!("the good record was refused: {refusal}"));

    // The listing with one byte of one file's `sha256` changed names
    // another closure.
    let mut changed = listing_of(&photo_stand_in_entries());
    changed[2].sha256[0] ^= 1;
    let changed_cid = listed_cid(&changed);
    assert_ne!(changed_cid, cid);
    let refusal = verify_cid_record(changed_cid, &record, &[did.clone()])
        .expect_err("a record over the listing must not pass for the changed listing");
    assert_names_another_cid(refusal, cid, changed_cid);
    // The other way round, where a checked bundle holds the CID: a record
    // over the changed listing, judged by both calls.
    let over_changed = sign_cid_record(&key, changed_cid);
    let refusal = refused_alike(cid, &held, &over_changed, &[did.clone()]);
    assert_names_another_cid(refusal, changed_cid, cid);

    let refusal = refused_alike(cid, &held, &record, &[other_did]);
    assert_not_accepted(refusal, &did);
    let refusal = refused_alike(cid, &held, &record, &[]);
    assert_not_accepted(refusal, &did);

    let mut flipped = record.clone();
    flipped.signature[0] ^= 1;
    let refusal = refused_alike(cid, &held, &flipped, &[did.clone()]);
    assert_does_not_verify(refusal, &did, &cid.to_string());

    let malformed = "did:web:example.invalid".to_owned();
    let mut bad = record.clone();
    bad.signer_did = malformed.clone();
    // Listed, so only the decoder can refuse it.
    let refusal = refused_alike(cid, &held, &bad, &[malformed.clone()]);
    assert_malformed(refusal, &malformed);
}
