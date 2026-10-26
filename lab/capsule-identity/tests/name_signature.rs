//! A test key signs the printed lab CID. Verification checks that signature
//! and nothing else: no trust policy, no admission, no launch.
mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use capsule_identity::{
    name_signature_message, sign_bundle, verify_checked_signature, verify_name_signature,
    NameSignature, Refusal,
};
use common::*;

/// SHA-256 of `domain || 0x00 || content-sample's printed lab CID`. README
/// pins the same digest.
const CONTENT_SAMPLE_NAME_DIGEST: &str =
    "650c3b5baeb1e1e2f3cf1e87ded48ee496090c863d11afb9c80fbf07efb59f11";

fn sign(bundle: &Path) -> (ed25519_dalek::SigningKey, NameSignature) {
    let key = fresh_signing_key();
    let sig = sign_bundle(&key, bundle)
        .unwrap_or_else(|refusal| panic!("{}: {refusal}", bundle.display()));
    (key, sig)
}

fn accepted_of(sig: &NameSignature) -> Vec<String> {
    vec![sig.signer_did.clone()]
}

fn flip_signature(sig: &mut NameSignature) {
    sig.signature[0] ^= 1;
}

#[test]
fn test_key_signature_over_the_lab_cid_verifies() {
    for (fixture, pin) in [
        (&CONTENT_SAMPLE, CONTENT_SAMPLE_LAB_CID),
        (&WEB_APP, WEB_APP_LAB_CID),
    ] {
        let bundle = assemble(fixture);
        let (key, sig) = sign(bundle.path());
        let cid = named(bundle.path());
        assert_eq!(cid.to_string(), pin);
        assert_eq!(sig.name, cid.to_string());
        assert_eq!(
            sig.signer_did,
            elastos_identity::encode_signing_key_did(&key)
        );
        verify_name_signature(bundle.path(), &sig, &accepted_of(&sig))
            .unwrap_or_else(|refusal| panic!("{pin} was refused: {refusal}"));
    }
}

#[test]
fn signed_message_is_the_domain_separated_lab_cid() {
    let digest = name_signature_message(CONTENT_SAMPLE_LAB_CID);
    assert_eq!(hex::encode(digest), CONTENT_SAMPLE_NAME_DIGEST);
}

#[test]
fn signature_for_another_bundle_is_refused() {
    let sample = assemble(&CONTENT_SAMPLE);
    let web = assemble(&WEB_APP);
    let (_, sig) = sign(sample.path());
    let actual = named(web.path());
    assert_mismatch(
        verify_name_signature(web.path(), &sig, &accepted_of(&sig)),
        &sig.name,
        actual,
    );
}

#[test]
fn tampered_bundle_byte_is_refused() {
    let bundle = assemble(&WEB_APP);
    let (_, sig) = sign(bundle.path());
    flip_web_app_js(bundle.path());
    let actual = named(bundle.path());
    assert_ne!(actual.to_string(), sig.name);
    assert_mismatch(
        verify_name_signature(bundle.path(), &sig, &accepted_of(&sig)),
        &sig.name,
        actual,
    );
}

#[test]
fn relabelled_signature_is_refused() {
    let sample = assemble(&CONTENT_SAMPLE);
    let web = assemble(&WEB_APP);
    let (_, mut sig) = sign(sample.path());
    sig.name = named(web.path()).to_string();
    let refusal = verify_name_signature(web.path(), &sig, &accepted_of(&sig))
        .expect_err("a signature over another name must be refused");
    assert_does_not_verify(refusal, &sig.signer_did, &sig.name);
}

#[test]
fn tampered_signature_byte_is_refused() {
    let bundle = assemble(&WEB_APP);
    let (_, mut sig) = sign(bundle.path());
    flip_signature(&mut sig);
    let refusal = verify_name_signature(bundle.path(), &sig, &accepted_of(&sig))
        .expect_err("a changed signature must be refused");
    assert_does_not_verify(refusal, &sig.signer_did, &sig.name);
}

#[test]
fn signature_by_another_key_is_refused() {
    let bundle = assemble(&CONTENT_SAMPLE);
    let (key_a, _) = sign(bundle.path());
    let key_b = fresh_signing_key();
    let mut sig = sign_bundle(&key_b, bundle.path()).expect("key B signs the bundle");
    sig.signer_did = elastos_identity::encode_signing_key_did(&key_a);
    let accepted = accepted_of(&sig);
    let refusal = verify_name_signature(bundle.path(), &sig, &accepted)
        .expect_err("a signature by another key must be refused");
    assert_does_not_verify(refusal, &sig.signer_did, &sig.name);
}

#[test]
fn signer_not_in_the_accepted_list_is_refused() {
    let bundle = assemble(&WEB_APP);
    let (key_a, _) = sign(bundle.path());
    let key_b = fresh_signing_key();
    let sig = sign_bundle(&key_b, bundle.path()).expect("key B signs the bundle");
    let only_a = vec![elastos_identity::encode_signing_key_did(&key_a)];
    let refusal = verify_name_signature(bundle.path(), &sig, &only_a)
        .expect_err("a signer outside the accepted list must be refused");
    assert_not_accepted(refusal, &sig.signer_did);

    let empty: Vec<String> = Vec::new();
    let refusal = verify_name_signature(bundle.path(), &sig, &empty)
        .expect_err("an empty accepted list must refuse every signer");
    assert_not_accepted(refusal, &sig.signer_did);
}

#[test]
fn checked_signature_judges_the_checked_bytes() {
    let bundle = assemble(&WEB_APP);
    let (_, sig) = sign(bundle.path());
    let held = checked(bundle.path());
    flip_web_app_js(bundle.path());

    verify_checked_signature(&held, &sig, &accepted_of(&sig))
        .unwrap_or_else(|refusal| panic!("the checked bytes were refused: {refusal}"));

    let actual = named(bundle.path());
    assert_ne!(actual.to_string(), sig.name);
    assert_mismatch(
        verify_name_signature(bundle.path(), &sig, &accepted_of(&sig)),
        &sig.name,
        actual,
    );
    let fresh = checked(bundle.path());
    assert_eq!(fresh.cid(), actual);
    assert_mismatch(
        verify_checked_signature(&fresh, &sig, &accepted_of(&sig)),
        &sig.name,
        fresh.cid(),
    );

    let empty: Vec<String> = Vec::new();
    let refusal = verify_checked_signature(&held, &sig, &empty)
        .expect_err("an empty accepted list must refuse the checked form");
    assert_not_accepted(refusal, &sig.signer_did);
}

#[test]
fn malformed_signer_did_is_refused() {
    let bundle = assemble(&CONTENT_SAMPLE);
    let (key, sig) = sign(bundle.path());
    let real = elastos_identity::encode_signing_key_did(&key);
    let bad_dids = [
        "did:web:example.invalid".to_owned(),
        format!("{real}1"),
        String::new(),
    ];
    for did in bad_dids {
        let mut bad = sig.clone();
        bad.signer_did = did.clone();
        // Listed, so only the decoder can refuse it.
        let accepted = vec![did.clone()];
        let refusal = verify_name_signature(bundle.path(), &bad, &accepted)
            .expect_err("a malformed signer DID must be refused");
        assert_malformed(refusal, &did);
    }
}

#[test]
fn checked_signature_runs_all_checks() {
    // Each fault is judged by verify_checked_signature itself. A check that
    // lives only on the path form would let that fault through here.
    let web = assemble(&WEB_APP);
    let sample = assemble(&CONTENT_SAMPLE);
    let (_, sig) = sign(web.path());
    let held = checked(web.path());

    let mut malformed = sig.clone();
    malformed.signer_did = "did:web:example.invalid".to_owned();
    let refusal = verify_checked_signature(&held, &malformed, &accepted_of(&malformed))
        .expect_err("a malformed DID must be refused on the checked form");
    assert_malformed(refusal, &malformed.signer_did);

    let mut flipped = sig.clone();
    flip_signature(&mut flipped);
    let refusal = verify_checked_signature(&held, &flipped, &accepted_of(&flipped))
        .expect_err("a bad signature must be refused on the checked form");
    assert_does_not_verify(refusal, &flipped.signer_did, &flipped.name);

    let (_, other) = sign(sample.path());
    assert_mismatch(
        verify_checked_signature(&held, &other, &accepted_of(&other)),
        &other.name,
        held.cid(),
    );

    let empty: Vec<String> = Vec::new();
    let refusal = verify_checked_signature(&held, &sig, &empty)
        .expect_err("an empty accepted list must be refused on the checked form");
    assert_not_accepted(refusal, &sig.signer_did);
}

#[test]
fn signature_paths_preserve_walk_refusals() {
    let good = assemble(&CONTENT_SAMPLE);
    let (_, sig) = sign(good.path());
    let mut malformed = sig.clone();
    malformed.signer_did = "did:web:example.invalid".to_owned();
    let mut flipped = sig.clone();
    flip_signature(&mut flipped);
    let mut not_a_name = sig.clone();
    not_a_name.name = "not-a-lab-cid".to_owned();
    let did = sig.signer_did.clone();
    let inputs = [
        (&sig, vec![did.clone()]),
        (&malformed, vec![malformed.signer_did.clone()]),
        (&sig, Vec::new()),
        (&flipped, vec![did.clone()]),
        (&not_a_name, vec![did]),
    ];
    for bundle in &walk_refused_bundles() {
        let path = bundle.path();
        let from_lab_cid = lab_cid_refusal(path);
        assert_same_refusal(
            sign_bundle(&fresh_signing_key(), path).map(|_| ()),
            &from_lab_cid,
        );
        let from_walk = checked_bundle_refusal(path);
        assert_eq!(from_walk, from_lab_cid);
        assert_eq!(from_walk.to_string(), from_lab_cid.to_string());
        for (sig, accepted) in &inputs {
            assert_same_refusal(verify_name_signature(path, sig, accepted), &from_walk);
        }
    }
}

#[test]
fn signature_walk_refusal_precedes_bad_signature() {
    let good = assemble(&CONTENT_SAMPLE);
    let (_, mut sig) = sign(good.path());
    flip_signature(&mut sig);
    let accepted = accepted_of(&sig);
    let refusal = verify_checked_signature(&checked(good.path()), &sig, &accepted)
        .expect_err("the canonical accepted signer has a bad signature");
    assert_does_not_verify(refusal, &sig.signer_did, &sig.name);

    let no_manifest = temp_dir();
    let from_walk = checked_bundle_refusal(no_manifest.path());
    assert_same_refusal(
        verify_name_signature(no_manifest.path(), &sig, &accepted),
        &from_walk,
    );
}

fn lab_cid_refusal(bundle: &Path) -> Refusal {
    capsule_identity::lab_cid(bundle).expect_err("lab_cid refuses this bundle")
}

fn checked_bundle_refusal(bundle: &Path) -> Refusal {
    capsule_identity::checked_bundle(bundle).expect_err("the walk refuses this bundle")
}

#[test]
fn signature_refusal_order_is_stable() {
    // Each input has two faults. The earlier check is the one that answers,
    // so swapping two adjacent checks changes the refusal.
    let bundle = assemble(&WEB_APP);
    let (key_a, sig) = sign(bundle.path());
    let key_b = fresh_signing_key();
    let did_a = elastos_identity::encode_signing_key_did(&key_a);
    let did_b = elastos_identity::encode_signing_key_did(&key_b);
    let held = checked(bundle.path());

    // (a) before (b): the DID is not canonical and it is not accepted.
    let mut malformed_and_unlisted = sig.clone();
    malformed_and_unlisted.signer_did.clear();
    let refusal = verify_checked_signature(&held, &malformed_and_unlisted, &[])
        .expect_err("a malformed unlisted DID is refused");
    assert_malformed(refusal, "");

    // (b) before (c): key B is not accepted, and the name is another bundle's.
    let mut unlisted_and_mismatch = sig.clone();
    unlisted_and_mismatch.signer_did = did_b.clone();
    unlisted_and_mismatch.name = CONTENT_SAMPLE_LAB_CID.to_owned();
    let refusal = verify_checked_signature(&held, &unlisted_and_mismatch, &[did_a.clone()])
        .expect_err("an unlisted signer with a mismatched name is refused");
    assert_not_accepted(refusal, &did_b);

    // (c) before (d): the name is another bundle's, and the signature bit is flipped.
    let mut mismatch_and_bad_signature = sig.clone();
    mismatch_and_bad_signature.name = CONTENT_SAMPLE_LAB_CID.to_owned();
    flip_signature(&mut mismatch_and_bad_signature);
    let refusal = verify_checked_signature(&held, &mismatch_and_bad_signature, &accepted_of(&sig))
        .expect_err("a mismatched name with a bad signature is refused");
    assert_mismatch(Err(refusal), CONTENT_SAMPLE_LAB_CID, held.cid());
}

#[test]
fn signature_paths_share_one_implementation() {
    let code = library_code();
    assert_eq!(code.matches("Sha256::new()").count(), 2, "Sha256::new()");
    assert_eq!(
        library_item(&code, "pub fn domain_separated_digest(")
            .matches("Sha256::new()")
            .count(),
        1
    );
    assert_eq!(
        library_item(&code, "pub fn encode_entries(")
            .matches("Sha256::new()")
            .count(),
        1
    );
    let message = library_item(&code, "pub fn name_signature_message(");
    assert_eq!(
        message.matches("domain_separated_digest(").count(),
        1,
        "{message}"
    );
    assert!(!message.contains("Sha256"), "{message}");
    assert_eq!(code.matches("name_signature_message(").count(), 3);
    // One DID encoder, one DID decoder and one Ed25519 verification, each
    // behind its one function, which both signatures call.
    assert_eq!(code.matches("decode_did_key(").count(), 1);
    assert_eq!(code.matches("encode_signing_key_did(").count(), 1);
    assert_eq!(code.matches(".verify(").count(), 1);
    assert_eq!(code.matches("Signature::from_bytes(").count(), 1);
    assert_eq!(code.matches("fn decode_signer(").count(), 1);
    assert_eq!(code.matches("fn require_accepted(").count(), 1);
    assert_eq!(code.matches("fn verify_signature(").count(), 1);
    assert_eq!(code.matches("fn verify_ed25519(").count(), 1);
    assert_eq!(code.matches("fn signer_did_of(").count(), 1);
    for (item, call) in [
        ("fn decode_signer(", "decode_did_key("),
        ("fn signer_did_of(", "encode_signing_key_did("),
        ("fn verify_ed25519(", ".verify("),
    ] {
        let body = library_item(&code, item);
        assert_eq!(body.matches(call).count(), 1, "{body}");
    }

    let sign = library_item(&code, "pub fn sign_bundle(");
    assert_eq!(sign.matches("lab_cid(").count(), 1, "{sign}");
    assert_eq!(sign.matches("name_signature_message(").count(), 1, "{sign}");
    assert_eq!(sign.matches("signer_did_of(").count(), 1, "{sign}");
    assert!(!sign.contains("Sha256"), "{sign}");
    assert!(!sign.contains("checked_bundle"), "{sign}");

    let message = library_item(&code, "fn verify_signature(");
    assert_eq!(
        message.matches("name_signature_message(").count(),
        1,
        "{message}"
    );
    assert_eq!(message.matches("verify_ed25519(").count(), 1, "{message}");

    let checked = library_item(&code, "pub fn verify_checked_signature(");
    for call in [
        "decode_signer(",
        "require_accepted(",
        "checked.check_name(",
        "verify_signature(",
    ] {
        assert_eq!(
            checked.matches(call).count(),
            1,
            "{call} is not the one check in the checked form:\n{checked}"
        );
    }
    let decode_at = checked.find("decode_signer(").expect("decode");
    let accept_at = checked.find("require_accepted(").expect("accept");
    let name_at = checked.find("checked.check_name(").expect("name");
    let verify_at = checked.find("verify_signature(").expect("verify");
    assert!(
        decode_at < accept_at && accept_at < name_at && name_at < verify_at,
        "the checked form's checks are out of order:\n{checked}"
    );

    let path = library_item(&code, "pub fn verify_name_signature(");
    assert_eq!(path.matches("checked_bundle(").count(), 1, "{path}");
    assert_eq!(
        path.matches("verify_checked_signature(").count(),
        1,
        "{path}"
    );
    for own in [
        "decode_signer(",
        "require_accepted(",
        "check_name(",
        "verify_signature(",
        "name_signature_message(",
        "decode_did_key(",
        "encode_signing_key_did(",
        "Sha256",
        ".verify(",
        "lab_cid(",
        "fs::",
        "File::",
    ] {
        assert!(
            !path.contains(own),
            "the path form does its own work ({own}):\n{path}"
        );
    }

    let definition = library_item(&code, "pub struct NameSignature {");
    assert!(!definition.contains("serde"), "{definition}");
    let start = code
        .find("pub struct NameSignature {")
        .expect("NameSignature");
    let attributes: Vec<&str> = code[..start]
        .lines()
        .rev()
        .take_while(|line| line.starts_with("#["))
        .collect();
    for maker in ["Serialize", "Deserialize"] {
        assert!(
            !attributes.iter().any(|attribute| attribute.contains(maker)),
            "NameSignature derives {maker}: {attributes:?}"
        );
    }
}

#[test]
fn test_keys_use_fresh_os_randomness() {
    let first = fresh_signing_key();
    let second = fresh_signing_key();
    assert!(
        first.verifying_key().to_bytes() != second.verifying_key().to_bytes(),
        "two fresh test keys were the same"
    );

    let generate = format!("SigningKey::generate(&mut {})", "OsRng");
    let banned = [
        format!("SigningKey::from_{}", "bytes"),
        format!("SigningKey::from_{}", "seed"),
        format!("SigningKey::from_{}", "keypair_bytes"),
        format!("{}::from_seed", "StdRng"),
        // Raw key bytes, such as a constant array, through `From`.
        format!("SigningKey::from{}", "("),
        format!("Secret{}", "Key"),
    ];
    let mut rust_files = Vec::new();
    collect_rust(&lane_dir(), &mut rust_files);
    let mut generate_count = 0;
    for path in &rust_files {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        generate_count += text.matches(&generate).count();
        for needle in &banned {
            assert!(
                !text.contains(needle),
                "{} contains {needle}",
                path.display()
            );
        }
    }
    assert_eq!(
        generate_count, 1,
        "test keys are generated in one place, from the operating system's generator"
    );
}

fn collect_rust(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|error| panic!("read {}: {error}", dir.display()));
    for entry in entries {
        let entry = entry.expect("read a directory entry");
        let path = entry.path();
        let name = entry.file_name();
        if name == "target" {
            continue;
        }
        if path.is_dir() {
            collect_rust(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// What `git ls-files` would stage under this lane: tracked files and
/// untracked files git would not ignore. An ignored file cannot be staged.
fn lane_files_git_would_stage() -> Vec<(String, Vec<u8>)> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .current_dir(lane_dir())
        .output()
        .unwrap_or_else(|error| panic!("git cannot run: {error}"));
    assert!(
        output.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut files = Vec::new();
    for name in output.stdout.split(|byte| *byte == 0) {
        if name.is_empty() {
            continue;
        }
        let name = String::from_utf8(name.to_vec())
            .unwrap_or_else(|error| panic!("a path is not UTF-8: {error}"));
        let path = lane_dir().join(&name);
        let bytes =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        files.push((name, bytes));
    }
    assert!(!files.is_empty(), "git listed no files");
    files
}

#[test]
fn no_key_material_is_tracked() {
    let staged = lane_files_git_would_stage();
    let filed: Vec<Filed<'_>> = staged
        .iter()
        .map(|(name, bytes)| Filed { name, bytes })
        .collect();
    let found = key_material_findings(&filed);
    assert!(
        found.is_empty(),
        "key material would be committed: {found:?}"
    );

    let (header_start, header_end) = pem_private_ends();
    let header = format!("{header_start}{header_end}");
    let raw = vec![0xff_u8; 32];
    let planted = [
        Filed {
            name: "planted.key",
            bytes: b"not a key",
        },
        Filed {
            name: "planted.seed",
            bytes: b"not a seed",
        },
        Filed {
            name: "notes.txt",
            bytes: header.as_bytes(),
        },
        Filed {
            name: "blob.bin",
            bytes: &raw,
        },
    ];
    let found = key_material_findings(&planted);
    for needle in [
        "name:planted.key",
        "name:planted.seed",
        "header:",
        "raw-seed:",
    ] {
        assert!(
            found.iter().any(|hit| hit.contains(needle)),
            "the scan missed {needle}: {found:?}"
        );
    }
}

#[test]
fn key_material_scan_finds_headers_in_non_utf8_files() {
    let (header_start, header_end) = pem_private_ends();
    let header = format!("{header_start}{header_end}");
    let padded = format!("\t\u{2003}{header}\u{2003}\r\n");
    for (bytes, line) in [
        ([b"\xff\n".as_slice(), header.as_bytes(), b"\n"].concat(), 1),
        ([padded.as_bytes(), b"\xff"].concat(), 0),
        (
            [header_start.as_bytes(), b"\xff", header_end.as_bytes()].concat(),
            0,
        ),
    ] {
        assert!(std::str::from_utf8(&bytes).is_err());
        assert_ne!(bytes.len(), 32, "this case isolates the header check");
        assert_eq!(
            key_material_findings(&[Filed {
                name: "notes.bin",
                bytes: &bytes
            }]),
            vec![format!("header:notes.bin:{line}")],
        );
    }

    let public_header = format!("{header_start}PUBLIC KEY-----");
    for bytes in [
        [b"\xff".as_slice(), header.as_bytes()].concat(),
        [header.as_bytes(), b"\xff"].concat(),
        [b"\xff\n".as_slice(), public_header.as_bytes(), b"\n"].concat(),
    ] {
        assert!(std::str::from_utf8(&bytes).is_err());
        assert_ne!(bytes.len(), 32, "this case isolates the header check");
        assert!(key_material_findings(&[Filed {
            name: "notes.bin",
            bytes: &bytes
        }])
        .is_empty());
    }
}

#[test]
fn key_and_seed_files_are_ignored_by_git() {
    let paths = ["x.key", "fixtures/x.key", "x.seed", "fixtures/x.seed"];
    let output = Command::new("git")
        .args(["check-ignore", "-v"])
        .args(paths)
        .current_dir(lane_dir())
        .output()
        .unwrap_or_else(|error| panic!("git cannot run: {error}"));
    assert!(
        output.status.success(),
        "git check-ignore failed ({:?}): {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    for path in paths {
        let ignored = text
            .lines()
            .any(|line| line.split('\t').nth(1) == Some(path));
        assert!(ignored, "{path} is not ignored:\n{text}");
    }
}
