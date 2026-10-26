//! A lab package record outside the bundle names the signer and binds the
//! printed lab CID. Verification checks that record and nothing else: no
//! trust policy, no admission, no launch. Every expected CID comes from the
//! pins in `common`, so a change of the printed form changes the pins only.
mod common;

use std::fs;
use std::path::Path;

use capsule_identity::{
    checked_bundle, domain_separated_digest, lab_cid, sign_package_record,
    verify_checked_package_record, verify_package_record, LabCid, PackageRecord, Refusal,
    MANIFEST_FILE,
};
use common::*;
use ed25519_dalek::{Signer, SigningKey};
use elastos_common::CapsuleManifest;

/// The two domains, written out here rather than read from the library, so
/// a changed domain constant fails these tests.
const NAME_DOMAIN: &str = "lab.capsule-identity.name-signature/v1";
const RECORD_DOMAIN: &str = "lab.capsule-identity.package-record/v1";

fn sign(key: &SigningKey, bundle: &Path) -> PackageRecord {
    sign_package_record(key, bundle)
        .unwrap_or_else(|refusal| panic!("{}: {refusal}", bundle.display()))
}

fn did_of(key: &SigningKey) -> String {
    elastos_identity::encode_signing_key_did(key)
}

/// Both verifiers' answers for `record` on the bundle at `bundle`: the
/// checked form on a fresh `checked_bundle`, then the path form. Every
/// refusal test judges both, so a check that lives only in the path form,
/// or only in the checked form, fails it.
fn both(
    bundle: &Path,
    record: &PackageRecord,
    accepted: &[String],
) -> [(&'static str, Result<(), Refusal>); 2] {
    [
        (
            "verify_checked_package_record",
            verify_checked_package_record(&checked(bundle), record, accepted),
        ),
        (
            "verify_package_record",
            verify_package_record(bundle, record, accepted),
        ),
    ]
}

/// Both verifiers refuse, and `judge` checks each refusal.
fn both_refuse(
    bundle: &Path,
    record: &PackageRecord,
    accepted: &[String],
    judge: impl Fn(Refusal),
) {
    for (verifier, answer) in both(bundle, record, accepted) {
        let Err(refusal) = answer else {
            panic!("{verifier} passed a record it must refuse")
        };
        judge(refusal);
    }
}

/// Both verifiers pass the record.
fn both_pass(bundle: &Path, record: &PackageRecord, accepted: &[String]) {
    for (verifier, answer) in both(bundle, record, accepted) {
        answer.unwrap_or_else(|refusal| panic!("{verifier} refused {}: {refusal}", record.cid));
    }
}

/// The refusal is check (c)'s: the record names `record_cid`, and the
/// checked bytes name `bundle`. Both values are in the text.
fn assert_names_another_cid(refusal: Refusal, record_cid: &str, bundle: LabCid) {
    assert_eq!(
        refusal,
        Refusal::RecordNamesAnotherCid {
            record: record_cid.to_owned(),
            bundle,
        }
    );
    assert_eq!(
        refusal.to_string(),
        format!("record names {record_cid}; the bundle names {bundle}")
    );
}

#[test]
fn package_record_binds_the_cid_and_verifies() {
    for (fixture, pin) in [
        (&CONTENT_SAMPLE, CONTENT_SAMPLE_LAB_CID),
        (&WEB_APP, WEB_APP_LAB_CID),
    ] {
        let bundle = assemble(fixture);
        let key = fresh_signing_key();
        let record = sign(&key, bundle.path());
        let did = did_of(&key);
        assert_eq!(record.cid, pin);
        assert_eq!(record.signer_did, did);
        // The rule, written out: compact JSON, keys in this order, no
        // spaces, no trailing newline, no name and no signature field.
        let expected = format!(
            "{{\"cid\":\"{pin}\",\"schema\":\"lab.capsule-identity.record/v1\",\"signer_did\":\"{did}\"}}"
        );
        let payload =
            String::from_utf8(record.package_record_payload()).expect("the payload is UTF-8 JSON");
        assert_eq!(payload, expected);
        both_pass(bundle.path(), &record, &[did]);
    }
}

#[test]
fn package_record_stays_outside_the_bundle() {
    for fixture in [&CONTENT_SAMPLE, &WEB_APP] {
        let parent = temp_dir();
        let bundle = parent.path().join(fixture.name);
        assemble_at(fixture, &bundle);
        let before = listing(parent.path());
        assert_eq!(
            before,
            [fixture.name],
            "the bundle is the parent's one entry"
        );
        let cid = named(&bundle);
        let manifest = fs::read(bundle.join(MANIFEST_FILE)).expect("read capsule.json");
        let untouched = |step: &str| {
            assert_eq!(
                listing(parent.path()),
                before,
                "{step} changed the entries next to the bundle"
            );
            assert_eq!(named(&bundle), cid, "{step} changed the bundle's lab CID");
            let now = fs::read(bundle.join(MANIFEST_FILE)).expect("read capsule.json");
            assert_eq!(now, manifest, "{step} changed capsule.json");
            let parsed: CapsuleManifest = serde_json::from_slice(&now)
                .expect("the Runtime's CapsuleManifest parses capsule.json");
            assert!(
                parsed.signature.is_none(),
                "{step} put a signature in capsule.json"
            );
        };

        let record = sign(&fresh_signing_key(), &bundle);
        untouched("signing");
        let accepted = [record.signer_did.clone()];
        verify_checked_package_record(&checked(&bundle), &record, &accepted)
            .unwrap_or_else(|refusal| panic!("the checked form refused: {refusal}"));
        untouched("the checked verifier");
        verify_package_record(&bundle, &record, &accepted)
            .unwrap_or_else(|refusal| panic!("the path form refused: {refusal}"));
        untouched("the path verifier");
    }
}

#[test]
fn record_signed_under_the_wrong_domain_is_refused() {
    let bundle = assemble(&CONTENT_SAMPLE);
    let key = fresh_signing_key();
    let record = sign(&key, bundle.path());
    let payload = record.package_record_payload();
    let accepted = [record.signer_did.clone()];

    let mut wrong = record.clone();
    wrong.signature = key
        .sign(&domain_separated_digest(NAME_DOMAIN, &payload))
        .to_bytes();
    both_refuse(bundle.path(), &wrong, &accepted, |refusal| {
        assert_does_not_verify(refusal, &record.signer_did, &record.cid)
    });

    let mut right = record.clone();
    right.signature = key
        .sign(&domain_separated_digest(RECORD_DOMAIN, &payload))
        .to_bytes();
    assert_eq!(
        right.signature, record.signature,
        "sign_package_record does not sign the record domain's digest of the payload"
    );
    both_pass(bundle.path(), &right, &accepted);
}

#[test]
fn record_rebound_to_another_cid_is_refused() {
    let sample = assemble(&CONTENT_SAMPLE);
    let web = assemble(&WEB_APP);
    let record = sign(&fresh_signing_key(), sample.path());
    assert_eq!(record.cid, CONTENT_SAMPLE_LAB_CID);
    let accepted = [record.signer_did.clone()];
    let mut rebound = record.clone();
    rebound.cid = WEB_APP_LAB_CID.to_owned();

    let sample_cid = named(sample.path());
    assert_eq!(sample_cid.to_string(), CONTENT_SAMPLE_LAB_CID);
    both_refuse(sample.path(), &rebound, &accepted, |refusal| {
        let text = refusal.to_string();
        assert!(text.contains(WEB_APP_LAB_CID) && text.contains(CONTENT_SAMPLE_LAB_CID));
        assert_names_another_cid(refusal, WEB_APP_LAB_CID, sample_cid)
    });

    // On the bundle it now names, the signature over the old payload fails.
    both_refuse(web.path(), &rebound, &accepted, |refusal| {
        assert_does_not_verify(refusal, &rebound.signer_did, WEB_APP_LAB_CID)
    });
}

#[test]
fn record_by_another_signer_is_refused() {
    let bundle = assemble(&WEB_APP);
    let key_a = fresh_signing_key();
    let key_b = fresh_signing_key();
    let did_a = did_of(&key_a);
    let did_b = did_of(&key_b);
    assert_ne!(did_a, did_b, "two fresh test keys have one DID");
    let by_b = sign(&key_b, bundle.path());
    assert_eq!(by_b.signer_did, did_b);

    let mut claims_a = by_b.clone();
    claims_a.signer_did = did_a.clone();
    both_refuse(bundle.path(), &claims_a, &[did_a.clone()], |refusal| {
        assert_does_not_verify(refusal, &did_a, &claims_a.cid)
    });

    both_refuse(bundle.path(), &by_b, &[did_a.clone()], |refusal| {
        assert_not_accepted(refusal, &did_b)
    });
    both_refuse(bundle.path(), &by_b, &[], |refusal| {
        assert_not_accepted(refusal, &did_b)
    });
}

#[test]
fn checked_record_judges_the_checked_bytes() {
    let bundle = assemble(&WEB_APP);
    let record = sign(&fresh_signing_key(), bundle.path());
    assert_eq!(record.cid, WEB_APP_LAB_CID);
    let accepted = [record.signer_did.clone()];
    let held = checked(bundle.path());
    flip_web_app_js(bundle.path());

    verify_checked_package_record(&held, &record, &accepted)
        .unwrap_or_else(|refusal| panic!("the checked bytes were refused: {refusal}"));

    let actual = named(bundle.path());
    assert_ne!(actual.to_string(), record.cid);
    let refusal = verify_package_record(bundle.path(), &record, &accepted)
        .expect_err("the changed folder no longer has the record's CID");
    assert_names_another_cid(refusal, WEB_APP_LAB_CID, actual);
}

#[test]
fn record_malformed_signer_did_is_refused() {
    let bundle = assemble(&CONTENT_SAMPLE);
    let key = fresh_signing_key();
    let record = sign(&key, bundle.path());
    let real = did_of(&key);
    for did in [
        "did:web:example.invalid".to_owned(),
        format!("{real}1"),
        String::new(),
    ] {
        let mut bad = record.clone();
        bad.signer_did = did.clone();
        // Listed, so only the decoder can refuse it.
        both_refuse(bundle.path(), &bad, &[did.clone()], |refusal| {
            assert_malformed(refusal, &did)
        });
    }
}

#[test]
fn record_refusal_order_is_stable() {
    // Each input has two faults. The earlier check is the one that answers,
    // so swapping two adjacent checks changes the refusal, in both verifiers.
    let sample = assemble(&CONTENT_SAMPLE);
    let key_a = fresh_signing_key();
    let did_a = did_of(&key_a);
    let did_b = did_of(&fresh_signing_key());
    let record = sign(&key_a, sample.path());
    let sample_cid = named(sample.path());

    // (a) before (b): the DID is not canonical and it is not accepted.
    let mut malformed_and_unlisted = record.clone();
    malformed_and_unlisted.signer_did.clear();
    both_refuse(sample.path(), &malformed_and_unlisted, &[], |refusal| {
        assert_malformed(refusal, "")
    });

    // (b) before (c): B is not accepted, and the CID is another bundle's.
    let mut unlisted_and_rebound = record.clone();
    unlisted_and_rebound.signer_did = did_b.clone();
    unlisted_and_rebound.cid = WEB_APP_LAB_CID.to_owned();
    both_refuse(
        sample.path(),
        &unlisted_and_rebound,
        &[did_a.clone()],
        |refusal| assert_not_accepted(refusal, &did_b),
    );

    // (c) before (d): the CID is another bundle's, so the signature over the
    // payload with that CID does not verify either.
    let mut rebound = record.clone();
    rebound.cid = WEB_APP_LAB_CID.to_owned();
    both_refuse(sample.path(), &rebound, &[did_a.clone()], |refusal| {
        assert_names_another_cid(refusal, WEB_APP_LAB_CID, sample_cid)
    });
}

#[test]
fn record_paths_preserve_walk_refusals() {
    let good = assemble(&CONTENT_SAMPLE);
    let record = sign(&fresh_signing_key(), good.path());
    let did = record.signer_did.clone();
    let mut malformed = record.clone();
    malformed.signer_did = "did:web:example.invalid".to_owned();
    let mut flipped = record.clone();
    flipped.signature[0] ^= 1;
    let mut rebound = record.clone();
    rebound.cid = WEB_APP_LAB_CID.to_owned();
    let inputs = [
        (&record, vec![did.clone()]),
        (&malformed, vec![malformed.signer_did.clone()]),
        (&record, Vec::new()),
        (&flipped, vec![did.clone()]),
        (&rebound, vec![did]),
    ];
    for bundle in &walk_refused_bundles() {
        let path = bundle.path();
        let from_lab_cid = lab_cid(path).expect_err("lab_cid refuses this bundle");
        assert_same_refusal(
            sign_package_record(&fresh_signing_key(), path).map(|_| ()),
            &from_lab_cid,
        );
        let from_walk = checked_bundle(path).expect_err("the walk refuses this bundle");
        assert_eq!(from_walk, from_lab_cid);
        for (record, accepted) in &inputs {
            assert_same_refusal(verify_package_record(path, record, accepted), &from_walk);
        }
    }
}

#[test]
fn record_paths_share_one_implementation() {
    let code = library_code();
    // One payload builder, one record message, one digest.
    for (text, count) in [
        ("\\\"cid\\\":", 1),
        ("\\\"schema\\\":", 1),
        ("\\\"signer_did\\\":", 1),
        ("PACKAGE_RECORD_SCHEMA", 2),
        ("PACKAGE_RECORD_DOMAIN", 2),
        ("package_record_payload(", 2),
        ("package_record_message(", 3),
        ("domain_separated_digest(", 3),
        ("fn require_record_cid(", 1),
        ("require_record_cid(", 2),
        ("signer_did_of(", 3),
        ("verify_ed25519(", 3),
    ] {
        assert_eq!(code.matches(text).count(), count, "{text}");
    }
    let payload = library_item(&code, "pub fn package_record_payload(&self");
    assert!(payload.contains("PACKAGE_RECORD_SCHEMA"), "{payload}");
    let message = library_item(&code, "fn package_record_message(");
    for call in [
        "domain_separated_digest(PACKAGE_RECORD_DOMAIN",
        "package_record_payload(",
    ] {
        assert_eq!(message.matches(call).count(), 1, "{message}");
    }

    let sign = library_item(&code, "pub fn sign_package_record(");
    for call in ["lab_cid(", "signer_did_of(", "package_record_message("] {
        assert_eq!(sign.matches(call).count(), 1, "{call}:\n{sign}");
    }
    for own in [
        "Sha256",
        "domain_separated_digest(",
        "format!",
        "checked_bundle",
        "encode_signing_key_did(",
        "fs::",
        "File",
    ] {
        assert!(
            !sign.contains(own),
            "the signer does its own work ({own}):\n{sign}"
        );
    }

    let checked = library_item(&code, "pub fn verify_checked_package_record(");
    let mut at = Vec::new();
    for call in [
        "decode_signer(",
        "require_accepted(",
        "require_record_cid(",
        "package_record_message(",
        "verify_ed25519(",
    ] {
        assert_eq!(
            checked.matches(call).count(),
            1,
            "{call} is not the one check in the checked form:\n{checked}"
        );
        at.push(checked.find(call).expect("found once"));
    }
    assert!(
        at.windows(2).all(|pair| pair[0] < pair[1]),
        "the checked form's checks are out of order:\n{checked}"
    );
    for own in [
        "decode_did_key(",
        ".verify(",
        "Signature::",
        "format!",
        "Sha256",
        "domain_separated_digest(",
        "checked_bundle(",
        "lab_cid(",
        "fs::",
    ] {
        assert!(
            !checked.contains(own),
            "the checked form does its own work ({own}):\n{checked}"
        );
    }

    let path = library_item(&code, "pub fn verify_package_record(");
    assert_eq!(path.matches("checked_bundle(").count(), 1, "{path}");
    assert_eq!(
        path.matches("verify_checked_package_record(").count(),
        1,
        "{path}"
    );
    for own in [
        "decode_signer(",
        "require_accepted(",
        "require_record_cid(",
        "package_record_message(",
        "package_record_payload(",
        "verify_ed25519(",
        "decode_did_key(",
        "domain_separated_digest(",
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

    let definition = library_item(&code, "pub struct PackageRecord {");
    assert!(!definition.contains("serde"), "{definition}");
    let start = code
        .find("pub struct PackageRecord {")
        .expect("PackageRecord");
    let attributes: Vec<&str> = code[..start]
        .lines()
        .rev()
        .take_while(|line| line.starts_with("#["))
        .collect();
    for maker in ["Serialize", "Deserialize"] {
        assert!(
            !attributes.iter().any(|attribute| attribute.contains(maker)),
            "PackageRecord derives {maker}: {attributes:?}"
        );
    }
}
