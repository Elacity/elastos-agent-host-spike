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
    // the bundle's own digits.
    let digits = WEB_APP_LAB_CID
        .strip_prefix("lab-cid:sha256:")
        .expect("the pin has the label");
    let not_lab_cids = [
        // No label, the right digits.
        digits.to_owned(),
        // Another label, or the label in capitals.
        format!("sha256:{digits}"),
        format!("LAB-CID:SHA256:{digits}"),
        // Uppercase hex.
        format!("lab-cid:sha256:{}", digits.to_uppercase()),
        // A character that is not hex, in place of the last digit.
        format!("lab-cid:sha256:{}g", &digits[..63]),
        // A character that is not ASCII: 64 bytes, but not 64 hex digits.
        format!("lab-cid:sha256:{}é", &digits[..62]),
        // 63 and 65 characters, a trailing newline, and none.
        format!("lab-cid:sha256:{}", &digits[..63]),
        format!("lab-cid:sha256:{digits}0"),
        format!("{WEB_APP_LAB_CID}\n"),
        "lab-cid:sha256:".to_owned(),
        String::new(),
    ];
    for claim in not_lab_cids {
        let refusal = check_name(bundle.path(), &claim)
            .expect_err("a claim that is not a lab CID must be refused");
        assert_eq!(
            refusal,
            Refusal::NotALabCid {
                claimed: claim.clone()
            },
            "{claim:?}"
        );
        assert_eq!(
            refusal.to_string(),
            format!(
                "the claim {claim:?} is not a lab CID: a lab CID is lab-cid:sha256: and 64 lowercase hex characters"
            )
        );
    }

    // The claim is checked before any bundle is read: where no bundle
    // exists, a claim that is not a lab CID is still refused as one.
    let nowhere = bundle.path().join("no-bundle-here");
    assert_eq!(
        check_name(&nowhere, digits),
        Err(Refusal::NotALabCid {
            claimed: digits.to_owned()
        }),
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
    // places: once in the encoder (the one naming hash) and once in
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
    assert_eq!(code.matches("encode_entries(").count(), 2, "encode_entries");
    assert_eq!(code.matches("Sha256::new()").count(), 2, "Sha256::new()");
    assert_eq!(
        library_item(&code, "pub fn encode_entries(")
            .matches("Sha256::new()")
            .count(),
        1,
        "encode_entries is not the one naming hash"
    );
    assert_eq!(
        library_item(&code, "pub fn domain_separated_digest(")
            .matches("Sha256::new()")
            .count(),
        1,
        "domain_separated_digest is not the one message hash"
    );
}
