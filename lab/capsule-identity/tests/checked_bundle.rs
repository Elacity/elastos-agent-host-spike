//! A checked bundle is the lab CID together with the bytes it names, made by
//! the one walk and the one manifest check. A caller uses those bytes and
//! never reads the folder again, and the checked name check judges them
//! without reading anything. (The swap test is in `tests/walk.rs`, beside
//! the other swap tests.)
mod common;

use std::os::unix::fs::symlink;

use capsule_identity::{checked_bundle, encode_entries, lab_cid, Refusal};
use common::*;
use elastos_common::CapsuleManifest;

#[test]
fn checked_bundle_returns_the_bytes_its_lab_cid_names() {
    // Every fixture whose files are all committed. One walk gives the name
    // and the bytes, and the name is the lab CID of exactly those bytes.
    for (fixture, pinned) in [
        (&CONTENT_SAMPLE, CONTENT_SAMPLE_LAB_CID),
        (&WEB_APP, WEB_APP_LAB_CID),
        (&AGENT_HOST, AGENT_HOST_LAB_CID),
    ] {
        let bundle = assemble(fixture);
        let value = checked(bundle.path());
        assert_eq!(value.cid().to_string(), pinned, "{}", fixture.name);
        assert_eq!(value.cid(), named(bundle.path()), "{}", fixture.name);
        assert_eq!(
            encode_entries(value.entries()),
            Ok(value.cid()),
            "{}: the lab CID does not name the entries the value holds",
            fixture.name
        );
        let mut paths: Vec<&str> = value
            .entries()
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        paths.sort_unstable();
        let mut files = fixture.files.to_vec();
        files.sort_unstable();
        assert_eq!(paths, files, "{}", fixture.name);
        for entry in value.entries() {
            assert!(
                entry.content == read_fixture(fixture, &entry.path),
                "{}: {} does not hold the committed bytes",
                fixture.name,
                entry.path
            );
        }
    }
}

#[test]
fn checked_bundle_refuses_what_lab_cid_refuses() {
    // Four bundles lab_cid refuses, each for its own reason. checked_bundle
    // runs the same walk and the same manifest check, so it gets exactly
    // lab_cid's refusal, variant and text, and returns no value. Opening the
    // FIFO would block, so every call is bounded.
    let no_manifest = temp_dir();
    let sample = read_fixture(&CONTENT_SAMPLE, "sample.example");
    write_file(no_manifest.path(), "sample.example", &sample);

    // The Runtime's own type gives the reason for the v2 schema.
    let invalid = assemble(&CONTENT_SAMPLE);
    let manifest = String::from_utf8(read_fixture(&CONTENT_SAMPLE, "capsule.json"))
        .expect("UTF-8 manifest")
        .replacen("elastos.capsule/v1", "elastos.capsule/v2", 1);
    write_file(invalid.path(), "capsule.json", manifest.as_bytes());
    let runtime_text = serde_json::from_slice::<CapsuleManifest>(manifest.as_bytes())
        .expect("the Runtime type parses any schema string")
        .validate()
        .expect_err("validate() refuses the v2 schema");

    let linked = assemble(&WEB_APP);
    symlink("app.js", linked.path().join("browser/alias.js")).expect("link a payload");

    let piped = assemble(&WEB_APP);
    make_fifo(&piped.path().join("browser/pipe"));

    for (bundle, reason) in [
        (&no_manifest, Refusal::NoManifest),
        (&invalid, Refusal::ManifestInvalid(runtime_text)),
        (
            &linked,
            Refusal::NotRegularFile {
                path: "browser/alias.js".into(),
                kind: "symbolic link",
            },
        ),
        (
            &piped,
            Refusal::NotRegularFile {
                path: "browser/pipe".into(),
                kind: "FIFO",
            },
        ),
    ] {
        let own =
            bounded("lab_cid", bundle.path(), lab_cid).expect_err("lab_cid refuses this bundle");
        assert_eq!(own, reason, "lab_cid gave another reason");
        let refusal = bounded("checked_bundle", bundle.path(), checked_bundle)
            .expect_err("checked_bundle returns no value for a bundle lab_cid refuses");
        assert_eq!(refusal, own, "checked_bundle changed lab_cid's refusal");
        assert_eq!(refusal.to_string(), own.to_string());
    }
}

#[test]
fn checked_name_check_judges_the_checked_bytes() {
    // The checked form judges the bytes the value holds and reads nothing
    // again; check_name(bundle, ..) reads the folder as it is now. So once
    // one byte of browser/app.js changes on disk, the value still passes its
    // own lab CID, while the changed folder is refused by both name checks
    // alike.
    let bundle = assemble(&WEB_APP);
    let before = checked(bundle.path());
    let mut app = read_fixture(&WEB_APP, "browser/app.js");
    app[0] ^= 0x20;
    write_file(bundle.path(), "browser/app.js", &app);
    let changed = named(bundle.path());
    assert_ne!(
        changed.to_string(),
        WEB_APP_LAB_CID,
        "the change did not reach the folder"
    );

    before
        .check_name(WEB_APP_LAB_CID)
        .unwrap_or_else(|refusal| panic!("the checked form judged the changed folder: {refusal}"));
    assert_name_mismatch(bundle.path(), WEB_APP_LAB_CID, changed);
    let fresh = checked(bundle.path());
    assert_eq!(fresh.cid(), changed);
    assert_mismatch(fresh.check_name(WEB_APP_LAB_CID), WEB_APP_LAB_CID, changed);

    // The same claim check as check_name, on the one list of text that is
    // not a lab CID.
    for claim in not_lab_cids() {
        let refusal = before
            .check_name(&claim)
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
}

#[test]
fn checked_name_check_refuses_a_mismatch() {
    // Only the checked form, so the compare this test sees is the one the
    // checked form makes: its own lab CID passes, and a lab CID its bytes do
    // not give is refused with both values.
    let bundle = assemble(&WEB_APP);
    let value = checked(bundle.path());
    value
        .check_name(WEB_APP_LAB_CID)
        .unwrap_or_else(|refusal| panic!("the bundle's own lab CID was refused: {refusal}"));
    assert_mismatch(
        value.check_name(CONTENT_SAMPLE_LAB_CID),
        CONTENT_SAMPLE_LAB_CID,
        value.cid(),
    );
}

#[test]
fn checked_name_check_shares_the_claim_check_and_the_compare() {
    // P10: the checked form is check_name on the lab CID the value holds. It
    // calls the one claim check and the one compare, makes no refusal of its
    // own, and reads or names nothing.
    let code = library_code();
    let body = library_item(&code, "pub fn check_name(&self");
    for shared in [
        "lab_cid_digits(claimed)?",
        "compare_name(self.cid, claimed_digits, claimed)",
    ] {
        assert_eq!(
            body.matches(shared).count(),
            1,
            "the checked form does not call {shared}:\n{body}"
        );
    }
    for own in [
        "strip_prefix",
        "Refusal::",
        "hex::",
        "lab_cid(",
        "checked_bundle",
        "collect_entries(",
        "check_manifest(",
        "encode_entries(",
    ] {
        assert!(
            !body.contains(own),
            "the checked form does its own work ({own}):\n{body}"
        );
    }
}

#[test]
fn checked_bundle_checks_the_manifest_once() {
    // P10: one manifest check. The Runtime's two checks run in one function,
    // check_manifest, which the seam calls once, on the root capsule.json the
    // walk read. lab_cid and both name checks get that check only through the
    // seam, and nothing else parses or validates a manifest.
    let code = library_code();
    assert_eq!(
        code.matches("check_manifest(").count(),
        2,
        "check_manifest is not defined once and called once"
    );
    let seam = library_item(&code, "pub fn checked_bundle_observed(");
    assert_eq!(
        seam.matches("check_manifest(").count(),
        1,
        "the seam does not check the manifest:\n{seam}"
    );
    for runtime_check in ["serde_json::from_slice", ".validate()"] {
        assert_eq!(
            code.matches(runtime_check).count(),
            1,
            "{runtime_check} is not in one place"
        );
    }
}

#[test]
fn checked_bundle_fields_are_private() {
    // A CheckedBundle exists only as the walk made it, so its lab CID always
    // names its entries. Its fields are private, so no caller sets or
    // changes one. In the library the seam is the one place that builds one:
    // no constructor, From, Default or Deserialize makes one with another lab
    // CID or other entries, and nothing hands out a &mut to it or its parts.
    let code = library_code();
    assert!(
        code.contains("#![forbid(unsafe_code)]"),
        "the crate does not forbid unsafe code"
    );

    let definition = library_item(&code, "pub struct CheckedBundle {");
    let fields: Vec<&str> = definition
        .lines()
        .skip(1)
        .filter(|line| line.trim() != "}")
        .collect();
    assert!(!fields.is_empty(), "{definition}");
    for field in fields {
        assert!(
            !field.trim_start().starts_with("pub"),
            "CheckedBundle has a public field: {}",
            field.trim()
        );
    }
    let start = code
        .find("pub struct CheckedBundle {")
        .expect("the definition");
    let attributes: Vec<&str> = code[..start]
        .lines()
        .rev()
        .take_while(|line| line.starts_with("#["))
        .collect();
    for maker in ["Default", "Deserialize"] {
        assert!(
            !attributes.iter().any(|attribute| attribute.contains(maker)),
            "CheckedBundle derives {maker}: {attributes:?}"
        );
    }

    // Every `CheckedBundle {` but the definition and impl heads is a build.
    let builds = code
        .match_indices("CheckedBundle {")
        .filter(|(at, _)| {
            !["struct ", "impl ", "for "]
                .iter()
                .any(|word| code[..*at].ends_with(word))
        })
        .count();
    let seam = library_item(&code, "pub fn checked_bundle_observed(");
    assert_eq!(
        (builds, seam.matches("CheckedBundle {").count()),
        (1, 1),
        "the seam is not the one place that builds a CheckedBundle"
    );

    let impls: Vec<&str> = code
        .split("\nimpl")
        .skip(1)
        .filter(|block| {
            block
                .lines()
                .next()
                .is_some_and(|head| head.contains("CheckedBundle"))
        })
        .map(|block| &block[..block.find("\n}").map_or(block.len(), |end| end + 2)])
        .collect();
    assert!(!impls.is_empty(), "the library has no impl CheckedBundle");
    for block in impls {
        for word in ["Self {", "&mut", "mut self"] {
            assert!(
                !block.contains(word),
                "an impl block of CheckedBundle holds {word:?}:\nimpl{block}"
            );
        }
    }
    assert!(
        !code.contains("&mut CheckedBundle"),
        "the library takes a CheckedBundle by &mut"
    );
}
