//! A bundle whose manifest pins a requirement by CID can be named, and the
//! three ways the Runtime's reader refuses a manifest stay three refusals.
//! Naming looks for nothing: a pin is checked for its form, and the capsule
//! it names is nobody's business here.
mod common;

use capsule_identity::{checked_bundle, encode_entries, lab_cid, BundleEntry, Refusal};
use common::*;
use elastos_common::{
    CapsuleManifest, PinnedManifest, PinnedManifestError, PIN_FORM_INVALID, REQUIREMENT_DUPLICATE,
};

/// web-app's manifest with one more key, `requires`, as given.
fn manifest_requiring(requires: &str) -> String {
    let manifest = String::from_utf8(read_fixture(&WEB_APP, "capsule.json")).expect("UTF-8");
    let with = manifest.replacen('{', &format!("{{\n  \"requires\": {requires},"), 1);
    assert_ne!(with, manifest, "the fixture opens with a brace");
    with
}

/// One requirement on a capsule, pinned to `cid`.
fn pin(name: &str, cid: &str) -> String {
    format!(r#"{{"name": "{name}", "kind": "capsule", "cid": "{cid}"}}"#)
}

/// A web-app bundle whose `capsule.json` is `manifest`.
fn bundle_with(manifest: &str) -> tempfile::TempDir {
    let bundle = assemble(&WEB_APP);
    write_file(bundle.path(), "capsule.json", manifest.as_bytes());
    bundle
}

/// What the Runtime's own reader says about the same bytes, as this crate's
/// refusal: the expected value of every refusal test below.
fn runtime_refusal(manifest: &str) -> Refusal {
    match PinnedManifest::parse(manifest.as_bytes()).expect_err("the Runtime's reader refuses") {
        PinnedManifestError::Unparsed(text) => Refusal::ManifestUnparsed(text),
        PinnedManifestError::Invalid(text) => Refusal::ManifestInvalid(text),
        PinnedManifestError::Pin { code, requirement } => Refusal::PinRefused { code, requirement },
    }
}

#[test]
fn a_bundle_whose_manifest_pins_a_requirement_is_named() {
    let manifest = manifest_requiring(&format!(
        "[{}]",
        pin("example-content", CONTENT_SAMPLE_LAB_CID)
    ));
    // The ordinary manifest type refuses these bytes: it has no `cid` key.
    // Until this slice that refusal was the bundle's.
    let ordinary = serde_json::from_slice::<CapsuleManifest>(manifest.as_bytes())
        .expect_err("the ordinary type refuses a pin")
        .to_string();
    assert!(ordinary.contains("unknown field `cid`"), "{ordinary}");

    let bundle = bundle_with(&manifest);
    let checked = checked_bundle(bundle.path()).expect("a pinned bundle is named");
    // Its name is the encoder's name of the files on disk, read here with
    // `std::fs`, not by the walk.
    let entries: Vec<BundleEntry> = WEB_APP
        .files
        .iter()
        .map(|file| BundleEntry {
            path: (*file).to_owned(),
            content: std::fs::read(bundle.path().join(file)).expect("read a bundle file"),
        })
        .collect();
    let encoded = encode_entries(&entries).expect("the encoder names the files");
    assert_eq!(checked.cid().to_string(), encoded.to_string());
    assert_eq!(
        lab_cid(bundle.path()).expect("named").to_string(),
        encoded.to_string()
    );
    // The name, the role and the type come from that same parse.
    assert_eq!(
        (
            checked.manifest_name(),
            checked.manifest_role(),
            checked.wasm()
        ),
        ("example-web-app", "app", false)
    );
    // The pin is among the bytes that are named: with no pin, or another
    // pin, the bundle has another name.
    assert_ne!(encoded.to_string(), WEB_APP_LAB_CID);
    let other = bundle_with(&manifest_requiring(&format!(
        "[{}]",
        pin("example-content", AGENT_HOST_LAB_CID)
    )));
    assert_ne!(
        lab_cid(other.path()).expect("named").to_string(),
        encoded.to_string()
    );
}

#[test]
fn a_refused_pinned_manifest_is_its_own_refusal_and_carries_the_runtimes_code() {
    let good = pin("one", CONTENT_SAMPLE_LAB_CID);
    let cases = [
        // Not a package root in its one spelling: a raw leaf's CID.
        (
            format!("[{}]", pin("example-content", SAMPLE_EXAMPLE_LEAF_CID)),
            PIN_FORM_INVALID,
            "example-content",
        ),
        // The capitals of a right root.
        (
            format!(
                "[{}]",
                pin("example-content", &CONTENT_SAMPLE_LAB_CID.to_uppercase())
            ),
            PIN_FORM_INVALID,
            "example-content",
        ),
        // Two requirements pin one CID: the second is the one named.
        (
            format!("[{good}, {}]", pin("two", CONTENT_SAMPLE_LAB_CID)),
            REQUIREMENT_DUPLICATE,
            "two",
        ),
        // A pin on a requirement that is not a capsule.
        (
            format!(
                r#"[{{"name": "kubo", "kind": "external", "cid": "{CONTENT_SAMPLE_LAB_CID}"}}]"#
            ),
            PIN_FORM_INVALID,
            "kubo",
        ),
        // Two requirements share a name, neither of them pinned, in a
        // manifest where a third has a pin. No pin is at fault here, which
        // is why the refusal speaks of the pinned manifest and not of a pin.
        (
            format!(
                r#"[{good}, {{"name": "twin", "kind": "capsule"}}, {{"name": "twin", "kind": "capsule"}}]"#
            ),
            REQUIREMENT_DUPLICATE,
            "twin",
        ),
        // Two requirements with no name at all, beside a pinned one: the
        // reader takes an absent name as the empty name, so they share it.
        (
            format!(r#"[{good}, {{"kind": "capsule"}}, {{"kind": "capsule"}}]"#),
            REQUIREMENT_DUPLICATE,
            "",
        ),
    ];
    for (requires, code, requirement) in cases {
        let manifest = manifest_requiring(&requires);
        let expected = Refusal::PinRefused {
            code,
            requirement: requirement.to_owned(),
        };
        assert_eq!(runtime_refusal(&manifest), expected, "{requires}");
        let refusal =
            lab_cid(bundle_with(&manifest).path()).expect_err("a refused pin gets no name");
        assert_eq!(refusal, expected, "{requires}");
        assert_eq!(
            refusal.to_string(),
            format!(
                "the Runtime refuses the pinned manifest capsule.json ({code}): requirement {requirement:?}"
            )
        );
    }
}

#[test]
fn a_pinned_manifest_that_does_not_parse_or_validate_keeps_those_refusals() {
    let pinned = manifest_requiring(&format!(
        "[{}]",
        pin("example-content", CONTENT_SAMPLE_LAB_CID)
    ));
    // A field the Runtime does not know, beside a pin.
    let unknown = pinned.replacen('{', "{\n  \"lab_cid\": \"x\",", 1);
    // A key written twice, in a manifest with a pin.
    let twice = pinned.replacen(
        "\"version\": \"0.1.0\",",
        "\"version\": \"0.1.0\",\n  \"version\": \"0.1.0\",",
        1,
    );
    // A schema validate() refuses, with a pin of the right form.
    let invalid = pinned.replacen("elastos.capsule/v1", "elastos.capsule/v2", 1);
    for (case, manifest, said) in [
        ("unknown field", &unknown, "unknown field `lab_cid`"),
        ("key twice", &twice, "duplicate key `version`"),
        ("schema v2", &invalid, "elastos.capsule/v2"),
    ] {
        assert_ne!(manifest, &pinned, "{case}: the edit changed nothing");
        let refusal = lab_cid(bundle_with(manifest).path()).expect_err(case);
        assert_eq!(refusal, runtime_refusal(manifest), "{case}");
        let (text, message) = match &refusal {
            Refusal::ManifestUnparsed(text) if case != "schema v2" => (
                text,
                format!("the Runtime's CapsuleManifest refused to parse capsule.json: {text}"),
            ),
            Refusal::ManifestInvalid(text) if case == "schema v2" => (
                text,
                format!("the Runtime's CapsuleManifest::validate() refused capsule.json: {text}"),
            ),
            other => panic!("{case}: the wrong refusal: {other:?}"),
        };
        assert!(text.contains(said), "{case}: {text}");
        assert_eq!(refusal.to_string(), message, "{case}");
    }
}
