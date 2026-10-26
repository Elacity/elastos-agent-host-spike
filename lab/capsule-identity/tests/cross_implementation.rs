//! README's Python rule is the committed outside check of the encoder:
//! `python3 -I` runs the ```python block of "The encoding" on each pinned
//! bundle, and the block, the pin and `encode_entries` must give one value.
//! wc001-core has no pin (its `capsule.wasm` is built on each machine), so it
//! is not checked here.
//!
//! README's two digest blocks are run the same way: the name signature's
//! `name_digest` on each pinned fixture's printed CID, and the package
//! record's `record_payload` and `record_digest` on records a fresh test key
//! signs. Each must give the bytes and the digest the Rust code signs.
mod common;

use capsule_identity::{
    domain_separated_digest, encode_entries, name_signature_message, sign_package_record,
    BundleEntry, PackageRecord, PACKAGE_RECORD_DOMAIN,
};
use common::*;
use ed25519_dalek::{Signature, Verifier};

/// How many pinned bundles the check covers: seven fixtures, the recipe and
/// the three bundles built for the profile tests.
const PINNED_BUNDLES: usize = 11;

/// How many committed fixtures have a pin: all but wc001-core.
const PINNED_FIXTURES: usize = 7;

/// How many package records the record check signs: content-sample's and
/// web-app's.
const SIGNED_RECORDS: usize = 2;

/// A bundle with a pinned lab CID: what it is, its pin and its entries.
struct Pinned {
    what: String,
    pin: &'static str,
    entries: Vec<BundleEntry>,
}

fn entry(path: &str, content: &[u8]) -> BundleEntry {
    BundleEntry {
        path: path.to_owned(),
        content: content.to_vec(),
    }
}

/// The entries of a committed fixture: exactly its listed files.
fn fixture_entries(fixture: &Fixture) -> Vec<BundleEntry> {
    fixture
        .files
        .iter()
        .map(|file| entry(file, &read_fixture(fixture, file)))
        .collect()
}

/// content-sample's entries with `change` made to them.
fn content_sample_with(change: impl FnOnce(&mut Vec<BundleEntry>)) -> Vec<BundleEntry> {
    let mut entries = fixture_entries(&CONTENT_SAMPLE);
    change(&mut entries);
    entries
}

/// Every committed fixture with a pin, each with its pin.
fn pinned_fixtures() -> [(&'static Fixture, &'static str); PINNED_FIXTURES] {
    let fixtures = [
        (&CONTENT_SAMPLE, CONTENT_SAMPLE_LAB_CID),
        (&WEB_APP, WEB_APP_LAB_CID),
        (&AGENT_HOST, AGENT_HOST_LAB_CID),
        (&PROVIDER, PROVIDER_LAB_CID),
        (&MODEL, MODEL_LAB_CID),
        (&PROVIDER_VARIANT_A, PROVIDER_VARIANT_A_LAB_CID),
        (&PROVIDER_VARIANT_B, PROVIDER_VARIANT_B_LAB_CID),
    ];
    // Every committed fixture but wc001-core is here, so a new fixture with
    // a pin cannot be left out.
    let listed: Vec<&str> = fixtures.iter().map(|(fixture, _)| fixture.name).collect();
    let committed: Vec<&str> = FIXTURES
        .iter()
        .map(|fixture| fixture.name)
        .filter(|name| *name != WC001_CORE.name)
        .collect();
    assert_eq!(listed, committed, "a pinned fixture is not checked");
    fixtures
}

/// Every pinned bundle, each with its pin.
fn pinned_bundles() -> Vec<Pinned> {
    let fixtures = pinned_fixtures();
    let mut bundles: Vec<Pinned> = fixtures
        .iter()
        .map(|(fixture, pin)| Pinned {
            what: format!("fixture {}", fixture.name),
            pin,
            entries: fixture_entries(fixture),
        })
        .collect();
    bundles.push(Pinned {
        what: "recipe provider-variant.recipe".to_owned(),
        pin: PROVIDER_VARIANT_RECIPE_LAB_CID,
        entries: vec![entry("provider-variant.recipe", &variant_recipe())],
    });
    bundles.push(Pinned {
        what: "chunk-limit bundle".to_owned(),
        pin: CHUNK_LIMIT_LAB_CID,
        entries: content_sample_with(|entries| {
            let sample = entries
                .iter_mut()
                .find(|entry| entry.path == "sample.example")
                .expect("content-sample holds sample.example");
            sample.content = vec![0; 262_144];
        }),
    });
    bundles.push(Pinned {
        what: "empty-file bundle".to_owned(),
        pin: EMPTY_FILE_LAB_CID,
        entries: content_sample_with(|entries| entries.push(entry("empty", b""))),
    });
    bundles.push(Pinned {
        what: "long UTF-8 name bundle".to_owned(),
        pin: LONG_UTF8_NAME_LAB_CID,
        entries: content_sample_with(|entries| {
            entries.push(entry(&long_utf8_name(), b"long name\n"))
        }),
    });
    bundles
}

#[test]
fn readme_python_recomputes_every_lab_cid_pin() {
    // The run never skips: each bad answer is refused with its own reason.
    let refused = |program: &str| run_python(program, b"").expect_err("this run must be refused");
    let late_exit = refused(&format!(
        "import sys\nprint({CONTENT_SAMPLE_LAB_CID:?})\nsys.exit(1)\n"
    ));
    assert!(
        late_exit.starts_with(&format!("{PYTHON} -I exited with exit status: 1")),
        "{late_exit}"
    );
    let silent = refused("pass\n");
    assert!(
        silent.starts_with(&format!("{PYTHON} -I printed nothing")),
        "{silent}"
    );
    let two_lines = refused(&format!(
        "print({CONTENT_SAMPLE_LAB_CID:?})\nprint({CONTENT_SAMPLE_LAB_CID:?})\n"
    ));
    assert!(
        two_lines.starts_with(&format!("{PYTHON} -I printed 2 lines, not one")),
        "{two_lines}"
    );
    let missing = "python3-is-not-this-program";
    let not_started = run_python_with(missing, "pass\n", b"").expect_err("no such interpreter");
    assert!(
        not_started.starts_with(&format!("{missing} -I could not run: ")),
        "{not_started}"
    );

    // The README block is the one Python copy of the rule: the driver only
    // calls its `lab_cid`. It holds none of the rule: no hash, no varint, no
    // base32, no function of its own.
    for rule in [
        "hashlib",
        "sha256",
        "varint",
        "base64",
        "B32",
        "abcdefghijklmnopqrstuvwxyz234567",
        "def ",
        "lambda",
    ] {
        assert!(
            !README_PYTHON_DRIVER.contains(rule),
            "the driver holds {rule:?}: {README_PYTHON_DRIVER}"
        );
    }
    assert_eq!(README_PYTHON_DRIVER.matches("lab_cid(").count(), 1);

    // Python, the pin and the Rust encoder agree on every pinned bundle.
    let bundles = pinned_bundles();
    let entries: Vec<&[BundleEntry]> = bundles.iter().map(|b| b.entries.as_slice()).collect();
    let python = readme_python_lab_cids(&entries).unwrap_or_else(|reason| panic!("{reason}"));
    let mut checked = 0;
    for (bundle, python) in bundles.iter().zip(&python) {
        let rust = encode_entries(&bundle.entries)
            .unwrap_or_else(|refusal| panic!("{}: {refusal}", bundle.what))
            .to_string();
        assert_eq!(
            (python.as_str(), rust.as_str()),
            (bundle.pin, bundle.pin),
            "{}: (README's Python, encode_entries) against its pin",
            bundle.what
        );
        checked += 1;
    }
    assert_eq!(checked, PINNED_BUNDLES, "checked {checked} bundles");
    assert_eq!(python.len(), bundles.len());
}

/// A README section without exactly one closed block is no pass: no
/// section, a section with no ```python block, a section with two, and a
/// block that is never closed before the next section are each refused with
/// their own reason, which names the section.
fn assert_bad_block_refused(heading: &str) {
    let title = heading.trim_end();
    let no_section = python_block_under("", heading).expect_err("no section");
    assert_eq!(no_section, format!("README.md has no {title:?} section"));
    let no_block = python_block_under(&format!("{heading}No block.\n"), heading)
        .expect_err("a section with no block");
    assert_eq!(
        no_block,
        format!("README.md's {title:?} holds no ```python block")
    );
    let block = "```python\nx = 1\n```\n";
    let two_blocks = python_block_under(&format!("{heading}{block}\n{block}"), heading)
        .expect_err("a section with two blocks");
    assert_eq!(
        two_blocks,
        format!("README.md's {title:?} holds 2 ```python blocks, not one")
    );
    // The fence after the next heading is not this block's end.
    let unclosed = format!("{heading}```python\nx = 1\n\n## Next\n```\n");
    let never_closed = python_block_under(&unclosed, heading).expect_err("an unclosed block");
    assert_eq!(
        never_closed,
        format!("README.md's ```python block in {title:?} is never closed")
    );
}

/// A block that defines no `function` is refused with Python's own reason,
/// so the driver never answers for a block that is not there.
fn assert_undefined(refusal: &str, function: &str) {
    assert!(
        refusal.starts_with(&format!("{PYTHON} -I exited with exit status: 1"))
            && refusal.contains(&format!("NameError: name '{function}' is not defined")),
        "{refusal}"
    );
}

#[test]
fn readme_python_matches_the_name_signature_digest() {
    // The run never skips: each missing part is refused with its own reason.
    assert_bad_block_refused(NAME_SIGNATURE_HEADING);
    let undefined = python_name_digests("", &[CONTENT_SAMPLE_LAB_CID]).expect_err("no name_digest");
    assert_undefined(&undefined, "name_digest");

    // The driver holds none of the digest: no hash, no domain, no separator,
    // no function of its own. It calls the block's `name_digest` once.
    for rule in [
        "hashlib",
        "sha256",
        "name-signature",
        "\\x00",
        "def ",
        "lambda",
    ] {
        assert!(
            !NAME_DIGEST_DRIVER.contains(rule),
            "the driver holds {rule:?}: {NAME_DIGEST_DRIVER}"
        );
    }
    assert_eq!(NAME_DIGEST_DRIVER.matches("name_digest(").count(), 1);

    // Python, the Rust message and, for content-sample, the pinned digest
    // agree on every pinned fixture's printed CID.
    let fixtures = pinned_fixtures();
    let names: Vec<&str> = fixtures.iter().map(|(_, pin)| *pin).collect();
    let python = readme_python_name_digests(&names).unwrap_or_else(|reason| panic!("{reason}"));
    let mut checked = 0;
    for ((fixture, pin), python) in fixtures.iter().zip(&python) {
        let rust = hex::encode(name_signature_message(pin));
        assert_eq!(
            python, &rust,
            "{}: README's name_digest against name_signature_message of {pin}",
            fixture.name
        );
        if fixture.name == CONTENT_SAMPLE.name {
            assert_eq!(rust, CONTENT_SAMPLE_NAME_DIGEST, "content-sample's pin");
        }
        checked += 1;
    }
    assert_eq!(checked, PINNED_FIXTURES, "checked {checked} names");
    assert_eq!(python.len(), names.len());
}

#[test]
fn readme_python_matches_the_package_record_bytes() {
    // The run never skips: each missing part is refused with its own reason.
    assert_bad_block_refused(PACKAGE_RECORD_HEADING);
    let undefined = python_records("", &[(CONTENT_SAMPLE_LAB_CID, "did:key:z")])
        .expect_err("no record_payload");
    assert_undefined(&undefined, "record_payload");
    let one_word = python_records(
        "def record_payload(cid, did):\n    return cid\n\n\ndef record_digest(cid, did):\n    return ''\n",
        &[(CONTENT_SAMPLE_LAB_CID, "did:key:z")],
    )
    .expect_err("one word");
    assert_eq!(
        one_word,
        format!("{PYTHON} -I printed \"{CONTENT_SAMPLE_LAB_CID} \", not a payload and a digest")
    );

    // The driver holds none of the encoding: no hash, no domain, no schema,
    // no JSON layout, no function of its own. It calls each block function
    // once.
    for rule in [
        "hashlib",
        "sha256",
        "package-record",
        "record/v1",
        "schema",
        "signer_did",
        "\\x00",
        "%",
        "def ",
        "lambda",
    ] {
        assert!(
            !RECORD_DRIVER.contains(rule),
            "the driver holds {rule:?}: {RECORD_DRIVER}"
        );
    }
    assert_eq!(RECORD_DRIVER.matches("record_payload(").count(), 1);
    assert_eq!(RECORD_DRIVER.matches("record_digest(").count(), 1);

    // A fresh test key signs a record for each bundle. Only the record's CID
    // and DID go to Python; no key byte leaves Rust.
    let signed: Vec<(PackageRecord, ed25519_dalek::VerifyingKey)> = [
        (&CONTENT_SAMPLE, CONTENT_SAMPLE_LAB_CID),
        (&WEB_APP, WEB_APP_LAB_CID),
    ]
    .iter()
    .map(|(fixture, pin)| {
        let bundle = assemble(fixture);
        let key = fresh_signing_key();
        let record = sign_package_record(&key, bundle.path())
            .unwrap_or_else(|refusal| panic!("{}: {refusal}", fixture.name));
        assert_eq!(record.cid, *pin, "{}", fixture.name);
        (record, key.verifying_key())
    })
    .collect();
    let inputs: Vec<(&str, &str)> = signed
        .iter()
        .map(|(record, _)| (record.cid.as_str(), record.signer_did.as_str()))
        .collect();
    let python = readme_python_records(&inputs).unwrap_or_else(|reason| panic!("{reason}"));

    let mut checked = 0;
    for ((record, verifying), (payload, digest)) in signed.iter().zip(&python) {
        let rust_payload = record.package_record_payload();
        let python_payload = hex::decode(payload)
            .unwrap_or_else(|error| panic!("{}: payload {payload:?}: {error}", record.cid));
        assert_eq!(
            String::from_utf8_lossy(&python_payload),
            String::from_utf8_lossy(&rust_payload),
            "{}: README's record_payload against package_record_payload",
            record.cid
        );
        assert_eq!(
            python_payload, rust_payload,
            "{}: byte for byte",
            record.cid
        );
        let rust_digest = domain_separated_digest(PACKAGE_RECORD_DOMAIN, &rust_payload);
        assert_eq!(
            digest,
            &hex::encode(rust_digest),
            "{}: README's record_digest against domain_separated_digest",
            record.cid
        );
        // The record's signature is over exactly Python's digest.
        let python_digest = hex::decode(digest).expect("the digest is hex");
        verifying
            .verify(&python_digest, &Signature::from_bytes(&record.signature))
            .unwrap_or_else(|error| panic!("{}: {error}", record.cid));
        checked += 1;
    }
    assert_eq!(checked, SIGNED_RECORDS, "checked {checked} records");
    assert_eq!(python.len(), signed.len());
}
