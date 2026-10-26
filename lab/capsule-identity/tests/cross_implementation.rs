//! README's Python rule is the committed outside check of the encoder:
//! `python3 -I` runs the ```python block of "The encoding" on each pinned
//! bundle, and the block, the pin and `encode_entries` must give one value.
//! wc001-core has no pin (its `capsule.wasm` is built on each machine), so it
//! is not checked here.
mod common;

use capsule_identity::{encode_entries, BundleEntry};
use common::*;

/// How many pinned bundles the check covers: seven fixtures, the recipe and
/// the three bundles built for the profile tests.
const PINNED_BUNDLES: usize = 11;

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

/// Every pinned bundle, each with its pin.
fn pinned_bundles() -> Vec<Pinned> {
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
