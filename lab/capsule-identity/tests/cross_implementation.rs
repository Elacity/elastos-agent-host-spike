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
//!
//! Kubo itself checks the pins in two ignored tests, run by hand (README,
//! "Kubo cross-check"): an offline, hash-only import with the Runtime's
//! profile flags must print every pin, and the same flags must print the
//! model package CID the Runtime admitted on this Mac. A third (task 054,
//! `kubo_leaves_out_hidden_names_but_not_every_empty_folder`) checks four
//! web-app copies: Kubo with the same flags prints web-app's pin for a root
//! `.DS_Store`, a `.well-known/a.txt` and an empty folder `e`, and prints
//! `KUBO_WEB_APP_WITH_F_HOLDING_EMPTY_G` (Kubo's value, not a pin) for a
//! folder `f` holding only an empty `g`; `lab_cid` refuses all four, with
//! `HiddenName` or `EmptyFolder`. It passes on this Mac (LOG.md, ci-57).
mod common;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;

use capsule_identity::{
    domain_separated_digest, encode_chunked_files, encode_entries, lab_cid, name_signature_message,
    sign_package_record, BundleEntry, ChunkedFile, PackageRecord, Refusal, PACKAGE_RECORD_DOMAIN,
};
use common::*;
use ed25519_dalek::{Signature, Verifier};
use tempfile::TempDir;

/// How many pinned bundles the check covers: seven fixtures, the recipe,
/// the three bundles built for the profile tests, the photo stand-in
/// consumer copy (task 047), the two bundles with a file over one leaf
/// (task 048), the bundle with a file of two tree levels (task 051), the
/// bundle whose root block is exactly 262144 bytes (task 053), the four
/// HAMT bundles (tasks 056 and 061), the bundle with a file root inside a
/// HAMT shard (task 062), the multibyte-name shard (task 063) and the
/// combining-mark shard (task 064): 23.
const PINNED_BUNDLES: usize = 23;

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
    bundles.push(Pinned {
        what: "consumer copy photo-stand-in-photo-set".to_owned(),
        pin: PHOTO_STAND_IN_LAB_CID,
        entries: photo_stand_in_entries(),
    });
    bundles.push(Pinned {
        what: "two-leaf file bundle".to_owned(),
        pin: TWO_LEAF_FILE_LAB_CID,
        entries: content_sample_with(|entries| {
            let sample = entries
                .iter_mut()
                .find(|entry| entry.path == "sample.example")
                .expect("content-sample holds sample.example");
            sample.content = vec![0; 262_145];
        }),
    });
    bundles.push(Pinned {
        what: "three-leaf nested file bundle".to_owned(),
        pin: THREE_LEAF_NESTED_LAB_CID,
        entries: content_sample_with(|entries| entries.push(entry(BIG_BIN, &big_bin_bytes()))),
    });
    bundles.push(Pinned {
        what: "two-level file bundle".to_owned(),
        pin: TWO_LEVEL_FILE_LAB_CID,
        entries: content_sample_with(|entries| {
            let sample = entries
                .iter_mut()
                .find(|entry| entry.path == "sample.example")
                .expect("content-sample holds sample.example");
            sample.content = two_level_bytes();
        }),
    });
    bundles.push(Pinned {
        what: "directory-at-limit bundle".to_owned(),
        pin: DIRECTORY_AT_LIMIT_LAB_CID,
        entries: content_sample_with(|entries| entries.extend(directory_at_limit_files(0))),
    });
    bundles.push(Pinned {
        what: "directory at the HAMT threshold".to_owned(),
        pin: DIRECTORY_AT_HAMT_THRESHOLD_LAB_CID,
        entries: directory_at_hamt_threshold_bundle(0),
    });
    bundles.push(Pinned {
        what: "directory over the HAMT threshold".to_owned(),
        pin: DIRECTORY_OVER_HAMT_THRESHOLD_LAB_CID,
        entries: directory_at_hamt_threshold_bundle(1),
    });
    bundles.push(Pinned {
        what: "directory with a one-link HAMT shard".to_owned(),
        pin: DIRECTORY_WITH_A_ONE_LINK_HAMT_SHARD_LAB_CID,
        entries: directory_with_a_one_link_hamt_shard_bundle(),
    });
    bundles.push(Pinned {
        what: "child directory over the HAMT threshold".to_owned(),
        pin: CHILD_DIRECTORY_OVER_HAMT_THRESHOLD_LAB_CID,
        entries: child_directory_at_hamt_threshold_bundle(1),
    });
    bundles.push(Pinned {
        what: "file root inside a HAMT shard".to_owned(),
        pin: FILE_ROOT_INSIDE_A_HAMT_LAB_CID,
        entries: file_root_inside_a_hamt_bundle(),
    });
    bundles.push(Pinned {
        what: "multibyte name over the HAMT threshold".to_owned(),
        pin: MULTIBYTE_NAME_OVER_HAMT_THRESHOLD_LAB_CID,
        entries: multibyte_name_over_the_hamt_threshold_bundle(),
    });
    bundles.push(Pinned {
        what: "combining mark over the HAMT threshold".to_owned(),
        pin: COMBINING_MARK_OVER_HAMT_THRESHOLD_LAB_CID,
        entries: combining_mark_over_the_hamt_threshold_bundle(),
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

    // README names the count this test checks, in the Python sentences, the
    // missing-block row and the Kubo cross-check, and the five say one count.
    let counts = readme_pinned_bundle_counts().unwrap_or_else(|reason| panic!("{reason}"));
    for count in counts {
        assert_eq!(
            count, PINNED_BUNDLES,
            "README names a count of pinned bundles that this test does not check"
        );
    }

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

/// Task 055: a caller that kept only its listing's chunk digests names every
/// pinned bundle as `encode_entries` and the pin do, and the file list's
/// order changes no root.
#[test]
fn chunked_listing_reproduces_every_existing_pin() {
    let bundles = pinned_bundles();
    let mut checked = 0;
    for bundle in &bundles {
        // The digests come from the bytes with `chunk_digests`, not from a
        // second CID or protobuf rule.
        let files: Vec<ChunkedFile> = bundle
            .entries
            .iter()
            .map(|entry| chunked_file(&entry.path, &entry.content))
            .collect();
        let from_chunks = encode_chunked_files(&files)
            .unwrap_or_else(|refusal| panic!("{}: {refusal}", bundle.what));
        let from_entries = encode_entries(&bundle.entries)
            .unwrap_or_else(|refusal| panic!("{}: {refusal}", bundle.what));
        assert_eq!(
            from_chunks.to_string(),
            bundle.pin,
            "{}: the chunked listing against its pin",
            bundle.what
        );
        assert_eq!(
            from_chunks, from_entries,
            "{}: the chunked listing against encode_entries",
            bundle.what
        );

        // Entries are given in any order: reversing the file list, whose
        // digests stay in file-byte order, preserves the root.
        let mut reversed = files.clone();
        reversed.reverse();
        let from_reversed = encode_chunked_files(&reversed)
            .unwrap_or_else(|refusal| panic!("{} reversed: {refusal}", bundle.what));
        assert_eq!(
            from_reversed, from_chunks,
            "{}: the reversed file list",
            bundle.what
        );
        checked += 1;
    }
    assert_eq!(checked, PINNED_BUNDLES, "checked {checked} bundles");
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

/// The variable that holds the path of the Kubo the two Kubo tests run.
const LAB_KUBO: &str = "LAB_KUBO";

/// The variable that holds the folder of the model package the Runtime
/// admitted on this Mac.
const LAB_ADMITTED_MODEL_DIR: &str = "LAB_ADMITTED_MODEL_DIR";

/// The one Kubo version the profile is pinned to: `version --number` must
/// print exactly this.
const KUBO_VERSION: &str = "0.40.1";

/// The import flags, written once. They are the release script's
/// `KUBO_ADD_FLAGS` (`scripts/ci-model-package.mjs:211`, run as
/// `add <flags> <dir>` at `:221`) with `--only-hash=true` from the Runtime
/// provider's `ADD_OPTIONS` (`capsules/ipfs-provider/src/directory_hash.rs:19-43`,
/// "Kubo v0.40.1 core/commands/add.go"). `--offline` is the script's own.
/// No flag here is missing from both copies.
const KUBO_ADD_FLAGS: [&str; 22] = [
    "--offline",
    "--only-hash=true",
    "--recursive=true",
    "--quieter=true",
    "--wrap-with-directory=false",
    "--cid-version=1",
    "--hash=sha2-256",
    "--raw-leaves=true",
    "--chunker=size-262144",
    "--trickle=false",
    "--max-file-links=174",
    "--max-directory-links=0",
    "--max-hamt-fanout=256",
    "--inline=false",
    "--nocopy=false",
    "--fscache=false",
    "--preserve-mode=false",
    "--preserve-mtime=false",
    "--empty-dirs=false",
    "--progress=false",
    "--fast-provide-root=false",
    "--fast-provide-wait=false",
];

/// The two HAMT values that have no add flag, as the provider's own Kubo
/// fixture writes them (`directory_hash.rs:1111-1112`) and its
/// `check_hamt_value` accepts them (`:507-524`).
const KUBO_HAMT_CONFIG: [(&str, &str); 2] = [
    ("Import.UnixFSHAMTDirectorySizeThreshold", "256KiB"),
    ("Import.UnixFSHAMTDirectorySizeEstimation", "links"),
];

/// The package CID of the SmolLM2 model package the Runtime admitted on this
/// Mac: Kubo made it at release, the Runtime's provider computed it again
/// before admission. `model-catalog.json` holds it (entry
/// `smollm2-135m-instruct-q8-0-local`, also `SMOL_CID` at
/// `scripts/ci-model-package.test.mjs:189`), and the ElastOS data folder's
/// `model-preparation/state.json` records it as `package_cid`, state
/// `admitted`.
const ADMITTED_MODEL_PACKAGE_CID: &str =
    "bafybeiew3vuq32fvuz2kmps7lmgl4rxpvwsvklxykx4covogbrkhgy5qky";

/// The files of the admitted folder and the size of each, where the task
/// fixed it. `_elastos_object.json` is the release script's object index
/// (`scripts/ci-model-package.mjs:124-127`).
const ADMITTED_MODEL_FILES: [(&str, Option<u64>); 6] = [
    ("LICENSE", Some(11_358)),
    ("LICENSE.base", Some(11_358)),
    ("PROVENANCE.md", Some(358)),
    ("_elastos_object.json", None),
    ("capsule.json", Some(751)),
    ("weights.gguf", Some(144_811_072)),
];

/// The weights file: 553 raw leaves, so a root over four file nodes of 174,
/// 174, 174 and 31 leaves (two tree levels).
const ADMITTED_WEIGHTS: &str = "weights.gguf";

/// How many raw leaves [`ADMITTED_WEIGHTS`] has.
const ADMITTED_WEIGHTS_LEAVES: u64 = 553;

/// The value of the variable `name`, or a panic that names it: a Kubo test
/// never skips.
fn required_var(name: &str, what: &str) -> OsString {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("{name} is not set: it must hold {what}"))
}

/// One Kubo with a fresh, empty repo in a temp folder outside the tree: no
/// daemon, no network, nothing written outside the temp folders. The repo's
/// config holds a node key Kubo makes at `init`; nothing here reads or prints
/// it.
struct HashOnlyKubo {
    binary: OsString,
    repo: TempDir,
}

impl HashOnlyKubo {
    /// The Kubo at `LAB_KUBO`, checked to be [`KUBO_VERSION`], with its repo
    /// made by `init --empty-repo` and [`KUBO_HAMT_CONFIG`] set.
    fn start() -> HashOnlyKubo {
        let kubo = HashOnlyKubo {
            binary: required_var(LAB_KUBO, "the path of a Kubo v0.40.1"),
            repo: temp_dir(),
        };
        let version = kubo.run(&["version", "--number"]);
        assert_eq!(
            version.strip_suffix('\n').unwrap_or(&version),
            KUBO_VERSION,
            "{LAB_KUBO} version --number printed {version:?}, not {KUBO_VERSION:?}"
        );
        // Init's output names the new node; it is not kept.
        kubo.run(&["init", "--empty-repo"]);
        for (key, value) in KUBO_HAMT_CONFIG {
            kubo.run(&["config", key, value]);
        }
        kubo
    }

    /// Kubo's root CID for the folder `folder`: an offline, hash-only import
    /// with [`KUBO_ADD_FLAGS`], which must print one line.
    fn root(&self, folder: &Path) -> String {
        let folder = folder.to_str().expect("a temp or admitted folder is UTF-8");
        let mut args = vec!["add"];
        args.extend(KUBO_ADD_FLAGS);
        args.push(folder);
        let output = self.run(&args);
        match output.lines().collect::<Vec<_>>()[..] {
            [root] => root.to_owned(),
            _ => panic!("kubo add {folder} printed {output:?}, not one root"),
        }
    }

    /// The one place Kubo runs: `args` with `IPFS_PATH` set to the temp repo,
    /// from the temp folder. A Kubo that cannot start or fails is a panic
    /// with its exit status and standard error; its output is returned.
    fn run(&self, args: &[&str]) -> String {
        let repo = self.repo.path().join("repo");
        let output = Command::new(&self.binary)
            .args(args)
            .env("IPFS_PATH", &repo)
            .current_dir(self.repo.path())
            .output()
            .unwrap_or_else(|error| panic!("{LAB_KUBO} {:?} could not run: {error}", args[0]));
        assert!(
            output.status.success(),
            "{LAB_KUBO} {:?} exited with {}: {}",
            args[0],
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("Kubo prints UTF-8")
    }
}

#[test]
#[ignore = "run by hand: needs LAB_KUBO, the path of a Kubo v0.40.1"]
fn kubo_hash_only_import_prints_every_lab_cid_pin() {
    let kubo = HashOnlyKubo::start();
    let bundles = pinned_bundles();
    let mut rows = Vec::new();
    for bundle in &bundles {
        let folder = temp_dir();
        for entry in &bundle.entries {
            write_file(folder.path(), &entry.path, &entry.content);
        }
        let root = kubo.root(folder.path());
        let rust = encode_entries(&bundle.entries)
            .unwrap_or_else(|refusal| panic!("{}: {refusal}", bundle.what))
            .to_string();
        println!(
            "{}: kubo {root}, pin {}, encode_entries {rust}",
            bundle.what, bundle.pin
        );
        rows.push((bundle.what.as_str(), root, bundle.pin, rust));
    }
    let differ: Vec<_> = rows
        .iter()
        .filter(|(_, root, pin, rust)| (root.as_str(), rust.as_str()) != (*pin, *pin))
        .collect();
    assert!(
        differ.is_empty(),
        "(bundle, Kubo, pin, encode_entries) are not one value: {differ:#?}"
    );
    assert_eq!(rows.len(), PINNED_BUNDLES, "checked {} bundles", rows.len());
}

/// Kubo's output, not a lab pin: the root Kubo v0.40.1 printed with
/// [`KUBO_ADD_FLAGS`] for web-app plus a folder `f` that holds only an empty
/// folder `g` (task 052's hand run). `--empty-dirs=false` keeps `f/g`, so
/// this is not web-app's pin. The lab never prints it: it refuses `f/g`.
const KUBO_WEB_APP_WITH_F_HOLDING_EMPTY_G: &str =
    "bafybeiglww2fwp3lu757nlc6gpjufsoseelyrsj46rkvr7oouurrz4imsy";

#[test]
#[ignore = "run by hand: needs LAB_KUBO, the path of a Kubo v0.40.1"]
fn kubo_leaves_out_hidden_names_but_not_every_empty_folder() {
    // web-app with (a) a root `.DS_Store`, (b) a hidden folder holding a
    // file, (c1) an empty folder `e`, (c2) a folder `f` holding only an
    // empty folder `g`. Kubo with the Runtime's flags (no `--hidden`,
    // `--empty-dirs=false`) prints web-app's pin for (a), (b) and (c1), but
    // keeps (c2)'s folders. The lab refuses all four: it never leaves bytes
    // out of a name, and it names no folder that holds no file.
    let kubo = HashOnlyKubo::start();
    let cases: [(&str, &dyn Fn(&Path), &str, Refusal); 4] = [
        (
            "(a) root .DS_Store",
            &|root| write_file(root, ".DS_Store", b"Bud1"),
            WEB_APP_LAB_CID,
            Refusal::HiddenName {
                path: ".DS_Store".into(),
            },
        ),
        (
            "(b) .well-known/a.txt",
            &|root| write_file(root, ".well-known/a.txt", b"a\n"),
            WEB_APP_LAB_CID,
            Refusal::HiddenName {
                path: ".well-known/a.txt".into(),
            },
        ),
        (
            "(c1) empty folder e",
            &|root| fs::create_dir(root.join("e")).expect("make e"),
            WEB_APP_LAB_CID,
            Refusal::EmptyFolder { path: "e".into() },
        ),
        (
            "(c2) f holding only an empty g",
            &|root| fs::create_dir_all(root.join("f/g")).expect("make f/g"),
            KUBO_WEB_APP_WITH_F_HOLDING_EMPTY_G,
            Refusal::EmptyFolder { path: "f/g".into() },
        ),
    ];
    let mut differ = Vec::new();
    for (what, add, expected_root, refusal) in cases {
        let bundle = assemble(&WEB_APP);
        add(bundle.path());
        let root = kubo.root(bundle.path());
        let walked = lab_cid(bundle.path()).map(|cid| cid.to_string());
        println!("{what}: kubo {root}, expected {expected_root}, lab_cid {walked:?}");
        let refused = Err(refusal);
        if root != expected_root || walked != refused {
            differ.push((what, root, expected_root, walked));
        }
    }
    assert!(
        differ.is_empty(),
        "(case, Kubo, expected, lab_cid) do not agree: {differ:#?}"
    );
}

#[test]
#[ignore = "run by hand: needs LAB_KUBO and LAB_ADMITTED_MODEL_DIR"]
fn kubo_profile_reproduces_the_admitted_model_package_cid() {
    let admitted = required_var(
        LAB_ADMITTED_MODEL_DIR,
        "the folder of the model package the Runtime admitted",
    );
    let admitted = Path::new(&admitted);
    let mut found: Vec<(String, u64)> = fs::read_dir(admitted)
        .unwrap_or_else(|error| panic!("read {}: {error}", admitted.display()))
        .map(|item| {
            let item = item.expect("a folder entry");
            let meta = item.metadata().expect("its metadata");
            let name = item.file_name().into_string().expect("a UTF-8 name");
            assert!(meta.is_file(), "{name} is not a regular file");
            (name, meta.len())
        })
        .collect();
    found.sort();
    let names: Vec<&str> = found.iter().map(|(name, _)| name.as_str()).collect();
    let expected: Vec<&str> = ADMITTED_MODEL_FILES.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, expected, "the admitted folder's files");
    for ((name, size), (_, expected)) in found.iter().zip(ADMITTED_MODEL_FILES) {
        if let Some(expected) = expected {
            assert_eq!(*size, expected, "{name}'s size");
        }
    }

    let kubo = HashOnlyKubo::start();
    let root = kubo.root(admitted);
    println!("admitted model package: kubo {root}, pin {ADMITTED_MODEL_PACKAGE_CID}");
    assert_eq!(
        root, ADMITTED_MODEL_PACKAGE_CID,
        "Kubo with these flags did not print the package CID the Runtime admitted"
    );

    // Task 051: the lab encoder, given the six files' bytes, gives the CID
    // Kubo and the Runtime made, so it names a file of two tree levels as
    // they do.
    let weights = found
        .iter()
        .find(|(name, _)| name == ADMITTED_WEIGHTS)
        .map(|(_, size)| *size)
        .expect("the admitted folder holds the weights");
    assert_eq!(
        weights.div_ceil(262_144),
        ADMITTED_WEIGHTS_LEAVES,
        "{ADMITTED_WEIGHTS}'s leaves"
    );
    let entries: Vec<BundleEntry> = names
        .iter()
        .map(|name| {
            let path = admitted.join(name);
            let content =
                fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            entry(name, &content)
        })
        .collect();
    let encoded = encode_entries(&entries)
        .unwrap_or_else(|refusal| panic!("encode_entries refused the admitted files: {refusal}"))
        .to_string();
    println!("admitted model package: encode_entries {encoded}");
    assert_eq!(
        encoded, ADMITTED_MODEL_PACKAGE_CID,
        "encode_entries over the admitted files did not give the package CID the Runtime admitted"
    );

    // lab_cid is the walk, the Runtime's manifest check and the same
    // encoder; it only reads the folder.
    let walked = lab_cid(admitted);
    println!("admitted model package: lab_cid {walked:?}");
    assert_eq!(
        walked.map(|cid| cid.to_string()),
        Ok(ADMITTED_MODEL_PACKAGE_CID.to_owned()),
        "lab_cid on the admitted folder"
    );
}
