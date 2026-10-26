//! Shared test support: fixture bundles assembled in fresh temp dirs, the
//! pinned lab CIDs, a bounded call for bundles that hold a FIFO, observers
//! that change a bundle while it is named, a driver for wc-001's own build,
//! the library's code for tests that read it, the refusal asserts both
//! signature checks share, the one key-material scan, the run of README's
//! Python rule, and the scan for lab crates that use this one, read through
//! `cargo metadata` (all three kept here, a file the falsifier runner
//! restores after a killed run).
//! Each test file includes this with `mod common;` and uses only part of it,
//! so dead-code warnings for the rest are silenced.
#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use capsule_identity::{
    check_name, checked_bundle, checked_bundle_observed, lab_cid, lab_cid_observed, BundleEntry,
    CheckedBundle, LabCid, Moment, Refusal,
};
use tempfile::TempDir;

/// The lab CIDs pinned for the committed fixtures. README.md lists the same
/// values.
pub const CONTENT_SAMPLE_LAB_CID: &str =
    "bafybeieahlroxjdalpmglh227eikmodrjhrlelvzlhylvyt3s65ackiybi";
pub const WEB_APP_LAB_CID: &str = "bafybeibc5wcwbtdmjt7qbwbi2rfqvfcfzumivqsoct2ekdqeec2yodqy7q";
pub const AGENT_HOST_LAB_CID: &str = "bafybeicesxlwcolv5hifwotsyafyyaclaq23gyzwl7esuvhwlownrhatym";
pub const PROVIDER_LAB_CID: &str = "bafybeicmpw5zf373ogbziqix2mj2bagmn5imgj3hy7347nulpmx32kooxe";
pub const MODEL_LAB_CID: &str = "bafybeifh6dj5r5wc2j5kqxz6ukga74y3gi56woglqdzmmcdhqvy7qtljzq";
pub const PROVIDER_VARIANT_A_LAB_CID: &str =
    "bafybeig77gyxfd7lldgueo5qtn2o7sjvwdr6txm3f7fc4dl4pyjsuvgoc4";
pub const PROVIDER_VARIANT_B_LAB_CID: &str =
    "bafybeieh6wqfmuqdn3nv7eu4vyd7j3tpxnt3mefzj2hmreumyazd4uzhr4";
/// The lab CID of `recipes/provider-variant.recipe`: the encoder over one
/// entry, `provider-variant.recipe` with the file's bytes.
pub const PROVIDER_VARIANT_RECIPE_LAB_CID: &str =
    "bafybeicgxv53aweiky6lfkoin7iqf5pc6eggehxv4fjnqmmwrfedyhskxm";

/// The chunk-limit bundle, built in a temp dir and never committed:
/// content-sample's `capsule.json` and `sample.example` as 262144 zero bytes,
/// the largest file one raw leaf holds.
pub const CHUNK_LIMIT_LAB_CID: &str = "bafybeibt53faomuek2j4yihvseuib2h6fosmkzympgilbnay2xevciasb4";
/// content-sample with one more file, `empty`, of zero bytes: a raw leaf
/// whose block is empty.
pub const EMPTY_FILE_LAB_CID: &str = "bafybeic2y3c3met6txd62reatxwqjnodhfejchfmltmd6dnpyhtah7l5we";
/// content-sample's entries and one more, [`long_utf8_name`] holding
/// `long name\n`: its name and its link are longer than 127 bytes, so their
/// protobuf lengths take two varint bytes.
pub const LONG_UTF8_NAME_LAB_CID: &str =
    "bafybeih6g5cy7asndjexb7bazovwryqyj4faxvababcjrbe4jxayhzvgmy";

/// SHA-256 of `domain || 0x00 || content-sample's printed lab CID`. README
/// pins the same digest.
pub const CONTENT_SAMPLE_NAME_DIGEST: &str =
    "e04c241b58d424a79e9c4308dc611216890d528ee098646acef7a836dbf4fbb9";

/// A 154-byte UTF-8 file name: fifty three-byte characters and `.txt`.
pub fn long_utf8_name() -> String {
    format!("{}.txt", "\u{540d}".repeat(50))
}

/// The leaf CID of content-sample's `sample.example`: a raw leaf, CIDv1 with
/// codec `0x55`, so a `bafkrei...` CID and no directory root. The encoder
/// never prints it; the claim checks refuse it.
pub const SAMPLE_EXAMPLE_LEAF_CID: &str =
    "bafkreieigdqewmuwbhvduqyyc5lg2eromsgdbnezmrdxmi62lux26qflgy";

/// The text that names no lab package CID: one list, for the parse and both
/// name checks. Each is refused as not a lab CID, even where it carries
/// web-app's own root.
pub fn not_lab_cids() -> Vec<String> {
    let pin = WEB_APP_LAB_CID;
    assert_eq!((pin.len(), &pin[..7]), (59, "bafybei"), "{pin}");
    let ends_with = |last: char| format!("{}{last}", &pin[..58]);
    // The last character holds 3 bits of the digest and 2 unused low bits,
    // so a pin's last letter has its 2 low bits clear. Setting one gives a
    // second spelling of the same bytes.
    let alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    let last = alphabet.find(&pin[58..]).expect("a base32 letter");
    assert_eq!(last % 4, 0, "{pin} has unused bits set");
    let low_bit_set = alphabet.as_bytes()[last | 1] as char;
    vec![
        // A raw leaf's CID: CIDv1, but codec 0x55, not a directory root.
        SAMPLE_EXAMPLE_LEAF_CID.to_owned(),
        // The uppercase form: the multibase `B`, base32 in capitals.
        pin.to_uppercase(),
        // The root without its multibase `b`.
        pin[1..].to_owned(),
        // 58 and 60 characters.
        pin[..58].to_owned(),
        format!("{pin}a"),
        // The old printed form: the label and 64 lowercase hex.
        format!(
            "lab-cid:sha256:{}",
            "5559e5e3fe8f8e31006c035af0367d87810e214d987d1e8548d1bac03ca82066"
        ),
        // A CIDv0, which is a bare base58 multihash.
        "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn".to_owned(),
        // 59 characters starting bafybei, but the 8th is outside a-h, so its
        // bytes do not start 01 70 12 20.
        format!("{}z{}", &pin[..7], &pin[8..]),
        // The right root with unused low bits set: not canonical.
        ends_with(low_bit_set),
        // A character that is not base32, and one that is not ASCII.
        ends_with('1'),
        ends_with('é'),
        // A trailing newline, and nothing.
        format!("{pin}\n"),
        String::new(),
    ]
}

/// The text of the refusal of `claim`, which is not a lab CID.
pub fn not_a_lab_cid_text(claim: &str) -> String {
    format!(
        "the claim {claim:?} is not a lab CID: a lab package CID is a 59-character CIDv1 bafybei... directory root"
    )
}

/// A committed fixture: its folder under `fixtures/` and the files of its
/// bundle.
pub struct Fixture {
    pub name: &'static str,
    pub files: &'static [&'static str],
}

pub const CONTENT_SAMPLE: Fixture = Fixture {
    name: "content-sample",
    files: &["capsule.json", "sample.example"],
};

/// Listed out of byte order on purpose: the encoder sorts.
pub const WEB_APP: Fixture = Fixture {
    name: "web-app",
    files: &["capsule.json", "browser/index.html", "browser/app.js"],
};

/// The manifest only. Its entrypoint `capsule.wasm` is built by wc-001's
/// `tools/build` in each test and is never committed.
pub const WC001_CORE: Fixture = Fixture {
    name: "wc001-core",
    files: &["capsule.json"],
};

/// The agent-host capsule's manifest and its declared asks, copied byte for
/// byte from `examples/agent-host/`. Its entrypoint module is build output
/// and is never committed, so it is not in the fixture.
pub const AGENT_HOST: Fixture = Fixture {
    name: "agent-host",
    files: &["capsule.json", "asks.json"],
};

/// A provider manifest with the fields of the Runtime's own
/// `test_parse_v1_manifest`, and a one-line stand-in for its entrypoint. The
/// stand-in is not a provider binary and is never launched.
pub const PROVIDER: Fixture = Fixture {
    name: "provider",
    files: &["capsule.json", "ipfs-provider"],
};

/// A model manifest with the fields of the Runtime's own synthetic
/// `model_content_fixture`, and one-line stand-ins for the files it names.
/// `weights.gguf` is not a model and is never loaded.
pub const MODEL: Fixture = Fixture {
    name: "model",
    files: &[
        "capsule.json",
        "weights.gguf",
        "LICENSE",
        "LICENSE.base",
        "PROVENANCE.md",
    ],
};

/// Two platform variants of the provider, each its own bundle: the provider
/// fixture's `capsule.json` byte for byte, and a one-line stand-in
/// `ipfs-provider` whose bytes differ, so the two lab CIDs differ. The
/// platform label is not in the folder name or the manifest: it lives only in
/// the variant binding.
pub const PROVIDER_VARIANT_A: Fixture = Fixture {
    name: "provider-variant-a",
    files: &["capsule.json", "ipfs-provider"],
};

pub const PROVIDER_VARIANT_B: Fixture = Fixture {
    name: "provider-variant-b",
    files: &["capsule.json", "ipfs-provider"],
};

pub const FIXTURES: [&Fixture; 8] = [
    &CONTENT_SAMPLE,
    &WEB_APP,
    &WC001_CORE,
    &AGENT_HOST,
    &PROVIDER,
    &MODEL,
    &PROVIDER_VARIANT_A,
    &PROVIDER_VARIANT_B,
];

/// The committed bytes of the variant recipe, `recipes/provider-variant.recipe`.
/// The library never reads it; tests give it these bytes.
pub fn variant_recipe() -> Vec<u8> {
    let path = lane_dir().join("recipes/provider-variant.recipe");
    fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// This lane's root: the folder holding `Cargo.toml` and `fixtures/`.
pub fn lane_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The committed bytes of one fixture file.
pub fn read_fixture(fixture: &Fixture, file: &str) -> Vec<u8> {
    let path = lane_dir().join("fixtures").join(fixture.name).join(file);
    fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// A fresh temp folder.
pub fn temp_dir() -> TempDir {
    tempfile::tempdir().expect("create a temp dir")
}

/// A fresh temp bundle holding exactly the fixture's committed files, so no
/// stray local file (such as `.DS_Store`) can reach a pinned value.
pub fn assemble(fixture: &Fixture) -> TempDir {
    let bundle = temp_dir();
    assemble_at(fixture, bundle.path());
    bundle
}

/// Write exactly the fixture's committed files into the bundle folder
/// `root`, making it, so a test can choose the folder's name and place.
pub fn assemble_at(fixture: &Fixture, root: &Path) {
    for file in fixture.files {
        write_file(root, file, &read_fixture(fixture, file));
    }
}

/// The lab CID of the bundle at `bundle`. A refusal fails the test with its
/// reason.
pub fn named(bundle: &Path) -> LabCid {
    lab_cid(bundle).unwrap_or_else(|refusal| panic!("{}: {refusal}", bundle.display()))
}

/// The checked bundle at `bundle`. A refusal fails the test with its reason.
pub fn checked(bundle: &Path) -> CheckedBundle {
    checked_bundle(bundle).unwrap_or_else(|refusal| panic!("{}: {refusal}", bundle.display()))
}

/// One fresh Ed25519 test key, drawn from the operating system's generator.
///
/// Every test key comes from here. Nothing writes it, prints it or keeps a
/// seed: the next call draws again, and two calls differ.
pub fn fresh_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// `check_name` refuses `claimed` for the bundle at `bundle`, whose bytes
/// name `actual`, and the refusal names both values.
pub fn assert_name_mismatch(bundle: &Path, claimed: &str, actual: LabCid) {
    assert_mismatch(check_name(bundle, claimed), claimed, actual);
}

/// A name check's answer refuses `claimed` for bytes that name `actual`, and
/// the refusal names both values. Both name checks are judged by this.
pub fn assert_mismatch(answer: Result<(), Refusal>, claimed: &str, actual: LabCid) {
    let refusal = answer.expect_err("a lab CID the bundle's bytes do not give must be refused");
    assert_eq!(
        refusal,
        Refusal::NameMismatch {
            actual,
            claimed: claimed.to_owned()
        }
    );
    assert_eq!(
        refusal.to_string(),
        format!("bundle bytes name {actual}; the claim is {claimed}")
    );
}

/// The refusal is the decoder's: `did` is not a canonical Ed25519 `did:key`,
/// with `elastos_identity::decode_did_key`'s own text.
pub fn assert_malformed(refusal: Refusal, did: &str) {
    let reason = elastos_identity::decode_did_key(did)
        .expect_err("this DID is not canonical")
        .to_string();
    assert_eq!(
        refusal,
        Refusal::MalformedSignerDid {
            did: did.to_owned(),
            reason: reason.clone(),
        }
    );
    assert_eq!(
        refusal.to_string(),
        format!("signer DID {did} is not a canonical Ed25519 did:key: {reason}")
    );
}

/// The refusal is the accepted-list check's, for `did`.
pub fn assert_not_accepted(refusal: Refusal, did: &str) {
    assert_eq!(
        refusal,
        Refusal::SignerNotAccepted {
            did: did.to_owned()
        }
    );
    assert_eq!(
        refusal.to_string(),
        format!("signer {did} is not in the accepted list")
    );
}

/// The refusal is the Ed25519 check's, for `did` over `name`.
pub fn assert_does_not_verify(refusal: Refusal, did: &str, name: &str) {
    assert_eq!(
        refusal,
        Refusal::SignatureDoesNotVerify {
            did: did.to_owned(),
            name: name.to_owned(),
        }
    );
    assert_eq!(
        refusal.to_string(),
        format!("signature by {did} does not verify over {name}")
    );
}

/// A wrapper's answer is the walk's own refusal `own`, unchanged.
pub fn assert_same_refusal(got: Result<(), Refusal>, own: &Refusal) {
    let got = got.expect_err("the wrapper must refuse what the walk refuses");
    assert_eq!(&got, own, "the wrapper changed the walk's refusal");
    assert_eq!(got.to_string(), own.to_string());
}

/// Flip one bit of web-app's `browser/app.js` on disk.
pub fn flip_web_app_js(bundle: &Path) {
    let mut bytes = fs::read(bundle.join("browser/app.js")).expect("read browser/app.js");
    assert!(!bytes.is_empty(), "browser/app.js has a byte to change");
    bytes[0] ^= 1;
    write_file(bundle, "browser/app.js", &bytes);
}

/// Three bundles the walk refuses, each for its own reason: no manifest, a
/// manifest the Runtime's check refuses, and a payload that is a link.
pub fn walk_refused_bundles() -> [TempDir; 3] {
    let no_manifest = temp_dir();
    write_file(
        no_manifest.path(),
        "sample.example",
        &read_fixture(&CONTENT_SAMPLE, "sample.example"),
    );

    let invalid = assemble(&CONTENT_SAMPLE);
    let manifest = String::from_utf8(read_fixture(&CONTENT_SAMPLE, "capsule.json"))
        .expect("UTF-8 manifest")
        .replacen("elastos.capsule/v1", "elastos.capsule/v2", 1);
    write_file(invalid.path(), "capsule.json", manifest.as_bytes());

    let linked = assemble(&WEB_APP);
    std::os::unix::fs::symlink("app.js", linked.path().join("browser/alias.js"))
        .expect("link a payload");

    [no_manifest, invalid, linked]
}

/// The names in the folder `parent`, sorted.
pub fn listing(parent: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(parent)
        .unwrap_or_else(|error| panic!("list {}: {error}", parent.display()))
        .map(|entry| {
            entry
                .expect("read a folder entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// The library's code without its comment lines, so a test that reads the
/// code is never misled by a comment that names a call.
pub fn library_code() -> String {
    include_str!("../../src/lib.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One item of `code` (from [`library_code`]): the text from `head`, which
/// must be found exactly once, to the closing brace at `head`'s own indent.
/// So `pub fn name(` gives a function and `pub fn name(&self` a method.
pub fn library_item<'a>(code: &'a str, head: &str) -> &'a str {
    assert_eq!(code.matches(head).count(), 1, "the library holds {head:?}");
    let start = code.find(head).expect("found once");
    let line_start = code[..start].rfind('\n').map_or(0, |at| at + 1);
    let close = format!("\n{}}}", &code[line_start..start]);
    let end = code[start..]
        .find(&close)
        .unwrap_or_else(|| panic!("{head:?} has no closing brace"));
    &code[start..start + end + close.len()]
}

/// The two ends of a PEM private-key header, built here so this source has
/// no header line of its own.
pub(super) fn pem_private_ends() -> (String, String) {
    (
        format!("-----{} ", "BEGIN"),
        format!("{}-----", "PRIVATE KEY"),
    )
}

pub(super) struct Filed<'a> {
    pub(super) name: &'a str,
    pub(super) bytes: &'a [u8],
}

pub(super) fn key_material_findings(files: &[Filed<'_>]) -> Vec<String> {
    let (header_start, header_end) = pem_private_ends();
    let mut found = Vec::new();
    for file in files {
        if file.name.ends_with(".key") || file.name.ends_with(".seed") {
            found.push(format!("name:{}", file.name));
        }
        if file.bytes.len() == 32 && std::str::from_utf8(file.bytes).is_err() {
            found.push(format!("raw-seed:{}", file.name));
        }
        // Invalid bytes elsewhere in a file must not hide its ASCII header markers.
        let text = String::from_utf8_lossy(file.bytes);
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with(&header_start) && trimmed.ends_with(&header_end) {
                found.push(format!("header:{}:{index}", file.name));
            }
        }
    }
    found
}

/// Write `bytes` at the bundle-relative `path` under `root`, making folders.
pub fn write_file(root: &Path, path: &str, bytes: &[u8]) {
    let target = root.join(path);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).expect("create a folder");
    }
    fs::write(&target, bytes).expect("write a file");
}

/// Make a FIFO at `path` with the system's `mkfifo`.
pub fn make_fifo(path: &Path) {
    let status = Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("spawn mkfifo");
    assert!(status.success(), "mkfifo {} failed", path.display());
}

/// A temp folder outside any bundle that holds web-app's `browser/` file
/// names with other bytes, plus one extra file. A walk that follows a link,
/// or reads or lists by path after its check, meets these bytes or the
/// extra file instead of web-app's.
pub fn outside_browser() -> TempDir {
    let outside = temp_dir();
    write_file(outside.path(), "app.js", b"// outside the bundle\n");
    write_file(
        outside.path(),
        "index.html",
        b"<!-- outside the bundle -->\n",
    );
    write_file(outside.path(), "extra.js", b"// only outside the bundle\n");
    outside
}

/// The observer that only watches: the walk `lab_cid` runs.
pub fn unobserved(_: Moment, _: &str) {}

/// An observer that makes `change` once, when the walk reaches the entry
/// `path` at `moment`, and only watches otherwise.
pub fn at(
    moment: Moment,
    path: &'static str,
    change: impl FnOnce() + Send + 'static,
) -> impl FnMut(Moment, &str) + Send + 'static {
    let mut change = Some(change);
    move |now, seen| {
        if (now, seen) == (moment, path) {
            if let Some(change) = change.take() {
                change();
            }
        }
    }
}

/// How long a bounded call may take. Naming a small bundle takes
/// milliseconds.
pub const BOUND: Duration = Duration::from_secs(10);

/// `call(bundle)` on its own thread, waited for at most [`BOUND`]. Opening a
/// FIFO to read blocks until a writer comes, so a walk that opens one before
/// checking its type, or without the non-blocking flag, fails here instead
/// of hanging the run. `what` names the call when it fails.
pub fn bounded<T: Send + 'static>(
    what: &str,
    bundle: &Path,
    call: impl FnOnce(&Path) -> Result<T, Refusal> + Send + 'static,
) -> Result<T, Refusal> {
    let (sender, receiver) = mpsc::channel();
    let bundle = bundle.to_path_buf();
    thread::spawn(move || {
        let _ = sender.send(call(&bundle));
    });
    match receiver.recv_timeout(BOUND) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => panic!(
            "{what} did not return within {BOUND:?}: it opened an entry it should have refused"
        ),
        Err(RecvTimeoutError::Disconnected) => panic!("{what} panicked"),
    }
}

/// `lab_cid_observed(bundle, observe)`, [`bounded`]. With [`unobserved`] it
/// runs the walk `lab_cid` runs.
pub fn lab_cid_bounded(
    bundle: &Path,
    observe: impl FnMut(Moment, &str) + Send + 'static,
) -> Result<LabCid, Refusal> {
    bounded("lab_cid", bundle, move |bundle| {
        lab_cid_observed(bundle, observe)
    })
}

/// `checked_bundle_observed(bundle, observe)`, [`bounded`]. With
/// [`unobserved`] it runs the walk `checked_bundle` runs.
pub fn checked_bundle_bounded(
    bundle: &Path,
    observe: impl FnMut(Moment, &str) + Send + 'static,
) -> Result<CheckedBundle, Refusal> {
    bounded("checked_bundle", bundle, move |bundle| {
        checked_bundle_observed(bundle, observe)
    })
}

/// Build wc-001 with its own `tools/build` into `out_dir` (a temp dir; the
/// build writes nothing inside `lab/wasm-capsule/`) and return the module it
/// wrote there. A build that cannot run fails the test; it never skips.
pub fn wc001_module(out_dir: &Path) -> Vec<u8> {
    let script = lane_dir()
        .parent()
        .expect("lab/ holds this lane")
        .join("wasm-capsule/tools/build");
    let output = Command::new("bash")
        .arg(&script)
        .arg(out_dir)
        .output()
        .expect("spawn wc-001 tools/build");
    assert!(
        output.status.success(),
        "wc-001 tools/build failed ({}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    fs::read(out_dir.join("capsule.wasm")).expect("read wc-001 capsule.wasm")
}

/// The interpreter that runs README's Python rule, always with `-I`.
pub const PYTHON: &str = "python3";

/// README.md as committed.
const README: &str = include_str!("../../README.md");

/// The heading of README's section that holds the Python rule.
const ENCODING_HEADING: &str = "## The encoding\n";

/// The heading of README's section that holds the name signature's Python
/// digest, `name_digest`.
pub const NAME_SIGNATURE_HEADING: &str = "## Test-key publisher signature (lab proposal)\n";

/// The heading of README's section that holds the package record's Python
/// payload and digest, `record_payload` and `record_digest`.
pub const PACKAGE_RECORD_HEADING: &str = "## Lab package record (outside the bundle)\n";

/// The ```python block of README's "The encoding" section: the one Python
/// copy of the naming rule, as committed.
pub fn readme_python_block() -> Result<String, String> {
    python_block_under(README, ENCODING_HEADING)
}

/// The one ```python block of the section of `readme` under `heading`, as
/// written. A missing section, a section with no block or with more than
/// one, or an unclosed block is refused with its reason, which names the
/// section.
pub fn python_block_under(readme: &str, heading: &str) -> Result<String, String> {
    fenced_block_under(readme, heading, "python")
}

/// The text of the section of `readme` under `heading`, up to the next `## `
/// heading. A missing section is refused with its reason.
pub fn section_under<'a>(readme: &'a str, heading: &str) -> Result<&'a str, String> {
    let title = heading.trim_end();
    let start = readme
        .find(heading)
        .ok_or_else(|| format!("README.md has no {title:?} section"))?
        + heading.len();
    let section = &readme[start..];
    Ok(&section[..section.find("\n## ").unwrap_or(section.len())])
}

/// The one ```` ```lang ```` block of the section of `readme` under `heading`,
/// as written: the one README block reader. Its refusals are
/// [`python_block_under`]'s, with `lang` in place of `python`.
pub fn fenced_block_under(readme: &str, heading: &str, lang: &str) -> Result<String, String> {
    let title = heading.trim_end();
    let section = section_under(readme, heading)?;
    let open = format!("```{lang}\n");
    match section.matches(&open).count() {
        1 => {}
        0 => return Err(format!("README.md's {title:?} holds no ```{lang} block")),
        more => {
            return Err(format!(
                "README.md's {title:?} holds {more} ```{lang} blocks, not one"
            ))
        }
    }
    let body = &section[section.find(&open).expect("found once") + open.len()..];
    let end = body
        .find("\n```\n")
        .ok_or_else(|| format!("README.md's ```{lang} block in {title:?} is never closed"))?;
    let block = &body[..end + 1];
    Ok(block.to_owned())
}

/// The driver run after README's block. It holds no part of the naming
/// rule: it reads `{bundle path: hex}` JSON from stdin, calls the block's
/// `lab_cid` and prints its answer. First it checks how it was started: under
/// `-I`, in an empty folder. If not, it exits non-zero with its reason.
pub const README_PYTHON_DRIVER: &str = r#"
import json, os, sys
if not sys.flags.isolated:
    sys.exit("the driver must run under python3 -I")
if os.listdir("."):
    sys.exit("the driver must run in a fresh, empty folder")
files = json.loads(sys.stdin.buffer.read())
print(lab_cid({path: bytes.fromhex(text) for path, text in files.items()}))
"#;

/// README's Python rule run on each bundle, given as its entries: one
/// [`PYTHON`] `-I` run of the block and the driver per bundle, in order. Each
/// answer is that run's one line. A missing block, or any run that gives no
/// one line, is refused with its reason.
pub fn readme_python_lab_cids(bundles: &[&[BundleEntry]]) -> Result<Vec<String>, String> {
    let block = readme_python_block()?;
    let program = format!("{block}{README_PYTHON_DRIVER}");
    bundles
        .iter()
        .map(|entries| {
            let files: serde_json::Map<String, serde_json::Value> = entries
                .iter()
                .map(|entry| (entry.path.clone(), hex::encode(&entry.content).into()))
                .collect();
            let input = serde_json::to_vec(&files).expect("the files as JSON");
            run_python(&program, &input)
        })
        .collect()
}

/// The driver run after README's name-signature block. It holds no part of
/// the digest: it reads one printed lab CID from stdin, calls the block's
/// `name_digest` and prints its answer.
pub const NAME_DIGEST_DRIVER: &str = r#"
import sys
print(name_digest(sys.stdin.read()))
"#;

/// README's name-signature block run on each printed lab CID in `names`:
/// one answer per name, in order, each `name_digest`'s hex.
pub fn readme_python_name_digests(names: &[&str]) -> Result<Vec<String>, String> {
    let block = python_block_under(README, NAME_SIGNATURE_HEADING)?;
    python_name_digests(&block, names)
}

/// `block` and [`NAME_DIGEST_DRIVER`] run once per name, through
/// [`run_python`].
pub fn python_name_digests(block: &str, names: &[&str]) -> Result<Vec<String>, String> {
    let program = format!("{block}{NAME_DIGEST_DRIVER}");
    names
        .iter()
        .map(|name| run_python(&program, name.as_bytes()))
        .collect()
}

/// The driver run after README's package-record block. It holds no part of
/// the encoding: it reads `{"cid": ..., "did": ...}` JSON from stdin, calls
/// the block's `record_payload` and `record_digest`, and prints both answers
/// on one line.
pub const RECORD_DRIVER: &str = r#"
import json, sys
record = json.loads(sys.stdin.read())
print(record_payload(record["cid"], record["did"]), record_digest(record["cid"], record["did"]))
"#;

/// README's package-record block run on each `(cid, signer DID)` in
/// `records`: one `(payload hex, digest hex)` per record, in order. The DID
/// goes in as data; no key byte does.
pub fn readme_python_records(records: &[(&str, &str)]) -> Result<Vec<(String, String)>, String> {
    let block = python_block_under(README, PACKAGE_RECORD_HEADING)?;
    python_records(&block, records)
}

/// `block` and [`RECORD_DRIVER`] run once per record, through
/// [`run_python`]. A line that is not two words (an empty answer counts as
/// none) is refused with its text.
pub fn python_records(
    block: &str,
    records: &[(&str, &str)],
) -> Result<Vec<(String, String)>, String> {
    let program = format!("{block}{RECORD_DRIVER}");
    records
        .iter()
        .map(|(cid, did)| {
            let input = serde_json::json!({ "cid": cid, "did": did }).to_string();
            let line = run_python(&program, input.as_bytes())?;
            match line.split_whitespace().collect::<Vec<_>>()[..] {
                [payload, digest] => Ok((payload.to_owned(), digest.to_owned())),
                _ => Err(format!(
                    "{PYTHON} -I printed {line:?}, not a payload and a digest"
                )),
            }
        })
        .collect()
}

/// `program` run once with [`PYTHON`] `-I -c` from a fresh, empty temp
/// folder, with `stdin` as its input: its one line of output.
pub fn run_python(program: &str, stdin: &[u8]) -> Result<String, String> {
    run_python_with(PYTHON, program, stdin)
}

/// [`run_python`] with the interpreter `interpreter`. It never skips: an
/// interpreter that cannot start, a non-zero exit, output that is not UTF-8,
/// no line or more than one line are each refused with their reason.
pub fn run_python_with(interpreter: &str, program: &str, stdin: &[u8]) -> Result<String, String> {
    let fresh = temp_dir();
    let mut child = Command::new(interpreter)
        .arg("-I")
        .arg("-c")
        .arg(program)
        .current_dir(fresh.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{interpreter} -I could not run: {error}"))?;
    let mut input = child.stdin.take().expect("a piped stdin");
    let stdin = stdin.to_vec();
    let writer = thread::spawn(move || input.write_all(&stdin));
    let output = child
        .wait_with_output()
        .map_err(|error| format!("{interpreter} -I could not be waited for: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!(
            "{interpreter} -I exited with {}: {stderr}",
            output.status
        ));
    }
    writer
        .join()
        .expect("the stdin writer returns")
        .map_err(|error| format!("could not write the input to {interpreter} -I: {error}"))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| format!("{interpreter} -I printed bytes that are not UTF-8"))?;
    let lines: Vec<&str> = stdout.lines().collect();
    match lines[..] {
        [line] => Ok(line.to_owned()),
        [] => Err(format!("{interpreter} -I printed nothing: {stderr}")),
        _ => Err(format!(
            "{interpreter} -I printed {} lines, not one: {stdout:?}",
            lines.len()
        )),
    }
}

/// The heading of README's consumer adoption note.
pub const ADOPTION_HEADING: &str = "## For a lab that uses the lab CID\n";

/// The text of README's consumer adoption note, as committed.
pub fn readme_adoption_note() -> Result<&'static str, String> {
    section_under(README, ADOPTION_HEADING)
}

/// The consumer manifests README's adoption note lists, sorted.
pub fn readme_lab_cid_consumers() -> Result<Vec<String>, String> {
    consumers_listed_in(README)
}

/// The manifests listed in the ```text block of `readme`'s adoption note,
/// sorted. Each line is a repo-relative path and what that consumer uses:
/// `pins`, `parse` or `both`. Any other line is refused with its text.
pub fn consumers_listed_in(readme: &str) -> Result<Vec<String>, String> {
    let block = fenced_block_under(readme, ADOPTION_HEADING, "text")?;
    let mut listed = Vec::new();
    for line in block.lines() {
        match line.split_whitespace().collect::<Vec<_>>()[..] {
            [path, "pins" | "parse" | "both"] => listed.push(path.to_owned()),
            _ => {
                let what = "a manifest path and pins, parse or both";
                return Err(format!("the adoption note's line {line:?} is not {what}"));
            }
        }
    }
    listed.sort();
    Ok(listed)
}

/// The package name a dependency on this crate carries in Cargo's metadata,
/// whatever key or rename the consumer writes.
const CRATE_NAME: &str = "capsule-identity";

/// This lane's folder, as `git ls-files` prints it from the repository root.
const LANE_PREFIX: &str = "lab/capsule-identity/";

/// The repository's root: the folder that holds `lab/`.
pub fn repo_dir() -> PathBuf {
    lane_dir()
        .parent()
        .and_then(Path::parent)
        .expect("the lane is lab/capsule-identity")
        .to_path_buf()
}

/// Every git-tracked `Cargo.toml` under `lab/`, at any depth, outside this
/// lane: repo-relative paths, sorted. A git that cannot run or fails, or a
/// path that is not UTF-8, is refused with its cause.
pub fn lab_manifests() -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .args(["ls-files", "-z", "--", ":(glob)lab/**/Cargo.toml"])
        .current_dir(repo_dir())
        .output()
        .map_err(|error| format!("git cannot run: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let mut manifests = Vec::new();
    for name in output.stdout.split(|byte| *byte == 0) {
        if name.is_empty() {
            continue;
        }
        let path = String::from_utf8(name.to_vec())
            .map_err(|_| format!("a tracked path is not UTF-8: {name:?}"))?;
        if !path.starts_with(LANE_PREFIX) {
            manifests.push(path);
        }
    }
    manifests.sort();
    Ok(manifests)
}

/// The manifests of [`lab_manifests`] whose package depends on this crate
/// ([`depends_on_this_crate`]): repo-relative paths, sorted. The first
/// manifest that cannot be read is refused with its cause.
pub fn lab_cid_consumers() -> Result<Vec<String>, String> {
    let mut consumers = Vec::new();
    for path in lab_manifests()? {
        if depends_on_this_crate(&repo_dir().join(&path))? {
            consumers.push(path);
        }
    }
    Ok(consumers)
}

/// Whether the package of the manifest at `manifest`, as Cargo's own reader
/// reads it, has a dependency of any kind on this crate. It runs `cargo
/// metadata --no-deps --offline --format-version 1` with the cargo that built
/// these tests, from a fresh, empty temp folder, and reads its JSON with
/// [`consumer_in_metadata`]. No TOML is read here. A cargo that cannot start
/// or exits non-zero is refused with the manifest and cargo's stderr.
pub fn depends_on_this_crate(manifest: &Path) -> Result<bool, String> {
    let empty = temp_dir();
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
        ])
        .arg("--manifest-path")
        .arg(manifest)
        .current_dir(empty.path())
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("cargo could not run for {}: {error}", manifest.display()))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata refused {} ({}): {}",
            manifest.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    consumer_in_metadata(manifest, &output.stdout)
}

/// Whether `metadata`, the JSON `cargo metadata` printed for `manifest`,
/// holds a package whose `manifest_path` is that file and whose dependencies,
/// of any kind, hold one with `name` [`CRATE_NAME`] and a `path` that
/// resolves to this lane's folder. JSON that does not parse, no package for
/// that manifest, a field that is not of its type, or a path that does not
/// resolve is refused with the manifest and its cause.
pub fn consumer_in_metadata(manifest: &Path, metadata: &[u8]) -> Result<bool, String> {
    let shown = manifest.display();
    let metadata: serde_json::Value = serde_json::from_slice(metadata)
        .map_err(|error| format!("cargo metadata for {shown} is not JSON: {error}"))?;
    let resolved = |path: &str| {
        fs::canonicalize(path).map_err(|error| {
            format!("cargo metadata for {shown} names {path}, which does not resolve: {error}")
        })
    };
    let wanted = resolved(&manifest.to_string_lossy())?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| format!("cargo metadata for {shown} holds no packages list"))?;
    let mut package = None;
    for candidate in packages {
        let path = candidate["manifest_path"].as_str().ok_or_else(|| {
            format!("cargo metadata for {shown} has a package with no manifest_path")
        })?;
        if resolved(path)? == wanted {
            package = Some(candidate);
        }
    }
    let package = package.ok_or_else(|| {
        format!("cargo metadata for {shown} holds no package whose manifest is that file")
    })?;
    let dependencies = package["dependencies"]
        .as_array()
        .ok_or_else(|| format!("cargo metadata for {shown} holds no dependencies list"))?;
    let lane = resolved(&lane_dir().to_string_lossy())?;
    for dependency in dependencies {
        if dependency["name"] != CRATE_NAME {
            continue;
        }
        let Some(path) = dependency["path"].as_str() else {
            continue;
        };
        if resolved(path)? == lane {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Every path under `root`, relative to it, with its bytes (a link's target
/// for a link, `None` for a folder), sorted: the state a scan must leave as
/// it found it, ignored files and folders such as `target/` included.
pub fn folder_state(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let mut state = Vec::new();
    let mut folders = vec![root.to_path_buf()];
    while let Some(folder) = folders.pop() {
        let entries = fs::read_dir(&folder)
            .unwrap_or_else(|error| panic!("list {}: {error}", folder.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| panic!("list {}: {error}", folder.display()));
            let path = entry.path();
            let relative = path.strip_prefix(root).expect("under root").to_path_buf();
            let kind = entry
                .file_type()
                .unwrap_or_else(|error| panic!("stat {}: {error}", path.display()));
            let bytes = if kind.is_dir() {
                folders.push(path);
                None
            } else if kind.is_symlink() {
                let target = fs::read_link(&path)
                    .unwrap_or_else(|error| panic!("read link {}: {error}", path.display()));
                Some(target.into_os_string().into_encoded_bytes())
            } else {
                Some(
                    fs::read(&path)
                        .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
                )
            };
            state.push((relative, bytes));
        }
    }
    state.sort();
    state
}
