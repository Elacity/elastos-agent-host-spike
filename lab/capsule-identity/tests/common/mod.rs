//! Shared test support: fixture bundles assembled in fresh temp dirs, the
//! pinned lab CIDs, a bounded call for bundles that hold a FIFO, observers
//! that change a bundle while it is named, a driver for wc-001's own build,
//! the library's code for tests that read it, the refusal asserts both
//! signature checks share, the one key-material scan, the run of README's
//! Python rule, and the scan of the lab crates that use this crate (all three
//! kept here, a file the falsifier runner restores after a killed run).
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

/// The key a consumer's manifest names this crate by.
const CRATE_KEY: &str = "capsule-identity";

/// This lane's folder, as `git ls-files --full-name` prints it.
const LANE_PREFIX: &str = "lab/capsule-identity/";

/// The repository's root: the folder that holds `lab/`.
pub fn repo_dir() -> PathBuf {
    let lane = lane_dir();
    lane.parent()
        .and_then(Path::parent)
        .expect("the lane is lab/capsule-identity")
        .to_path_buf()
}

/// Every git-tracked `Cargo.toml` under `lab/` outside this lane whose
/// `[dependencies]` or `[dev-dependencies]` has a `capsule-identity` key
/// with a `path`: repo-relative paths, sorted. It reads only files outside
/// this lane. A git that cannot run, a path that is not UTF-8, an unreadable
/// manifest, or a manifest that names the crate in a form
/// [`depends_on_this_crate`] does not read, is refused with its cause.
pub fn lab_cid_consumers() -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "--cached",
            "--full-name",
            "-z",
            "--",
            "*Cargo.toml",
        ])
        .current_dir(repo_dir().join("lab"))
        .output()
        .map_err(|error| format!("git cannot run: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let mut consumers = Vec::new();
    for name in output.stdout.split(|byte| *byte == 0) {
        let path = String::from_utf8(name.to_vec())
            .map_err(|_| format!("a tracked path is not UTF-8: {name:?}"))?;
        let manifest = path.starts_with("lab/") && path.ends_with("/Cargo.toml");
        if !manifest || path.starts_with(LANE_PREFIX) {
            continue;
        }
        if depends_on_this_crate(&path, &read_manifest(&path)?)? {
            consumers.push(path);
        }
    }
    consumers.sort();
    Ok(consumers)
}

/// The text of the manifest at the repo-relative `path`. A manifest that
/// cannot be read is refused with its path and cause.
pub fn read_manifest(path: &str) -> Result<String, String> {
    fs::read_to_string(repo_dir().join(path)).map_err(|error| format!("read {path}: {error}"))
}

/// Whether the manifest `text`, at `path`, has a `capsule-identity` key with
/// a `path` in its `[dependencies]` or `[dev-dependencies]` table, written as
/// one inline table. It reads [`manifest_statements`], so a comment, and the
/// text inside a string, are never read as a key or a table, and a quoted
/// key is read with its escapes decoded. Cargo reads no dependency under
/// `[package]`, whose strings (a description, metadata) are text, so that
/// table is passed over. Any other statement with a key, a word or a string
/// that names the crate (another table, a dotted header or key, no inline
/// `path`, a `package` rename) is refused with its first line, so a consumer
/// written in a form this reader does not take fails the scan instead of
/// being missed.
pub fn depends_on_this_crate(path: &str, text: &str) -> Result<bool, String> {
    let mut table: Vec<String> = Vec::new();
    let mut found = false;
    for statement in manifest_statements(path, text)? {
        let tokens = &statement.tokens;
        let header = tokens.first() == Some(&Token::Mark('['));
        if header {
            table = names_in(tokens);
        }
        let (key, value) = match tokens.iter().position(|token| *token == Token::Mark('=')) {
            Some(at) if !header => (names_in(&tokens[..at]), &tokens[at + 1..]),
            _ => (Vec::new(), &tokens[..0]),
        };
        let place = table.first().or(key.first());
        if place.is_some_and(|name| name == "package") || !tokens.iter().any(names_this_crate) {
            continue;
        }
        let dependencies =
            matches!(&table[..], [one] if one == "dependencies" || one == "dev-dependencies");
        if dependencies && key == [CRATE_KEY] && has_inline_path(value) {
            found = true;
        } else {
            return Err(format!(
                "{path}:{}: {:?} names {CRATE_KEY} in a form the scan does not read",
                statement.line, statement.source
            ));
        }
    }
    Ok(found)
}

/// Whether `token` is a word or a string that holds this crate's key.
fn names_this_crate(token: &Token) -> bool {
    matches!(token, Token::Word(text) | Token::Text(text) if text.contains(CRATE_KEY))
}

/// The words and strings of `tokens`, in order: a header's table names or a
/// statement's dotted key.
fn names_in(tokens: &[Token]) -> Vec<String> {
    tokens
        .iter()
        .filter_map(|token| match token {
            Token::Word(text) | Token::Text(text) => Some(text.clone()),
            Token::Mark(_) => None,
        })
        .collect()
}

/// Whether `value` is one inline table with a `path` key of its own.
fn has_inline_path(value: &[Token]) -> bool {
    if value.first() != Some(&Token::Mark('{')) || value.last() != Some(&Token::Mark('}')) {
        return false;
    }
    let mut depth = 0;
    value.windows(3).any(|three| {
        match three[0] {
            Token::Mark('{' | '[') => depth += 1,
            Token::Mark('}' | ']') => depth -= 1,
            _ => {}
        }
        let key = matches!(&three[1], Token::Word(text) | Token::Text(text) if text == "path");
        let opens = matches!(three[0], Token::Mark('{' | ','));
        depth == 1 && opens && key && three[2] == Token::Mark('=')
    })
}

/// One piece of a manifest statement: a mark (`[ ] { } = , .`), a bare word,
/// or a string with its escapes decoded.
#[derive(Debug, PartialEq)]
pub enum Token {
    Mark(char),
    Word(String),
    Text(String),
}

/// A manifest statement: a table header or a `key = value`, with every line
/// of any string, array or inline table it opens. `line` is its first line's
/// number and `source` that line as written.
#[derive(Debug, PartialEq)]
pub struct Statement<'a> {
    pub line: usize,
    pub source: &'a str,
    pub tokens: Vec<Token>,
}

/// The statements of the manifest `text`, at `path`, read as TOML: comments
/// dropped, each string one token with its escapes decoded, and a statement
/// ending only at a line end outside any string, array or inline table. A
/// string never closed, an escape TOML does not define, and a bracket out of
/// balance are each refused with the line and the reason.
pub fn manifest_statements<'a>(path: &str, text: &'a str) -> Result<Vec<Statement<'a>>, String> {
    let sources: Vec<&str> = text.lines().collect();
    let chars: Vec<char> = text.chars().collect();
    let mut lexer = Lexer {
        chars: &chars,
        at: 0,
        line: 1,
    };
    let mut statements = Vec::new();
    let mut tokens = Vec::new();
    let mut start = 1;
    let mut depth = 0usize;
    let mut word = String::new();
    let refuse = |line: usize, reason: String| format!("{path}:{line}: {reason}");
    while let Some(c) = lexer.peek(0) {
        if tokens.is_empty() && word.is_empty() {
            start = lexer.line;
        }
        if !(c.is_whitespace() || "[]{}=,.#\"'".contains(c)) {
            word.push(c);
            lexer.at += 1;
            continue;
        }
        if !word.is_empty() {
            tokens.push(Token::Word(std::mem::take(&mut word)));
        }
        match c {
            '#' => lexer.skip_comment(),
            '"' | '\'' => {
                let line = lexer.line;
                tokens.push(Token::Text(
                    lexer.string().map_err(|why| refuse(line, why))?,
                ));
            }
            '\n' if depth == 0 => {
                lexer.next();
                if !tokens.is_empty() {
                    let source = sources[start - 1];
                    let tokens = std::mem::take(&mut tokens);
                    statements.push(Statement {
                        line: start,
                        source,
                        tokens,
                    });
                }
            }
            '[' | '{' | ']' | '}' | '=' | ',' | '.' => {
                if "[{".contains(c) {
                    depth += 1;
                } else if "]}".contains(c) {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| refuse(lexer.line, format!("a {c:?} closes nothing")))?;
                }
                tokens.push(Token::Mark(c));
                lexer.next();
            }
            _ => {
                lexer.next();
            }
        }
    }
    if !word.is_empty() {
        tokens.push(Token::Word(word));
    }
    if depth != 0 {
        return Err(refuse(
            start,
            "a bracket opened here is never closed".to_owned(),
        ));
    }
    if !tokens.is_empty() {
        statements.push(Statement {
            line: start,
            source: sources[start - 1],
            tokens,
        });
    }
    Ok(statements)
}

/// The characters of a manifest and where the reader is in them.
struct Lexer<'c> {
    chars: &'c [char],
    at: usize,
    line: usize,
}

impl Lexer<'_> {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    /// The next character, counting lines.
    fn next(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.at += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    /// Passes over a comment, up to its line's end.
    fn skip_comment(&mut self) {
        while self.peek(0).is_some_and(|c| c != '\n') {
            self.at += 1;
        }
    }

    /// The string that starts here, one-line or multi-line, basic or literal,
    /// with a basic string's escapes decoded.
    fn string(&mut self) -> Result<String, String> {
        let quote = self.next().expect("a quote");
        let multi = self.peek(0) == Some(quote) && self.peek(1) == Some(quote);
        if multi {
            self.at += 2;
            if self.peek(0) == Some('\n') {
                self.next();
            }
        }
        let mut text = String::new();
        loop {
            let Some(c) = self.next() else {
                return Err("a string is never closed".to_owned());
            };
            match c {
                '\n' if !multi => return Err("a one-line string is never closed".to_owned()),
                '\\' if quote == '"' => self.escape(multi, &mut text)?,
                _ if c == quote && !multi => return Ok(text),
                _ if c == quote => {
                    // Up to two quotes may end the text just before the
                    // closing three.
                    let mut run = 1;
                    while self.peek(0) == Some(quote) && run < 5 {
                        self.at += 1;
                        run += 1;
                    }
                    let closes = run >= 3;
                    let kept = if closes { run - 3 } else { run };
                    text.extend(std::iter::repeat(quote).take(kept));
                    if closes {
                        return Ok(text);
                    }
                }
                _ => text.push(c),
            }
        }
    }

    /// The escape after a `\` in a basic string, pushed to `text` decoded.
    /// In a multi-line string, a `\` at a line's end drops the line break
    /// and the white space after it.
    fn escape(&mut self, multi: bool, text: &mut String) -> Result<(), String> {
        let Some(c) = self.next() else {
            return Err("a string is never closed".to_owned());
        };
        let simple = match c {
            'b' => Some('\u{8}'),
            't' => Some('\t'),
            'n' => Some('\n'),
            'f' => Some('\u{c}'),
            'r' => Some('\r'),
            'e' => Some('\u{1b}'),
            '"' => Some('"'),
            '\\' => Some('\\'),
            _ => None,
        };
        if let Some(decoded) = simple {
            text.push(decoded);
            return Ok(());
        }
        let digits = match c {
            'x' => 2,
            'u' => 4,
            'U' => 8,
            ' ' | '\t' | '\r' | '\n' if multi => {
                let mut rest = c;
                while rest == ' ' || rest == '\t' || rest == '\r' {
                    rest = self.next().unwrap_or('\0');
                }
                if rest != '\n' {
                    return Err("a \\ in a multi-line string is not at a line's end".to_owned());
                }
                while self.peek(0).is_some_and(char::is_whitespace) {
                    self.next();
                }
                return Ok(());
            }
            _ => return Err(format!("the escape \\{c} is not TOML's")),
        };
        let hex: String = (0..digits).filter_map(|_| self.next()).collect();
        let decoded = u32::from_str_radix(&hex, 16)
            .ok()
            .filter(|_| hex.len() == digits && hex.chars().all(|d| d.is_ascii_hexdigit()))
            .and_then(char::from_u32)
            .ok_or_else(|| format!("the escape \\{c}{hex} is not a character"))?;
        text.push(decoded);
        Ok(())
    }
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
