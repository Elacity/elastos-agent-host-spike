//! Runs the built `archive-viewer.component.wasm` in `ComponentProvider`, the
//! Runtime's own Component runner (`elastos-compute/src/providers/component.rs`),
//! with a fake Runtime bridge behind the Bus hostcall.
//!
//! Build the component first: `../build.sh`.
//!
//! The bridge, the run, the admission check and the fuel runner are the
//! capsule kit's (`examples/capsule-kit/v1-host-test`), shared with the photo
//! and documents viewers.
//!
//! Both zip-bomb rules that only the component can prove get their evidence
//! here: F3 (the B2 streaming ratio check stops an entry whose first 16-byte
//! steps burst past the cap, while its declared ratio passes F4) and F43 (B5:
//! a 256 MiB declared total is shown and never sizes a buffer, under the
//! host's 128 MiB store limit). F35 (a run with no read grant stops with the
//! authority failure and writes no view) and F36 (one archive per hostile
//! class at its caps stays at or below 80% of the Runtime's 100,000,000 fuel)
//! are here too.

use std::path::{Path, PathBuf};

use capsule_v1_host_test::{admission, Bridge, ALLOWED_BUS_IMPORTS};
use elastos_common::CapsuleManifest;
use serde_json::{json, Value};

const REQUEST: &str = "localhost://Users/self/.AppData/App/archive-viewer/open.json";
const VIEW: &str = "localhost://Users/self/.AppData/App/archive-viewer/view.json";
const ARCHIVE: &str = "localhost://Users/self/Documents/trip.zip";
const REQUEST_SCHEMA: &str = "elastos.archive-viewer.open/v1";
const VIEW_SCHEMA: &str = "elastos.archive-viewer.view/v1";

// The caps the gate archives are built to (examples/archive-viewer/src/lib.rs,
// src/preview.rs). They are restated here, as the documents viewer restates
// its shelf caps, so a fixture can be built at its cap before the component
// sees it.
const MAX_DIRECTORY_BYTES: usize = 16 * 1024;
const MAX_ENTRIES: usize = 256;
const MAX_NAME_BYTES: usize = 255;
const MAX_PREVIEW_BYTES: usize = 16 * 1024;
const MAX_INFLATE_BYTES: usize = 64 * 1024;
const MAX_COMPRESSED_BYTES: usize = 24 * 1024;
const MAX_READ_BYTES: usize = 64 * 1024;
const MAX_VIEW_BYTES: usize = 64 * 1024;
const MAX_REQUEST_SHOW: usize = 8;

fn capsule_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn component_path() -> PathBuf {
    let path = capsule_dir().join("archive-viewer.component.wasm");
    assert!(
        path.is_file(),
        "{} is missing; run examples/archive-viewer/build.sh first",
        path.display()
    );
    path
}

fn manifest() -> CapsuleManifest {
    let text = std::fs::read_to_string(capsule_dir().join("capsule.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

// --- the shared harness (examples/capsule-kit/v1-host-test) ---------------------

/// A bridge holding the request, the archive and the view write.
fn bridge_with(archive: Vec<u8>, show: &[usize]) -> Bridge {
    let mut bridge = Bridge::default();
    bridge.put(REQUEST, request(ARCHIVE, show));
    bridge.allow(REQUEST, "read");
    bridge.put(ARCHIVE, archive);
    bridge.allow(ARCHIVE, "read");
    bridge.allow(VIEW, "write");
    bridge
}

/// Loads and starts the component once. Returns the Runtime's result and the
/// bridge after the run.
async fn run(bridge: Bridge) -> (Result<(), String>, Bridge) {
    let _ = component_path();
    capsule_v1_host_test::run(&capsule_dir(), manifest(), bridge).await
}

// --- fixtures ----------------------------------------------------------------------

fn request(uri: &str, show: &[usize]) -> Vec<u8> {
    let mut value = json!({ "schema": REQUEST_SCHEMA, "uri": uri });
    if !show.is_empty() {
        value["show"] = json!(show);
    }
    serde_json::to_vec(&value).unwrap()
}

/// One entry the builder writes: its name, its stored or deflated bytes, and
/// the uncompressed text. The stream may be supplied (the ratio-cap bomb), and
/// the declared uncompressed size may differ from the text (B5's declared
/// totals).
struct Fixture {
    name: String,
    method: u16,
    text: Vec<u8>,
    compressed: Option<Vec<u8>>,
    declared: Option<u64>,
}

impl Fixture {
    fn stored(name: &str) -> Self {
        Fixture {
            name: name.to_string(),
            method: 0,
            text: Vec::new(),
            compressed: None,
            declared: None,
        }
    }

    fn file(name: &str, text: &[u8]) -> Self {
        Fixture {
            name: name.to_string(),
            method: 0,
            text: text.to_vec(),
            compressed: None,
            declared: None,
        }
    }

    fn deflated(name: &str, text: &[u8]) -> Self {
        Fixture {
            name: name.to_string(),
            method: 8,
            text: text.to_vec(),
            compressed: None,
            declared: None,
        }
    }

    fn deflated_with(name: &str, text: Vec<u8>, compressed: Vec<u8>) -> Self {
        Fixture {
            name: name.to_string(),
            method: 8,
            text,
            compressed: Some(compressed),
            declared: None,
        }
    }

    /// A deflated entry whose declared uncompressed size is not its data's:
    /// B5 says a declaration is display only and never sizes a buffer.
    fn declaring(name: &str, text: &[u8], declared: u64) -> Self {
        Fixture {
            name: name.to_string(),
            method: 8,
            text: text.to_vec(),
            compressed: None,
            declared: Some(declared),
        }
    }
}

/// The bytes and declaration of one fixture.
struct Built {
    name: Vec<u8>,
    method: u16,
    crc: u32,
    data: Vec<u8>,
    uncompressed: u32,
}

fn u16b(value: u16) -> [u8; 2] {
    value.to_le_bytes()
}

fn u32b(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// One built archive, with where its records sit: each entry's local-header
/// offset and the central directory's range.
struct Archive {
    bytes: Vec<u8>,
    local_offsets: Vec<u64>,
    directory_offset: u64,
    directory_size: u64,
}

/// The archive's bytes.
fn zip(fixtures: &[Fixture]) -> Vec<u8> {
    archive(fixtures).bytes
}

/// Builds a ZIP byte by byte: local headers and data, then the central
/// directory, then the end record.
fn archive(fixtures: &[Fixture]) -> Archive {
    let mut out = Vec::new();
    let mut built = Vec::new();
    let mut offsets = Vec::new();
    for fixture in fixtures {
        let (method, data) = if fixture.method == 0 {
            (0, fixture.text.clone())
        } else {
            let data = fixture
                .compressed
                .clone()
                .unwrap_or_else(|| miniz_oxide::deflate::compress_to_vec(&fixture.text, 6));
            (8, data)
        };
        built.push(Built {
            name: fixture.name.as_bytes().to_vec(),
            method,
            crc: crc32(&fixture.text),
            data,
            uncompressed: fixture.declared.unwrap_or(fixture.text.len() as u64) as u32,
        });
    }
    for entry in &built {
        offsets.push(out.len() as u32);
        out.extend_from_slice(&u32b(0x0403_4b50));
        out.extend_from_slice(&u16b(20));
        out.extend_from_slice(&u16b(0));
        out.extend_from_slice(&u16b(entry.method));
        out.extend_from_slice(&u16b(0));
        out.extend_from_slice(&u16b(0));
        out.extend_from_slice(&u32b(entry.crc));
        out.extend_from_slice(&u32b(entry.data.len() as u32));
        out.extend_from_slice(&u32b(entry.uncompressed));
        out.extend_from_slice(&u16b(entry.name.len() as u16));
        out.extend_from_slice(&u16b(0));
        out.extend_from_slice(&entry.name);
        out.extend_from_slice(&entry.data);
    }
    let directory_offset = out.len() as u32;
    for (entry, offset) in built.iter().zip(&offsets) {
        out.extend_from_slice(&u32b(0x0201_4b50));
        out.extend_from_slice(&u16b(20));
        out.extend_from_slice(&u16b(20));
        out.extend_from_slice(&u16b(0));
        out.extend_from_slice(&u16b(entry.method));
        out.extend_from_slice(&u16b(0));
        out.extend_from_slice(&u16b(0));
        out.extend_from_slice(&u32b(entry.crc));
        out.extend_from_slice(&u32b(entry.data.len() as u32));
        out.extend_from_slice(&u32b(entry.uncompressed));
        out.extend_from_slice(&u16b(entry.name.len() as u16));
        out.extend_from_slice(&u16b(0));
        out.extend_from_slice(&u16b(0));
        out.extend_from_slice(&u16b(0));
        out.extend_from_slice(&u16b(0));
        out.extend_from_slice(&u32b(0));
        out.extend_from_slice(&u32b(*offset));
        out.extend_from_slice(&entry.name);
    }
    let directory_size = out.len() as u32 - directory_offset;
    out.extend_from_slice(&u32b(0x0605_4b50));
    out.extend_from_slice(&u16b(0));
    out.extend_from_slice(&u16b(0));
    out.extend_from_slice(&u16b(built.len() as u16));
    out.extend_from_slice(&u16b(built.len() as u16));
    out.extend_from_slice(&u32b(directory_size));
    out.extend_from_slice(&u32b(directory_offset));
    out.extend_from_slice(&u16b(0));
    Archive {
        bytes: out,
        local_offsets: offsets.iter().map(|offset| u64::from(*offset)).collect(),
        directory_offset: u64::from(directory_offset),
        directory_size: u64::from(directory_size),
    }
}

/// The central directory's size for these fixtures: a record is 46 bytes plus
/// its name.
fn directory_bytes(fixtures: &[Fixture]) -> usize {
    fixtures.iter().map(|fixture| 46 + fixture.name.len()).sum()
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Printable text with a moderate deflate ratio: a repeating 200-byte block.
fn text_block(len: usize) -> Vec<u8> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut block = Vec::with_capacity(200);
    let mut state = 0x9e37_79b9u32;
    for _ in 0..200 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        block.push(ALPHABET[(state >> 16) as usize % ALPHABET.len()]);
    }
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        out.extend_from_slice(&block);
    }
    out.truncate(len);
    out
}

/// Printable text with little repetition: a full-period xorshift sequence over
/// the alphabet, so the deflate stream is mostly literals. It is the worst
/// Huffman work the decompressor can be given within the caps; the fuel test
/// compares it against [`text_block`].
fn plain_text(len: usize) -> Vec<u8> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut out = Vec::with_capacity(len);
    let mut state = 0x2545_f491u32;
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push(ALPHABET[state as usize % ALPHABET.len()]);
    }
    out
}

/// The largest directory within the 256-entry and 16 KiB caps: 256 entries
/// whose 18-byte names make the directory exactly 16,384 bytes.
fn largest_directory() -> Vec<Fixture> {
    (0..MAX_ENTRIES)
        .map(|n| Fixture::stored(&format!("f{n:013}.txt")))
        .collect()
}

/// The most names at their longest that fit the directory cap: 54 entries of
/// 255 bytes each (54 × 301 = 16,254 bytes).
fn longest_names() -> Vec<Fixture> {
    (0..54)
        .map(|n| Fixture::stored(&format!("{n:03}{}", "a".repeat(MAX_NAME_BYTES - 3))))
        .collect()
}

/// Eight entries, each 6 KiB of text: the most entries one run may show, with
/// 48 KiB inflated in all (under the 64 KiB total and the 24 KiB compressed
/// caps).
fn most_shown() -> Vec<Fixture> {
    (0..MAX_REQUEST_SHOW)
        .map(|n| Fixture::deflated(&format!("p{n}.txt"), &text_block(6 * 1024)))
        .collect()
}

/// Five entries of 16 KiB: the first is shown, the next three inflate to the
/// end and fail the text check (each ends in NUL), and the fifth is skipped
/// `inflate_budget` before any read. The four inflated entries consume the
/// whole 64 KiB B3 allowance; the view stays small because only the first
/// entry renders.
fn full_inflate_allowance() -> Vec<Fixture> {
    let shown = text_block(MAX_PREVIEW_BYTES);
    let mut fixtures = vec![Fixture::deflated("shown.txt", &shown)];
    for n in 1..5 {
        let mut not_text = text_block(MAX_PREVIEW_BYTES);
        *not_text.last_mut().expect("16 KiB of text") = 0;
        fixtures.push(Fixture::deflated(&format!("n{n}.bin"), &not_text));
    }
    fixtures
}

/// The compressed size a stream needs to stay inside B2's declared-ratio cap:
/// `uncompressed <= compressed * 100 + 1024`.
fn compressed_floor(uncompressed: usize) -> usize {
    uncompressed.saturating_sub(1024).div_ceil(100)
}

/// A 16 KiB bomb whose declared ratio sits at the cap: runs of zeros broken by
/// one literal each, compressed at the level closest to the floor.
fn ratio_cap_bomb() -> Fixture {
    let mut text = Vec::with_capacity(MAX_PREVIEW_BYTES);
    let mut literal = 1u8;
    while text.len() < MAX_PREVIEW_BYTES {
        text.extend(std::iter::repeat_n(0u8, 258));
        text.push(literal);
        literal = literal.wrapping_add(1);
        if literal == 0 {
            literal = 1;
        }
    }
    text.truncate(MAX_PREVIEW_BYTES);
    let floor = compressed_floor(text.len());
    let mut chosen: Option<Vec<u8>> = None;
    for level in 1..=10 {
        let candidate = miniz_oxide::deflate::compress_to_vec(&text, level);
        if candidate.len() < floor {
            continue;
        }
        if chosen
            .as_ref()
            .is_none_or(|best| candidate.len() < best.len())
        {
            chosen = Some(candidate);
        }
    }
    let compressed = chosen.unwrap_or_else(|| miniz_oxide::deflate::compress_to_vec(&text, 6));
    Fixture::deflated_with("bomb.bin", text, compressed)
}

/// One entry of the worst text inflate cost: 16 KiB of low-compressibility
/// text shown. The fuel test proves it costs more than the repeating text.
fn worst_text() -> Vec<Fixture> {
    vec![Fixture::deflated("t.txt", &plain_text(MAX_PREVIEW_BYTES))]
}

/// B2 (F3): a hand-built deflate stream of exactly 100 bytes that inflates to
/// exactly 10,000. Its first block is dynamic with a 1-bit code for the
/// 258-byte length, a 1-bit distance code and a 2-bit literal that seeds the
/// history, so after the first 16 compressed bytes it has produced 2,839
/// bytes: past 100 × 16 + 1 KiB = 2,624. The rest of the stream is a valid
/// fixed block, so the whole stream ends at byte 100 with 10,000 out, and the
/// declared ratio (10,000 from 100) passes F4. Without the per-step check the
/// entry inflates to its declared size instead of stopping at the burst.
const BOMB_STREAM: [u8; 100] = [
    0xec, 0xc0, 0x01, 0x01, 0x00, 0x00, 0x00, 0x80, 0x90, 0xfe, 0xaf, 0xee, 0x08, 0x01, 0x00, 0x00,
    0x0b, 0x20, 0x80, 0x00, 0x63, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
    0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
    0x60, 0x60, 0x60, 0x60, 0x18, 0x05, 0xa3, 0x60, 0x14, 0x8c, 0x82, 0x51, 0x30, 0x0a, 0x46, 0xc1,
    0x28, 0x18, 0x05, 0xa3, 0x60, 0x14, 0x8c, 0x82, 0x51, 0x30, 0x0a, 0x46, 0xc1, 0x28, 0x18, 0x05,
    0xa3, 0x60, 0x14, 0x8c, 0x82, 0x51, 0x30, 0x0a, 0x46, 0xc1, 0x28, 0x18, 0x05, 0xa3, 0x60, 0x28,
    0x80, 0x11, 0x0f, 0x00,
];

fn ratio_burst_bomb() -> Fixture {
    Fixture::deflated_with("bomb.bin", vec![0u8; 10_000], BOMB_STREAM.to_vec())
}

/// The output of the first `steps` compressed bytes of a stream, decoded the
/// way the guest decodes them: a bounded step with the rest of the stream
/// still behind it. Returns the compressed bytes used and the output bytes.
///
/// The guest runs the same step size (`INFLATE_STEP_BYTES`), so this pins the
/// fixture's counts at the step where its streaming check trips.
fn step_output(compressed: &[u8], steps: usize) -> (usize, u64) {
    use miniz_oxide::inflate::core::{decompress_with_limit, inflate_flags, DecompressorOxide};
    const STEP: usize = 16;
    const DICTIONARY_BYTES: usize = 32 * 1024;
    let end = (steps * STEP).min(compressed.len());
    let mut state = DecompressorOxide::new();
    let mut dictionary = vec![0u8; DICTIONARY_BYTES];
    let flags = if end < compressed.len() {
        inflate_flags::TINFL_FLAG_HAS_MORE_INPUT
    } else {
        0
    };
    let (_, used, produced) = decompress_with_limit(
        &mut state,
        &compressed[..end],
        &mut dictionary,
        0,
        DICTIONARY_BYTES,
        flags,
    );
    (used, produced as u64)
}

/// B5 (F43): 256 entries that declare 1 MiB each, 268,435,456 bytes in all.
/// That fits a wasm32 `usize` and is above the host's 128 MiB store limit, so
/// `total as usize` stays 268,435,456 and cannot become 0. A 512 GiB total is
/// not used: it exceeds `usize::MAX`, and `as usize` would wrap it to 0, which
/// the allocation mutant would survive.
fn declared_256_mib() -> Vec<Fixture> {
    const MIB: u64 = 1024 * 1024;
    (0..MAX_ENTRIES)
        .map(|n| Fixture::declaring(&format!("{n:02x}"), &[], MIB))
        .collect()
}

/// The same 256 records with a small declared size: the bytes and so the read
/// trace are identical, and only the declared total differs.
fn declared_small() -> Vec<Fixture> {
    (0..MAX_ENTRIES)
        .map(|n| Fixture::declaring(&format!("{n:02x}"), &[], 1))
        .collect()
}

/// A listing of 256 entries and two 15 KiB previews: the whole view near its
/// 64 KiB cap.
fn largest_view() -> Vec<Fixture> {
    let mut fixtures: Vec<Fixture> = (0..MAX_ENTRIES - 2)
        .map(|n| Fixture::stored(&format!("f{n:013}.txt")))
        .collect();
    fixtures.push(Fixture::deflated("a.txt", &text_block(15 * 1024)));
    fixtures.push(Fixture::deflated("b.txt", &text_block(15 * 1024)));
    fixtures
}

/// The archives the fuel gate runs, one per hostile class at its caps
/// (DESIGN.md, "The fuel gate (F36)").
fn worst_archives() -> Vec<(&'static str, Bridge)> {
    let show_all: Vec<usize> = (0..MAX_REQUEST_SHOW).collect();
    vec![
        (
            "the largest directory",
            bridge_with(zip(&largest_directory()), &[]),
        ),
        (
            "the most names at their longest",
            bridge_with(zip(&longest_names()), &[]),
        ),
        (
            "the most shown entries",
            bridge_with(zip(&most_shown()), &show_all),
        ),
        (
            "the full inflate allowance",
            bridge_with(zip(&full_inflate_allowance()), &[0, 1, 2, 3, 4]),
        ),
        (
            "a bomb at the ratio cap",
            bridge_with(zip(&[ratio_cap_bomb()]), &[0]),
        ),
        (
            "a worst-inflate text entry",
            bridge_with(zip(&worst_text()), &[0]),
        ),
        (
            "the largest view",
            bridge_with(zip(&largest_view()), &[MAX_ENTRIES - 2, MAX_ENTRIES - 1]),
        ),
    ]
}

// --- manifest -----------------------------------------------------------------------

#[test]
fn manifest_is_a_valid_component_capsule_with_its_storage_bounds() {
    let manifest = manifest();
    manifest.validate().expect("manifest validates");
    assert!(manifest.is_component_capsule());
    assert_eq!(manifest.entrypoint, "archive-viewer.component.wasm");
    assert_eq!(
        manifest.resource_authority_bounds(),
        vec![
            "localhost://Users/self/*".to_string(),
            "localhost://Users/self/.AppData/App/archive-viewer/*".to_string(),
        ]
    );
}

// --- runs in the Runtime's ComponentProvider ------------------------------------------

fn view(bridge: &Bridge) -> Value {
    serde_json::from_str(&bridge.written[VIEW]).expect("the view was written")
}

fn denied(err: &str) -> bool {
    err.contains("Component capsule denied: BusError::Denied(")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_small_archive_is_listed_and_its_text_is_shown_through_the_runtime() {
    let archive = zip(&[
        Fixture::file("hello.txt", b"hello world\n"),
        Fixture::stored("dir/"),
        Fixture::deflated("more.txt", b"second entry\n"),
    ]);
    let size = archive.len();
    let (result, bridge) = run(bridge_with(archive, &[0])).await;
    result.unwrap();
    let view = view(&bridge);
    assert_eq!(view["schema"], VIEW_SCHEMA);
    assert_eq!(view["archive"]["uri"], ARCHIVE);
    assert_eq!(view["archive"]["size"], size);
    assert_eq!(view["entries"].as_array().unwrap().len(), 3);
    assert_eq!(view["entries"][0]["path"], "hello.txt");
    assert_eq!(view["entries"][0]["status"], "listed");
    assert_eq!(view["entries"][1]["path"], "dir/");
    assert_eq!(view["entries"][1]["kind"], "directory");
    assert_eq!(view["entries"][2]["path"], "more.txt");
    assert_eq!(view["previews"][0]["index"], 0);
    assert_eq!(view["previews"][0]["blocks"][0]["kind"], "paragraph");
    assert_eq!(
        view["previews"][0]["blocks"][0]["spans"][0]["text"],
        "hello world"
    );
    assert_eq!(view["skipped"], json!([]));
    // The request, the one archive, and its view: each through its own token.
    let uris: Vec<&str> = bridge
        .lines
        .iter()
        .filter(|line| line["request"]["type"] == "request_capability")
        .map(|line| line["request"]["resource"].as_str().unwrap())
        .collect();
    assert_eq!(uris, [REQUEST, ARCHIVE, VIEW]);
}

/// The produced and consumed counts a `ratio` skip message states:
/// `... (2839 bytes from 16 compressed bytes)`.
fn ratio_counts(message: &str) -> (u64, u64) {
    let (_, tail) = message.split_once('(').expect("the counts");
    let (produced, rest) = tail.split_once(" bytes from ").expect("the consumed count");
    let (consumed, _) = rest.split_once(' ').expect("the trailing words");
    (
        produced.parse().expect("produced is a number"),
        consumed.parse().expect("consumed is a number"),
    )
}

/// F3: the streaming ratio check runs after every 16-byte inflate step inside
/// the component. The fixture's declared ratio (10,000 from 100 bytes) is
/// inside F4's cap, so the declared check lets it read; its first 16-byte step
/// then produces 2,839 bytes, past 100 × 16 + 1 KiB, and the component skips
/// it `ratio` and states the counters it stopped at.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bomb_entry_stops_at_the_ratio_cap() {
    let bomb = ratio_burst_bomb();
    let compressed = bomb.compressed.clone().expect("the crafted stream");
    assert_eq!(compressed.len(), 100, "the fixture is 100 compressed bytes");
    assert_eq!(bomb.text.len(), 10_000);
    // F4's declared-ratio check passes: 10,000 ≤ 100 × 100 + 1 KiB.
    assert!(bomb.text.len() as u64 <= 100 * 100 + 1024);

    // The step the component stops on: the first 16 bytes are the burst. A
    // single 16-byte window is that step.
    let (used, produced) = step_output(&compressed, 1);
    assert_eq!(used, 16);
    assert!(
        used < compressed.len(),
        "the stop is before the stream ends"
    );
    assert!(produced > 1024, "{produced} bytes came out");
    assert!(
        produced > 100 * used as u64 + 1024,
        "{produced} bytes from {used} is inside the cap"
    );
    // The whole stream is valid: all 100 bytes inflate to exactly 10,000, so
    // only the per-step check can stop this entry. Without it, the entry
    // inflates to its declared size instead of being skipped at the burst.
    let (used, produced) = step_output(&compressed, compressed.len());
    assert_eq!(used, compressed.len());
    assert_eq!(produced, 10_000);

    let archive = zip(&[bomb]);
    let (result, bridge) = run(bridge_with(archive, &[0])).await;
    result.unwrap();
    let view = view(&bridge);
    assert_eq!(view["entries"][0]["status"], "listed");
    assert_eq!(view["skipped"][0]["reason"], "ratio");
    // The component's own counters, at the step it stopped on.
    let (stopped_produced, stopped_consumed) =
        ratio_counts(view["skipped"][0]["message"].as_str().expect("a message"));
    assert_eq!(stopped_consumed, 16, "the first 16-byte step");
    assert_eq!(stopped_produced, 2839);
    assert!(stopped_produced > 1024);
    assert!(stopped_produced > 100 * stopped_consumed + 1024);
    assert!(stopped_consumed < compressed.len() as u64);
}

/// The ordered archive-read tuples a bridge saw: URI, operation, requested
/// offset and requested length.
fn archive_reads(bridge: &Bridge) -> Vec<(String, String, u64, u64)> {
    bridge
        .lines
        .iter()
        .filter(|line| {
            line["request"]["type"] == "resource_invoke"
                && line["request"]["uri"] == ARCHIVE
                && line["request"]["operation"] == "read"
        })
        .map(|line| {
            (
                line["request"]["uri"].as_str().expect("a uri").to_string(),
                line["request"]["operation"]
                    .as_str()
                    .expect("an operation")
                    .to_string(),
                line["request"]["body"]["offset"].as_u64().unwrap_or(0),
                line["request"]["body"]["length"].as_u64().unwrap_or(0),
            )
        })
        .collect()
}

/// F43: a declared total is display only (B5). 256 entries declare 1 MiB
/// each. The complete listing is written, every read window is the one the
/// same records with a small declaration ask for, and no buffer is sized
/// from the declared 268,435,456-byte total (the allocation mutant traps on
/// `memory.grow` in the host's 128 MiB store).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_256_mib_total_is_listed_with_bounded_reads_and_memory() {
    const MIB: u64 = 1024 * 1024;
    const LOCAL_HEADER: u64 = 30;
    let declared = declared_256_mib();
    let total = MIB * declared.len() as u64;
    assert_eq!(total, 268_435_456);
    assert!(usize::try_from(total).is_ok(), "fits a wasm32 usize");
    assert!(total > 128 * 1024 * 1024, "above the host's store limit");

    let built = archive(&declared);
    let size = built.bytes.len() as u64;
    let (result, bridge) = run(bridge_with(built.bytes.clone(), &[])).await;
    result.unwrap();
    let view = view(&bridge);
    let entries = view["entries"].as_array().expect("the listing");
    assert_eq!(entries.len(), MAX_ENTRIES, "every entry is listed");
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry["index"], index);
        assert_eq!(entry["path"], format!("{index:02x}"));
        assert_eq!(entry["status"], "listed");
        assert_eq!(entry["uncompressed_size"], MIB);
    }
    let shown: u64 = entries
        .iter()
        .map(|entry| entry["uncompressed_size"].as_u64().unwrap())
        .sum();
    assert_eq!(shown, total, "the declared total is shown, not acted on");
    assert_eq!(view["previews"], json!([]));
    assert_eq!(view["skipped"], json!([]));
    assert!(size < MAX_READ_BYTES as u64, "{size} bytes of archive");

    // The read trace, not only its total: one-byte size probes, then the
    // tail, the directory and each 30-byte local header, at the record's own
    // offset and in offset order.
    let reads = archive_reads(&bridge);
    let tail_start = size.saturating_sub(22 + 1024);
    let mut expected: Vec<(u64, u64)> = vec![
        (tail_start, size - tail_start),
        (built.directory_offset, built.directory_size),
    ];
    expected.extend(built.local_offsets.iter().map(|at| (*at, LOCAL_HEADER)));
    let (probes, records) = reads.split_at(reads.len() - expected.len());
    assert!(!probes.is_empty(), "the one-byte size probes");
    assert!(
        probes.iter().all(|(_, _, _, length)| *length == 1),
        "the size probes ask for one byte"
    );
    let windows: Vec<(u64, u64)> = records
        .iter()
        .map(|(_, _, offset, length)| (*offset, *length))
        .collect();
    assert_eq!(windows, expected);
    assert!(
        records[2..].windows(2).all(|pair| pair[0].2 < pair[1].2),
        "the local headers are read in offset order"
    );
    assert!(reads
        .iter()
        .all(|(uri, operation, _, _)| uri == ARCHIVE && operation == "read"));

    // The same records with a 1-byte declaration have the same bytes and the
    // same layout, so every window must match exactly: the declared total
    // never reaches a read.
    let control = archive(&declared_small());
    assert_eq!(control.bytes.len(), size as usize);
    let (control_result, control_bridge) = run(bridge_with(control.bytes.clone(), &[])).await;
    control_result.unwrap();
    assert_eq!(archive_reads(&control_bridge), reads);
    assert_eq!(
        control_bridge.bytes_served.get(ARCHIVE),
        bridge.bytes_served.get(ARCHIVE)
    );
    let read: u64 = reads.iter().map(|(_, _, _, length)| *length).sum();
    assert!(read <= MAX_READ_BYTES as u64, "{read} bytes read");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_grant_stops_the_run_through_the_runtime() {
    let archive = zip(&[Fixture::file("hello.txt", b"hello\n")]);
    let mut bridge = bridge_with(archive, &[]);
    bridge.deny(ARCHIVE, "read");
    let (result, bridge) = run(bridge).await;
    let err = result.unwrap_err();
    assert!(denied(&err), "{err}");
    assert!(err.contains(ARCHIVE), "{err}");
    assert_eq!(bridge.invokes_on(ARCHIVE), 0, "no read without a grant");
    assert!(
        bridge.written.is_empty(),
        "an authority failure writes no view"
    );
    assert_eq!(bridge.invokes_on(VIEW), 0, "no write may be attempted");
}

/// The archives the gate runs are valid at their caps, and each really writes
/// its view: the bomb is inflated and skipped as not text, not refused for its
/// declared ratio, and the largest view stays inside its cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worst_archives_run_and_write_their_views() {
    for (name, bridge) in worst_archives() {
        let (result, bridge) = run(bridge).await;
        result.unwrap_or_else(|err| panic!("{name}: {err}"));
        let text = &bridge.written[VIEW];
        println!("{name}: {} bytes of view", text.len());
        assert!(text.len() <= MAX_VIEW_BYTES, "{name}: {} bytes", text.len());
        let view = view(&bridge);
        match name {
            "the largest directory" => {
                assert_eq!(view["entries"].as_array().unwrap().len(), MAX_ENTRIES);
            }
            "the most names at their longest" => {
                let entries = view["entries"].as_array().unwrap();
                assert_eq!(entries.len(), 54);
                assert!(entries
                    .iter()
                    .all(|entry| entry["path"].as_str().unwrap().len() == MAX_NAME_BYTES));
            }
            "the most shown entries" => {
                assert_eq!(view["previews"].as_array().unwrap().len(), MAX_REQUEST_SHOW);
            }
            "the full inflate allowance" => {
                assert_eq!(view["previews"].as_array().unwrap().len(), 1);
                let skipped = view["skipped"].as_array().unwrap();
                assert_eq!(skipped.len(), 4);
                let reasons: Vec<&str> = skipped
                    .iter()
                    .map(|skip| skip["reason"].as_str().unwrap())
                    .collect();
                // The four inflated entries spend the whole allowance; the
                // fifth is refused before any read.
                assert_eq!(
                    reasons,
                    ["not_text", "not_text", "not_text", "inflate_budget"]
                );
            }
            "a bomb at the ratio cap" => {
                assert_eq!(view["entries"][0]["status"], "listed");
                assert_eq!(view["skipped"][0]["reason"], "not_text");
            }
            "a worst-inflate text entry" => {
                let previews = view["previews"].as_array().unwrap();
                assert_eq!(previews.len(), 1);
                assert_eq!(
                    previews[0]["blocks"][0]["spans"][0]["text"]
                        .as_str()
                        .unwrap()
                        .len(),
                    MAX_PREVIEW_BYTES
                );
            }
            "the largest view" => {
                assert_eq!(view["previews"].as_array().unwrap().len(), 2);
                assert!(
                    text.len() > MAX_VIEW_BYTES * 15 / 16,
                    "{name}: {}",
                    text.len()
                );
            }
            _ => {}
        }
    }
}

#[test]
fn the_worst_archives_reach_their_caps() {
    let largest = largest_directory();
    assert_eq!(directory_bytes(&largest), MAX_DIRECTORY_BYTES);
    let names = longest_names();
    assert_eq!(names.len(), 54);
    assert!(names
        .iter()
        .all(|fixture| fixture.name.len() == MAX_NAME_BYTES));
    assert!(directory_bytes(&names) <= MAX_DIRECTORY_BYTES);
    let shown = most_shown();
    let inflated: usize = shown.iter().map(|fixture| fixture.text.len()).sum();
    assert_eq!(shown.len(), MAX_REQUEST_SHOW);
    assert_eq!(inflated, 48 * 1024);
    assert!(inflated <= MAX_INFLATE_BYTES);
    let compressed: usize = shown
        .iter()
        .map(|fixture| miniz_oxide::deflate::compress_to_vec(&fixture.text, 6).len())
        .sum();
    assert!(compressed <= MAX_COMPRESSED_BYTES);

    // The full-allowance archive: four 16 KiB entries spend the whole B3
    // allowance exactly, and the fifth proves the allowance is at zero.
    let allowance = full_inflate_allowance();
    assert_eq!(allowance.len(), 5);
    assert!(allowance
        .iter()
        .all(|fixture| fixture.text.len() == MAX_PREVIEW_BYTES));
    assert_ne!(allowance[0].text.last(), Some(&0));
    assert!(allowance[1..]
        .iter()
        .all(|fixture| fixture.text.last() == Some(&0)));
    assert_eq!(4 * MAX_PREVIEW_BYTES, MAX_INFLATE_BYTES);
    let allowance_compressed: usize = allowance
        .iter()
        .map(|fixture| miniz_oxide::deflate::compress_to_vec(&fixture.text, 6).len())
        .sum();
    assert!(allowance_compressed <= MAX_COMPRESSED_BYTES);

    // The worst text is the low-compressibility one, which fits the declared
    // ratio and the compressed budget.
    let text = worst_text();
    assert_eq!(text[0].text.len(), MAX_PREVIEW_BYTES);
    let text_compressed = miniz_oxide::deflate::compress_to_vec(&text[0].text, 6);
    assert!(text_compressed.len() <= MAX_COMPRESSED_BYTES);
    assert!(text[0].text.len() <= text_compressed.len() * 100 + 1024);

    // The bomb's declared ratio is inside the cap: it is read, not refused.
    let bomb = ratio_cap_bomb();
    let compressed = bomb.compressed.as_ref().unwrap().len();
    assert!(compressed >= compressed_floor(bomb.text.len()));
    assert!(bomb.text.len() <= compressed * 100 + 1024);

    assert!(directory_bytes(&largest_view()) <= MAX_DIRECTORY_BYTES);
}

/// The worst text is chosen by measurement, not assumption: one 16 KiB entry
/// of low-compressibility text costs more fuel than the repeating text.
#[test]
fn low_compressibility_text_costs_more_than_repeating_text() {
    let repeating = measure::run(
        bridge_with(
            zip(&[Fixture::deflated("t.txt", &text_block(MAX_PREVIEW_BYTES))]),
            &[0],
        ),
        measure::RUNTIME_FUEL,
    );
    let plain = measure::run(bridge_with(zip(&worst_text()), &[0]), measure::RUNTIME_FUEL);
    repeating.0.unwrap();
    plain.0.unwrap();
    println!(
        "16 KiB text: repeating {} fuel, low-compressibility {} fuel",
        repeating.1, plain.1
    );
    assert!(
        plain.1 > repeating.1,
        "the low-compressibility text must cost more: {} vs {}",
        plain.1,
        repeating.1
    );
}

// --- artifact ---------------------------------------------------------------------

#[test]
fn component_imports_only_the_elastos_bus() {
    let (imports, exports) = capsule_v1_host_test::imports_and_exports(&component_path());
    println!("imports: {imports:?}");
    println!("exports: {exports:?}");
    assert!(!imports.is_empty());
    for import in &imports {
        assert!(
            ALLOWED_BUS_IMPORTS.contains(&import.as_str()),
            "import {import} is outside elastos:bus@v1"
        );
        assert!(!import.to_ascii_lowercase().contains("wasi"));
    }
    assert_eq!(exports, vec!["elastos:bus/lifecycle@1.0.0".to_string()]);
}

#[test]
fn component_passes_the_runtime_admission_import_check() {
    let bytes = std::fs::read(component_path()).unwrap();
    admission::validate_component_imports(&bytes).expect("Runtime would admit these imports");
}

#[test]
fn the_copied_admission_check_refuses_a_core_module() {
    // A plain core module (version 1, no component layer) is not admissible.
    let err = admission::validate_component_imports(b"\0asm\x01\0\0\0").unwrap_err();
    assert!(err.contains("must be a WebAssembly component"), "{err}");
}

// --- fuel measurement (the shared runner) --------------------------------------------

mod measure {
    use super::Bridge;
    pub use capsule_v1_host_test::measure::RUNTIME_FUEL;

    /// Runs the built component once with `fuel`. Returns the outcome and the
    /// fuel used.
    pub fn run(bridge: Bridge, fuel: u64) -> (Result<(), String>, u64) {
        capsule_v1_host_test::measure::run(bridge, &super::component_path(), "archive-viewer", fuel)
    }
}

/// F36: one archive per hostile class at its caps, at the Runtime's fixed
/// 100,000,000 fuel, uses at most 80%. A run that spends the whole budget is
/// recorded as 100% and fails the gate: the cap, not the trap, is the rule.
#[test]
fn worst_archives_stay_under_80_percent_of_the_runtime_fuel() {
    let mut highest = (0.0f64, "no archive");
    for (name, bridge) in worst_archives() {
        let (outcome, used) = measure::run(bridge, measure::RUNTIME_FUEL);
        if let Err(err) = &outcome {
            // Out of fuel is a budget failure at 100%; any other stop is a
            // broken fixture, not a measurement.
            assert!(err.contains("OutOfFuel"), "{name}: {err}");
        }
        let percent = used as f64 * 100.0 / measure::RUNTIME_FUEL as f64;
        println!("{name}: {used} fuel ({percent:.1}% of the Runtime budget)");
        if percent > highest.0 {
            highest = (percent, name);
        }
    }
    assert!(
        highest.0 <= 80.0,
        "{} uses {:.1}% of the fuel",
        highest.1,
        highest.0
    );
}
