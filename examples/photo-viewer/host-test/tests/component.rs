//! Runs the built `photo-viewer.component.wasm` in `ComponentProvider`, the
//! Runtime's own Component runner (`elastos-compute/src/providers/component.rs`),
//! with a fake Runtime bridge behind the Bus hostcall. The bridge, the run,
//! the admission check and the fuel runner are the capsule kit's
//! (`examples/capsule-kit/v1-host-test`), shared with the documents viewer.
//!
//! Build the component first: `../build.sh`.

use std::path::{Path, PathBuf};

use capsule_v1_host_test::{admission, Bridge, ALLOWED_BUS_IMPORTS};
use elastos_common::CapsuleManifest;
use serde_json::{json, Value};

const ALBUM: &str = "localhost://Users/self/.AppData/App/photo-viewer/album.json";
const PLAYLIST: &str = "localhost://Users/self/.AppData/App/photo-viewer/playlist.json";
const A: &str = "localhost://Users/self/Pictures/a.png";
const B: &str = "localhost://Users/self/Pictures/b.jpg";
const C: &str = "localhost://Users/self/Pictures/c.webp";
const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ALBUM_BYTES: usize = 16 * 1024;
const MAX_ALBUM_ITEMS: usize = 64;
const MAX_JPEG_SEGMENTS: usize = 32;
const HEADER_BYTES: usize = 32;
/// Between the old `json!` write (64.9% of the Runtime budget) and the
/// straight writer (59.1%) for the worst album.
const CHEAPER_WRITE_GATE: u64 = 62_000_000;

fn capsule_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn component_path() -> PathBuf {
    let path = capsule_dir().join("photo-viewer.component.wasm");
    assert!(
        path.is_file(),
        "{} is missing; run examples/photo-viewer/build.sh first",
        path.display()
    );
    path
}

fn manifest() -> CapsuleManifest {
    let text = std::fs::read_to_string(capsule_dir().join("capsule.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

// --- the shared harness (examples/capsule-kit/v1-host-test) ---------------------

fn bridge_with<S: AsRef<str>>(objects: &[(S, Vec<u8>)]) -> Bridge {
    Bridge::with_list(ALBUM, "elastos.photo-viewer.album/v1", PLAYLIST, objects)
}

/// Loads and starts the component once. Returns the Runtime's result and the
/// bridge after the run.
async fn run(bridge: Bridge) -> (Result<(), String>, Bridge) {
    let _ = component_path();
    capsule_v1_host_test::run(&capsule_dir(), manifest(), bridge).await
}

// --- fixtures ----------------------------------------------------------------------

fn png(width: u32, height: u32, total: usize) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR".to_vec();
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]);
    bytes.resize(total.max(bytes.len()), 0x5a);
    bytes
}

fn jpeg(width: u16, height: u16) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08];
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1, 0xff, 0xd9]);
    bytes
}

/// A JPEG whose frame header follows APPn segments of these payload sizes.
fn jpeg_after(segments: &[usize], width: u16, height: u16) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xd8];
    for (index, size) in segments.iter().enumerate() {
        bytes.extend_from_slice(&[0xff, 0xe1 + (index % 14) as u8]);
        bytes.extend_from_slice(&((size + 2) as u16).to_be_bytes());
        bytes.extend(std::iter::repeat_n(0x45u8, *size));
    }
    bytes.extend_from_slice(&jpeg(width, height)[2..]);
    bytes
}

fn webp_vp8l(width: u32, height: u32) -> Vec<u8> {
    let bits = (width - 1) | (height - 1) << 14;
    let mut bytes = b"RIFF\x11\x00\x00\x00WEBPVP8L\x05\x00\x00\x00\x2f".to_vec();
    bytes.extend_from_slice(&bits.to_le_bytes());
    bytes
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

#[test]
fn manifest_is_a_valid_component_capsule_with_narrow_storage_bounds() {
    let manifest = manifest();
    manifest.validate().expect("manifest validates");
    assert!(manifest.is_component_capsule());
    assert_eq!(manifest.entrypoint, "photo-viewer.component.wasm");
    assert_eq!(
        manifest.resource_authority_bounds(),
        vec![
            "localhost://Users/self/.AppData/App/photo-viewer/*".to_string(),
            "localhost://Users/self/Pictures/*".to_string(),
        ]
    );
}

// --- runs in the Runtime's ComponentProvider ------------------------------------------

fn playlist(bridge: &Bridge) -> Value {
    serde_json::from_str(&bridge.written[PLAYLIST]).expect("playlist written")
}

fn denied(err: &str) -> bool {
    err.contains("Component capsule denied: BusError::Denied(")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn album_plays_and_the_playlist_is_written() {
    let objects = [
        (A, png(640, 480, 2048)),
        (B, jpeg(1920, 1080)),
        (C, webp_vp8l(300, 200)),
    ];
    let (result, bridge) = run(bridge_with(&objects)).await;
    result.expect("component run succeeds");
    let playlist = playlist(&bridge);
    println!("playlist: {playlist}");
    let items: Vec<_> = playlist["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["uri"].as_str().unwrap(),
                item["mime"].as_str().unwrap(),
                item["width"].as_u64().unwrap(),
                item["height"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        items,
        vec![
            (A, "image/png", 640, 480),
            (B, "image/jpeg", 1920, 1080),
            (C, "image/webp", 300, 200),
        ]
    );
    assert_eq!(playlist["skipped"], json!([]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_photo_sized_jpeg_plays_from_its_headers() {
    // 12 MiB, frame header after 64 KiB of EXIF and a 40 KiB ICC profile.
    let mut bytes = jpeg_after(&[65_000, 40_000], 6000, 4000);
    bytes.resize(12 * 1024 * 1024, 0x11);
    let (result, bridge) = run(bridge_with(&[(B, bytes)])).await;
    result.expect("component run succeeds");
    let item = &playlist(&bridge)["items"][0];
    assert_eq!(
        (item["width"].clone(), item["height"].clone()),
        (json!(6000), json!(4000))
    );
    println!("bytes served for a 12 MiB JPEG: {}", bridge.bytes_served[B]);
    assert!(bridge.bytes_served[B] < 100);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_failures_are_skipped_and_listed_through_the_runtime() {
    let objects = [
        ("localhost://Users/self/Pictures/ok.png", png(10, 10, 64)),
        (
            "localhost://Users/self/Pictures/note.png",
            b"GIF89a....".to_vec(),
        ),
        (
            "localhost://Users/self/Pictures/cut.png",
            b"\x89PNG\r\n\x1a\n\x00\x00".to_vec(),
        ),
        (
            "localhost://Users/self/Pictures/huge.png",
            png(10, 10, MAX_OBJECT_BYTES + 1),
        ),
        (
            "localhost://Users/self/Pictures/wide.png",
            png(9000, 10, 64),
        ),
        ("localhost://Users/self/Pictures/zero.png", png(0, 10, 64)),
    ];
    let (result, bridge) = run(bridge_with(&objects)).await;
    result.expect("content failures do not stop the run");
    let playlist = playlist(&bridge);
    assert_eq!(playlist["items"].as_array().unwrap().len(), 1);
    assert_eq!(playlist["items"][0]["uri"], objects[0].0);
    let skipped: Vec<_> = playlist["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|skip| {
            (
                skip["order"].as_u64().unwrap(),
                skip["reason"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        skipped,
        vec![
            (1, "wrong_type"),
            (2, "truncated"),
            (3, "oversize"),
            (4, "dimensions"),
            (5, "malformed"),
        ]
    );
    assert_eq!(bridge.bytes_served[objects[3].0], HEADER_BYTES + 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_grant_stops_the_run_through_the_runtime() {
    let mut bridge = bridge_with(&[(A, png(1, 1, 64)), (B, jpeg(2, 2))]);
    bridge.deny(A, "read");
    let (result, bridge) = run(bridge).await;
    let err = result.unwrap_err();
    assert!(denied(&err) && err.contains(A), "{err}");
    assert_eq!(bridge.invokes_on(A), 0);
    assert_eq!(bridge.invokes_on(B), 0);
    assert!(bridge.written.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_error_stops_the_run_through_the_runtime() {
    let mut bridge = bridge_with(&[(A, png(1, 1, 64)), (B, jpeg(2, 2))]);
    bridge
        .provider_errors
        .insert(A.to_string(), "disk gone".to_string());
    let (result, bridge) = run(bridge).await;
    let err = result.unwrap_err();
    assert!(
        err.contains("Component capsule denied: BusError::Unavailable(")
            && err.contains("disk gone"),
        "{err}"
    );
    assert_eq!(bridge.invokes_on(B), 0);
    assert!(bridge.written.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_without_grant_is_denied_through_the_runtime() {
    let mut bridge = bridge_with(&[(A, png(1, 1, 64))]);
    bridge.deny(PLAYLIST, "write");
    let (result, bridge) = run(bridge).await;
    let err = result.unwrap_err();
    assert!(denied(&err) && err.contains(PLAYLIST), "{err}");
    assert_eq!(bridge.invokes_on(PLAYLIST), 0);
}

/// The two albums that cost the most fuel within the guest's own limits:
/// the album object near its 16 KiB cap with 64 items, each a JPEG whose
/// frame header sits after the most segments the guest walks.
fn worst_case_albums() -> Vec<(&'static str, Bridge)> {
    let name_len = MAX_ALBUM_BYTES / MAX_ALBUM_ITEMS - 64;
    let walked: Vec<(String, Vec<u8>)> = (0..MAX_ALBUM_ITEMS)
        .map(|index| {
            (
                format!(
                    "localhost://Users/self/Pictures/{index:02}{}.jpg",
                    "x".repeat(name_len)
                ),
                jpeg_after(&[0; MAX_JPEG_SEGMENTS - 2], 10, 10),
            )
        })
        .collect();
    let skipped: Vec<(String, Vec<u8>)> = walked
        .iter()
        .map(|(uri, _)| (uri.clone(), jpeg_after(&[0; MAX_JPEG_SEGMENTS], 10, 10)))
        .collect();
    vec![
        ("64 JPEGs, 31 segments each", bridge_with(&walked)),
        ("64 JPEGs past the segment limit", bridge_with(&skipped)),
    ]
}

#[test]
fn the_worst_case_album_object_is_near_its_cap() {
    for (name, bridge) in worst_case_albums() {
        let size = bridge.objects[ALBUM].len();
        assert!(
            size <= MAX_ALBUM_BYTES && size > MAX_ALBUM_BYTES * 3 / 4,
            "{name}: album is {size} bytes"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worst_case_albums_run_in_the_runtime_component_provider() {
    for (name, bridge) in worst_case_albums() {
        let (result, bridge) = run(bridge).await;
        result.unwrap_or_else(|err| panic!("{name}: {err}"));
        assert!(bridge.written.contains_key(PLAYLIST), "{name}");
    }
}

#[test]
fn worst_case_albums_stay_under_80_percent_of_the_runtime_fuel() {
    for (name, bridge) in worst_case_albums() {
        let (outcome, used) = measure::run(bridge, measure::RUNTIME_FUEL);
        outcome.unwrap_or_else(|err| panic!("{name}: {err}"));
        let percent = used as f64 * 100.0 / measure::RUNTIME_FUEL as f64;
        println!("{name}: {used} fuel ({percent:.1}% of the Runtime budget)");
        assert!(percent <= 80.0, "{name} uses {percent:.1}% of the fuel");
    }
}

/// The write is cheaper, and that is what the rule is for: `json!` builds a
/// `serde_json::Value` per byte and costs 64.9% of the Runtime budget for the
/// worst album; the straight writer costs 59.1%. The limit sits between the
/// two, so a return to the old serializer fails here even while the 80% gate
/// still passes.
#[test]
fn the_worst_case_album_is_written_without_a_value_per_byte() {
    for (name, bridge) in worst_case_albums() {
        let (outcome, used) = measure::run(bridge, measure::RUNTIME_FUEL);
        outcome.unwrap_or_else(|err| panic!("{name}: {err}"));
        println!("{name}: {used} fuel");
        assert!(
            used < CHEAPER_WRITE_GATE,
            "{name} uses {used} fuel; the json! writer used 64.9% of {}",
            measure::RUNTIME_FUEL
        );
    }
}

// --- fuel measurement (the shared runner) --------------------------------------------

mod measure {
    use super::Bridge;
    pub use capsule_v1_host_test::measure::RUNTIME_FUEL;

    /// Runs the built component once with `fuel`. Returns the outcome and the
    /// fuel used.
    pub fn run(bridge: Bridge, fuel: u64) -> (Result<(), String>, u64) {
        capsule_v1_host_test::measure::run(bridge, &super::component_path(), "photo-viewer", fuel)
    }
}

/// Named objects for one album.
type Objects = Vec<(String, Vec<u8>)>;

/// Measurement, not a gate: fuel per album shape. Run with
/// `cargo test --locked -- --ignored --nocapture fuel_probe`.
#[test]
#[ignore]
fn fuel_probe() {
    let shapes: Vec<(String, Objects)> = vec![
        ("1 PNG".into(), vec![(A.to_string(), png(10, 10, 64))]),
        (
            "1 PNG of 12 MiB".into(),
            vec![(A.to_string(), png(10, 10, 12 << 20))],
        ),
        (
            "1 JPEG, 31 segments".into(),
            vec![(B.to_string(), jpeg_after(&[0; 30], 10, 10))],
        ),
        (
            "64 PNGs".into(),
            (0..64)
                .map(|index| {
                    (
                        format!("localhost://Users/self/Pictures/{index}.png"),
                        png(10, 10, 64),
                    )
                })
                .collect(),
        ),
    ];
    for (name, objects) in shapes {
        let (outcome, used) = measure::run(bridge_with(&objects), u64::MAX / 2);
        println!(
            "fuel_probe {name}: {used} fuel ({:.1}% of the Runtime budget), {}",
            used as f64 * 100.0 / measure::RUNTIME_FUEL as f64,
            if outcome.is_ok() {
                "ok".to_string()
            } else {
                format!("{outcome:?}")
            }
        );
    }
}
