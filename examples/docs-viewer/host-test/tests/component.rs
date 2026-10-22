//! Runs the built `docs-viewer.component.wasm` in `ComponentProvider`, the
//! Runtime's own Component runner (`elastos-compute/src/providers/component.rs`),
//! with a fake Runtime bridge behind the Bus hostcall.
//!
//! Build the component first: `../build.sh`.
//!
//! The bridge, the run, the admission check and the fuel runner are the
//! capsule kit's (`examples/capsule-kit/v1-host-test`), shared with the photo
//! viewer.

use std::path::{Path, PathBuf};

use capsule_v1_host_test::{admission, Bridge, ALLOWED_BUS_IMPORTS};
use elastos_common::CapsuleManifest;
use serde_json::{json, Value};

const SHELF: &str = "localhost://Users/self/.AppData/App/docs-viewer/shelf.json";
const PAGES: &str = "localhost://Users/self/.AppData/App/docs-viewer/pages.json";
const A: &str = "localhost://Users/self/Documents/notes.md";
const B: &str = "localhost://Users/self/Documents/todo.txt";
const MAX_DOCUMENT_BYTES: usize = 16 * 1024;
const MAX_SHELF_BYTES: usize = 4 * 1024;
const MAX_SHELF_ITEMS: usize = 8;

fn capsule_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn component_path() -> PathBuf {
    let path = capsule_dir().join("docs-viewer.component.wasm");
    assert!(
        path.is_file(),
        "{} is missing; run examples/docs-viewer/build.sh first",
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
    Bridge::with_list(SHELF, "elastos.docs-viewer.shelf/v1", PAGES, objects)
}

/// Loads and starts the component once. Returns the Runtime's result and the
/// bridge after the run.
async fn run(bridge: Bridge) -> (Result<(), String>, Bridge) {
    let _ = component_path();
    capsule_v1_host_test::run(&capsule_dir(), manifest(), bridge).await
}

// --- fixtures ----------------------------------------------------------------------

/// `size` bytes of ordinary markdown: headings, paragraphs with some
/// emphasis and code, and lists.
fn markdown(size: usize) -> Vec<u8> {
    let unit =
        "## A section\n\nSome *words* here, a `name` there and **a few** more words to read.\n\
                It goes on for a line or two, as notes do.\n\n- one item\n- another item\n\n";
    repeat_to(unit, size)
}

/// `size` bytes of markdown with the most spans a block may hold, which
/// renders past what a shelf may show and is skipped.
fn worst_markdown(size: usize) -> Vec<u8> {
    repeat_to(&format!("{}\n\n", "`a` ".repeat(127)), size)
}

/// Markdown that renders to nearly all a shelf may show (64 KiB) from about
/// 4 KiB: nine paragraphs of 120 one-character code spans.
fn shown_to_the_cap() -> Vec<u8> {
    format!("{}\n\n", "`a` ".repeat(120)).repeat(9).into_bytes()
}

/// `size` bytes that are read in full and then skipped: too many spans.
fn too_long_markdown(size: usize) -> Vec<u8> {
    repeat_to(&format!("{}\n\n", "`a` ".repeat(300)), size)
}

/// `size` bytes of openers that never close.
fn never_closed(size: usize) -> Vec<u8> {
    repeat_to("[a](*b <c:", size)
}

fn repeat_to(unit: &str, size: usize) -> Vec<u8> {
    let mut bytes = unit.repeat(size / unit.len() + 1).into_bytes();
    bytes.truncate(size);
    bytes
}

fn doc(n: usize) -> String {
    format!("localhost://Users/self/Documents/{n}.md")
}

// --- manifest -----------------------------------------------------------------------

#[test]
fn manifest_is_a_valid_component_capsule_with_narrow_storage_bounds() {
    let manifest = manifest();
    manifest.validate().expect("manifest validates");
    assert!(manifest.is_component_capsule());
    assert_eq!(manifest.entrypoint, "docs-viewer.component.wasm");
    assert_eq!(
        manifest.resource_authority_bounds(),
        vec![
            "localhost://Users/self/.AppData/App/docs-viewer/*".to_string(),
            "localhost://Users/self/Documents/*".to_string(),
        ]
    );
}

// --- runs in the Runtime's ComponentProvider ------------------------------------------

fn pages(bridge: &Bridge) -> Value {
    serde_json::from_str(&bridge.written[PAGES]).expect("pages written")
}

fn denied(err: &str) -> bool {
    err.contains("Component capsule denied: BusError::Denied(")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shelf_is_shown_and_its_pages_are_written() {
    let objects = [
        (A, b"# Trip\n\n- tent\n- `stove`\n".to_vec()),
        (B, b"milk\nbread".to_vec()),
    ];
    let (result, bridge) = run(bridge_with(&objects)).await;
    result.unwrap();
    let pages = pages(&bridge);
    assert_eq!(pages["schema"], "elastos.docs-viewer.pages/v1");
    assert_eq!(pages["documents"][0]["title"], "Trip");
    assert_eq!(
        pages["documents"][0]["blocks"][1],
        json!({ "kind": "list", "ordered": false, "items": [
            [{ "style": "plain", "text": "tent" }],
            [{ "style": "code", "text": "stove" }],
        ] })
    );
    assert_eq!(pages["documents"][1]["mime"], "text/plain");
    assert_eq!(pages["skipped"], json!([]));
    // Each object through its own token, in order.
    let uris: Vec<&str> = bridge
        .lines
        .iter()
        .filter(|line| line["request"]["type"] == "request_capability")
        .map(|line| line["request"]["resource"].as_str().unwrap())
        .collect();
    assert_eq!(uris, [SHELF, A, B, PAGES]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_failures_are_skipped_and_listed_through_the_runtime() {
    let objects = [
        (
            "localhost://Users/self/Documents/a.pdf".to_string(),
            b"%PDF-1.7".to_vec(),
        ),
        (
            "localhost://Users/self/Documents/b.md".to_string(),
            b"\0\x01\x02".to_vec(),
        ),
        (
            "localhost://Users/self/Documents/c.md".to_string(),
            markdown(MAX_DOCUMENT_BYTES + 1),
        ),
        (A.to_string(), b"kept".to_vec()),
    ];
    let (result, bridge) = run(bridge_with(&objects)).await;
    result.unwrap();
    let pages = pages(&bridge);
    let reasons: Vec<&str> = pages["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|skip| skip["reason"].as_str().unwrap())
        .collect();
    assert_eq!(reasons, ["wrong_kind", "not_text", "oversize"]);
    assert_eq!(pages["documents"][0]["order"], 3);
    assert!(bridge.bytes_served["localhost://Users/self/Documents/c.md"] <= 512 + 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_grant_stops_the_run_through_the_runtime() {
    let mut bridge = bridge_with(&[(A, b"# a".to_vec()), (B, b"b".to_vec())]);
    bridge.deny(A, "read");
    let (result, bridge) = run(bridge).await;
    let err = result.unwrap_err();
    assert!(denied(&err), "{err}");
    assert!(err.contains(A), "{err}");
    assert_eq!(bridge.invokes_on(A), 0, "no read without a grant");
    assert_eq!(bridge.invokes_on(B), 0);
    assert!(bridge.written.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_error_stops_the_run_through_the_runtime() {
    let mut bridge = bridge_with(&[(A, b"# a".to_vec())]);
    bridge
        .provider_errors
        .insert(A.to_string(), "disk gone".to_string());
    let (result, bridge) = run(bridge).await;
    let err = result.unwrap_err();
    assert!(err.contains("disk gone"), "{err}");
    assert!(bridge.written.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_without_grant_is_denied_through_the_runtime() {
    let mut bridge = bridge_with(&[(A, b"# a".to_vec())]);
    bridge.deny(PAGES, "write");
    let (result, bridge) = run(bridge).await;
    let err = result.unwrap_err();
    assert!(denied(&err), "{err}");
    assert!(bridge.written.is_empty());
}

/// The shelves that cost the most fuel within the caps.
fn worst_case_shelves() -> Vec<(&'static str, Bridge)> {
    let shelf_of = |make: fn(usize) -> Vec<u8>| -> Bridge {
        let docs: Vec<(String, Vec<u8>)> = (0..MAX_SHELF_ITEMS)
            .map(|n| (doc(n), make(MAX_DOCUMENT_BYTES)))
            .collect();
        bridge_with(&docs)
    };
    // The shelf itself at its cap: the longest names that fit.
    let name = "n".repeat(
        (MAX_SHELF_BYTES - 60) / MAX_SHELF_ITEMS - "localhost://Users/self/Documents/".len() - 20,
    );
    let named: Vec<(String, Vec<u8>)> = (0..MAX_SHELF_ITEMS)
        .map(|n| {
            (
                format!("localhost://Users/self/Documents/{name}{n}.md"),
                worst_markdown(MAX_DOCUMENT_BYTES),
            )
        })
        .collect();
    vec![
        ("8 full documents", shelf_of(markdown)),
        (
            "8 full documents of the most spans",
            shelf_of(worst_markdown),
        ),
        (
            "8 full documents skipped after reading",
            shelf_of(too_long_markdown),
        ),
        (
            "8 full documents of openers that never close",
            shelf_of(never_closed),
        ),
        (
            "8 full documents of brackets that never close",
            shelf_of(|size| repeat_to("[", size)),
        ),
        ("the longest shelf of the most spans", bridge_with(&named)),
        ("shown to the cap, then read to the cap", {
            let mut docs = vec![(doc(0), shown_to_the_cap())];
            docs.extend(
                (1..MAX_SHELF_ITEMS).map(|n| (doc(n), too_long_markdown(MAX_DOCUMENT_BYTES))),
            );
            bridge_with(&docs)
        }),
    ]
}

#[test]
fn the_worst_case_shelf_object_is_near_its_cap() {
    let (_, bridge) = worst_case_shelves()
        .into_iter()
        .find(|(name, _)| *name == "the longest shelf of the most spans")
        .unwrap();
    let size = bridge.objects[SHELF].len();
    println!("worst shelf object: {size} bytes");
    assert!(size <= MAX_SHELF_BYTES, "{size}");
    assert!(size > MAX_SHELF_BYTES * 3 / 4, "{size}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worst_case_shelves_run_in_the_runtime_component_provider() {
    for (name, bridge) in worst_case_shelves() {
        let (result, bridge) = run(bridge).await;
        result.unwrap_or_else(|err| panic!("{name}: {err}"));
        // Written whole, each byte as a number of up to four characters: far
        // under the 1 MiB bridge frame (`resource_bridge.rs:32`).
        let size = bridge.written[PAGES].len();
        println!("{name}: {size} bytes of pages");
        assert!(size <= 96 * 1024, "{name}: {size}");
    }
}

#[test]
fn worst_case_shelves_stay_under_80_percent_of_the_runtime_fuel() {
    for (name, bridge) in worst_case_shelves() {
        let (outcome, used) = measure::run(bridge, measure::RUNTIME_FUEL);
        outcome.unwrap_or_else(|err| panic!("{name}: {err}"));
        let percent = used as f64 * 100.0 / measure::RUNTIME_FUEL as f64;
        println!("{name}: {used} fuel ({percent:.1}% of the Runtime budget)");
        assert!(percent <= 80.0, "{name} uses {percent:.1}% of the fuel");
    }
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
        capsule_v1_host_test::measure::run(bridge, &super::component_path(), "docs-viewer", fuel)
    }
}

/// Named objects for one shelf.
type Objects = Vec<(String, Vec<u8>)>;

/// Measurement, not a gate: fuel per shelf shape. Run with
/// `cargo test --locked -- --ignored --nocapture fuel_probe`.
#[test]
#[ignore]
fn fuel_probe() {
    let shapes: Vec<(String, Objects)> = vec![
        ("1 small".into(), vec![(A.to_string(), markdown(100))]),
        (
            "1 of 16 KiB".into(),
            vec![(A.to_string(), markdown(16 << 10))],
        ),
        (
            "1 of 16 KiB, most spans".into(),
            vec![(A.to_string(), worst_markdown(16 << 10))],
        ),
        (
            "2 of 16 KiB, most spans".into(),
            (0..2).map(|n| (doc(n), worst_markdown(16 << 10))).collect(),
        ),
        (
            "8 of 16 KiB, most spans".into(),
            (0..8).map(|n| (doc(n), worst_markdown(16 << 10))).collect(),
        ),
        (
            "8 small".into(),
            (0..8).map(|n| (doc(n), markdown(100))).collect(),
        ),
        (
            "3 of 16 KiB, most spans".into(),
            (0..3).map(|n| (doc(n), worst_markdown(16 << 10))).collect(),
        ),
        (
            "1 of 16 KiB, unclosed emphasis".into(),
            vec![(
                A.to_string(),
                "*a ".repeat(6000).into_bytes()[..16 << 10].to_vec(),
            )],
        ),
        (
            "1 of 16 KiB, never closed".into(),
            vec![(A.to_string(), never_closed(16 << 10))],
        ),
        (
            "1 of 16 KiB, backtick runs".into(),
            vec![(
                A.to_string(),
                "`a ``b ".repeat(3000).into_bytes()[..16 << 10].to_vec(),
            )],
        ),
        (
            "1 of 16 KiB, plain words".into(),
            vec![(
                A.to_string(),
                "word ".repeat(4000).into_bytes()[..16 << 10].to_vec(),
            )],
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
