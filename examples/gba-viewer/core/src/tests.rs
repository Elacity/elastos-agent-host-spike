//! Rows for the GBA core. Every row drives the core's real entry: `run` for
//! the record's rules and `entry` for the error the Runtime receives.
//!
//! The harness below is the photo core's launch harness: the Runtime's answer
//! to launch names, around the kit's fake bus. It answers reads of
//! `elastos://launch/content/` with the Runtime's listing, one file read under
//! the launch's one grant, and writes under `elastos://launch/output/`.
//! Tests write nothing to disk.

use std::collections::BTreeMap;

use capsule_kit_guest::fake::FakeBus;
use capsule_kit_guest::InvokeReply;
use serde_json::{json, Value};

use crate::*;

/// A ROM of exactly the cap and one of the cap plus a byte, each built for
/// the row that uses it.
fn zeros(size: u64) -> Vec<u8> {
    vec![0u8; size as usize]
}

/// A small fixed ROM: every byte value once. Its sha256 is a literal below,
/// computed independently of this crate.
fn small_rom() -> Vec<u8> {
    (0..=255u8).collect()
}

const SMALL_ROM_SHA256: &str = "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880";

/// The Runtime's answers to launch names, around the kit's fake bus, which
/// answers every other name as the person's storage. `content` is the game set
/// the run was launched with, by path, or none; `refuse` replaces the answer
/// to every launch request with that failure.
struct Launch<'a> {
    storage: &'a mut FakeBus,
    content: Option<BTreeMap<String, Vec<u8>>>,
    refuse: Option<BusFailure>,
    output: BTreeMap<String, Vec<u8>>,
    asked: Vec<(String, String)>,
    read: Vec<String>,
}

impl<'a> Launch<'a> {
    fn of(storage: &'a mut FakeBus, content: Option<&[(&str, Vec<u8>)]>) -> Self {
        let content = content.map(|files| {
            let file = |(path, bytes): &(&str, Vec<u8>)| (path.to_string(), bytes.clone());
            files.iter().map(file).collect()
        });
        Launch {
            storage,
            content,
            refuse: None,
            output: BTreeMap::new(),
            asked: Vec::new(),
            read: Vec::new(),
        }
    }

    fn listing(content: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
        let file = |(path, bytes): (&String, &Vec<u8>)| json!({"path": path, "size": bytes.len()});
        let files: Vec<Value> = content.iter().map(file).collect();
        json!({"schema": LISTING_SCHEMA, "files": files})
            .to_string()
            .into_bytes()
    }
}

fn launch_reply(result: Value) -> InvokeReply {
    InvokeReply {
        status: result["status"].as_str().unwrap_or("ok").to_string(),
        body: serde_json::to_vec(&result).unwrap(),
    }
}

impl Bus for Launch<'_> {
    fn request(
        &mut self,
        resource: &str,
        action: &str,
        reason: &str,
    ) -> Result<String, BusFailure> {
        if !resource.starts_with("elastos://launch/") {
            return self.storage.request(resource, action, reason);
        }
        self.asked.push((resource.to_string(), action.to_string()));
        if let Some(failure) = &self.refuse {
            return Err(failure.clone());
        }
        match (self.content.is_some(), resource, action) {
            (true, LAUNCH_CONTENT_PATTERN, "read") => Ok("launch-content".to_string()),
            (true, LAUNCH_OUTPUT_PATTERN, "write") => Ok("launch-output".to_string()),
            _ => Err(BusFailure::NotFound(
                "no content launch binds this name".to_string(),
            )),
        }
    }

    fn invoke(
        &mut self,
        resource: &str,
        operation: &str,
        body: &[u8],
        grant: &str,
    ) -> Result<InvokeReply, BusFailure> {
        if !resource.starts_with("elastos://launch/") {
            return self.storage.invoke(resource, operation, body, grant);
        }
        let body: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(
            body["path"], resource,
            "a launch name travels as its own path"
        );
        let not_found = || BusFailure::NotFound("no content launch binds this name".to_string());
        let content = self.content.as_ref().ok_or_else(not_found)?;
        match (operation, grant) {
            ("read", "launch-content") if resource.starts_with(LAUNCH_CONTENT) => {
                self.read.push(resource.to_string());
                let bytes = match &resource[LAUNCH_CONTENT.len()..] {
                    "" => Self::listing(content),
                    path => content.get(path).cloned().ok_or_else(not_found)?,
                };
                let start = body["offset"].as_u64().unwrap_or(0) as usize;
                let length = body["length"].as_u64().unwrap() as usize;
                let window = bytes.get(start..).unwrap_or_default();
                let window = &window[..length.min(window.len())];
                Ok(launch_reply(
                    json!({"status": "ok", "data": {"content": window, "size": window.len()}}),
                ))
            }
            ("write", "launch-output") if resource.starts_with("elastos://launch/output/") => {
                let bytes: Vec<u8> = serde_json::from_value(body["content"].clone()).unwrap();
                self.output.insert(resource.to_string(), bytes);
                Ok(launch_reply(json!({"status": "ok", "data": {"size": 0}})))
            }
            _ => Err(BusFailure::Denied(
                "Capability validation failed".to_string(),
            )),
        }
    }
}

fn run_launch<'a>(
    storage: &'a mut FakeBus,
    files: &[(&str, Vec<u8>)],
) -> (Launch<'a>, Result<String, CoreError>) {
    let mut launch = Launch::of(storage, Some(files));
    let result = crate::run(&mut launch);
    (launch, result)
}

/// c1: a ROM of exactly 67,108,864 bytes is accepted, and a small fixed ROM's
/// record names its path, size and independently computed sha256. The cap row
/// compares size; the small row compares the literal hash.
#[test]
fn c1_a_rom_at_the_cap_is_accepted_and_the_record_names_path_size_and_sha256() {
    let mut storage = FakeBus::default();
    let cap = zeros(MAX_ROM_BYTES);
    let (launch, result) = run_launch(&mut storage, &[("ucity.gba", cap)]);
    let text = result.expect("a ROM of exactly the cap is accepted");
    let record: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(record["path"], "ucity.gba");
    assert_eq!(record["size"], 67_108_864u64);
    assert_eq!(
        record["sha256"].as_str().unwrap().len(),
        64,
        "a sha256 is lowercase hex of 64 characters"
    );
    assert!(record["sha256"]
        .as_str()
        .unwrap()
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!(launch.output[LAUNCH_RECORD_URI], text.as_bytes());
    assert_eq!(
        launch.asked,
        [
            (LAUNCH_CONTENT_PATTERN.to_string(), "read".to_string()),
            (LAUNCH_OUTPUT_PATTERN.to_string(), "write".to_string()),
        ]
    );
    drop(launch);
    assert!(storage.calls.is_empty());

    let mut storage = FakeBus::default();
    let (launch, result) = run_launch(&mut storage, &[("ucity.gba", small_rom())]);
    let text = result.expect("the small ROM is accepted");
    let record: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(record["path"], "ucity.gba");
    assert_eq!(record["size"], 256u64);
    assert_eq!(record["sha256"], SMALL_ROM_SHA256);
    drop(launch);
    assert!(storage.calls.is_empty());
}

/// c2: one byte over the cap is refused by name, before the ROM is read, and
/// nothing is written.
#[test]
fn c2_a_rom_one_byte_over_the_cap_is_refused_by_name() {
    let mut storage = FakeBus::default();
    let (launch, result) = run_launch(&mut storage, &[("ucity.gba", zeros(MAX_ROM_BYTES + 1))]);
    let error = result.expect_err("an over-cap ROM is refused");
    assert_eq!(error.to_string(), "gba_core_rom_too_large: 67108865");
    assert_eq!(launch.read, [LAUNCH_CONTENT], "only the listing was read");
    assert!(launch.output.is_empty());
    drop(launch);
    assert!(storage.calls.is_empty());
}

/// c3: a set with no `.gba` file and a `.gba` file of zero bytes are refused
/// by name, and nothing is written.
#[test]
fn c3_a_missing_or_empty_rom_is_refused_by_name() {
    let mut storage = FakeBus::default();
    let (launch, result) = run_launch(&mut storage, &[("capsule.json", b"{}".to_vec())]);
    let error = result.expect_err("a set with no ROM is refused");
    assert_eq!(error.to_string(), "gba_core_rom_missing");
    assert_eq!(launch.read, [LAUNCH_CONTENT]);
    assert!(launch.output.is_empty());
    drop(launch);
    assert!(storage.calls.is_empty());

    let mut storage = FakeBus::default();
    let (launch, result) = run_launch(&mut storage, &[("ucity.gba", Vec::new())]);
    let error = result.expect_err("an empty ROM is refused");
    assert_eq!(error.to_string(), "gba_core_rom_empty: ucity.gba");
    assert!(launch.read.iter().all(|name| name == LAUNCH_CONTENT));
    assert!(launch.output.is_empty());
    drop(launch);
    assert!(storage.calls.is_empty());
}

/// c4: the record has exactly the keys `path`, `size` and `sha256`.
#[test]
fn c4_the_record_has_exactly_path_size_and_sha256() {
    let mut storage = FakeBus::default();
    let (launch, result) = run_launch(&mut storage, &[("ucity.gba", small_rom())]);
    let text = result.expect("the small ROM is accepted");
    let record: Value = serde_json::from_str(&text).unwrap();
    let keys: Vec<&str> = record
        .as_object()
        .expect("the record is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["path", "sha256", "size"]);
    assert_eq!(keys.len(), 3);
    assert_eq!(launch.output[LAUNCH_RECORD_URI], text.as_bytes());
}

/// c5: a core error fails the open. The entry returns the error and nothing is
/// written to the launch's output.
#[test]
fn c5_a_core_error_fails_the_open_and_writes_nothing() {
    let mut storage = FakeBus::default();
    let mut launch = Launch::of(
        &mut storage,
        Some(&[("ucity.gba", zeros(MAX_ROM_BYTES + 1))]),
    );
    let error = crate::entry(&mut launch).expect_err("the entry returns the error");
    assert_eq!(
        error,
        BusFailure::Invalid("gba_core_rom_too_large: 67108865".to_string())
    );
    assert!(launch.output.is_empty(), "nothing is written to the output");
    drop(launch);
    assert!(storage.calls.is_empty());
}
