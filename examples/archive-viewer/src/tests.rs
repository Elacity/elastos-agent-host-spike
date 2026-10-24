use serde_json::{json, Value};

use capsule_kit_guest::fake::{Call, FakeBus};

use crate::*;

const ARCHIVE: &str = "localhost://Users/self/Documents/trip.zip";

/// One entry of a fixture archive, as the builder writes it.
#[derive(Clone)]
struct Spec {
    /// The name in the central directory.
    name: Vec<u8>,
    /// The name in the local header, when it differs.
    local_name: Option<Vec<u8>>,
    flags: u16,
    method: u16,
    crc: u32,
    /// The compressed bytes, written after the local header.
    data: Vec<u8>,
    /// The declared uncompressed size (defaults to `data.len()`).
    uncompressed: Option<u32>,
    /// The declared compressed size (defaults to `data.len()`); the bytes
    /// written are still `data`.
    compressed: Option<u32>,
    /// The method in the local header, when it differs.
    local_method: Option<u16>,
    external: u32,
    /// Extra bytes in the local header (only its length matters to the checks).
    local_extra: Vec<u8>,
    dir_extra: Vec<u8>,
    dir_comment: Vec<u8>,
    /// Place the local header at this offset instead of one after the other.
    local_offset: Option<u32>,
}

impl Spec {
    fn file(name: &str) -> Self {
        Spec {
            name: name.as_bytes().to_vec(),
            local_name: None,
            flags: 0,
            method: 0,
            crc: 0,
            data: Vec::new(),
            uncompressed: None,
            compressed: None,
            local_method: None,
            external: 0,
            local_extra: Vec::new(),
            dir_extra: Vec::new(),
            dir_comment: Vec::new(),
            local_offset: None,
        }
    }

    fn data(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }
}

fn u16b(value: u16) -> [u8; 2] {
    value.to_le_bytes()
}

fn u32b(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// Builds a ZIP byte by byte, so a fixture can lie where a real tool refuses.
/// Local headers and data first, then the directory, then the end record.
fn build(specs: &[Spec], comment: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for spec in specs {
        let offset = spec.local_offset.unwrap_or(out.len() as u32);
        let name = spec.local_name.as_deref().unwrap_or(&spec.name);
        offsets.push(offset);
        let mut header = Vec::new();
        header.extend_from_slice(&u32b(0x0403_4b50));
        header.extend_from_slice(&u16b(20));
        header.extend_from_slice(&u16b(spec.flags));
        header.extend_from_slice(&u16b(spec.local_method.unwrap_or(spec.method)));
        header.extend_from_slice(&u16b(0));
        header.extend_from_slice(&u16b(0));
        header.extend_from_slice(&u32b(spec.crc));
        header.extend_from_slice(&u32b(spec.compressed.unwrap_or(spec.data.len() as u32)));
        header.extend_from_slice(&u32b(spec.uncompressed.unwrap_or(spec.data.len() as u32)));
        header.extend_from_slice(&u16b(name.len() as u16));
        header.extend_from_slice(&u16b(spec.local_extra.len() as u16));
        header.extend_from_slice(name);
        header.extend_from_slice(&spec.local_extra);
        header.extend_from_slice(&spec.data);
        write_at(&mut out, offset as usize, &header);
    }
    let directory_offset = out.len() as u32;
    for (spec, offset) in specs.iter().zip(&offsets) {
        let mut record = Vec::new();
        record.extend_from_slice(&u32b(0x0201_4b50));
        record.extend_from_slice(&u16b(20));
        record.extend_from_slice(&u16b(20));
        record.extend_from_slice(&u16b(spec.flags));
        record.extend_from_slice(&u16b(spec.method));
        record.extend_from_slice(&u16b(0));
        record.extend_from_slice(&u16b(0));
        record.extend_from_slice(&u32b(spec.crc));
        record.extend_from_slice(&u32b(spec.compressed.unwrap_or(spec.data.len() as u32)));
        record.extend_from_slice(&u32b(spec.uncompressed.unwrap_or(spec.data.len() as u32)));
        record.extend_from_slice(&u16b(spec.name.len() as u16));
        record.extend_from_slice(&u16b(spec.dir_extra.len() as u16));
        record.extend_from_slice(&u16b(spec.dir_comment.len() as u16));
        record.extend_from_slice(&u16b(0));
        record.extend_from_slice(&u16b(0));
        record.extend_from_slice(&u32b(spec.external));
        record.extend_from_slice(&u32b(*offset));
        record.extend_from_slice(&spec.name);
        record.extend_from_slice(&spec.dir_extra);
        record.extend_from_slice(&spec.dir_comment);
        out.extend_from_slice(&record);
    }
    let directory_size = out.len() as u32 - directory_offset;
    end_record(
        &mut out,
        specs.len() as u16,
        directory_offset,
        directory_size,
        comment,
    );
    out
}

/// Writes `bytes` at `offset`, extending or overwriting: fixtures need
/// records that share a region.
fn write_at(out: &mut Vec<u8>, offset: usize, bytes: &[u8]) {
    if out.len() < offset + bytes.len() {
        out.resize(offset + bytes.len(), 0);
    }
    out[offset..offset + bytes.len()].copy_from_slice(bytes);
}

fn end_record(out: &mut Vec<u8>, count: u16, offset: u32, size: u32, comment: &[u8]) {
    out.extend_from_slice(&u32b(0x0605_4b50));
    out.extend_from_slice(&u16b(0));
    out.extend_from_slice(&u16b(0));
    out.extend_from_slice(&u16b(count));
    out.extend_from_slice(&u16b(count));
    out.extend_from_slice(&u32b(size));
    out.extend_from_slice(&u32b(offset));
    out.extend_from_slice(&u16b(comment.len() as u16));
    out.extend_from_slice(comment);
}

fn request(uri: &str, show: &[usize]) -> Vec<u8> {
    let mut value = json!({ "schema": REQUEST_SCHEMA, "uri": uri });
    if !show.is_empty() {
        value["show"] = json!(show);
    }
    serde_json::to_vec(&value).unwrap()
}

/// A fake Runtime with the request, the archive, every read allowed and the
/// view write allowed.
fn bus_with(request_bytes: Vec<u8>, archive: &str, archive_bytes: Vec<u8>) -> FakeBus {
    FakeBus::default()
        .object(REQUEST_URI, request_bytes)
        .allow(REQUEST_URI, "read")
        .object(archive, archive_bytes)
        .allow(archive, "read")
        .allow(VIEW_URI, "write")
}

fn run_fixture(request_bytes: Vec<u8>, archive: &str, archive_bytes: Vec<u8>) -> FakeBus {
    let mut bus = bus_with(request_bytes, archive, archive_bytes);
    run(&mut bus).expect("a content refusal still writes the view");
    bus
}

fn view(bus: &FakeBus) -> Value {
    serde_json::from_str(bus.written.get(VIEW_URI).expect("the view was written")).unwrap()
}

fn entries(bus: &FakeBus) -> Vec<Value> {
    view(bus)["entries"].as_array().unwrap().clone()
}

fn status_of(bus: &FakeBus, index: usize) -> (String, Option<String>) {
    let entry = &entries(bus)[index];
    (
        entry["status"].as_str().unwrap().to_string(),
        entry["reason"].as_str().map(str::to_string),
    )
}

fn skipped(bus: &FakeBus) -> Vec<Value> {
    view(bus)["skipped"].as_array().unwrap().clone()
}

fn assert_nothing_written(bus: &FakeBus) {
    assert!(bus.written.is_empty(), "no view may be written");
    assert!(
        bus.invokes_on(VIEW_URI).is_empty(),
        "no write may be attempted"
    );
}

fn single(name: &str) -> FakeBus {
    run_fixture(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[Spec::file(name)], &[]),
    )
}

#[test]
fn a_plain_archive_lists_its_entries_in_directory_order() {
    let bus = run_fixture(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[Spec::file("a.txt"), Spec::file("b/c.txt")], &[]),
    );
    let view = view(&bus);
    assert_eq!(view["schema"], VIEW_SCHEMA);
    assert_eq!(view["archive"]["uri"], ARCHIVE);
    assert!(view.get("refused").is_none(), "the archive is not refused");
    let entries = entries(&bus);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["path"], "a.txt");
    assert_eq!(entries[0]["status"], "listed");
    assert_eq!(entries[0]["kind"], "file");
    assert_eq!(entries[1]["path"], "b/c.txt");
}

#[test]
fn the_request_names_the_archive_and_the_view_is_written_once() {
    let bus = run_fixture(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[Spec::file("a.txt")], &[]),
    );
    assert_eq!(bus.written.len(), 1, "exactly one object is written");
    assert!(bus.written.contains_key(VIEW_URI));
    let calls: Vec<&Call> = bus
        .calls
        .iter()
        .filter(|call| matches!(call, Call::Request { .. }))
        .collect();
    assert_eq!(calls.len(), 3, "request read, archive read, view write");
}

#[test]
fn a_request_without_a_read_grant_stops_before_any_read() {
    let mut bus = FakeBus::default()
        .object(ARCHIVE, build(&[Spec::file("a.txt")], &[]))
        .allow(ARCHIVE, "read")
        .allow(VIEW_URI, "write");
    let err = run(&mut bus).expect_err("no request grant stops the run");
    assert!(matches!(err, Refusal::NoGrant { .. }), "{err:?}");
    assert_nothing_written(&bus);
    assert!(bus.invokes_on(ARCHIVE).is_empty());
}

#[test]
fn an_archive_without_a_read_grant_stops_before_any_view() {
    let mut bus = FakeBus::default()
        .object(REQUEST_URI, request(ARCHIVE, &[]))
        .allow(REQUEST_URI, "read")
        .object(ARCHIVE, build(&[Spec::file("a.txt")], &[]))
        .allow(VIEW_URI, "write");
    let err = run(&mut bus).expect_err("no archive grant stops the run");
    assert!(matches!(err, Refusal::NoGrant { .. }), "{err:?}");
    assert_nothing_written(&bus);
}

#[test]
fn a_provider_error_while_listing_stops_the_run_and_writes_nothing() {
    let mut bus = bus_with(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[Spec::file("a.txt")], &[]),
    );
    bus.provider_errors.insert(
        ARCHIVE.to_string(),
        ("read_failed".to_string(), "the object is gone".to_string()),
    );
    let err = run(&mut bus).expect_err("an authority failure stops the run");
    assert!(matches!(err, Refusal::Call { .. }), "{err:?}");
    assert_nothing_written(&bus);
}

#[test]
fn a_request_for_an_appdata_uri_is_refused() {
    let app_data = "localhost://Users/self/.AppData/App/other-app/secret.json";
    let mut bus = FakeBus::default()
        .object(REQUEST_URI, request(app_data, &[]))
        .allow(REQUEST_URI, "read")
        .allow(VIEW_URI, "write");
    bus = bus.object(app_data, build(&[Spec::file("a.txt")], &[]));
    bus = bus.allow(app_data, "read");
    let err = run(&mut bus).expect_err("an .AppData/ request is refused");
    assert!(matches!(err, Refusal::Input(_)), "{err:?}");
    assert_nothing_written(&bus);
    assert!(
        bus.invokes_on(app_data).is_empty(),
        "no archive byte is read"
    );
}

#[test]
fn a_request_with_unknown_fields_is_refused() {
    let mut value = serde_json::from_slice::<Value>(&request(ARCHIVE, &[])).unwrap();
    value["extra"] = json!(1);
    let mut bus = bus_with(
        serde_json::to_vec(&value).unwrap(),
        ARCHIVE,
        build(&[], &[]),
    );
    let err = run(&mut bus).expect_err("unknown fields are refused");
    assert!(matches!(err, Refusal::Input(_)), "{err:?}");
    assert_nothing_written(&bus);
}

// --- Names: P1 to P9 -------------------------------------------------------

fn listed(name: &str) -> (String, Option<String>) {
    status_of(&single(name), 0)
}

fn blocked(name: &str, reason: &str) {
    let (status, got) = listed(name);
    assert_eq!(status, "blocked", "{name:?}");
    assert_eq!(got.as_deref(), Some(reason), "{name:?}");
}

#[test]
fn absolute_names_are_blocked() {
    blocked("/etc/passwd", "absolute_name");
    blocked("/a.txt", "absolute_name");
    blocked("C:/a.txt", "absolute_name");
    blocked("c:a.txt", "absolute_name");
    blocked("\\\\server\\share\\a.txt", "backslash");
}

#[test]
fn dot_and_empty_segments_are_blocked() {
    blocked("../a.txt", "dot_segment");
    blocked("a/../b.txt", "dot_segment");
    blocked("./a.txt", "dot_segment");
    blocked("a//b.txt", "dot_segment");
    blocked("a//", "dot_segment");
    blocked(".", "dot_segment");
    // A trailing slash is a directory's, and that one is listed.
    let bus = single("a/");
    assert_eq!(status_of(&bus, 0), ("listed".to_string(), None));
    assert_eq!(entries(&bus)[0]["kind"], "directory");
}

#[test]
fn a_backslash_is_blocked() {
    blocked("a\\b.txt", "backslash");
    blocked("a\\\\b.txt", "backslash");
}

#[test]
fn control_and_bidi_characters_are_blocked() {
    let mut nul = Spec::file("a");
    nul.flags = 1 << 11;
    nul.name = b"a\0.txt".to_vec();
    assert_eq!(
        status_of(
            &run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[nul], &[])),
            0
        ),
        ("blocked".to_string(), Some("control_character".to_string()))
    );
    let mut bidi = Spec::file("a");
    bidi.flags = 1 << 11;
    bidi.name = "txt\u{202e}exe".as_bytes().to_vec();
    assert_eq!(
        status_of(
            &run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[bidi], &[])),
            0
        ),
        ("blocked".to_string(), Some("control_character".to_string()))
    );
    blocked("a\nb.txt", "not_ascii");
}

#[test]
fn names_are_utf8_when_marked_and_ascii_otherwise() {
    let mut marked = Spec::file("a");
    marked.flags = 1 << 11;
    marked.name = "caf\u{e9}.txt".as_bytes().to_vec();
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[marked], &[]));
    assert_eq!(status_of(&bus, 0), ("listed".to_string(), None));
    assert_eq!(entries(&bus)[0]["path"], "caf\u{e9}.txt");

    let mut bad_utf8 = Spec::file("a");
    bad_utf8.flags = 1 << 11;
    bad_utf8.name = b"caf\xe9.txt".to_vec();
    assert_eq!(
        status_of(
            &run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[bad_utf8], &[])),
            0
        ),
        ("blocked".to_string(), Some("not_utf8".to_string()))
    );

    let mut unmarked = Spec::file("a");
    unmarked.name = b"caf\xe9.txt".to_vec();
    assert_eq!(
        status_of(
            &run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[unmarked], &[])),
            0
        ),
        ("blocked".to_string(), Some("not_ascii".to_string()))
    );
}

#[test]
fn duplicate_names_are_both_blocked() {
    let bus = run_fixture(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[Spec::file("a.txt"), Spec::file("a.txt")], &[]),
    );
    assert_eq!(
        status_of(&bus, 0),
        ("blocked".to_string(), Some("duplicate".to_string()))
    );
    assert_eq!(
        status_of(&bus, 1),
        ("blocked".to_string(), Some("duplicate".to_string()))
    );
}

#[test]
fn names_that_differ_only_in_case_are_both_listed() {
    let bus = run_fixture(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[Spec::file("A.txt"), Spec::file("a.txt")], &[]),
    );
    assert_eq!(status_of(&bus, 0), ("listed".to_string(), None));
    assert_eq!(status_of(&bus, 1), ("listed".to_string(), None));
    assert_eq!(entries(&bus)[0]["path"], "A.txt");
    assert_eq!(entries(&bus)[1]["path"], "a.txt");
}

#[test]
fn a_file_and_a_directory_of_one_path_are_both_listed() {
    let bus = run_fixture(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[Spec::file("a").data(b"x"), Spec::file("a/")], &[]),
    );
    assert_eq!(status_of(&bus, 0), ("listed".to_string(), None));
    assert_eq!(status_of(&bus, 1), ("listed".to_string(), None));
    assert_eq!(entries(&bus)[0]["kind"], "file");
    assert_eq!(entries(&bus)[1]["kind"], "directory");
}

#[test]
fn a_name_over_its_cap_is_blocked() {
    let long = "a".repeat(256);
    blocked(&long, "name_too_long");
    let segments = ["d"; 33].join("/");
    blocked(&segments, "name_too_long");
    let fits = "a".repeat(255);
    let (status, _) = listed(&fits);
    assert_eq!(status, "listed");
}

#[test]
fn a_symlink_entry_is_blocked() {
    let mut symlink = Spec::file("link");
    symlink.external = 0o120777 << 16;
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[symlink], &[]));
    assert_eq!(
        status_of(&bus, 0),
        ("blocked".to_string(), Some("unsupported_kind".to_string()))
    );
    assert_eq!(entries(&bus)[0]["kind"], "other");
}

#[test]
fn a_nested_archive_is_listed_not_opened() {
    let inner = build(&[Spec::file("x.txt")], &[]);
    let spec = Spec::file("inner.zip").data(&inner);
    // A filler keeps the object larger than the 22 + 1,024-byte tail, so the
    // tail read cannot cover the nested archive either.
    let filler = Spec::file("filler.bin").data(&vec![0u8; 1000]);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[spec, filler], &[]));
    assert_eq!(status_of(&bus, 0), ("listed".to_string(), None));
    assert_eq!(entries(&bus)[0]["kind"], "archive");
    // Its bytes were never read: no window reaches its data, which starts
    // after the 30-byte local header and its 9-byte name.
    let data_start = 30 + 9;
    let data_end = data_start + inner.len();
    for call in bus.invokes_on(ARCHIVE) {
        if let Call::Invoke {
            operation, body, ..
        } = call
        {
            if operation == "read" {
                let offset = body["offset"].as_u64().unwrap();
                let length = body["length"].as_u64().unwrap();
                let end = offset + length;
                // The one-byte size probes may land anywhere; no other
                // read window reaches the entry's data.
                assert!(
                    length == 1 || end <= data_start as u64 || offset >= data_end as u64,
                    "a read reached the entry's data: {body}"
                );
            }
        }
    }
}

// --- Methods and encryption: F29, F30 --------------------------------------

#[test]
fn other_methods_are_listed_unsupported() {
    let mut spec = Spec::file("a.bin");
    spec.method = 12;
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[spec], &[]));
    assert_eq!(status_of(&bus, 0), ("unsupported".to_string(), None));
}

#[test]
fn encrypted_entries_are_listed_not_read() {
    let mut spec = Spec::file("a.txt").data(b"secret");
    spec.flags = 1;
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[spec], &[]));
    assert_eq!(status_of(&bus, 0), ("encrypted".to_string(), None));
    assert!(skipped(&bus).is_empty());
}

#[test]
fn a_stored_entry_lists_with_its_declared_sizes() {
    let spec = Spec::file("a.txt").data(b"hello");
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[spec], &[]));
    let entry = &entries(&bus)[0];
    assert_eq!(entry["compressed_size"], 5);
    assert_eq!(entry["uncompressed_size"], 5);
    assert_eq!(entry["method"], 0);
}

// --- The end record and the directory: L1 to L4 ----------------------------

fn eocd_start(bytes: &[u8]) -> usize {
    let comment = u16::from_le_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
    bytes.len() - 22 - usize::from(comment)
}

fn patch_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn refused(bus: &FakeBus) -> (String, String) {
    let view = view(bus);
    assert!(
        view["entries"].as_array().unwrap().is_empty(),
        "a refused archive lists no entry"
    );
    let refused = view.get("refused").expect("a refused archive says why");
    (
        refused["code"].as_str().unwrap().to_string(),
        refused["message"].as_str().unwrap().to_string(),
    )
}

#[test]
fn an_empty_archive_lists_no_entries() {
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[], &[]));
    assert_eq!(entries(&bus).len(), 0);
    assert!(view(&bus).get("refused").is_none());
}

#[test]
fn an_archive_without_an_end_record_is_refused() {
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    archive.truncate(archive.len() - 22);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    let (code, _) = refused(&bus);
    assert_eq!(code, "end_record_missing");
}

#[test]
fn a_comment_over_1_kib_refuses_the_archive_without_reading_it() {
    let comment = vec![b'c'; 2000];
    let bus = run_fixture(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[Spec::file("a.txt")], &comment),
    );
    let (code, message) = refused(&bus);
    assert_eq!(code, "end_record_missing");
    assert!(message.contains("comment"), "{message}");
    // The comment was never read: the tail and the size probes only.
    let read = bus.bytes_served(ARCHIVE);
    assert!(
        read <= 22 + MAX_COMMENT_BYTES + 40,
        "read {read} bytes of a {}-byte comment",
        comment.len()
    );
}

#[test]
fn two_end_records_refuse_the_archive() {
    let mut inner = Vec::new();
    end_record(&mut inner, 1, 0, 0, &[]);
    let bus = run_fixture(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[Spec::file("a.txt")], &inner),
    );
    let (code, message) = refused(&bus);
    assert_eq!(code, "ambiguous_end");
    assert!(message.contains('2'), "{message}");
}

#[test]
fn a_directory_that_does_not_end_at_the_end_record_refuses_the_archive() {
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    let at = eocd_start(&archive);
    archive.insert(at, 0);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    assert_eq!(refused(&bus).0, "directory_not_at_end_record");
}

#[test]
fn a_count_that_differs_from_the_records_refuses_the_archive() {
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    let at = eocd_start(&archive);
    patch_u16(&mut archive, at + 8, 2);
    patch_u16(&mut archive, at + 10, 2);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    assert_eq!(refused(&bus).0, "count_mismatch");
}

#[test]
fn a_record_that_runs_past_the_directory_refuses_the_archive() {
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    let at = eocd_start(&archive);
    let directory = u32::from_le_bytes([
        archive[at + 16],
        archive[at + 17],
        archive[at + 18],
        archive[at + 19],
    ]) as usize;
    patch_u16(&mut archive, directory + 28, 0xffff);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    assert_eq!(refused(&bus).0, "record_too_long");
}

#[test]
fn too_many_entries_refuse_the_archive() {
    let specs: Vec<Spec> = (0..=MAX_ENTRIES)
        .map(|index| Spec::file(&format!("e{index}.txt")))
        .collect();
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&specs, &[]));
    assert_eq!(refused(&bus).0, "too_many_entries");
}

// --- Records that share bytes: B4, F6, F6b, F6c ----------------------------

#[test]
fn entries_that_share_data_refuse_the_archive() {
    let mut first = Spec::file("a").data(&[1u8; 8]);
    first.local_offset = Some(0);
    let mut second = Spec::file("b").data(&[2u8; 8]);
    second.local_offset = Some(0);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[first, second], &[]));
    assert_eq!(refused(&bus).0, "overlapping_entries");
}

#[test]
fn entries_that_overlap_only_after_the_local_extra_field_refuse_the_archive() {
    let second = Spec::file("b.txt").data(b"BBBB");
    // The same directory record (declared 4 bytes) with no local extra: the
    // records are adjacent and the listing is accepted.
    let plain = build(&[Spec::file("a.txt").data(b"AAAA"), second.clone()], &[]);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, plain);
    assert!(view(&bus).get("refused").is_none());
    assert_eq!(entries(&bus).len(), 2);

    // Only the local extra grows, and no bytes of data follow it: the first
    // record now covers the second entry's local header.
    let mut grown = Spec::file("a.txt").data(&[]);
    grown.compressed = Some(4);
    grown.local_extra = vec![0u8; 64];
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[grown, second], &[]));
    assert_eq!(refused(&bus).0, "overlapping_entries");
}

#[test]
fn entries_that_share_a_local_header_region_refuse_the_archive() {
    // Records (local_offset, data, end) of (0, 95, 103) and (35, 66, 74): the
    // second sits inside the first's extra field, and only the payloads are
    // disjoint.
    let mut first = Spec::file("a").data(&[1u8; 8]);
    first.local_offset = Some(0);
    first.local_extra = vec![0u8; 64];
    let mut second = Spec::file("b").data(&[2u8; 8]);
    second.local_offset = Some(35);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[first, second], &[]));
    assert_eq!(refused(&bus).0, "overlapping_entries");
}

// --- The local header before an entry is shown: L5, F24, F25 ---------------

#[test]
fn a_local_name_that_differs_skips_the_entry() {
    let mut spec = Spec::file("a.txt");
    spec.local_name = Some(b"b.txt".to_vec());
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[spec], &[]));
    assert_eq!(status_of(&bus, 0), ("listed".to_string(), None));
    let skipped = skipped(&bus);
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0]["index"], 0);
    assert_eq!(skipped[0]["reason"], "local_header_name");
}

#[test]
fn a_local_header_that_differs_skips_the_entry() {
    let mut spec = Spec::file("a.txt");
    spec.local_method = Some(8);
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[spec], &[]));
    assert_eq!(status_of(&bus, 0), ("listed".to_string(), None));
    assert_eq!(skipped(&bus)[0]["reason"], "local_header_method");
}

#[test]
fn a_consistent_local_header_is_shown() {
    let mut spec = Spec::file("a.txt").data(b"hello");
    spec.method = 0;
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[spec], &[]));
    assert!(skipped(&bus).is_empty());
    assert_eq!(entries(&bus)[0]["status"], "listed");
}

#[test]
fn a_requested_entry_that_is_blocked_is_not_shown() {
    let mut spec = Spec::file("a\\b.txt");
    spec.local_name = Some(b"a\\b.txt".to_vec());
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[spec], &[]));
    assert_eq!(skipped(&bus)[0]["reason"], "backslash");
}

#[test]
fn a_request_for_an_index_the_archive_lacks_is_skipped() {
    let bus = run_fixture(
        request(ARCHIVE, &[9]),
        ARCHIVE,
        build(&[Spec::file("a.txt")], &[]),
    );
    assert_eq!(skipped(&bus)[0]["reason"], "no_such_entry");
}

// --- A directory with bytes: L9, F40 ---------------------------------------

#[test]
fn a_nonempty_directory_is_blocked_and_the_valid_entry_still_lists() {
    let directory = Spec::file("dir/").data(b"data!");
    let file = Spec::file("a.txt").data(b"hello");
    let bus = run_fixture(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[directory, file], &[]),
    );
    assert_eq!(
        status_of(&bus, 0),
        (
            "blocked".to_string(),
            Some("directory_with_data".to_string())
        )
    );
    assert_eq!(entries(&bus)[0]["kind"], "directory");
    assert_eq!(status_of(&bus, 1), ("listed".to_string(), None));
    assert!(view(&bus).get("refused").is_none());
}

// --- The read budget: F31 --------------------------------------------------

#[test]
fn every_read_counts_toward_the_budget() {
    let archive = build(&[Spec::file("a.txt").data(b"hello")], &[]);
    let mut bus = FakeBus::default()
        .object(ARCHIVE, archive)
        .allow(ARCHIVE, "read");
    let grant = capsule_kit_guest::grant(&mut bus, ARCHIVE, "read", "test the budget").unwrap();
    let mut left = 60;
    {
        let mut reader = zip::Reader::new(&mut bus, ARCHIVE, &grant, &mut left);
        reader.read(0, 60).unwrap();
        assert!(
            matches!(reader.read(0, 1), Err(zip::ReadError::Budget)),
            "a read past what is left is refused before it is asked"
        );
    }
    assert_eq!(left, 0, "a read is taken off the budget at once");
}

#[test]
fn no_listing_reads_more_than_the_run_may() {
    let archives = [
        build(&[Spec::file("a.txt").data(b"hello")], &[]),
        build(&[Spec::file("inner.zip").data(&[0u8; 64])], &[]),
        build(
            &(0..MAX_ENTRIES)
                .map(|index| Spec::file(&format!("{index:0>4}/a.txt")))
                .collect::<Vec<_>>(),
            &[],
        ),
        build(&[Spec::file("a.txt")], &vec![b'c'; 1000]),
    ];
    for archive in archives {
        let len = archive.len();
        let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
        let read = bus.bytes_served(ARCHIVE);
        assert!(
            read <= MAX_READ_BYTES,
            "read {read} bytes of a {len}-byte archive"
        );
    }
}
