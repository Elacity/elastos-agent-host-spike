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
    /// The flags, CRC and sizes in the local header, when they differ.
    local_flags: Option<u16>,
    local_crc: Option<u32>,
    local_compressed: Option<u32>,
    local_uncompressed: Option<u32>,
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
            local_flags: None,
            local_crc: None,
            local_compressed: None,
            local_uncompressed: None,
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
        header.extend_from_slice(&u16b(spec.local_flags.unwrap_or(spec.flags)));
        header.extend_from_slice(&u16b(spec.local_method.unwrap_or(spec.method)));
        header.extend_from_slice(&u16b(0));
        header.extend_from_slice(&u16b(0));
        header.extend_from_slice(&u32b(spec.local_crc.unwrap_or(spec.crc)));
        header.extend_from_slice(&u32b(
            spec.local_compressed
                .unwrap_or(spec.compressed.unwrap_or(spec.data.len() as u32)),
        ));
        header.extend_from_slice(&u32b(
            spec.local_uncompressed
                .unwrap_or(spec.uncompressed.unwrap_or(spec.data.len() as u32)),
        ));
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

fn assert_no_archive_request(bus: &FakeBus, archive: &str) {
    assert!(
        !bus.calls
            .iter()
            .any(|call| matches!(call, Call::Request { resource, .. } if resource == archive)),
        "the archive must not be granted"
    );
}

fn single(name: &str) -> FakeBus {
    run_fixture(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[Spec::file(name)], &[]),
    )
}

/// A fake Runtime that answers one read short, as a provider can when the
/// object changes after an earlier read.
struct ShortReadBus {
    inner: FakeBus,
    archive: String,
    at: u64,
    keep: usize,
}

impl Bus for ShortReadBus {
    fn request(
        &mut self,
        resource: &str,
        action: &str,
        reason: &str,
    ) -> Result<String, BusFailure> {
        self.inner.request(resource, action, reason)
    }

    fn invoke(
        &mut self,
        resource: &str,
        operation: &str,
        body: &[u8],
        grant: &str,
    ) -> Result<InvokeReply, BusFailure> {
        let reply = self.inner.invoke(resource, operation, body, grant)?;
        if resource == self.archive && operation == "read" {
            let ask: Value = serde_json::from_slice(body).expect("the kit sends JSON");
            if ask["offset"].as_u64() == Some(self.at) {
                let mut answer: Value = serde_json::from_slice(&reply.body).expect("JSON answer");
                if let Some(content) = answer["data"]["content"].as_array_mut() {
                    content.truncate(self.keep);
                    let answered = content.len();
                    answer["data"]["size"] = json!(answered);
                }
                return Ok(InvokeReply {
                    status: reply.status,
                    body: serde_json::to_vec(&answer).unwrap(),
                });
            }
        }
        Ok(reply)
    }
}

/// A fake Runtime that changes one byte of the local header on the L5 read,
/// as an object that changes between B4a and the show would.
struct ChangedLocalHeaderBus {
    inner: FakeBus,
    archive: String,
    at: u64,
    byte: usize,
    value: u8,
}

impl Bus for ChangedLocalHeaderBus {
    fn request(
        &mut self,
        resource: &str,
        action: &str,
        reason: &str,
    ) -> Result<String, BusFailure> {
        self.inner.request(resource, action, reason)
    }

    fn invoke(
        &mut self,
        resource: &str,
        operation: &str,
        body: &[u8],
        grant: &str,
    ) -> Result<InvokeReply, BusFailure> {
        let reply = self.inner.invoke(resource, operation, body, grant)?;
        if resource == self.archive && operation == "read" {
            let ask: Value = serde_json::from_slice(body).expect("the kit sends JSON");
            // B4a reads exactly the 30-byte prefix; L5 reads the prefix and
            // the name.
            if ask["offset"].as_u64() == Some(self.at) && ask["length"].as_u64().unwrap_or(0) > 30 {
                let mut answer: Value = serde_json::from_slice(&reply.body).expect("JSON answer");
                if let Some(content) = answer["data"]["content"].as_array_mut() {
                    content[self.byte] = json!(self.value);
                }
                return Ok(InvokeReply {
                    status: reply.status,
                    body: serde_json::to_vec(&answer).unwrap(),
                });
            }
        }
        Ok(reply)
    }
}

/// A fake Runtime that denies one read — the central directory's — after
/// answering the size probes and the tail that come before it.
struct DeniedDirectoryBus {
    inner: FakeBus,
    archive: String,
    directory: (u64, u64),
    denied: Vec<(u64, u64)>,
}

impl Bus for DeniedDirectoryBus {
    fn request(
        &mut self,
        resource: &str,
        action: &str,
        reason: &str,
    ) -> Result<String, BusFailure> {
        self.inner.request(resource, action, reason)
    }

    fn invoke(
        &mut self,
        resource: &str,
        operation: &str,
        body: &[u8],
        grant: &str,
    ) -> Result<InvokeReply, BusFailure> {
        if resource == self.archive && operation == "read" {
            let ask: Value = serde_json::from_slice(body).expect("the kit sends JSON");
            let read = (
                ask["offset"].as_u64().unwrap_or(0),
                ask["length"].as_u64().unwrap_or(0),
            );
            if read == self.directory {
                self.denied.push(read);
                return Err(BusFailure::Denied("the directory read is denied".into()));
            }
        }
        self.inner.invoke(resource, operation, body, grant)
    }
}

/// A fake Runtime with one sparse object larger than ZIP can address: every
/// byte in range reads as zero, with an empty-directory end record ending at
/// 2^32.
struct SparseObjectBus {
    inner: FakeBus,
    archive: String,
    len: u64,
    end_record_at: u64,
    end_record: Vec<u8>,
}

impl SparseObjectBus {
    fn content(&self, offset: u64, length: u64) -> Vec<u8> {
        if offset >= self.len {
            return Vec::new();
        }
        let end = offset.saturating_add(length).min(self.len);
        let mut bytes = vec![0u8; (end - offset) as usize];
        let record_end = self.end_record_at + self.end_record.len() as u64;
        let from = offset.max(self.end_record_at);
        let to = end.min(record_end);
        if from < to {
            let start = (from - self.end_record_at) as usize;
            let at = (from - offset) as usize;
            let count = (to - from) as usize;
            bytes[at..at + count].copy_from_slice(&self.end_record[start..start + count]);
        }
        bytes
    }
}

impl Bus for SparseObjectBus {
    fn request(
        &mut self,
        resource: &str,
        action: &str,
        reason: &str,
    ) -> Result<String, BusFailure> {
        self.inner.request(resource, action, reason)
    }

    fn invoke(
        &mut self,
        resource: &str,
        operation: &str,
        body: &[u8],
        grant: &str,
    ) -> Result<InvokeReply, BusFailure> {
        if resource == self.archive && operation == "read" {
            let ask: Value = serde_json::from_slice(body).expect("the kit sends JSON");
            let offset = ask["offset"].as_u64().unwrap();
            let length = ask["length"].as_u64().unwrap();
            // The grant is checked by the inner fake, so a denied read still
            // fails exactly as it would there.
            self.inner.invoke(resource, operation, body, grant)?;
            let content = self.content(offset, length);
            let answered = content.len();
            return Ok(InvokeReply {
                status: "ok".to_string(),
                body: serde_json::to_vec(&json!({
                    "status": "ok",
                    "data": { "content": content, "size": answered },
                }))
                .unwrap(),
            });
        }
        self.inner.invoke(resource, operation, body, grant)
    }
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
fn a_denied_read_during_the_directory_read_stops_the_run() {
    // The probes and the tail are allowed; only the directory read is
    // denied, as a grant can fail part-way through a run. The refusal must
    // stop the run, not become a content skip of one entry.
    let archive = build(&[Spec::file("a.txt").data(b"hello")], &[]);
    let at = eocd_start(&archive);
    let directory = (
        u64::from(u32::from_le_bytes([
            archive[at + 16],
            archive[at + 17],
            archive[at + 18],
            archive[at + 19],
        ])),
        u64::from(u32::from_le_bytes([
            archive[at + 12],
            archive[at + 13],
            archive[at + 14],
            archive[at + 15],
        ])),
    );
    let inner = bus_with(request(ARCHIVE, &[]), ARCHIVE, archive);
    let mut bus = DeniedDirectoryBus {
        inner,
        archive: ARCHIVE.to_string(),
        directory,
        denied: Vec::new(),
    };
    let err = run(&mut bus).expect_err("a denied directory read stops the run");
    assert!(matches!(err, Refusal::Call { .. }), "{err:?}");
    assert_nothing_written(&bus.inner);
    assert_eq!(bus.denied, vec![directory], "the denial is the directory's");
    assert!(
        !bus.inner.invokes_on(ARCHIVE).is_empty(),
        "the probes and the tail were answered before the denial"
    );
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
    assert_no_archive_request(&bus, app_data);
}

#[test]
fn a_request_for_an_appdata_case_alias_is_refused() {
    // A Mac filesystem is case-insensitive: `.appdata` names `.AppData`.
    for app_data in [
        "localhost://Users/self/.appdata/App/other-app/secret.json",
        "localhost://Users/self/.APPDATA/App/other-app/secret.json",
        "localhost://Users/self/.AppData",
    ] {
        let mut bus = FakeBus::default()
            .object(REQUEST_URI, request(app_data, &[]))
            .allow(REQUEST_URI, "read")
            .allow(VIEW_URI, "write")
            .object(app_data, build(&[Spec::file("a.txt")], &[]))
            .allow(app_data, "read");
        let err = run(&mut bus).expect_err("an .AppData alias is refused");
        assert!(matches!(err, Refusal::Input(_)), "{app_data}: {err:?}");
        assert_nothing_written(&bus);
        assert!(bus.invokes_on(app_data).is_empty(), "{app_data}");
        assert_no_archive_request(&bus, app_data);
    }
}

#[test]
fn a_request_outside_the_users_folders_is_refused() {
    // The kit's URI check is this caller's rule too: a wrong prefix, a
    // traversal, an empty segment, a folder, or a malformed character all
    // stop the run before the archive grant.
    for uri in [
        "localhost://Users/other/Documents/trip.zip",
        "localhost://Users/selfX/Documents/trip.zip",
        "localhost://Users/self/Documents/../secret.zip",
        "localhost://Users/self/Documents//secret.zip",
        "localhost://Users/self/Documents/",
        "localhost://Users/self/Documents/trip.zip?x",
        "localhost://Users/self/Documents/trip\\zip",
        "localhost://Users/self/Documents/trip\n.zip",
    ] {
        let mut bus = FakeBus::default()
            .object(REQUEST_URI, request(uri, &[]))
            .allow(REQUEST_URI, "read")
            .allow(VIEW_URI, "write")
            .object(uri, build(&[Spec::file("a.txt")], &[]))
            .allow(uri, "read");
        let err = run(&mut bus).expect_err("a uri outside the person's folders is refused");
        assert!(matches!(err, Refusal::Input(_)), "{uri:?}: {err:?}");
        assert_nothing_written(&bus);
        assert!(bus.invokes_on(uri).is_empty(), "{uri:?}");
        assert_no_archive_request(&bus, uri);
    }
}

#[test]
fn a_request_at_its_cap_is_accepted_and_one_byte_over_is_refused() {
    // JSON tolerates trailing whitespace, so the padding changes only the
    // object's length. The literals pin the design's 4 KiB cap, not the
    // constant's current value.
    let cap = 4096;
    let base = request(ARCHIVE, &[]);
    let padded = |length: usize| {
        let mut bytes = base.clone();
        assert!(bytes.len() <= length);
        bytes.resize(length, b' ');
        bytes
    };
    let bus = run_fixture(padded(cap), ARCHIVE, build(&[Spec::file("a.txt")], &[]));
    assert!(view(&bus).get("refused").is_none());

    let mut bus = bus_with(padded(cap + 1), ARCHIVE, build(&[Spec::file("a.txt")], &[]));
    let err = run(&mut bus).expect_err("a request over its cap stops the run");
    assert!(matches!(err, Refusal::InputTooLarge), "{err:?}");
    assert_nothing_written(&bus);
    assert_no_archive_request(&bus, ARCHIVE);
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

#[test]
fn a_request_with_a_wrong_schema_is_refused() {
    for value in [
        json!({"schema": "elastos.archive-viewer.open/v2", "uri": ARCHIVE, "show": []}),
        json!({"uri": ARCHIVE, "show": []}),
    ] {
        let mut bus = bus_with(
            serde_json::to_vec(&value).unwrap(),
            ARCHIVE,
            build(&[], &[]),
        );
        let err = run(&mut bus).expect_err("a wrong schema is refused");
        assert!(matches!(err, Refusal::Input(_)), "{err:?}");
        assert_nothing_written(&bus);
        assert_no_archive_request(&bus, ARCHIVE);
    }
}

#[test]
fn a_request_with_too_many_indexes_is_refused() {
    let show: Vec<usize> = (0..=MAX_REQUEST_SHOW).collect();
    assert_eq!(show.len(), MAX_REQUEST_SHOW + 1);
    let mut bus = bus_with(request(ARCHIVE, &show), ARCHIVE, build(&[], &[]));
    let err = run(&mut bus).expect_err("more indexes than the limit is refused");
    assert!(matches!(err, Refusal::Input(_)), "{err:?}");
    assert_nothing_written(&bus);
    assert_no_archive_request(&bus, ARCHIVE);
}

#[test]
fn a_request_with_the_index_limit_is_accepted() {
    let show: Vec<usize> = (0..MAX_REQUEST_SHOW).collect();
    let bus = run_fixture(
        request(ARCHIVE, &show),
        ARCHIVE,
        build(&[Spec::file("a.txt")], &[]),
    );
    assert!(view(&bus).get("refused").is_none());
    assert_eq!(skipped(&bus).len(), MAX_REQUEST_SHOW - 1);
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
    // P1's `\\server` form is a backslash path too; the reason stays P3's.
    blocked("\\\\server\\share\\a.txt", "backslash");
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

    // An unmarked name must be printable ASCII: a newline is a control
    // character, so the encoding rule refuses it before the path rules do.
    blocked("a\nb.txt", "not_ascii");
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
    let fits = "a".repeat(255);
    let (status, _) = listed(&fits);
    assert_eq!(status, "listed");
}

#[test]
fn a_directory_with_32_segments_is_listed() {
    // A directory's permitted trailing slash is not a 33rd segment. The
    // literal 32 pins the design's cap, not the constant's current value.
    let directory = format!("{}/", ["d"; 32].join("/"));
    let bus = run_fixture(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[Spec::file(&directory)], &[]),
    );
    assert_eq!(status_of(&bus, 0), ("listed".to_string(), None));
    assert_eq!(entries(&bus)[0]["kind"], "directory");
}

#[test]
fn a_name_with_33_segments_is_blocked() {
    let file = ["d"; 33].join("/");
    let directory = format!("{file}/");
    let bus = run_fixture(
        request(ARCHIVE, &[]),
        ARCHIVE,
        build(&[Spec::file(&file), Spec::file(&directory)], &[]),
    );
    assert_eq!(
        status_of(&bus, 0),
        ("blocked".to_string(), Some("name_too_long".to_string()))
    );
    assert_eq!(
        status_of(&bus, 1),
        ("blocked".to_string(), Some("name_too_long".to_string()))
    );
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
fn other_entry_kinds_are_blocked() {
    // P9: a regular file's Unix mode is listed; a FIFO is not a regular file,
    // even though its name looks like one.
    let mut regular = Spec::file("regular.txt");
    regular.external = 0o100644 << 16;
    let mut fifo = Spec::file("pipe");
    fifo.external = 0o010644 << 16;
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[regular, fifo], &[]));
    assert_eq!(status_of(&bus, 0), ("listed".to_string(), None));
    assert_eq!(entries(&bus)[0]["kind"], "file");
    assert_eq!(
        status_of(&bus, 1),
        ("blocked".to_string(), Some("unsupported_kind".to_string()))
    );
    assert_eq!(entries(&bus)[1]["kind"], "other");
}

/// No read window reaches the bytes `[data_start, data_end)`, in any run.
fn assert_data_unread(bus: &FakeBus, data_start: u64, data_end: u64) {
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
                    length == 1 || end <= data_start || offset >= data_end,
                    "a read reached the entry's data: {body}"
                );
            }
        }
    }
}

#[test]
fn a_nested_archive_is_listed_not_opened() {
    let inner = build(&[Spec::file("x.txt")], &[]);
    let spec = Spec::file("inner.zip").data(&inner);
    // A filler keeps the object larger than the tail windows the design and
    // its falsifier explore, so no tail read can cover the nested archive.
    let filler = Spec::file("filler.bin").data(&vec![0u8; 4000]);
    let archive = build(&[spec, filler], &[]);
    // Its data starts after the 30-byte local header and its 9-byte name.
    let data_start = 30 + 9;
    let data_end = data_start + inner.len() as u64;
    // An ordinary listing and a request to show the entry both leave its
    // bytes unread: N1 says a nested archive is listed, never opened.
    for show in [Vec::new(), vec![0]] {
        let bus = run_fixture(request(ARCHIVE, &show), ARCHIVE, archive.clone());
        assert_eq!(status_of(&bus, 0), ("listed".to_string(), None));
        assert_eq!(entries(&bus)[0]["kind"], "archive");
        assert!(skipped(&bus).is_empty());
        assert_data_unread(&bus, data_start, data_end);
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

/// An encrypted entry followed by a filler: the 6-byte payload at
/// `[35, 41)` lies before the tail window, so a read that reaches it read
/// the payload rather than the tail.
fn encrypted_archive() -> (Vec<u8>, u64, u64) {
    let mut spec = Spec::file("a.txt").data(b"secret");
    spec.flags = 1;
    let filler = Spec::file("filler.bin").data(&vec![0u8; 2000]);
    (build(&[spec, filler], &[]), 30 + 5, 30 + 5 + 6)
}

#[test]
fn encrypted_entries_are_listed_not_read() {
    let (archive, data_start, data_end) = encrypted_archive();
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    assert_eq!(status_of(&bus, 0), ("encrypted".to_string(), None));
    assert!(skipped(&bus).is_empty());
    assert_data_unread(&bus, data_start, data_end);
}

#[test]
fn a_requested_encrypted_entry_is_skipped_with_its_status() {
    let (archive, data_start, data_end) = encrypted_archive();
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, archive);
    assert_eq!(status_of(&bus, 0), ("encrypted".to_string(), None));
    let skipped = skipped(&bus);
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0]["index"], 0);
    assert_eq!(skipped[0]["reason"], "encrypted");
    assert_data_unread(&bus, data_start, data_end);
}

#[test]
fn a_requested_unsupported_entry_is_skipped_with_its_status() {
    let mut spec = Spec::file("a.bin");
    spec.method = 12;
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[spec], &[]));
    assert_eq!(status_of(&bus, 0), ("unsupported".to_string(), None));
    let skipped = skipped(&bus);
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0]["reason"], "unsupported");
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

fn patch_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn directory_start(bytes: &[u8]) -> usize {
    let at = eocd_start(bytes);
    u32::from_le_bytes([
        bytes[at + 16],
        bytes[at + 17],
        bytes[at + 18],
        bytes[at + 19],
    ]) as usize
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
fn a_short_tail_response_refuses_the_archive() {
    // A valid archive with a seven-byte comment and a filler that puts the
    // tail window inside the object. Truncating the last seven bytes (the
    // comment) leaves the end record and every directory byte intact, so
    // only the answer's own length proves that the tail is short.
    let filler = Spec::file("filler.bin").data(&vec![0u8; 2000]);
    let archive = build(&[Spec::file("a.txt"), filler], b"1234567");
    let tail = 22 + MAX_COMMENT_BYTES;
    assert!(archive.len() as u64 > tail);
    let at = archive.len() as u64 - tail;
    let inner = bus_with(request(ARCHIVE, &[]), ARCHIVE, archive);
    let mut bus = ShortReadBus {
        inner,
        archive: ARCHIVE.to_string(),
        at,
        keep: (tail - 7) as usize,
    };
    run(&mut bus).expect("a content refusal still writes the view");
    let view: Value = serde_json::from_str(
        bus.inner
            .written
            .get(VIEW_URI)
            .expect("the view was written"),
    )
    .unwrap();
    assert!(view["entries"].as_array().unwrap().is_empty());
    assert_eq!(view["refused"]["code"], "end_record_truncated");
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
fn an_on_disk_count_that_differs_refuses_the_archive() {
    // On-disk count 2 and record count 1: only the on-disk comparison can
    // refuse this archive.
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    let at = eocd_start(&archive);
    patch_u16(&mut archive, at + 8, 2);
    patch_u16(&mut archive, at + 10, 1);
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
fn a_multi_disk_archive_is_refused() {
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    let at = eocd_start(&archive);
    patch_u16(&mut archive, at + 4, 1);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    assert_eq!(refused(&bus).0, "multi_disk");
}

#[test]
fn a_zip64_end_record_is_refused() {
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    let at = eocd_start(&archive);
    patch_u16(&mut archive, at + 10, u16::MAX);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    assert_eq!(refused(&bus).0, "zip64");
}

#[test]
fn an_entry_on_another_disk_refuses_the_archive() {
    // The end record names one disk; the entry's own disk field says another.
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    let at = directory_start(&archive);
    patch_u16(&mut archive, at + 34, 1);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    assert_eq!(refused(&bus).0, "multi_disk");
}

#[test]
fn an_entry_with_a_zip64_sentinel_refuses_the_archive() {
    // Each size field is a separate 32-bit value: a sentinel in any of them
    // claims zip64, which this viewer does not parse.
    let archive = build(&[Spec::file("a.txt")], &[]);
    let at = directory_start(&archive);
    for field in [20, 24, 42] {
        let mut archive = archive.clone();
        patch_u32(&mut archive, at + field, u32::MAX);
        let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
        assert_eq!(refused(&bus).0, "zip64", "field at the record + {field}");
    }
}

#[test]
fn a_directory_outside_the_object_is_refused() {
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    let at = eocd_start(&archive);
    patch_u32(&mut archive, at + 16, at as u32 + 1);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    assert_eq!(refused(&bus).0, "directory_outside_object");
}

#[test]
fn a_directory_over_its_cap_is_refused() {
    let mut spec = Spec::file("a.txt");
    spec.dir_extra = vec![0u8; 20_000];
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[spec], &[]));
    let (code, message) = refused(&bus);
    assert_eq!(code, "directory_too_large");
    assert!(
        message.contains(&MAX_DIRECTORY_BYTES.to_string()),
        "{message}"
    );
}

#[test]
fn a_record_without_its_signature_refuses_the_archive() {
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    let at = directory_start(&archive);
    patch_u32(&mut archive, at, 0);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    assert_eq!(refused(&bus).0, "record_signature");
}

#[test]
fn a_local_header_outside_the_object_refuses_the_archive() {
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    let at = directory_start(&archive);
    patch_u32(&mut archive, at + 42, 0x0010_0000);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    assert_eq!(refused(&bus).0, "local_header_outside_object");
}

#[test]
fn a_local_header_without_its_signature_refuses_the_archive() {
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    patch_u32(&mut archive, 0, 0);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    assert_eq!(refused(&bus).0, "local_header_signature");
}

#[test]
fn an_entry_record_that_passes_the_directory_refuses_the_archive() {
    let mut archive = build(&[Spec::file("a.txt")], &[]);
    let at = directory_start(&archive);
    patch_u32(&mut archive, at + 20, 1000);
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, archive);
    assert_eq!(refused(&bus).0, "entry_outside_directory");
}

#[test]
fn a_short_directory_response_refuses_the_archive() {
    let archive = build(&[Spec::file("a.txt")], &[]);
    let at = directory_start(&archive) as u64;
    let inner = bus_with(request(ARCHIVE, &[]), ARCHIVE, archive);
    let mut bus = ShortReadBus {
        inner,
        archive: ARCHIVE.to_string(),
        at,
        keep: 4,
    };
    run(&mut bus).expect("a content refusal still writes the view");
    let view: Value = serde_json::from_str(
        bus.inner
            .written
            .get(VIEW_URI)
            .expect("the view was written"),
    )
    .unwrap();
    assert!(view["entries"].as_array().unwrap().is_empty());
    assert_eq!(view["refused"]["code"], "directory_truncated");
}

#[test]
fn an_object_larger_than_the_supported_size_is_refused() {
    // A sparse 5 GiB object whose empty-directory end record ends at 2^32.
    let len = 5 * 1024 * 1024 * 1024u64;
    let end_record_at = (1u64 << 32) - 22;
    let mut record = Vec::new();
    end_record(&mut record, 0, end_record_at as u32, 0, &[]);
    let inner = bus_with(request(ARCHIVE, &[]), ARCHIVE, Vec::new());
    let mut bus = SparseObjectBus {
        inner,
        archive: ARCHIVE.to_string(),
        len,
        end_record_at,
        end_record: record,
    };
    run(&mut bus).expect("a content refusal still writes the view");
    let view: Value = serde_json::from_str(
        bus.inner
            .written
            .get(VIEW_URI)
            .expect("the view was written"),
    )
    .unwrap();
    assert!(view["entries"].as_array().unwrap().is_empty());
    assert_eq!(view["refused"]["code"], "object_too_large");
}

#[test]
fn too_many_entries_refuse_the_archive() {
    // 257 entries: the directory is 13,768 bytes, under the 16 KiB cap, so
    // only the entry-count bound can refuse this fixture.
    let specs: Vec<Spec> = (0..257)
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
    spec.crc = preview::crc32(b"hello");
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[spec], &[]));
    assert!(skipped(&bus).is_empty());
    assert_eq!(entries(&bus)[0]["status"], "listed");
}

#[test]
fn a_local_flag_that_differs_skips_the_entry() {
    let mut spec = Spec::file("a.txt").data(b"hello");
    spec.local_flags = Some(1 << 1);
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[spec], &[]));
    assert_eq!(status_of(&bus, 0), ("listed".to_string(), None));
    assert_eq!(skipped(&bus)[0]["reason"], "local_header_flags");
}

#[test]
fn a_data_descriptor_flag_is_ignored() {
    // Local bit 3 set, directory clear: the flag compare ignores bit 3, and
    // the sizes still have to agree.
    let mut local = Spec::file("a.txt").data(b"hello");
    local.local_flags = Some(1 << 3);
    local.crc = preview::crc32(b"hello");
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[local], &[]));
    assert!(skipped(&bus).is_empty(), "{:?}", skipped(&bus));

    // Directory bit 3 set, local sizes differ: a data descriptor means the
    // local CRC and sizes are not compared.
    let mut descriptor = Spec::file("a.txt").data(b"hello");
    descriptor.flags = 1 << 3;
    descriptor.crc = preview::crc32(b"hello");
    descriptor.local_flags = Some(0);
    descriptor.local_crc = Some(0xffff_ffff);
    descriptor.local_compressed = Some(0);
    descriptor.local_uncompressed = Some(0);
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[descriptor], &[]));
    assert!(skipped(&bus).is_empty(), "{:?}", skipped(&bus));
    assert_eq!(entries(&bus)[0]["status"], "listed");
}

#[test]
fn a_local_crc_that_differs_skips_the_entry() {
    let mut spec = Spec::file("a.txt").data(b"hello");
    spec.local_crc = Some(0x1234_5678);
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[spec], &[]));
    assert_eq!(skipped(&bus)[0]["reason"], "local_header_crc");
}

#[test]
fn a_local_size_that_differs_skips_the_entry() {
    let mut compressed = Spec::file("a.txt").data(b"hello");
    compressed.local_compressed = Some(0);
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[compressed], &[]));
    assert_eq!(skipped(&bus)[0]["reason"], "local_header_sizes");

    let mut uncompressed = Spec::file("a.txt").data(b"hello");
    uncompressed.local_uncompressed = Some(6);
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[uncompressed], &[]));
    assert_eq!(skipped(&bus)[0]["reason"], "local_header_sizes");
}

#[test]
fn a_local_length_that_differs_skips_the_entry() {
    let archive = build(&[Spec::file("a.txt")], &[]);
    for (byte, value) in [(26usize, 4u8), (28, 1)] {
        let inner = bus_with(request(ARCHIVE, &[0]), ARCHIVE, archive.clone());
        let mut bus = ChangedLocalHeaderBus {
            inner,
            archive: ARCHIVE.to_string(),
            at: 0,
            byte,
            value,
        };
        run(&mut bus).expect("a content refusal still writes the view");
        let view: Value = serde_json::from_str(
            bus.inner
                .written
                .get(VIEW_URI)
                .expect("the view was written"),
        )
        .unwrap();
        assert_eq!(
            view["skipped"][0]["reason"], "local_header_lengths",
            "byte {byte}"
        );
    }
}

#[test]
fn a_requested_entry_that_is_blocked_is_not_shown() {
    // A marked name that is not valid UTF-8 is blocked; no falsifier for the
    // path or encoding rules changes this status, so the skip path is proven
    // on its own.
    let mut spec = Spec::file("a");
    spec.flags = 1 << 11;
    spec.name = b"a\xe9.txt".to_vec();
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[spec], &[]));
    assert_eq!(
        status_of(&bus, 0),
        ("blocked".to_string(), Some("not_utf8".to_string()))
    );
    assert_eq!(skipped(&bus)[0]["reason"], "not_utf8");
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

#[test]
fn a_dos_directory_entry_is_listed_as_a_directory() {
    // A ZIP made on Windows can mark a directory with the DOS attribute and
    // no trailing slash; the low byte of the external attributes is DOS.
    let mut directory = Spec::file("dir");
    directory.external = 0x10;
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[directory], &[]));
    assert_eq!(status_of(&bus, 0), ("listed".to_string(), None));
    assert_eq!(entries(&bus)[0]["kind"], "directory");
}

#[test]
fn a_dos_directory_with_data_is_blocked() {
    // L9: the DOS attribute says directory, so its bytes are refused even
    // though the name has no trailing slash.
    let mut directory = Spec::file("dir").data(b"data!");
    directory.external = 0x10;
    let bus = run_fixture(request(ARCHIVE, &[]), ARCHIVE, build(&[directory], &[]));
    assert_eq!(
        status_of(&bus, 0),
        (
            "blocked".to_string(),
            Some("directory_with_data".to_string())
        )
    );
    assert_eq!(entries(&bus)[0]["kind"], "directory");
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

#[test]
fn no_view_is_longer_than_its_cap() {
    // A sweep: a giant name, a preview-heavy request and a mixed one. Each
    // view, written or refused, stays inside the cap.
    let mut giant = Spec::file("a");
    giant.flags = 1 << 11;
    giant.name = vec![0u8; 12_000];
    let mut over: Vec<Spec> = (0..8)
        .map(|index| deflated(&format!("e{index}.txt"), &text_block(16 * 1024)))
        .collect();
    // Long names in the listing count against the same cap as the previews.
    over.extend((0..60).map(|index| Spec::file(&format!("{index:0>3}{}", "n".repeat(196)))));
    let mixed: Vec<Spec> = (0..3)
        .map(|index| deflated(&format!("m{index}.txt"), &text_block(12 * 1024)))
        .collect();
    let cases: Vec<(Vec<Spec>, Vec<usize>, bool)> = vec![
        (vec![giant], Vec::new(), true),
        (over, (0..8).collect(), true),
        (mixed, (0..3).collect(), false),
    ];
    for (specs, show, refused) in cases {
        let bus = run_fixture(request(ARCHIVE, &show), ARCHIVE, build(&specs, &[]));
        let written = bus.written.get(VIEW_URI).expect("a view is written");
        assert!(
            written.len() as u64 <= MAX_VIEW_BYTES,
            "{} bytes",
            written.len()
        );
        let view = view(&bus);
        if refused {
            assert!(view["entries"].as_array().unwrap().is_empty());
            assert_eq!(view["refused"]["code"], "view_too_large");
        } else {
            assert!(view.get("refused").is_none());
            assert_eq!(view["previews"].as_array().unwrap().len(), 3);
        }
    }
}

// --- Text previews: B1 to B3, L6 to L8, F1, F2, F4, F5, F26 to F28, F33 -----

fn previews(bus: &FakeBus) -> Vec<Value> {
    view(bus)["previews"].as_array().unwrap().clone()
}

/// A stored entry whose sizes agree and whose CRC is right.
fn stored(name: &str, text: &[u8]) -> Spec {
    let mut spec = Spec::file(name).data(text);
    spec.method = 0;
    spec.crc = preview::crc32(text);
    spec
}

/// A deflated entry whose declared sizes and CRC are right.
fn deflated(name: &str, text: &[u8]) -> Spec {
    let mut spec = Spec::file(name);
    spec.method = 8;
    spec.data = miniz_oxide::deflate::compress_to_vec(text, 6);
    spec.crc = preview::crc32(text);
    spec.uncompressed = Some(text.len() as u32);
    spec
}

/// Bytes that do not compress, so a lying declared size still has a
/// compressed stream under the caps.
fn noise(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = 0x1234_5678u32;
    for _ in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 24) as u8);
    }
    out
}

/// One final DEFLATE stored block: the whole payload is copied out of the
/// decompressor in a single call unless the caps stop it first.
fn stored_deflate_block(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u16;
    let mut out = vec![0x01];
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// Printable text with a moderate deflate ratio: a 200-byte run repeated to
/// `len`. It passes B2 and stays small enough for the compressed budget.
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

/// The listed entries of an archive, and the bus its reads go through.
fn listing_of(archive: Vec<u8>) -> (FakeBus, String, Vec<zip::Entry>) {
    let mut bus = bus_with(request(ARCHIVE, &[]), ARCHIVE, archive);
    let grant = capsule_kit_guest::grant(&mut bus, ARCHIVE, "read", "test a preview").unwrap();
    let mut left = MAX_READ_BYTES;
    let entries = {
        let mut reader = zip::Reader::new(&mut bus, ARCHIVE, &grant, &mut left);
        zip::listing(&mut reader).unwrap().entries
    };
    (bus, grant, entries)
}

#[test]
fn crc32_matches_the_standard_check_value() {
    // The check value every CRC-32 implementation is measured by.
    assert_eq!(preview::crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(preview::crc32(b""), 0);
    assert_eq!(preview::crc32(b"hello"), 0x3610_A686);
}

#[test]
fn a_text_entry_is_shown_with_its_text() {
    let bus = run_fixture(
        request(ARCHIVE, &[0]),
        ARCHIVE,
        build(&[stored("a.txt", b"hello\n")], &[]),
    );
    assert!(skipped(&bus).is_empty());
    let previews = previews(&bus);
    assert_eq!(previews.len(), 1);
    assert_eq!(previews[0]["index"], 0);
    assert_eq!(previews[0]["blocks"][0]["kind"], "paragraph");
    assert_eq!(previews[0]["blocks"][0]["spans"][0]["text"], "hello");
}

#[test]
fn a_deflated_text_entry_is_shown() {
    let text = vec![b'a'; 1000];
    let bus = run_fixture(
        request(ARCHIVE, &[0]),
        ARCHIVE,
        build(&[deflated("a.txt", &text)], &[]),
    );
    assert!(skipped(&bus).is_empty());
    assert_eq!(
        previews(&bus)[0]["blocks"][0]["spans"][0]["text"],
        String::from_utf8(text).unwrap()
    );
}

#[test]
fn an_entry_over_the_preview_cap_is_skipped_after_one_byte_past_it() {
    // The declared size is at the cap, but the stream inflates past it. The
    // window stops after exactly one byte past the cap.
    let mut spec = Spec::file("a.bin");
    spec.method = 8;
    spec.data = stored_deflate_block(&noise(20_000));
    spec.uncompressed = Some(preview::MAX_PREVIEW_BYTES as u32);
    assert!(spec.data.len() as u64 <= preview::MAX_COMPRESSED_BYTES);
    let archive = build(&[spec], &[]);
    let (mut bus, grant, entries) = listing_of(archive.clone());
    let mut left = MAX_READ_BYTES;
    let budget = preview::Budget::new();
    let outcome = {
        let mut reader = zip::Reader::new(&mut bus, ARCHIVE, &grant, &mut left);
        preview::preview(&mut reader, &entries[0], &budget).unwrap()
    };
    assert_eq!(
        outcome.produced,
        preview::MAX_PREVIEW_BYTES + 1,
        "the window stops one byte past the cap"
    );
    assert_eq!(outcome.blocks, Err("oversize"));
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, archive);
    assert_eq!(skipped(&bus)[0]["reason"], "oversize");
    assert!(previews(&bus).is_empty());
}

#[test]
fn a_preview_stops_for_its_budget_before_any_corruption_reason() {
    // A valid stream longer than what the run may inflate is the budget's
    // failure, not the stream's.
    let archive = build(&[deflated("a.txt", b"hello")], &[]);
    let (mut bus, grant, entries) = listing_of(archive);
    let mut left = MAX_READ_BYTES;
    let budget = preview::Budget {
        inflate: 1,
        compressed: u64::MAX,
    };
    let outcome = {
        let mut reader = zip::Reader::new(&mut bus, ARCHIVE, &grant, &mut left);
        preview::preview(&mut reader, &entries[0], &budget).unwrap()
    };
    assert_eq!(outcome.produced, 1);
    assert_eq!(outcome.blocks, Err("inflate_budget"));

    // Exactly one byte past the window, and the stream declares the window:
    // B1's reason wins over L6's.
    let mut spec = Spec::file("a.bin");
    spec.method = 8;
    spec.data = stored_deflate_block(&vec![b'x'; preview::MAX_PREVIEW_BYTES as usize + 1]);
    spec.uncompressed = Some(preview::MAX_PREVIEW_BYTES as u32);
    let archive = build(&[spec], &[]);
    let (mut bus, grant, entries) = listing_of(archive);
    let mut left = MAX_READ_BYTES;
    let budget = preview::Budget::new();
    let outcome = {
        let mut reader = zip::Reader::new(&mut bus, ARCHIVE, &grant, &mut left);
        preview::preview(&mut reader, &entries[0], &budget).unwrap()
    };
    assert_eq!(outcome.produced, preview::MAX_PREVIEW_BYTES + 1);
    assert_eq!(outcome.blocks, Err("oversize"));
}

#[test]
fn an_entry_declared_over_the_cap_is_not_read() {
    // B1: the declared uncompressed size is checked before any read.
    let text = vec![b'a'; preview::MAX_PREVIEW_BYTES as usize + 1];
    let filler = Spec::file("filler.bin").data(&vec![0u8; 2000]);
    let archive = build(&[stored("a.txt", &text), filler], &[]);
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, archive);
    assert_eq!(skipped(&bus)[0]["reason"], "oversize");
    assert!(previews(&bus).is_empty());
    // The entry's data starts after its 30-byte local header and 5-byte name.
    let data_start = 30 + 5;
    assert_data_unread(&bus, data_start, data_start + text.len() as u64);
}

#[test]
fn an_entry_declared_past_the_ratio_is_not_read() {
    // B2: a declared ratio past the cap is not even read.
    let text = vec![b'0'; 15_000];
    let spec = deflated("a.txt", &text);
    let declared = spec.uncompressed.unwrap() as u64;
    let compressed = spec.data.len() as u64;
    assert!(
        declared > compressed * preview::MAX_RATIO + preview::RATIO_SLACK_BYTES,
        "{declared} from {compressed} is inside the ratio"
    );
    let filler = Spec::file("filler.bin").data(&vec![0u8; 2000]);
    let archive = build(&[spec, filler], &[]);
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, archive);
    assert_eq!(skipped(&bus)[0]["reason"], "ratio");
    assert!(previews(&bus).is_empty());
    let data_start = 30 + 5;
    assert_data_unread(&bus, data_start, data_start + compressed);
}

#[test]
fn an_entry_longer_or_shorter_than_declared_is_skipped() {
    // L6: the bytes, not the declaration, decide the sizes.
    let mut longer = deflated("longer.txt", b"abcdef");
    longer.uncompressed = Some(4);
    let mut shorter = deflated("shorter.txt", b"abcd");
    shorter.uncompressed = Some(8);
    let bus = run_fixture(
        request(ARCHIVE, &[0, 1]),
        ARCHIVE,
        build(&[longer, shorter], &[]),
    );
    assert_eq!(skipped(&bus)[0]["reason"], "size_mismatch");
    assert_eq!(skipped(&bus)[1]["reason"], "size_mismatch");
    assert!(previews(&bus).is_empty());
}

#[test]
fn a_crc_mismatch_skips_the_entry() {
    let mut spec = stored("a.txt", b"hello");
    spec.crc ^= 1;
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, build(&[spec], &[]));
    assert_eq!(skipped(&bus)[0]["reason"], "crc_mismatch");
    assert!(previews(&bus).is_empty());
}

#[test]
fn a_stored_entry_with_two_sizes_is_skipped() {
    // L8: a stored entry's two sizes must agree, before its bytes are read.
    let text = b"abcdef";
    let mut spec = stored("a.txt", text);
    spec.uncompressed = Some(5);
    let filler = Spec::file("filler.bin").data(&vec![0u8; 2000]);
    let archive = build(&[spec, filler], &[]);
    let bus = run_fixture(request(ARCHIVE, &[0]), ARCHIVE, archive);
    assert_eq!(skipped(&bus)[0]["reason"], "size_mismatch");
    assert!(previews(&bus).is_empty());
    let data_start = 30 + 5;
    assert_data_unread(&bus, data_start, data_start + text.len() as u64);
}

#[test]
fn a_text_entry_that_is_not_text_is_skipped() {
    let bus = run_fixture(
        request(ARCHIVE, &[0]),
        ARCHIVE,
        build(&[stored("a.txt", b"abc\0def")], &[]),
    );
    assert_eq!(skipped(&bus)[0]["reason"], "not_text");
    assert!(previews(&bus).is_empty());
}

#[test]
fn a_text_entry_with_too_many_blocks_is_skipped() {
    // 600 paragraphs pass the text checks but not the model's block cap.
    let text = "x\n\n".repeat(600);
    let bus = run_fixture(
        request(ARCHIVE, &[0]),
        ARCHIVE,
        build(&[stored("a.txt", text.as_bytes())], &[]),
    );
    assert_eq!(skipped(&bus)[0]["reason"], "too_long");
    assert!(previews(&bus).is_empty());
}

#[test]
fn no_run_inflates_more_than_its_total() {
    // B3 through the run's own accounting: five deflated entries inflate and
    // are then skipped, in every order, and the fifth stops at the total. A
    // NUL at the end makes each entry not text with a correct CRC, so no
    // other rule decides whether it costs output.
    let mut text = text_block(14 * 1024);
    let last = text.len() - 1;
    text[last] = 0;
    let specs: Vec<Spec> = (0..5)
        .map(|index| deflated(&format!("e{index}.txt"), &text))
        .collect();
    let archive = build(&specs, &[]);
    let orders = [[0usize, 1, 2, 3, 4], [4, 0, 1, 2, 3], [2, 3, 4, 0, 1]];
    for order in orders {
        let bus = run_fixture(request(ARCHIVE, &order), ARCHIVE, archive.clone());
        let skipped = skipped(&bus);
        let budget_skips: Vec<&Value> = skipped
            .iter()
            .filter(|skip| skip["reason"] == "inflate_budget")
            .collect();
        assert_eq!(
            budget_skips.len(),
            1,
            "one entry stops at the total: {order:?}"
        );
        assert_eq!(
            budget_skips[0]["index"], order[4],
            "the last entry stops at the total: {order:?}"
        );
        assert_eq!(
            previews(&bus).len() + skipped.len(),
            5,
            "every requested entry was decided: {order:?}"
        );
    }
}

#[test]
fn no_run_reads_more_compressed_data_than_its_cap() {
    // The compressed budget is separate from the inflate one: the third
    // stored entry would pass it, and is not read.
    let text = vec![b'a'; 9 * 1024];
    let specs: Vec<Spec> = (0..3)
        .map(|index| stored(&format!("e{index}.txt"), &text))
        .collect();
    let archive = build(&specs, &[]);
    let (mut bus, grant, entries) = listing_of(archive);
    let mut budget = preview::Budget::new();
    let mut left = MAX_READ_BYTES;
    for entry in &entries[..2] {
        let outcome = {
            let mut reader = zip::Reader::new(&mut bus, ARCHIVE, &grant, &mut left);
            preview::preview(&mut reader, entry, &budget).unwrap()
        };
        assert!(outcome.blocks.is_ok(), "{:?}", outcome.blocks);
        budget.take(&outcome);
    }
    let outcome = {
        let mut reader = zip::Reader::new(&mut bus, ARCHIVE, &grant, &mut left);
        preview::preview(&mut reader, &entries[2], &budget).unwrap()
    };
    assert_eq!(outcome.read, 0, "the third entry's bytes are not read");
    assert_eq!(outcome.blocks, Err("compressed_budget"));
}
