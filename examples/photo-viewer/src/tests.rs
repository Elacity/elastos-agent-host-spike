use serde_json::{json, Value};

use std::collections::BTreeMap;

use crate::*;
use capsule_kit_guest::fake::{Call, FakeBus};

/// The Runtime's answers to launch names, around the kit's fake bus, which
/// answers every other name as the person's storage. `content` is the photo
/// set the run was launched with, by path, or none; `refuse` replaces the
/// answer to every launch request with that failure.
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

/// A run that was not launched with content: the launch name answers
/// `not_found`, as the Runtime answers it, and the rest is the person's.
fn run(bus: &mut FakeBus) -> Result<String, Refusal> {
    let mut launch = Launch::of(bus, None);
    let ran = crate::run(&mut launch);
    assert_eq!(
        launch.asked,
        [(LAUNCH_CONTENT_PATTERN.to_string(), "read".to_string())]
    );
    ran
}

const A: &str = "localhost://Users/self/Pictures/a.png";
const B: &str = "localhost://Users/self/Pictures/trip/b.jpg";
const C: &str = "localhost://Users/self/Pictures/c.webp";

fn png(width: u32, height: u32, total: usize) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.extend_from_slice(&13u32.to_be_bytes());
    bytes.extend_from_slice(b"IHDR");
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]);
    bytes.resize(total.max(bytes.len()), 0);
    bytes
}

fn jpeg(width: u16, height: u16) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xd8];
    // APP0 with 14 bytes of payload.
    bytes.extend_from_slice(&[0xff, 0xe0, 0x00, 0x10]);
    bytes.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
    // SOF0: length 17, precision 8, height, width, 3 components.
    bytes.extend_from_slice(&[0xff, 0xc0, 0x00, 0x11, 0x08]);
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
    bytes.extend_from_slice(&[0xff, 0xd9]);
    bytes
}

fn riff(chunk: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = b"RIFF".to_vec();
    bytes.extend_from_slice(&((4 + 8 + payload.len()) as u32).to_le_bytes());
    bytes.extend_from_slice(b"WEBP");
    bytes.extend_from_slice(chunk);
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn webp_vp8x(width: u32, height: u32) -> Vec<u8> {
    let mut payload = vec![0u8; 4];
    payload.extend_from_slice(&(width - 1).to_le_bytes()[..3]);
    payload.extend_from_slice(&(height - 1).to_le_bytes()[..3]);
    riff(b"VP8X", &payload)
}

fn webp_vp8l(width: u32, height: u32) -> Vec<u8> {
    let bits = (width - 1) | (height - 1) << 14;
    let mut payload = vec![0x2f];
    payload.extend_from_slice(&bits.to_le_bytes());
    riff(b"VP8L", &payload)
}

fn webp_vp8(width: u16, height: u16) -> Vec<u8> {
    let mut payload = vec![0x50, 0x01, 0x00, 0x9d, 0x01, 0x2a];
    payload.extend_from_slice(&width.to_le_bytes());
    payload.extend_from_slice(&height.to_le_bytes());
    riff(b"VP8 ", &payload)
}

fn album(items: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({ "schema": ALBUM_SCHEMA, "items": items })).unwrap()
}

/// An album of `uris`, every read allowed, and the playlist write allowed.
fn granted(uris: &[(&str, Vec<u8>)]) -> FakeBus {
    let items: Vec<Value> = uris.iter().map(|(uri, _)| json!({ "uri": uri })).collect();
    let mut bus = FakeBus::default()
        .object(ALBUM_URI, album(Value::Array(items)))
        .allow(ALBUM_URI, "read")
        .allow(PLAYLIST_URI, "write");
    for (uri, bytes) in uris {
        bus = bus.object(uri, bytes.clone()).allow(uri, "read");
    }
    bus
}

fn written(bus: &FakeBus) -> Value {
    serde_json::from_str(bus.written.get(PLAYLIST_URI).expect("playlist written")).unwrap()
}

fn assert_nothing_written(bus: &FakeBus) {
    assert!(bus.written.is_empty(), "no playlist may be written");
    assert!(
        bus.invokes_on(PLAYLIST_URI).is_empty(),
        "no write may be attempted"
    );
}

/// A JPEG whose frame header follows APPn segments of these payload sizes.
fn jpeg_after(segments: &[usize], width: u16, height: u16) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xd8];
    for (index, size) in segments.iter().enumerate() {
        bytes.extend_from_slice(&[0xff, 0xe1 + (index % 14) as u8]);
        bytes.extend_from_slice(&((size + 2) as u16).to_be_bytes());
        bytes.extend(std::iter::repeat_n(0x45u8, *size));
    }
    bytes.extend_from_slice(&jpeg(width, height)[20..]);
    bytes
}

fn skipped(bus: &FakeBus) -> Vec<(u64, String, String)> {
    written(bus)["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|skip| {
            (
                skip["order"].as_u64().unwrap(),
                skip["uri"].as_str().unwrap().to_string(),
                skip["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn played(bus: &FakeBus) -> Vec<String> {
    written(bus)["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["uri"].as_str().unwrap().to_string())
        .collect()
}

/// One item with these bytes; it must be skipped for `reason`.
fn assert_skipped(bytes: Vec<u8>, reason: &str) -> FakeBus {
    let mut bus = granted(&[(A, bytes)]);
    run(&mut bus).unwrap_or_else(|err| panic!("{reason}: the run must not stop: {err:?}"));
    assert_eq!(skipped(&bus), vec![(0, A.to_string(), reason.to_string())]);
    assert!(played(&bus).is_empty());
    bus
}

// --- plays ------------------------------------------------------------------

#[test]
fn plays_png_jpeg_and_webp_in_album_order() {
    let mut bus = FakeBus::default()
        .object(
            ALBUM_URI,
            album(json!([
                { "uri": A, "duration_ms": 4000 },
                { "uri": B },
                { "uri": C, "duration_ms": 60000 },
            ])),
        )
        .allow(ALBUM_URI, "read")
        .allow(PLAYLIST_URI, "write")
        .object(A, png(640, 480, 100))
        .allow(A, "read")
        .object(B, jpeg(1920, 1080))
        .allow(B, "read")
        .object(C, webp_vp8x(4000, 3000))
        .allow(C, "read");

    let text = run(&mut bus).expect("album plays");
    let playlist = written(&bus);
    assert_eq!(text, bus.written[PLAYLIST_URI]);
    assert_eq!(playlist["schema"], PLAYLIST_SCHEMA);
    assert_eq!(playlist["album"], ALBUM_URI);
    assert_eq!(playlist["skipped"], json!([]));
    let summary: Vec<_> = playlist["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["order"].as_u64().unwrap(),
                item["uri"].as_str().unwrap(),
                item["mime"].as_str().unwrap(),
                item["width"].as_u64().unwrap(),
                item["height"].as_u64().unwrap(),
                item["duration_ms"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            (0, A, "image/png", 640, 480, 4000),
            (1, B, "image/jpeg", 1920, 1080, DEFAULT_DURATION_MS),
            (2, C, "image/webp", 4000, 3000, 60000),
        ]
    );
    // No body hash and no size: Runtime is to name the bytes by CID.
    let keys: Vec<&str> = playlist["items"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        vec!["duration_ms", "height", "mime", "order", "uri", "width"]
    );
}

#[test]
fn every_webp_frame_header_gives_its_dimensions() {
    let mut bus = granted(&[
        (A, webp_vp8x(300, 200)),
        (B, webp_vp8l(301, 201)),
        (C, webp_vp8(1024, 768)),
    ]);
    run(&mut bus).unwrap();
    let items = written(&bus)["items"].clone();
    let sizes: Vec<_> = items
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["width"].as_u64().unwrap(),
                item["height"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(sizes, vec![(300, 200), (301, 201), (1024, 768)]);
}

#[test]
fn a_large_image_is_checked_from_its_header_alone() {
    let mut bus = granted(&[(A, png(4000, 3000, 10 * 1024 * 1024))]);
    run(&mut bus).unwrap();
    assert_eq!(played(&bus), vec![A]);
    assert_eq!(
        bus.bytes_served(A),
        HEADER_BYTES,
        "the header only; the size probe past the limit is empty"
    );
}

#[test]
fn a_jpeg_frame_header_after_large_exif_is_found_without_reading_the_payloads() {
    let bytes = jpeg_after(&[60_000, 60_000, 4_000], 6000, 4000);
    let mut bus = granted(&[(B, bytes)]);
    run(&mut bus).unwrap();
    let item = &written(&bus)["items"][0];
    assert_eq!(
        (item["width"].clone(), item["height"].clone()),
        (json!(6000), json!(4000))
    );
    // Header, then 4 bytes per APPn marker, the APP0 and SOF markers, and the frame header.
    assert!(bus.bytes_served(B) < 100, "served {}", bus.bytes_served(B));
}

#[test]
fn an_object_of_exactly_the_size_limit_plays() {
    let mut bus = granted(&[(A, png(10, 10, MAX_OBJECT_BYTES as usize))]);
    run(&mut bus).unwrap();
    assert_eq!(played(&bus), vec![A]);
}

#[test]
fn playlist_text_is_the_same_on_every_run() {
    let objects = [(A, png(1, 1, 64)), (B, b"not an image".to_vec())];
    let mut first = granted(&objects);
    let mut second = granted(&objects);
    assert_eq!(run(&mut first).unwrap(), run(&mut second).unwrap());
}

#[test]
fn the_playlist_is_written_as_bytes_with_append_false() {
    let mut bus = granted(&[(A, png(1, 1, 64))]);
    let text = run(&mut bus).unwrap();
    let body = bus
        .invokes_on(PLAYLIST_URI)
        .into_iter()
        .find_map(|call| match call {
            Call::Invoke {
                operation, body, ..
            } if operation == "write" => Some(body.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(body["append"], json!(false));
    assert_eq!(body["content"], json!(text.as_bytes()));
}

// --- content failures skip the item --------------------------------------------------

#[test]
fn wrong_type_is_skipped_after_reading_only_its_header() {
    for bytes in [
        b"GIF89a\x01\x00\x01\x00\x00\x00\x00".to_vec(),
        b"just some text, not an image".to_vec(),
        b"RIFF\x10\x00\x00\x00WAVEfmt ".to_vec(),
        vec![0u8; 64],
    ] {
        let mut padded = bytes.clone();
        padded.resize(200_000, b'x');
        let bus = assert_skipped(padded, "wrong_type");
        assert_eq!(bus.bytes_served(A), HEADER_BYTES, "{bytes:?}");
    }
}

#[test]
fn oversize_is_skipped_without_reading_the_body() {
    let bus = assert_skipped(png(10, 10, MAX_OBJECT_BYTES as usize + 1), "oversize");
    assert_eq!(bus.bytes_served(A), HEADER_BYTES + 1);
}

#[test]
fn truncated_magic_is_skipped() {
    for bytes in [
        vec![],
        b"\x89PN".to_vec(),
        b"\x89PNG\r\n\x1a".to_vec(),
        vec![0xff, 0xd8],
        b"RIFF\x10\x00".to_vec(),
        b"RIFF\x10\x00\x00\x00WE".to_vec(),
    ] {
        assert_skipped(bytes, "truncated");
    }
}

#[test]
fn an_image_cut_before_its_size_field_is_skipped_as_truncated() {
    let mut png_cut = png(640, 480, 0);
    png_cut.truncate(20);
    let mut jpeg_cut = jpeg(640, 480);
    jpeg_cut.truncate(24);
    let mut jpeg_marker_cut = jpeg_after(&[100], 640, 480);
    jpeg_marker_cut.truncate(2 + 4 + 100 + 3);
    let mut vp8x_cut = webp_vp8x(640, 480);
    vp8x_cut.truncate(27);
    let mut vp8l_cut = webp_vp8l(640, 480);
    vp8l_cut.truncate(22);
    for bytes in [png_cut, jpeg_cut, jpeg_marker_cut, vp8x_cut, vp8l_cut] {
        assert_skipped(bytes, "truncated");
    }
}

#[test]
fn malformed_headers_are_skipped() {
    let mut no_ihdr = png(1, 1, 64);
    no_ihdr[12..16].copy_from_slice(b"IDAT");
    let mut jpeg_scan_first = vec![0xff, 0xd8, 0xff, 0xda, 0x00, 0x08];
    jpeg_scan_first.resize(64, 0);
    let too_many_segments = jpeg_after(&[0; MAX_JPEG_SEGMENTS], 10, 10);
    for bytes in [
        png(0, 10, 64),
        png(10, 0, 64),
        jpeg(0, 10),
        no_ihdr,
        jpeg_scan_first,
        too_many_segments,
    ] {
        assert_skipped(bytes, "malformed");
    }
    // One segment fewer than the limit still reaches the frame header.
    let mut bus = granted(&[(B, jpeg_after(&[0; MAX_JPEG_SEGMENTS - 2], 10, 10))]);
    run(&mut bus).unwrap();
    assert_eq!(played(&bus), vec![B]);
}

#[test]
fn dimension_limits_are_enforced_at_the_boundary() {
    for (width, height, plays) in [
        (MAX_SIDE, 1, true),
        (MAX_SIDE + 1, 1, false),
        (1, MAX_SIDE + 1, false),
        (8192, 4882, true),  // 39 993 344 pixels
        (8192, 4883, false), // 40 001 536 pixels
    ] {
        let mut bus = granted(&[(A, png(width, height, 64))]);
        run(&mut bus).unwrap();
        if plays {
            assert_eq!(played(&bus), vec![A], "{width}x{height}");
        } else {
            assert_eq!(
                skipped(&bus),
                vec![(0, A.to_string(), "dimensions".to_string())]
            );
            assert!(written(&bus)["skipped"][0]["message"]
                .as_str()
                .unwrap()
                .contains(&format!("{width}x{height}")));
        }
    }
}

#[test]
fn a_bad_item_is_skipped_and_the_rest_play_in_order() {
    let mut bus = granted(&[
        (A, png(1, 1, 64)),
        (B, b"not an image at all".to_vec()),
        (C, webp_vp8l(2, 2)),
    ]);
    run(&mut bus).unwrap();
    assert_eq!(played(&bus), vec![A, C]);
    assert_eq!(
        skipped(&bus),
        vec![(1, B.to_string(), "wrong_type".to_string())]
    );
    let orders: Vec<u64> = written(&bus)["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["order"].as_u64().unwrap())
        .collect();
    assert_eq!(orders, vec![0, 2], "album order is kept");
    let skip = &written(&bus)["skipped"][0];
    assert_eq!(skip["message"], "not PNG, JPEG or WebP");
}

#[test]
fn an_album_where_every_item_is_skipped_still_writes_a_playlist() {
    let mut bus = granted(&[(A, b"text".to_vec()), (B, png(9000, 1, 64))]);
    run(&mut bus).unwrap();
    assert!(played(&bus).is_empty());
    assert_eq!(
        skipped(&bus),
        vec![
            (0, A.to_string(), "wrong_type".to_string()),
            (1, B.to_string(), "dimensions".to_string()),
        ]
    );
}

// --- authority failures stop the run -------------------------------------------------

#[test]
fn album_without_a_read_grant_stops_before_any_read() {
    let mut bus = granted(&[(A, png(1, 1, 64))]);
    bus.allowed
        .remove(&(ALBUM_URI.to_string(), "read".to_string()));

    let err = run(&mut bus).unwrap_err();
    assert!(matches!(&err, Refusal::NoGrant { resource, .. } if resource == ALBUM_URI));
    assert!(matches!(err.to_bus_failure(&APP), BusFailure::Denied(_)));
    assert!(
        bus.invokes_on(ALBUM_URI).is_empty(),
        "album must not be read"
    );
    assert!(bus.invokes_on(A).is_empty());
    assert_nothing_written(&bus);
}

#[test]
fn image_without_a_read_grant_stops_the_run_and_is_not_skipped() {
    let mut bus = granted(&[(A, png(1, 1, 64)), (B, jpeg(2, 2)), (C, webp_vp8l(3, 3))]);
    bus.allowed.remove(&(B.to_string(), "read".to_string()));

    let err = run(&mut bus).unwrap_err();
    assert!(matches!(&err, Refusal::NoGrant { resource, .. } if resource == B));
    assert!(matches!(err.to_bus_failure(&APP), BusFailure::Denied(_)));
    assert!(
        bus.invokes_on(B).is_empty(),
        "denied image must not be read"
    );
    assert!(
        bus.invokes_on(C).is_empty(),
        "the run stops at the first authority failure"
    );
    assert_nothing_written(&bus);
}

#[test]
fn playlist_without_a_write_grant_stops_and_is_not_written() {
    let mut bus = granted(&[(A, png(1, 1, 64))]);
    bus.allowed
        .remove(&(PLAYLIST_URI.to_string(), "write".to_string()));

    let err = run(&mut bus).unwrap_err();
    assert!(matches!(&err, Refusal::NoGrant { resource, .. } if resource == PLAYLIST_URI));
    assert_nothing_written(&bus);
}

#[test]
fn a_read_grant_is_not_a_write_grant() {
    let mut bus = granted(&[(A, png(1, 1, 64))]);
    bus.allowed
        .remove(&(PLAYLIST_URI.to_string(), "write".to_string()));
    bus.allowed
        .insert((PLAYLIST_URI.to_string(), "read".to_string()));

    let err = run(&mut bus).unwrap_err();
    assert!(matches!(&err, Refusal::NoGrant { resource, .. } if resource == PLAYLIST_URI));
    assert_nothing_written(&bus);
}

#[test]
fn each_object_is_read_with_the_grant_issued_for_it() {
    let mut bus = granted(&[(A, png(1, 1, 64)), (B, jpeg(2, 2))]);
    run(&mut bus).unwrap();
    let requests: Vec<_> = bus
        .calls
        .iter()
        .filter_map(|call| match call {
            Call::Request { resource, action } => Some((resource.as_str(), action.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(
        requests,
        vec![
            (ALBUM_URI, "read"),
            (A, "read"),
            (B, "read"),
            (PLAYLIST_URI, "write"),
        ]
    );
}

#[test]
fn a_provider_error_stops_the_run_and_is_not_skipped() {
    let mut bus = granted(&[(A, png(1, 1, 64)), (B, png(1, 1, 64))]).provider_error(
        A,
        "read_failed",
        "disk gone",
    );
    let err = run(&mut bus).unwrap_err();
    assert!(matches!(
        &err,
        Refusal::Call { resource, error: CallError::Provider { code, .. } } if resource == A && code == "read_failed"
    ));
    assert!(matches!(
        err.to_bus_failure(&APP),
        BusFailure::Unavailable(_)
    ));
    assert!(err.message(&APP).contains("disk gone"));
    assert!(bus.invokes_on(B).is_empty());
    assert_nothing_written(&bus);
}

#[test]
fn a_missing_object_stops_the_run() {
    let mut bus = granted(&[(A, png(1, 1, 64))]);
    bus.objects.remove(A);
    let err = run(&mut bus).unwrap_err();
    assert!(matches!(
        &err,
        Refusal::Call {
            error: CallError::Provider { .. },
            ..
        }
    ));
    assert_nothing_written(&bus);
}

#[test]
fn album_larger_than_its_limit_stops_the_run() {
    let mut bus = granted(&[(A, png(1, 1, 64))]);
    let mut big = album(json!([{ "uri": A }]));
    big.resize(MAX_ALBUM_BYTES as usize + 1, b' ');
    bus.objects.insert(ALBUM_URI.to_string(), big);
    let err = run(&mut bus).unwrap_err();
    assert_eq!(err, Refusal::InputTooLarge);
    assert!(bus.invokes_on(A).is_empty());
    assert_nothing_written(&bus);
}

#[test]
fn malformed_albums_stop_before_any_image_is_read() {
    let too_many: Vec<Value> = (0..=MAX_ALBUM_ITEMS).map(|_| json!({ "uri": A })).collect();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("not json", b"{".to_vec()),
        ("not an object", b"[]".to_vec()),
        (
            "wrong schema",
            serde_json::to_vec(&json!({ "schema": "other/v1", "items": [{ "uri": A }] })).unwrap(),
        ),
        (
            "unknown album field",
            serde_json::to_vec(&json!({ "schema": ALBUM_SCHEMA, "items": [{ "uri": A }], "x": 1 }))
                .unwrap(),
        ),
        ("no items", album(json!([]))),
        ("too many items", album(Value::Array(too_many))),
        (
            "not under Pictures",
            album(json!([{ "uri": "localhost://Users/self/Documents/a.png" }])),
        ),
        (
            "other principal",
            album(json!([{ "uri": "localhost://Users/other/Pictures/a.png" }])),
        ),
        (
            "elastos uri",
            album(json!([{ "uri": "elastos://object/read" }])),
        ),
        (
            "dot dot",
            album(json!([{ "uri": "localhost://Users/self/Pictures/../.ssh/id" }])),
        ),
        (
            "folder",
            album(json!([{ "uri": "localhost://Users/self/Pictures/trip/" }])),
        ),
        (
            "query",
            album(json!([{ "uri": "localhost://Users/self/Pictures/a.png?x=1" }])),
        ),
        (
            "unknown item field",
            album(json!([{ "uri": A, "token": "t" }])),
        ),
        (
            "short duration",
            album(json!([{ "uri": A, "duration_ms": MIN_DURATION_MS - 1 }])),
        ),
        (
            "long duration",
            album(json!([{ "uri": A, "duration_ms": MAX_DURATION_MS + 1 }])),
        ),
        (
            "text duration",
            album(json!([{ "uri": A, "duration_ms": "5s" }])),
        ),
    ];
    for (name, bytes) in cases {
        let mut bus = granted(&[(A, png(1, 1, 64))]);
        bus.objects.insert(ALBUM_URI.to_string(), bytes);
        let err = run(&mut bus).unwrap_err();
        assert!(matches!(err, Refusal::Input(_)), "{name}: {err:?}");
        assert!(
            matches!(err.to_bus_failure(&APP), BusFailure::Invalid(_)),
            "{name}"
        );
        assert!(bus.invokes_on(A).is_empty(), "{name}: no image may be read");
        assert_nothing_written(&bus);
    }
}

/// A photo set launched by its CID plays from the launch. The core asks for
/// the launch's content, reads the Runtime's listing, takes the files under
/// `images/` in path order as its album, reads each under the one grant the
/// launch gave, and writes the playlist to the launch's output. It asks the
/// person's storage for nothing and writes nothing there.
#[test]
fn a_launched_photo_set_plays_from_the_launch_and_its_output() {
    let mut storage = FakeBus::default();
    let files = [
        ("capsule.json", b"{}".to_vec()),
        ("images/01.png", png(640, 480, 100)),
        ("images/02.jpg", jpeg(1920, 1080)),
        ("images/03.txt", b"not a picture".to_vec()),
        ("notes.txt", b"not in the album".to_vec()),
    ];
    let mut launch = Launch::of(&mut storage, Some(&files));
    let text = crate::run(&mut launch).expect("the set plays");

    let launch_name = |path: &str| format!("{LAUNCH_CONTENT}{path}");
    assert_eq!(
        launch.asked,
        [
            (LAUNCH_CONTENT_PATTERN.to_string(), "read".to_string()),
            (LAUNCH_OUTPUT_PATTERN.to_string(), "write".to_string()),
        ]
    );
    assert_eq!(
        launch.read.first().map(String::as_str),
        Some(LAUNCH_CONTENT),
        "the listing first"
    );
    assert!(!launch.read.contains(&launch_name("notes.txt")));
    assert_eq!(launch.output.len(), 1);
    assert_eq!(launch.output[LAUNCH_PLAYLIST_URI], text.as_bytes());
    let playlist: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(playlist["album"], LAUNCH_CONTENT);
    let uris: Vec<&str> = playlist["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["uri"].as_str().unwrap())
        .collect();
    assert_eq!(
        uris,
        [launch_name("images/01.png"), launch_name("images/02.jpg")]
    );
    assert_eq!(playlist["skipped"][0]["uri"], launch_name("images/03.txt"));
    assert_eq!(playlist["skipped"][0]["reason"], "wrong_type");
    drop(launch);
    assert!(
        storage.calls.is_empty(),
        "nothing of the person's: {:?}",
        storage.calls
    );
    assert!(storage.written.is_empty());
}

/// Not launched with content: the launch name answers `not_found`, and the
/// album and the playlist are the person's, as before.
#[test]
fn a_run_not_launched_with_content_plays_the_persons_album() {
    let mut storage = FakeBus::default()
        .object(ALBUM_URI, album(json!([{ "uri": A }])))
        .allow(ALBUM_URI, "read")
        .object(A, png(10, 10, 64))
        .allow(A, "read")
        .allow(PLAYLIST_URI, "write");
    let mut launch = Launch::of(&mut storage, None);
    crate::run(&mut launch).expect("the album plays");
    assert_eq!(
        launch.asked,
        [(LAUNCH_CONTENT_PATTERN.to_string(), "read".to_string())]
    );
    assert!(launch.output.is_empty());
    drop(launch);
    assert!(storage.written.contains_key(PLAYLIST_URI));
}

/// Only `not_found` means "not launched with content". Any other answer to
/// the launch request ends the run at once, naming the launch name; the
/// person's album is not asked for and nothing is written anywhere.
#[test]
fn any_other_answer_to_the_launch_question_ends_the_run() {
    for failure in [
        BusFailure::Denied("denied".into()),
        BusFailure::Timeout("timed out".into()),
        BusFailure::Unavailable("unavailable".into()),
        BusFailure::Internal("internal".into()),
        BusFailure::Invalid("invalid".into()),
    ] {
        let mut storage = FakeBus::default()
            .object(ALBUM_URI, album(json!([{ "uri": A }])))
            .allow(ALBUM_URI, "read")
            .allow(PLAYLIST_URI, "write");
        let mut launch = Launch::of(&mut storage, None);
        launch.refuse = Some(failure.clone());
        let refusal = crate::run(&mut launch).unwrap_err();
        assert_eq!(
            refusal,
            Refusal::NoGrant {
                resource: LAUNCH_CONTENT_PATTERN.to_string(),
                failure: failure.clone()
            }
        );
        assert!(launch.output.is_empty());
        drop(launch);
        assert!(storage.calls.is_empty(), "{failure:?}: {:?}", storage.calls);
        assert!(storage.written.is_empty());
    }
}

/// A launched set with no file under `images/`, and one with more than an
/// album holds, are refused before any picture is read; nothing is written.
#[test]
fn a_launched_set_with_no_pictures_or_too_many_is_refused() {
    let many: Vec<(String, Vec<u8>)> = (0..=MAX_ALBUM_ITEMS)
        .map(|index| (format!("images/{index:03}.png"), png(10, 10, 64)))
        .collect();
    let many: Vec<(&str, Vec<u8>)> = many
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.clone()))
        .collect();
    let none = vec![
        ("capsule.json", b"{}".to_vec()),
        ("photo.png", png(10, 10, 64)),
    ];
    for (files, count) in [(none, 0), (many, MAX_ALBUM_ITEMS + 1)] {
        let mut storage = FakeBus::default();
        let mut launch = Launch::of(&mut storage, Some(&files));
        let refusal = crate::run(&mut launch).unwrap_err();
        assert_eq!(
            refusal,
            Refusal::Input(format!(
                "the set holds {count} files under images/; 1 to {MAX_ALBUM_ITEMS} are played"
            ))
        );
        assert_eq!(launch.read, [LAUNCH_CONTENT], "only the listing was read");
        assert!(launch.output.is_empty());
        drop(launch);
        assert!(storage.calls.is_empty());
    }
}
