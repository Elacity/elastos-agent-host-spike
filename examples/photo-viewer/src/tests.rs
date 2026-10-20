use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::fake::{Call, FakeBus};
use crate::*;

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
    let items = playlist["items"].as_array().unwrap();
    let summary: Vec<_> = items
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
}

#[test]
fn playlist_records_the_size_and_sha256_of_the_bytes_read() {
    let bytes = png(10, 20, 100_000);
    let mut bus = granted(&[(A, bytes.clone())]);
    run(&mut bus).unwrap();
    let item = &written(&bus)["items"][0];
    assert_eq!(item["bytes"], bytes.len() as u64);
    let expected: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(item["sha256"], expected);
    // 100 000 bytes need four 32 KiB reads; each stays under the bridge frame.
    assert!(bus.invokes_on(A).iter().all(|call| match call {
        Call::Invoke { body, .. } => body["length"].as_u64().unwrap() <= READ_CHUNK_BYTES,
        _ => true,
    }));
}

#[test]
fn every_webp_frame_header_gives_its_dimensions() {
    let mut bus = granted(&[
        (A, webp_vp8x(1, 16384)),
        (B, webp_vp8l(300, 200)),
        (C, webp_vp8(1024, 768)),
    ]);
    // VP8X 1x16384 is over the side limit; check the other two first.
    let err = run(&mut bus).unwrap_err();
    assert!(matches!(
        err,
        Refusal::Dimensions {
            index: 0,
            width: 1,
            height: 16384,
            ..
        }
    ));

    let mut bus = granted(&[(B, webp_vp8l(300, 200)), (C, webp_vp8(1024, 768))]);
    run(&mut bus).unwrap();
    let items = written(&bus)["items"].clone();
    assert_eq!(
        (items[0]["width"].clone(), items[0]["height"].clone()),
        (json!(300), json!(200))
    );
    assert_eq!(
        (items[1]["width"].clone(), items[1]["height"].clone()),
        (json!(1024), json!(768))
    );
}

#[test]
fn playlist_text_is_the_same_on_every_run() {
    let objects = [(A, png(1, 1, 64)), (B, jpeg(2, 3))];
    let mut first = granted(&objects);
    let mut second = granted(&objects);
    assert_eq!(run(&mut first).unwrap(), run(&mut second).unwrap());
}

// --- grants -----------------------------------------------------------------

#[test]
fn album_without_a_read_grant_is_denied_before_any_read() {
    let mut bus = granted(&[(A, png(1, 1, 64))]);
    bus.allowed
        .remove(&(ALBUM_URI.to_string(), "read".to_string()));

    let err = run(&mut bus).unwrap_err();
    assert!(matches!(&err, Refusal::NoGrant { resource, .. } if resource == ALBUM_URI));
    assert!(matches!(err.to_bus_failure(), BusFailure::Denied(_)));
    assert!(
        bus.invokes_on(ALBUM_URI).is_empty(),
        "album must not be read"
    );
    assert!(bus.invokes_on(A).is_empty());
    assert_nothing_written(&bus);
}

#[test]
fn image_without_a_read_grant_is_denied_before_any_read_of_it() {
    let mut bus = granted(&[(A, png(1, 1, 64)), (B, jpeg(2, 2)), (C, webp_vp8l(3, 3))]);
    bus.allowed.remove(&(B.to_string(), "read".to_string()));

    let err = run(&mut bus).unwrap_err();
    assert!(matches!(&err, Refusal::NoGrant { resource, .. } if resource == B));
    assert!(matches!(err.to_bus_failure(), BusFailure::Denied(_)));
    assert!(
        bus.invokes_on(B).is_empty(),
        "denied image must not be read"
    );
    assert!(
        bus.invokes_on(C).is_empty(),
        "the run stops at the first refusal"
    );
    assert_nothing_written(&bus);
}

#[test]
fn playlist_without_a_write_grant_is_denied_and_not_written() {
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

// --- type -------------------------------------------------------------------

#[test]
fn wrong_type_is_refused_and_the_body_is_not_read() {
    for bytes in [
        b"GIF89a\x01\x00\x01\x00\x00\x00\x00".to_vec(),
        b"just some text, not an image".to_vec(),
        b"RIFF\x10\x00\x00\x00WAVEfmt ".to_vec(),
        vec![0u8; 64],
    ] {
        let mut padded = bytes.clone();
        padded.resize(200_000, b'x');
        let mut bus = granted(&[(A, padded)]);
        let err = run(&mut bus).unwrap_err();
        assert!(
            matches!(&err, Refusal::WrongType { index: 0, uri } if uri == A),
            "{bytes:?}: {err:?}"
        );
        assert!(matches!(err.to_bus_failure(), BusFailure::Invalid(_)));
        assert_eq!(bus.bytes_served(A), HEADER_BYTES, "only the header is read");
        assert_nothing_written(&bus);
    }
}

#[test]
fn one_bad_item_stops_the_whole_album() {
    let mut bus = granted(&[
        (A, png(1, 1, 64)),
        (B, b"not an image at all".to_vec()),
        (C, webp_vp8l(2, 2)),
    ]);
    let err = run(&mut bus).unwrap_err();
    assert!(matches!(err, Refusal::WrongType { index: 1, .. }));
    assert!(bus.invokes_on(C).is_empty());
    assert_nothing_written(&bus);
}

// --- truncated header ---------------------------------------------------------

#[test]
fn truncated_magic_is_refused() {
    for bytes in [
        vec![],
        b"\x89PN".to_vec(),
        b"\x89PNG\r\n\x1a".to_vec(),
        vec![0xff, 0xd8],
        b"RIFF\x10\x00".to_vec(),
        b"RIFF\x10\x00\x00\x00WE".to_vec(),
    ] {
        let mut bus = granted(&[(A, bytes.clone())]);
        let err = run(&mut bus).unwrap_err();
        assert!(
            matches!(&err, Refusal::Truncated { index: 0, uri } if uri == A),
            "{bytes:?}: {err:?}"
        );
        assert_nothing_written(&bus);
    }
}

#[test]
fn image_cut_before_its_size_field_is_truncated() {
    let mut png_cut = png(640, 480, 0);
    png_cut.truncate(20);
    let mut jpeg_cut = jpeg(640, 480);
    jpeg_cut.truncate(24);
    let mut vp8x_cut = webp_vp8x(640, 480);
    vp8x_cut.truncate(27);
    let mut vp8l_cut = webp_vp8l(640, 480);
    vp8l_cut.truncate(22);
    for bytes in [png_cut, jpeg_cut, vp8x_cut, vp8l_cut] {
        let mut bus = granted(&[(A, bytes.clone())]);
        let err = run(&mut bus).unwrap_err();
        assert!(
            matches!(&err, Refusal::Truncated { index: 0, .. }),
            "{bytes:?}: {err:?}"
        );
        assert_nothing_written(&bus);
    }
}

#[test]
fn malformed_headers_are_refused() {
    let mut no_ihdr = png(1, 1, 64);
    no_ihdr[12..16].copy_from_slice(b"IDAT");
    let mut jpeg_scan_first = vec![0xff, 0xd8, 0xff, 0xda, 0x00, 0x08];
    jpeg_scan_first.resize(64, 0);
    for bytes in [png(0, 10, 64), png(10, 0, 64), no_ihdr, jpeg_scan_first] {
        let mut bus = granted(&[(A, bytes.clone())]);
        let err = run(&mut bus).unwrap_err();
        assert!(
            matches!(&err, Refusal::Malformed { index: 0, .. }),
            "{bytes:?}: {err:?}"
        );
        assert_nothing_written(&bus);
    }
}

// --- size -------------------------------------------------------------------

#[test]
fn oversize_is_refused_without_reading_the_body() {
    let mut bus = granted(&[(A, png(10, 10, MAX_OBJECT_BYTES as usize + 1))]);
    let err = run(&mut bus).unwrap_err();
    assert!(matches!(&err, Refusal::Oversize { index: 0, uri } if uri == A));
    assert!(matches!(err.to_bus_failure(), BusFailure::Invalid(_)));
    assert_eq!(
        bus.bytes_served(A),
        HEADER_BYTES + 1,
        "only the header and one byte past the limit are read"
    );
    assert_nothing_written(&bus);
}

#[test]
fn an_object_of_exactly_the_size_limit_plays() {
    let mut bus = granted(&[(A, png(10, 10, MAX_OBJECT_BYTES as usize))]);
    run(&mut bus).unwrap();
    assert_eq!(written(&bus)["items"][0]["bytes"], MAX_OBJECT_BYTES);
}

#[test]
fn album_larger_than_its_limit_is_refused() {
    let mut bus = granted(&[(A, png(1, 1, 64))]);
    let mut big = album(json!([{ "uri": A }]));
    big.resize(MAX_ALBUM_BYTES as usize + 1, b' ');
    bus.objects.insert(ALBUM_URI.to_string(), big);
    let err = run(&mut bus).unwrap_err();
    assert_eq!(err, Refusal::AlbumTooLarge);
    assert!(bus.invokes_on(A).is_empty());
    assert_nothing_written(&bus);
}

// --- dimensions ---------------------------------------------------------------

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
        let result = run(&mut bus);
        assert_eq!(result.is_ok(), plays, "{width}x{height}: {result:?}");
        if !plays {
            assert!(matches!(result, Err(Refusal::Dimensions { .. })));
            assert_nothing_written(&bus);
        }
    }
}

// --- album shape ----------------------------------------------------------------

#[test]
fn malformed_albums_are_refused_before_any_image_is_read() {
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
        assert!(matches!(err, Refusal::Album(_)), "{name}: {err:?}");
        assert!(
            matches!(err.to_bus_failure(), BusFailure::Invalid(_)),
            "{name}"
        );
        assert!(bus.invokes_on(A).is_empty(), "{name}: no image may be read");
        assert_nothing_written(&bus);
    }
}

// --- Runtime answers -------------------------------------------------------------

#[test]
fn a_provider_error_answer_is_a_refusal_not_data() {
    let mut bus = granted(&[(A, png(1, 1, 64))]).provider_error(A, "read_failed", "disk gone");
    let err = run(&mut bus).unwrap_err();
    assert!(matches!(
        &err,
        Refusal::Call { resource, error: CallError::Provider { code, .. } } if resource == A && code == "read_failed"
    ));
    assert!(matches!(err.to_bus_failure(), BusFailure::Unavailable(_)));
    assert!(err.message().contains("disk gone"));
    assert_nothing_written(&bus);
}

#[test]
fn a_missing_object_is_a_refusal() {
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

/// A Runtime that answers every read with something other than bytes.
struct OddAnswers(Value);

impl Bus for OddAnswers {
    fn request(&mut self, _: &str, _: &str, _: &str) -> Result<String, BusFailure> {
        Ok("grant".into())
    }

    fn invoke(&mut self, _: &str, _: &str, _: &[u8], _: &str) -> Result<InvokeReply, BusFailure> {
        Ok(InvokeReply {
            status: "ok".into(),
            body: serde_json::to_vec(&self.0).unwrap(),
        })
    }
}

#[test]
fn an_answer_without_byte_content_is_refused() {
    for answer in [
        json!({ "status": "ok" }),
        json!({ "status": "ok", "data": {} }),
        json!({ "status": "ok", "data": { "content": "AAEC" } }),
        json!({ "status": "ok", "data": { "content": [1, 2, 300] } }),
        json!({ "status": "pending" }),
    ] {
        let err = run(&mut OddAnswers(answer.clone())).unwrap_err();
        assert!(
            matches!(
                &err,
                Refusal::Call {
                    error: CallError::Shape(_),
                    ..
                }
            ),
            "{answer}: {err:?}"
        );
        assert!(matches!(err.to_bus_failure(), BusFailure::Internal(_)));
    }
}

#[test]
fn a_read_answer_longer_than_asked_is_refused() {
    let answer = json!({ "status": "ok", "data": { "content": [1, 2, 3, 4] } });
    let err = crate::bus::read_window(&mut OddAnswers(answer), A, "grant", 0, 3).unwrap_err();
    assert!(matches!(err, CallError::Shape(_)), "{err:?}");
}

#[test]
fn a_runtime_denial_of_an_invoke_is_reported_as_denied() {
    struct DeniesInvoke;
    impl Bus for DeniesInvoke {
        fn request(&mut self, _: &str, _: &str, _: &str) -> Result<String, BusFailure> {
            Ok("grant".into())
        }
        fn invoke(
            &mut self,
            _: &str,
            _: &str,
            _: &[u8],
            _: &str,
        ) -> Result<InvokeReply, BusFailure> {
            Err(BusFailure::Denied("Capability validation failed".into()))
        }
    }
    let err = run(&mut DeniesInvoke).unwrap_err();
    assert!(matches!(err.to_bus_failure(), BusFailure::Denied(_)));
}

// --- album body budget ------------------------------------------------------------

#[test]
fn album_whose_images_exceed_the_body_budget_is_refused_at_the_item_that_crosses_it() {
    let half = MAX_ALBUM_BODY_BYTES as usize / 2;
    let mut bus = granted(&[
        (A, png(1, 1, half)),
        (B, png(1, 1, half)),
        (C, png(1, 1, 1)),
    ]);
    // A and B fill the budget exactly; C has no bytes left.
    let err = run(&mut bus).unwrap_err();
    assert!(
        matches!(&err, Refusal::AlbumBodyBudget { index: 2, uri } if uri == C),
        "{err:?}"
    );
    assert!(matches!(err.to_bus_failure(), BusFailure::Invalid(_)));
    assert!(err.message().contains("the most one run can check"));
    assert_eq!(
        bus.bytes_served(C),
        HEADER_BYTES + 1,
        "only C's header and one byte past the budget are read"
    );
    assert_nothing_written(&bus);
}

#[test]
fn album_that_fills_the_body_budget_exactly_plays() {
    let half = MAX_ALBUM_BODY_BYTES as usize / 2;
    let mut bus = granted(&[(A, png(1, 1, half)), (B, png(1, 1, half))]);
    run(&mut bus).unwrap();
    assert_eq!(written(&bus)["items"].as_array().unwrap().len(), 2);
}

#[test]
fn an_oversize_object_is_reported_as_oversize_even_when_the_budget_is_low() {
    let mut bus = granted(&[
        (A, png(1, 1, MAX_ALBUM_BODY_BYTES as usize - 10)),
        (B, png(1, 1, MAX_OBJECT_BYTES as usize + 1)),
    ]);
    let err = run(&mut bus).unwrap_err();
    assert!(matches!(err, Refusal::Oversize { index: 1, .. }), "{err:?}");
}

#[test]
fn an_error_answer_that_also_carries_data_is_still_an_error() {
    let answer = json!({
        "status": "error",
        "code": "read_failed",
        "message": "partial",
        "data": { "content": [0x89, 0x50] },
    });
    let err = run(&mut OddAnswers(answer)).unwrap_err();
    assert!(
        matches!(&err, Refusal::Call { error: CallError::Provider { code, .. }, .. } if code == "read_failed"),
        "{err:?}"
    );
}
