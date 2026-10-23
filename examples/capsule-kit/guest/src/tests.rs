//! The kit's own tests: the Bus answers, the write, the refusals and their
//! `bus-error`, the reads, the URI check, the text checks and the fake.
//! Moved here from the photo and documents viewers, which had a copy each.

use serde_json::{json, Value};

use crate::bus::{read_window, write_body};
use crate::fake::{Call, FakeBus};
use crate::text::{check_head, check_whole, TextError};
use crate::uri::check_object_uri;
use crate::*;

const A: &str = "localhost://Users/self/Pictures/a.png";
const OUT: &str = "localhost://Users/self/.AppData/App/kit/out.json";
const APP: App = App {
    name: "kit-test",
    input: "list",
    max_input_bytes: 4096,
};

/// A Runtime that grants everything and answers every call with `self.0`.
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

/// A Runtime that refuses every call with `self.0`.
struct Refuses(BusFailure);

impl Bus for Refuses {
    fn request(&mut self, _: &str, _: &str, _: &str) -> Result<String, BusFailure> {
        Err(self.0.clone())
    }

    fn invoke(&mut self, _: &str, _: &str, _: &[u8], _: &str) -> Result<InvokeReply, BusFailure> {
        Err(self.0.clone())
    }
}

/// A Runtime that grants, then refuses every invoke with `self.0`.
struct RefusesInvoke(BusFailure);

impl Bus for RefusesInvoke {
    fn request(&mut self, _: &str, _: &str, _: &str) -> Result<String, BusFailure> {
        Ok("grant".into())
    }

    fn invoke(&mut self, _: &str, _: &str, _: &[u8], _: &str) -> Result<InvokeReply, BusFailure> {
        Err(self.0.clone())
    }
}

fn readable(bytes: &[u8]) -> FakeBus {
    FakeBus::default()
        .object(A, bytes.to_vec())
        .allow(A, "read")
}

// --- Bus answers -----------------------------------------------------------------------

#[test]
fn an_answer_without_byte_content_stops_the_run() {
    for answer in [
        json!({ "status": "ok" }),
        json!({ "status": "ok", "data": {} }),
        json!({ "status": "ok", "data": { "content": "AAEC" } }),
        json!({ "status": "ok", "data": { "content": [1, 2, 300] } }),
        json!({ "status": "pending" }),
    ] {
        let err = read_at(&mut OddAnswers(answer.clone()), A, "grant", 0, 8).unwrap_err();
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
        assert!(matches!(err.to_bus_failure(&APP), BusFailure::Internal(_)));
    }
}

#[test]
fn an_error_answer_that_also_carries_data_is_still_an_error() {
    let answer = json!({
        "status": "error",
        "code": "read_failed",
        "message": "partial",
        "data": { "content": [0x89, 0x50] },
    });
    let err = read_at(&mut OddAnswers(answer), A, "grant", 0, 8).unwrap_err();
    assert!(
        matches!(&err, Refusal::Call { error: CallError::Provider { code, .. }, .. } if code == "read_failed"),
        "{err:?}"
    );
    assert!(matches!(
        err.to_bus_failure(&APP),
        BusFailure::Unavailable(_)
    ));
}

#[test]
fn a_write_answer_without_data_is_refused() {
    // A read with no data is caught by its missing content; a write has no
    // content to miss, so the answer itself must be refused.
    for answer in [json!({ "status": "ok" }), json!({ "status": "pending" })] {
        let err =
            bus::write_bytes(&mut OddAnswers(answer.clone()), OUT, "grant", b"x").unwrap_err();
        assert!(matches!(err, CallError::Shape(_)), "{answer}: {err:?}");
    }
}

#[test]
fn a_read_answer_longer_than_asked_is_refused() {
    let answer = json!({ "status": "ok", "data": { "content": [1, 2, 3, 4] } });
    let err = read_window(&mut OddAnswers(answer), A, "grant", 0, 3).unwrap_err();
    assert!(matches!(err, CallError::Shape(_)), "{err:?}");
}

#[test]
fn a_runtime_denial_of_an_invoke_is_reported_as_denied() {
    let denied = BusFailure::Denied("Capability validation failed".into());
    let err = read_at(&mut RefusesInvoke(denied), A, "grant", 0, 8).unwrap_err();
    assert!(matches!(err.to_bus_failure(&APP), BusFailure::Denied(_)));
}

// --- The write -------------------------------------------------------------------------

#[test]
fn the_write_body_is_the_json_the_provider_takes() {
    let content: Vec<u8> = (0..=255).collect();
    let uri = "localhost://Users/self/Documents/\"q\".md";
    let body = write_body(uri, &content);
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        parsed,
        json!({ "path": uri, "content": content, "append": false })
    );
    assert_eq!(
        body,
        parsed.to_string(),
        "the same bytes as json!, keys sorted"
    );
    assert_eq!(
        write_body("u", b""),
        r#"{"append":false,"content":[],"path":"u"}"#
    );
}

#[test]
fn the_write_is_one_byte_array_with_append_false() {
    let mut bus = FakeBus::default().allow(OUT, "write");
    let id = grant(&mut bus, OUT, "write", "write").unwrap();
    bus::write_bytes(&mut bus, OUT, &id, b"[1]").unwrap();
    let writes: Vec<&Value> = bus
        .calls
        .iter()
        .filter_map(|call| match call {
            Call::Invoke {
                operation, body, ..
            } if operation == "write" => Some(body),
            _ => None,
        })
        .collect();
    assert_eq!(
        writes,
        [&json!({ "path": OUT, "content": b"[1]", "append": false })]
    );
    assert_eq!(bus.written[OUT], "[1]");
}

// --- Refusals --------------------------------------------------------------------------

#[test]
fn every_refusal_names_the_app_and_maps_to_its_bus_error() {
    let failure = |make: fn(String) -> BusFailure| make("why".into());
    let call = |error: CallError| Refusal::Call {
        resource: A.into(),
        error,
    };
    let cases = [
        (
            Refusal::NoGrant {
                resource: A.into(),
                failure: failure(BusFailure::NotFound),
            },
            "denied",
        ),
        (call(CallError::Bus(failure(BusFailure::Denied))), "denied"),
        (
            call(CallError::Bus(failure(BusFailure::NotFound))),
            "not_found",
        ),
        (
            call(CallError::Bus(failure(BusFailure::Timeout))),
            "timeout",
        ),
        (
            call(CallError::Bus(failure(BusFailure::Unavailable))),
            "unavailable",
        ),
        (
            call(CallError::Bus(failure(BusFailure::Invalid))),
            "invalid",
        ),
        (
            call(CallError::Bus(failure(BusFailure::Internal))),
            "internal",
        ),
        (
            call(CallError::Provider {
                code: "read_failed".into(),
                message: "disk gone".into(),
            }),
            "unavailable",
        ),
        (call(CallError::Shape("odd".into())), "internal"),
        (Refusal::InputTooLarge, "invalid"),
        (Refusal::Input("bad".into()), "invalid"),
    ];
    for (refusal, kind) in cases {
        let message = refusal.message(&APP);
        assert!(message.starts_with("kit-test "), "{message}");
        let mapped = match refusal.to_bus_failure(&APP) {
            BusFailure::Denied(m) => ("denied", m),
            BusFailure::NotFound(m) => ("not_found", m),
            BusFailure::Invalid(m) => ("invalid", m),
            BusFailure::Unavailable(m) => ("unavailable", m),
            BusFailure::Timeout(m) => ("timeout", m),
            BusFailure::Internal(m) => ("internal", m),
        };
        assert_eq!(mapped, (kind, message), "{refusal:?}");
    }
    assert_eq!(
        Refusal::InputTooLarge.message(&APP),
        "kit-test list is larger than 4096 bytes"
    );
    assert!(call(CallError::Provider {
        code: "read_failed".into(),
        message: "disk gone".into(),
    })
    .message(&APP)
    .contains("disk gone"));
}

#[test]
fn a_refused_grant_is_no_grant_for_that_resource() {
    let err = grant(
        &mut Refuses(BusFailure::Denied("no".into())),
        A,
        "read",
        "why",
    )
    .unwrap_err();
    assert!(matches!(&err, Refusal::NoGrant { resource, .. } if resource == A));
    assert!(err.message(&APP).contains(A));
}

// --- Reads -----------------------------------------------------------------------------

#[test]
fn a_bounded_read_takes_an_exact_fit_and_refuses_one_byte_more() {
    for size in [
        0,
        1,
        READ_CHUNK_BYTES as usize,
        3 * READ_CHUNK_BYTES as usize + 5,
    ] {
        let bytes: Vec<u8> = (0..size).map(|n| n as u8).collect();
        let mut bus = readable(&bytes);
        let id = grant(&mut bus, A, "read", "").unwrap();
        let limit = size as u64;
        assert_eq!(
            read_bounded(&mut bus, A, &id, Vec::new(), limit).unwrap(),
            Some(bytes.clone()),
            "{size}"
        );
        if size > 0 {
            assert_eq!(
                read_bounded(&mut bus, A, &id, Vec::new(), limit - 1).unwrap(),
                None,
                "{size}"
            );
        }
    }
}

#[test]
fn a_bounded_read_goes_on_from_what_it_was_given() {
    let bytes: Vec<u8> = (0..100u8).collect();
    let mut bus = readable(&bytes);
    let id = grant(&mut bus, A, "read", "").unwrap();
    let head = read_at(&mut bus, A, &id, 0, 10).unwrap();
    assert_eq!(
        read_bounded(&mut bus, A, &id, head, 100).unwrap(),
        Some(bytes)
    );
    assert_eq!(bus.bytes_served(A), 100, "the head is not read again");
}

#[test]
fn every_read_names_a_window_of_at_most_one_chunk() {
    let mut bus = readable(&vec![7; 5 * READ_CHUNK_BYTES as usize]);
    let id = grant(&mut bus, A, "read", "").unwrap();
    read_bounded(&mut bus, A, &id, Vec::new(), 8 * READ_CHUNK_BYTES).unwrap();
    for call in bus.invokes_on(A) {
        let Call::Invoke { body, .. } = call else {
            continue;
        };
        let length = body["length"].as_u64().expect("every read names a length");
        assert!(length <= READ_CHUNK_BYTES, "{body}");
    }
}

#[test]
fn a_counted_read_takes_what_it_returned_off_the_budget() {
    let mut bus = readable(b"0123456789");
    let id = grant(&mut bus, A, "read", "").unwrap();
    let mut left = 32;
    assert_eq!(
        read_counted(&mut bus, A, &id, &mut left, 0, 4).unwrap(),
        b"0123"
    );
    assert_eq!(left, 28);
    // A short answer takes off only what came back.
    assert_eq!(
        read_counted(&mut bus, A, &id, &mut left, 8, 16).unwrap(),
        b"89"
    );
    assert_eq!(left, 26);
    assert_eq!(
        read_counted(&mut bus, A, &id, &mut left, 10, 4).unwrap(),
        b""
    );
    assert_eq!(left, 26);
}

#[test]
#[should_panic(expected = "a read past what the run may read")]
fn a_counted_read_never_asks_past_what_is_left() {
    let mut bus = readable(b"0123456789");
    let id = grant(&mut bus, A, "read", "").unwrap();
    let mut left = 3;
    let _ = read_counted(&mut bus, A, &id, &mut left, 0, 4);
}

// --- The URI check ---------------------------------------------------------------------

#[test]
fn an_input_uri_names_one_object_under_its_folder() {
    let prefix = "localhost://Users/self/Pictures/";
    assert_eq!(check_object_uri(A, prefix), Ok(()));
    assert_eq!(
        check_object_uri("localhost://Users/self/Pictures/trip/b.jpg", prefix),
        Ok(())
    );
    for bad in [
        "localhost://Users/self/Documents/a.png",
        "localhost://Users/other/Pictures/a.png",
        "elastos://object/read",
        "localhost://Users/self/Pictures/",
        "localhost://Users/self/Pictures/trip/",
        "localhost://Users/self/Pictures/../.ssh/id",
        "localhost://Users/self/Pictures/./a.png",
        "localhost://Users/self/Pictures/a//b.png",
        "localhost://Users/self/Pictures/a.png?x=1",
        "localhost://Users/self/Pictures/a.png#x",
        "localhost://Users/self/Pictures/a\\b.png",
        "localhost://Users/self/Pictures/a\nb.png",
    ] {
        assert!(check_object_uri(bad, prefix).is_err(), "{bad}");
    }
}

// --- Text ------------------------------------------------------------------------------

#[test]
fn text_is_utf8_with_no_control_character_but_tab_and_line_ends() {
    assert_eq!(check_whole(b"a\tb\r\nc\n"), Ok("a\tb\r\nc\n"));
    assert_eq!(
        check_whole("caf\u{e9} \u{1f600}".as_bytes()),
        Ok("caf\u{e9} \u{1f600}")
    );
    assert_eq!(
        check_whole(b"\xEF\xBB\xBFtitle"),
        Ok("title"),
        "a UTF-8 BOM goes"
    );
    assert_eq!(check_whole(b"a\0b"), Err(TextError::Control));
    assert_eq!(check_whole(b"a\x1bb"), Err(TextError::Control), "escape");
    assert_eq!(check_whole(b"a\x0cb"), Err(TextError::Control), "form feed");
    assert_eq!(
        check_whole("a\u{85}b".as_bytes()),
        Err(TextError::Control),
        "C1"
    );
    assert_eq!(check_whole(b"a\xffb"), Err(TextError::NotUtf8));
    assert_eq!(check_whole(b"\xFF\xFEa\0"), Err(TextError::OtherEncoding));
    assert_eq!(check_whole(b"\xFE\xFF\0a"), Err(TextError::OtherEncoding));
    assert_eq!(
        check_whole(b"\x00\x00\xFE\xFF"),
        Err(TextError::OtherEncoding)
    );
}

#[test]
fn a_head_may_end_inside_a_character_only_if_the_document_goes_on() {
    let text = "ab\u{e9}".as_bytes();
    let cut = &text[..text.len() - 1];
    assert_eq!(check_head(cut, true), Ok(()));
    assert_eq!(check_head(cut, false), Err(TextError::NotUtf8));
    assert_eq!(
        check_head(b"a\xffb", true),
        Err(TextError::NotUtf8),
        "bad in the middle"
    );
    assert_eq!(check_head(b"ab\0", true), Err(TextError::Control));
    assert_eq!(
        check_head(b"\xFF\xFEa", true),
        Err(TextError::OtherEncoding)
    );
}

// --- The fake --------------------------------------------------------------------------

#[test]
fn the_fake_refuses_bodies_the_localhost_provider_refuses() {
    let mut bus = FakeBus::default()
        .object(A, vec![1, 2, 3])
        .allow(OUT, "write")
        .allow(A, "read");
    let write = bus.request(OUT, "write", "").unwrap();
    let read = bus.request(A, "read", "").unwrap();
    // The same read without the extra field is taken, so each refusal below
    // is for its body alone.
    let good = json!({ "path": A, "offset": 0, "length": 1 });
    let reply = bus
        .invoke(A, "read", good.to_string().as_bytes(), &read)
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap()["status"],
        "ok"
    );
    for (uri, operation, grant, body) in [
        (
            OUT,
            "write",
            &write,
            json!({ "path": OUT, "content": "text", "append": false }),
        ),
        (OUT, "write", &write, json!({ "path": OUT, "content": [1] })),
        (A, "read", &read, json!({ "path": A, "offset": 0 })),
        (
            A,
            "read",
            &read,
            json!({ "path": A, "offset": 0, "length": 1, "token": "t" }),
        ),
    ] {
        let reply = bus
            .invoke(uri, operation, body.to_string().as_bytes(), grant)
            .unwrap();
        assert_eq!(reply.status, "error", "{body}");
    }
}
