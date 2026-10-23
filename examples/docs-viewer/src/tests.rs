use serde_json::{json, Value};

use crate::*;
use capsule_kit_guest::fake::{Call, FakeBus};

const A: &str = "localhost://Users/self/Documents/notes.md";
const B: &str = "localhost://Users/self/Documents/trip/todo.txt";
const C: &str = "localhost://Users/self/Documents/readme.markdown";

fn shelf(items: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({ "schema": SHELF_SCHEMA, "items": items })).unwrap()
}

/// A shelf of `docs`, every read allowed, and the pages write allowed.
fn granted(docs: &[(&str, Vec<u8>)]) -> FakeBus {
    let items: Vec<Value> = docs.iter().map(|(uri, _)| json!({ "uri": uri })).collect();
    let mut bus = FakeBus::default()
        .object(SHELF_URI, shelf(Value::Array(items)))
        .allow(SHELF_URI, "read")
        .allow(PAGES_URI, "write");
    for (uri, bytes) in docs {
        bus = bus.object(uri, bytes.clone()).allow(uri, "read");
    }
    bus
}

fn written(bus: &FakeBus) -> Value {
    serde_json::from_str(bus.written.get(PAGES_URI).expect("pages written")).unwrap()
}

fn assert_nothing_written(bus: &FakeBus) {
    assert!(bus.written.is_empty(), "no pages may be written");
    assert!(
        bus.invokes_on(PAGES_URI).is_empty(),
        "no write may be attempted"
    );
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

fn doc(n: usize) -> String {
    format!("localhost://Users/self/Documents/{n}.md")
}

/// `size` bytes of markdown text.
fn text_of(size: usize) -> Vec<u8> {
    let mut bytes = b"# Long\n\n".to_vec();
    while bytes.len() < size {
        bytes.extend_from_slice(b"word ");
    }
    bytes.truncate(size);
    bytes
}

#[test]
fn a_shelf_is_read_and_its_pages_are_written() {
    let md = b"# Trip notes\n\nPack **boots** and a `map`.\n\n- tent\n- stove\n".to_vec();
    let txt = b"Buy milk\nCall Ann\n\nLater: taxes".to_vec();
    let mut bus = granted(&[(A, md.clone()), (B, txt.clone())]);
    let text = run(&mut bus).unwrap();
    let pages = written(&bus);
    assert_eq!(text, bus.written[PAGES_URI]);
    assert_eq!(
        pages,
        json!({
            "schema": PAGES_SCHEMA,
            "shelf": SHELF_URI,
            "documents": [
                {
                    "order": 0, "uri": A, "mime": "text/markdown", "title": "Trip notes",
                    "bytes": md.len(),
                    "blocks": [
                        { "kind": "heading", "level": 1, "spans": [{ "style": "plain", "text": "Trip notes" }] },
                        { "kind": "paragraph", "spans": [
                            { "style": "plain", "text": "Pack " },
                            { "style": "strong", "text": "boots" },
                            { "style": "plain", "text": " and a " },
                            { "style": "code", "text": "map" },
                            { "style": "plain", "text": "." },
                        ] },
                        { "kind": "list", "ordered": false, "items": [
                            [{ "style": "plain", "text": "tent" }],
                            [{ "style": "plain", "text": "stove" }],
                        ] },
                    ],
                },
                {
                    "order": 1, "uri": B, "mime": "text/plain", "title": "Buy milk",
                    "bytes": txt.len(),
                    "blocks": [
                        { "kind": "paragraph", "spans": [{ "style": "plain", "text": "Buy milk\nCall Ann" }] },
                        { "kind": "paragraph", "spans": [{ "style": "plain", "text": "Later: taxes" }] },
                    ],
                },
            ],
            "skipped": [],
        })
    );
    // Keys are sorted, so the same shelf always writes the same bytes.
    let mut again = granted(&[(A, md), (B, txt)]);
    assert_eq!(run(&mut again).unwrap(), text);
}

#[test]
fn every_object_gets_its_own_grant_with_one_action() {
    let mut bus = granted(&[(A, b"# a".to_vec()), (B, b"b".to_vec())]);
    run(&mut bus).unwrap();
    let requests: Vec<(String, String)> = bus
        .calls
        .iter()
        .filter_map(|call| match call {
            Call::Request { resource, action } => Some((resource.clone(), action.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        requests,
        [
            (SHELF_URI.to_string(), "read".to_string()),
            (A.to_string(), "read".to_string()),
            (B.to_string(), "read".to_string()),
            (PAGES_URI.to_string(), "write".to_string()),
        ]
    );
}

#[test]
fn every_read_names_a_window_of_at_most_one_chunk() {
    let mut bus = granted(&[(A, text_of(12 * 1024))]);
    run(&mut bus).unwrap();
    for call in &bus.calls {
        if let Call::Invoke {
            operation, body, ..
        } = call
        {
            if operation == "read" {
                let length = body["length"].as_u64().expect("a read names a length");
                assert!(length <= READ_CHUNK_BYTES, "{body}");
                assert!(body["offset"].is_u64(), "{body}");
            }
        }
    }
}

#[test]
fn shelf_without_a_read_grant_stops_before_any_read() {
    let mut bus = FakeBus::default()
        .object(SHELF_URI, shelf(json!([{ "uri": A }])))
        .allow(PAGES_URI, "write");
    let err = run(&mut bus).unwrap_err();
    assert!(matches!(&err, Refusal::NoGrant { resource, .. } if resource == SHELF_URI));
    assert!(matches!(err.to_bus_failure(&APP), BusFailure::Denied(_)));
    assert!(bus.invokes_on(SHELF_URI).is_empty());
    assert_nothing_written(&bus);
}

#[test]
fn document_without_a_read_grant_stops_the_run_and_is_not_skipped() {
    let mut bus = granted(&[(A, b"# a".to_vec()), (B, b"b".to_vec())]);
    bus.allowed.remove(&(A.to_string(), "read".to_string()));
    let err = run(&mut bus).unwrap_err();
    assert!(matches!(&err, Refusal::NoGrant { resource, .. } if resource == A));
    assert!(err.message(&APP).contains(A));
    assert!(bus.invokes_on(A).is_empty());
    assert!(bus.invokes_on(B).is_empty(), "the run stops at the first");
    assert_nothing_written(&bus);
}

#[test]
fn pages_without_a_write_grant_stops_and_is_not_written() {
    let mut bus = granted(&[(A, b"# a".to_vec())]);
    bus.allowed
        .remove(&(PAGES_URI.to_string(), "write".to_string()));
    let err = run(&mut bus).unwrap_err();
    assert!(matches!(&err, Refusal::NoGrant { resource, .. } if resource == PAGES_URI));
    assert_nothing_written(&bus);
}

#[test]
fn a_provider_error_stops_the_run_and_is_not_skipped() {
    let mut bus = granted(&[(A, b"# a".to_vec()), (B, b"b".to_vec())]).provider_error(
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
fn a_missing_document_stops_the_run() {
    let mut bus = granted(&[(A, b"# a".to_vec())]);
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
fn malformed_shelves_stop_before_any_document_is_read() {
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (b"not json".to_vec(), "not JSON"),
        (b"[]".to_vec(), "JSON object"),
        (
            serde_json::to_vec(&json!({ "schema": SHELF_SCHEMA, "items": [{ "uri": A }], "x": 1 }))
                .unwrap(),
            "unknown field",
        ),
        (
            serde_json::to_vec(&json!({ "schema": "elastos.photo-viewer.album/v1", "items": [] }))
                .unwrap(),
            "schema",
        ),
        (shelf(json!([])), "no items"),
        (
            shelf(Value::Array(
                (0..=MAX_SHELF_ITEMS)
                    .map(|n| json!({ "uri": doc(n) }))
                    .collect(),
            )),
            "the limit is",
        ),
        (shelf(json!([{ "uri": A, "title": "x" }])), "unknown field"),
        (shelf(json!([{ "uri": 7 }])), "uri must be a string"),
        (
            shelf(json!([{ "uri": "localhost://Users/self/Pictures/a.md" }])),
            "must start with",
        ),
        (
            shelf(json!([{ "uri": "localhost://Users/self/Documents/../secret.md" }])),
            ". or .. segments",
        ),
        (
            shelf(json!([{ "uri": "localhost://Users/self/Documents/a//b.md" }])),
            ". or .. segments",
        ),
        (
            shelf(json!([{ "uri": "localhost://Users/self/Documents/a.md?x" }])),
            "control characters",
        ),
        (
            shelf(json!([{ "uri": "localhost://Users/self/Documents/" }])),
            "not a folder",
        ),
    ];
    for (bytes, expected) in cases {
        let mut bus = granted(&[(A, b"# a".to_vec())]).object(SHELF_URI, bytes);
        let err = run(&mut bus).unwrap_err();
        let message = err.message(&APP);
        assert!(matches!(err, Refusal::Input(_)), "{message}");
        assert!(
            message.contains(expected),
            "{message} should say {expected}"
        );
        assert!(bus.invokes_on(A).is_empty(), "{message}");
        assert_nothing_written(&bus);
    }
}

#[test]
fn a_shelf_over_its_cap_stops() {
    let padding = " ".repeat(MAX_SHELF_BYTES as usize);
    let bytes = format!(r#"{{"schema":"{SHELF_SCHEMA}","items":[{{"uri":"{A}"}}]}}{padding}"#);
    let mut bus = granted(&[(A, b"# a".to_vec())]).object(SHELF_URI, bytes.into_bytes());
    let err = run(&mut bus).unwrap_err();
    assert_eq!(err, Refusal::InputTooLarge);
    assert_nothing_written(&bus);
    // Exactly at the cap is still read.
    let fits = format!(r#"{{"schema":"{SHELF_SCHEMA}","items":[{{"uri":"{A}"}}]}}"#);
    let fits = format!(
        "{fits}{}",
        " ".repeat(MAX_SHELF_BYTES as usize - fits.len())
    );
    let mut bus = granted(&[(A, b"# a".to_vec())]).object(SHELF_URI, fits.into_bytes());
    run(&mut bus).unwrap();
}

#[test]
fn content_failures_are_skipped_and_listed_and_the_rest_are_shown_in_order() {
    let html = "localhost://Users/self/Documents/page.html";
    let empty = "localhost://Users/self/Documents/empty.md";
    let binary = "localhost://Users/self/Documents/binary.md";
    let utf16 = "localhost://Users/self/Documents/utf16.txt";
    let late = "localhost://Users/self/Documents/late.md";
    let huge = "localhost://Users/self/Documents/huge.md";
    let blocks = "localhost://Users/self/Documents/blocks.md";
    let mut late_bytes = text_of(2000);
    late_bytes[1500] = 0xff;
    let docs = [
        (html, b"<p>hi</p>".to_vec()),
        (empty, Vec::new()),
        (binary, b"PK\x03\x04\0\0zip".to_vec()),
        (utf16, b"\xFF\xFEh\0i\0".to_vec()),
        (A, b"# kept".to_vec()),
        (late, late_bytes),
        (huge, text_of(MAX_DOCUMENT_BYTES as usize + 1)),
        (
            blocks,
            "x\n\n".repeat(docs_model::MAX_BLOCKS + 1).into_bytes(),
        ),
    ];
    let mut bus = granted(&docs);
    run(&mut bus).unwrap();
    assert_eq!(
        skipped(&bus),
        [
            (0, html.to_string(), "wrong_kind".to_string()),
            (1, empty.to_string(), "empty".to_string()),
            (2, binary.to_string(), "not_text".to_string()),
            (3, utf16.to_string(), "not_text".to_string()),
            (5, late.to_string(), "not_text".to_string()),
            (6, huge.to_string(), "oversize".to_string()),
            (7, blocks.to_string(), "too_long".to_string()),
        ]
    );
    let pages = written(&bus);
    let shown: Vec<u64> = pages["documents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|document| document["order"].as_u64().unwrap())
        .collect();
    assert_eq!(shown, [4]);
    let messages: Vec<&str> = pages["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|skip| skip["message"].as_str().unwrap())
        .collect();
    assert!(messages[3].contains("UTF-16"), "{messages:?}");
    assert!(messages[5].contains("16384"), "{messages:?}");
    // The wrong kind is skipped from its name: no grant, no read.
    assert!(!bus
        .calls
        .iter()
        .any(|call| matches!(call, Call::Request { resource, .. } if resource == html)));
    assert!(bus.invokes_on(html).is_empty());
}

#[test]
fn a_binary_head_and_an_oversize_document_are_found_without_reading_the_body() {
    let binary = "localhost://Users/self/Documents/binary.md";
    let mut binary_bytes = b"\0\0\0\0".to_vec();
    binary_bytes.extend(text_of(MAX_DOCUMENT_BYTES as usize));
    let huge = "localhost://Users/self/Documents/huge.md";
    let mut bus = granted(&[
        (binary, binary_bytes),
        (huge, text_of(4 * MAX_DOCUMENT_BYTES as usize)),
    ]);
    run(&mut bus).unwrap();
    assert_eq!(bus.bytes_served(binary), HEAD_BYTES);
    // The head, and the one byte past the limit.
    assert_eq!(bus.bytes_served(huge), HEAD_BYTES + 1);
}

#[test]
fn exactly_the_cap_is_shown_and_one_byte_more_is_not() {
    let fits = "localhost://Users/self/Documents/fits.md";
    let over = "localhost://Users/self/Documents/over.md";
    let mut bus = granted(&[
        (fits, text_of(MAX_DOCUMENT_BYTES as usize)),
        (over, text_of(MAX_DOCUMENT_BYTES as usize + 1)),
    ]);
    run(&mut bus).unwrap();
    assert_eq!(
        skipped(&bus),
        [(1, over.to_string(), "oversize".to_string())]
    );
    assert_eq!(written(&bus)["documents"][0]["bytes"], MAX_DOCUMENT_BYTES);
}

#[test]
fn a_shelf_stops_taking_documents_at_its_budget_without_reading_the_one_that_would_pass_it() {
    let full = MAX_DOCUMENT_BYTES as usize;
    let docs: Vec<(String, Vec<u8>)> = vec![
        (doc(0), text_of(full)),
        (doc(1), text_of(full)),
        (doc(2), text_of(full)),
        (doc(3), b"# small".to_vec()),
    ];
    let refs: Vec<(&str, Vec<u8>)> = docs.iter().map(|(u, b)| (u.as_str(), b.clone())).collect();
    let mut bus = granted(&refs);
    run(&mut bus).unwrap();
    assert_eq!(
        MAX_SHELF_TEXT_BYTES as usize,
        2 * full,
        "this test fills the budget with two documents"
    );
    assert_eq!(
        skipped(&bus),
        [
            (2, doc(2), "shelf_full".to_string()),
            (3, doc(3), "shelf_full".to_string()),
        ]
    );
    // The budget is spent, so the third and fourth are not read at all.
    assert_eq!(bus.bytes_served(&doc(2)), 0);
    assert_eq!(bus.bytes_served(&doc(3)), 0);
}

/// Every byte served for the documents of a shelf.
fn served(bus: &FakeBus, docs: &[(String, Vec<u8>)]) -> u64 {
    docs.iter().map(|(uri, _)| bus.bytes_served(uri)).sum()
}

#[test]
fn a_short_document_that_is_not_text_still_counts_toward_the_shelf_budget() {
    // Codex's shelf: six short heads of NULs, then two full text documents.
    let full = MAX_DOCUMENT_BYTES as usize;
    let mut docs: Vec<(String, Vec<u8>)> = (0..6)
        .map(|n| (doc(n), vec![0; HEAD_BYTES as usize - 1]))
        .collect();
    docs.push((doc(6), text_of(full)));
    docs.push((doc(7), text_of(full)));
    let refs: Vec<(&str, Vec<u8>)> = docs.iter().map(|(u, b)| (u.as_str(), b.clone())).collect();
    let mut bus = granted(&refs);
    run(&mut bus).unwrap();
    assert!(
        served(&bus, &docs) <= MAX_SHELF_TEXT_BYTES,
        "{} bytes read",
        served(&bus, &docs)
    );
    let reasons: Vec<String> = skipped(&bus)
        .into_iter()
        .map(|(_, _, reason)| reason)
        .collect();
    assert_eq!(reasons, [vec!["not_text"; 6], vec!["shelf_full"]].concat());
    assert_eq!(written(&bus)["documents"].as_array().unwrap().len(), 1);
}

#[test]
fn no_shelf_reads_more_than_its_budget() {
    // Every mix of short skipped heads and full documents, in either order.
    let full = MAX_DOCUMENT_BYTES as usize;
    for short in 0..=MAX_SHELF_ITEMS {
        for size in [
            1,
            HEAD_BYTES as usize - 1,
            HEAD_BYTES as usize,
            HEAD_BYTES as usize + 1,
        ] {
            for first in [true, false] {
                let mut docs: Vec<(String, Vec<u8>)> = Vec::new();
                for n in 0..MAX_SHELF_ITEMS {
                    let is_short = if first {
                        n < short
                    } else {
                        n >= MAX_SHELF_ITEMS - short
                    };
                    let bytes = if is_short {
                        vec![0; size]
                    } else {
                        text_of(full)
                    };
                    docs.push((doc(n), bytes));
                }
                let refs: Vec<(&str, Vec<u8>)> =
                    docs.iter().map(|(u, b)| (u.as_str(), b.clone())).collect();
                let mut bus = granted(&refs);
                run(&mut bus).unwrap();
                let read = served(&bus, &docs);
                assert!(
                    read <= MAX_SHELF_TEXT_BYTES,
                    "{short} short of {size} bytes, first {first}: {read} bytes read"
                );
            }
        }
    }
}

#[test]
fn a_head_that_ends_inside_a_character_is_still_text() {
    let mut bytes = vec![b'a'; HEAD_BYTES as usize - 1];
    bytes.extend_from_slice("\u{e9} and more".as_bytes());
    let mut bus = granted(&[(A, bytes.clone())]);
    run(&mut bus).unwrap();
    assert_eq!(written(&bus)["documents"][0]["bytes"], bytes.len());
}

#[test]
fn markup_and_links_in_a_document_stay_text() {
    let hostile = "<script>alert(1)</script> [x](javascript:alert(2)) ![p](http://h/p.png)";
    let mut bus = granted(&[(A, hostile.as_bytes().to_vec())]);
    run(&mut bus).unwrap();
    let blocks = &written(&bus)["documents"][0]["blocks"];
    assert_eq!(
        blocks,
        &json!([{ "kind": "paragraph", "spans": [{ "style": "plain",
            "text": "<script>alert(1)</script> x (javascript:alert(2)) [image: p]" }] }])
    );
}

#[test]
fn every_output_block_has_one_of_six_shapes_and_only_text() {
    let doc = "# h\n\npara *em*\n\n- a\n\n1. b\n\n> q\n\n***\n\n```\ncode\n```\n";
    let mut bus = granted(&[(A, doc.as_bytes().to_vec())]);
    run(&mut bus).unwrap();
    let blocks = written(&bus)["documents"][0]["blocks"].clone();
    let kinds: Vec<&str> = blocks
        .as_array()
        .unwrap()
        .iter()
        .map(|block| block["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "heading",
            "paragraph",
            "list",
            "list",
            "quote",
            "rule",
            "code"
        ]
    );
    for block in blocks.as_array().unwrap() {
        let keys: Vec<&String> = block.as_object().unwrap().keys().collect();
        let allowed: &[&str] = match block["kind"].as_str().unwrap() {
            "heading" => &["kind", "level", "spans"],
            "paragraph" | "quote" => &["kind", "spans"],
            "list" => &["items", "kind", "ordered"],
            "code" => &["kind", "text"],
            "rule" => &["kind"],
            other => panic!("unknown kind {other}"),
        };
        assert_eq!(keys, allowed.iter().collect::<Vec<_>>(), "{block}");
    }
}

#[test]
fn the_shelf_and_a_markdown_name_are_case_insensitive_kinds_only() {
    let mut bus = granted(&[(C, b"Read me\n=======\n".to_vec())]);
    run(&mut bus).unwrap();
    assert_eq!(written(&bus)["documents"][0]["title"], "Read me");
    assert_eq!(written(&bus)["documents"][0]["mime"], "text/markdown");
}

#[test]
fn a_document_skipped_after_it_was_read_still_counts_toward_the_shelf_budget() {
    let full = MAX_DOCUMENT_BYTES as usize;
    let mut not_text = text_of(full);
    not_text[full - 1] = 0;
    let too_long = format!("{}x", "x\n\n".repeat(docs_model::MAX_BLOCKS)).into_bytes();
    let docs: Vec<(String, Vec<u8>)> = vec![
        (doc(0), not_text),
        (doc(1), too_long.clone()),
        (doc(2), text_of(full)),
    ];
    let refs: Vec<(&str, Vec<u8>)> = docs.iter().map(|(u, b)| (u.as_str(), b.clone())).collect();
    let mut bus = granted(&refs);
    run(&mut bus).unwrap();
    assert_eq!(
        skipped(&bus),
        [
            (0, doc(0), "not_text".to_string()),
            (1, doc(1), "too_long".to_string()),
            (2, doc(2), "shelf_full".to_string()),
        ]
    );
    assert_eq!(bus.bytes_served(&doc(0)), MAX_DOCUMENT_BYTES);
    assert_eq!(bus.bytes_served(&doc(1)), too_long.len() as u64);
    assert_eq!(bus.bytes_served(&doc(2)), HEAD_BYTES + 1);
}

#[test]
fn the_write_is_one_byte_array_with_append_false() {
    let mut bus = granted(&[(A, b"# a".to_vec())]);
    let text = run(&mut bus).unwrap();
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
        [&json!({ "path": PAGES_URI, "content": text.as_bytes(), "append": false })]
    );
}

#[test]
fn the_pages_text_is_the_sorted_json_of_its_value() {
    let mut bus = granted(&[
        (A, b"# T \"1\"\n\n- a\n\n> q".to_vec()),
        ("localhost://Users/self/Documents/x.pdf", b"%PDF".to_vec()),
    ]);
    let text = run(&mut bus).unwrap();
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(text, value.to_string(), "sorted keys, no whitespace");
}

#[test]
fn a_document_that_renders_past_what_a_shelf_may_show_is_skipped() {
    // One-character code spans render to about eight times their size.
    let spans = |paragraphs: usize| -> Vec<u8> {
        format!("{}\n\n", "`a` ".repeat(120))
            .repeat(paragraphs)
            .into_bytes()
    };
    let big = spans(30); // about 14 KiB, renders past 64 KiB on its own
    let half = spans(4); // about 28 KiB rendered, under half of it
    let docs: Vec<(String, Vec<u8>)> = vec![
        (doc(0), big),
        (doc(1), half.clone()),
        (doc(2), half.clone()),
        (doc(3), half),
    ];
    let refs: Vec<(&str, Vec<u8>)> = docs.iter().map(|(u, b)| (u.as_str(), b.clone())).collect();
    let mut bus = granted(&refs);
    let text = run(&mut bus).unwrap();
    assert_eq!(
        skipped(&bus),
        [
            (0, doc(0), "too_long".to_string()),
            (3, doc(3), "shelf_full".to_string()),
        ]
    );
    assert!(text.len() as u64 <= MAX_PAGES_BYTES, "{}", text.len());
}

/// One-character code spans render to about eight times their size: one
/// paragraph of `full` lines of 120, then one of `tail`.
fn code_spans(full: usize, tail: usize) -> Vec<u8> {
    let mut text = format!("{}\n\n", "`a` ".repeat(120)).repeat(full);
    if tail > 0 {
        text.push_str(&"`a` ".repeat(tail));
    }
    text.into_bytes()
}

/// The size of a document's blocks, as the core renders them.
fn rendered_size(bytes: &[u8]) -> usize {
    let text = std::str::from_utf8(bytes).unwrap();
    let blocks = docs_model::blocks(docs_model::Kind::Markdown, text).unwrap();
    let mut out = vec![b'['];
    for (index, block) in blocks.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        docs_model::write_block(&mut out, block);
    }
    out.push(b']');
    out.len()
}

#[test]
fn a_document_whose_blocks_fit_but_whose_pages_would_not_is_skipped() {
    // Codex's case: the blocks fit under the cap, the pages around them do not.
    let uri = format!("localhost://Users/self/Documents/{}.md", "n".repeat(600));
    let frame = pages_json(&[], &[]).len();
    let tail = (0..120)
        .find(|&tail| rendered_size(&code_spans(9, tail)) > MAX_PAGES_BYTES as usize - frame - 400)
        .expect("a size just under the cap");
    let bytes = code_spans(9, tail);
    assert!(rendered_size(&bytes) < MAX_PAGES_BYTES as usize - frame);
    let mut bus = granted(&[(uri.as_str(), bytes)]);
    let text = run(&mut bus).unwrap();
    assert!(text.len() as u64 <= MAX_PAGES_BYTES, "{}", text.len());
    assert_eq!(skipped(&bus), [(0, uri, "shelf_full".to_string())]);
}

#[test]
fn no_pages_are_longer_than_their_cap() {
    // Six skipped items with long names and two documents, the skipped ones
    // first or last; the second document grows a span at a time past what fits.
    let skips: Vec<(String, Vec<u8>)> = (0..6)
        .map(|n| {
            let name = format!(
                "localhost://Users/self/Documents/{n}{}.pdf",
                "s".repeat(380)
            );
            (name, b"%PDF".to_vec())
        })
        .collect();
    for skips_first in [true, false] {
        let mut shown_at_least_once = false;
        let mut skipped_at_least_once = false;
        let sizes = (4..=5).flat_map(|full| (0..=120).map(move |tail| (full, tail)));
        for (full, tail) in sizes {
            let documents = vec![(doc(6), code_spans(4, 0)), (doc(7), code_spans(full, tail))];
            let docs: Vec<(String, Vec<u8>)> = if skips_first {
                [skips.clone(), documents].concat()
            } else {
                [documents, skips.clone()].concat()
            };
            let refs: Vec<(&str, Vec<u8>)> =
                docs.iter().map(|(u, b)| (u.as_str(), b.clone())).collect();
            let mut bus = granted(&refs);
            let text = run(&mut bus).unwrap();
            assert!(
                text.len() as u64 <= MAX_PAGES_BYTES,
                "skipped first {skips_first}, {full} lines and {tail}: {}",
                text.len()
            );
            if skipped(&bus).iter().any(|(_, uri, _)| *uri == doc(7)) {
                skipped_at_least_once = true;
            } else {
                shown_at_least_once = true;
            }
        }
        assert!(
            shown_at_least_once && skipped_at_least_once,
            "skipped first {skips_first}: the sweep crosses the cap"
        );
    }
}

/// The pages of a shelf with every block kind, every skip the surface lists,
/// and hostile text, as the core writes them. The surface tests read this
/// file (`surface/fixtures/pages.json`), so both sides are held to one format.
/// Run with `DOCS_VIEWER_WRITE_FIXTURE=1` to write it again.
#[test]
fn the_surface_fixture_is_what_the_core_writes() {
    let hostile = "# <img src=x onerror=\"fetch('/api/apps/home/state')\">\n\n\
                   Read [the guide](javascript:fetch('/x')) and ![a cat](http://h/c.png).\n\n\
                   <script>alert(1)</script>\n";
    let kinds = "# Trip notes\n\nPack **boots**, *socks* and a `map`.\n\n- tent\n- stove\n\n\
                 1. drive\n2. walk\n\n> Leave early.\n\n---\n\n```\nfn go() {}\n```\n";
    let mut bus = granted(&[
        (A, kinds.as_bytes().to_vec()),
        (
            "localhost://Users/self/Documents/page.html",
            b"<p>hi</p>".to_vec(),
        ),
        (B, b"milk\nbread\n\nlater".to_vec()),
        (
            "localhost://Users/self/Documents/hostile.md",
            hostile.as_bytes().to_vec(),
        ),
        (
            "localhost://Users/self/Documents/binary.md",
            b"\0\x01".to_vec(),
        ),
    ]);
    let text = run(&mut bus).unwrap();
    let pretty = serde_json::to_string_pretty(&serde_json::from_str::<Value>(&text).unwrap())
        .unwrap()
        + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("surface/fixtures/pages.json");
    if std::env::var_os("DOCS_VIEWER_WRITE_FIXTURE").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &pretty).unwrap();
    }
    let checked_in = std::fs::read_to_string(&path).expect("surface/fixtures/pages.json");
    assert_eq!(
        checked_in, pretty,
        "the core writes other pages than the surface is tested with"
    );
}
