//! Pattern 6 for the documents viewer: the reader is a resident Bus v2 guest
//! in the Bus v2 proof's stub host (`examples/bus2-proof/host`). It reads by
//! grant under its own cap, draws with `ui.present`, stops when its events
//! close, and does not starve a second guest.
// The Bus v2 proof's own test helpers (`guest`, `within`), used as they are.
#[path = "../../../../bus2-proof/host/tests/common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use bus2_host::{
    run_resident, BusError, Ending, Event, HostState, Limits, Node, Outcome, StubObject, Ticker,
};
use wasmtime::component::Component;

const NOTES: &str = "localhost://Users/self/Documents/notes.md";
const TODO: &str = "localhost://Users/self/Documents/todo.txt";
const GUEST_CAP: usize = 16 * 1024;

/// A guest built in the Bus v2 proof's own workspace (`verify.sh` builds it),
/// componentized: the proof's busy guest is used as it is.
fn proof_guest(name: &str) -> Vec<u8> {
    let path = common::root()
        .join("../../bus2-proof/target/wasm32-unknown-unknown/release")
        .join(format!("{name}.wasm"));
    let core = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}; build it first (../verify.sh)", path.display()));
    bus2_host::componentize(&core).unwrap()
}

fn reader_state(docs: &[(&str, Vec<u8>)]) -> HostState {
    let mut state = HostState::default();
    for (uri, bytes) in docs {
        state
            .policy
            .push((uri.to_string(), vec!["read".to_string()]));
        state
            .objects
            .insert(uri.to_string(), StubObject::new(bytes.clone()));
    }
    state
}

/// Sends each URI as a message, waits `hold`, then closes the events.
fn read(state: HostState, uris: Vec<&'static str>, hold: Duration) -> (Outcome, Duration) {
    common::within(Duration::from_secs(30), async move {
        let engine = bus2_host::engine().unwrap();
        let _ticker = Ticker::start(&engine, Duration::from_millis(10));
        let component = Component::new(&engine, common::guest("docs_bus2_guest")).unwrap();
        let started = Instant::now();
        let outcome = run_resident(
            &engine,
            &component,
            state,
            Limits::default(),
            async move |events| {
                for uri in uris {
                    events.send(Event::Message(uri.as_bytes().to_vec()));
                }
                tokio::time::sleep(hold).await;
            },
        )
        .await
        .unwrap();
        (outcome, started.elapsed())
    })
}

/// The text of each node of each frame.
fn frames(outcome: &Outcome) -> Vec<Vec<String>> {
    outcome
        .state
        .frames
        .iter()
        .map(|frame| {
            frame
                .nodes
                .iter()
                .map(|node| match node {
                    Node::Text(text) => text.clone(),
                    other => panic!("the reader draws text only, not {other:?}"),
                })
                .collect()
        })
        .collect()
}

#[test]
fn the_guest_imports_only_the_bus_v2_interfaces_it_uses() {
    let imports = bus2_host::admission::check_imports(&common::guest("docs_bus2_guest")).unwrap();
    println!("imports: {imports:?}");
    assert!(imports
        .iter()
        .all(|name| name.starts_with("elastos:bus/") && name.ends_with("@2.0.0")));
    for used in ["capabilities", "providers", "ui"] {
        assert!(
            imports.contains(&format!("elastos:bus/{used}@2.0.0")),
            "{used}"
        );
    }
}

#[test]
fn a_resident_reader_shows_each_document_it_is_sent_and_stops_when_its_events_close() {
    let docs = [
        (NOTES, b"# Trip notes\n\nPack **boots**.\n\n- tent\n- stove\n\n1. drive\n\n> early\n\n---\n\n```\ncode\n```\n".to_vec()),
        (TODO, b"milk\nbread\n\nlater".to_vec()),
    ];
    let (outcome, _) = read(
        reader_state(&docs),
        vec![NOTES, TODO],
        Duration::from_millis(100),
    );
    assert_eq!(outcome.ending, Ending::Stopped);
    assert_eq!(
        frames(&outcome),
        [
            vec![
                "Trip notes",
                "Pack boots.",
                "• tent\n• stove",
                "1. drive",
                "> early",
                "—",
                "code"
            ],
            vec!["milk\nbread", "later"],
        ]
    );
    // One grant per document, read only.
    let granted: Vec<&str> = outcome
        .state
        .grants
        .iter()
        .map(|grant| grant.resource.as_str())
        .collect();
    assert_eq!(granted, [NOTES, TODO]);
    assert!(outcome
        .state
        .grants
        .iter()
        .all(|grant| grant.actions == ["read"]));
}

#[test]
fn markup_in_a_document_is_text_in_the_frame() {
    let hostile = "<script>alert(1)</script> \"quoted\" \\ [x](javascript:y) ![p](http://h/p.png)";
    let (outcome, _) = read(
        reader_state(&[(NOTES, hostile.as_bytes().to_vec())]),
        vec![NOTES],
        Duration::from_millis(50),
    );
    assert_eq!(outcome.ending, Ending::Stopped);
    assert_eq!(
        frames(&outcome),
        [vec![
            "<script>alert(1)</script> \"quoted\" \\ x (javascript:y) [image: p]".to_string()
        ]]
    );
}

#[test]
fn a_document_not_shown_gets_a_frame_that_says_so_and_the_reader_goes_on() {
    let html = "localhost://Users/self/Documents/page.html";
    let binary = "localhost://Users/self/Documents/binary.md";
    let huge = "localhost://Users/self/Documents/huge.md";
    let mut state = reader_state(&[
        (html, b"<p>hi</p>".to_vec()),
        (binary, b"\0\x01\x02".to_vec()),
        (huge, vec![b'a'; GUEST_CAP + 1]),
        (NOTES, b"# kept".to_vec()),
    ]);
    state
        .policy
        .push((html.to_string(), vec!["read".to_string()]));
    let (outcome, _) = read(
        state,
        vec![html, binary, huge, NOTES],
        Duration::from_millis(100),
    );
    assert_eq!(outcome.ending, Ending::Stopped);
    let shown = frames(&outcome);
    assert_eq!(shown.len(), 4);
    assert!(
        shown[0][0].starts_with(&format!("Not shown: {html} is not a .md")),
        "{shown:?}"
    );
    assert!(shown[1][0].contains("is not UTF-8 text"), "{shown:?}");
    // The host refused it before any byte: over the guest's own cap.
    assert!(shown[2][0].contains("over the cap of 16384"), "{shown:?}");
    assert_eq!(shown[3], ["kept"]);
    // The wrong kind is not even asked for.
    assert!(!outcome
        .state
        .grants
        .iter()
        .any(|grant| grant.resource == html));
}

#[test]
fn the_reader_refuses_more_bytes_than_it_asked_for_even_if_they_arrive() {
    let mut state = reader_state(&[(NOTES, vec![b'a'; GUEST_CAP + 1])]);
    state.ignore_guest_cap = true;
    let (outcome, _) = read(state, vec![NOTES], Duration::from_millis(50));
    let shown = frames(&outcome);
    assert!(
        shown[0][0].contains("sent more than the 16384 bytes asked for"),
        "{shown:?}"
    );
}

#[test]
fn nothing_partial_is_shown_when_a_read_fails_at_the_end() {
    let mut state = reader_state(&[(NOTES, b"# grows".to_vec())]);
    // A file still being written: it grows past the cap while it is read.
    state.objects.get_mut(NOTES).unwrap().grows_by = GUEST_CAP;
    let (outcome, _) = read(state, vec![NOTES], Duration::from_millis(50));
    assert_eq!(outcome.ending, Ending::Stopped);
    let shown = frames(&outcome);
    assert_eq!(shown.len(), 1);
    assert!(shown[0][0].contains("grew past the cap"), "{shown:?}");
    assert!(!shown[0].iter().any(|node| node == "grows"), "{shown:?}");
}

#[test]
fn a_refused_grant_ends_the_run_with_its_reason() {
    let mut state = reader_state(&[(NOTES, b"# a".to_vec())]);
    state.policy.clear();
    let (outcome, _) = read(state, vec![NOTES], Duration::from_millis(50));
    match &outcome.ending {
        Ending::ReturnedError(BusError::Denied(why)) => assert!(why.contains(NOTES), "{why}"),
        other => panic!("expected a denied ending, got {other:?}"),
    }
    assert!(outcome.state.frames.is_empty());
}

#[test]
fn a_long_document_is_cut_to_one_frame_and_the_frame_says_so() {
    let long: String = (0..40).map(|n| format!("paragraph {n}\n\n")).collect();
    let (outcome, _) = read(
        reader_state(&[(NOTES, long.into_bytes())]),
        vec![NOTES],
        Duration::from_millis(50),
    );
    assert_eq!(outcome.ending, Ending::Stopped);
    let shown = frames(&outcome);
    assert_eq!(shown[0].len(), 32);
    assert_eq!(shown[0][0], "paragraph 0");
    assert!(
        shown[0][31].starts_with("… 9 more blocks are not shown"),
        "{:?}",
        shown[0][31]
    );
}

#[test]
fn a_busy_guest_does_not_starve_the_reader() {
    let ((busy, busy_ended), (reader, reader_ended)) =
        common::within(Duration::from_secs(30), async {
            let engine = bus2_host::engine().unwrap();
            let _ticker = Ticker::start(&engine, Duration::from_millis(10));
            let busy = Component::new(&engine, proof_guest("bus2_busy_guest")).unwrap();
            let reader = Component::new(&engine, common::guest("docs_bus2_guest")).unwrap();
            let started = Instant::now();
            let busy_limits = Limits {
                max_ticks: 100,
                grace: Duration::from_secs(10),
                ..Limits::default()
            };
            let a = async {
                let outcome = run_resident(
                    &engine,
                    &busy,
                    HostState::default(),
                    busy_limits,
                    async |_events| {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    },
                )
                .await
                .unwrap();
                (outcome, started.elapsed())
            };
            let b = async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let state = reader_state(&[(NOTES, b"# notes\n\ntext".to_vec())]);
                let outcome =
                    run_resident(&engine, &reader, state, Limits::default(), async |events| {
                        events.send(Event::Message(NOTES.as_bytes().to_vec()));
                    })
                    .await
                    .unwrap();
                (outcome, started.elapsed())
            };
            tokio::join!(a, b)
        });
    println!("reader done after {reader_ended:?}; busy guest ended after {busy_ended:?}");
    assert_eq!(reader.ending, Ending::Stopped);
    assert_eq!(reader.state.frames.len(), 1);
    assert!(
        reader_ended < Duration::from_millis(300),
        "{reader_ended:?}"
    );
    assert_eq!(busy.ending, Ending::EpochDeadline);
    assert!(busy_ended >= Duration::from_millis(900), "{busy_ended:?}");
}
