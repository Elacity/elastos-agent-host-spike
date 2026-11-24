//! Proof 3: ui.present draws one typed document. An image is a grant.
mod common;

use std::time::Duration;

use bus2_host::elastos::bus::ui::{Block, Image, Item, Nested, Span};
use bus2_host::objects::request_grant;
use bus2_host::ui::check_document;
use bus2_host::{
    run_resident, BusError, Event, Frame, HostState, Limits, Node, Outcome, Piece, StubObject,
    Ticker,
};
use wasmtime::component::Component;

const PHOTO: &str = "localhost://Users/self/Pictures/a.png";
const OTHER: &str = "localhost://Users/self/Pictures/b.png";
const NOTES: &str = "localhost://Users/self/Documents/notes.txt";
const PNG: &[u8] = b"\x89PNG\r\n\x1a\nfixture";

fn state() -> HostState {
    let mut state = HostState::default();
    for uri in [PHOTO, OTHER] {
        state
            .policy
            .push((uri.to_string(), vec!["read".to_string()]));
        state
            .objects
            .insert(uri.to_string(), StubObject::new(PNG.to_vec()));
    }
    state
        .policy
        .push((NOTES.to_string(), vec!["read".to_string()]));
    state
        .objects
        .insert(NOTES.to_string(), StubObject::new(b"just text".to_vec()));
    state.credentials.push(common::licence(PNG));
    state
}

fn show(state: HostState, uris: &'static [&'static str]) -> Outcome {
    common::within(Duration::from_secs(30), async move {
        let engine = bus2_host::engine().unwrap();
        let _ticker = Ticker::start(&engine, Duration::from_millis(10));
        let component = Component::new(&engine, common::guest("bus2_photo_guest")).unwrap();
        run_resident(
            &engine,
            &component,
            state,
            Limits::default(),
            async |events| {
                for uri in uris {
                    events.send(Event::Message(uri.as_bytes().to_vec()));
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            },
        )
        .await
        .unwrap()
    })
}

fn plain(text: &str) -> Span {
    Span::Plain(text.to_string())
}

fn image(id: &str) -> Vec<Block> {
    vec![Block::Image(Image {
        grant: id.to_string(),
        alt: String::new(),
    })]
}

#[test]
fn a_good_document_draws_one_frame_that_names_the_image_by_grant() {
    let outcome = show(state(), &[PHOTO]);
    assert_eq!(outcome.ending.reason(), "stopped");
    assert_eq!(
        outcome.state.frames,
        [Frame {
            nodes: vec![
                Node::Image {
                    grant: "grant:1".into(),
                    resource: PHOTO.into(),
                    alt: String::new(),
                },
                Node::Paragraph {
                    spans: vec![Piece {
                        style: "plain".into(),
                        text: format!("{} bytes", PNG.len()),
                    }],
                },
            ]
        }]
    );
}

#[test]
fn a_new_present_replaces_the_frame() {
    let outcome = show(state(), &[PHOTO, OTHER]);
    assert_eq!(outcome.state.frames.len(), 2);
    let on_screen = outcome.state.frames.last().unwrap();
    assert!(matches!(&on_screen.nodes[0], Node::Image { resource, .. } if resource == OTHER));
}

fn refused(state: &HostState, document: &[Block]) -> BusError {
    match check_document(state, document) {
        Ok(frame) => panic!("expected a refusal, drew {frame:?}"),
        Err(error) => error,
    }
}

#[test]
fn a_script_shaped_string_is_text() {
    let state = state();
    let frame = check_document(
        &state,
        &[Block::Paragraph(vec![plain("<script>alert(1)</script>")])],
    )
    .unwrap();
    assert_eq!(
        frame.nodes,
        vec![Node::Paragraph {
            spans: vec![Piece {
                style: "plain".into(),
                text: "<script>alert(1)</script>".into(),
            }],
        }]
    );
}

#[test]
fn an_image_needs_a_held_unrevoked_read_grant_on_an_image() {
    let mut state = state();
    let photo = request_grant(&mut state, PHOTO.into(), vec!["read".into()]).unwrap();
    let other = request_grant(&mut state, OTHER.into(), vec!["read".into()]).unwrap();
    let notes = request_grant(&mut state, NOTES.into(), vec!["read".into()]).unwrap();
    assert!(check_document(&state, &image(&photo.id)).is_ok());
    assert!(check_document(&state, &image(&other.id)).is_ok());
    assert_eq!(
        refused(&state, &image("grant:99")),
        BusError::Denied("grant:99 is not a grant this guest holds".into())
    );
    match refused(&state, &image(&notes.id)) {
        BusError::Denied(why) => assert!(why.contains("is not a PNG, JPEG or WebP image"), "{why}"),
        other => panic!("{other:?}"),
    }
    state.revoked.push(photo.id.clone());
    assert_eq!(
        refused(&state, &image(&photo.id)),
        BusError::Denied(format!("{} was revoked", photo.id))
    );
}

#[test]
fn bounds_refuse_an_empty_document_and_a_long_string() {
    let state = state();
    match refused(&state, &[]) {
        BusError::Invalid(why) => assert!(why.contains("1 to 32"), "{why}"),
        other => panic!("{other:?}"),
    }
    match refused(&state, &[Block::Paragraph(vec![plain(&"x".repeat(1001))])]) {
        BusError::Invalid(why) => assert!(why.contains("1000"), "{why}"),
        other => panic!("{other:?}"),
    }
    let nested = Block::List((
        false,
        vec![Item::Blocks(vec![Nested::List((
            true,
            vec![vec![plain("inside")]],
        ))])],
    ));
    assert!(check_document(&state, &[nested]).is_ok());
}
