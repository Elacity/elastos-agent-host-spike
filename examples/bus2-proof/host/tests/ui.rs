//! Proof 3: ui.present draws one frame from one declarative document,
//! images by granted handle, no script.
mod common;

use std::time::Duration;

use bus2_host::objects::request_grant;
use bus2_host::ui::check_document;
use bus2_host::{
    run_resident, BusError, Event, Frame, HostState, Limits, Node, Outcome, StubObject, Ticker,
    UI_MEDIA_TYPE,
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
                    resource: PHOTO.into()
                },
                Node::Text(format!("{} bytes", PNG.len())),
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

fn refused(state: &HostState, media_type: &str, document: &str) -> BusError {
    match check_document(state, media_type, document.as_bytes()) {
        Ok(frame) => panic!("expected a refusal, drew {frame:?}"),
        Err(error) => {
            println!("refused: {error:?}");
            error
        }
    }
}

fn invalid_with(error: BusError, part: &str) {
    match error {
        BusError::Invalid(why) => assert!(why.contains(part), "{why:?} should say {part:?}"),
        other => panic!("expected invalid, got {other:?}"),
    }
}

#[test]
fn a_document_with_script_or_handlers_is_refused() {
    let state = state();
    let no_script = "scripts and event handlers are not allowed";
    invalid_with(
        refused(
            &state,
            UI_MEDIA_TYPE,
            r#"{"frame":[{"script":"alert(1)"}]}"#,
        ),
        no_script,
    );
    invalid_with(
        refused(
            &state,
            UI_MEDIA_TYPE,
            r#"{"frame":[{"text":"hi","onclick":"x"}]}"#,
        ),
        no_script,
    );
    invalid_with(
        refused(
            &state,
            UI_MEDIA_TYPE,
            r#"{"frame":[{"image":{"grant":"grant:1","onload":"x"}}]}"#,
        ),
        no_script,
    );
    invalid_with(
        refused(&state, UI_MEDIA_TYPE, r#"{"frame":[{"html":"<b>hi</b>"}]}"#),
        "never by a URI or bytes",
    );
}

#[test]
fn an_image_by_uri_or_bytes_is_refused() {
    let state = state();
    for document in [
        r#"{"frame":[{"image":{"uri":"localhost://Users/self/Pictures/a.png"}}]}"#,
        r#"{"frame":[{"image":{"src":"https://example.com/a.png"}}]}"#,
        r#"{"frame":[{"image":{"bytes":"iVBORw0KGgo="}}]}"#,
    ] {
        invalid_with(
            refused(&state, UI_MEDIA_TYPE, document),
            "never by a URI or bytes",
        );
    }
}

#[test]
fn an_image_needs_a_held_unrevoked_read_grant_on_an_image() {
    let mut state = state();
    let photo = request_grant(&mut state, PHOTO.into(), vec!["read".into()]).unwrap();
    let notes = request_grant(&mut state, NOTES.into(), vec!["read".into()]).unwrap();
    let image = |id: &str| format!(r#"{{"frame":[{{"image":{{"grant":"{id}"}}}}]}}"#);

    assert!(check_document(&state, UI_MEDIA_TYPE, image(&photo.id).as_bytes()).is_ok());
    assert_eq!(
        refused(&state, UI_MEDIA_TYPE, &image("grant:99")),
        BusError::Denied("grant:99 is not a grant this guest holds".into())
    );
    invalid_with(
        refused(&state, UI_MEDIA_TYPE, &image(&notes.id)),
        "is not a PNG, JPEG or WebP image",
    );
    state.revoked.push(photo.id.clone());
    assert_eq!(
        refused(&state, UI_MEDIA_TYPE, &image(&photo.id)),
        BusError::Denied(format!("{} was revoked", photo.id))
    );
}

#[test]
fn a_document_that_is_not_the_one_format_is_refused() {
    let state = state();
    let good = r#"{"frame":[{"text":"hi"}]}"#;
    invalid_with(refused(&state, "text/html", good), "media type");
    invalid_with(
        refused(&state, "application/vnd.elastos.ui+json;v=1", good),
        "media type",
    );
    invalid_with(
        refused(
            &state,
            UI_MEDIA_TYPE,
            r#"{"frame":[{"text":"hi"}],"style":"x"}"#,
        ),
        "unknown field",
    );
    invalid_with(
        refused(
            &state,
            UI_MEDIA_TYPE,
            r#"{"frame":[{"video":{"grant":"grant:1"}}]}"#,
        ),
        "unknown variant",
    );
    invalid_with(
        refused(&state, UI_MEDIA_TYPE, r#"{"frame":[],"frame":[]}"#),
        "duplicate field",
    );
    invalid_with(
        refused(&state, UI_MEDIA_TYPE, r#"{"frame":[]}"#),
        "1 to 32 nodes",
    );
    invalid_with(refused(&state, UI_MEDIA_TYPE, "not json"), "not JSON");
    let long = format!(r#"{{"frame":[{{"text":"{}"}}]}}"#, "x".repeat(1001));
    invalid_with(
        refused(&state, UI_MEDIA_TYPE, &long),
        "at most 1000 characters",
    );
    let big = format!(r#"{{"frame":[{{"text":"{}"}}]}}"#, " ".repeat(17 * 1024));
    invalid_with(refused(&state, UI_MEDIA_TYPE, &big), "byte limit");
}
