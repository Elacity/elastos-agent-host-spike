//! Proof 2: providers.invoke streams an object read into the guest in
//! chunks, under a size cap. Above the cap it is refused, never truncated.
mod common;

use std::time::Duration;

use bus2_host::elastos::bus::types::InvokeRequest;
use bus2_host::objects::start_read;
use bus2_host::{
    run_resident, BusError, Ending, Event, HostState, Limits, Outcome, StubObject, Ticker,
    READ_CHUNK,
};
use wasmtime::component::Component;

const PHOTO: &str = "localhost://Users/self/Pictures/a.png";
/// The photo guest's cap, from guests/photo/capsule.json.
const GUEST_CAP: usize = 1_048_576;

fn photo_state(object: StubObject) -> HostState {
    let mut state = HostState::default();
    state
        .policy
        .push((PHOTO.to_string(), vec!["read".to_string()]));
    state.credentials.push(common::licence(&object.bytes));
    state.objects.insert(PHOTO.to_string(), object);
    state
}

/// `len` bytes that start like a PNG, so the host will draw them.
fn bytes(len: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..len).map(|at| (at % 251) as u8).collect();
    let png = b"\x89PNG\r\n\x1a\n";
    let head = png.len().min(len);
    bytes[..head].copy_from_slice(&png[..head]);
    bytes
}

fn show(state: HostState) -> Outcome {
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
                events.send(Event::Message(PHOTO.as_bytes().to_vec()));
                tokio::time::sleep(Duration::from_millis(200)).await;
            },
        )
        .await
        .unwrap()
    })
}

fn refused_with(outcome: &Outcome) -> BusError {
    match &outcome.ending {
        Ending::ReturnedError(error) => error.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_object_at_the_cap_is_read_whole_in_chunks() {
    let outcome = show(photo_state(StubObject::new(bytes(GUEST_CAP))));
    assert_eq!(outcome.ending, Ending::Stopped);
    let read = &outcome.state.reads[0];
    assert_eq!(read.result, Ok(()));
    assert_eq!(read.bytes, GUEST_CAP);
    assert_eq!(read.chunks, GUEST_CAP / READ_CHUNK);
    assert!(read.chunks > 1);
}

#[test]
fn an_object_over_the_cap_is_refused_before_any_byte_is_sent() {
    let outcome = show(photo_state(StubObject::new(bytes(GUEST_CAP + 1))));
    assert_eq!(
        refused_with(&outcome),
        BusError::Invalid(format!(
            "object is {} bytes, over the cap of {GUEST_CAP}",
            GUEST_CAP + 1
        ))
    );
    assert!(outcome.state.reads.is_empty(), "no stream was opened");
}

#[test]
fn an_object_that_grows_past_the_cap_is_refused_and_nothing_partial_is_used() {
    let object = StubObject {
        bytes: bytes(GUEST_CAP - 10),
        grows_by: 100,
    };
    let outcome = show(photo_state(object));
    let reason = BusError::Invalid(format!(
        "object grew past the cap of {GUEST_CAP} bytes while it was read"
    ));
    let read = &outcome.state.reads[0];
    assert_eq!(read.result, Err(reason.clone()));
    assert!(read.bytes <= GUEST_CAP);
    // The guest saw the trailing error and used nothing.
    assert_eq!(refused_with(&outcome), reason);
}

#[test]
fn the_host_cap_applies_whatever_the_guest_asks_for() {
    let mut state = photo_state(StubObject::new(bytes(600 * 1024)));
    state.max_read_bytes = 512 * 1024;
    let outcome = show(state);
    assert_eq!(
        refused_with(&outcome),
        BusError::Invalid(format!(
            "object is {} bytes, over the cap of {}",
            600 * 1024,
            512 * 1024
        ))
    );
}

#[test]
fn a_guest_refuses_more_bytes_than_it_asked_for_even_if_they_arrive() {
    let mut state = photo_state(StubObject::new(bytes(2 * GUEST_CAP)));
    state.ignore_guest_cap = true;
    let outcome = show(state);
    assert_eq!(
        refused_with(&outcome),
        BusError::Invalid(format!(
            "more than the {GUEST_CAP} bytes asked for arrived; none are used"
        ))
    );
}

#[test]
fn a_guest_gets_no_grant_the_policy_does_not_allow() {
    let mut state = photo_state(StubObject::new(bytes(10)));
    state.policy.clear();
    let outcome = show(state);
    assert_eq!(
        refused_with(&outcome),
        BusError::Denied(format!("no policy allows [\"read\"] on {PHOTO}"))
    );
    assert!(outcome.state.reads.is_empty());
}

#[test]
fn the_provider_refuses_a_read_without_the_right_grant_or_params() {
    let mut state = photo_state(StubObject::new(bytes(10)));
    let other = "localhost://Users/self/Pictures/b.png".to_string();
    state.policy.push((other.clone(), vec!["read".to_string()]));
    state
        .policy
        .push((PHOTO.to_string(), vec!["list".to_string()]));
    let for_photo =
        bus2_host::objects::request_grant(&mut state, PHOTO.into(), vec!["read".into()]).unwrap();
    let for_other =
        bus2_host::objects::request_grant(&mut state, other.clone(), vec!["read".into()]).unwrap();
    let list_only =
        bus2_host::objects::request_grant(&mut state, PHOTO.into(), vec!["list".into()]).unwrap();
    let request = |grant: Option<&str>, operation: &str, params: &str| InvokeRequest {
        resource: PHOTO.to_string(),
        operation: operation.to_string(),
        grant: grant.map(str::to_string),
        params: params.as_bytes().to_vec(),
    };
    let good = r#"{"max_bytes":100}"#;
    let refused = |state: &mut HostState, request: InvokeRequest, body: bool| match start_read(
        state, request, body,
    ) {
        Ok(_) => panic!("expected a refusal"),
        Err(error) => error,
    };

    assert!(matches!(
        refused(&mut state, request(None, "read", good), false),
        BusError::Denied(_)
    ));
    assert!(matches!(
        refused(&mut state, request(Some("grant:99"), "read", good), false),
        BusError::Denied(_)
    ));
    assert_eq!(
        refused(
            &mut state,
            request(Some(&for_other.id), "read", good),
            false
        ),
        BusError::Denied(format!("{} is for {other}, not {PHOTO}", for_other.id))
    );
    assert_eq!(
        refused(
            &mut state,
            request(Some(&list_only.id), "read", good),
            false
        ),
        BusError::Denied(format!("{} does not allow read", list_only.id))
    );
    assert!(matches!(
        refused(
            &mut state,
            request(Some(&for_photo.id), "write", good),
            false
        ),
        BusError::Invalid(_)
    ));
    assert!(matches!(
        refused(&mut state, request(Some(&for_photo.id), "read", good), true),
        BusError::Invalid(_)
    ));
    for params in [
        "",
        "[]",
        r#"{"max_bytes":0}"#,
        r#"{"max_bytes":-1}"#,
        r#"{"max_bytes":1,"x":2}"#,
        r#"{"bytes":1}"#,
    ] {
        assert!(
            matches!(
                refused(
                    &mut state,
                    request(Some(&for_photo.id), "read", params),
                    false
                ),
                BusError::Invalid(_)
            ),
            "{params}"
        );
    }
    state.objects.clear();
    assert!(matches!(
        refused(
            &mut state,
            request(Some(&for_photo.id), "read", good),
            false
        ),
        BusError::NotFound(_)
    ));
}
