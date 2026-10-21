//! Proof 1: a resident guest receives events, is asked to stop by closing
//! its events stream, and each ending records a named reason.
mod common;

use std::time::{Duration, Instant};

use bus2_host::{run_resident, BusError, Ending, Event, HostState, Limits, Outcome, Ticker};
use wasmtime::component::Component;

const TICK: Duration = Duration::from_millis(10);
const WATCHDOG: Duration = Duration::from_secs(20);

fn run(
    guest: &'static str,
    limits: Limits,
    events: Vec<Event>,
    hold: Duration,
) -> (Outcome, Duration) {
    common::within(WATCHDOG, async move {
        let engine = bus2_host::engine().unwrap();
        let _ticker = Ticker::start(&engine, TICK);
        let component = Component::new(&engine, common::guest(guest)).unwrap();
        let started = Instant::now();
        let outcome = run_resident(
            &engine,
            &component,
            HostState::default(),
            limits,
            async move |sender| {
                for event in events {
                    sender.send(event);
                }
                tokio::time::sleep(hold).await;
                // `sender` is dropped here: the events stream closes.
            },
        )
        .await
        .unwrap();
        (outcome, started.elapsed())
    })
}

fn texts(outcome: &Outcome) -> Vec<String> {
    outcome
        .state
        .frames
        .iter()
        .map(|frame| String::from_utf8(frame.clone()).unwrap())
        .collect()
}

#[test]
fn a_resident_guest_handles_events_and_stops_when_they_close() {
    let events = vec![
        Event::UserInput(b"hi".to_vec()),
        Event::Message(b"abc".to_vec()),
    ];
    let (outcome, _) = run(
        "bus2_resident_guest",
        Limits::default(),
        events,
        Duration::from_millis(50),
    );
    assert_eq!(outcome.ending, Ending::Stopped);
    assert_eq!(outcome.ending.reason(), "stopped");
    assert_eq!(
        texts(&outcome),
        [
            r#"{"frame":[{"text":"event 1: 2 bytes"}]}"#,
            r#"{"frame":[{"text":"event 2: 3 bytes"}]}"#
        ]
    );
}

#[test]
fn a_guest_that_returns_before_the_close_is_recorded_as_returned() {
    let events = vec![Event::Message(b"return-now".to_vec())];
    let (outcome, _) = run(
        "bus2_resident_guest",
        Limits::default(),
        events,
        Duration::from_secs(2),
    );
    assert_eq!(outcome.ending.reason(), "returned");
}

#[test]
fn a_guest_that_returns_an_error_records_it() {
    let events = vec![Event::Message(b"fail-on-stop".to_vec())];
    let (outcome, _) = run(
        "bus2_resident_guest",
        Limits::default(),
        events,
        Duration::ZERO,
    );
    assert_eq!(
        outcome.ending,
        Ending::ReturnedError(BusError::Internal("asked to fail when stopped".into()))
    );
    assert_eq!(outcome.ending.reason(), "returned-error");
}

#[test]
fn a_guest_that_does_not_return_is_cancelled_after_the_grace_period() {
    let limits = Limits {
        grace: Duration::from_millis(300),
        ..Limits::default()
    };
    let events = vec![Event::Message(b"linger".to_vec())];
    let (outcome, took) = run("bus2_resident_guest", limits, events, Duration::ZERO);
    assert_eq!(outcome.ending.reason(), "cancelled-after-grace");
    assert!(took >= Duration::from_millis(300), "{took:?}");
}

#[test]
fn a_busy_guest_that_yields_each_slice_can_still_be_cancelled() {
    let limits = Limits {
        grace: Duration::from_millis(1000),
        ..Limits::default()
    };
    let (outcome, took) = run("bus2_busy_guest", limits, vec![], Duration::ZERO);
    assert_eq!(outcome.ending.reason(), "cancelled-after-grace");
    assert!(took >= Duration::from_millis(1000), "{took:?}");
}

#[test]
fn a_guest_that_never_awaits_is_ended_at_the_epoch_deadline() {
    let limits = Limits {
        grace: Duration::from_secs(10),
        max_ticks: 20,
        yield_each_tick: false,
        ..Limits::default()
    };
    let (outcome, took) = run("bus2_busy_guest", limits, vec![], Duration::ZERO);
    assert_eq!(outcome.ending, Ending::EpochDeadline);
    assert_eq!(outcome.ending.reason(), "epoch-deadline");
    assert!(took < Duration::from_secs(5), "{took:?}");
}

#[test]
fn a_guest_that_uses_up_a_slice_of_fuel_is_ended() {
    let limits = Limits {
        fuel_per_tick: 10_000,
        fuel_slice: 1_000,
        ..Limits::default()
    };
    let (outcome, _) = run("bus2_busy_guest", limits, vec![], Duration::ZERO);
    assert_eq!(outcome.ending, Ending::FuelExhausted);
    assert_eq!(outcome.ending.reason(), "fuel-exhausted");
}

/// Review change 4: `stop-requested` adds nothing the close cannot do.
#[test]
fn stop_requested_adds_nothing_the_close_cannot_do() {
    // A guest that is sent stop-requested, then more input, keeps running and
    // handles the input; only the close stops it.
    let events = vec![Event::StopRequested, Event::UserInput(b"after".to_vec())];
    let (with_request, _) = run(
        "bus2_resident_guest",
        Limits::default(),
        events,
        Duration::from_millis(200),
    );
    assert_eq!(with_request.ending.reason(), "stopped");
    assert_eq!(
        texts(&with_request),
        [r#"{"frame":[{"text":"event 1: 5 bytes"}]}"#]
    );

    // The close alone stops it the same way.
    let (without, _) = run(
        "bus2_resident_guest",
        Limits::default(),
        vec![],
        Duration::from_millis(50),
    );
    assert_eq!(without.ending.reason(), "stopped");

    // And a guest that never stops on its own is ended by the host whether or
    // not it was sent stop-requested: the request cannot be relied on.
    let limits = Limits {
        grace: Duration::from_millis(200),
        ..Limits::default()
    };
    let events = vec![Event::Message(b"linger".to_vec()), Event::StopRequested];
    let (lingering, _) = run("bus2_resident_guest", limits, events, Duration::ZERO);
    assert_eq!(lingering.ending.reason(), "cancelled-after-grace");
}
