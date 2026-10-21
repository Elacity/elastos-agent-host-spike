//! Proof 6: fuel slices plus async yield mean one busy guest cannot starve
//! a second guest in the same host, on one single-threaded executor.
mod common;

use std::time::{Duration, Instant};

use bus2_host::{run_resident, Ending, Event, HostState, Limits, Outcome, StubObject, Ticker};
use wasmtime::component::Component;

const PHOTO: &str = "localhost://Users/self/Pictures/a.png";
const PNG: &[u8] = b"\x89PNG\r\n\x1a\nthe photo";

fn photo_state() -> HostState {
    let mut state = HostState::default();
    state
        .policy
        .push((PHOTO.to_string(), vec!["read".to_string()]));
    state
        .objects
        .insert(PHOTO.to_string(), StubObject::new(PNG.to_vec()));
    state.credentials.push(common::licence(PNG));
    state
}

/// Runs a busy guest and the photo guest side by side on one thread, and
/// returns each outcome with the time it ended.
fn side_by_side() -> ((Outcome, Duration), (Outcome, Duration)) {
    common::within(Duration::from_secs(30), async {
        let engine = bus2_host::engine().unwrap();
        let _ticker = Ticker::start(&engine, Duration::from_millis(10));
        let busy = Component::new(&engine, common::guest("bus2_busy_guest")).unwrap();
        let photo = Component::new(&engine, common::guest("bus2_photo_guest")).unwrap();
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
            // Let the busy guest get going first.
            tokio::time::sleep(Duration::from_millis(50)).await;
            let outcome = run_resident(
                &engine,
                &photo,
                photo_state(),
                Limits::default(),
                async |events| {
                    events.send(Event::Message(PHOTO.as_bytes().to_vec()));
                },
            )
            .await
            .unwrap();
            (outcome, started.elapsed())
        };
        tokio::join!(a, b)
    })
}

#[test]
fn a_busy_guest_does_not_starve_a_second_guest() {
    let ((busy, busy_ended), (photo, photo_ended)) = side_by_side();
    println!("photo guest done after {photo_ended:?}; busy guest ended after {busy_ended:?}");

    // The photo guest did its whole job, and finished long before the busy one.
    assert_eq!(photo.ending, Ending::Stopped);
    assert_eq!(photo.state.frames.len(), 1);
    assert!(photo_ended < busy_ended, "{photo_ended:?} < {busy_ended:?}");
    assert!(photo_ended < Duration::from_millis(900), "{photo_ended:?}");

    // The busy guest ran the whole time on refilled slices, and was ended by
    // its deadline, not by running out of fuel.
    assert_eq!(busy.ending, Ending::EpochDeadline);
    assert!(busy_ended >= Duration::from_millis(900), "{busy_ended:?}");
}
