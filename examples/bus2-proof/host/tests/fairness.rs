//! Proof 6: fuel slices plus async yield mean one busy guest cannot starve
//! a second guest in the same host, on one single-threaded executor.
mod common;

use std::time::{Duration, Instant};

use bus2_host::{run_resident, Ending, Event, HostState, Limits, Outcome, StubObject, Ticker};
use wasmtime::component::Component;

const PHOTO: &str = "localhost://Users/self/Pictures/a.png";
const PNG: &[u8] = b"\x89PNG\r\n\x1a\nthe photo";

/// The photo guest shows one photo and stops. Returns its outcome and how
/// long it took from its own start.
async fn show_photo(engine: &wasmtime::Engine, photo: &Component) -> (Outcome, Duration) {
    let started = Instant::now();
    let outcome = run_resident(
        engine,
        photo,
        photo_state(),
        Limits::default(),
        async |events| {
            events.send(Event::Message(PHOTO.as_bytes().to_vec()));
        },
    )
    .await
    .unwrap();
    (outcome, started.elapsed())
}

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

/// Counted, not timed: the test below runs on a clock it moves by hand
/// (`HandClock`), one tick for every 4 turns of the two guests together, so
/// its result is the same on a fast machine, a slow one and a loaded one.
/// In 3 turns of every 4 the busy guest uses up a fuel slice; in the fourth
/// it yields because its tick asks it to. So it uses 3 slices a tick, of a
/// budget of 40, and its 100 ticks take 300 slices: more than seven budgets.
const TURNS_PER_TICK: u64 = 4;
const BUSY_BUDGET_IN_SLICES: u64 = 40;
const BUSY_MAX_TICKS: u64 = 100;
/// The photo guest starts at this tick, once the busy guest is going.
const PHOTO_STARTS_AT_TICK: u64 = 2;

/// Runs a busy guest and the photo guest side by side on one thread, and
/// returns each outcome with the tick at which it ended.
fn side_by_side() -> ((Outcome, u64), (Outcome, u64)) {
    common::within(Duration::from_secs(30), async {
        let engine = bus2_host::engine().unwrap();
        let clock = common::HandClock::new(&engine, TURNS_PER_TICK);
        let busy = Component::new(&engine, common::guest("bus2_busy_guest")).unwrap();
        let photo = Component::new(&engine, common::guest("bus2_photo_guest")).unwrap();
        let busy_limits = Limits {
            max_ticks: BUSY_MAX_TICKS,
            fuel_per_tick: BUSY_BUDGET_IN_SLICES * Limits::default().fuel_slice,
            ..Limits::default()
        };
        // The photo guest is given all the time it needs after its events
        // close: this proof is about turns, not about its grace period.
        let photo_limits = Limits {
            grace: Duration::from_secs(20),
            ..Limits::default()
        };
        let a = async {
            let outcome = run_resident(
                &engine,
                &busy,
                HostState::default(),
                busy_limits,
                // Its events never close: only its deadline ends it.
                async |_events| std::future::pending::<()>().await,
            )
            .await
            .unwrap();
            (outcome, clock.ticks())
        };
        let b = async {
            // Let the busy guest get going first.
            clock.at_tick(PHOTO_STARTS_AT_TICK).await;
            let outcome = run_resident(
                &engine,
                &photo,
                photo_state(),
                photo_limits,
                async |events| {
                    events.send(Event::Message(PHOTO.as_bytes().to_vec()));
                },
            )
            .await
            .unwrap();
            (outcome, clock.ticks())
        };
        clock.run(async { tokio::join!(a, b) }).await
    })
}

#[test]
fn a_busy_guest_does_not_starve_a_second_guest() {
    let ((busy, busy_ended), (photo, photo_ended)) = side_by_side();
    println!(
        "photo guest done at tick {photo_ended} ({} yields); busy guest ended at tick \
         {busy_ended} ({} yields, {} ticks)",
        photo.yields, busy.yields, busy.ticks
    );

    // The photo guest did its whole job, and finished long before the busy one.
    assert_eq!(photo.ending, Ending::Stopped);
    assert_eq!(photo.state.frames.len(), 1);
    assert!(photo_ended < busy_ended, "{photo_ended} < {busy_ended}");
    // It started at tick 2 of the busy guest's 100, and may be at most ten
    // ticks late.
    assert!(
        photo_ended <= PHOTO_STARTS_AT_TICK + 10,
        "tick {photo_ended}"
    );

    // The busy guest ran all its ticks, and was ended by its deadline, not by
    // running out of fuel.
    assert_eq!(busy.ending, Ending::EpochDeadline);
    assert_eq!(busy.ticks, BUSY_MAX_TICKS + 1);
    assert!(busy_ended >= BUSY_MAX_TICKS, "tick {busy_ended}");
    // It ran on refilled slices. At most one yield a tick was asked for by
    // the tick; every other one was a used-up slice, and those came to more
    // than seven budgets. Without the refill it ends fuel-exhausted after one.
    let slices = busy.yields.saturating_sub(busy.ticks);
    assert!(slices > 7 * BUSY_BUDGET_IN_SLICES, "{slices} slices");
}

#[test]
fn a_guest_stuck_in_start_up_does_not_delay_a_second_guest() {
    let ((stuck, stuck_ended), (photo, photo_took, photo_ended), alone) =
        common::within(Duration::from_secs(30), async {
            let engine = bus2_host::engine().unwrap();
            let _ticker = Ticker::start(&engine, Duration::from_millis(10));
            let looping = Component::new(&engine, common::guest("bus2_start_loop_guest")).unwrap();
            let photo = Component::new(&engine, common::guest("bus2_photo_guest")).unwrap();

            // The photo guest alone, for comparison.
            let (_, alone) = show_photo(&engine, &photo).await;

            let started = Instant::now();
            // Start-up never ends and its fuel budget is out of reach: only the
            // epoch deadline (about 1 s) ends it.
            let stuck_limits = Limits {
                instantiate_fuel: 1 << 50,
                max_ticks: 100,
                grace: Duration::from_secs(10),
                ..Limits::default()
            };
            let a = async {
                let outcome = run_resident(
                    &engine,
                    &looping,
                    HostState::default(),
                    stuck_limits,
                    async |_events| {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    },
                )
                .await
                .unwrap();
                (outcome, started.elapsed())
            };
            let b = async {
                // Let the stuck guest get into its start-up first.
                tokio::time::sleep(Duration::from_millis(50)).await;
                let (outcome, took) = show_photo(&engine, &photo).await;
                (outcome, took, started.elapsed())
            };
            let (a, b) = tokio::join!(a, b);
            (a, b, alone)
        });
    println!(
        "photo guest alone {alone:?}; next to a stuck start-up {photo_took:?} \
         (done at {photo_ended:?}); stuck guest ended at {stuck_ended:?}"
    );

    // The photo guest did its whole job while the other guest was stuck in
    // start-up, not after it.
    assert_eq!(photo.ending, Ending::Stopped);
    assert_eq!(photo.state.frames.len(), 1);
    assert!(
        photo_ended < stuck_ended,
        "{photo_ended:?} < {stuck_ended:?}"
    );
    // It was due to start at 50 ms. Its own clock starts only when it first
    // gets a turn, so the bound is on the shared clock: at most 100 ms (ten
    // ticks) late, where waiting for the stuck guest's start-up is about 1 s.
    assert!(photo_ended < Duration::from_millis(150), "{photo_ended:?}");

    // The stuck guest never got past start-up, and was ended by its deadline.
    assert!(!stuck.started);
    assert_eq!(stuck.ending.reason(), "epoch-deadline");
    assert!(stuck_ended >= Duration::from_millis(900), "{stuck_ended:?}");
}
