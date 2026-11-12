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

/// The same two guests with the real ticker: the thread that advances the
/// epoch every 10 ms. The photo guest must finish next to the busy one; then
/// the busy guest's events close, and it must be cancelled after its grace
/// period.
///
/// This test is coverage, not a detector. No falsifier names it, and the two
/// counted tests are the ones that catch a missing refill or a missing yield.
/// It asserts on what happened (the endings, who finished first, that ticks
/// arrived). Its three time limits only tell a guest that got its turns from
/// one that was starved, and they are wide on purpose:
/// - the photo guest needs one or two turns, about 5 ms on the machine this
///   was written on. Before each of its turns the busy guest runs for at most
///   one fuel slice (under 1 ms there) or until the next tick. A loaded CI
///   runner a hundred times slower still needs well under a second. The limit
///   is 10 s;
/// - the cancel lands at the busy guest's first yield after the grace period,
///   again one slice or one tick away. The limit is 10 s on top of the grace
///   period;
/// - the watchdog allows 60 s for a run that takes about 0.6 s. The guests
///   are compiled before it starts, because compiling is what a loaded
///   machine slows down most.
///
/// A starved photo guest cannot pass inside those limits. With this budget a
/// busy guest that never yields holds the thread for more than 30 s on a
/// fast machine and longer on a slow one, so the photo guest is late for its
/// 10 s, or the watchdog ends the test.
#[test]
fn with_the_real_ticker_a_busy_guest_lets_a_second_guest_finish_and_is_then_cancelled() {
    const GRACE: Duration = Duration::from_millis(500);
    const PHOTO_DUE: Duration = Duration::from_millis(50);
    const PHOTO_WITHIN: Duration = Duration::from_secs(10);
    const CANCEL_WITHIN: Duration = Duration::from_secs(10);

    let engine = bus2_host::engine().unwrap();
    let busy = Component::new(&engine, common::guest("bus2_busy_guest")).unwrap();
    let photo = Component::new(&engine, common::guest("bus2_photo_guest")).unwrap();
    // Neither guest is ended by a deadline here: only what the test is about
    // can end them. The busy guest's budget is a hundred times the default,
    // so a ticker thread that is late by whole seconds on a loaded machine
    // does not end it as fuel-exhausted.
    let busy_limits = Limits {
        grace: GRACE,
        max_ticks: u64::MAX,
        fuel_per_tick: 100 * Limits::default().fuel_per_tick,
        ..Limits::default()
    };
    let photo_limits = Limits {
        grace: Duration::from_secs(30),
        max_ticks: u64::MAX,
        ..Limits::default()
    };

    let ((busy, closed_at, busy_ended), (photo, photo_ended)) =
        common::within(Duration::from_secs(60), async move {
            let _ticker = Ticker::start(&engine, Duration::from_millis(10));
            let (photo_is_done, photo_done) = tokio::sync::oneshot::channel::<()>();
            let started = Instant::now();
            let a = async {
                let mut closed_at = None;
                let outcome = run_resident(
                    &engine,
                    &busy,
                    HostState::default(),
                    busy_limits,
                    async |_events| {
                        // Hold the events open until the photo guest is done.
                        let _ = photo_done.await;
                        closed_at = Some(started.elapsed());
                        // `_events` is dropped here: the events stream closes.
                    },
                )
                .await
                .unwrap();
                (outcome, closed_at, started.elapsed())
            };
            let b = async {
                // Let the busy guest get going first.
                tokio::time::sleep(PHOTO_DUE).await;
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
                let ended = started.elapsed();
                let _ = photo_is_done.send(());
                (outcome, ended)
            };
            tokio::join!(a, b)
        });
    println!(
        "real ticker: photo guest done after {photo_ended:?}; busy guest's events closed after \
         {closed_at:?}; it ended after {busy_ended:?} ({} yields, {} ticks)",
        busy.yields, busy.ticks
    );

    // The photo guest did its whole job while the busy guest was running.
    assert_eq!(photo.ending, Ending::Stopped);
    assert_eq!(photo.state.frames.len(), 1);
    let closed_at = closed_at.expect("the busy guest's events were closed");
    assert!(photo_ended <= closed_at, "{photo_ended:?} <= {closed_at:?}");
    assert!(photo_ended < PHOTO_DUE + PHOTO_WITHIN, "{photo_ended:?}");

    // The busy guest was still running then, saw real ticks, and was ended
    // by the cancel after its grace period, not by fuel or by a deadline.
    assert!(busy.started);
    assert_eq!(busy.ending, Ending::CancelledAfterGrace);
    assert!(busy.ticks >= 1, "{} ticks", busy.ticks);
    let after_close = busy_ended - closed_at;
    assert!(after_close >= GRACE, "{after_close:?}");
    assert!(after_close < GRACE + CANCEL_WITHIN, "{after_close:?}");
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
