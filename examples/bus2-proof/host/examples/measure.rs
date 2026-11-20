//! Sizes and start-up times for the report. Not a test: the numbers depend
//! on the machine. Build the guests first (`./verify.sh`), then:
//!
//!     cargo run --locked --release -p bus2-host --example measure
#[path = "../tests/common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use bus2_host::{
    run_resident, Ending, Event, HostState, Limits, ProductCapsuleV2, StubObject, Ticker,
};
use wasmtime::component::Component;
use wasmtime::{Engine, Store};

const RUNS: usize = 9;
const GUESTS: [&str; 3] = ["bus2_photo_guest", "bus2_resident_guest", "bus2_busy_guest"];
const PHOTO: &str = "localhost://Users/self/Pictures/a.png";

fn median(mut times: Vec<Duration>) -> Duration {
    times.sort();
    times[times.len() / 2]
}

fn ms(time: Duration) -> String {
    format!("{:.2} ms", time.as_secs_f64() * 1000.0)
}

async fn instantiate(engine: &Engine, component: &Component) {
    let linker = bus2_host::linker(engine).unwrap();
    let mut store = Store::new(engine, HostState::default());
    store.set_fuel(Limits::default().instantiate_fuel).unwrap();
    store.set_epoch_deadline(Limits::default().max_ticks);
    ProductCapsuleV2::instantiate_async(&mut store, component, &linker)
        .await
        .unwrap();
}

/// A 1 MiB PNG-prefixed photo (the photo guest's manifest cap), its licence,
/// and one message to show it.
async fn show_photo(engine: &Engine, component: &Component) -> Duration {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.resize(1024 * 1024, 0x5A);
    let mut state = HostState::default();
    state
        .policy
        .push((PHOTO.to_string(), vec!["read".to_string()]));
    state.credentials.push(common::licence(&bytes));
    state
        .objects
        .insert(PHOTO.to_string(), StubObject::new(bytes));
    let started = Instant::now();
    let outcome = run_resident(
        engine,
        component,
        state,
        Limits::default(),
        async |events| {
            events.send(Event::Message(PHOTO.as_bytes().to_vec()));
        },
    )
    .await
    .unwrap();
    let took = started.elapsed();
    assert_eq!(outcome.ending, Ending::Stopped);
    assert_eq!(outcome.state.frames.len(), 1);
    took
}

async fn measure() {
    let engine = bus2_host::engine().unwrap();
    let _ticker = Ticker::start(&engine, Duration::from_millis(10));
    println!("median of {RUNS} runs");
    println!("| guest | core module | component | compiled | cold start | warm start | instantiate only |");
    println!("|---|---|---|---|---|---|---|");
    for name in GUESTS {
        let core = std::fs::metadata(
            common::root()
                .join("target/wasm32-unknown-unknown/release")
                .join(format!("{name}.wasm")),
        )
        .unwrap()
        .len();
        let bytes = common::guest(name);
        let compiled = Component::new(&engine, &bytes)
            .unwrap()
            .serialize()
            .unwrap();

        let (mut cold, mut warm, mut only) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..RUNS {
            // Cold: compile the component, then instantiate it.
            let started = Instant::now();
            let component = Component::new(&engine, &bytes).unwrap();
            instantiate(&engine, &component).await;
            cold.push(started.elapsed());

            // Warm: load the already-compiled code, then instantiate it.
            let started = Instant::now();
            // SAFETY: the bytes are this engine's own `serialize` output.
            let component = unsafe { Component::deserialize(&engine, &compiled) }.unwrap();
            instantiate(&engine, &component).await;
            warm.push(started.elapsed());

            let started = Instant::now();
            instantiate(&engine, &component).await;
            only.push(started.elapsed());
        }
        println!(
            "| {name} | {core} B | {} B | {} B | {} | {} | {} |",
            bytes.len(),
            compiled.len(),
            ms(median(cold)),
            ms(median(warm)),
            ms(median(only)),
        );
    }

    let photo = Component::new(&engine, common::guest("bus2_photo_guest")).unwrap();
    let mut shows = Vec::new();
    for _ in 0..RUNS {
        shows.push(show_photo(&engine, &photo).await);
    }
    println!(
        "photo guest, already compiled: instantiate, read 1 MiB, check its licence, draw, stop: {}",
        ms(median(shows))
    );
}

fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&runtime, measure());
}
