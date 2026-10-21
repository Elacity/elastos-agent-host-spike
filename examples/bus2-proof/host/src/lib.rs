//! A stub host for the guest-side Bus v2 proof. Not the Runtime: it runs only
//! inside this folder's tests, with test-set policy, objects and credentials.
//!
//! Every operation has one path:
//! - an object is read only through `providers.invoke` (`read`, with a grant);
//! - a guest is asked to stop only by closing its events stream.
//!
//! Every refusal is a `bus-error` naming what was expected.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wasmtime::component::{HasSelf, Linker};
use wasmtime::Result;
use wasmtime::{Config, Engine};

pub mod admission;
mod imports;
pub mod objects;
pub mod run;

wasmtime::component::bindgen!({
    path: "../wit",
    world: "product-capsule-v2",
    additional_derives: [PartialEq],
});

pub use elastos::bus::types::{BusError, Credential, Event, Grant};
pub use objects::{ReadRecord, StubObject, HOST_MAX_READ_BYTES, READ_CHUNK};
pub use run::{run_resident, Ending, Events, Limits, Outcome};

/// The one media type `ui.present` takes in this proof.
pub const UI_MEDIA_TYPE: &str = "application/vnd.elastos.ui+json;v=0";

/// The store data for one guest.
pub struct HostState {
    /// Test-set policy: the (resource, actions) pairs a grant may be issued for.
    pub policy: Vec<(String, Vec<String>)>,
    /// Grants issued to this guest.
    pub grants: Vec<Grant>,
    /// Object URI to object, standing in for the Library.
    pub objects: BTreeMap<String, StubObject>,
    /// The host's own cap on one read.
    pub max_read_bytes: usize,
    /// Test only: a provider that ignores the guest's cap (the guest must
    /// still refuse more than it asked for).
    pub ignore_guest_cap: bool,
    /// Every read the provider streamed, as the host saw it.
    pub reads: Vec<ReadRecord>,
    /// What `credentials.presented` returns.
    pub credentials: Vec<Credential>,
    /// Every frame drawn by `ui.present`, in order; the last is on screen.
    pub frames: Vec<Vec<u8>>,
    next_id: u64,
}

impl Default for HostState {
    fn default() -> Self {
        HostState {
            policy: Vec::new(),
            grants: Vec::new(),
            objects: BTreeMap::new(),
            max_read_bytes: HOST_MAX_READ_BYTES,
            ignore_guest_cap: false,
            reads: Vec::new(),
            credentials: Vec::new(),
            frames: Vec::new(),
            next_id: 0,
        }
    }
}

/// One engine for every guest in a test: Component Model async, fuel and
/// epoch interruption on.
pub fn engine() -> Result<Engine> {
    let mut config = Config::new();
    config
        .wasm_component_model(true)
        .wasm_component_model_async(true)
        .concurrency_support(true)
        .consume_fuel(true)
        .epoch_interruption(true);
    Engine::new(&config)
}

/// Turns a guest's core module (from wit-bindgen) into a component.
pub fn componentize(core: &[u8]) -> Result<Vec<u8>> {
    wit_component::ComponentEncoder::default()
        .module(core)
        .map_err(|err| wasmtime::format_err!("guest core module: {err:#}"))?
        .validate(true)
        .encode()
        .map_err(|err| wasmtime::format_err!("componentize the guest: {err:#}"))
}

pub fn linker(engine: &Engine) -> Result<Linker<HostState>> {
    let mut linker = Linker::new(engine);
    ProductCapsuleV2::add_to_linker::<HostState, HasSelf<HostState>>(&mut linker, |state| state)?;
    Ok(linker)
}

/// Advances the engine's epoch every `tick` until dropped.
pub struct Ticker {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Ticker {
    pub fn start(engine: &Engine, tick: Duration) -> Ticker {
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (engine, stop) = (engine.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(tick);
                    engine.increment_epoch();
                }
            })
        };
        Ticker {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Ticker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
