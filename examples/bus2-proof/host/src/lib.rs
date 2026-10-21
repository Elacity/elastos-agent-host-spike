//! A stub host for the guest-side Bus v2 proof. Not the Runtime: it runs only
//! inside this folder's tests, with test-set policy, objects and credentials.
//!
//! Every operation has one path:
//! - an object is read only through `providers.invoke` (`read`, with a grant);
//! - a guest is asked to stop only by closing its events stream.
//!
//! Every refusal is a `bus-error` naming what was expected.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::task::{Context, Poll};

use wasmtime::component::{
    Accessor, Component, Destination, HasSelf, Linker, StreamProducer, StreamReader, StreamResult,
};
use wasmtime::Result;
use wasmtime::{Config, Engine, Store, StoreContextMut};

pub mod admission;

wasmtime::component::bindgen!({
    path: "../wit",
    world: "product-capsule-v2",
});

pub use elastos::bus::types::{BusError, Credential, Event, Grant};

/// The store data for one guest.
#[derive(Default)]
pub struct HostState {
    /// Test-set policy: the (resource, actions) pairs a grant may be issued for.
    pub policy: Vec<(String, Vec<String>)>,
    /// Grants issued to this guest.
    pub grants: Vec<Grant>,
    /// Object URI to bytes, standing in for the Library.
    pub objects: BTreeMap<String, Vec<u8>>,
    /// What `credentials.presented` returns.
    pub credentials: Vec<Credential>,
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

/// Feeds events to a guest; dropping the sender closes the stream.
struct EventFeed(tokio::sync::mpsc::UnboundedReceiver<Event>);

impl<D> StreamProducer<D> for EventFeed {
    type Item = Event;
    type Buffer = Option<Event>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _store: StoreContextMut<'a, D>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<Result<StreamResult>> {
        match self.0.poll_recv(cx) {
            Poll::Ready(Some(event)) => {
                destination.set_buffer(Some(event));
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Poll::Ready(None) => Poll::Ready(Ok(StreamResult::Dropped)),
            Poll::Pending if finish => Poll::Ready(Ok(StreamResult::Cancelled)),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub async fn run_once(
    engine: &Engine,
    component: &Component,
    state: HostState,
) -> Result<Result<(), BusError>> {
    let linker = linker(engine)?;
    let mut store = Store::new(engine, state);
    store.set_fuel(u64::MAX)?;
    store.set_epoch_deadline(u64::MAX);
    let world = ProductCapsuleV2::instantiate_async(&mut store, component, &linker).await?;
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    let events = StreamReader::new(&mut store, EventFeed(receiver))?;
    drop(sender);
    let result = store
        .run_concurrent(async |accessor| {
            world
                .elastos_bus_lifecycle()
                .call_run(accessor, events)
                .await
        })
        .await??;
    Ok(result)
}

impl elastos::bus::types::Host for HostState {}

impl elastos::bus::runtime::Host for HostState {
    fn info(&mut self) -> elastos::bus::runtime::RuntimeInfo {
        elastos::bus::runtime::RuntimeInfo {
            abi: "elastos:bus@2.0.0".into(),
            runtime_version: "bus2-proof-stub".into(),
            capsule_cid: None,
        }
    }
}

impl elastos::bus::identity::Host for HostState {
    fn context(&mut self) -> elastos::bus::identity::IdentityContext {
        elastos::bus::identity::IdentityContext {
            principal: None,
            capsule: "bus2-photo-guest".into(),
            session: "stub".into(),
            device: None,
        }
    }
}

impl elastos::bus::clock::Host for HostState {
    fn now_ms(&mut self) -> u64 {
        0
    }
}

impl<T: Send + 'static> elastos::bus::clock::HostWithStore<T> for HasSelf<HostState> {
    async fn sleep_until_ms(_accessor: &Accessor<T, Self>, _deadline: u64) {}
}

impl elastos::bus::random::Host for HostState {
    fn fill(&mut self, len: u32) -> Vec<u8> {
        vec![0; len as usize]
    }
}

impl elastos::bus::credentials::Host for HostState {
    fn presented(&mut self) -> Vec<Credential> {
        self.credentials.clone()
    }
}

impl elastos::bus::capabilities::Host for HostState {}
impl<T: Send + 'static> elastos::bus::capabilities::HostWithStore<T> for HasSelf<HostState> {
    async fn request(
        _accessor: &Accessor<T, Self>,
        _resource: String,
        _actions: Vec<String>,
        _reason: String,
    ) -> Result<Grant, BusError> {
        Err(BusError::Denied("not yet".into()))
    }
}

impl elastos::bus::providers::Host for HostState {}
impl<T: Send + 'static> elastos::bus::providers::HostWithStore<T> for HasSelf<HostState> {
    async fn invoke(
        _accessor: &Accessor<T, Self>,
        _request: elastos::bus::types::InvokeRequest,
        _body: Option<StreamReader<u8>>,
    ) -> Result<
        (
            elastos::bus::types::InvokeStatus,
            StreamReader<u8>,
            wasmtime::component::FutureReader<Result<(), BusError>>,
        ),
        BusError,
    > {
        Err(BusError::Unavailable("not yet".into()))
    }
}

impl elastos::bus::ui::Host for HostState {}
impl<T: Send + 'static> elastos::bus::ui::HostWithStore<T> for HasSelf<HostState> {
    async fn present(
        _accessor: &Accessor<T, Self>,
        _media_type: String,
        _document: Vec<u8>,
    ) -> Result<(), BusError> {
        Err(BusError::Unavailable("not yet".into()))
    }
}
