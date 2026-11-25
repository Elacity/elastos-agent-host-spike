//! Compute provider implementations

mod bus2_stream;
pub mod bus2_ui;
mod component;
mod fuel_bucket;

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub use component::{
    ActivationOutcome, ComponentProvider, ResidentActivation, SEALED_BRIDGE, STOPPED_BEFORE_RUN,
};

/// Synchronous request/response bridge from a Component into the Runtime Bus.
pub type BridgeHostcall =
    Arc<dyn Fn(&str, &str, Option<&str>) -> std::result::Result<String, String> + Send + Sync>;

/// v2 awaits this on the guest runtime. Dropping the future is the timeout.
pub type BridgeHostcallAsync = Arc<
    dyn Fn(
            &str,
            &str,
            Option<&str>,
        ) -> Pin<Box<dyn Future<Output = std::result::Result<String, String>> + Send>>
        + Send
        + Sync,
>;

/// Which thread drives one bridge future. The caller chooses. A `spawn_blocking`
/// worker has a runtime handle entered, so this is not read from
/// `Handle::try_current`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentBridgeLeg {
    /// v1: `handle.block_on` on this thread. No thread is added for the call.
    Caller,
    /// v2: one scoped thread, so the guest runtime does not block on itself.
    Side,
}

std::thread_local! {
    static COMPONENT_BRIDGE_LEG: Cell<ComponentBridgeLeg> =
        const { Cell::new(ComponentBridgeLeg::Caller) };
}

/// The leg the component call on this thread asked for.
pub fn component_bridge_leg() -> ComponentBridgeLeg {
    COMPONENT_BRIDGE_LEG.with(|leg| leg.get())
}

/// Sets the leg for this thread and restores the previous one on drop.
pub(crate) struct BridgeLegGuard(ComponentBridgeLeg);

impl BridgeLegGuard {
    pub(crate) fn enter(leg: ComponentBridgeLeg) -> Self {
        let previous = COMPONENT_BRIDGE_LEG.with(|slot| slot.replace(leg));
        Self(previous)
    }
}

impl Drop for BridgeLegGuard {
    fn drop(&mut self) {
        COMPONENT_BRIDGE_LEG.with(|slot| slot.set(self.0));
    }
}
