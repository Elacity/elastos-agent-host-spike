//! Compute provider implementations

mod bus2_stream;
mod component;

use std::sync::Arc;

pub use component::{
    ActivationOutcome, ComponentProvider, ResidentActivation, SEALED_BRIDGE, STOPPED_BEFORE_RUN,
};

/// Synchronous request/response bridge from a Component into the Runtime Bus.
pub type BridgeHostcall =
    Arc<dyn Fn(&str, &str, Option<&str>) -> std::result::Result<String, String> + Send + Sync>;
