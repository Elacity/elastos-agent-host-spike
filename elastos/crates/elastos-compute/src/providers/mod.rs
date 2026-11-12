//! Compute provider implementations

mod component;

use std::sync::Arc;

pub use component::{ComponentProvider, SEALED_BRIDGE};

/// Synchronous request/response bridge from a Component into the Runtime Bus.
pub type BridgeHostcall =
    Arc<dyn Fn(&str, &str, Option<&str>) -> std::result::Result<String, String> + Send + Sync>;
