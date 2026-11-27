//! Capsule lifecycle management
//!
//! Manages capsule instances with:
//! - Unique ID generation
//! - Lifecycle tracking (running, stopped, suspended)
//! - Integration with capability tokens
//! - Metrics and audit logging
//! - Memory clearing on termination (security)

mod entrypoint;
#[cfg(test)]
mod fetched_launch;
#[cfg(test)]
mod manager;

pub use entrypoint::check_entrypoint_file;
#[cfg(test)]
pub use fetched_launch::{prepare_fetched_capsule, PreparedFetchedCapsule};
#[cfg(test)]
pub use manager::{CapsuleId, CapsuleInfo, CapsuleManager, CapsuleState};
