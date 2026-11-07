//! Compute abstraction layer for ElastOS

mod traits;

pub mod exec_vm;
pub mod providers;

pub use traits::{CapsuleHandle, CapsuleInfo, ComputeProvider};
