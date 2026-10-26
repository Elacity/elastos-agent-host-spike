//! Fail-closed launcher guard for the Linux confinement layers (M1 check C0).
//!
//! The guard applies each required layer in the provider's own process, after
//! `fork` and before `exec`. A layer that cannot be applied makes `spawn`
//! fail, so the provider image is never entered. The guard reports the
//! failure as a [`Refusal`] that names the provider and the layer.
//!
//! The crate stands alone. It depends on no confinement backend; a backend
//! plugs in by implementing [`Kernel`].
#![cfg(target_os = "linux")]

mod fault;
mod guard;
mod host;
mod policy;

pub use fault::{Fault, Layer, ProviderKind, Refusal, REASON_PREFIX};
pub use guard::{Errno, Guard, Kernel, LaunchError, REQUIRED_LANDLOCK_ABI};
pub use host::HostKernel;
pub use policy::{FsRules, Policy, SeccompProgram, SockFilter, DEFAULT_DENIED_SYSCALLS};
