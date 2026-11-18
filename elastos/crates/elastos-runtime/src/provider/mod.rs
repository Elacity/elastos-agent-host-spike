//! Provider registry for protocol routing
//!
//! Routes resource requests to appropriate providers based on URL scheme:
//! - `localhost://<file-backed-root>/...` -> Local sovereign PC2 state
//! - `elastos://...` -> Decentralized content and service namespaces
//!
//! Providers are registered at startup and can be dynamically added/removed.

pub mod bridge;
pub mod dispatch;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod failure_record;
mod landlock_plan;
#[cfg(target_os = "linux")]
mod linux_model_seccomp;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod local_model_broker;
mod macos_profile;
mod os_entry;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod preexec_installer;
mod registry;
mod rights;
mod rights_table;
mod seccomp_list;
mod seccomp_program;

pub use bridge::{CapsuleProvider, ProviderBridge, ProviderConfig as BridgeProviderConfig};
pub use registry::{
    decode_provider_stream_payload, EntryType, LocalIpfsCapacityObservation, Provider,
    ProviderByteRange, ProviderCarrierInvoker, ProviderCarrierRoute, ProviderError,
    ProviderInvocation, ProviderInvocationTransport, ProviderProgress, ProviderRegistration,
    ProviderRegistry, ProviderStreamOptions, ProviderStreamRead, ProviderStreamSession,
    ProviderTransfer, ResourceAction, ResourceResponse,
};

// Re-export for use by external provider implementations
#[allow(unused_imports)]
pub use registry::{ResourceEntry, ResourceRequest};
