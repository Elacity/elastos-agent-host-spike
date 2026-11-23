//! Provider registry for protocol routing
//!
//! Routes resource requests to appropriate providers based on URL scheme:
//! - `localhost://<file-backed-root>/...` -> Local sovereign PC2 state
//! - `elastos://...` -> Decentralized content and service namespaces
//!
//! Providers are registered at startup and can be dynamically added/removed.

#[cfg(unix)]
pub mod bridge;
#[cfg(windows)]
#[path = "bridge_windows.rs"]
pub mod bridge;
mod bridge_protocol;
#[cfg(unix)]
mod checked_executable;
#[cfg(windows)]
#[path = "checked_executable_windows.rs"]
mod checked_executable;
pub mod dispatch;
#[cfg(unix)]
mod landlock_plan;
#[cfg(target_os = "linux")]
mod linux_model_seccomp;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod local_model_broker;
#[cfg(unix)]
mod macos_profile;
#[cfg(unix)]
mod os_entry;
#[cfg(unix)]
mod path_allow;
mod registry;
#[cfg(unix)]
mod rights;
#[cfg(unix)]
mod rights_table;
#[cfg(unix)]
mod root_pin;
#[cfg(unix)]
mod seccomp_list;
#[cfg(unix)]
mod seccomp_program;

pub use bridge::{
    CapsuleProvider, Confined, ProviderBridge, ProviderConfig as BridgeProviderConfig,
};
#[cfg(any(windows, target_os = "macos"))]
pub use checked_executable::recover_verified_copies;
pub use checked_executable::CheckedExecutable;
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
