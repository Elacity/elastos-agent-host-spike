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
mod chain_resolver;
#[cfg(unix)]
mod checked_executable;
#[cfg(windows)]
#[path = "checked_executable_windows.rs"]
mod checked_executable;
pub mod dispatch;
#[cfg(all(
    not(elastos_unsupported_os_check),
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
mod landlock_plan;
#[cfg(target_os = "linux")]
mod linux_model_seccomp;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod local_model_broker;
#[cfg(unix)]
mod macos_profile;
#[cfg(unix)]
mod os_entry;
#[cfg(all(
    not(elastos_unsupported_os_check),
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
mod path_allow;
mod registry;
#[cfg(unix)]
mod rights;
#[cfg(unix)]
mod rights_table;
#[cfg(all(
    not(elastos_unsupported_os_check),
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
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
/// Inactive custody state, relative to the Home data directory.
pub const CUSTODY_STATE_ROOT_RELATIVE: &str = "protected-content/custody-provider/inactive";

/// The base path Init receives. Custody's root is its state directory.
/// Every other path-allow provider receives the data directory.
#[cfg(unix)]
fn init_base_path(
    provider: rights_table::RuntimeProviderId,
    data_dir: &std::path::Path,
) -> std::path::PathBuf {
    match provider {
        rights_table::RuntimeProviderId::Custody => data_dir.join(CUSTODY_STATE_ROOT_RELATIVE),
        _ => data_dir.to_path_buf(),
    }
}

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
