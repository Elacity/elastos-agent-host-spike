//! Windows provider bridge boundary. Windows has no confined provider launcher.
//! Keep protocol types available to callers and refuse every provider start.

use super::checked_executable::CheckedExecutable;
use super::registry::{Provider, ProviderError, ResourceRequest, ResourceResponse};
use elastos_common::ProviderAuthority;
use std::path::Path;
use std::sync::Arc;

const WINDOWS_PROVIDER_REFUSAL: &str =
    "provider start is refused: no confined provider launcher on Windows";

fn refuse_checked(binary_path: &CheckedExecutable) -> BridgeError {
    match binary_path.verify_at_spawn() {
        Err(reason) => BridgeError::Refused(reason),
        Ok(prepared) => {
            let _ = prepared.exec_path();
            BridgeError::Refused(super::checked_executable::WINDOWS_CHECKED_PROVIDER.into())
        }
    }
}

/// Keep registry request deadlines available when the Windows bridge refuses a start.
pub(super) const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub use super::bridge_protocol::{BridgeError, ProviderConfig, ProviderRequest, ProviderResponse};

/// A confined provider handle. Windows cannot construct one through a start.
pub struct Confined {
    bridge: Arc<ProviderBridge>,
}

impl Confined {
    pub fn bridge(&self) -> &Arc<ProviderBridge> {
        &self.bridge
    }
}

/// Windows bridge has no process or transport handle.
pub struct ProviderBridge;

impl ProviderBridge {
    pub async fn spawn(
        binary_path: &CheckedExecutable,
        _config: ProviderConfig,
    ) -> Result<Self, BridgeError> {
        Err(refuse_checked(binary_path))
    }

    pub async fn spawn_with_owned_helpers(
        binary_path: &CheckedExecutable,
        _config: ProviderConfig,
    ) -> Result<Self, BridgeError> {
        Err(refuse_checked(binary_path))
    }

    pub async fn spawn_confined(
        _component_key: &str,
        _authority: &ProviderAuthority,
        binary_path: &CheckedExecutable,
        _storage_root: &Path,
        _config: ProviderConfig,
    ) -> Result<Confined, BridgeError> {
        Err(refuse_checked(binary_path))
    }

    /// A test transport still has no provider execution path on Windows.
    pub fn from_io(
        _reader: impl tokio::io::AsyncBufRead + Unpin + Send + 'static,
        _writer: impl tokio::io::AsyncWrite + Unpin + Send + 'static,
    ) -> Self {
        Self
    }

    pub async fn request(&self, _req: ProviderRequest) -> Result<ProviderResponse, BridgeError> {
        Err(BridgeError::Refused(WINDOWS_PROVIDER_REFUSAL.into()))
    }

    pub async fn send_raw(
        &self,
        _request: &serde_json::Value,
    ) -> Result<serde_json::Value, BridgeError> {
        Err(BridgeError::Refused(WINDOWS_PROVIDER_REFUSAL.into()))
    }

    pub async fn shutdown(&self) -> Result<(), BridgeError> {
        Ok(())
    }
}

/// A provider adapter that can only report Windows refusal.
pub struct CapsuleProvider {
    bridge: Arc<ProviderBridge>,
    scheme: &'static str,
}

impl CapsuleProvider {
    pub fn new(bridge: Arc<ProviderBridge>) -> Self {
        Self::with_scheme(bridge, "localhost")
    }

    pub fn with_scheme(bridge: Arc<ProviderBridge>, scheme: impl Into<String>) -> Self {
        Self {
            bridge,
            scheme: Box::leak(scheme.into().into_boxed_str()),
        }
    }

    pub fn from_confined(confined: Confined, scheme: impl Into<String>) -> Self {
        Self::with_scheme(confined.bridge, scheme)
    }

    pub fn bridge(&self) -> &Arc<ProviderBridge> {
        &self.bridge
    }
}

#[async_trait::async_trait]
impl Provider for CapsuleProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(WINDOWS_PROVIDER_REFUSAL.into()))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![self.scheme]
    }

    fn name(&self) -> &'static str {
        "capsule-provider"
    }

    async fn send_raw(
        &self,
        _request: &serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        Err(ProviderError::Provider(WINDOWS_PROVIDER_REFUSAL.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn windows_provider_start_refuses_before_spawn() {
        let checked = CheckedExecutable::pinned(
            Path::new("missing-provider.exe"),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("pin");
        let error = ProviderBridge::spawn(&checked, ProviderConfig::default())
            .await
            .err()
            .expect("Windows must refuse provider start");
        assert!(matches!(
            error,
            BridgeError::Refused(reason)
                if reason == super::super::checked_executable::WINDOWS_CHECKED_PROVIDER
        ));
    }
}
