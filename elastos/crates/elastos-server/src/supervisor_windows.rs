//! Windows supervisor boundary. VM requests refuse before any backend is used.

use crate::setup::ComponentsManifest;
use elastos_runtime::provider::ProviderRegistry;
use elastos_runtime::session::SessionRegistry;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug)]
pub struct MicroVmUnavailable;

impl std::fmt::Display for MicroVmUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MicroVM backend unavailable on Windows")
    }
}
impl std::error::Error for MicroVmUnavailable {}

pub use super::supervisor_protocol::{SupervisorRequest, SupervisorResponse};

/// Windows has no VM backend. A supervisor request returns a typed refusal.
pub struct Supervisor {
    #[cfg(test)]
    collaboration_chat_product_port:
        Option<crate::collaboration_product::CollaborationChatProductPort>,
    #[cfg(test)]
    collaboration_presence_product_port:
        Option<crate::collaboration_presence::CollaborationPresenceProductPort>,
}

impl Supervisor {
    pub fn new(data_dir: PathBuf, _registry: ComponentsManifest) -> Self {
        crate::setup::reconcile_capsule_start(&data_dir);
        Self {
            #[cfg(test)]
            collaboration_chat_product_port: None,
            #[cfg(test)]
            collaboration_presence_product_port: None,
        }
    }

    pub fn set_session(&mut self, _token: String, _addr: String, _sessions: Arc<SessionRegistry>) {}
    pub fn set_provider_registry(&mut self, _registry: Arc<ProviderRegistry>) {}
    pub fn set_collaboration_chat_product_port(
        &mut self,
        port: crate::collaboration_product::CollaborationChatProductPort,
    ) {
        #[cfg(test)]
        {
            self.collaboration_chat_product_port = Some(port);
        }
        #[cfg(not(test))]
        let _ = port;
    }
    pub fn set_collaboration_presence_product_port(
        &mut self,
        port: crate::collaboration_presence::CollaborationPresenceProductPort,
    ) {
        #[cfg(test)]
        {
            self.collaboration_presence_product_port = Some(port);
        }
        #[cfg(not(test))]
        let _ = port;
    }
    pub fn set_carrier_endpoint(&mut self, _endpoint: iroh::Endpoint) {}
    pub fn set_collaboration_discovery_service(
        &mut self,
        _service: crate::collaboration_discovery_runtime::CollaborationDiscoveryService,
    ) {
    }
    pub fn set_capability_manager(
        &mut self,
        _manager: Arc<elastos_runtime::capability::CapabilityManager>,
    ) {
    }
    pub fn set_pending_store(
        &mut self,
        _store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
    ) {
    }

    #[cfg(test)]
    pub(crate) fn test_collaboration_chat_product_port(
        &self,
    ) -> Option<&crate::collaboration_product::CollaborationChatProductPort> {
        self.collaboration_chat_product_port.as_ref()
    }
    #[cfg(test)]
    pub(crate) fn test_collaboration_presence_product_port(
        &self,
    ) -> Option<&crate::collaboration_presence::CollaborationPresenceProductPort> {
        self.collaboration_presence_product_port.as_ref()
    }

    pub async fn handle_request(&self, _request: SupervisorRequest) -> SupervisorResponse {
        SupervisorResponse::err(MicroVmUnavailable.to_string())
    }

    pub async fn resolve_launch_plan(
        &self,
        _target: &str,
    ) -> anyhow::Result<(Vec<String>, Vec<String>)> {
        Err(MicroVmUnavailable.into())
    }

    pub(crate) async fn load_capsule_manifest(
        &self,
        _name: &str,
    ) -> anyhow::Result<(PathBuf, elastos_common::CapsuleManifest)> {
        Err(MicroVmUnavailable.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn windows_microvm_launch_returns_typed_refusal() {
        let registry: ComponentsManifest = serde_json::from_value(serde_json::json!({
            "external": {}, "profiles": {}
        }))
        .unwrap();
        let supervisor = Supervisor::new(PathBuf::new(), registry);
        let response = supervisor
            .handle_request(SupervisorRequest::LaunchCapsule {
                name: "fixture".into(),
                guest_payload: serde_json::Value::Null,
                interactive: false,
                capsule_args: Vec::new(),
                principal_id: None,
            })
            .await;
        assert_eq!(response.status, "error");
        assert_eq!(
            response.error.as_deref(),
            Some("MicroVM backend unavailable on Windows")
        );
        assert!(response.handle.is_none());
    }
}
