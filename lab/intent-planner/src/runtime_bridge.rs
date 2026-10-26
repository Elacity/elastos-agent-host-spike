//! The real Runtime path this lab can call without changing ElastOS.
//!
//! Grants are `CapabilityManager` tokens: one resource, one action, one use.
//! Journal steps are `resource_invoke` lines on
//! `elastos_server::resource_bridge::handle_remote_request_with_audit_dir`,
//! the public elastos:bus bridge. The in-runtime journal store is
//! `handle_component_resource_request`, and that function is `pub(crate)`.

use std::sync::Arc;

use elastos_runtime::capability::manager::ValidationError;
use elastos_runtime::capability::{
    Action, CapabilityManager, CapabilityStore, ResourceId, TokenConstraints,
};
use elastos_runtime::primitives::audit::AuditLog;
use elastos_runtime::primitives::metrics::MetricsManager;

/// The launching person. The journal lives under this person's `Users/self`.
pub const LAUNCHING_PERSON: &str = "person:local:intent-planner";

/// Capsule id carried in the capability token and on the bus call.
pub const CAPSULE_ID: &str = "intent-planner";

/// `scope_current_user_alias` returns a `localhost://UsersAI/...` path unchanged.
/// `principal_root_read_write_uri` accepts only `localhost://Users/`.
pub const USERS_AI_GAP: &str = "scope_current_user_alias does not bind a UsersAI principal root";

/// Text returned by the public bus bridge for a principal-root journal.
pub const STORAGE_BRIDGE_GAP: &str =
    "principal-root storage requires an in-runtime protected storage bridge";

pub const STORAGE_BRIDGE_CODE: &str = "principal_context_required";

pub const MISSING_TOKEN_CODE: &str = "missing_token";

pub const MISSING_TOKEN_MESSAGE: &str = "resource_invoke requires a capability token";

/// Guest name for the task journal. The bridge rewrites `Users/self`.
pub fn guest_journal(agent: &str) -> String {
    format!("localhost://Users/self/.AppData/Agents/{agent}/tasks/task-1/journal")
}

/// Guest name for notes. The Runtime has no `UsersAI` principal root.
pub fn guest_notes(agent: &str) -> String {
    format!("localhost://UsersAI/{agent}/notes")
}

/// The resource a capability token stores after `Users/self` is scoped.
pub fn scoped_journal(agent: &str) -> String {
    let root = elastos_server::auth::principal_localhost_root(LAUNCHING_PERSON);
    format!("{root}/.AppData/Agents/{agent}/tasks/task-1/journal")
}

/// The Runtime capability signer and use counter for one lab host.
pub struct Grants {
    manager: CapabilityManager,
}

impl std::fmt::Debug for Grants {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Grants")
    }
}

impl Grants {
    pub fn new() -> Self {
        Self {
            manager: CapabilityManager::new(
                Arc::new(CapabilityStore::new()),
                Arc::new(AuditLog::new()),
                Arc::new(MetricsManager::new()),
            ),
        }
    }

    /// One allow-once write grant. The token is the base64 form the bus carries.
    pub fn mint_journal_write(&self, agent: &str) -> String {
        let token = self.manager.grant(
            CAPSULE_ID,
            ResourceId::new(scoped_journal(agent)),
            Action::Write,
            TokenConstraints::new(0, false, None, Some(1)),
            None,
        );
        token
            .to_base64()
            .expect("a Runtime capability token encodes")
    }

    pub fn validate_journal_write(&self, token_b64: &str, resource: &str) -> Result<(), String> {
        let token = elastos_runtime::capability::CapabilityToken::from_base64(token_b64)?;
        block_on(self.manager.validate(
            &token,
            CAPSULE_ID,
            Action::Write,
            &ResourceId::new(resource),
            None,
        ))
        .map_err(|err: ValidationError| err.to_string())
    }
}

impl Default for Grants {
    fn default() -> Self {
        Self::new()
    }
}

/// What the public bus bridge returned. This is not a stored journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeReply {
    pub code: String,
    pub message: String,
}

/// How a bridge reply maps onto a step the host can record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeClass {
    /// Principal-root storage is not on this public bridge.
    StorageBlocked,
    /// The invoke carried no capability token.
    Unapproved,
    /// Any other bridge answer, including a result this lab does not treat as stored.
    Other,
}

pub fn classify(reply: &BridgeReply) -> BridgeClass {
    if reply.code == STORAGE_BRIDGE_CODE && reply.message == STORAGE_BRIDGE_GAP {
        BridgeClass::StorageBlocked
    } else if reply.code == MISSING_TOKEN_CODE && reply.message == MISSING_TOKEN_MESSAGE {
        BridgeClass::Unapproved
    } else {
        BridgeClass::Other
    }
}

/// Send one journal write on the public elastos:bus bridge.
///
/// An empty `token` is an unapproved step. A non-empty token is the capability
/// grant the caller presents. The public bridge refuses principal-root storage
/// before it validates that token.
pub fn invoke_journal(token: &str, guest_uri: &str) -> Result<BridgeReply, String> {
    let line = serde_json::json!({
        "id": 1,
        "request": {
            "type": "resource_invoke",
            "uri": guest_uri,
            "operation": "write",
            "token": token,
            "body": {
                "content": b"EAHJ".to_vec(),
                "append": false,
                "create_only": true
            }
        }
    })
    .to_string();
    let root = elastos_server::auth::principal_localhost_root(LAUNCHING_PERSON);
    let manifest = vec![format!("{root}/.AppData/Agents/*")];
    let value = block_on(
        elastos_server::resource_bridge::handle_remote_request_with_audit_dir(
            &line,
            "http://127.0.0.1:9",
            "lab-bridge-client",
            CAPSULE_ID,
            &manifest,
            Some(LAUNCHING_PERSON),
            None,
        ),
    )
    .map_err(|err| err.to_string())?;
    let response = &value["response"];
    if response["type"] == "resource_result" {
        return Ok(BridgeReply {
            code: "stored".to_owned(),
            message: response.to_string(),
        });
    }
    Ok(BridgeReply {
        code: response["code"].as_str().unwrap_or("").to_owned(),
        message: response["message"].as_str().unwrap_or("").to_owned(),
    })
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}
