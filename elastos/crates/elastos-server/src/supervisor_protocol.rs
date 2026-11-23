//! Shared supervisor request and response types.

use serde::{Deserialize, Serialize};

// ── Control API types ───────────────────────────────────────────────

/// Request from shell to runtime supervisor.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum SupervisorRequest {
    #[serde(rename = "ensure_capsule")]
    EnsureCapsule { name: String },

    #[serde(rename = "launch_capsule")]
    LaunchCapsule {
        name: String,
        /// The guest payload, moved whole to the guest. The host reads none of
        /// it; the wire name stays `config`.
        #[serde(default, rename = "config")]
        guest_payload: serde_json::Value,
        /// Guest stdio: a shell-launched capsule that needs a terminal.
        #[serde(default)]
        interactive: bool,
        /// Arguments forwarded to the capsule entrypoint by the guest init.
        #[serde(default)]
        capsule_args: Vec<String>,
        /// Typed: a request that deserialises carries `None`, because the
        /// wire cannot mint a `BridgePrincipal` (`#[serde(skip, default)]`).
        #[serde(skip, default)]
        principal_id: Option<crate::resource_bridge::BridgePrincipal>,
    },

    #[serde(rename = "stop_capsule")]
    StopCapsule { handle: String },

    #[serde(rename = "wait_capsule")]
    WaitCapsule { handle: String },

    #[serde(rename = "capsule_status")]
    CapsuleStatus { handle: String },

    #[serde(rename = "download_external")]
    DownloadExternal { name: String, platform: String },

    #[serde(rename = "start_gateway")]
    StartGateway {
        addr: String,
        #[serde(default)]
        cache_dir: Option<String>,
    },
}

/// Response from runtime supervisor to shell.
#[derive(Debug, Serialize, Deserialize)]
pub struct SupervisorResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vsock_cid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SupervisorResponse {
    #[cfg(unix)]
    pub(crate) fn ok() -> Self {
        Self {
            status: "ok".into(),
            path: None,
            handle: None,
            vsock_cid: None,
            uptime_secs: None,
            exit_code: None,
            error: None,
        }
    }

    #[cfg(unix)]
    pub(crate) fn ok_with_path(path: impl Into<String>) -> Self {
        Self {
            path: Some(path.into()),
            ..Self::ok()
        }
    }

    #[cfg(unix)]
    pub(crate) fn ok_with_exit_code(exit_code: i32) -> Self {
        Self {
            exit_code: Some(exit_code),
            ..Self::ok()
        }
    }

    #[cfg(unix)]
    pub(crate) fn ok_with_handle(handle: impl Into<String>, vsock_cid: u32) -> Self {
        Self {
            handle: Some(handle.into()),
            vsock_cid: Some(vsock_cid),
            ..Self::ok()
        }
    }

    pub(crate) fn err(msg: impl Into<String>) -> Self {
        Self {
            status: "error".into(),
            error: Some(msg.into()),
            path: None,
            handle: None,
            vsock_cid: None,
            uptime_secs: None,
            exit_code: None,
        }
    }
}
