//! Shared provider wire types and typed bridge errors.

use serde::{Deserialize, Serialize};

// === Wire protocol types (mirror capsules/localhost-provider/src/main.rs) ===

/// Request from runtime to provider capsule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderRequest {
    /// Initialize the provider
    Init { config: ProviderConfig },

    /// Read file contents
    Read {
        path: String,
        token: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        length: Option<u64>,
    },

    /// Write file contents
    Write {
        path: String,
        token: String,
        content: Vec<u8>,
        #[serde(default)]
        append: bool,
    },

    /// List directory contents
    List { path: String, token: String },

    /// Delete file or directory
    Delete {
        path: String,
        token: String,
        #[serde(default)]
        recursive: bool,
    },

    /// Get file/directory metadata
    Stat { path: String, token: String },

    /// Create directory
    Mkdir {
        path: String,
        token: String,
        #[serde(default)]
        parents: bool,
    },

    /// Check if path exists
    Exists { path: String, token: String },

    /// Shutdown the provider
    Shutdown,
}

/// Response from provider capsule to runtime
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProviderResponse {
    /// Operation succeeded
    Ok {
        #[serde(default)]
        data: Option<serde_json::Value>,
    },

    /// Operation failed
    Error { code: String, message: String },
}

/// Provider configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Base path for all operations (sandbox root)
    #[serde(default)]
    pub base_path: String,

    /// Allowed path prefixes (relative to base_path)
    #[serde(default)]
    pub allowed_paths: Vec<String>,

    /// Read-only mode
    #[serde(default)]
    pub read_only: bool,

    /// Hex-encoded AES-256 encryption key (empty = no encryption)
    #[serde(default)]
    pub encryption_key: String,

    /// Provider-specific configuration (passed through to provider init)
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

// === Bridge errors ===

/// Errors from provider bridge operations
#[derive(Debug)]
pub enum BridgeError {
    /// Failed to spawn provider process
    Spawn(std::io::Error),
    /// Provider initialization failed
    InitFailed(String),
    /// Request timed out
    Timeout,
    /// Provider process exited unexpectedly
    ProcessExited,
    /// Failed to serialize/deserialize
    Serde(serde_json::Error),
    /// I/O error
    Io(std::io::Error),
    /// Provider returned an error
    Provider { code: String, message: String },
    /// Background provider I/O task failed
    TaskJoin(String),
    /// The Runtime refused to start a provider; it names the reason verbatim.
    Refused(String),
    /// The object helper was not given a public runtime DID.
    NoPublicRuntimeDid,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::Spawn(e) => write!(f, "failed to spawn provider: {}", e),
            BridgeError::InitFailed(msg) => write!(f, "provider init failed: {}", msg),
            BridgeError::Timeout => write!(f, "provider request timed out"),
            BridgeError::ProcessExited => write!(f, "provider process exited unexpectedly"),
            BridgeError::Serde(e) => write!(f, "serialization error: {}", e),
            BridgeError::Io(e) => write!(f, "I/O error: {}", e),
            BridgeError::Provider { code, message } => {
                write!(f, "provider error [{}]: {}", code, message)
            }
            BridgeError::TaskJoin(message) => {
                write!(f, "provider bridge task failed: {}", message)
            }
            BridgeError::Refused(message) => write!(f, "{}", message),
            BridgeError::NoPublicRuntimeDid => {
                write!(f, "object helper spawn refused: no public runtime DID")
            }
        }
    }
}

impl std::error::Error for BridgeError {}
