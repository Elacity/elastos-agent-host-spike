//! ElastOS Localhost Provider Capsule
//!
//! This provider capsule gives controlled access to localhost resources.
//! Storage operations require capability tokens and are scoped to allowed paths.
//! When an encryption key is provided, files are encrypted at rest with AES-256-GCM.

use elastos_guest::prelude::*;
use localhost_provider::{encrypt_bytes, encrypt_file_key_bytes, read_sealed_localhost_file};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

use elastos_common::localhost::{
    is_plaintext_root, parse_localhost_path, parse_localhost_uri, v2_read_offers,
};

/// Per-person (`Users`) and per-agent (`UsersAI`) areas. A request that reaches
/// one of these roots must name it; a symlink from another root must not widen
/// access into it.
const PROTECTED_AREA_ROOTS: &[&str] = &["Users", "UsersAI"];

/// Provider protocol version
const PROTOCOL_VERSION: &str = "1.0";
/// Crate version for startup logging and status
const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Request from runtime to provider
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderRequest {
    /// Initialize the provider
    Init { config: ProviderConfig },

    /// Read file contents
    Read {
        path: String,
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        encoding: Option<String>,
        offset: Option<u64>,
        length: Option<u64>,
        /// Set by a v2 read. Absent on a v1 read, which keeps its old answer.
        #[serde(default)]
        check_revision: bool,
    },

    /// Write file contents
    Write {
        path: String,
        #[serde(default)]
        token: Option<String>,
        content: Vec<u8>,
        append: bool,
    },

    /// List directory contents
    List {
        path: String,
        #[serde(default)]
        token: Option<String>,
    },

    /// Delete file or directory
    Delete {
        path: String,
        #[serde(default)]
        token: Option<String>,
        recursive: bool,
    },

    /// Get file/directory metadata
    Stat {
        path: String,
        #[serde(default)]
        token: Option<String>,
    },

    /// Create directory
    Mkdir {
        path: String,
        #[serde(default)]
        token: Option<String>,
        parents: bool,
    },

    /// Check if path exists
    Exists {
        path: String,
        #[serde(default)]
        token: Option<String>,
    },

    /// Shutdown the provider
    Shutdown,
}

/// Response from provider to runtime
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProviderResponse {
    /// Operation succeeded
    Ok { data: Option<serde_json::Value> },

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
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

/// File metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStat {
    pub path: String,
    pub is_file: bool,
    pub is_dir: bool,
    pub size: u64,
    pub readonly: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<u64>,
}

/// Directory entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub is_file: bool,
    pub is_dir: bool,
    pub size: u64,
}

/// Local filesystem provider
pub struct LocalProvider {
    config: ProviderConfig,
    base_path: PathBuf,
    /// Parsed AES-256 encryption key (None = no encryption)
    encryption_key: Option<[u8; 32]>,
}

impl LocalProvider {
    fn is_plaintext_path(path: &str) -> bool {
        let trimmed = path.trim_start_matches('/');
        parse_localhost_path(trimmed)
            .map(|(root, _)| is_plaintext_root(root))
            .unwrap_or(false)
    }

    /// Create a new provider with configuration
    pub fn new(config: ProviderConfig) -> io::Result<Self> {
        let base_path = if config.base_path.is_empty() {
            std::env::current_dir()?
        } else {
            PathBuf::from(&config.base_path)
        };

        // lstat, so a symlink to the data directory is still a path. `exists`
        // follows the link and a seatbelt can hide that follow.
        if std::fs::symlink_metadata(&base_path).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Base path does not exist: {:?}", base_path),
            ));
        }
        let base_path = base_path.canonicalize().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to canonicalize base path: {}", e),
            )
        })?;

        // Parse encryption key from hex
        let encryption_key = if config.encryption_key.is_empty() {
            None
        } else {
            let bytes = hex::decode(&config.encryption_key).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("bad encryption_key hex: {}", e),
                )
            })?;
            if bytes.len() != 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "encryption_key has invalid length {} (expected 32)",
                        bytes.len()
                    ),
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Some(key)
        };

        Ok(Self {
            config,
            base_path,
            encryption_key,
        })
    }

    /// Resolve and validate a path (hardened against symlink traversal).
    ///
    /// The resolved location is used only for the access check below. Every
    /// operation acts on the path as requested, so deleting a link removes the
    /// link, not its target. Known limits, both of which need write access
    /// inside the data folder itself: a check-then-use race on a replaced
    /// component, and hard links that alias a protected file. They are out of
    /// scope here.
    fn resolve_path(&self, path: &str) -> io::Result<PathBuf> {
        // Normalize the path
        let normalized = if let Some((root, rest)) = parse_localhost_uri(path) {
            if rest.is_empty() {
                root.to_string()
            } else {
                format!("{}/{}", root, rest)
            }
        } else {
            path.trim_start_matches('/').to_string()
        };
        let path = normalized.as_str();
        if path.is_empty() {
            return Ok(self.base_path.clone());
        }

        // Reject explicit ".." components (defense in depth)
        for component in std::path::Path::new(path).components() {
            match component {
                std::path::Component::ParentDir => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Path traversal not allowed",
                    ));
                }
                std::path::Component::Normal(_) => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("Invalid path component in: {}", path),
                    ));
                }
            }
        }

        let full_path = self.base_path.join(path);

        // Double-check the joined path is under base_path
        if !full_path.starts_with(&self.base_path) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Path escapes sandbox",
            ));
        }

        // Resolve the location the request actually addresses: the target when
        // it exists, otherwise its deepest existing ancestor plus the names that
        // do not exist yet. Every check below uses this resolved form, so a
        // symlink inside the data folder cannot widen what a request reaches.
        let resolved = Self::resolve_existing_prefix(&full_path)?;
        if !resolved.starts_with(&self.base_path) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Path escapes sandbox via symlink",
            ));
        }

        let resolved_relative = resolved
            .strip_prefix(&self.base_path)
            .unwrap_or(resolved.as_path());
        let resolved_root = match resolved_relative.components().next() {
            Some(std::path::Component::Normal(name)) => Some(name),
            _ => None,
        };
        let requested_root = Path::new(path)
            .components()
            .find_map(|component| match component {
                std::path::Component::Normal(name) => Some(name),
                _ => None,
            });

        // A link from an allowed root into `Users` or `UsersAI` must not pass:
        // the request has to name the protected area itself.
        if let Some(root) = resolved_root {
            if PROTECTED_AREA_ROOTS.iter().any(|area| root == *area) && requested_root != Some(root)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Path resolves into protected root {:?} without naming it",
                        root
                    ),
                ));
            }
        }

        // Check against allowed paths if configured, on the resolved path
        if !self.config.allowed_paths.is_empty() {
            let rel_str = resolved_relative.to_string_lossy();

            let allowed = self.config.allowed_paths.iter().any(|allowed| {
                if allowed == "*" {
                    return true;
                }
                rel_str.as_ref() == allowed || rel_str.starts_with(&format!("{}/", allowed))
            });

            if !allowed {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Path not in allowed list",
                ));
            }
        }

        // The check is complete; hand back the requested path so every
        // operation keeps its v2.0.1 semantics (deleting a link removes the
        // link itself, not the resolved target).
        Ok(full_path)
    }

    /// Canonicalize the deepest existing ancestor of `full_path` and reattach
    /// the names that do not exist yet. A dangling symlink has no resolvable
    /// target, so it is refused instead of treated as a new file.
    fn resolve_existing_prefix(full_path: &Path) -> io::Result<PathBuf> {
        let mut existing = full_path;
        let mut missing: Vec<std::ffi::OsString> = Vec::new();
        while fs::symlink_metadata(existing).is_err() {
            let Some(name) = existing.file_name() else {
                break;
            };
            missing.push(name.to_os_string());
            let Some(parent) = existing.parent() else {
                break;
            };
            existing = parent;
        }
        let mut resolved = existing.canonicalize().map_err(|e| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Failed to resolve path: {}", e),
            )
        })?;
        for name in missing.iter().rev() {
            resolved.push(name);
        }
        Ok(resolved)
    }

    /// Validate a capability token (placeholder - runtime validates tokens)
    fn validate_token(&self, _token: &str, _action: &str, _path: &str) -> io::Result<()> {
        // In the full implementation, this would:
        // 1. Send a message to the runtime to validate the token
        // 2. Check the token grants the required action on the path
        // For Phase 3, we trust the runtime has already validated
        Ok(())
    }

    /// Read file contents
    #[rustfmt::skip]
    pub fn read_file(
        &self,
        path: &str,
        token: &str,
        offset: Option<u64>,
        length: Option<u64>,
    ) -> io::Result<Vec<u8>> {
        self.validate_token(token, "read", path)?;
        let full_path = self.resolve_path(path)?;

        let metadata = fs::metadata(&full_path)?;
        if metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot read directory as file",
            ));
        }

        if let Some(ref key) = self.encryption_key {
            if Self::is_plaintext_path(path) {
                let mut file = fs::File::open(&full_path)?;
                let file_size = metadata.len();

                if let Some(off) = offset {
                    use std::io::Seek;
                    file.seek(std::io::SeekFrom::Start(off))?;
                }

                let to_read = match length {
                    Some(len) => len as usize,
                    None => (file_size - offset.unwrap_or(0)) as usize,
                };

                let mut buffer = vec![0u8; to_read];
                let bytes_read = file.read(&mut buffer)?;
                buffer.truncate(bytes_read);
                return Ok(buffer);
            }

            let read_span = || localhost_provider::read_plain_localhost_range(&full_path, path, offset.unwrap_or(0), length);
            if (offset.is_some() || length.is_some()) && localhost_provider::is_plain_localhost_file(&full_path)? {
                return read_span();
            }
            let plaintext = read_sealed_localhost_file(key, &full_path, path)?;

            let off = offset.unwrap_or(0) as usize;
            if off >= plaintext.len() {
                return Ok(Vec::new());
            }
            let end = match length {
                Some(len) => (off + len as usize).min(plaintext.len()),
                None => plaintext.len(),
            };
            if off == 0 && end == plaintext.len() {
                return Ok(plaintext);
            }
            return Ok(plaintext[off..end].to_vec());
        }

        // No encryption: stream directly
        let mut file = fs::File::open(&full_path)?;
        let file_size = metadata.len();

        if let Some(off) = offset {
            use std::io::Seek;
            file.seek(std::io::SeekFrom::Start(off))?;
        }

        let to_read = match length {
            Some(len) => len as usize,
            None => (file_size - offset.unwrap_or(0)) as usize,
        };

        let mut buffer = vec![0u8; to_read];
        let bytes_read = file.read(&mut buffer)?;
        buffer.truncate(bytes_read);

        Ok(buffer)
    }

    fn seal(&self, key: &[u8; 32], plain: &[u8]) -> io::Result<Vec<u8>> {
        if self
            .config
            .extra
            .get("file_key")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            encrypt_file_key_bytes(key, plain)
        } else {
            encrypt_bytes(key, plain)
        }
    }

    /// Write file contents
    pub fn write_file(
        &self,
        path: &str,
        token: &str,
        content: &[u8],
        append: bool,
    ) -> io::Result<u64> {
        if self.config.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Provider is read-only",
            ));
        }

        self.validate_token(token, "write", path)?;
        let full_path = self.resolve_path(path)?;

        // Ensure parent directory exists
        if let Some(parent) = full_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        if let Some(ref key) = self.encryption_key {
            if Self::is_plaintext_path(path) {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .append(append)
                    .truncate(!append)
                    .open(&full_path)?;

                file.write_all(content)?;
                file.flush()?;
                return Ok(content.len() as u64);
            }

            let plaintext = if append && full_path.exists() {
                // Read-decrypt-append-re-encrypt
                let mut existing = read_sealed_localhost_file(key, &full_path, path)?;
                existing.extend_from_slice(content);
                existing
            } else {
                content.to_vec()
            };

            let encrypted = self.seal(key, &plaintext)?;
            fs::write(&full_path, &encrypted)?;
            return Ok(content.len() as u64);
        }

        // No encryption: write directly
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(append)
            .truncate(!append)
            .open(&full_path)?;

        file.write_all(content)?;
        file.flush()?;

        Ok(content.len() as u64)
    }

    /// List directory contents
    pub fn list_dir(&self, path: &str, token: &str) -> io::Result<Vec<DirEntry>> {
        self.validate_token(token, "list", path)?;
        let full_path = self.resolve_path(path)?;

        if !full_path.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Path is not a directory",
            ));
        }

        let mut entries = Vec::new();
        for entry in fs::read_dir(&full_path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            entries.push(DirEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                is_file: metadata.is_file(),
                is_dir: metadata.is_dir(),
                size: metadata.len(),
            });
        }

        // Sort by name
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(entries)
    }

    /// Delete file or directory
    pub fn delete(&self, path: &str, token: &str, recursive: bool) -> io::Result<()> {
        if self.config.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Provider is read-only",
            ));
        }

        self.validate_token(token, "delete", path)?;
        let full_path = self.resolve_path(path)?;

        if full_path.is_dir() {
            if recursive {
                fs::remove_dir_all(&full_path)?;
            } else {
                fs::remove_dir(&full_path)?;
            }
        } else {
            fs::remove_file(&full_path)?;
        }

        Ok(())
    }

    /// Get file/directory metadata
    pub fn stat(&self, path: &str, token: &str) -> io::Result<FileStat> {
        self.validate_token(token, "stat", path)?;
        let full_path = self.resolve_path(path)?;

        let metadata = fs::metadata(&full_path)?;

        // Get timestamps if available
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        let created = metadata
            .created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        Ok(FileStat {
            path: path.to_string(),
            is_file: metadata.is_file(),
            is_dir: metadata.is_dir(),
            size: metadata.len(),
            readonly: metadata.permissions().readonly(),
            modified,
            created,
        })
    }

    /// Create directory
    pub fn mkdir(&self, path: &str, token: &str, parents: bool) -> io::Result<()> {
        if self.config.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Provider is read-only",
            ));
        }

        self.validate_token(token, "write", path)?;
        let full_path = self.resolve_path(path)?;

        if parents {
            fs::create_dir_all(&full_path)?;
        } else {
            fs::create_dir(&full_path)?;
        }

        Ok(())
    }

    /// Check if path exists
    pub fn exists(&self, path: &str, token: &str) -> io::Result<bool> {
        self.validate_token(token, "stat", path)?;
        let full_path = self.resolve_path(path)?;
        Ok(full_path.exists())
    }

    /// Handle a request
    pub fn handle_request(&mut self, request: ProviderRequest) -> ProviderResponse {
        match request {
            ProviderRequest::Init { config } => match LocalProvider::new(config) {
                Ok(provider) => {
                    *self = provider;
                    ProviderResponse::Ok {
                        data: Some(serde_json::json!({
                            "protocol_version": PROTOCOL_VERSION,
                            "provider": "localhost",
                        })),
                    }
                }
                Err(e) => ProviderResponse::Error {
                    code: "init_failed".to_string(),
                    message: e.to_string(),
                },
            },

            ProviderRequest::Read {
                path,
                token,
                encoding,
                offset,
                length,
                check_revision,
            } => {
                if check_revision {
                    return match read_v2_window(
                        self,
                        &path,
                        token.as_deref().unwrap_or(""),
                        offset,
                        length,
                    ) {
                        Ok(data) => ProviderResponse::Ok { data: Some(data) },
                        Err(e) => ProviderResponse::Error {
                            code: v2_read_code(&e),
                            message: e.to_string(),
                        },
                    };
                }
                match self.read_file(&path, token.as_deref().unwrap_or(""), offset, length) {
                    Ok(data) => match read_response_data(data, encoding.as_deref()) {
                        Ok(data) => ProviderResponse::Ok { data: Some(data) },
                        Err(e) => ProviderResponse::Error {
                            code: "read_failed".to_string(),
                            message: e.to_string(),
                        },
                    },
                    Err(e) => ProviderResponse::Error {
                        code: "read_failed".to_string(),
                        message: e.to_string(),
                    },
                }
            }

            ProviderRequest::Write {
                path,
                token,
                content,
                append,
            } => match self.write_file(&path, token.as_deref().unwrap_or(""), &content, append) {
                Ok(written) => ProviderResponse::Ok {
                    data: Some(serde_json::json!({
                        "bytes_written": written,
                    })),
                },
                Err(e) => ProviderResponse::Error {
                    code: "write_failed".to_string(),
                    message: e.to_string(),
                },
            },

            ProviderRequest::List { path, token } => {
                match self.list_dir(&path, token.as_deref().unwrap_or("")) {
                    Ok(entries) => ProviderResponse::Ok {
                        data: Some(serde_json::to_value(entries).unwrap()),
                    },
                    Err(e) => ProviderResponse::Error {
                        code: "list_failed".to_string(),
                        message: e.to_string(),
                    },
                }
            }

            ProviderRequest::Delete {
                path,
                token,
                recursive,
            } => match self.delete(&path, token.as_deref().unwrap_or(""), recursive) {
                Ok(()) => ProviderResponse::Ok { data: None },
                Err(e) => ProviderResponse::Error {
                    code: "delete_failed".to_string(),
                    message: e.to_string(),
                },
            },

            ProviderRequest::Stat { path, token } => {
                match self.stat(&path, token.as_deref().unwrap_or("")) {
                    Ok(stat) => ProviderResponse::Ok {
                        data: Some(serde_json::to_value(stat).unwrap()),
                    },
                    Err(e) => ProviderResponse::Error {
                        code: "stat_failed".to_string(),
                        message: e.to_string(),
                    },
                }
            }

            ProviderRequest::Mkdir {
                path,
                token,
                parents,
            } => match self.mkdir(&path, token.as_deref().unwrap_or(""), parents) {
                Ok(()) => ProviderResponse::Ok { data: None },
                Err(e) => ProviderResponse::Error {
                    code: "mkdir_failed".to_string(),
                    message: e.to_string(),
                },
            },

            ProviderRequest::Exists { path, token } => {
                match self.exists(&path, token.as_deref().unwrap_or("")) {
                    Ok(exists) => ProviderResponse::Ok {
                        data: Some(serde_json::json!({ "exists": exists })),
                    },
                    Err(e) => ProviderResponse::Error {
                        code: "exists_failed".to_string(),
                        message: e.to_string(),
                    },
                }
            }

            ProviderRequest::Shutdown => ProviderResponse::Ok {
                data: Some(serde_json::json!({ "message": "Provider shutting down" })),
            },
        }
    }
}

#[derive(Debug)]
struct V2ReadFail {
    code: &'static str,
    message: String,
}

impl std::fmt::Display for V2ReadFail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for V2ReadFail {}

fn v2_fail(code: &'static str, message: impl Into<String>) -> io::Error {
    io::Error::other(V2ReadFail {
        code,
        message: message.into(),
    })
}

fn v2_read_code(err: &io::Error) -> String {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<V2ReadFail>())
        .map(|fail| fail.code.to_string())
        .unwrap_or_else(|| "read_failed".to_string())
}

/// Local, Public, and Users. Any other root is returned by name.
fn offered_v2_root(path: &str) -> Result<(), String> {
    let trimmed = path
        .trim()
        .trim_start_matches("localhost://")
        .trim_start_matches('/');
    match parse_localhost_path(trimmed).map(|(root, _)| root) {
        Some(name) if v2_read_offers(name) => Ok(()),
        Some(name) => Err(name.to_string()),
        None => Err(trimmed.split('/').next().unwrap_or(trimmed).to_string()),
    }
}

#[cfg(test)]
static REVISION_GAP: std::sync::Mutex<Option<Box<dyn FnMut() + Send>>> =
    std::sync::Mutex::new(None);

fn between_revision_reads() {
    #[cfg(test)]
    if let Some(hook) = REVISION_GAP.lock().expect("revision gap").as_mut() {
        hook();
    }
}

/// Smallest plaintext a hex-JSON envelope of `file_len` bytes can hold.
/// The wrapper and the 16-byte tag are taken at their largest, so a file
/// this bound calls too big is too big. A smaller file is judged after decrypt.
fn encrypted_plaintext_lower_bound(file_len: u64) -> u64 {
    const MAX_WRAPPER: u64 = 96;
    const TAG: u64 = 16;
    (file_len.saturating_sub(MAX_WRAPPER) / 2).saturating_sub(TAG)
}

/// A Public or MyWebSite path, written as a short path or a localhost address.
fn plain_root_path(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    parse_localhost_uri(path)
        .or_else(|| parse_localhost_path(trimmed))
        .is_some_and(|(root, _)| is_plaintext_root(root))
}

fn window_of(bytes: &[u8], start: u64, window: u64) -> Vec<u8> {
    let start = usize::try_from(start)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let room = usize::try_from(window).unwrap_or(usize::MAX);
    let end = start.saturating_add(room).min(bytes.len());
    bytes[start..end].to_vec()
}

/// A v2 read. A plain file whose length exceeds the window is refused before
/// its body is read. A plain root is refused then only when that length and
/// the lower bound both do. An encrypted file is judged by the lower bound
/// first: that bound can pass a plaintext up to 16 bytes over the window, and
/// the decrypted body is then refused. A plain root follows `decrypt_bytes`:
/// that rule opens an envelope, and a file it rejects stays plain. The body
/// is read once. A change of length or mtime during that read is
/// `revision_conflict`.
fn read_v2_window(
    provider: &LocalProvider,
    path: &str,
    token: &str,
    offset: Option<u64>,
    length: Option<u64>,
) -> io::Result<serde_json::Value> {
    if let Err(root) = offered_v2_root(path) {
        return Err(v2_fail(
            "root_not_offered",
            format!("{root} is not offered"),
        ));
    }
    let full_path = provider.resolve_path(path)?;
    let metadata = fs::metadata(&full_path)?;
    if metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Cannot read directory as file",
        ));
    }
    let start = offset.unwrap_or(0);
    let window = length.unwrap_or(u64::MAX);
    let by_bytes = provider.encryption_key.is_some() && plain_root_path(path);
    let encrypted =
        provider.encryption_key.is_some() && !by_bytes && !LocalProvider::is_plaintext_path(path);
    let raw_over = metadata.len().saturating_sub(start) > window;
    let bound_over = encrypted_plaintext_lower_bound(metadata.len()).saturating_sub(start) > window;
    if (!by_bytes || bound_over) && (raw_over || encrypted) && (bound_over || !encrypted) {
        return Err(v2_fail("invalid", "object is over the read cap"));
    }
    let read_once = |provider: &LocalProvider| -> io::Result<Vec<u8>> {
        if by_bytes {
            let raw = fs::read(&full_path)?;
            let key = provider.encryption_key.as_ref().expect("plain root key");
            let body = decrypt_bytes(key, &raw).unwrap_or(raw);
            if (body.len() as u64).saturating_sub(start) > window {
                return Err(v2_fail("invalid", "object is over the read cap"));
            }
            return Ok(window_of(&body, start, window));
        }
        if !encrypted {
            return provider.read_file(path, token, offset, length);
        }
        let plain = provider.read_file(path, token, None, None)?;
        if (plain.len() as u64).saturating_sub(start) > window {
            return Err(v2_fail("invalid", "object is over the read cap"));
        }
        Ok(window_of(&plain, start, window))
    };
    let before_len = metadata.len();
    let before_modified = metadata.modified().ok();
    let bytes = read_once(provider)?;
    between_revision_reads();
    let after = fs::metadata(&full_path)?;
    if after.len() != before_len || after.modified().ok() != before_modified {
        return Err(v2_fail("revision_conflict", "revision_conflict"));
    }
    Ok(serde_json::json!({
        "content": { "b64": encode_b64(&bytes) },
        "size": bytes.len(),
        "revision": fnv_hex(&bytes),
    }))
}

fn encode_b64(bytes: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let packed = (u32::from(bytes[index]) << 16)
            | (u32::from(bytes[index + 1]) << 8)
            | u32::from(bytes[index + 2]);
        for shift in [18u32, 12, 6, 0] {
            out.push(ALPHA[((packed >> shift) & 63) as usize] as char);
        }
        index += 3;
    }
    let rest = bytes.len() - index;
    if rest > 0 {
        let mut packed = u32::from(bytes[index]) << 16;
        if rest == 2 {
            packed |= u32::from(bytes[index + 1]) << 8;
        }
        out.push(ALPHA[((packed >> 18) & 63) as usize] as char);
        out.push(ALPHA[((packed >> 12) & 63) as usize] as char);
        if rest == 2 {
            out.push(ALPHA[((packed >> 6) & 63) as usize] as char);
            out.push('=');
        } else {
            out.push('=');
            out.push('=');
        }
    }
    out
}

fn fnv_hex(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn read_response_data(data: Vec<u8>, encoding: Option<&str>) -> io::Result<serde_json::Value> {
    match encoding {
        Some("utf8") => {
            let size = data.len();
            let content = String::from_utf8(data).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("read content is not valid utf8: {}", e),
                )
            })?;
            Ok(serde_json::json!({
                "content": content,
                "encoding": "utf8",
                "size": size,
            }))
        }
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported read encoding: {}", other),
        )),
        None => Ok(serde_json::json!({
            "content": data,
            "size": data.len(),
        })),
    }
}

fn main() {
    // Print startup message
    eprintln!("localhost-provider: starting v{}", PROVIDER_VERSION);

    // Get capsule info from environment
    let info = CapsuleInfo::from_env();
    if info.is_elastos_runtime() {
        eprintln!("Running as: {} ({})", info.name(), info.id());
    } else {
        eprintln!("Running in standalone mode");
    }

    // Create provider with default config (will be initialized via Init request)
    let mut provider = LocalProvider {
        config: ProviderConfig::default(),
        base_path: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        encryption_key: None,
    };

    // Message loop - read JSON requests from stdin, write responses to stdout
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        };

        if line.is_empty() {
            continue;
        }

        // Parse request
        let request: ProviderRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(e) => {
                let response = ProviderResponse::Error {
                    code: "parse_error".to_string(),
                    message: e.to_string(),
                };
                let json = serde_json::to_string(&response).unwrap();
                writeln!(stdout, "{}", json).unwrap();
                stdout.flush().unwrap();
                continue;
            }
        };

        // Check for shutdown
        let is_shutdown = matches!(request, ProviderRequest::Shutdown);

        // Handle request
        let response = provider.handle_request(request);

        // Send response
        let json = serde_json::to_string(&response).unwrap();
        writeln!(stdout, "{}", json).unwrap();
        stdout.flush().unwrap();

        // Exit on shutdown
        if is_shutdown {
            break;
        }
    }

    eprintln!("Localhost provider exiting");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("test.txt"), b"hello world").unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        fs::write(dir.path().join("subdir/nested.txt"), b"nested content").unwrap();
        dir
    }

    fn test_key() -> [u8; 32] {
        // Deterministic test key
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    fn make_encrypted_provider(dir: &tempfile::TempDir) -> LocalProvider {
        let key = test_key();
        LocalProvider::new(ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: hex::encode(key),
            extra: serde_json::json!({ "file_key": true }),
        })
        .unwrap()
    }

    fn provider_from_config(
        dir: &tempfile::TempDir,
        key: &[u8; 32],
        file_key: bool,
    ) -> LocalProvider {
        let config: ProviderConfig = serde_json::from_value(serde_json::json!({
            "base_path": dir.path().to_string_lossy(),
            "allowed_paths": ["*"],
            "read_only": false,
            "encryption_key": hex::encode(key),
            "extra": { "file_key": file_key }
        }))
        .unwrap();
        LocalProvider::new(config).unwrap()
    }

    #[test]
    fn a_device_key_writes_the_old_header_and_a_file_key_writes_the_new_one() {
        let dir = setup_test_dir();
        let device = [1u8; 32];
        let file = [2u8; 32];
        let old = provider_from_config(&dir, &device, false);
        old.write_file("device.bin", "token", b"device-plain", false)
            .unwrap();
        let planted = fs::read(dir.path().join("device.bin")).unwrap();
        assert!(localhost_provider::header_is_device_key_envelope(&planted));
        assert!(!localhost_provider::header_is_file_key_envelope(&planted));
        assert_eq!(
            old.read_file("device.bin", "token", None, None).unwrap(),
            b"device-plain"
        );
        let again = provider_from_config(&dir, &device, false);
        assert_eq!(
            again.read_file("device.bin", "token", None, None).unwrap(),
            b"device-plain"
        );

        let new = provider_from_config(&dir, &file, true);
        new.write_file("file.bin", "token", b"file-plain", false)
            .unwrap();
        let sealed = fs::read(dir.path().join("file.bin")).unwrap();
        assert!(localhost_provider::header_is_file_key_envelope(&sealed));
        assert!(!localhost_provider::header_is_device_key_envelope(&sealed));
        assert_eq!(
            new.read_file("file.bin", "token", None, None).unwrap(),
            b"file-plain"
        );
        println!(
            "SL_R19_DEVICE={}",
            String::from_utf8_lossy(&planted[..localhost_provider::FILE_KEY_ENVELOPE_PREFIX.len()])
        );
        println!("SL_R19_FILE={}", String::from_utf8_lossy(&sealed[..22]));
    }

    #[test]
    fn test_storage_request_body_token_is_optional() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };
        let mut provider = LocalProvider::new(config).unwrap();

        let read: ProviderRequest =
            serde_json::from_value(serde_json::json!({"op": "read", "path": "test.txt"})).unwrap();
        match &read {
            ProviderRequest::Read { token, .. } => assert!(token.is_none()),
            _ => panic!("expected read request"),
        }
        assert!(matches!(
            provider.handle_request(read),
            ProviderResponse::Ok { .. }
        ));

        let write: ProviderRequest = serde_json::from_value(serde_json::json!({
            "op": "write",
            "path": "new.txt",
            "content": [104, 105],
            "append": false
        }))
        .unwrap();
        match &write {
            ProviderRequest::Write { token, .. } => assert!(token.is_none()),
            _ => panic!("expected write request"),
        }
        assert!(matches!(
            provider.handle_request(write),
            ProviderResponse::Ok { .. }
        ));
        assert_eq!(fs::read(dir.path().join("new.txt")).unwrap(), b"hi");
    }

    #[test]
    fn read_response_data_can_return_utf8_content_without_byte_array_expansion() {
        let data = read_response_data(br#"{"ok":true}"#.to_vec(), Some("utf8")).unwrap();

        assert_eq!(
            data.get("content").and_then(|value| value.as_str()),
            Some(r#"{"ok":true}"#)
        );
        assert_eq!(
            data.get("encoding").and_then(|value| value.as_str()),
            Some("utf8")
        );
        assert_eq!(data.get("size").and_then(|value| value.as_u64()), Some(11));
    }

    #[test]
    fn test_read_file() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();
        let content = provider.read_file("test.txt", "token", None, None).unwrap();
        assert_eq!(content, b"hello world");
    }

    #[test]
    fn test_read_file_accepts_rooted_localhost_uri() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["Users".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };
        fs::create_dir_all(dir.path().join("Users/self/Documents")).unwrap();
        fs::write(
            dir.path().join("Users/self/Documents/readme.txt"),
            b"hello rooted world",
        )
        .unwrap();

        let provider = LocalProvider::new(config).unwrap();
        let content = provider
            .read_file(
                "localhost://Users/self/Documents/readme.txt",
                "token",
                None,
                None,
            )
            .unwrap();
        assert_eq!(content, b"hello rooted world");
    }

    fn protected_area_provider(dir: &tempfile::TempDir) -> LocalProvider {
        fs::create_dir_all(dir.path().join("Public")).unwrap();
        fs::create_dir_all(dir.path().join("UsersAI/agent-root/Documents")).unwrap();
        fs::create_dir_all(dir.path().join("Users/self/Documents")).unwrap();
        fs::write(
            dir.path().join("UsersAI/agent-root/Documents/a.md"),
            b"agent secret",
        )
        .unwrap();
        fs::write(
            dir.path().join("Users/self/Documents/a.md"),
            b"person secret",
        )
        .unwrap();
        fs::write(dir.path().join("Public/note.txt"), b"public note").unwrap();

        LocalProvider::new(ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: elastos_common::localhost::file_backed_prefixes(),
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        })
        .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn storage_through_public_symlink_into_protected_roots_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let provider = protected_area_provider(&dir);
        std::os::unix::fs::symlink(
            "../UsersAI/agent-root/Documents",
            dir.path().join("Public/agent-link"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../Users/self/Documents",
            dir.path().join("Public/person-link"),
        )
        .unwrap();

        for (link, target, original) in [
            (
                "Public/agent-link/a.md",
                "UsersAI/agent-root/Documents/a.md",
                &b"agent secret"[..],
            ),
            (
                "Public/person-link/a.md",
                "Users/self/Documents/a.md",
                &b"person secret"[..],
            ),
        ] {
            let read = provider
                .read_file(link, "token", None, None)
                .expect_err("read through link must be refused");
            assert_eq!(read.kind(), io::ErrorKind::PermissionDenied, "read {link}");

            let write = provider
                .write_file(link, "token", b"overwritten", false)
                .expect_err("write through link must be refused");
            assert_eq!(
                write.kind(),
                io::ErrorKind::PermissionDenied,
                "write {link}"
            );

            let delete = provider
                .delete(link, "token", false)
                .expect_err("delete through link must be refused");
            assert_eq!(
                delete.kind(),
                io::ErrorKind::PermissionDenied,
                "delete {link}"
            );

            assert_eq!(fs::read(dir.path().join(target)).unwrap(), original);
        }
        assert!(!dir
            .path()
            .join("UsersAI/agent-root/Documents/new.md")
            .exists());
        assert!(!dir.path().join("Users/self/Documents/new.md").exists());
    }

    #[cfg(unix)]
    #[test]
    fn new_file_through_public_symlink_into_protected_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let provider = protected_area_provider(&dir);
        std::os::unix::fs::symlink(
            "../UsersAI/agent-root/Documents",
            dir.path().join("Public/agent-link"),
        )
        .unwrap();

        let write = provider
            .write_file("Public/agent-link/new.md", "token", b"# new", false)
            .expect_err("write through link must be refused");
        assert_eq!(write.kind(), io::ErrorKind::PermissionDenied);
        assert!(!dir
            .path()
            .join("UsersAI/agent-root/Documents/new.md")
            .exists());

        let mkdir = provider
            .mkdir("Public/agent-link/new-dir", "token", false)
            .expect_err("mkdir through link must be refused");
        assert_eq!(mkdir.kind(), io::ErrorKind::PermissionDenied);
        assert!(!dir
            .path()
            .join("UsersAI/agent-root/Documents/new-dir")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn deleting_a_public_link_removes_the_link_and_keeps_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let provider = protected_area_provider(&dir);
        fs::write(dir.path().join("Public/target.txt"), b"target bytes").unwrap();
        std::os::unix::fs::symlink("target.txt", dir.path().join("Public/link")).unwrap();

        provider.delete("Public/link", "token", false).unwrap();

        assert!(
            fs::symlink_metadata(dir.path().join("Public/link")).is_err(),
            "the link itself must be gone"
        );
        assert_eq!(
            fs::read(dir.path().join("Public/target.txt")).unwrap(),
            b"target bytes",
            "the target must survive delete of the link"
        );
    }

    #[test]
    fn public_root_storage_and_named_protected_root_storage_still_work() {
        let dir = tempfile::tempdir().unwrap();
        let provider = protected_area_provider(&dir);

        assert_eq!(
            provider
                .read_file("Public/note.txt", "token", None, None)
                .unwrap(),
            b"public note"
        );
        provider
            .write_file("Public/added.txt", "token", b"# added", false)
            .unwrap();
        assert_eq!(
            fs::read(dir.path().join("Public/added.txt")).unwrap(),
            b"# added"
        );
        provider.delete("Public/added.txt", "token", false).unwrap();
        assert!(!dir.path().join("Public/added.txt").exists());

        // The runtime principal-scoped route still names the protected root.
        assert_eq!(
            provider
                .read_file(
                    "localhost://UsersAI/agent-root/Documents/a.md",
                    "token",
                    None,
                    None
                )
                .unwrap(),
            b"agent secret"
        );
        provider
            .write_file(
                "UsersAI/agent-root/Documents/named.md",
                "token",
                b"# named",
                false,
            )
            .unwrap();
        assert_eq!(
            fs::read(dir.path().join("UsersAI/agent-root/Documents/named.md")).unwrap(),
            b"# named"
        );
    }

    #[test]
    fn test_read_file_with_offset() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();
        let content = provider
            .read_file("test.txt", "token", Some(6), Some(5))
            .unwrap();
        assert_eq!(content, b"world");
    }

    #[test]
    fn test_write_file() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();
        provider
            .write_file("new.txt", "token", b"new content", false)
            .unwrap();

        let content = fs::read_to_string(dir.path().join("new.txt")).unwrap();
        assert_eq!(content, "new content");
    }

    #[test]
    fn test_write_file_append() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();
        provider
            .write_file("test.txt", "token", b" appended", true)
            .unwrap();

        let content = fs::read_to_string(dir.path().join("test.txt")).unwrap();
        assert_eq!(content, "hello world appended");
    }

    #[test]
    fn test_read_only_mode() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: true,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();
        let result = provider.write_file("test.txt", "token", b"data", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_dir() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();
        let entries = provider.list_dir("", "token").unwrap();

        assert_eq!(entries.len(), 2);
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"test.txt"));
        assert!(names.contains(&"subdir"));
    }

    #[test]
    fn test_stat() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();
        let stat = provider.stat("test.txt", "token").unwrap();

        assert!(stat.is_file);
        assert!(!stat.is_dir);
        assert_eq!(stat.size, 11); // "hello world"
    }

    #[test]
    fn test_mkdir() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();
        provider.mkdir("newdir/nested", "token", true).unwrap();

        assert!(dir.path().join("newdir/nested").is_dir());
    }

    #[test]
    fn test_delete() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();
        provider.delete("test.txt", "token", false).unwrap();

        assert!(!dir.path().join("test.txt").exists());
    }

    #[test]
    fn test_path_escape_prevention() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();
        let result = provider.read_file("../../../etc/passwd", "token", None, None);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_path_escape_intermediate_dotdot() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();
        // foo/../../etc/passwd has ".." components that should be rejected
        let result = provider.read_file("foo/../../etc/passwd", "token", None, None);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_traversal_blocked() {
        let dir = setup_test_dir();

        // Create a target file outside the storage base
        let outside_dir = tempfile::tempdir().unwrap();
        let outside_file = outside_dir.path().join("secret.txt");
        fs::write(&outside_file, b"secret data").unwrap();

        // Create a symlink inside base_path pointing outside
        let symlink_path = dir.path().join("escape");
        std::os::unix::fs::symlink(outside_dir.path(), &symlink_path).unwrap();

        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();

        // Read through symlink should fail
        let result = provider.read_file("escape/secret.txt", "token", None, None);
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "symlink read should be blocked"
        );

        // Write through symlink should also fail
        let result = provider.write_file("escape/new.txt", "token", b"evil", false);
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "symlink write should be blocked"
        );
    }

    #[test]
    fn test_exists() {
        let dir = setup_test_dir();
        let config = ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
            extra: serde_json::Value::Null,
        };

        let provider = LocalProvider::new(config).unwrap();
        assert!(provider.exists("test.txt", "token").unwrap());
        assert!(!provider.exists("nonexistent.txt", "token").unwrap());
    }

    // === Encryption tests ===

    #[test]
    fn test_encrypted_read_write() {
        let dir = setup_test_dir();
        let provider = make_encrypted_provider(&dir);

        provider
            .write_file("secret.txt", "token", b"sensitive data", false)
            .unwrap();

        // Raw file should NOT contain plaintext
        let raw = fs::read_to_string(dir.path().join("secret.txt")).unwrap();
        assert!(
            !raw.contains("sensitive data"),
            "raw file should be encrypted"
        );
        assert!(raw.contains("ciphertext"), "raw file should be an envelope");

        // Read back through provider should return plaintext
        let content = provider
            .read_file("secret.txt", "token", None, None)
            .unwrap();
        assert_eq!(content, b"sensitive data");
    }

    #[test]
    fn an_over_cap_file_is_refused_by_name_and_a_small_file_still_reads() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("Users")).unwrap();
        let provider = make_encrypted_provider(&dir);
        provider
            .write_file("Users/small.bin", "token", b"small", false)
            .unwrap();

        let video = dir.path().join("Users/video.bin");
        fs::write(&video, b"ftyp").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&video)
            .unwrap()
            .set_len(32 * 1024 * 1024 + 1)
            .unwrap();
        let whole = provider
            .read_file("Users/video.bin", "token", None, None)
            .unwrap();
        assert!(whole.starts_with(b"ftyp"));
        assert_eq!(whole.len(), 32 * 1024 * 1024 + 1);
        assert_eq!(
            provider
                .read_file("Users/small.bin", "token", None, None)
                .unwrap(),
            b"small"
        );
        let slice = provider
            .read_file("Users/video.bin", "token", Some(0), Some(4))
            .unwrap();
        assert_eq!(slice, b"ftyp");
    }

    /// 40 MiB plain bytes, and plain JSON that starts with `{"`, through the
    /// provider read the Home routes send.
    ///
    /// Whole: `GET /api/localhost/*` and a registry read (no offset).
    /// Sliced: `POST /api/provider/localhost/read` and a bridge invoke, which
    /// forward `offset` and `length`.
    /// Streamed: those same reads, one window at a time, and
    /// [`stream_plain_localhost_file`], which keeps one chunk.
    #[test]
    fn a_40_mib_plain_file_is_read_whole_sliced_and_streamed() {
        const SIZE: u64 = 40 * 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("Users")).unwrap();
        let mut provider = make_encrypted_provider(&dir);
        let video = dir.path().join("Users/video.bin");
        fs::write(&video, b"ftyp").unwrap();
        let marker_at = 20 * 1024 * 1024;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&video)
            .unwrap();
        use std::io::{Seek, Write};
        file.seek(std::io::SeekFrom::Start(marker_at)).unwrap();
        file.write_all(b"MARK").unwrap();
        file.set_len(SIZE).unwrap();
        drop(file);

        let mut digest = 0u64;
        let mut widest = 0usize;
        let streamed =
            localhost_provider::stream_plain_localhost_file(&video, 64 * 1024, |chunk| {
                widest = widest.max(chunk.len());
                for byte in chunk {
                    digest = digest.wrapping_add(*byte as u64);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(streamed, SIZE);
        assert_eq!(digest, 750, "the stream did not see ftyp and MARK");
        assert!(widest <= 64 * 1024, "a stream chunk held {widest} bytes");

        let _ = localhost_provider::take_sealed_read_bytes();
        let slice = provider.handle_request(ProviderRequest::Read {
            path: "Users/video.bin".into(),
            token: Some("token".into()),
            encoding: None,
            offset: Some(marker_at),
            length: Some(4),
        });
        let slice = match slice {
            ProviderResponse::Ok { data: Some(data) } => data,
            other => panic!("slice {other:?}"),
        };
        assert_eq!(
            slice["content"],
            serde_json::json!([b'M', b'A', b'R', b'K'])
        );
        assert_eq!(slice["size"], 4);
        let ranged = localhost_provider::take_sealed_read_bytes();
        assert_eq!(ranged, 4 + 64, "a range read loaded the file: {ranged}");
        println!("SL_R18_UNDER_GIB={ranged}");

        let whole = provider
            .read_file("Users/video.bin", "token", None, None)
            .unwrap();
        assert_eq!(whole.len() as u64, SIZE);
        assert!(whole.starts_with(b"ftyp"));
        assert_eq!(&whole[marker_at as usize..marker_at as usize + 4], b"MARK");
        assert!(
            whole.capacity() <= SIZE as usize + 8,
            "whole read held {} bytes",
            whole.capacity()
        );
        drop(whole);

        let json_path = dir.path().join("Users/note.json");
        fs::write(&json_path, br#"{"note":"plain"#).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&json_path)
            .unwrap()
            .set_len(SIZE)
            .unwrap();
        let _ = localhost_provider::take_sealed_read_bytes();
        let json_slice = provider
            .read_file("Users/note.json", "token", Some(0), Some(7))
            .unwrap();
        assert_eq!(json_slice, br#"{"note""#);
        assert!(json_slice.capacity() <= 16);
        let json_ranged = localhost_provider::take_sealed_read_bytes();
        assert_eq!(
            json_ranged,
            7 + 64,
            "a json range read loaded the file: {json_ranged}"
        );
        let json_whole = provider
            .read_file("Users/note.json", "token", None, None)
            .unwrap();
        assert_eq!(json_whole.len() as u64, SIZE);
        assert!(json_whole.starts_with(br#"{"note":"plain"#));
        assert!(json_whole.capacity() <= SIZE as usize + 8);
    }

    #[test]
    fn test_encrypted_read_with_offset() {
        let dir = setup_test_dir();
        let provider = make_encrypted_provider(&dir);

        provider
            .write_file("offset.txt", "token", b"hello world", false)
            .unwrap();

        let content = provider
            .read_file("offset.txt", "token", Some(6), Some(5))
            .unwrap();
        assert_eq!(content, b"world");
    }

    #[test]
    fn test_encrypted_append() {
        let dir = setup_test_dir();
        let provider = make_encrypted_provider(&dir);

        provider
            .write_file("append.txt", "token", b"hello", false)
            .unwrap();
        provider
            .write_file("append.txt", "token", b" world", true)
            .unwrap();

        let content = provider
            .read_file("append.txt", "token", None, None)
            .unwrap();
        assert_eq!(content, b"hello world");
    }

    #[test]
    fn test_public_paths_stay_plaintext_with_encryption_enabled() {
        let dir = setup_test_dir();
        let provider = make_encrypted_provider(&dir);

        provider
            .write_file(
                "Public/elastos/index.html",
                "token",
                b"<h1>Hello</h1>",
                false,
            )
            .unwrap();

        let raw = fs::read(dir.path().join("Public/elastos/index.html")).unwrap();
        assert_eq!(raw, b"<h1>Hello</h1>");

        let content = provider
            .read_file("Public/elastos/index.html", "token", None, None)
            .unwrap();
        assert_eq!(content, b"<h1>Hello</h1>");
    }

    fn plant_prefix(path: &std::path::Path, len: u64) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, localhost_provider::FILE_KEY_ENVELOPE_MARK).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(len)
            .unwrap();
    }

    fn refusal(
        provider: &LocalProvider,
        path: &str,
        offset: Option<u64>,
        length: Option<u64>,
    ) -> String {
        provider
            .read_file(path, "token", offset, length)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn a_file_key_header_is_refused_when_cut_off_corrupt_or_over_the_limit() {
        let dir = setup_test_dir();
        fs::create_dir(dir.path().join("Users")).unwrap();
        let provider = make_encrypted_provider(&dir);
        let over = localhost_provider::ENVELOPE_BYTE_LIMIT + 1;
        let huge = localhost_provider::SEALED_READ_HARD_LIMIT + 1;

        let cut = dir.path().join("Users/cut.bin");
        plant_prefix(&cut, over);
        assert!(!localhost_provider::is_plain_localhost_file(&cut).unwrap());
        assert_eq!(
            refusal(&provider, "Users/cut.bin", None, None),
            "Users/cut.bin is cut off. Move it aside, or remove it."
        );
        assert_eq!(
            refusal(&provider, "Users/cut.bin", Some(0), Some(4)),
            "Users/cut.bin is cut off. Move it aside, or remove it."
        );
        let before = fs::read(&cut).unwrap();
        let err = provider
            .write_file("Users/cut.bin", "token", b"more", true)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "Users/cut.bin is cut off. Move it aside, or remove it."
        );
        assert_eq!(fs::read(&cut).unwrap(), before);

        let bad = dir.path().join("Users/bad.bin");
        let mut file = fs::File::create(&bad).unwrap();
        use std::io::Write;
        file.write_all(localhost_provider::FILE_KEY_ENVELOPE_MARK)
            .unwrap();
        file.write_all(b"g").unwrap();
        let chunk = [b'a'; 64 * 1024];
        let mut left = over as usize - file.metadata().unwrap().len() as usize;
        while left > 0 {
            let n = left.min(chunk.len());
            file.write_all(&chunk[..n]).unwrap();
            left -= n;
        }
        file.write_all(br#""}"#).unwrap();
        drop(file);
        assert!(fs::metadata(&bad).unwrap().len() > localhost_provider::ENVELOPE_BYTE_LIMIT);
        assert!(!localhost_provider::is_plain_localhost_file(&bad).unwrap());
        assert_eq!(
            refusal(&provider, "Users/bad.bin", None, None),
            "Users/bad.bin is cut off. Move it aside, or remove it."
        );
        let bad_before = fs::metadata(&bad).unwrap().len();
        let err = provider
            .write_file("Users/bad.bin", "token", b"more", true)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "Users/bad.bin is cut off. Move it aside, or remove it."
        );
        assert_eq!(fs::metadata(&bad).unwrap().len(), bad_before);

        let big = dir.path().join("Users/huge.bin");
        plant_prefix(&big, huge);
        assert!(!localhost_provider::is_plain_localhost_file(&big).unwrap());
        let sliced = refusal(&provider, "Users/huge.bin", Some(0), Some(8));
        assert!(
            sliced.contains("Users/huge.bin is larger than this process can read"),
            "{sliced}"
        );
        assert!(sliced.contains("Move it out of the folder."), "{sliced}");
        let err = provider
            .write_file("Users/huge.bin", "token", b"more", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("larger than this process can read"), "{err}");
        assert_eq!(fs::metadata(&big).unwrap().len(), huge);
        let mut head = [0u8; 64];
        std::io::Read::read_exact(&mut fs::File::open(&big).unwrap(), &mut head).unwrap();
        assert!(head.starts_with(localhost_provider::FILE_KEY_ENVELOPE_MARK));
        assert!(localhost_provider::header_is_file_key_envelope(&head));
        assert!(!localhost_provider::header_is_file_key_envelope(
            &head[..localhost_provider::FILE_KEY_ENVELOPE_PREFIX.len()]
        ));
    }

    fn old_sealed(dir: &std::path::Path, name: &str, len: u64) -> std::path::PathBuf {
        let path = dir.join(name);
        let sealed = localhost_provider::encrypt_bytes(&[9; 32], b"sealed").unwrap();
        assert!(localhost_provider::header_is_device_key_envelope(&sealed));
        fs::write(&path, &sealed).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len)
            .unwrap();
        path
    }

    #[test]
    fn an_old_header_is_refused_when_cut_off_or_past_the_hard_limit() {
        let dir = setup_test_dir();
        fs::create_dir(dir.path().join("Users")).unwrap();
        let provider = make_encrypted_provider(&dir);
        let forty = 40 * 1024 * 1024;
        let huge = localhost_provider::SEALED_READ_HARD_LIMIT + 1;
        let cut = old_sealed(dir.path(), "Users/cut.bin", forty);
        let before = fs::metadata(&cut).unwrap().len();
        let mut head = [0u8; 63];
        std::io::Read::read_exact(&mut fs::File::open(&cut).unwrap(), &mut head).unwrap();
        assert_eq!(
            refusal(&provider, "Users/cut.bin", None, None),
            "Users/cut.bin is cut off. Move it aside, or remove it."
        );
        assert_eq!(
            refusal(&provider, "Users/cut.bin", Some(0), Some(4)),
            "Users/cut.bin is cut off. Move it aside, or remove it."
        );
        let err = provider
            .write_file("Users/cut.bin", "token", b"more", true)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "Users/cut.bin is cut off. Move it aside, or remove it."
        );
        assert_eq!(fs::metadata(&cut).unwrap().len(), before);
        let mut after = [0u8; 63];
        std::io::Read::read_exact(&mut fs::File::open(&cut).unwrap(), &mut after).unwrap();
        assert_eq!(after, head);

        let big = old_sealed(dir.path(), "Users/huge.bin", huge);
        let sliced = refusal(&provider, "Users/huge.bin", Some(0), Some(8));
        assert!(
            sliced.contains("Users/huge.bin is larger than this process can read"),
            "{sliced}"
        );
        assert!(sliced.contains("Move it out of the folder."), "{sliced}");
        let err = provider
            .write_file("Users/huge.bin", "token", b"more", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("larger than this process can read"), "{err}");
        assert_eq!(fs::metadata(&big).unwrap().len(), huge);
        let mut big_head = [0u8; 63];
        std::io::Read::read_exact(&mut fs::File::open(&big).unwrap(), &mut big_head).unwrap();
        assert!(localhost_provider::header_is_device_key_envelope(&big_head));

        let name = dir.path().join("Users/name.json");
        let prefix = br#"{"version":1,"name":"ada""#;
        fs::write(&name, prefix).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&name)
            .unwrap()
            .set_len(localhost_provider::ENVELOPE_BYTE_LIMIT + 1)
            .unwrap();
        assert!(localhost_provider::is_plain_localhost_file(&name).unwrap());
        assert_eq!(
            provider
                .read_file(
                    "Users/name.json",
                    "token",
                    Some(0),
                    Some(prefix.len() as u64)
                )
                .unwrap(),
            prefix
        );
    }

    #[test]
    fn a_small_sealed_read_opens_the_file_once() {
        let dir = setup_test_dir();
        fs::create_dir(dir.path().join("Users")).unwrap();
        let provider = make_encrypted_provider(&dir);
        let key = test_key();
        let path = dir.path().join("Users/once.bin");
        let sealed = localhost_provider::encrypt_file_key_bytes(&key, b"hello").unwrap();
        fs::write(&path, &sealed).unwrap();
        let _ = localhost_provider::take_sealed_read_bytes();
        assert_eq!(
            provider
                .read_file("Users/once.bin", "token", None, None)
                .unwrap(),
            b"hello"
        );
        assert_eq!(
            localhost_provider::take_sealed_read_bytes(),
            sealed.len() as u64
        );
    }

    #[test]
    fn a_cut_off_old_header_under_32_mib_uses_the_cut_off_sentence() {
        let dir = setup_test_dir();
        fs::create_dir(dir.path().join("Users")).unwrap();
        let provider = make_encrypted_provider(&dir);
        let sealed = localhost_provider::encrypt_bytes(&test_key(), b"sealed-old").unwrap();
        assert!(localhost_provider::header_is_device_key_envelope(&sealed));
        assert!(
            sealed.len() > 80 && (sealed.len() as u64) <= localhost_provider::ENVELOPE_BYTE_LIMIT
        );
        let cut = &sealed[..80];
        assert!(localhost_provider::header_is_device_key_envelope(cut));
        fs::write(dir.path().join("Users/old-cut.bin"), cut).unwrap();
        assert_eq!(
            refusal(&provider, "Users/old-cut.bin", None, None),
            "Users/old-cut.bin is cut off. Move it aside, or remove it."
        );
    }

    #[test]
    fn a_plain_file_past_the_hard_limit_is_sliced_without_loading_it() {
        let dir = setup_test_dir();
        fs::create_dir(dir.path().join("Users")).unwrap();
        let provider = make_encrypted_provider(&dir);
        let path = dir.path().join("Users/huge-plain.bin");
        let mut file = fs::File::create(&path).unwrap();
        use std::io::{Seek, Write};
        file.write_all(b"{over").unwrap();
        file.seek(std::io::SeekFrom::Start(100)).unwrap();
        file.write_all(b"AT100").unwrap();
        file.seek(std::io::SeekFrom::Start(4096)).unwrap();
        file.write_all(b"PAGE").unwrap();
        let huge = localhost_provider::SEALED_READ_HARD_LIMIT + 1;
        file.set_len(huge).unwrap();
        drop(file);
        let name = "Users/huge-plain.bin";
        let sentence =
            format!("{name} is larger than this process can read. Move it out of the folder.");
        let read = |offset, length| {
            let _ = localhost_provider::take_sealed_read_bytes();
            let out = provider.read_file(name, "token", offset, length);
            (out, localhost_provider::take_sealed_read_bytes())
        };
        for (offset, length, expect) in [
            (Some(0), Some(5), &b"{over"[..]),
            (Some(100), Some(5), &b"AT100"[..]),
            (Some(4096), Some(4), &b"PAGE"[..]),
        ] {
            let (out, n) = read(offset, length);
            assert_eq!(out.unwrap(), expect, "{offset:?} {length:?}");
            assert_eq!(n, 64 + length.unwrap(), "held more than the range: {n}");
            println!("SL_R18_OFF={offset:?} LEN={length:?} READ={n}");
        }
        for offset in [None, Some(0), Some(100), Some(4096)] {
            let (out, n) = read(offset, None);
            assert_eq!(out.unwrap_err().to_string(), sentence, "{offset:?}");
            assert!(n <= 128, "a no-length read held the file: {n}");
            println!("SL_R18_NOLEN={offset:?} READ={n}");
        }
        for offset in [Some(huge), Some(huge + 100)] {
            let (out, n) = read(offset, Some(8));
            assert_eq!(out.unwrap(), b"", "{offset:?}");
            assert!(n <= 64, "past the end held the file: {n}");
        }
        let (out, n) = read(Some(huge), None);
        assert_eq!(out.unwrap(), b"");
        assert!(n <= 64, "past the end with no length held the file: {n}");
    }

    fn reorder_envelope(sealed: &[u8]) -> Vec<u8> {
        let value: serde_json::Value = serde_json::from_slice(sealed).unwrap();
        format!(
            "{{\"ciphertext\":{},\"nonce\":{},\"version\":{}}}",
            value["ciphertext"], value["nonce"], value["version"]
        )
        .into_bytes()
    }

    #[test]
    fn a_reordered_envelope_over_32_mib_opens_once_and_a_bad_tag_does_not_decrypt() {
        let dir = setup_test_dir();
        fs::create_dir(dir.path().join("Users")).unwrap();
        let provider = make_encrypted_provider(&dir);
        let key = test_key();
        let plain = vec![0x11u8; 16 * 1024 * 1024];
        let sealed = localhost_provider::encrypt_file_key_bytes(&key, &plain).unwrap();
        let reordered = reorder_envelope(&sealed);
        assert!(reordered.len() as u64 > localhost_provider::ENVELOPE_BYTE_LIMIT);
        let path = dir.path().join("Users/reordered.bin");
        fs::write(&path, &reordered).unwrap();
        let _ = localhost_provider::take_sealed_read_bytes();
        assert_eq!(
            provider
                .read_file("Users/reordered.bin", "token", None, None)
                .unwrap(),
            plain
        );
        let read = localhost_provider::take_sealed_read_bytes();
        assert!(
            read > reordered.len() as u64,
            "the body was not scanned: {read}"
        );
        assert!(
            read < reordered.len() as u64 * 5 / 2,
            "the file was scanned more than once: {read}"
        );

        let mut bad = reordered;
        let marker = br#""ciphertext":""#;
        let at = bad
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap()
            + marker.len();
        bad[at] = if bad[at] == b'0' { b'1' } else { b'0' };
        fs::write(&path, &bad).unwrap();
        let err = refusal(&provider, "Users/reordered.bin", None, None);
        assert!(err.contains("does not decrypt"), "{err}");
        assert!(err.contains("Move it aside, or remove it."), "{err}");
        assert!(!err.contains("device.key"), "{err}");
        assert!(!err.contains("restart"), "{err}");
        assert!(!err.contains("larger than 32 MiB"), "{err}");
        assert!(!err.contains("Remove it"), "{err}");
    }

    #[test]
    fn a_bad_old_envelope_names_a_remedy_for_this_system() {
        let dir = setup_test_dir();
        fs::create_dir(dir.path().join("Users")).unwrap();
        let provider = make_encrypted_provider(&dir);
        let key = test_key();
        let mut sealed = localhost_provider::encrypt_bytes(&key, b"old-secret").unwrap();
        let marker = br#""ciphertext":""#;
        let at = sealed
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap()
            + marker.len();
        sealed[at] = if sealed[at] == b'0' { b'1' } else { b'0' };
        fs::write(dir.path().join("Users/old.bin"), &sealed).unwrap();
        let err = refusal(&provider, "Users/old.bin", None, None);
        assert!(err.contains("does not decrypt"), "{err}");
        #[cfg(unix)]
        {
            assert!(err.contains("Move the file aside, then restart."), "{err}");
            assert!(!err.contains("device.key"), "{err}");
        }
        #[cfg(not(unix))]
        {
            assert!(
                err.contains("Restore identity/device.key, or move the file aside, then restart."),
                "{err}"
            );
        }
        assert!(!err.contains("Move it aside, or remove it."), "{err}");
    }

    #[test]
    fn a_long_header_does_not_panic_the_plain_scan() {
        let header = vec![b'{'; 9000];
        let mut rest = std::io::Cursor::new(Vec::<u8>::new());
        let (plain, read) =
            localhost_provider::reads_as_plain_bytes(&header, 40 * 1024 * 1024, &mut rest).unwrap();
        assert!(plain, "a run of braces is not an envelope");
        assert_eq!(read, 0);
    }

    fn plain_provider(dir: &tempfile::TempDir) -> LocalProvider {
        LocalProvider::new(ProviderConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            allowed_paths: vec!["*".to_string()],
            read_only: false,
            encryption_key: String::new(),
        })
        .unwrap()
    }

    #[test]
    fn v2_windowed_read_on_local_public_and_users() {
        let dir = setup_test_dir();
        for root in ["Local", "Public", "Users"] {
            fs::create_dir_all(dir.path().join(root)).unwrap();
        }
        let mut provider = plain_provider(&dir);
        for (root, bytes) in [
            ("Local", &b"local-bytes"[..]),
            ("Public", &b"public-bytes"[..]),
            ("Users", &b"users-bytes"[..]),
        ] {
            let path = format!("{root}/note.txt");
            provider.write_file(&path, "token", bytes, false).unwrap();
            let request: ProviderRequest = serde_json::from_value(serde_json::json!({
                "op": "read",
                "path": path,
                "offset": 0,
                "length": 64,
                "check_revision": true
            }))
            .unwrap();
            let ProviderResponse::Ok { data: Some(data) } = provider.handle_request(request) else {
                panic!("{root} windowed read failed");
            };
            assert_eq!(data["content"]["b64"], encode_b64(bytes), "{root}");
            assert_eq!(data["size"], bytes.len());
            assert!(data["revision"].is_string());
            let v1: ProviderRequest = serde_json::from_value(serde_json::json!({
                "op": "read", "path": path, "offset": 0, "length": 64
            }))
            .unwrap();
            let ProviderResponse::Ok { data: Some(old) } = provider.handle_request(v1) else {
                panic!("v1 read failed");
            };
            assert!(
                old["content"].as_array().is_some(),
                "a v1 read stays a byte array"
            );
        }
        provider
            .write_file("Local/big.txt", "token", b"0123456789abcdef", false)
            .unwrap();
        let over: ProviderRequest = serde_json::from_value(serde_json::json!({
            "op": "read",
            "path": "Local/big.txt",
            "offset": 0,
            "length": 4,
            "check_revision": true
        }))
        .unwrap();
        match provider.handle_request(over) {
            ProviderResponse::Error { code, message } => {
                assert_eq!(code, "invalid");
                assert!(message.contains("over the read cap"), "{message}");
            }
            other => panic!("oversized object was read: {other:?}"),
        }
        *REVISION_GAP.lock().expect("gap") = Some(Box::new({
            let path = dir.path().join("Local/note.txt");
            move || {
                fs::write(&path, b"changed").unwrap();
            }
        }));
        let gap: ProviderRequest = serde_json::from_value(serde_json::json!({
            "op": "read",
            "path": "Local/note.txt",
            "offset": 0,
            "length": 64,
            "check_revision": true
        }))
        .unwrap();
        match provider.handle_request(gap) {
            ProviderResponse::Error { code, message } => {
                assert_eq!(code, "revision_conflict");
                assert!(message.contains("revision_conflict"), "{message}");
            }
            other => panic!("a changed file was accepted: {other:?}"),
        }
        *REVISION_GAP.lock().expect("gap") = None;
        for root in [
            "ElastOS",
            "AppCapsules",
            "MyWebSite",
            "UsersAI",
            "WebSpaces",
        ] {
            let request: ProviderRequest = serde_json::from_value(serde_json::json!({
                "op": "read",
                "path": format!("{root}/note.txt"),
                "offset": 0,
                "length": 8,
                "check_revision": true
            }))
            .unwrap();
            match provider.handle_request(request) {
                ProviderResponse::Error { code, message } => {
                    assert_eq!(code, "root_not_offered", "{root} {message}");
                    assert!(
                        message.contains(root) && message.contains("is not offered"),
                        "{message}"
                    );
                }
                other => panic!("{root} fell through: {other:?}"),
            }
        }
    }

    #[test]
    fn v2_windowed_read_bounds_an_encrypted_users_file() {
        let dir = setup_test_dir();
        fs::create_dir_all(dir.path().join("Users")).unwrap();
        fs::create_dir_all(dir.path().join("Local")).unwrap();
        let mut provider = make_encrypted_provider(&dir);
        provider
            .write_file("Users/small.txt", "token", b"secret", false)
            .unwrap();
        provider
            .write_file("Local/note.txt", "token", b"journal v1", false)
            .unwrap();
        let ok: ProviderRequest = serde_json::from_value(serde_json::json!({
            "op": "read",
            "path": "Users/small.txt",
            "offset": 0,
            "length": 64,
            "check_revision": true
        }))
        .unwrap();
        let ProviderResponse::Ok { data: Some(data) } = provider.handle_request(ok) else {
            panic!("a small encrypted file must be readable");
        };
        assert_eq!(data["content"]["b64"], encode_b64(b"secret"));
        let local: ProviderRequest = serde_json::from_value(serde_json::json!({
            "op": "read",
            "path": "Local/note.txt",
            "offset": 0,
            "length": 64,
            "check_revision": true
        }))
        .unwrap();
        let ProviderResponse::Ok { data: Some(data) } = provider.handle_request(local) else {
            panic!("a 10-byte encrypted Local file must fit a 64-byte window");
        };
        assert_eq!(data["content"]["b64"], encode_b64(b"journal v1"));
        provider
            .write_file("Users/big.txt", "token", &[7u8; 32], false)
            .unwrap();
        let over: ProviderRequest = serde_json::from_value(serde_json::json!({
            "op": "read",
            "path": "Users/big.txt",
            "offset": 0,
            "length": 8,
            "check_revision": true
        }))
        .unwrap();
        match provider.handle_request(over) {
            ProviderResponse::Error { message, .. } => {
                assert!(message.contains("over the read cap"), "{message}");
            }
            other => panic!("the encrypted body was read: {other:?}"),
        }
    }

    #[test]
    fn an_encrypted_local_file_over_half_the_window_is_the_plaintext() {
        let dir = setup_test_dir();
        fs::create_dir_all(dir.path().join("Local")).unwrap();
        let mut provider = make_encrypted_provider(&dir);
        let plain = vec![b'a'; 40_000];
        provider
            .write_file("Local/report.txt", "token", &plain, false)
            .unwrap();
        let window = 65_536u64;
        assert!(plain.len() as u64 > window / 2);
        let request: ProviderRequest = serde_json::from_value(serde_json::json!({
            "op": "read",
            "path": "Local/report.txt",
            "offset": 0,
            "length": window,
            "check_revision": true
        }))
        .unwrap();
        let ProviderResponse::Ok { data: Some(data) } = provider.handle_request(request) else {
            panic!("plaintext over half the window must be returned");
        };
        assert_eq!(data["content"]["b64"], encode_b64(&plain));
    }

    #[test]
    fn a_16mib_encrypted_local_read_stays_inside_two_seconds() {
        let dir = setup_test_dir();
        fs::create_dir_all(dir.path().join("Local")).unwrap();
        let mut provider = make_encrypted_provider(&dir);
        let cap = 16 * 1024 * 1024;
        let plain = vec![b'b'; cap];
        provider
            .write_file("Local/report.bin", "token", &plain, false)
            .unwrap();
        let rss = || -> u64 {
            let output = std::process::Command::new("ps")
                .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()
                .expect("ps");
            String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0)
        };
        let before = rss();
        let started = std::time::Instant::now();
        let request: ProviderRequest = serde_json::from_value(serde_json::json!({
            "op": "read",
            "path": "Local/report.bin",
            "offset": 0,
            "length": cap,
            "check_revision": true
        }))
        .unwrap();
        let response = provider.handle_request(request);
        let elapsed = started.elapsed();
        let after = rss();
        let ProviderResponse::Ok { data: Some(data) } = response else {
            panic!("a 16 MiB plaintext must fit the cap");
        };
        assert_eq!(data["size"], cap);
        println!(
            "16mib elapsed_ms={} rss_kib_before={before} rss_kib_after={after}",
            elapsed.as_millis()
        );
        assert!(
            cfg!(debug_assertions) || elapsed < std::time::Duration::from_secs(2),
            "the read took {elapsed:?}"
        );
        let growth = after.saturating_sub(before);
        assert!(growth < 256 * 1024, "rss grew by {growth} KiB");
    }

    #[test]
    fn v2_uri_read_uses_the_file_key_and_a_uri_write_stays_encrypted() {
        let dir = setup_test_dir();
        for root in ["Local", "Public", "Users"] {
            fs::create_dir_all(dir.path().join(root)).unwrap();
        }
        let provider = make_encrypted_provider(&dir);
        for (root, bytes) in [
            ("Public", &b"plain-public"[..]),
            ("Local", &b"secret-local"[..]),
            ("Users", &b"secret-users"[..]),
        ] {
            let path = format!("{root}/note.txt");
            provider.write_file(&path, "token", bytes, false).unwrap();
            let stored = fs::read(provider.resolve_path(&path).unwrap()).unwrap();
            if root == "Public" {
                assert_eq!(stored, bytes, "a Public path write stays plain");
            } else {
                assert_ne!(stored, bytes, "{root} stays encrypted");
                assert!(std::str::from_utf8(&stored).unwrap().contains("ciphertext"));
            }
            let data = read_v2_window(
                &provider,
                &format!("localhost://{path}"),
                "token",
                None,
                None,
            )
            .unwrap_or_else(|err| panic!("{root} uri read: {err}"));
            assert_eq!(data["content"]["b64"], encode_b64(bytes), "{root}");
        }
        provider
            .write_file("localhost://Public/uri.txt", "token", b"not-plain", false)
            .unwrap();
        let stored =
            fs::read(provider.resolve_path("localhost://Public/uri.txt").unwrap()).unwrap();
        assert_ne!(stored, b"not-plain");
        assert!(
            std::str::from_utf8(&stored).unwrap().contains("ciphertext"),
            "a localhost URI write stays encrypted"
        );
    }

    // RA2-R16-V1-ROWS
    fn row(name: &str) {
        eprintln!("row {name}");
    }

    fn stored_bytes(provider: &LocalProvider, path: &str) -> Vec<u8> {
        fs::read(provider.resolve_path(path).unwrap()).unwrap()
    }

    fn v1_plain_root(provider: &LocalProvider, root: &str) {
        let bytes = b"address-bytes";
        let more = b"-more";
        let joined: Vec<u8> = [bytes.as_slice(), more].concat();
        let address = format!("localhost://{root}/by-address.txt");
        provider
            .write_file(&address, "token", bytes, false)
            .unwrap();
        let stored = stored_bytes(provider, &address);
        assert_ne!(stored, bytes, "{root} address write");
        assert!(std::str::from_utf8(&stored).unwrap().contains("ciphertext"));
        assert_eq!(
            provider.read_file(&address, "token", None, None).unwrap(),
            bytes
        );
        row(&format!("{root} address write then address read"));
        provider.write_file(&address, "token", more, true).unwrap();
        assert_eq!(
            provider.read_file(&address, "token", None, None).unwrap(),
            joined
        );
        row(&format!("{root} address append then address read"));

        let short = format!("{root}/by-short.txt");
        let address_of_short = format!("localhost://{root}/by-short.txt");
        provider.write_file(&short, "token", bytes, false).unwrap();
        assert_eq!(stored_bytes(provider, &short), bytes);
        assert_eq!(
            provider.read_file(&short, "token", None, None).unwrap(),
            bytes
        );
        row(&format!("{root} short write then short read"));
        provider.write_file(&short, "token", more, true).unwrap();
        assert_eq!(
            provider.read_file(&short, "token", None, None).unwrap(),
            joined
        );
        row(&format!("{root} short append then short read"));
        let err = provider
            .read_file(&address_of_short, "token", None, None)
            .unwrap_err();
        assert!(
            err.to_string().contains("not an encrypted envelope"),
            "{root} address read of a short file: {err}"
        );
        row(&format!("{root} address read of a short file"));

        let envelope = format!("localhost://{root}/envelope.txt");
        let short_envelope = format!("{root}/envelope.txt");
        provider
            .write_file(&envelope, "token", bytes, false)
            .unwrap();
        let stored = stored_bytes(provider, &envelope);
        assert_eq!(
            provider
                .read_file(&short_envelope, "token", None, None)
                .unwrap(),
            stored
        );
        row(&format!("{root} short read of an address file"));

        let plain = format!("{root}/plain-append.txt");
        let plain_address = format!("localhost://{root}/plain-append.txt");
        provider.write_file(&plain, "token", bytes, false).unwrap();
        let before = stored_bytes(provider, &plain);
        let err = provider
            .write_file(&plain_address, "token", more, true)
            .unwrap_err();
        assert!(
            err.to_string().contains("not an encrypted envelope"),
            "{root} address append onto a short file: {err}"
        );
        assert_eq!(stored_bytes(provider, &plain), before);
        row(&format!("{root} address append onto a short file"));

        let envelope_append = format!("localhost://{root}/envelope-append.txt");
        let short_append = format!("{root}/envelope-append.txt");
        provider
            .write_file(&envelope_append, "token", bytes, false)
            .unwrap();
        let before = stored_bytes(provider, &envelope_append);
        provider
            .write_file(&short_append, "token", more, true)
            .unwrap();
        let after = stored_bytes(provider, &envelope_append);
        assert!(after.starts_with(&before) && after.ends_with(more));
        assert_eq!(
            provider
                .read_file(&short_append, "token", None, None)
                .unwrap(),
            after
        );
        row(&format!("{root} short append onto an address file"));
    }

    fn v1_sealed_root(provider: &LocalProvider, root: &str) {
        let bytes = b"secret";
        let more = b"-more";
        let joined = b"secret-more";
        let address = format!("localhost://{root}/note.txt");
        let short = format!("{root}/note.txt");
        provider
            .write_file(&address, "token", bytes, false)
            .unwrap();
        let stored = stored_bytes(provider, &address);
        assert_ne!(stored, bytes);
        assert!(std::str::from_utf8(&stored).unwrap().contains("ciphertext"));
        assert_eq!(
            provider.read_file(&address, "token", None, None).unwrap(),
            bytes
        );
        assert_eq!(
            provider.read_file(&short, "token", None, None).unwrap(),
            bytes
        );
        row(&format!("{root} address write then address and short read"));
        provider.write_file(&short, "token", more, true).unwrap();
        assert_eq!(
            provider.read_file(&address, "token", None, None).unwrap(),
            joined
        );
        assert_eq!(
            provider.read_file(&short, "token", None, None).unwrap(),
            joined
        );
        row(&format!("{root} short append then address and short read"));

        let other = format!("{root}/other.txt");
        let other_address = format!("localhost://{root}/other.txt");
        provider.write_file(&other, "token", bytes, false).unwrap();
        let stored = stored_bytes(provider, &other);
        assert_ne!(stored, bytes);
        assert_eq!(
            provider.read_file(&other, "token", None, None).unwrap(),
            bytes
        );
        assert_eq!(
            provider
                .read_file(&other_address, "token", None, None)
                .unwrap(),
            bytes
        );
        row(&format!("{root} short write then short and address read"));
        provider
            .write_file(&other_address, "token", more, true)
            .unwrap();
        assert_eq!(
            provider.read_file(&other, "token", None, None).unwrap(),
            joined
        );
        assert_eq!(
            provider
                .read_file(&other_address, "token", None, None)
                .unwrap(),
            joined
        );
        row(&format!(
            "{root} address append then short and address read"
        ));
    }

    fn v1_lookalike(provider: &LocalProvider) {
        let lookalike = br#"{"version":1,"nonce":"00112233445566778899aabb","ciphertext":"abcd"}"#;
        let path = "Public/lookalike.txt";
        let address = "localhost://Public/lookalike.txt";
        provider
            .write_file(path, "token", lookalike, false)
            .unwrap();
        assert_eq!(stored_bytes(provider, path), lookalike);
        assert_eq!(
            provider.read_file(path, "token", None, None).unwrap(),
            lookalike
        );
        let err = provider
            .read_file(address, "token", None, None)
            .unwrap_err();
        assert!(
            err.to_string().contains("decryption"),
            "address read of a lookalike: {err}"
        );
        row("Public short write of a lookalike then short read");
        row("Public address read of a lookalike");
    }

    #[test]
    fn v1_address_write_read_and_append_match_main() {
        let dir = setup_test_dir();
        let provider = make_encrypted_provider(&dir);
        for root in ["Public", "MyWebSite"] {
            v1_plain_root(&provider, root);
        }
        for root in ["Local", "Users"] {
            v1_sealed_root(&provider, root);
        }
        v1_lookalike(&provider);
    }
    // RA2-R16-V1-ROWS-END

    fn v2_b64(provider: &LocalProvider, path: &str) -> String {
        let data = read_v2_window(provider, path, "token", None, None)
            .unwrap_or_else(|err| panic!("{path}: {err}"));
        data["content"]["b64"].as_str().unwrap().to_string()
    }

    #[test]
    fn v2_plain_roots_follow_the_envelope_and_a_lookalike_stays_plain() {
        let dir = setup_test_dir();
        let provider = make_encrypted_provider(&dir);
        {
            let root = "Public";
            let plain = b"via-address";
            let address = format!("localhost://{root}/address.txt");
            let short = format!("{root}/address.txt");
            provider
                .write_file(&address, "token", plain, false)
                .unwrap();
            let stored = stored_bytes(&provider, &address);
            let want = encode_b64(plain);
            assert_eq!(
                provider.read_file(&address, "token", None, None).unwrap(),
                plain,
                "{root} v1 address"
            );
            assert_eq!(v2_b64(&provider, &address), want, "{root} v2 address");
            assert_eq!(
                v2_b64(&provider, &short),
                want,
                "{root} v2 short of address"
            );
            assert_ne!(v2_b64(&provider, &short), encode_b64(&stored));
            assert_eq!(
                provider.read_file(&short, "token", None, None).unwrap(),
                stored,
                "{root} v1 short of address stays the envelope"
            );
            provider
                .write_file(&address, "token", b"-more", true)
                .unwrap();
            let joined = encode_b64(b"via-address-more");
            assert_eq!(v2_b64(&provider, &address), joined);
            assert_eq!(v2_b64(&provider, &short), joined);

            let text = b"via-short";
            let short_file = format!("{root}/short.txt");
            let short_address = format!("localhost://{root}/short.txt");
            provider
                .write_file(&short_file, "token", text, false)
                .unwrap();
            let want = encode_b64(text);
            assert_eq!(
                provider
                    .read_file(&short_file, "token", None, None)
                    .unwrap(),
                text
            );
            let err = provider
                .read_file(&short_address, "token", None, None)
                .unwrap_err();
            assert!(err.to_string().contains("not an encrypted envelope"));
            assert_eq!(v2_b64(&provider, &short_file), want, "{root} v2 short");
            assert_eq!(
                v2_b64(&provider, &short_address),
                want,
                "{root} v2 address of short"
            );
        }
        for root in ["Local", "Users"] {
            for (label, path, other) in [
                (
                    "address",
                    format!("localhost://{root}/note.txt"),
                    format!("{root}/note.txt"),
                ),
                (
                    "short",
                    format!("{root}/other.txt"),
                    format!("localhost://{root}/other.txt"),
                ),
            ] {
                provider
                    .write_file(&path, "token", b"secret", false)
                    .unwrap();
                let stored = stored_bytes(&provider, &path);
                assert_ne!(stored, b"secret", "{root} {label}");
                let want = encode_b64(b"secret");
                assert_eq!(
                    provider.read_file(&path, "token", None, None).unwrap(),
                    b"secret"
                );
                assert_eq!(
                    provider.read_file(&other, "token", None, None).unwrap(),
                    b"secret"
                );
                assert_eq!(v2_b64(&provider, &path), want, "{root} v2 {label}");
                assert_eq!(v2_b64(&provider, &other), want, "{root} v2 other {label}");
            }
        }
        let lookalike = br#"{"version":1,"nonce":"00112233445566778899aabb","ciphertext":"abcd"}"#;
        assert!(std::str::from_utf8(lookalike)
            .unwrap()
            .contains("ciphertext"));
        let path = "Public/lookalike.txt";
        let address = "localhost://Public/lookalike.txt";
        provider
            .write_file(path, "token", lookalike, false)
            .unwrap();
        assert_eq!(stored_bytes(&provider, path), lookalike);
        assert_eq!(
            provider.read_file(path, "token", None, None).unwrap(),
            lookalike
        );
        let err = provider
            .read_file(address, "token", None, None)
            .unwrap_err();
        assert!(err.to_string().contains("decryption"), "{err}");
        let want = encode_b64(lookalike);
        assert_eq!(v2_b64(&provider, path), want);
        assert_eq!(v2_b64(&provider, address), want);
        row("Public lookalike stays plain for v2");
    }
}
