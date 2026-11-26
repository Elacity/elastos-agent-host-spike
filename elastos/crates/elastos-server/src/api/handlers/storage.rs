//! Mutable storage API handlers
//!
//! HTTP handlers for file-backed localhost:// roots.
//!
//! Public contract: rooted local paths such as `MyWebSite/...`.
//! Principal-owned `Users/...` roots require a runtime principal context and
//! must use the Home/provider routes that can encrypt protected roots.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use elastos_common::localhost::{parse_localhost_uri, rooted_localhost_uri};
use elastos_runtime::capability::{Action, CapabilityManager, CapabilityToken, ResourceId};
use elastos_runtime::primitives::audit::AuditLog;
use elastos_runtime::provider::{
    EntryType as ProviderEntryType, ProviderError, ProviderRegistry, ResourceAction,
    ResourceResponse,
};
use elastos_runtime::session::Session;

/// Shared state for storage handlers (backed by ProviderRegistry)
#[derive(Clone)]
pub struct ProviderStorageState {
    pub registry: Arc<ProviderRegistry>,
    pub audit_log: Option<Arc<AuditLog>>,
    pub capability_manager: Option<Arc<CapabilityManager>>,
    /// Per-capsule storage quota in MB. 0 means unlimited.
    pub storage_quota_mb: u32,
    /// This Home's data folder. The local-apps refusal is stored for this path.
    pub data_dir: std::path::PathBuf,
}

/// Storage API errors
#[derive(Debug)]
pub enum StorageApiError {
    NotFound(String),
    PermissionDenied(String),
    InvalidPath(String),
    QuotaExceeded(String),
    LocalApps(String),
    Internal(String),
}

impl IntoResponse for StorageApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            StorageApiError::NotFound(path) => {
                (StatusCode::NOT_FOUND, format!("Not found: {}", path))
            }
            StorageApiError::PermissionDenied(msg) => {
                (StatusCode::FORBIDDEN, format!("Permission denied: {}", msg))
            }
            StorageApiError::InvalidPath(msg) => {
                (StatusCode::BAD_REQUEST, format!("Invalid path: {}", msg))
            }
            StorageApiError::QuotaExceeded(msg) => (
                StatusCode::INSUFFICIENT_STORAGE,
                format!("Storage quota exceeded: {}", msg),
            ),
            StorageApiError::LocalApps(sentence) => (StatusCode::SERVICE_UNAVAILABLE, sentence),
            StorageApiError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", msg),
            ),
        };

        (status, message).into_response()
    }
}

impl From<ProviderError> for StorageApiError {
    fn from(err: ProviderError) -> Self {
        match err {
            ProviderError::NotFound(p) => StorageApiError::NotFound(p),
            ProviderError::PermissionDenied(m) => StorageApiError::PermissionDenied(m),
            ProviderError::InvalidUri(m) => StorageApiError::InvalidPath(m),
            ProviderError::NoProvider(m) => {
                StorageApiError::Internal(format!("No provider: {}", m))
            }
            ProviderError::Provider(m) => {
                match crate::local_apps::sentence_from_local_apps_provider_error(&m) {
                    // No caller is known here, so the file name stays in the map.
                    Some(_) => StorageApiError::LocalApps(
                        crate::local_apps::LOCAL_APPS_OFF_TO_OTHERS.to_string(),
                    ),
                    None => StorageApiError::Internal(m),
                }
            }
            ProviderError::Unavailable(m) => {
                StorageApiError::Internal(format!("Peer unavailable: {}", m))
            }
            ProviderError::Io(e) => StorageApiError::Internal(e.to_string()),
            ProviderError::NotEnoughFreeSpace(e) => StorageApiError::Internal(e.to_string()),
        }
    }
}

// === Read File ===

/// GET /api/localhost/*path
///
/// Read a file from a file-backed localhost root.
/// Returns the file contents with appropriate content-type.
fn owner_shell(session: &Session, headers: &HeaderMap) -> bool {
    session.is_shell() && !headers.contains_key("X-Elastos-Capsule-Id")
}

/// A caller who would be refused anyway gets that 403 first. The owner's
/// shell sees the file sentence. A guest shell is ambient and sees one plain line.
async fn refuse_local_apps(
    state: &ProviderStorageState,
    session: &Session,
    headers: &HeaderMap,
    path: &str,
    op: &str,
) -> Result<(), StorageApiError> {
    let Some(sentence) = crate::local_apps::await_local_apps_decision(&state.data_dir).await else {
        return Ok(());
    };
    if owner_shell(session, headers) {
        return Err(StorageApiError::LocalApps(sentence));
    }
    let path = normalize_path(path);
    reject_principal_root_storage_path(&path)?;
    enforce_capability(state, session, headers, &path, row_right(op)?).await?;
    Err(StorageApiError::LocalApps(
        crate::local_apps::local_apps_refusal_body(&sentence, false),
    ))
}

pub async fn read_file(
    State(state): State<ProviderStorageState>,
    Extension(session): Extension<Session>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Result<Response, StorageApiError> {
    refuse_local_apps(&state, &session, &headers, &path, "read").await?;
    let user_id = session_user_id(&session);
    let path = normalize_path(&path);
    reject_principal_root_storage_path(&path)?;
    enforce_capability(&state, &session, &headers, &path, row_right("read")?).await?;
    let uri = canonical_local_uri(&path)?;

    let result = state
        .registry
        .route(&uri, session.id.as_str(), ResourceAction::Read, None)
        .await;
    let success = result.is_ok();
    emit_audit(&state, &session, &user_id, &uri, "read", success);

    match result? {
        ResourceResponse::Data(data) => {
            let content_type = guess_content_type(&path);
            Ok(([(header::CONTENT_TYPE, content_type)], data).into_response())
        }
        _ => Err(StorageApiError::Internal("Unexpected response".into())),
    }
}

// === Write File ===

/// PUT /api/localhost/*path
///
/// Write a file to a file-backed localhost root.
/// Creates parent directories as needed.
pub async fn write_file(
    State(state): State<ProviderStorageState>,
    Extension(session): Extension<Session>,
    headers: HeaderMap,
    Path(path): Path<String>,
    body: Bytes,
) -> Result<Json<WriteOutput>, StorageApiError> {
    refuse_local_apps(&state, &session, &headers, &path, "write").await?;
    let user_id = session_user_id(&session);
    let path = normalize_path(&path);
    reject_principal_root_storage_path(&path)?;
    enforce_capability(&state, &session, &headers, &path, row_right("write")?).await?;

    // Enforce storage quota (0 = unlimited)
    if state.storage_quota_mb > 0 {
        let quota_bytes = state.storage_quota_mb as u64 * 1024 * 1024;
        let current_usage = state.registry.storage_usage(&user_id).await.unwrap_or(0);
        if current_usage + body.len() as u64 > quota_bytes {
            return Err(StorageApiError::QuotaExceeded(format!(
                "write of {} bytes would exceed {}MB quota (current usage: {} bytes)",
                body.len(),
                state.storage_quota_mb,
                current_usage
            )));
        }
    }

    let uri = canonical_local_uri(&path)?;

    let result = state
        .registry
        .route(
            &uri,
            session.id.as_str(),
            ResourceAction::Write,
            Some(body.to_vec()),
        )
        .await;
    let success = result.is_ok();
    emit_audit(&state, &session, &user_id, &uri, "write", success);

    match result? {
        ResourceResponse::Written { bytes } => Ok(Json(WriteOutput {
            path: canonical_local_uri(&path)?,
            size: bytes as u64,
        })),
        _ => Err(StorageApiError::Internal("Unexpected response".into())),
    }
}

#[derive(Debug, Serialize)]
pub struct WriteOutput {
    /// Path that was written
    pub path: String,
    /// Size in bytes
    pub size: u64,
}

// === Delete ===

/// DELETE /api/localhost/*path
///
/// Delete a file or empty directory.
/// Use ?recursive=true to delete non-empty directories.
pub async fn delete_path(
    State(state): State<ProviderStorageState>,
    Extension(session): Extension<Session>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<Json<DeleteOutput>, StorageApiError> {
    refuse_local_apps(&state, &session, &headers, &path, "delete").await?;
    let user_id = session_user_id(&session);
    let path = normalize_path(&path);
    reject_principal_root_storage_path(&path)?;
    enforce_capability(&state, &session, &headers, &path, row_right("delete")?).await?;
    let uri = canonical_local_uri(&path)?;
    let recursive = query.recursive.unwrap_or(false);

    let result = state
        .registry
        .route_with_options(
            &uri,
            session.id.as_str(),
            ResourceAction::Delete,
            None,
            recursive,
        )
        .await;
    let success = result.is_ok();
    emit_audit(&state, &session, &user_id, &uri, "delete", success);
    result?;

    Ok(Json(DeleteOutput {
        path: canonical_local_uri(&path)?,
        deleted: true,
    }))
}

#[derive(Debug, Deserialize)]
pub struct DeleteQuery {
    /// Delete recursively (for non-empty directories)
    pub recursive: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct DeleteOutput {
    /// Path that was deleted
    pub path: String,
    /// Whether deletion succeeded
    pub deleted: bool,
}

// === List Directory ===

/// GET /api/localhost/*path?list=true
///
/// List contents of a directory.
pub async fn list_dir(
    State(state): State<ProviderStorageState>,
    Extension(session): Extension<Session>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Result<Json<ListOutput>, StorageApiError> {
    refuse_local_apps(&state, &session, &headers, &path, "list").await?;
    let user_id = session_user_id(&session);
    let path = normalize_path(&path);
    reject_principal_root_storage_path(&path)?;
    enforce_capability(&state, &session, &headers, &path, row_right("list")?).await?;
    let uri = canonical_local_uri(&path)?;

    let result = state
        .registry
        .route(&uri, session.id.as_str(), ResourceAction::List, None)
        .await;
    let success = result.is_ok();
    emit_audit(&state, &session, &user_id, &uri, "list", success);

    match result? {
        ResourceResponse::List(entries) => {
            let entries: Vec<EntryOutput> = entries
                .into_iter()
                .map(|e| {
                    let entry_type = if e.is_directory {
                        elastos_storage::EntryType::Directory
                    } else {
                        elastos_storage::EntryType::File
                    };
                    let entry_path = if path.is_empty() {
                        e.name.clone()
                    } else {
                        format!("{}/{}", path, e.name)
                    };
                    Ok(EntryOutput {
                        name: e.name.clone(),
                        path: canonical_local_uri(&entry_path)?,
                        entry_type,
                        size: e.size.unwrap_or(0),
                        modified: e.modified.unwrap_or(0),
                    })
                })
                .collect::<Result<_, StorageApiError>>()?;

            Ok(Json(ListOutput {
                path: canonical_local_uri(&path)?,
                entries,
            }))
        }
        _ => Err(StorageApiError::Internal("Unexpected response".into())),
    }
}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    /// Path that was listed
    pub path: String,
    /// Directory entries
    pub entries: Vec<EntryOutput>,
}

#[derive(Debug, Serialize)]
pub struct EntryOutput {
    /// Entry name
    pub name: String,
    /// Full path (localhost://...)
    pub path: String,
    /// Type: "file" or "directory"
    #[serde(rename = "type")]
    pub entry_type: elastos_storage::EntryType,
    /// Size in bytes
    pub size: u64,
    /// Last modified timestamp (unix seconds)
    pub modified: u64,
}

// === Stat / Exists ===

/// HEAD /api/localhost/*path
///
/// Check if a path exists and get metadata.
/// Returns 200 with headers if exists, 404 if not.
pub async fn stat_path(
    State(state): State<ProviderStorageState>,
    Extension(session): Extension<Session>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Result<Response, StorageApiError> {
    refuse_local_apps(&state, &session, &headers, &path, "stat").await?;
    let user_id = session_user_id(&session);
    let path = normalize_path(&path);
    reject_principal_root_storage_path(&path)?;
    enforce_capability(&state, &session, &headers, &path, row_right("stat")?).await?;
    let uri = canonical_local_uri(&path)?;

    let result = state
        .registry
        .route(&uri, session.id.as_str(), ResourceAction::Stat, None)
        .await;
    let success = result.is_ok();
    emit_audit(&state, &session, &user_id, &uri, "stat", success);

    match result? {
        ResourceResponse::Metadata {
            size,
            entry_type,
            modified,
        } => {
            let type_str = match entry_type {
                ProviderEntryType::File => "file",
                ProviderEntryType::Directory => "directory",
            };

            Ok((
                StatusCode::OK,
                [
                    ("X-Entry-Type", type_str),
                    ("X-Size", &size.to_string()),
                    ("X-Modified", &modified.to_string()),
                ],
            )
                .into_response())
        }
        _ => Err(StorageApiError::Internal("Unexpected response".into())),
    }
}

// === Mkdir ===

/// POST /api/localhost/*path?mkdir=true
///
/// Create a directory (and parents).
pub async fn mkdir(
    State(state): State<ProviderStorageState>,
    Extension(session): Extension<Session>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Result<Json<MkdirOutput>, StorageApiError> {
    refuse_local_apps(&state, &session, &headers, &path, "mkdir").await?;
    let user_id = session_user_id(&session);
    let path = normalize_path(&path);
    reject_principal_root_storage_path(&path)?;
    enforce_capability(&state, &session, &headers, &path, row_right("mkdir")?).await?;
    let uri = canonical_local_uri(&path)?;

    let result = state
        .registry
        .route(&uri, session.id.as_str(), ResourceAction::Mkdir, None)
        .await;
    let success = result.is_ok();
    emit_audit(&state, &session, &user_id, &uri, "mkdir", success);
    result?;

    Ok(Json(MkdirOutput {
        path: canonical_local_uri(&path)?,
        created: true,
    }))
}

#[derive(Debug, Serialize)]
pub struct MkdirOutput {
    /// Path that was created
    pub path: String,
    /// Whether directory was created
    pub created: bool,
}

// === Capability Enforcement ===

fn row_right(op: &str) -> Result<Action, StorageApiError> {
    crate::provider_resource::provider_operation_action("localhost", op).ok_or_else(|| {
        StorageApiError::PermissionDenied(format!("localhost operation {op} has no required right"))
    })
}

/// Validate that the session has permission for this storage operation.
///
/// Shell sessions are exempt (orchestrator privilege).
/// Capsule sessions must provide a valid capability token in X-Capability-Token header.
async fn enforce_capability(
    state: &ProviderStorageState,
    session: &Session,
    headers: &HeaderMap,
    path: &str,
    action: Action,
) -> Result<(), StorageApiError> {
    // Shell sessions have orchestrator privilege — no token needed
    if session.is_shell() {
        return Ok(());
    }

    let cap_mgr = match state.capability_manager {
        Some(ref mgr) => mgr,
        None => {
            return Err(StorageApiError::PermissionDenied(
                "capability manager not configured — storage access denied (no ambient authority)"
                    .into(),
            ));
        }
    };

    let token_b64 = headers
        .get("X-Capability-Token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            StorageApiError::PermissionDenied("missing X-Capability-Token header".into())
        })?;

    let token = CapabilityToken::from_base64(token_b64)
        .map_err(|e| StorageApiError::PermissionDenied(format!("invalid token: {}", e)))?;

    let resource = ResourceId::new(canonical_local_uri(path)?);

    cap_mgr
        .validate(&token, session.id.as_str(), action, &resource, None)
        .await
        .map_err(|e| StorageApiError::PermissionDenied(e.to_string()))
}

// === Helpers ===

/// Emit audit event for storage operations
fn emit_audit(
    state: &ProviderStorageState,
    session: &Session,
    user_id: &str,
    uri: &str,
    action: &str,
    success: bool,
) {
    if let Some(ref audit) = state.audit_log {
        audit.storage_access(session.id.as_str(), user_id, uri, action, success);
    }
}

/// Get user ID from session for storage isolation.
/// Uses owner if set, otherwise derives from session ID.
fn session_user_id(session: &Session) -> String {
    if let Some(ref owner) = session.owner {
        owner.clone()
    } else {
        // Derive deterministic user ID from session ID
        let hash = Sha256::digest(session.id.as_str().as_bytes());
        hex::encode(hash)
    }
}

/// Normalize a path from the URL.
fn normalize_path(path: &str) -> String {
    let path = path.trim();
    let path = path.strip_prefix("localhost://").unwrap_or(path);
    let path = path.trim_matches('/');
    path.to_string()
}

fn canonical_local_uri(path: &str) -> Result<String, StorageApiError> {
    if path.is_empty() {
        return Ok("localhost://".to_string());
    }

    rooted_localhost_uri(path).ok_or_else(|| {
        StorageApiError::InvalidPath("path must be rooted under localhost://<root>/...".to_string())
    })
}

fn reject_principal_root_storage_path(path: &str) -> Result<(), StorageApiError> {
    let uri = canonical_local_uri(path)?;
    if matches!(parse_localhost_uri(&uri), Some(("Users" | "UsersAI", _))) {
        return Err(StorageApiError::PermissionDenied(
            "principal-root storage requires a runtime principal-scoped provider route".into(),
        ));
    }
    if path.split('/').any(|segment| segment == "..") {
        return Err(StorageApiError::InvalidPath(
            "path must not contain parent segments".to_string(),
        ));
    }
    Ok(())
}

/// Guess content type from file extension.
fn guess_content_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext.to_lowercase().as_str() {
        "json" => "application/json",
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "xml" => "application/xml",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

// === Query params for routing ===

#[derive(Debug, Deserialize)]
pub struct StorageQuery {
    /// If true, list directory contents
    pub list: Option<bool>,
    /// If true, create directory
    pub mkdir: Option<bool>,
}

/// Root handler (no path parameter) - for /api/localhost without a subpath.
pub async fn handle_get_root(
    state: State<ProviderStorageState>,
    session: Extension<Session>,
    headers: HeaderMap,
    Query(query): Query<StorageQuery>,
) -> Result<Response, StorageApiError> {
    if !query.list.unwrap_or(false) {
        if owner_shell(&session, &headers) {
            if let Some(sentence) = crate::local_apps::local_apps_refusal(&state.data_dir) {
                return Err(StorageApiError::LocalApps(sentence));
            }
        }
        return Err(StorageApiError::InvalidPath(
            "Cannot read root as file".to_string(),
        ));
    }
    list_dir(state, session, headers, Path(String::new()))
        .await
        .map(|j| j.into_response())
}

/// Combined handler that routes based on query params and method.
/// This simplifies routing for the wildcard path.
pub async fn handle_get(
    state: State<ProviderStorageState>,
    session: Extension<Session>,
    headers: HeaderMap,
    path: Path<String>,
    Query(query): Query<StorageQuery>,
) -> Result<Response, StorageApiError> {
    if query.list.unwrap_or(false) {
        list_dir(state, session, headers, path)
            .await
            .map(|j| j.into_response())
    } else {
        read_file(state, session, headers, path).await
    }
}

pub async fn handle_post(
    state: State<ProviderStorageState>,
    session: Extension<Session>,
    headers: HeaderMap,
    path: Path<String>,
    Query(query): Query<StorageQuery>,
    body: Bytes,
) -> Result<Response, StorageApiError> {
    if query.mkdir.unwrap_or(false) {
        mkdir(state, session, headers, path)
            .await
            .map(|j| j.into_response())
    } else {
        // POST without mkdir acts like PUT (write file)
        write_file(state, session, headers, path, body)
            .await
            .map(|j| j.into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastos_runtime::capability::{CapabilityStore, TokenConstraints};
    use elastos_runtime::primitives::metrics::MetricsManager;
    use elastos_runtime::session::SessionType;

    #[cfg(unix)]
    #[tokio::test]
    async fn s5_p7_storage_closes_both_launched_agent_roots() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = crate::api::routes::tests::ProbeLaunch::new(&["s5-x", "s5-y"]).await;
        let x = home.agents[0].clone();
        let y = home.agents[1].clone();
        let _vm_id = home.launched_instance_id(&x).await;
        let x_root = home.root(&x);
        let y_root = home.root(&y);
        let y_file = home
            .data_dir
            .join(y_root.trim_start_matches("localhost://"))
            .join("memory/notes.md");
        std::fs::create_dir_all(y_file.parent().unwrap()).unwrap();
        std::fs::write(&y_file, b"Y private bytes").unwrap();
        let y_segment = y_root.strip_prefix("localhost://UsersAI/").unwrap();
        let x_segment = x_root.strip_prefix("localhost://UsersAI/").unwrap();
        for raw in [
            y_root.clone(),
            format!("{y_root}/memory/notes.md"),
            "UsersAI".to_owned(),
            "UsersAI/".to_owned(),
            format!("UsersAI/./{y_segment}/memory/notes.md"),
            format!("UsersAI//{y_segment}/memory/notes.md"),
            format!("UsersAI/{x_segment}/../{y_segment}/memory/notes.md"),
            x_root.clone(),
            format!("{x_root}/memory/notes.md"),
        ] {
            let path = normalize_path(&raw);
            assert!(
                reject_principal_root_storage_path(&path).is_err(),
                "P7 X's storage route accepted {raw:?} -> {path:?}"
            );
            assert_eq!(std::fs::read(&y_file).unwrap(), b"Y private bytes");
        }
        assert!(home.pending_store.list_pending().await.is_empty());
    }

    /// Every principal-root path is refused on this route, however it is
    /// spelled: the guard must see what the route will use, after trimming.
    #[test]
    fn a_users_path_is_refused_however_it_is_spaced() {
        for raw in [
            "Users/h/.AppData/Agents/agent-host",
            " Users/h/.AppData/Agents/agent-host",
            "/ Users/h/.AppData/Agents/agent-host",
            "/\tUsers/h/.AppData/Agents/agent-host",
            "localhost:// Users/h/.AppData/Agents/agent-host",
            "\u{a0}Users/h/Documents/a.md",
            "Users",
            " Users ",
        ] {
            let path = normalize_path(raw);
            assert!(
                reject_principal_root_storage_path(&path).is_err(),
                "{raw:?} -> {path:?} must be refused"
            );
        }
        for raw in [
            "Local/SharedByLocalUsersAndBots/Home/a.md",
            "MyWebSite/index.html",
        ] {
            assert!(
                reject_principal_root_storage_path(&normalize_path(raw)).is_ok(),
                "{raw}"
            );
        }
    }

    use axum::{body::Body, http::Request};
    use elastos_runtime::provider::{Provider, ResourceRequest};
    use tokio::sync::Mutex;
    use tower::ServiceExt;

    #[derive(Default)]
    struct RecordingLocalhostProvider {
        requests: Mutex<Vec<ResourceRequest>>,
    }

    #[async_trait::async_trait]
    impl Provider for RecordingLocalhostProvider {
        async fn handle(
            &self,
            request: ResourceRequest,
        ) -> Result<ResourceResponse, ProviderError> {
            self.requests.lock().await.push(request);
            Ok(ResourceResponse::Data(b"allowed".to_vec()))
        }

        fn schemes(&self) -> Vec<&'static str> {
            vec!["localhost"]
        }

        fn name(&self) -> &'static str {
            "recording-localhost"
        }
    }

    #[tokio::test]
    async fn storage_http_refuses_principal_areas_for_all_operations() {
        let registry = Arc::new(ProviderRegistry::new());
        let provider = Arc::new(RecordingLocalhostProvider::default());
        registry.register(provider.clone()).await;
        let app = crate::api::server::storage_router()
            .layer(Extension(make_session(SessionType::Shell)))
            .with_state(ProviderStorageState {
                data_dir: std::path::PathBuf::new(),
                registry,
                audit_log: None,
                capability_manager: None,
                storage_quota_mb: 0,
            });

        for area in ["Users", "UsersAI"] {
            let child = format!("{area}/owner/Documents/a.md");
            let spellings = [
                format!("%2F%20{child}"),
                format!("localhost:%2F%2F%20{child}"),
                format!("localhost:%2F%2Flocalhost:%2F%2F{child}"),
                format!("%20{child}"),
                format!("%2F%09{child}"),
                format!("%2F%0A{child}"),
                format!("%2F%C2%A0{child}"),
                area.to_string(),
                format!("{area}/"),
                format!("{child}/"),
                format!("{area}//owner//Documents/a.md"),
                format!("{area}/./owner/Documents/a.md"),
                format!("{area}/owner/../owner/Documents/a.md"),
            ];
            for spelling in spellings {
                for (method, query) in [
                    ("GET", ""),
                    ("PUT", ""),
                    ("DELETE", ""),
                    ("GET", "?list=true"),
                    ("HEAD", ""),
                    ("POST", "?mkdir=true"),
                ] {
                    let response = app
                        .clone()
                        .oneshot(
                            Request::builder()
                                .method(method)
                                .uri(format!("/api/localhost/{spelling}{query}"))
                                .body(Body::from("test"))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status(),
                        StatusCode::FORBIDDEN,
                        "{method} {spelling}{query}"
                    );
                }
            }
        }
        assert!(provider.requests.lock().await.is_empty());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/localhost/MyWebSite/Pictures/allowed.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), b"allowed");
        let requests = provider.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].uri,
            "localhost://MyWebSite/Pictures/allowed.txt"
        );
    }

    fn make_capability_manager() -> Arc<CapabilityManager> {
        let store = Arc::new(CapabilityStore::new());
        let audit = Arc::new(AuditLog::new());
        let metrics = Arc::new(MetricsManager::new());
        Arc::new(CapabilityManager::new(store, audit, metrics))
    }

    fn make_session(session_type: SessionType) -> Session {
        Session::new(session_type, None)
    }

    fn make_state(cap_mgr: Option<Arc<CapabilityManager>>) -> ProviderStorageState {
        ProviderStorageState {
            data_dir: std::path::PathBuf::new(),
            registry: Arc::new(ProviderRegistry::new()),
            audit_log: None,
            capability_manager: cap_mgr,
            storage_quota_mb: 0,
        }
    }

    #[tokio::test]
    async fn test_shell_session_exempt_from_capability_check() {
        let cap_mgr = make_capability_manager();
        let state = make_state(Some(cap_mgr));
        let session = make_session(SessionType::Shell);
        let headers = HeaderMap::new();

        let result = enforce_capability(
            &state,
            &session,
            &headers,
            "MyWebSite/Pictures/a.jpg",
            Action::Read,
        )
        .await;
        assert!(
            result.is_ok(),
            "Shell sessions should bypass capability check"
        );
    }

    #[tokio::test]
    async fn test_capsule_session_rejected_without_token() {
        let cap_mgr = make_capability_manager();
        let state = make_state(Some(cap_mgr));
        let session = make_session(SessionType::Capsule);
        let headers = HeaderMap::new();

        let result = enforce_capability(
            &state,
            &session,
            &headers,
            "MyWebSite/Pictures/a.jpg",
            Action::Read,
        )
        .await;
        assert!(matches!(result, Err(StorageApiError::PermissionDenied(_))));
    }

    #[tokio::test]
    async fn test_capsule_session_rejected_with_invalid_token() {
        let cap_mgr = make_capability_manager();
        let state = make_state(Some(cap_mgr));
        let session = make_session(SessionType::Capsule);
        let mut headers = HeaderMap::new();
        headers.insert("X-Capability-Token", "not-valid-base64!!".parse().unwrap());

        let result = enforce_capability(
            &state,
            &session,
            &headers,
            "MyWebSite/Pictures/a.jpg",
            Action::Read,
        )
        .await;
        assert!(matches!(result, Err(StorageApiError::PermissionDenied(_))));
    }

    #[tokio::test]
    async fn test_capsule_session_accepted_with_valid_token() {
        let cap_mgr = make_capability_manager();
        let session = make_session(SessionType::Capsule);

        // Grant a token for this session's capsule ID
        let token = cap_mgr.grant(
            session.id.as_str(),
            ResourceId::new("localhost://MyWebSite/Pictures/*"),
            Action::Read,
            TokenConstraints::default(),
            None,
        );
        let token_b64 = token.to_base64().unwrap();

        let state = make_state(Some(cap_mgr));
        let mut headers = HeaderMap::new();
        headers.insert("X-Capability-Token", token_b64.parse().unwrap());

        let result = enforce_capability(
            &state,
            &session,
            &headers,
            "MyWebSite/Pictures/a.jpg",
            Action::Read,
        )
        .await;
        assert!(result.is_ok(), "Valid token should be accepted");
    }

    #[tokio::test]
    async fn test_capsule_session_rejected_wrong_resource() {
        let cap_mgr = make_capability_manager();
        let session = make_session(SessionType::Capsule);

        // Grant for photos/*, but access documents/
        let token = cap_mgr.grant(
            session.id.as_str(),
            ResourceId::new("localhost://MyWebSite/Pictures/*"),
            Action::Read,
            TokenConstraints::default(),
            None,
        );
        let token_b64 = token.to_base64().unwrap();

        let state = make_state(Some(cap_mgr));
        let mut headers = HeaderMap::new();
        headers.insert("X-Capability-Token", token_b64.parse().unwrap());

        let result = enforce_capability(
            &state,
            &session,
            &headers,
            "MyWebSite/Documents/secret.txt",
            Action::Read,
        )
        .await;
        assert!(matches!(result, Err(StorageApiError::PermissionDenied(_))));
    }

    #[tokio::test]
    async fn test_capsule_session_rejected_wrong_action() {
        let cap_mgr = make_capability_manager();
        let session = make_session(SessionType::Capsule);

        // Grant read, but try to write
        let token = cap_mgr.grant(
            session.id.as_str(),
            ResourceId::new("localhost://MyWebSite/Pictures/*"),
            Action::Read,
            TokenConstraints::default(),
            None,
        );
        let token_b64 = token.to_base64().unwrap();

        let state = make_state(Some(cap_mgr));
        let mut headers = HeaderMap::new();
        headers.insert("X-Capability-Token", token_b64.parse().unwrap());

        let result = enforce_capability(
            &state,
            &session,
            &headers,
            "MyWebSite/Pictures/a.jpg",
            Action::Write,
        )
        .await;
        assert!(matches!(result, Err(StorageApiError::PermissionDenied(_))));
    }

    #[tokio::test]
    async fn test_no_capability_manager_denies_access() {
        let state = make_state(None);
        let session = make_session(SessionType::Capsule);
        let headers = HeaderMap::new();

        let result = enforce_capability(
            &state,
            &session,
            &headers,
            "MyWebSite/Pictures/a.jpg",
            Action::Read,
        )
        .await;
        assert!(
            matches!(result, Err(StorageApiError::PermissionDenied(_))),
            "No capability manager must deny access — no ambient authority"
        );
    }

    #[tokio::test]
    async fn test_public_storage_rejects_users_root_without_principal_context() {
        let state = State(make_state(None));
        let session = Extension(make_session(SessionType::Shell));
        let headers = HeaderMap::new();

        let write_result = write_file(
            state.clone(),
            session.clone(),
            headers.clone(),
            Path("Users/self/Documents/a.md".to_string()),
            Bytes::from_static(b"# draft"),
        )
        .await;
        assert!(matches!(
            write_result,
            Err(StorageApiError::PermissionDenied(message))
                if message.contains("principal-scoped provider route")
        ));

        let list_result = list_dir(
            state,
            session,
            headers,
            Path("localhost://Users/foreign-root/Documents".to_string()),
        )
        .await;
        assert!(matches!(
            list_result,
            Err(StorageApiError::PermissionDenied(message))
                if message.contains("principal-scoped provider route")
        ));
    }

    const PRINCIPAL_AREA_SPELLINGS: &[&str] = &[
        "UsersAI",
        "UsersAI/",
        "localhost://UsersAI",
        "/UsersAI",
        "UsersAI//agent-root/Documents/a.md",
        "UsersAI/./agent-root/Documents/a.md",
        "UsersAI/agent-root/../agent-root/Documents/a.md",
        "/UsersAI/agent-root/Documents/a.md",
        "localhost://UsersAI/agent-root/Documents/a.md",
    ];

    #[tokio::test]
    async fn shell_storage_rejects_every_agent_root_spelling() {
        for spelling in PRINCIPAL_AREA_SPELLINGS {
            let state = State(make_state(None));
            let session = Extension(make_session(SessionType::Shell));
            let headers = HeaderMap::new();

            let read_result = read_file(
                state.clone(),
                session.clone(),
                headers.clone(),
                Path((*spelling).to_string()),
            )
            .await;
            assert!(
                matches!(
                    read_result,
                    Err(StorageApiError::PermissionDenied(message))
                        if message.contains("principal-scoped provider route")
                ),
                "read {spelling}"
            );

            let write_result = write_file(
                state.clone(),
                session.clone(),
                headers.clone(),
                Path((*spelling).to_string()),
                Bytes::from_static(b"# draft"),
            )
            .await;
            assert!(
                matches!(
                    write_result,
                    Err(StorageApiError::PermissionDenied(message))
                        if message.contains("principal-scoped provider route")
                ),
                "write {spelling}"
            );

            let delete_result = delete_path(
                state,
                session,
                headers,
                Path((*spelling).to_string()),
                Query(DeleteQuery { recursive: None }),
            )
            .await;
            assert!(
                matches!(
                    delete_result,
                    Err(StorageApiError::PermissionDenied(message))
                        if message.contains("principal-scoped provider route")
                ),
                "delete {spelling}"
            );
        }
    }

    /// The guard follows the root parser used to build the provider URI.
    #[test]
    fn principal_area_guard_uses_routed_root() {
        for path in ["MyWebSite/UsersAI/a.md", "Public/a.md"] {
            assert!(
                reject_principal_root_storage_path(path).is_ok(),
                "{path} must pass the guard"
            );
        }
        for path in [
            "Users",
            "Users/a.md",
            "Users/../Public/a.md",
            "UsersAI",
            "UsersAI/a.md",
            " UsersAI/a.md",
            "localhost://UsersAI/a.md",
        ] {
            assert!(
                matches!(
                    reject_principal_root_storage_path(path),
                    Err(StorageApiError::PermissionDenied(_))
                ),
                "{path} must be refused"
            );
        }
        assert!(matches!(
            reject_principal_root_storage_path("Public/../Users/a.md"),
            Err(StorageApiError::InvalidPath(_))
        ));
    }

    async fn refusal_body(err: StorageApiError) -> (StatusCode, String) {
        let response = err.into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[test]
    fn a_provider_error_is_local_apps_only_with_the_refusal_mark() {
        let sentence = "Users/note.bin is not readable. Make it readable or move it out of the folder, then restart.";
        let marked = elastos_runtime::provider::ProviderError::Provider(
            crate::local_apps::marked_local_apps_refusal(sentence),
        );
        match StorageApiError::from(marked) {
            StorageApiError::LocalApps(got) => {
                assert_eq!(got, crate::local_apps::LOCAL_APPS_OFF_TO_OTHERS);
                assert!(!got.contains("note.bin"), "{got}");
            }
            other => panic!("{other:?}"),
        }
        let foreign = elastos_runtime::provider::ProviderError::Provider(
            "Make it readable or move it out of the folder, then restart.".into(),
        );
        assert!(
            matches!(StorageApiError::from(foreign), StorageApiError::Internal(_)),
            "a recovery substring is not the refusal"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_app_routes_refuse_with_the_migration_sentence() {
        let _guard = crate::local_apps::lock_local_apps_for_test();
        let sentence = "MyWebSite/index.html is not readable. Make it readable or move it out of the folder, then restart.";
        crate::local_apps::set_local_apps_refusal_for_test(Some(sentence.to_string()));
        let state = || State(make_state(None));
        let session = || Extension(make_session(SessionType::Shell));
        let headers = || HeaderMap::new();
        let path = || -> Path<String> { Path("MyWebSite/index.html".to_string()) };
        let mut errors = Vec::new();
        errors.push(
            read_file(state(), session(), headers(), path())
                .await
                .unwrap_err(),
        );
        errors.push(
            write_file(
                state(),
                session(),
                headers(),
                path(),
                Bytes::from_static(b"no"),
            )
            .await
            .unwrap_err(),
        );
        errors.push(
            delete_path(
                state(),
                session(),
                headers(),
                path(),
                Query(DeleteQuery { recursive: None }),
            )
            .await
            .unwrap_err(),
        );
        errors.push(
            list_dir(state(), session(), headers(), path())
                .await
                .unwrap_err(),
        );
        errors.push(
            stat_path(state(), session(), headers(), path())
                .await
                .unwrap_err(),
        );
        errors.push(
            mkdir(state(), session(), headers(), path())
                .await
                .unwrap_err(),
        );
        errors.push(
            handle_get(
                state(),
                session(),
                headers(),
                path(),
                Query(StorageQuery {
                    list: Some(true),
                    mkdir: None,
                }),
            )
            .await
            .unwrap_err(),
        );
        errors.push(
            handle_post(
                state(),
                session(),
                headers(),
                path(),
                Query(StorageQuery {
                    list: None,
                    mkdir: Some(true),
                }),
                Bytes::from_static(b"no"),
            )
            .await
            .unwrap_err(),
        );
        errors.push(
            handle_get_root(
                state(),
                session(),
                headers(),
                Query(StorageQuery {
                    list: None,
                    mkdir: None,
                }),
            )
            .await
            .unwrap_err(),
        );
        for err in errors {
            let (status, body) = refusal_body(err).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body, sentence);
        }
    }

    #[tokio::test]
    async fn a_private_file_name_is_only_for_the_owner_shell() {
        let _guard = crate::local_apps::lock_local_apps_for_test();
        let home = tempfile::tempdir().unwrap();
        let sentence = "Users/secret.bin is not readable. Make it readable, then restart.";
        crate::local_apps::set_local_apps_refusal(home.path(), Some(sentence.to_string()));
        let cap = make_capability_manager();
        let mut state = make_state(Some(cap.clone()));
        state.data_dir = home.path().to_path_buf();
        let path = "MyWebSite/index.html".to_string();

        let shell = make_session(SessionType::Shell);
        let (status, body) = refusal_body(
            read_file(
                State(state.clone()),
                Extension(shell.clone()),
                HeaderMap::new(),
                Path(path.clone()),
            )
            .await
            .unwrap_err(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, sentence);
        let (status, body) = refusal_body(
            handle_get_root(
                State(state.clone()),
                Extension(shell),
                HeaderMap::new(),
                Query(StorageQuery {
                    list: None,
                    mkdir: None,
                }),
            )
            .await
            .unwrap_err(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, sentence);

        let capsule = make_session(SessionType::Capsule);
        let (status, body) = refusal_body(
            read_file(
                State(state.clone()),
                Extension(capsule.clone()),
                HeaderMap::new(),
                Path(path.clone()),
            )
            .await
            .unwrap_err(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("missing X-Capability-Token"), "{body}");
        assert!(!body.contains("secret.bin"), "{body}");
        assert_ne!(body, "Local apps are off.");
        let (status, body) = refusal_body(
            handle_get_root(
                State(state.clone()),
                Extension(capsule.clone()),
                HeaderMap::new(),
                Query(StorageQuery {
                    list: None,
                    mkdir: None,
                }),
            )
            .await
            .unwrap_err(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("Cannot read root as file"), "{body}");
        assert!(!body.contains("secret.bin"), "{body}");

        let token = cap.grant(
            capsule.id.as_str(),
            ResourceId::new("localhost://MyWebSite/*"),
            Action::Read,
            TokenConstraints::default(),
            None,
        );
        let mut granted = HeaderMap::new();
        granted.insert(
            "X-Capability-Token",
            token.to_base64().unwrap().parse().unwrap(),
        );
        let (status, body) = refusal_body(
            read_file(
                State(state.clone()),
                Extension(capsule),
                granted,
                Path(path.clone()),
            )
            .await
            .unwrap_err(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "Local apps are off.");

        let mut guest_headers = HeaderMap::new();
        guest_headers.insert("X-Elastos-Capsule-Id", "guest-app".parse().unwrap());
        let (status, body) = refusal_body(
            read_file(
                State(state),
                Extension(make_session(SessionType::Shell)),
                guest_headers,
                Path(path),
            )
            .await
            .unwrap_err(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "Local apps are off.");
    }
}
