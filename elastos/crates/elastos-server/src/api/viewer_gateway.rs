use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use elastos_common::localhost::rooted_localhost_fs_path;
use elastos_runtime::auth::RuntimeAuditEventV1;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::gateway::{
    content_type, require_home_projection_launch_token_context,
    require_home_viewer_launch_token_context, viewer_object_shell_description,
    viewer_object_shell_title, GatewayState, HomeLaunchTokenContext,
};

#[derive(Debug, Serialize)]
struct ViewerLibraryResponse {
    items: Vec<ViewerLibraryItem>,
}

#[derive(Debug, Serialize)]
struct ViewerLibraryItem {
    capsule: String,
    title: String,
    description: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
pub struct ViewerLibraryObjectQuery {
    uri: String,
    #[serde(default)]
    raw: bool,
    #[serde(default)]
    stat_only: bool,
    #[serde(default)]
    entries: bool,
    #[serde(default)]
    preview_entry: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ViewerLibraryObjectWrite {
    data: String,
    #[serde(default)]
    mime: Option<String>,
    #[serde(default)]
    if_revision: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ViewerLibraryArchiveExtractEntries {
    destination_uri: String,
    entries: Vec<String>,
    #[serde(default)]
    conflict_policy: Option<String>,
    #[serde(default)]
    if_revision: Option<String>,
    #[serde(default)]
    cancel: bool,
}

struct ViewerLibraryObjectRequest {
    uri: String,
    stat_only: bool,
    entries: bool,
    preview_entry: Option<String>,
    write: Option<ViewerLibraryObjectWrite>,
}

pub async fn viewer_library_summary(
    State(state): State<GatewayState>,
    Path(viewer): Path<String>,
    headers: HeaderMap,
) -> Response {
    let viewer = match clean_capsule_ref(&viewer, "viewer") {
        Ok(viewer) => viewer,
        Err(err) => return viewer_error_response(err),
    };
    if !super::browser_capsules::is_viewer_capsule(&state.data_dir, &viewer) {
        return (StatusCode::NOT_FOUND, "viewer capsule not found").into_response();
    }
    let (selected_resource, _context) =
        match require_viewer_library_launch_context(&state.data_dir, &headers, &viewer) {
            Ok(required) => required,
            Err(err) => return viewer_error_response(err),
        };

    Json(ViewerLibraryResponse {
        items: super::browser_capsules::list_viewer_bound_capsules(&state.data_dir, &viewer)
            .into_iter()
            .filter(|capsule| selected_resource == viewer || capsule.name == selected_resource)
            .map(|capsule| ViewerLibraryItem {
                title: viewer_object_shell_title(&capsule.name, capsule.description.as_deref()),
                description: viewer_object_shell_description(
                    &capsule.viewer,
                    capsule.description.as_deref(),
                ),
                entrypoint: capsule.entrypoint,
                capsule: capsule.name,
            })
            .collect(),
    })
    .into_response()
}

pub async fn viewer_content(
    State(state): State<GatewayState>,
    Path((viewer, capsule)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let viewer = match clean_capsule_ref(&viewer, "viewer") {
        Ok(viewer) => viewer,
        Err(err) => return viewer_error_response(err),
    };
    let capsule = match clean_capsule_ref(&capsule, "capsule") {
        Ok(capsule) => capsule,
        Err(err) => return viewer_error_response(err),
    };
    if !super::browser_capsules::is_viewer_capsule(&state.data_dir, &viewer) {
        return (StatusCode::NOT_FOUND, "viewer capsule not found").into_response();
    }
    if let Err(err) =
        require_viewer_bound_launch_token_context(&state.data_dir, &headers, &viewer, &capsule)
    {
        return viewer_error_response(err);
    }

    let Some(capsule) =
        super::browser_capsules::resolve_viewer_bound_capsule(&state.data_dir, &capsule, &viewer)
    else {
        return (StatusCode::NOT_FOUND, "viewer content capsule not found").into_response();
    };
    let Some(capsule_dir) =
        super::capsule_inventory::installed_active_capsule_dir(&state.data_dir, &capsule.name)
    else {
        return (StatusCode::NOT_FOUND, "viewer content file not found").into_response();
    };
    let asset_path = capsule_dir.join(&capsule.entrypoint);
    let Ok(bytes) = tokio::fs::read(&asset_path).await else {
        return (StatusCode::NOT_FOUND, "viewer content file not found").into_response();
    };
    (
        StatusCode::OK,
        [
            ("content-type", content_type(&capsule.entrypoint)),
            ("cache-control", "no-store"),
        ],
        bytes,
    )
        .into_response()
}

pub async fn viewer_library_object_get(
    State(state): State<GatewayState>,
    Path(viewer): Path<String>,
    Query(query): Query<ViewerLibraryObjectQuery>,
    headers: HeaderMap,
) -> Response {
    let viewer = match clean_capsule_ref(&viewer, "viewer") {
        Ok(viewer) => viewer,
        Err(err) => return viewer_error_response(err),
    };
    let context = match require_library_object_viewer_context(&state.data_dir, &headers, &viewer) {
        Ok(context) => context,
        Err(err) => return viewer_error_response(err),
    };
    if query.raw {
        if query.stat_only || query.entries || query.preview_entry.is_some() {
            return (
                StatusCode::BAD_REQUEST,
                "raw viewer reads cannot include metadata options",
            )
                .into_response();
        }
        return match read_viewer_library_object_bytes(&state, &context, &viewer, &query.uri).await {
            Ok(bytes) => (
                StatusCode::OK,
                [
                    ("content-type", "application/octet-stream"),
                    ("cache-control", "no-store"),
                ],
                bytes,
            )
                .into_response(),
            Err(err) => viewer_error_response(err),
        };
    }
    match viewer_library_object(
        &state,
        &context,
        &viewer,
        ViewerLibraryObjectRequest {
            uri: query.uri,
            stat_only: query.stat_only,
            entries: query.entries,
            preview_entry: query.preview_entry,
            write: None,
        },
    )
    .await
    {
        Ok(response) => Json(response).into_response(),
        Err(err) => viewer_error_response(err),
    }
}

pub async fn viewer_library_object_put(
    State(state): State<GatewayState>,
    Path(viewer): Path<String>,
    Query(query): Query<ViewerLibraryObjectQuery>,
    headers: HeaderMap,
    Json(input): Json<ViewerLibraryObjectWrite>,
) -> Response {
    let viewer = match clean_capsule_ref(&viewer, "viewer") {
        Ok(viewer) => viewer,
        Err(err) => return viewer_error_response(err),
    };
    if viewer != "documents" {
        return (
            StatusCode::FORBIDDEN,
            "viewer does not support Library object writes",
        )
            .into_response();
    }
    let context = match require_documents_viewer_context(&state.data_dir, &headers, &viewer) {
        Ok(context) => context,
        Err(err) => return viewer_error_response(err),
    };
    match viewer_library_object(
        &state,
        &context,
        &viewer,
        ViewerLibraryObjectRequest {
            uri: query.uri,
            stat_only: false,
            entries: false,
            preview_entry: None,
            write: Some(input),
        },
    )
    .await
    {
        Ok(response) => Json(response).into_response(),
        Err(err) => viewer_error_response(err),
    }
}

pub async fn viewer_library_object_post(
    State(state): State<GatewayState>,
    Path(viewer): Path<String>,
    Query(query): Query<ViewerLibraryObjectQuery>,
    headers: HeaderMap,
    Json(input): Json<ViewerLibraryArchiveExtractEntries>,
) -> Response {
    let viewer = match clean_capsule_ref(&viewer, "viewer") {
        Ok(viewer) => viewer,
        Err(err) => return viewer_error_response(err),
    };
    let context = match require_library_object_viewer_context(&state.data_dir, &headers, &viewer) {
        Ok(context) => context,
        Err(err) => return viewer_error_response(err),
    };
    match viewer_library_archive_extract_entries(&state, &context, &viewer, &query.uri, input).await
    {
        Ok(response) => Json(response).into_response(),
        Err(err) => viewer_error_response(err),
    }
}

pub async fn viewer_library_roots_get(
    State(state): State<GatewayState>,
    Path(viewer): Path<String>,
    headers: HeaderMap,
) -> Response {
    let viewer = match clean_capsule_ref(&viewer, "viewer") {
        Ok(viewer) => viewer,
        Err(err) => return viewer_error_response(err),
    };
    if viewer != "archive-manager" {
        return (
            StatusCode::FORBIDDEN,
            "viewer does not support Library destination roots",
        )
            .into_response();
    }
    let context = match require_library_object_viewer_context(&state.data_dir, &headers, &viewer) {
        Ok(context) => context,
        Err(err) => return viewer_error_response(err),
    };
    match viewer_object_provider_request(&state, &context, &viewer, "roots", json!({})).await {
        Ok(response) => Json(response).into_response(),
        Err(err) => viewer_error_response(err),
    }
}

pub async fn viewer_storage_get(
    State(state): State<GatewayState>,
    Path((viewer, capsule, scope, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let target =
        match viewer_storage_target(&state.data_dir, &headers, &viewer, &capsule, &scope, &name) {
            Ok(target) => target,
            Err(err) => return viewer_error_response(err),
        };
    match std::fs::symlink_metadata(&target.path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return (StatusCode::NOT_FOUND, "viewer storage file not found").into_response();
        }
        Ok(metadata) if metadata.is_file() => {}
        _ => return (StatusCode::BAD_REQUEST, "viewer storage file unavailable").into_response(),
    }
    match crate::auth::read_principal_root_object(
        &state.data_dir,
        &target.principal_id,
        &target.localhost_root,
        &target.object_uri,
        &target.path,
    ) {
        Ok(bytes) => {
            let revision = crate::auth::principal_root_object_revision(
                &target.principal_id,
                &target.object_uri,
                &bytes,
            );
            (
                StatusCode::OK,
                [
                    ("content-type", "application/octet-stream"),
                    ("cache-control", "no-store"),
                    ("etag", revision.as_str()),
                    ("access-control-expose-headers", "ETag"),
                ],
                bytes,
            )
                .into_response()
        }
        Err(err) => viewer_error_response(err),
    }
}

pub async fn viewer_storage_put(
    State(state): State<GatewayState>,
    Path((viewer, capsule, scope, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let target =
        match viewer_storage_target(&state.data_dir, &headers, &viewer, &capsule, &scope, &name) {
            Ok(target) => target,
            Err(err) => return viewer_error_response(err),
        };
    let precondition = match viewer_storage_precondition(&headers) {
        Ok(precondition) => precondition,
        Err(status) => {
            return (
                status,
                "viewer storage requires one valid save precondition",
            )
                .into_response()
        }
    };
    match crate::auth::write_principal_root_object_if_revision(
        &state.data_dir,
        &target.principal_id,
        &target.localhost_root,
        &target.object_uri,
        &target.path,
        body.as_ref(),
        precondition,
    ) {
        Ok(()) => {
            let revision = crate::auth::principal_root_object_revision(
                &target.principal_id,
                &target.object_uri,
                body.as_ref(),
            );
            (
                StatusCode::NO_CONTENT,
                [
                    ("etag", revision.as_str()),
                    ("cache-control", "no-store"),
                    ("access-control-expose-headers", "ETag"),
                ],
            )
                .into_response()
        }
        Err(err) if err.is::<crate::auth::PrincipalRootObjectWriteConflict>() => (
            StatusCode::PRECONDITION_FAILED,
            "saved data changed in another window",
        )
            .into_response(),
        Err(err) => viewer_error_response(err),
    }
}

fn viewer_storage_precondition(
    headers: &HeaderMap,
) -> Result<crate::auth::PrincipalRootObjectPrecondition<'_>, StatusCode> {
    use crate::auth::PrincipalRootObjectPrecondition;
    let matching = headers.get_all("if-match").iter().collect::<Vec<_>>();
    let absent = headers.get_all("if-none-match").iter().collect::<Vec<_>>();
    match (matching.as_slice(), absent.as_slice()) {
        ([], []) => Err(StatusCode::PRECONDITION_REQUIRED),
        ([], [value]) if value.as_bytes() == b"*" => Ok(PrincipalRootObjectPrecondition::Absent),
        ([value], []) => {
            let value = value.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
            if value.len() != 66
                || !value.starts_with('"')
                || !value.ends_with('"')
                || !value.as_bytes()[1..65]
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            {
                return Err(StatusCode::BAD_REQUEST);
            }
            Ok(PrincipalRootObjectPrecondition::Revision(value))
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn viewer_library_object(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    viewer: &str,
    request: ViewerLibraryObjectRequest,
) -> anyhow::Result<Value> {
    let stat = viewer_object_provider_request(
        state,
        context,
        viewer,
        "stat",
        json!({ "uri": &request.uri }),
    )
    .await?;
    ensure_viewer_can_view_library_object(&stat, viewer)?;
    if request.stat_only {
        return Ok(stat);
    }
    if request.entries {
        if viewer != "archive-manager" {
            anyhow::bail!("viewer does not support Library archive entry listing");
        }
        return viewer_object_provider_request(
            state,
            context,
            viewer,
            "archive_entries",
            json!({ "uri": &request.uri }),
        )
        .await;
    }
    if let Some(entry) = request.preview_entry {
        if viewer != "archive-manager" {
            anyhow::bail!("viewer does not support Library archive entry preview");
        }
        return viewer_object_provider_request(
            state,
            context,
            viewer,
            "archive_preview_entry",
            json!({ "uri": &request.uri, "entry": entry }),
        )
        .await;
    }
    if viewer != "documents" {
        anyhow::bail!("viewer supports Library object metadata only");
    }
    let payload = match request.write {
        Some(write) => json!({
            "uri": &request.uri,
            "data": write.data,
            "mime": write.mime,
            "if_revision": write.if_revision,
        }),
        None => json!({ "uri": &request.uri }),
    };
    let op = if payload.get("data").is_some() {
        "write"
    } else {
        "read"
    };
    viewer_object_provider_request(state, context, viewer, op, payload).await
}

async fn viewer_object_provider_request(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    viewer: &str,
    op: &str,
    request: Value,
) -> anyhow::Result<Value> {
    if state.provider_registry.is_none() {
        anyhow::bail!("object provider unavailable");
    }
    let request_id = format!("viewer-library:{op}:{}", crate::auth::now_ts());
    append_viewer_library_audit(
        &state.data_dir,
        context,
        viewer,
        &request_id,
        "library.viewer.requested",
        "requested",
        &format!("Viewer requested Library object operation {op}"),
    )?;
    let response = object_provider_request(state, context, op, request).await?;
    let completed = response.get("status").and_then(Value::as_str) == Some("ok");
    if completed && op == "write" {
        crate::library::library_event_notifier().notify_waiters();
    }
    append_viewer_library_audit(
        &state.data_dir,
        context,
        viewer,
        &request_id,
        if completed {
            "library.viewer.completed"
        } else {
            "library.viewer.failed"
        },
        if completed { "completed" } else { "failed" },
        &format!(
            "Viewer {} Library object operation {op}",
            if completed { "completed" } else { "failed" }
        ),
    )?;
    Ok(response)
}

/// One Library object provider request for the launch's principal, with no
/// audit of its own: the caller records the request it serves.
async fn object_provider_request(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    op: &str,
    mut request: Value,
) -> anyhow::Result<Value> {
    let registry = state
        .provider_registry
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("object provider unavailable"))?;
    request["op"] = Value::String(op.to_string());
    request["principal_id"] = Value::String(context.principal_id.clone());
    Ok(crate::library::handle_object_provider_runtime_request(
        &state.data_dir,
        Arc::clone(registry),
        &request,
    )
    .await)
}

pub(super) async fn read_viewer_library_object_bytes(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    viewer: &str,
    uri: &str,
) -> anyhow::Result<Vec<u8>> {
    let stat =
        viewer_object_provider_request(state, context, viewer, "stat", json!({ "uri": uri }))
            .await?;
    ensure_viewer_can_view_library_object(&stat, viewer)?;
    let response =
        viewer_object_provider_request(state, context, viewer, "read", json!({ "uri": uri }))
            .await?;
    if response.get("status").and_then(Value::as_str) == Some("error") {
        anyhow::bail!(
            "Library object read failed: {}",
            response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown object provider error")
        );
    }
    let encoded = response
        .get("data")
        .and_then(|data| data.get("data"))
        .or_else(|| response.get("data"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Library object read returned no bytes"))?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| anyhow::anyhow!("Library object read returned invalid base64"))
}

async fn viewer_library_archive_extract_entries(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    viewer: &str,
    uri: &str,
    input: ViewerLibraryArchiveExtractEntries,
) -> anyhow::Result<Value> {
    if viewer != "archive-manager" {
        anyhow::bail!("viewer does not support Library archive extraction");
    }
    let stat =
        viewer_object_provider_request(state, context, viewer, "stat", json!({ "uri": uri }))
            .await?;
    ensure_viewer_can_view_library_object(&stat, viewer)?;
    let response = viewer_object_provider_request(
        state,
        context,
        viewer,
        "archive_extract_entries",
        json!({
            "uri": uri,
            "destination_uri": input.destination_uri,
            "entries": input.entries,
            "conflict_policy": input.conflict_policy,
            "if_revision": input.if_revision,
            "cancel": input.cancel,
        }),
    )
    .await?;
    if response.get("status").and_then(Value::as_str) == Some("ok") {
        crate::library::library_event_notifier().notify_waiters();
    }
    Ok(response)
}

fn ensure_viewer_can_view_library_object(response: &Value, viewer_id: &str) -> anyhow::Result<()> {
    let object = response
        .get("data")
        .and_then(|data| data.get("object"))
        .ok_or_else(|| anyhow::anyhow!("library object not found"))?;
    let can_view = object
        .get("viewers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|viewer| viewer.get("id").and_then(Value::as_str) == Some(viewer_id));
    if !can_view {
        anyhow::bail!("Library object is not viewable by {viewer_id}");
    }
    Ok(())
}

fn require_library_object_viewer_context(
    data_dir: &FsPath,
    headers: &HeaderMap,
    viewer: &str,
) -> anyhow::Result<HomeLaunchTokenContext> {
    let viewer = clean_capsule_ref(viewer, "viewer")?;
    if !super::browser_capsules::is_viewer_capsule(data_dir, &viewer) {
        anyhow::bail!("viewer capsule not found");
    }
    require_viewer_library_launch_context(data_dir, headers, &viewer).map(|(_, context)| context)
}

fn require_documents_viewer_context(
    data_dir: &FsPath,
    headers: &HeaderMap,
    viewer: &str,
) -> anyhow::Result<HomeLaunchTokenContext> {
    let viewer = clean_capsule_ref(viewer, "viewer")?;
    if viewer != "documents" || !super::browser_capsules::is_viewer_capsule(data_dir, &viewer) {
        anyhow::bail!("viewer capsule not found");
    }
    require_viewer_library_launch_context(data_dir, headers, &viewer).map(|(_, context)| context)
}

fn append_viewer_library_audit(
    data_dir: &FsPath,
    context: &HomeLaunchTokenContext,
    viewer: &str,
    request_id: &str,
    event_type: &str,
    result: &str,
    reason: &str,
) -> anyhow::Result<()> {
    let now = crate::auth::now_ts();
    crate::auth::append_audit_event(
        data_dir,
        RuntimeAuditEventV1 {
            schema: RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: format!("audit:{event_type}:{request_id}:{now}"),
            event_type: event_type.to_string(),
            principal_id: Some(context.principal_id.clone()),
            proof_binding_id: context.proof_binding_id.clone(),
            session_id: Some(context.session_id.clone()),
            challenge_id: Some(request_id.to_string()),
            capsule_id: Some(viewer.to_string()),
            result: result.to_string(),
            reason: reason.to_string(),
            occurred_at: now,
            signer_did: None,
            signature: None,
        },
    )
}

struct ViewerStorageTarget {
    path: PathBuf,
    principal_id: String,
    localhost_root: String,
    object_uri: String,
}

fn require_viewer_library_launch_context(
    data_dir: &FsPath,
    headers: &HeaderMap,
    viewer: &str,
) -> anyhow::Result<(String, HomeLaunchTokenContext)> {
    let (selected_resource, context) =
        require_home_viewer_launch_token_context(data_dir, headers, viewer)?;
    if selected_resource != viewer
        && super::browser_capsules::resolve_viewer_bound_capsule(
            data_dir,
            &selected_resource,
            viewer,
        )
        .is_none()
    {
        anyhow::bail!("selected resource is not bound to the executable viewer");
    }
    Ok((selected_resource, context))
}

fn require_viewer_bound_launch_token_context(
    data_dir: &FsPath,
    headers: &HeaderMap,
    viewer: &str,
    capsule: &str,
) -> anyhow::Result<HomeLaunchTokenContext> {
    match require_home_projection_launch_token_context(data_dir, headers, capsule, viewer) {
        Ok(context) => Ok(context),
        Err(exact_error) => {
            let (selected_resource, context) =
                require_viewer_library_launch_context(data_dir, headers, viewer)?;
            if selected_resource == viewer
                && super::browser_capsules::resolve_viewer_bound_capsule(data_dir, capsule, viewer)
                    .is_some()
            {
                Ok(context)
            } else {
                Err(exact_error)
            }
        }
    }
}

fn viewer_storage_target(
    data_dir: &FsPath,
    headers: &HeaderMap,
    viewer: &str,
    capsule: &str,
    scope: &str,
    name: &str,
) -> anyhow::Result<ViewerStorageTarget> {
    let viewer = clean_capsule_ref(viewer, "viewer")?;
    let capsule = clean_capsule_ref(capsule, "capsule")?;
    if !super::browser_capsules::is_viewer_capsule(data_dir, &viewer) {
        anyhow::bail!("viewer capsule not found");
    }
    let context = require_viewer_bound_launch_token_context(data_dir, headers, &viewer, &capsule)?;
    let root_uri = viewer_storage_root_uri(data_dir, &context, &viewer, &capsule)?;
    let root = rooted_localhost_fs_path(data_dir, &root_uri)
        .ok_or_else(|| anyhow::anyhow!("invalid viewer storage root"))?;
    let file_name = clean_storage_file_name(name)?;
    let (dir, object_uri) = match scope {
        "save" => (root, format!("{root_uri}/{file_name}")),
        "state" => (
            root.join("states"),
            format!("{root_uri}/states/{file_name}"),
        ),
        _ => anyhow::bail!("invalid viewer storage scope"),
    };
    let principal_id = context.principal_id;
    let localhost_root = crate::auth::principal_localhost_root(&principal_id);
    Ok(ViewerStorageTarget {
        path: dir.join(file_name),
        principal_id,
        localhost_root,
        object_uri,
    })
}

fn viewer_storage_root_uri(
    data_dir: &FsPath,
    context: &HomeLaunchTokenContext,
    viewer: &str,
    capsule: &str,
) -> anyhow::Result<String> {
    let storage = if capsule == viewer {
        super::capsule_inventory::list_active_capsule_manifests(data_dir)
            .into_iter()
            .find(|manifest| manifest.name == viewer)
            .and_then(|manifest| manifest.permissions.storage.into_iter().next())
            .ok_or_else(|| anyhow::anyhow!("viewer capsule has no storage grant"))?
    } else {
        super::browser_capsules::resolve_viewer_bound_capsule(data_dir, capsule, viewer)
            .and_then(|capsule| capsule.storage.into_iter().next())
            .ok_or_else(|| anyhow::anyhow!("viewer content capsule has no storage grant"))?
    };
    let root_uri = principal_scoped_storage_uri(&storage, context);
    let localhost_root = crate::auth::principal_localhost_root(&context.principal_id);
    if root_uri != localhost_root
        && !root_uri
            .strip_prefix(&localhost_root)
            .is_some_and(|rest| rest.starts_with('/'))
    {
        anyhow::bail!("viewer storage must be scoped to the launch principal root");
    }
    Ok(root_uri)
}

pub(super) fn principal_root_protected_object_inventory(
    data_dir: &FsPath,
    localhost_root: &str,
) -> Vec<crate::auth::PrincipalRootProtectedObjectDeclarationV1> {
    let mut inventory = vec![
        crate::auth::PrincipalRootProtectedObjectDeclarationV1::root(format!(
            "{localhost_root}/.AppData/LocalHost/GBA"
        )),
    ];
    for storage in super::capsule_inventory::list_active_capsule_manifests(data_dir)
        .into_iter()
        .flat_map(|manifest| manifest.permissions.storage)
    {
        let root_uri = principal_scoped_storage_uri_for_root(&storage, localhost_root);
        if root_uri == localhost_root
            || !root_uri
                .strip_prefix(localhost_root)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            continue;
        }
        let browser_profiles = format!("{localhost_root}/BrowserProfiles");
        if root_uri == browser_profiles || root_uri.starts_with(&format!("{browser_profiles}/")) {
            continue;
        }
        inventory.push(crate::auth::PrincipalRootProtectedObjectDeclarationV1::root(root_uri));
    }
    inventory.sort();
    inventory.dedup();
    inventory
}

fn principal_scoped_storage_uri(storage: &str, context: &HomeLaunchTokenContext) -> String {
    let principal_root = crate::auth::principal_localhost_root(&context.principal_id);
    principal_scoped_storage_uri_for_root(storage, &principal_root)
}

fn principal_scoped_storage_uri_for_root(storage: &str, principal_root: &str) -> String {
    let root_uri = storage.trim_end_matches('*').trim_end_matches('/');
    if root_uri == "localhost://Users/self" {
        return principal_root.to_string();
    }
    if let Some(rest) = root_uri.strip_prefix("localhost://Users/self/") {
        return format!("{principal_root}/{rest}");
    }
    root_uri.to_string()
}

fn clean_capsule_ref(value: &str, label: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{label} must not be empty");
    }
    if value.contains('/') || value.contains('\\') || value == "." || value == ".." {
        anyhow::bail!("invalid {label}");
    }
    Ok(value.to_string())
}

fn clean_storage_file_name(name: &str) -> anyhow::Result<String> {
    let file_name = name.trim();
    if file_name.is_empty()
        || file_name.contains('/')
        || file_name.contains('\\')
        || file_name == "."
        || file_name == ".."
    {
        anyhow::bail!("invalid viewer storage file name");
    }
    Ok(file_name.to_string())
}

fn viewer_error_response(err: anyhow::Error) -> Response {
    let text = err.to_string();
    let status = if text.contains("not found") {
        StatusCode::NOT_FOUND
    } else if text.contains("home launch token") {
        StatusCode::UNAUTHORIZED
    } else if text.contains("does not support")
        || text.contains("not viewable")
        || text.contains("metadata only")
    {
        StatusCode::FORBIDDEN
    } else if text.contains("invalid")
        || text.contains("must not be empty")
        || text.contains("no storage grant")
    {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (status, text).into_response()
}

// --- Photos surface --------------------------------------------------------
//
// The Photos surface (`image-viewer`) reads through these two routes only:
// the playlist bound to its launch, and one item of that playlist by
// position. It sends no path. Runtime takes the playlist from the signed
// launch context, serves only items the playlist lists under Pictures/, and
// leaves exactly one audit record per request. There is no write route.

pub(crate) const PHOTOS_VIEWER: &str = "image-viewer";
/// The one playlist a Photos launch may bind: the one the `photo-viewer`
/// Component writes (examples/photo-viewer). Known spike limit: any capsule
/// whose storage bounds cover this path could write it, which can only choose
/// which of the person's own Pictures Photos shows. Phase 2 binds the
/// launch's own run output instead of a fixed path.
pub(crate) const PHOTOS_PLAYLIST_URI: &str =
    "localhost://Users/self/.AppData/App/photo-viewer/playlist.json";
/// The lifetime of a launch that binds the playlist.
pub(crate) const PHOTOS_LAUNCH_TOKEN_TTL_SECS: u64 = 15 * 60;
const PHOTOS_PLAYLIST_SCHEMA: &str = "elastos.photo-viewer.playlist/v1";
const PHOTOS_PICTURES_PREFIX: &str = "localhost://Users/self/Pictures/";
const MAX_PHOTOS_PLAYLIST_BYTES: u64 = 64 * 1024;
const MAX_PHOTOS_ITEM_BYTES: u64 = 64 * 1024 * 1024;

/// What Runtime binds when Home launches `target`: the token's selected
/// resource and, for a Photos playlist launch, its shorter lifetime. Only
/// Photos takes a selected resource from Home, and only its playlist.
pub(crate) fn photos_launch_binding(
    target: &str,
    requested: Option<&str>,
) -> anyhow::Result<(String, Option<u64>)> {
    if target != PHOTOS_VIEWER {
        if requested.is_some() {
            anyhow::bail!("only Photos takes a selected resource");
        }
        return Ok((target.to_string(), None));
    }
    match requested {
        // Opened from the Library for one image: no playlist is bound, the
        // Photos routes refuse it, and the token keeps the default lifetime.
        None => Ok((target.to_string(), None)),
        Some(PHOTOS_PLAYLIST_URI) => Ok((
            PHOTOS_PLAYLIST_URI.to_string(),
            Some(PHOTOS_LAUNCH_TOKEN_TTL_SECS),
        )),
        Some(_) => anyhow::bail!("Photos can bind only its playlist"),
    }
}

#[derive(Debug)]
pub(crate) struct PhotosRefusal {
    pub(crate) status: StatusCode,
    pub(crate) reason: String,
}

impl PhotosRefusal {
    fn new(status: StatusCode, reason: impl Into<String>) -> Self {
        Self {
            status,
            reason: reason.into(),
        }
    }
}

impl IntoResponse for PhotosRefusal {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.reason }))).into_response()
    }
}

/// What one Photos request touched, for its single audit record.
struct PhotosRecord {
    playlist: Option<String>,
    playlist_sha256: Option<String>,
    position: Option<String>,
    item: Option<String>,
}

/// The launch token, for the Photos viewer only. Before it is valid there is
/// no principal or launch to record, so a refusal here is counted, not
/// recorded on its own (`count_photos_unadmitted`); the error carries its
/// fixed code. The gateway front door refuses requests with no valid token at
/// all before they reach this.
fn require_photos_token(
    data_dir: &FsPath,
    headers: &HeaderMap,
) -> Result<super::gateway::RequiredHomeLaunchToken, (PhotosRefusal, &'static str)> {
    super::gateway::require_home_viewer_launch(data_dir, headers, PHOTOS_VIEWER).map_err(|err| {
        // Runtime's own message, never request text.
        let code = if err.to_string() == "missing home launch token" {
            "missing_token"
        } else {
            "token_refused"
        };
        (
            PhotosRefusal::new(
                StatusCode::UNAUTHORIZED,
                format!("Photos needs its own launch token: {err}"),
            ),
            code,
        )
    })
}

/// The bound playlist under the launch's own principal root.
fn require_photos_playlist(
    data_dir: &FsPath,
    launch: &super::gateway::RequiredHomeLaunchToken,
) -> Result<String, PhotosRefusal> {
    if !super::browser_capsules::is_viewer_capsule(data_dir, PHOTOS_VIEWER) {
        return Err(PhotosRefusal::new(
            StatusCode::NOT_FOUND,
            "the Photos viewer is not installed",
        ));
    }
    if launch.launch_context.selected_resource != PHOTOS_PLAYLIST_URI {
        return Err(PhotosRefusal::new(
            StatusCode::FORBIDDEN,
            "this Photos launch is not bound to a playlist",
        ));
    }
    principal_self_uri(PHOTOS_PLAYLIST_URI, &launch.context.principal_id).ok_or_else(|| {
        PhotosRefusal::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid playlist path")
    })
}

/// `localhost://Users/self/<rest>` under the principal's own root.
fn principal_self_uri(self_uri: &str, principal_id: &str) -> Option<String> {
    let rest = self_uri.strip_prefix("localhost://Users/self/")?;
    Some(format!(
        "{}/{rest}",
        crate::auth::principal_localhost_root(principal_id)
    ))
}

/// A playlist item must name one object under the person's Pictures folder.
fn photos_item_uri(uri: &str, principal_id: &str) -> Result<String, PhotosRefusal> {
    let refuse = |why: &str| {
        PhotosRefusal::new(
            StatusCode::FORBIDDEN,
            format!("playlist item {uri:?} {why}"),
        )
    };
    let Some(rest) = uri.strip_prefix(PHOTOS_PICTURES_PREFIX) else {
        return Err(refuse("is not under localhost://Users/self/Pictures/"));
    };
    if rest
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(refuse("has an empty, . or .. segment"));
    }
    if rest.contains(['?', '#', '\\']) || rest.chars().any(char::is_control) {
        return Err(refuse("has ?, #, \\ or a control character"));
    }
    principal_self_uri(uri, principal_id).ok_or_else(|| refuse("is not a principal path"))
}

/// The `uri` of the item at `order` in the playlist. A skipped entry is not
/// an item.
fn photos_listed_item(playlist: &[u8], order: u64) -> Result<String, PhotosRefusal> {
    let malformed = |why: &str| {
        PhotosRefusal::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("the bound playlist {why}"),
        )
    };
    let playlist: Value = serde_json::from_slice(playlist).map_err(|_| malformed("is not JSON"))?;
    if playlist.get("schema").and_then(Value::as_str) != Some(PHOTOS_PLAYLIST_SCHEMA) {
        return Err(malformed(&format!("is not {PHOTOS_PLAYLIST_SCHEMA}")));
    }
    let items = playlist
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("has no items list"))?;
    let mut found = None;
    for item in items {
        let item_order = item
            .get("order")
            .and_then(Value::as_u64)
            .ok_or_else(|| malformed("has an item without an order"))?;
        if item_order != order {
            continue;
        }
        if found.is_some() {
            return Err(malformed(&format!("lists position {order} twice")));
        }
        let uri = item
            .get("uri")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("has an item without a uri"))?;
        found = Some(uri.to_string());
    }
    found.ok_or_else(|| {
        PhotosRefusal::new(
            StatusCode::NOT_FOUND,
            format!("position {order} is not a playable item in this launch's playlist"),
        )
    })
}

/// Reads one Library object of at most `limit` bytes, checking the size
/// before the read. `viewable` also requires the object to be one the Photos
/// viewer may open. The stat and the read are internal to one Photos request
/// and leave no audit record of their own.
async fn read_photos_object(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    uri: &str,
    limit: u64,
    viewable: bool,
) -> Result<Vec<u8>, PhotosRefusal> {
    let provider_failed =
        |err: anyhow::Error| PhotosRefusal::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    let stat = object_provider_request(state, context, "stat", json!({ "uri": uri }))
        .await
        .map_err(provider_failed)?;
    if stat.get("status").and_then(Value::as_str) != Some("ok") {
        return Err(PhotosRefusal::new(
            StatusCode::NOT_FOUND,
            format!("{uri} not found"),
        ));
    }
    if viewable {
        ensure_viewer_can_view_library_object(&stat, PHOTOS_VIEWER)
            .map_err(|err| PhotosRefusal::new(StatusCode::FORBIDDEN, err.to_string()))?;
    }
    let size = stat
        .pointer("/data/object/size")
        .and_then(Value::as_u64)
        .ok_or_else(|| PhotosRefusal::new(StatusCode::BAD_GATEWAY, "Library stat has no size"))?;
    let too_large = || {
        PhotosRefusal::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("{uri} is larger than {limit} bytes"),
        )
    };
    if size > limit {
        return Err(too_large());
    }
    let read = object_provider_request(state, context, "read", json!({ "uri": uri }))
        .await
        .map_err(provider_failed)?;
    let encoded = read
        .pointer("/data/data")
        .and_then(Value::as_str)
        .filter(|_| read.get("status").and_then(Value::as_str) == Some("ok"))
        .ok_or_else(|| {
            PhotosRefusal::new(StatusCode::BAD_GATEWAY, format!("{uri} could not be read"))
        })?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| PhotosRefusal::new(StatusCode::BAD_GATEWAY, "Library read was not base64"))?;
    // The object may have grown between stat and read.
    if bytes.len() as u64 > limit {
        return Err(too_large());
    }
    Ok(bytes)
}

/// At most this many launches hold a pin at once. A new launch is refused
/// while the table is full; a live pin is never evicted to make room.
pub(crate) const PHOTOS_MAX_PINS: usize = 1024;

/// The playlist sha256 each launch saw first, so a launch keeps playing the
/// playlist it started with. Held in memory: entries older than a Photos
/// token's lifetime are dropped when a new launch pins, and a Runtime restart
/// starts afresh.
pub(crate) struct PhotosPins {
    entries: std::collections::HashMap<String, (String, std::time::Instant)>,
    cap: usize,
}

impl PhotosPins {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            cap,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Binds `sha256` to the launch at its first read, and refuses a later
    /// read of different bytes. The table is scanned only when a new launch
    /// pins, and holds at most `cap` entries.
    pub(crate) fn pin(
        &mut self,
        launch_id: &str,
        sha256: &str,
        now: std::time::Instant,
    ) -> Result<(), PhotosRefusal> {
        match self.entries.get(launch_id) {
            Some((pinned, _)) if pinned != sha256 => Err(PhotosRefusal::new(
                StatusCode::CONFLICT,
                format!("the playlist changed during this launch (pinned sha256:{pinned})"),
            )),
            Some(_) => Ok(()),
            None => {
                let lifetime = std::time::Duration::from_secs(PHOTOS_LAUNCH_TOKEN_TTL_SECS);
                self.entries.retain(|_, (_, pinned_at)| {
                    now.saturating_duration_since(*pinned_at) <= lifetime
                });
                if self.entries.len() >= self.cap {
                    return Err(PhotosRefusal::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!(
                            "too many Photos launches are open ({}); try again when one ends",
                            self.cap
                        ),
                    ));
                }
                self.entries
                    .insert(launch_id.to_string(), (sha256.to_string(), now));
                Ok(())
            }
        }
    }
}

fn photos_playlist_pins() -> &'static std::sync::Mutex<PhotosPins> {
    static PINS: std::sync::OnceLock<std::sync::Mutex<PhotosPins>> = std::sync::OnceLock::new();
    PINS.get_or_init(|| std::sync::Mutex::new(PhotosPins::new(PHOTOS_MAX_PINS)))
}

fn pin_photos_playlist(launch_id: &str, playlist: &[u8]) -> Result<String, PhotosRefusal> {
    use sha2::Digest as _;
    let sha256 = hex::encode(sha2::Sha256::digest(playlist));
    photos_playlist_pins()
        .lock()
        .map_err(|_| PhotosRefusal::new(StatusCode::INTERNAL_SERVER_ERROR, "playlist pins"))?
        .pin(launch_id, &sha256, std::time::Instant::now())?;
    Ok(sha256)
}

/// The bound playlist's bytes for this launch, pinned by sha256.
async fn read_pinned_photos_playlist(
    state: &GatewayState,
    launch: &super::gateway::RequiredHomeLaunchToken,
    playlist_uri: &str,
    record: &mut PhotosRecord,
) -> Result<Vec<u8>, PhotosRefusal> {
    let bytes = read_photos_object(
        state,
        &launch.context,
        playlist_uri,
        MAX_PHOTOS_PLAYLIST_BYTES,
        false,
    )
    .await?;
    record.playlist_sha256 = Some(pin_photos_playlist(&launch.launch_id, &bytes)?);
    Ok(bytes)
}

/// Distinguishes this Runtime process, so record ids stay unique when the
/// counter restarts with the process while a launch token is still valid.
fn photos_record_boot() -> &'static str {
    static BOOT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BOOT.get_or_init(|| hex::encode(rand::random::<[u8; 8]>()))
}

/// The one audit record of a Photos request: the playlist (and its sha256),
/// the position, the item URI and the result. Its id is the launch id and a
/// counter. If the record cannot be written, the request fails.
fn photos_audit(
    data_dir: &FsPath,
    launch: &super::gateway::RequiredHomeLaunchToken,
    route: &str,
    record: &PhotosRecord,
    outcome: &Result<Vec<u8>, PhotosRefusal>,
) -> Result<(), PhotosRefusal> {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let event_type = format!("photos.viewer.{route}");
    let (result, outcome_text) = match outcome {
        Ok(bytes) => ("served", format!("served {} bytes", bytes.len())),
        Err(refusal) => (
            "refused",
            format!("refused {}: {}", refusal.status.as_u16(), refusal.reason),
        ),
    };
    let field = |value: &Option<String>| value.clone().unwrap_or_else(|| "-".to_string());
    let reason = format!(
        "playlist={} sha256={} position={} item={} result={outcome_text}",
        field(&record.playlist),
        field(&record.playlist_sha256),
        field(&record.position),
        field(&record.item),
    );
    let context = &launch.context;
    crate::auth::append_audit_event(
        data_dir,
        RuntimeAuditEventV1 {
            schema: RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: format!(
                "audit:{event_type}:{}:{}:{sequence}",
                launch.launch_id,
                photos_record_boot()
            ),
            event_type,
            principal_id: Some(context.principal_id.clone()),
            proof_binding_id: context.proof_binding_id.clone(),
            session_id: Some(context.session_id.clone()),
            challenge_id: Some(launch.launch_id.clone()),
            capsule_id: Some(PHOTOS_VIEWER.to_string()),
            result: result.to_string(),
            reason,
            occurred_at: crate::auth::now_ts(),
            signer_did: None,
            signature: None,
        },
    )
    .map_err(|err| {
        PhotosRefusal::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Photos read was not audited: {err}"),
        )
    })
}

// ---- Refusals before the token check: counted per window ----
//
// A request refused before its launch token is accepted has no principal and
// no launch, and anyone can send one. Each is counted by (route, code) in a
// 60-second window, and the window is written as ONE audit event carrying all
// its counts, so a steady flood costs one event a minute out of the 512-event
// audit tail. The route is the matched route's fixed name and the code comes
// from a fixed list; request text never becomes a key. The window is written
// at the first request of a later window, or at gateway shutdown. A crash
// loses the open window.

const PHOTOS_UNADMITTED_WINDOW_SECS: u64 = 60;
/// A backstop for distinct keys per window. The fixed lists give at most
/// 2 routes x 3 codes = 6 keys today, so it is not reached.
const PHOTOS_UNADMITTED_KEY_CAP: usize = 16;
const PHOTOS_UNADMITTED_ROUTES: [&str; 2] = ["playlist", "item"];
const PHOTOS_UNADMITTED_CODES: [&str; 3] = ["missing_token", "token_refused", "other"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhotosUnadmittedWindow {
    pub(crate) start: u64,
    pub(crate) counts: std::collections::BTreeMap<(&'static str, &'static str), u32>,
    pub(crate) overflow: u32,
    cap: usize,
}

/// `name` if it is on `known`, else `"other"`.
fn photos_fixed_name(known: &[&'static str], name: &str) -> &'static str {
    known
        .iter()
        .find(|known| **known == name)
        .copied()
        .unwrap_or("other")
}

impl PhotosUnadmittedWindow {
    pub(crate) fn new(start: u64, cap: usize) -> Self {
        Self {
            start,
            counts: std::collections::BTreeMap::new(),
            overflow: 0,
            cap,
        }
    }

    pub(crate) fn add(&mut self, route: &str, code: &str) {
        let key = (
            photos_fixed_name(&PHOTOS_UNADMITTED_ROUTES, route),
            photos_fixed_name(&PHOTOS_UNADMITTED_CODES, code),
        );
        if let Some(count) = self.counts.get_mut(&key) {
            *count = count.saturating_add(1);
        } else if self.counts.len() < self.cap {
            self.counts.insert(key, 1);
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
    }

    fn is_empty(&self) -> bool {
        self.counts.is_empty() && self.overflow == 0
    }

    /// `window=<start>-<end> counts=<route>/<code>:<n>,... overflow=<n> total=<n>`
    pub(crate) fn reason(&self) -> String {
        let counts: Vec<String> = self
            .counts
            .iter()
            .map(|((route, code), count)| format!("{route}/{code}:{count}"))
            .collect();
        let total = self
            .counts
            .values()
            .fold(self.overflow, |total, count| total.saturating_add(*count));
        let counts = if counts.is_empty() {
            "-".to_string()
        } else {
            counts.join(",")
        };
        format!(
            "window={}-{} counts={counts} overflow={} total={total}",
            self.start,
            self.start + PHOTOS_UNADMITTED_WINDOW_SECS,
            self.overflow,
        )
    }
}

type PhotosUnadmittedWindows =
    std::sync::Mutex<std::collections::HashMap<PathBuf, PhotosUnadmittedWindow>>;

/// One open window per data root (one per Runtime; tests run many).
fn photos_unadmitted_windows() -> &'static PhotosUnadmittedWindows {
    static WINDOWS: std::sync::OnceLock<PhotosUnadmittedWindows> = std::sync::OnceLock::new();
    WINDOWS.get_or_init(Default::default)
}

/// Counts one refusal before the token check at `now`, first writing the
/// previous window if `now` is in a later one.
pub(crate) fn count_photos_unadmitted_at(
    data_dir: &FsPath,
    route: &str,
    code: &str,
    now: u64,
) -> anyhow::Result<()> {
    let start = now - now % PHOTOS_UNADMITTED_WINDOW_SECS;
    let finished = {
        let mut windows = photos_unadmitted_windows()
            .lock()
            .map_err(|_| anyhow::anyhow!("Photos refusal counts are unavailable"))?;
        let window = windows
            .entry(data_dir.to_path_buf())
            .or_insert_with(|| PhotosUnadmittedWindow::new(start, PHOTOS_UNADMITTED_KEY_CAP));
        // A clock that steps back keeps counting into the open window.
        let finished = (start > window.start).then(|| {
            std::mem::replace(
                window,
                PhotosUnadmittedWindow::new(start, PHOTOS_UNADMITTED_KEY_CAP),
            )
        });
        window.add(route, code);
        finished
    };
    match finished {
        Some(window) => write_photos_unadmitted(data_dir, &window),
        None => Ok(()),
    }
}

/// Writes the open window, if it counted anything. Called at gateway shutdown.
pub(crate) fn flush_photos_unadmitted(data_dir: &FsPath) -> anyhow::Result<()> {
    let window = photos_unadmitted_windows()
        .lock()
        .map_err(|_| anyhow::anyhow!("Photos refusal counts are unavailable"))?
        .remove(data_dir);
    match window {
        Some(window) => write_photos_unadmitted(data_dir, &window),
        None => Ok(()),
    }
}

fn write_photos_unadmitted(
    data_dir: &FsPath,
    window: &PhotosUnadmittedWindow,
) -> anyhow::Result<()> {
    if window.is_empty() {
        return Ok(());
    }
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let event_type = "photos.viewer.unadmitted";
    crate::auth::append_audit_event(
        data_dir,
        RuntimeAuditEventV1 {
            schema: RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: format!(
                "audit:{event_type}:{}:{}:{sequence}",
                window.start,
                photos_record_boot()
            ),
            event_type: event_type.to_string(),
            principal_id: None,
            proof_binding_id: None,
            session_id: None,
            challenge_id: None,
            capsule_id: Some(PHOTOS_VIEWER.to_string()),
            result: "refused".to_string(),
            reason: window.reason(),
            occurred_at: crate::auth::now_ts(),
            signer_did: None,
            signature: None,
        },
    )
}

/// The request is refused whatever happens here; a failed write is logged.
fn count_photos_unadmitted(data_dir: &FsPath, route: &'static str, code: &'static str) {
    if let Err(err) = count_photos_unadmitted_at(data_dir, route, code, crate::auth::now_ts()) {
        tracing::warn!("Photos refusal counts were not written: {err}");
    }
}

fn photos_bytes_response(content_type: &'static str, bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            ("content-type", content_type),
            ("cache-control", "no-store"),
            ("x-content-type-options", "nosniff"),
        ],
        bytes,
    )
        .into_response()
}

pub async fn photos_playlist_get(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let launch = match require_photos_token(&state.data_dir, &headers) {
        Ok(launch) => launch,
        Err((refusal, code)) => {
            count_photos_unadmitted(&state.data_dir, "playlist", code);
            return refusal.into_response();
        }
    };
    let mut record = PhotosRecord {
        playlist: None,
        playlist_sha256: None,
        position: None,
        item: None,
    };
    let outcome = async {
        let playlist_uri = require_photos_playlist(&state.data_dir, &launch)?;
        record.playlist = Some(playlist_uri.clone());
        read_pinned_photos_playlist(&state, &launch, &playlist_uri, &mut record).await
    }
    .await;
    if let Err(refusal) = photos_audit(&state.data_dir, &launch, "playlist", &record, &outcome) {
        return refusal.into_response();
    }
    match outcome {
        Ok(bytes) => photos_bytes_response("application/json", bytes),
        Err(refusal) => refusal.into_response(),
    }
}

pub async fn photos_playlist_item_get(
    State(state): State<GatewayState>,
    Path(order): Path<String>,
    headers: HeaderMap,
) -> Response {
    let launch = match require_photos_token(&state.data_dir, &headers) {
        Ok(launch) => launch,
        Err((refusal, code)) => {
            count_photos_unadmitted(&state.data_dir, "item", code);
            return refusal.into_response();
        }
    };
    let mut record = PhotosRecord {
        playlist: None,
        playlist_sha256: None,
        position: Some(order.clone()),
        item: None,
    };
    let outcome = async {
        let playlist_uri = require_photos_playlist(&state.data_dir, &launch)?;
        record.playlist = Some(playlist_uri.clone());
        let order: u64 = order.parse().map_err(|_| {
            PhotosRefusal::new(
                StatusCode::BAD_REQUEST,
                "a playlist position is a whole number",
            )
        })?;
        let playlist =
            read_pinned_photos_playlist(&state, &launch, &playlist_uri, &mut record).await?;
        let listed = photos_listed_item(&playlist, order)?;
        record.item = Some(listed.clone());
        let uri = photos_item_uri(&listed, &launch.context.principal_id)?;
        read_photos_object(&state, &launch.context, &uri, MAX_PHOTOS_ITEM_BYTES, true).await
    }
    .await;
    if let Err(refusal) = photos_audit(&state.data_dir, &launch, "item", &record, &outcome) {
        return refusal.into_response();
    }
    match outcome {
        Ok(bytes) => photos_bytes_response("application/octet-stream", bytes),
        Err(refusal) => refusal.into_response(),
    }
}
