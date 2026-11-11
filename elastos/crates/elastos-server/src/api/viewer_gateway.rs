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
    match viewer_storage_read(&state.data_dir, &target) {
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
    match viewer_storage_write(&state.data_dir, &target, body.as_ref(), precondition) {
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
    // Documents opens and saves files by URI, including the plain files its
    // list shows from the Documents folder: never through a link.
    if viewer == "documents" {
        crate::library::refuse_linked_library_object(
            &state.data_dir,
            &context.principal_id,
            &request.uri,
        )?;
    }
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
    mut request: Value,
) -> anyhow::Result<Value> {
    let registry = state
        .provider_registry
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("object provider unavailable"))?;
    request["op"] = Value::String(op.to_string());
    request["principal_id"] = Value::String(context.principal_id().to_string());
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
    let response = crate::library::handle_object_provider_runtime_request(
        &state.data_dir,
        Arc::clone(registry),
        &request,
    )
    .await;
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
            principal_id: Some(context.principal_id().to_string()),
            proof_binding_id: context.proof_binding_id().map(ToString::to_string),
            session_id: Some(context.session_id().to_string()),
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
    root: crate::auth::ResolvedPrincipalRoot,
    object_uri: String,
}

fn viewer_storage_read(data_dir: &FsPath, target: &ViewerStorageTarget) -> anyhow::Result<Vec<u8>> {
    crate::auth::read_principal_root_object_resolved(
        data_dir,
        &target.root,
        &target.object_uri,
        &target.path,
    )
}

fn viewer_storage_write(
    data_dir: &FsPath,
    target: &ViewerStorageTarget,
    bytes: &[u8],
    precondition: crate::auth::PrincipalRootObjectPrecondition<'_>,
) -> anyhow::Result<()> {
    crate::auth::write_principal_root_object_if_revision_resolved(
        data_dir,
        &target.root,
        &target.object_uri,
        &target.path,
        bytes,
        precondition,
    )
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
    viewer_storage_target_for_context(data_dir, &context, &viewer, &capsule, scope, name)
}

fn viewer_storage_target_for_context(
    data_dir: &FsPath,
    context: &HomeLaunchTokenContext,
    viewer: &str,
    capsule: &str,
    scope: &str,
    name: &str,
) -> anyhow::Result<ViewerStorageTarget> {
    let root_uri = viewer_storage_root_uri(data_dir, context, viewer, capsule)?;
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
    // Agent journals live under .AppData/Agents/ and are written only through
    // the Runtime bridge, with its revision rule. Viewer storage may not reach
    // them, whatever the manifest declares.
    if crate::provider_resource::in_agents_area(&root_uri)
        || crate::provider_resource::in_agents_area(&object_uri)
    {
        anyhow::bail!("viewer storage does not support .AppData/Agents/ (agent journals)");
    }
    let principal_id = context.principal_id().to_string();
    Ok(ViewerStorageTarget {
        path: dir.join(file_name),
        principal_id,
        root: context.root().clone(),
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
    // One canonical string for every check and for the filesystem path: the
    // path resolver trims surrounding whitespace and slashes, so a check on
    // the raw grant could see "Agents " and resolve "Agents".
    let root_uri = elastos_common::localhost::rooted_localhost_uri(&principal_scoped_storage_uri(
        &storage, context,
    ))
    .ok_or_else(|| anyhow::anyhow!("invalid viewer storage root"))?;
    if !viewer_storage_root_matches(&root_uri, context) {
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
    principal_scoped_storage_uri_for_root(storage, context.root().localhost_root())
}

#[cfg(test)]
fn viewer_target_root(context: &HomeLaunchTokenContext) -> String {
    context.root().localhost_root().to_string()
}

fn viewer_storage_root_matches(root_uri: &str, context: &HomeLaunchTokenContext) -> bool {
    let localhost_root = context.root().localhost_root();
    root_uri == localhost_root
        || root_uri
            .strip_prefix(localhost_root)
            .is_some_and(|rest| rest.starts_with('/'))
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

#[cfg(test)]
mod r4_root_tests {
    use super::*;
    use crate::api::gateway::r3_stored_root_tests::verified_parent_device_context;
    use crate::auth::r4_fixture::{store, AGENT_ID, AGENT_ROOT, HUMAN_ROOT, ID};
    use crate::auth::PrincipalKind;

    fn active_viewer(data_dir: &FsPath) {
        let capsule = data_dir.join("capsules/documents");
        std::fs::create_dir_all(capsule.join("browser")).unwrap();
        std::fs::write(capsule.join("browser/index.html"), "viewer").unwrap();
        std::fs::write(
            capsule.join("capsule.json"),
            serde_json::to_vec(&json!({
                "schema": "elastos.capsule/v1", "name": "documents", "version": "0.1.0",
                "author": "elastos", "role": "viewer", "type": "wasm",
                "entrypoint": "browser/index.html",
                "permissions": {"storage": ["localhost://Users/self/Documents/*"]}
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            data_dir.join("components.json"),
            serde_json::to_vec(&json!({"external": {"documents": {
                "install_path": "capsules/documents", "platforms": {}
            }}, "capsules": {}, "profiles": {}}))
            .unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn parent_signed_viewer_storage_round_trips_under_parent_root() {
        let dir = tempfile::tempdir().unwrap();
        active_viewer(dir.path());
        let (context, parent_root, child_root, token) =
            verified_parent_device_context(dir.path(), "documents");
        assert_eq!(context.root().localhost_root(), parent_root);
        let state = GatewayState {
            provider_registry: None,
            collaboration_chat_product_port: None,
            collaboration_presence_product_port: None,
            carrier_endpoint: None,
            collaboration_discovery_service: None,
            browser_internet: Default::default(),
            identity_manager: Arc::new(std::sync::OnceLock::new()),
            cache_dir: dir.path().to_path_buf(),
            data_dir: dir.path().to_path_buf(),
        };
        let mut headers = HeaderMap::new();
        headers.insert("host", "localhost:61180".parse().unwrap());
        headers.insert("origin", "null".parse().unwrap());
        headers.insert("x-elastos-home-token", token.parse().unwrap());
        headers.insert("if-none-match", "*".parse().unwrap());
        let route = (
            "documents".into(),
            "documents".into(),
            "save".into(),
            "note.md".into(),
        );
        let denied = viewer_storage_put(
            State(state.clone()),
            Path(route.clone()),
            headers.clone(),
            Bytes::from_static(b"parent bytes"),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let denied_body = axum::body::to_bytes(denied.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&denied_body).contains("home launch token"));
        let target = viewer_storage_target_for_context(
            dir.path(),
            &context,
            "documents",
            "documents",
            "save",
            "note.md",
        )
        .unwrap();
        let child_uri = format!("{child_root}/Documents/note.md");
        let child_path = rooted_localhost_fs_path(dir.path(), &child_uri).unwrap();
        std::fs::create_dir_all(child_path.parent().unwrap()).unwrap();
        std::fs::write(&child_path, b"child decoy").unwrap();
        let written = viewer_storage_write(
            dir.path(),
            &target,
            b"parent bytes",
            crate::auth::PrincipalRootObjectPrecondition::Absent,
        );
        assert!(
            written.is_ok(),
            "verified parent storage write: {written:?}"
        );
        assert_eq!(
            viewer_storage_read(dir.path(), &target).map_err(|error| error.to_string()),
            Ok(b"parent bytes".to_vec())
        );
        let denied_read = viewer_storage_get(State(state), Path(route), headers).await;
        assert_eq!(denied_read.status(), StatusCode::UNAUTHORIZED);
        let parent_uri = format!("{parent_root}/Documents/note.md");
        assert!(rooted_localhost_fs_path(dir.path(), &parent_uri)
            .unwrap()
            .is_file());
        assert_eq!(std::fs::read(&child_path).unwrap(), b"child decoy");
        assert!(!crate::auth::principal_object_io::reads(dir.path()).contains(&child_path));
        assert!(!crate::auth::principal_object_io::writes(dir.path()).contains(&child_path));
    }

    #[test]
    fn r4_viewer_target_and_storage_grant_reach_agent_root() {
        let dir = tempfile::tempdir().unwrap();
        store(dir.path(), PrincipalKind::Agent);
        active_viewer(dir.path());
        elastos_identity::load_or_create_did(dir.path()).unwrap();
        let now = crate::auth::now_ts();
        let proof_binding_id = crate::auth::stored_principal_record(dir.path(), AGENT_ID)
            .unwrap()
            .unwrap()
            .proof_binding_id;
        crate::auth::plant_session_grant(
            dir.path(),
            elastos_runtime::auth::AuthSessionGrantV1 {
                schema: elastos_runtime::auth::AuthSessionGrantV1::SCHEMA.into(),
                grant_id: "grant:r4-viewer".into(),
                session_id: "session:r4-viewer".into(),
                principal_id: AGENT_ID.into(),
                proof_binding_id: proof_binding_id.clone(),
                issued_at: now,
                expires_at: now + 600,
                apps: vec!["documents".into()],
            },
        );
        let root =
            crate::auth::ResolvedPrincipalRoot::resolve(dir.path(), dir.path(), AGENT_ID).unwrap();
        let context = HomeLaunchTokenContext::resolved(
            root,
            AGENT_ID.into(),
            "session:r4-viewer".into(),
            Some(proof_binding_id),
            "grant:r4-viewer".into(),
        );
        let token = crate::api::gateway::issue_home_launch_token_with_context(
            dir.path(),
            "documents",
            &context,
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("host", "localhost:61180".parse().unwrap());
        headers.insert("origin", "null".parse().unwrap());
        headers.insert("x-elastos-home-token", token.parse().unwrap());
        let live_target = viewer_storage_target(
            dir.path(),
            &headers,
            "documents",
            "documents",
            "save",
            "note.md",
        )
        .expect("R4 viewer request reaches stored Agent root");
        assert_eq!(
            live_target.root.localhost_root(),
            AGENT_ROOT,
            "R4 viewer request root"
        );
        assert_eq!(
            live_target.object_uri,
            format!("{AGENT_ROOT}/Documents/note.md")
        );
        let uri = viewer_storage_root_uri(dir.path(), &context, "documents", "documents")
            .expect("R4 viewer grant reaches stored Agent root");
        assert_eq!(
            uri,
            format!("{AGENT_ROOT}/Documents"),
            "R4 viewer grant root"
        );
        let target = viewer_storage_target_for_context(
            dir.path(),
            &context,
            "documents",
            "documents",
            "save",
            "note.md",
        )
        .expect("R4 viewer target reaches stored Agent root");
        assert_eq!(
            target.root.localhost_root(),
            AGENT_ROOT,
            "R4 viewer target root"
        );
        assert_eq!(target.object_uri, format!("{AGENT_ROOT}/Documents/note.md"));
    }

    #[test]
    fn r4_remote_viewer_storage_refuses_empty_root() {
        let dir = tempfile::tempdir().unwrap();
        active_viewer(dir.path());
        let id = "remote:00000000000000000000000000000000";
        let context = HomeLaunchTokenContext::resolved(
            crate::auth::ResolvedPrincipalRoot::remote(id).unwrap(),
            id.into(),
            "session".into(),
            None,
            "grant".into(),
        );
        assert_eq!(
            viewer_storage_root_uri(dir.path(), &context, "documents", "documents")
                .unwrap_err()
                .to_string(),
            "invalid viewer storage root"
        );
    }

    #[test]
    fn r4_viewer_uses_context_root_at_all_three_sites() {
        let missing = tempfile::tempdir().unwrap();
        assert_eq!(
            crate::api::gateway::launch_principal_root(missing.path(), missing.path(), ID)
                .unwrap_err()
                .to_string(),
            "Home launch principal root unresolved"
        );
        for (kind, expected) in [
            (PrincipalKind::Agent, AGENT_ROOT),
            (PrincipalKind::Human, HUMAN_ROOT),
        ] {
            let dir = tempfile::tempdir().unwrap();
            store(dir.path(), kind);
            let root = crate::auth::ResolvedPrincipalRoot::resolve(
                dir.path(),
                dir.path(),
                crate::auth::r4_fixture::principal_id(kind),
            )
            .unwrap();
            let context = HomeLaunchTokenContext::resolved(
                root,
                crate::auth::r4_fixture::principal_id(kind).to_string(),
                "session".into(),
                None,
                "grant".into(),
            );
            assert_eq!(
                viewer_target_root(&context),
                expected,
                "R4 viewer target root"
            );
            assert_eq!(
                principal_scoped_storage_uri("localhost://Users/self/Documents/*", &context),
                format!("{expected}/Documents"),
                "R4 viewer scoped URI"
            );
            assert!(
                viewer_storage_root_matches(&format!("{expected}/Documents"), &context),
                "R4 viewer root check"
            );
        }
    }
}

/// R8d evidence row for Viewer storage, for a parent passkey person on a
/// child Runtime. Entry: `viewer_storage_write` (line 695) with the
/// `Absent` precondition, which `viewer_storage_put` calls after the target
/// is built for the person's root.
#[cfg(test)]
mod r8d_passkey_rows {
    use super::*;
    use crate::api::gateway::gateway_tests::r8d_passkey_rows::{passkey_person, ROOT};

    const DOCUMENTS: &str = "documents";

    /// The `documents` viewer an installed Home carries: a manifest whose
    /// storage grant is scoped to the person's root. No capsule bytes run.
    fn documents_viewer(data_dir: &FsPath) {
        let capsule = data_dir.join("capsules/documents");
        std::fs::create_dir_all(capsule.join("browser")).unwrap();
        std::fs::write(capsule.join("browser/index.html"), "viewer").unwrap();
        std::fs::write(
            capsule.join("capsule.json"),
            serde_json::to_vec(&json!({
                "schema": "elastos.capsule/v1", "name": "documents", "version": "0.1.0",
                "author": "elastos", "role": "viewer", "type": "wasm",
                "entrypoint": "browser/index.html",
                "permissions": {"storage": ["localhost://Users/self/Documents/*"]}
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            data_dir.join("components.json"),
            serde_json::to_vec(&json!({"external": {"documents": {
                "install_path": "capsules/documents", "platforms": {}
            }}, "capsules": {}, "profiles": {}}))
            .unwrap(),
        )
        .unwrap();
    }

    /// Today the child's viewer storage write with the `Absent` precondition
    /// leaves the bytes as given under the person's root, and no protection
    /// record is needed.
    #[test]
    fn r8d_child_viewer_storage_save_for_the_passkey_person() {
        let person = passkey_person(DOCUMENTS);
        let child = person.child.path();
        documents_viewer(child);
        let target = viewer_storage_target_for_context(
            child,
            &person.ctx,
            DOCUMENTS,
            DOCUMENTS,
            "save",
            "r8d-note.md",
        )
        .unwrap_or_else(|error| panic!("{error:#}"));
        assert_eq!(target.object_uri, format!("{ROOT}/Documents/r8d-note.md"));
        let bytes = b"r8d child viewer note".to_vec();
        viewer_storage_write(
            child,
            &target,
            &bytes,
            crate::auth::PrincipalRootObjectPrecondition::Absent,
        )
        .unwrap_or_else(|error| panic!("{error:#}"));
        let relative = format!(
            "{}/Documents/r8d-note.md",
            ROOT.trim_start_matches("localhost://")
        );
        assert_eq!(
            std::fs::read(child.join(&relative)).unwrap(),
            bytes,
            "{relative} holds the bytes it was given"
        );
        let expected = [
            "capsules/documents/browser/index.html".to_string(),
            "capsules/documents/capsule.json".to_string(),
            "components.json".to_string(),
            relative,
        ];
        let also: Vec<&str> = expected.iter().map(String::as_str).collect();
        person.assert_child_holds_only(&also);
    }
}
