//! Capability request handlers
//!
//! Handles capability request/grant/deny flow.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use elastos_common::localhost::{is_supported_resource_scheme, is_system_only_backend_resource};
use elastos_runtime::capability::{
    pending::{PendingCapabilityRequest, PendingRequestStore},
    Action, CapabilityManager, CapabilityStore, GrantDuration, PolicyEvaluator, PolicyOutcome,
    RequestStatus, ResourceId, Settler, TokenConstraints,
};
use elastos_runtime::session::Session;

use crate::provider_resource::ensure_generic_wallet_capability;

/// Shared state for capability handlers
#[derive(Clone)]
pub struct CapabilityState {
    pub pending_store: Arc<PendingRequestStore>,
    pub capability_manager: Arc<CapabilityManager>,
    /// The same store `capability_manager` holds: revocations, use counts, epoch.
    pub capability_store: Arc<CapabilityStore>,
    pub policy_evaluator: Arc<PolicyEvaluator>,
}

// === Request Capability ===

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestCapabilityInput {
    /// Resource to request access to (e.g., "localhost://MyWebSite/Pictures/*")
    pub resource: String,
    /// Action to request (e.g., "read", "write")
    pub action: String,
    /// Plain-language reason shown during approval.
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct RequestCapabilityOutput {
    /// Status: "pending", "granted", or "auto_denied"
    pub status: String,
    /// Request ID (if pending)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Capability token (if auto-granted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Reason (if auto-denied)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /api/capability/request
///
/// Request a capability token. Returns immediately with either:
/// - status: "pending" + request_id (needs user approval)
/// - status: "granted" + token (auto-granted)
/// - status: "auto_denied" + reason (policy rejection)
pub async fn request_capability(
    State(state): State<CapabilityState>,
    Extension(session): Extension<Session>,
    Json(input): Json<RequestCapabilityInput>,
) -> Result<Json<RequestCapabilityOutput>, (StatusCode, String)> {
    // Parse action
    let action = match input.action.to_lowercase().as_str() {
        "read" => Action::Read,
        "write" => Action::Write,
        "execute" => Action::Execute,
        "delete" => Action::Delete,
        "message" => Action::Message,
        "admin" => Action::Admin,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Invalid action: {}. Expected: read, write, execute, delete, message, admin",
                    input.action
                ),
            ));
        }
    };

    if !is_supported_resource_scheme(&input.resource) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Unsupported resource scheme. Allowed: elastos://, localhost://".to_string(),
        ));
    }

    if is_system_only_backend_resource(&input.resource) {
        return Ok(Json(RequestCapabilityOutput {
            status: "denied".to_string(),
            request_id: None,
            token: None,
            reason: Some(
                "system backends are not app capabilities; use elastos://content".to_string(),
            ),
        }));
    }

    if let Err(reason) = ensure_generic_wallet_capability(&input.resource, action) {
        return Ok(Json(RequestCapabilityOutput {
            status: "denied".to_string(),
            request_id: None,
            token: None,
            reason: Some(reason),
        }));
    }

    let resource = ResourceId::new(&input.resource);

    // For now, all requests go to pending (no auto-grant policy yet)
    // Future: check if session already has this capability, or if policy allows auto-grant

    let request = state
        .pending_store
        .create_request_with_reason(session.id.clone(), resource, action, input.reason)
        .await;

    // If pre-denied (e.g. rate limit), surface the denial immediately
    if request.is_denied() {
        return Ok(Json(RequestCapabilityOutput {
            status: "denied".to_string(),
            request_id: Some(request.id.to_string()),
            token: None,
            reason: Some("Too many pending requests".to_string()),
        }));
    }

    Ok(Json(RequestCapabilityOutput {
        status: "pending".to_string(),
        request_id: Some(request.id.to_string()),
        token: None,
        reason: None,
    }))
}

// === Request Status ===

#[derive(Debug, Serialize)]
pub struct RequestStatusOutput {
    /// Status: "pending", "granted", "denied", or "expired"
    pub status: String,
    /// Capability token (if granted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Reason (if denied)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// GET /api/capability/request/:id
///
/// Check the status of a capability request.
pub async fn request_status(
    State(state): State<CapabilityState>,
    Extension(session): Extension<Session>,
    Path(request_id): Path<String>,
) -> Result<Json<RequestStatusOutput>, (StatusCode, String)> {
    let request = state
        .pending_store
        .get_request(&request_id)
        .await
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("Request not found: {}", request_id),
            )
        })?;

    // Verify the request belongs to this session
    if request.session_id != session.id {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot access another session's request".to_string(),
        ));
    }

    // Check for expiry
    if request.is_expired() {
        return Ok(Json(RequestStatusOutput {
            status: "expired".to_string(),
            token: None,
            reason: Some("Request timed out".to_string()),
        }));
    }

    match &request.status {
        elastos_runtime::capability::RequestStatus::Pending => Ok(Json(RequestStatusOutput {
            status: "pending".to_string(),
            token: None,
            reason: None,
        })),
        elastos_runtime::capability::RequestStatus::Granted { token, .. } => {
            Ok(Json(RequestStatusOutput {
                status: "granted".to_string(),
                token: Some(token.to_base64().unwrap_or_default()),
                reason: None,
            }))
        }
        elastos_runtime::capability::RequestStatus::Denied { reason, .. } => {
            Ok(Json(RequestStatusOutput {
                status: "denied".to_string(),
                token: None,
                reason: Some(reason.clone()),
            }))
        }
        elastos_runtime::capability::RequestStatus::Expired => Ok(Json(RequestStatusOutput {
            status: "expired".to_string(),
            token: None,
            reason: Some("Request timed out".to_string()),
        })),
    }
}

// === List Pending (Shell Only) ===

#[derive(Debug, Serialize)]
pub struct PendingRequestOutput {
    pub request_id: String,
    pub session_id: String,
    pub resource: String,
    pub action: String,
    pub reason: String,
    pub requested_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Serialize)]
pub struct ListPendingOutput {
    pub requests: Vec<PendingRequestOutput>,
}

/// GET /api/capability/pending
///
/// List all pending capability requests (shell only).
pub async fn list_pending(
    State(state): State<CapabilityState>,
    Extension(_session): Extension<Session>, // Shell check done by middleware
) -> Json<ListPendingOutput> {
    let pending = state.pending_store.list_pending().await;

    let requests = pending
        .into_iter()
        .map(|r| PendingRequestOutput {
            request_id: r.id.to_string(),
            session_id: r.session_id.to_string(),
            resource: r.resource.to_string(),
            action: r.action.to_string(),
            reason: r.reason,
            requested_at: r.requested_at.unix_secs,
            expires_at: r.expires_at.unix_secs,
        })
        .collect();

    Json(ListPendingOutput { requests })
}

// === Grant Request (Shell Only) ===

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequestInput {
    /// Request ID to grant
    pub request_id: String,
    /// Duration: "once" or "session"
    #[serde(default = "default_duration")]
    pub duration: String,
    /// Shell's rationale for granting (passed to PolicyEvaluator audit)
    #[serde(default)]
    pub rationale: Option<String>,
}

fn default_duration() -> String {
    "session".to_string()
}

#[derive(Debug, Serialize)]
pub struct GrantRequestOutput {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// POST /api/capability/grant
///
/// Grant a pending capability request (shell only).
pub async fn grant_request(
    State(state): State<CapabilityState>,
    Extension(_session): Extension<Session>, // Shell check done by middleware
    Json(input): Json<GrantRequestInput>,
) -> Result<Json<GrantRequestOutput>, (StatusCode, String)> {
    // Parse duration
    let duration: GrantDuration = input
        .duration
        .parse()
        .map_err(|e: String| (StatusCode::BAD_REQUEST, e))?;

    // Get the pending request
    let request = state
        .pending_store
        .get_request(&input.request_id)
        .await
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("Request not found: {}", input.request_id),
            )
        })?;

    if !request.is_pending() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Request {} is not pending", input.request_id),
        ));
    }

    // Policy evaluation (observational)
    let rationale = input.rationale.as_deref().unwrap_or("Shell auto-grant");
    let _decision = state
        .policy_evaluator
        .evaluate(&request, PolicyOutcome::Grant, rationale);

    // Create the capability token
    let constraints = match duration {
        GrantDuration::Once => TokenConstraints::new(0, false, None, Some(1)),
        GrantDuration::Session => TokenConstraints::default(),
    };

    // Use session ID as capsule ID for now
    let token = state.capability_manager.grant(
        &request.session_id.to_string(),
        request.resource.clone(),
        request.action,
        constraints,
        None, // No expiry for now (session-scoped)
    );

    // Mark request as granted
    state
        .pending_store
        .grant_request(&input.request_id, token.clone(), duration)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(GrantRequestOutput {
        success: true,
        token: Some(token.to_base64().unwrap_or_default()),
        error: None,
    }))
}

// === Deny Request (Shell Only) ===

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyRequestInput {
    /// Request ID to deny
    pub request_id: String,
    /// Reason for denial (optional)
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DenyRequestOutput {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// POST /api/capability/deny
///
/// Deny a pending capability request (shell only).
pub async fn deny_request(
    State(state): State<CapabilityState>,
    Extension(_session): Extension<Session>, // Shell check done by middleware
    Json(input): Json<DenyRequestInput>,
) -> Result<Json<DenyRequestOutput>, (StatusCode, String)> {
    let reason = input.reason.unwrap_or_else(|| "Denied by user".to_string());

    // Policy evaluation (observational)
    if let Some(request) = state.pending_store.get_request(&input.request_id).await {
        let _decision = state
            .policy_evaluator
            .evaluate(&request, PolicyOutcome::Deny, &reason);
    }

    state
        .pending_store
        .deny_request_by(&input.request_id, &reason, Settler::Shell)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    Ok(Json(DenyRequestOutput {
        success: true,
        error: None,
    }))
}

// === List Capabilities ===

#[derive(Debug, Serialize)]
pub struct CapabilityOutput {
    pub request_id: String,
    /// The grant's session. Only the `all_sessions_live` view names it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub resource: String,
    pub action: String,
    pub duration: String,
    pub granted_at: u64,
}

#[derive(Debug, Serialize)]
pub struct ListCapabilitiesOutput {
    /// `all_sessions_live` on the scoped view; absent on the default view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<&'static str>,
    pub capabilities: Vec<CapabilityOutput>,
}

/// The one `?scope=` value: live grants across every session, shell only.
const LIVE_SCOPE: &str = "all_sessions_live";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListCapabilitiesQuery {
    pub scope: Option<String>,
}

fn capability_output(
    r: &PendingCapabilityRequest,
    session_id: Option<String>,
) -> Option<CapabilityOutput> {
    let RequestStatus::Granted { duration, .. } = &r.status else {
        return None;
    };
    Some(CapabilityOutput {
        request_id: r.id.to_string(),
        session_id,
        resource: r.resource.to_string(),
        action: r.action.to_string(),
        duration: duration.to_string(),
        granted_at: r.requested_at.unix_secs, // Use requested_at as proxy for granted_at
    })
}

/// A granted record whose token still authorises: not revoked by id, not
/// spent, not past its expiry, and minted in the current epoch.
async fn is_live(store: &CapabilityStore, r: &PendingCapabilityRequest) -> bool {
    let Some(token) = r.granted_token() else {
        return false;
    };
    let spent = match token.constraints().max_uses() {
        Some(max_uses) => store.has_exceeded_uses(token.id(), max_uses).await,
        None => false,
    };
    let expired = token.expiry().is_some_and(|expiry| expiry.is_expired());
    !store.is_token_revoked(token.id()).await
        && !spent
        && !expired
        && store.is_epoch_valid(token.constraints().epoch())
}

/// Every session's live grants, sorted by session then request id.
async fn live_capabilities(state: &CapabilityState) -> ListCapabilitiesOutput {
    let mut live = Vec::new();
    for r in state.pending_store.list_requests().await {
        if is_live(&state.capability_store, &r).await {
            live.push(r);
        }
    }
    live.sort_by(|a, b| {
        let key = |r: &PendingCapabilityRequest| (r.session_id.to_string(), r.id.to_string());
        key(a).cmp(&key(b))
    });
    let capabilities = live
        .iter()
        .filter_map(|r| capability_output(r, Some(r.session_id.to_string())))
        .collect();
    ListCapabilitiesOutput {
        scope: Some(LIVE_SCOPE),
        capabilities,
    }
}

/// One session's granted requests, projected from the Runtime's global list.
async fn session_granted(
    store: &PendingRequestStore,
    session_id: &str,
) -> Vec<PendingCapabilityRequest> {
    let held = store.list_requests().await.into_iter();
    held.filter(|r| r.is_granted() && r.session_id.to_string() == session_id)
        .collect()
}

/// GET /api/capability/list
///
/// List active capabilities for the current session. `?scope=all_sessions_live`
/// lists live grants across every session, for a shell session only.
pub async fn list_capabilities(
    State(state): State<CapabilityState>,
    Extension(session): Extension<Session>,
    Query(query): Query<ListCapabilitiesQuery>,
) -> Result<Json<ListCapabilitiesOutput>, (StatusCode, String)> {
    if let Some(scope) = query.scope {
        if scope != LIVE_SCOPE {
            let reason = format!("unknown capability list scope: {scope}");
            return Err((StatusCode::BAD_REQUEST, reason));
        }
        if !session.is_shell() {
            let reason = "This endpoint requires shell privileges".to_string();
            return Err((StatusCode::FORBIDDEN, reason));
        }
        return Ok(Json(live_capabilities(&state).await));
    }
    // Get granted requests for this session
    let session_id = session.id.to_string();
    let granted_requests = session_granted(&state.pending_store, &session_id).await;

    let capabilities = granted_requests
        .iter()
        .filter_map(|r| capability_output(r, None))
        .collect();

    Ok(Json(ListCapabilitiesOutput {
        scope: None,
        capabilities,
    }))
}

// === Session Request Records (Shell Only) ===

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequestsQuery {
    pub session: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RequestRecordOutput {
    pub request_id: String,
    pub session_id: String,
    pub resource: String,
    pub action: String,
    pub reason: String,
    /// `pending`, `granted`, `denied` (a revoked grant reads `denied`) or `expired`.
    pub status: &'static str,
    /// `shell` or `runtime` on a denied record, null otherwise: the core
    /// records no settler for a pending, granted or expired record.
    pub settled_by: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct SessionRequestsOutput {
    pub requests: Vec<RequestRecordOutput>,
}

fn request_record(r: &PendingCapabilityRequest) -> RequestRecordOutput {
    let (status, settled_by) = match &r.status {
        RequestStatus::Pending => ("pending", None),
        RequestStatus::Granted { .. } => ("granted", None),
        RequestStatus::Denied { settled_by, .. } => match settled_by {
            Settler::Shell => ("denied", Some("shell")),
            Settler::Runtime => ("denied", Some("runtime")),
        },
        // The core records no settler for `Expired`: the store's cleanup
        // writes it, and so does a shell grant on a past-deadline request.
        RequestStatus::Expired => ("expired", None),
    };
    RequestRecordOutput {
        request_id: r.id.to_string(),
        session_id: r.session_id.to_string(),
        resource: r.resource.to_string(),
        action: r.action.to_string(),
        reason: r.reason.clone(),
        status,
        settled_by,
    }
}

/// GET /api/capability/requests?session=
///
/// The request records the store still holds for one session, sorted by
/// request id (shell only). The store drops resolved records by age and
/// under load, so this is not a full history.
pub async fn session_requests(
    State(state): State<CapabilityState>,
    Extension(_session): Extension<Session>, // Shell check done by middleware
    Query(query): Query<SessionRequestsQuery>,
) -> Result<Json<SessionRequestsOutput>, (StatusCode, String)> {
    let Some(session) = query.session.filter(|session| !session.is_empty()) else {
        let reason = "requests need a session".to_string();
        return Err((StatusCode::BAD_REQUEST, reason));
    };
    let held = state.pending_store.list_requests().await.into_iter();
    let mut held: Vec<_> = held.filter(|r| r.session_id.as_str() == session).collect();
    held.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    let requests = held.iter().map(request_record).collect();
    Ok(Json(SessionRequestsOutput { requests }))
}

// === Revoke Capability (Shell Only) ===

#[derive(Debug, Serialize)]
pub struct RevokeCapabilityOutput {
    pub success: bool,
    pub revoked_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// DELETE /api/capability/:id
///
/// Revoke a specific capability by request ID (shell only).
pub async fn revoke_capability(
    State(state): State<CapabilityState>,
    Extension(_session): Extension<Session>, // Shell check done by middleware
    Path(request_id): Path<String>,
) -> Result<Json<RevokeCapabilityOutput>, (StatusCode, String)> {
    // Get the request to find the token
    let request = state
        .pending_store
        .get_request(&request_id)
        .await
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("Capability request not found: {}", request_id),
            )
        })?;

    // Check if it was granted
    match &request.status {
        elastos_runtime::capability::RequestStatus::Granted { token, .. } => {
            // Revoke the token
            state
                .capability_manager
                .revoke(*token.id(), "Revoked by user via API")
                .await;

            // Mark the request as revoked in the pending store
            state
                .pending_store
                .revoke_request_by(&request_id, "Revoked by user", Settler::Shell)
                .await;

            Ok(Json(RevokeCapabilityOutput {
                success: true,
                revoked_request_id: request_id,
                error: None,
            }))
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("Capability {} was not granted", request_id),
        )),
    }
}

// === Revoke All Capabilities (Shell Only) ===

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeAllInput {
    /// Reason for revoking all capabilities
    #[serde(default = "default_revoke_reason")]
    pub reason: String,
}

fn default_revoke_reason() -> String {
    "Revoked all by user".to_string()
}

#[derive(Debug, Serialize)]
pub struct RevokeAllOutput {
    pub success: bool,
    pub new_epoch: u64,
    pub reason: String,
}

/// POST /api/capability/revoke-all
///
/// Revoke all capabilities by advancing the epoch (shell only).
/// All tokens with epoch < new_epoch will be rejected.
pub async fn revoke_all_capabilities(
    State(state): State<CapabilityState>,
    Extension(_session): Extension<Session>, // Shell check done by middleware
    Json(input): Json<RevokeAllInput>,
) -> Json<RevokeAllOutput> {
    let new_epoch = state.capability_manager.revoke_all(&input.reason);

    // Mark all granted requests as revoked
    state.pending_store.revoke_all_granted().await;

    Json(RevokeAllOutput {
        success: true,
        new_epoch,
        reason: input.reason,
    })
}

// === Session Info ===

#[derive(Debug, Serialize)]
pub struct SessionInfoOutput {
    pub session_id: String,
    pub session_type: String,
    pub vm_id: Option<String>,
    pub capabilities_count: usize,
    pub created_at: u64,
    pub last_active: u64,
}

/// GET /api/session
///
/// Get information about the current session.
pub async fn session_info(
    State(state): State<CapabilityState>,
    Extension(session): Extension<Session>,
) -> Json<SessionInfoOutput> {
    let session_id = session.id.to_string();
    let capabilities_count = session_granted(&state.pending_store, &session_id)
        .await
        .len();

    Json(SessionInfoOutput {
        session_id,
        session_type: session.session_type.to_string(),
        vm_id: session.vm_id.clone(),
        capabilities_count,
        created_at: session.created_at.unix_secs,
        last_active: session.last_active.unix_secs,
    })
}

// === Audit Log API (Shell Only) ===

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLogQuery {
    /// Maximum number of events to return (default: 100, max: 1000)
    #[serde(default = "default_audit_limit")]
    pub limit: usize,
    /// Filter by event type (e.g., "capability_grant", "capability_revoke")
    #[serde(rename = "type")]
    pub event_type: Option<String>,
}

fn default_audit_limit() -> usize {
    100
}

#[derive(Debug, Serialize)]
pub struct AuditLogOutput {
    /// List of audit events (newest first)
    pub events: Vec<elastos_runtime::primitives::audit::AuditEvent>,
    /// Total events in memory buffer
    pub total_in_memory: usize,
    /// Current epoch
    pub current_epoch: u64,
}

/// GET /api/audit
///
/// Get recent audit log events (shell only).
/// Query params:
/// - limit: Max events to return (default 100, max 1000)
/// - type: Filter by event type (e.g., "capability_grant")
pub async fn get_audit_log(
    State(state): State<CapabilityState>,
    Extension(_session): Extension<Session>, // Shell check done by middleware
    Query(query): Query<AuditLogQuery>,
) -> Json<AuditLogOutput> {
    let limit = query.limit.min(1000);
    let audit_log = state.capability_manager.audit_log();

    let events = if let Some(ref event_type) = query.event_type {
        audit_log.recent_events_filtered(limit, Some(event_type))
    } else {
        audit_log.recent_events(limit)
    };

    Json(AuditLogOutput {
        events,
        total_in_memory: audit_log.event_count(),
        current_epoch: state.capability_manager.current_epoch(),
    })
}

/// Available audit event types for filtering
#[derive(Debug, Serialize)]
pub struct AuditEventTypesOutput {
    pub event_types: Vec<&'static str>,
}

/// GET /api/audit/types
///
/// List available audit event types for filtering.
pub async fn get_audit_event_types(
    Extension(_session): Extension<Session>,
) -> Json<AuditEventTypesOutput> {
    Json(AuditEventTypesOutput {
        event_types: vec![
            "runtime_start",
            "runtime_stop",
            "capsule_launch",
            "capsule_stop",
            "capability_grant",
            "capability_revoke",
            "capability_use",
            "capability_requested",
            "capability_denied",
            "content_fetch",
            "auth_attempt",
            "epoch_advance",
            "config_change",
            "security_warning",
            "session_created",
            "session_destroyed",
            "policy_proposal",
            "policy_decision_made",
            "policy_divergence",
            "custom",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_supported_resource_schemes() {
        assert!(is_supported_resource_scheme("elastos://did/*"));
        assert!(is_supported_resource_scheme(
            "localhost://MyWebSite/Documents/*"
        ));
    }

    #[test]
    fn test_rejects_unsupported_resource_schemes() {
        assert!(!is_supported_resource_scheme("elastos:/broken"));
        assert!(!is_supported_resource_scheme("localhost:/broken"));
        assert!(!is_supported_resource_scheme("resource-without-scheme"));
        assert!(!is_supported_resource_scheme(""));
    }

    #[test]
    fn test_system_only_backend_resource_detection() {
        assert!(is_system_only_backend_resource("elastos://ipfs/add"));
        assert!(is_system_only_backend_resource("elastos://ipfs"));
        assert!(is_system_only_backend_resource("elastos://kubo/rpc"));
        assert!(is_system_only_backend_resource(
            "elastos://ipfs-cluster/pins"
        ));
        assert!(is_system_only_backend_resource("elastos://elacity-sdk/pin"));
        assert!(is_system_only_backend_resource(
            "elastos://ipfs-provider/add"
        ));
        assert!(is_system_only_backend_resource("elastos://gateway/raw"));
        assert!(!is_system_only_backend_resource(
            "elastos://content/publish"
        ));
        assert!(!is_system_only_backend_resource(
            "localhost://MyWebSite/Documents/x"
        ));
    }

    fn assert_rejects_unknown_field<T: serde::de::DeserializeOwned>(value: serde_json::Value) {
        let err = match serde_json::from_value::<T>(value) {
            Ok(_) => panic!("expected capability body to reject unknown fields"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("unknown field"), "{err}");
    }

    #[test]
    fn test_capability_inputs_reject_hidden_authority_fields() {
        assert_rejects_unknown_field::<RequestCapabilityInput>(json!({
            "resource": "elastos://content/publish",
            "action": "write",
            "capability_token": "must-not-be-accepted"
        }));
        assert_rejects_unknown_field::<GrantRequestInput>(json!({
            "request_id": "request:test",
            "duration": "session",
            "rationale": "ok",
            "token": "must-not-be-accepted"
        }));
        assert_rejects_unknown_field::<DenyRequestInput>(json!({
            "request_id": "request:test",
            "reason": "no",
            "override": true
        }));
        assert_rejects_unknown_field::<RevokeAllInput>(json!({
            "reason": "rotate",
            "session_id": "session:other"
        }));
        assert_rejects_unknown_field::<AuditLogQuery>(json!({
            "limit": 10,
            "type": "capability_grant",
            "include_private": true
        }));
    }

    fn test_state() -> CapabilityState {
        let audit_log = std::sync::Arc::new(elastos_runtime::primitives::audit::AuditLog::new());
        let store = std::sync::Arc::new(elastos_runtime::capability::CapabilityStore::new());
        let metrics =
            std::sync::Arc::new(elastos_runtime::primitives::metrics::MetricsManager::new());
        let capability_manager = std::sync::Arc::new(CapabilityManager::new(
            store.clone(),
            audit_log.clone(),
            metrics,
        ));

        CapabilityState {
            pending_store: std::sync::Arc::new(PendingRequestStore::new(audit_log.clone())),
            capability_manager,
            capability_store: store,
            policy_evaluator: std::sync::Arc::new(PolicyEvaluator::new(
                Box::new(elastos_runtime::capability::evaluator::ShellPassthroughVerifier),
                audit_log,
            )),
        }
    }

    async fn settler(state: &CapabilityState, id: &str) -> Settler {
        match state.pending_store.get_request(id).await.unwrap().status {
            elastos_runtime::capability::RequestStatus::Denied { settled_by, .. } => settled_by,
            other => panic!("request {id} is not denied: {other:?}"),
        }
    }

    #[tokio::test]
    async fn shell_deny_route_records_the_shell_as_settler() {
        let state = test_state();
        let session = elastos_runtime::session::SessionId::from_string("capsule-1");
        let resource = ResourceId::new("elastos://content/publish");
        let request = state
            .pending_store
            .create_request(session, resource, Action::Write)
            .await;
        let input = DenyRequestInput {
            request_id: request.id.to_string(),
            reason: None,
        };
        let shell = Extension(Session::new_shell("shell-vm".to_string()));
        let output = deny_request(State(state.clone()), shell, Json(input)).await;
        assert!(output.unwrap().0.success);
        assert_eq!(settler(&state, request.id.as_str()).await, Settler::Shell);
    }

    #[tokio::test]
    async fn shell_revoke_route_records_the_shell_as_settler() {
        let state = test_state();
        let session = elastos_runtime::session::SessionId::from_string("capsule-1");
        let resource = ResourceId::new("elastos://content/publish");
        let request = state
            .pending_store
            .create_request(session, resource.clone(), Action::Write)
            .await;
        let id = request.id.to_string();
        let constraints = TokenConstraints::default();
        let token =
            state
                .capability_manager
                .grant("capsule-1", resource, Action::Write, constraints, None);
        let store = &state.pending_store;
        store
            .grant_request(&id, token, GrantDuration::Session)
            .await
            .unwrap();
        let shell = Extension(Session::new_shell("shell-vm".to_string()));
        let output = revoke_capability(State(state.clone()), shell, Path(id.clone())).await;
        assert!(output.unwrap().0.success);
        assert_eq!(settler(&state, &id).await, Settler::Shell);
    }

    #[tokio::test]
    async fn session_views_exclude_another_session_the_global_list_includes() {
        let state = test_state();
        let (a, b) = (
            Session::new_capsule("vm-a".into()),
            Session::new_capsule("vm-b".into()),
        );
        let mut ids = Vec::new();
        for session in [&a, &b] {
            let resource = ResourceId::new("elastos://content/publish");
            let store = &state.pending_store;
            let request = store.create_request(session.id.clone(), resource.clone(), Action::Write);
            let id = request.await.id.to_string();
            let token = state.capability_manager.grant(
                session.id.as_str(),
                resource,
                Action::Write,
                TokenConstraints::default(),
                None,
            );
            store
                .grant_request(&id, token, GrantDuration::Session)
                .await
                .unwrap();
            ids.push(id);
        }
        let query = Query(ListCapabilitiesQuery { scope: None });
        let listed = list_capabilities(State(state.clone()), Extension(a.clone()), query).await;
        let listed: Vec<_> = listed
            .unwrap()
            .0
            .capabilities
            .into_iter()
            .map(|c| c.request_id)
            .collect();
        assert_eq!(listed, vec![ids[0].clone()]);
        let info = session_info(State(state.clone()), Extension(a)).await;
        assert_eq!(info.0.capabilities_count, 1);
        assert_eq!(state.pending_store.list_requests().await.len(), 2);
    }

    /// Grants one write request in `session`; returns its request id and token.
    async fn grant_in(
        state: &CapabilityState,
        session: &str,
        max_uses: Option<u32>,
        expiry: Option<elastos_common::SecureTimestamp>,
    ) -> (String, elastos_runtime::capability::CapabilityToken) {
        let resource = ResourceId::new("elastos://content/publish");
        let session_id = elastos_runtime::session::SessionId::from_string(session);
        let store = &state.pending_store;
        let request = store.create_request(session_id, resource.clone(), Action::Write);
        let id = request.await.id.to_string();
        let constraints = TokenConstraints::new(0, false, None, max_uses);
        let manager = &state.capability_manager;
        let token = manager.grant(session, resource, Action::Write, constraints, expiry);
        store
            .grant_request(&id, token.clone(), GrantDuration::Session)
            .await
            .unwrap();
        (id, token)
    }

    /// Lists `?scope=all_sessions_live` as the shell; returns the body and its request ids.
    async fn live_view(state: &CapabilityState) -> (serde_json::Value, Vec<String>) {
        let uri = "http://runtime/api/capability/list?scope=all_sessions_live";
        let query = Query::try_from_uri(&uri.parse().unwrap()).unwrap();
        let shell = Extension(Session::new_shell("shell-vm".to_string()));
        let body = list_capabilities(State(state.clone()), shell, query).await;
        let body = serde_json::to_value(body.unwrap().0).unwrap();
        let ids = body["capabilities"].as_array().unwrap().iter();
        let ids = ids.map(|c| c["request_id"].as_str().unwrap().to_owned());
        let ids = ids.collect();
        (body, ids)
    }

    #[tokio::test]
    async fn live_scope_lists_only_live_grants_of_every_session() {
        let start = elastos_common::SecureTimestamp::now().unix_secs;
        let state = test_state();
        let manager = state.capability_manager.clone();
        let (old_epoch, _) = grant_in(&state, "session-a", None, None).await;
        manager.revoke_all("key rotated"); // its record stays granted
        let (live_a, _) = grant_in(&state, "session-a", None, None).await;
        let (live_b, _) = grant_in(&state, "session-b", None, None).await;
        let (revoked, token) = grant_in(&state, "session-a", None, None).await;
        manager.revoke(*token.id(), "operator detached").await; // record stays granted
        let (spent, token) = grant_in(&state, "session-b", Some(1), None).await;
        let resource = ResourceId::new("elastos://content/publish");
        let used = manager.validate(&token, "session-b", Action::Write, &resource, None);
        used.await.expect("the once grant is used");
        let past = Some(elastos_common::SecureTimestamp::at(1));
        let (expired, _) = grant_in(&state, "session-b", None, past).await;
        let held = state.pending_store.list_requests().await;
        let granted = held.iter().filter(|r| r.is_granted()).count();
        assert_eq!(
            granted, 6,
            "all six records are still granted, so only the live rule drops one"
        );

        let (mut body, ids) = live_view(&state).await;
        assert!(
            !ids.contains(&revoked),
            "F-norevoke: a grant revoked by id is absent"
        );
        assert!(!ids.contains(&spent), "a spent once grant is absent");
        assert!(
            !ids.contains(&old_epoch),
            "a grant from an old epoch is absent"
        );
        assert!(!ids.contains(&expired), "a grant past its expiry is absent");
        let end = elastos_common::SecureTimestamp::now().unix_secs;
        for entry in body["capabilities"].as_array_mut().unwrap() {
            let granted_at = entry["granted_at"].as_u64().unwrap();
            assert!(
                (start..=end).contains(&granted_at),
                "granted_at is the request time"
            );
            entry.as_object_mut().unwrap().remove("granted_at");
        }
        let entry = |id: &str, session: &str| {
            json!({ "request_id": id, "session_id": session, "duration": "session",
                    "resource": "elastos://content/publish", "action": "write" })
        };
        let expected = json!({ "scope": "all_sessions_live",
            "capabilities": [entry(&live_a, "session-a"), entry(&live_b, "session-b")] });
        assert_eq!(
            body, expected,
            "the live view is exactly the two live grants"
        );
    }

    /// The lab stand-in's shell-only reason, written out independently.
    const SHELL_REASON: &str = "This endpoint requires shell privileges";

    #[tokio::test]
    async fn default_scope_stays_the_callers_session_and_the_scope_is_shell_only() {
        let state = test_state();
        let client = Session::new_capsule("vm-a".to_string());
        let shell = Session::new_shell("shell-vm".to_string());
        let (own, _) = grant_in(&state, client.id.as_str(), None, None).await;
        grant_in(&state, "session-b", None, None).await;
        let list = |session: &Session, scope: Option<&str>| {
            let query = Query(ListCapabilitiesQuery {
                scope: scope.map(str::to_owned),
            });
            list_capabilities(State(state.clone()), Extension(session.clone()), query)
        };
        let body = list(&client, None).await.unwrap().0;
        let mut body = serde_json::to_value(body).unwrap();
        body["capabilities"][0]
            .as_object_mut()
            .unwrap()
            .remove("granted_at");
        let entry = json!({ "request_id": own, "duration": "session",
            "resource": "elastos://content/publish", "action": "write" });
        assert_eq!(
            body,
            json!({ "capabilities": [entry] }),
            "the default view lists only the caller's session, with no scope or session_id"
        );
        let body = serde_json::to_value(list(&shell, None).await.unwrap().0).unwrap();
        assert_eq!(
            body,
            json!({ "capabilities": [] }),
            "the shell's default view is its own session, not every session"
        );
        let shell_only = (StatusCode::FORBIDDEN, SHELL_REASON.to_owned());
        assert_eq!(
            list(&client, Some("all_sessions_live")).await.err(),
            Some(shell_only),
            "a client is refused the all_sessions_live view"
        );
        let unknown = "unknown capability list scope: session".to_owned();
        assert_eq!(
            list(&shell, Some("session")).await.err(),
            Some((StatusCode::BAD_REQUEST, unknown)),
            "an unknown scope is refused"
        );
        assert_rejects_unknown_field::<ListCapabilitiesQuery>(json!({
            "scope": "all_sessions_live",
            "session": "session-b"
        }));
    }

    type Records = std::collections::HashMap<String, serde_json::Value>;

    /// Reads `?session=` back through the handler: the ids in order, and each record by id.
    async fn records(state: &CapabilityState, session: &str) -> (Vec<String>, Records) {
        let uri = format!("http://runtime/api/capability/requests?session={session}");
        let query = Query::try_from_uri(&uri.parse().unwrap()).unwrap();
        let shell = Extension(Session::new_shell("shell-vm".to_string()));
        let body = session_requests(State(state.clone()), shell, query).await;
        let body = serde_json::to_value(body.unwrap().0).unwrap();
        let entries = body["requests"].as_array().unwrap().clone();
        let id = |e: &serde_json::Value| e["request_id"].as_str().unwrap().to_owned();
        let ids = entries.iter().map(id).collect();
        (ids, entries.into_iter().map(|e| (id(&e), e)).collect())
    }

    fn record(
        id: &str,
        session: &str,
        status: &str,
        by: Option<&str>,
    ) -> Option<serde_json::Value> {
        Some(
            json!({ "request_id": id, "session_id": session, "status": status,
            "settled_by": by, "resource": "elastos://content/publish", "action": "write",
            "reason": "" }),
        )
    }

    #[tokio::test]
    async fn session_requests_read_back_each_state_and_its_settler() {
        let state = test_state();
        let store = state.pending_store.clone();
        let resource = ResourceId::new("elastos://content/publish");
        let create = |session: &str| {
            let session = elastos_runtime::session::SessionId::from_string(session);
            store.create_request(session, resource.clone(), Action::Write)
        };
        let pending = create("session-a").await.id.to_string();
        let by_shell = create("session-a").await.id.to_string();
        let shell_deny = store.deny_request_by(&by_shell, "no", Settler::Shell);
        shell_deny.await.unwrap();
        let by_runtime = create("session-a").await.id.to_string();
        let runtime_deny = store.deny_request_by(&by_runtime, "ended", Settler::Runtime);
        runtime_deny.await.unwrap();
        let (granted, _) = grant_in(&state, "session-a", None, None).await;
        let (revoked, _) = grant_in(&state, "session-a", None, None).await;
        store
            .revoke_request_by(&revoked, "ended", Settler::Runtime)
            .await;
        create("session-b").await;

        let (ids, by_id) = records(&state, "session-a").await;
        let at = |id: &str| by_id.get(id).cloned();
        let a = "session-a";
        assert_eq!(
            at(&pending),
            record(&pending, a, "pending", None),
            "a pending request"
        );
        let shell = record(&by_shell, a, "denied", Some("shell"));
        assert_eq!(
            at(&by_shell),
            shell,
            "a shell deny reads back denied, settled by the shell"
        );
        let runtime = record(&by_runtime, a, "denied", Some("runtime"));
        assert_eq!(
            at(&by_runtime),
            runtime,
            "a runtime deny reads back settled by the runtime"
        );
        assert_eq!(
            at(&granted),
            record(&granted, a, "granted", None),
            "a granted request"
        );
        let revoke = record(&revoked, a, "denied", Some("runtime"));
        assert_eq!(
            at(&revoked),
            revoke,
            "a revoked grant reads back denied, by its revoker"
        );
        let mut want = vec![pending, by_shell, by_runtime, granted, revoked];
        want.sort();
        assert_eq!(
            ids, want,
            "exactly session-a's records, sorted by request id"
        );

        let audit = Arc::new(elastos_runtime::primitives::audit::AuditLog::new());
        let pending_store = Arc::new(PendingRequestStore::with_timeout(audit, 0));
        let expiring = CapabilityState {
            pending_store,
            ..test_state()
        };
        let session = elastos_runtime::session::SessionId::from_string("session-c");
        let request = expiring
            .pending_store
            .create_request(session, resource, Action::Write);
        let expired = request.await.id.to_string();
        assert_eq!(
            expiring.pending_store.cleanup_expired().await,
            1,
            "the request is due"
        );
        let (_, by_id) = records(&expiring, "session-c").await;
        let want = record(&expired, "session-c", "expired", None);
        assert_eq!(
            by_id.get(&expired).cloned(),
            want,
            "an expired request names no settler"
        );
    }

    #[tokio::test]
    async fn requests_route_is_shell_only() {
        use axum::{body::Body, http::header::AUTHORIZATION, http::Request};
        use elastos_runtime::session::{SessionRegistry, SessionType};
        use tower::ServiceExt;
        let audit = Arc::new(elastos_runtime::primitives::audit::AuditLog::new());
        let session_registry = Arc::new(SessionRegistry::new(audit));
        let shell = session_registry.create_session(SessionType::Shell, None);
        let shell = shell.await;
        let client = session_registry.create_session(SessionType::Capsule, None);
        let client = client.await;
        let api_state = crate::api::middleware::ApiState { session_registry };
        let app = crate::api::server::shell_capability_routes(api_state, test_state());
        let get = |token: &str, query: &str| {
            let request = Request::get(format!("/api/capability/requests{query}"));
            let request = request.header(AUTHORIZATION, format!("Bearer {token}"));
            app.clone().oneshot(request.body(Body::empty()).unwrap())
        };
        let read = |response: axum::response::Response| async move {
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX);
            (
                status,
                String::from_utf8(body.await.unwrap().to_vec()).unwrap(),
            )
        };

        let refused = read(get(&client.token, "?session=session-a").await.unwrap()).await;
        let shell_only = (StatusCode::FORBIDDEN, SHELL_REASON.to_owned());
        assert_eq!(
            refused, shell_only,
            "a client session is refused the requests view"
        );
        let listed = read(get(&shell.token, "?session=session-a").await.unwrap()).await;
        let empty = (StatusCode::OK, r#"{"requests":[]}"#.to_owned());
        assert_eq!(listed, empty, "a shell session reads the requests view");
        let missing = read(get(&shell.token, "").await.unwrap()).await;
        let need = (
            StatusCode::BAD_REQUEST,
            "requests need a session".to_owned(),
        );
        assert_eq!(missing, need, "a shell request with no session is refused");
    }

    #[tokio::test]
    async fn a_grant_on_a_past_deadline_request_reads_expired_with_no_settler() {
        use axum::{body::Body, http::header::AUTHORIZATION, http::Request};
        use elastos_runtime::session::{SessionRegistry, SessionType};
        use tower::ServiceExt;
        let audit = Arc::new(elastos_runtime::primitives::audit::AuditLog::new());
        let state = CapabilityState {
            pending_store: Arc::new(PendingRequestStore::with_timeout(audit.clone(), 0)),
            ..test_state()
        };
        let session = elastos_runtime::session::SessionId::from_string("session-d");
        let resource = ResourceId::new("elastos://content/publish");
        let store = state.pending_store.clone();
        let request = store.create_request(session, resource.clone(), Action::Write);
        let id = request.await.id.to_string();
        let session_registry = Arc::new(SessionRegistry::new(audit));
        let shell = session_registry.create_session(SessionType::Shell, None);
        let token = shell.await.token;
        let api_state = crate::api::middleware::ApiState { session_registry };
        let app = crate::api::server::shell_capability_routes(api_state, state.clone());
        let grant = Request::post("/api/capability/grant")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({ "request_id": id }).to_string()))
            .unwrap();
        let refused = app.oneshot(grant).await.unwrap();
        let status = refused.status();
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the shell grant route refuses it"
        );
        let manager = &state.capability_manager;
        let constraints = TokenConstraints::default();
        let minted = manager.grant("session-d", resource, Action::Write, constraints, None);
        // The store's own grant, as the browser operator approval calls it.
        let stored = store
            .grant_request(&id, minted, GrantDuration::Session)
            .await;
        assert_eq!(stored, Err(format!("Request {id} has expired")));
        let (_, by_id) = records(&state, "session-d").await;
        let want = record(&id, "session-d", "expired", None);
        let message = "a grant-written expiry reads expired with no settler";
        assert_eq!(by_id.get(&id).cloned(), want, "{message}");
    }

    #[tokio::test]
    async fn test_request_capability_denies_ipfs_backend() {
        let output = request_capability(
            State(test_state()),
            Extension(Session::new_capsule("capsule-1".to_string())),
            Json(RequestCapabilityInput {
                resource: "elastos://ipfs/add".to_string(),
                action: "write".to_string(),
                reason: "publish content".to_string(),
            }),
        )
        .await
        .expect("ipfs backend request should return a structured denial")
        .0;

        assert_eq!(output.status, "denied");
        assert_eq!(output.request_id, None);
        assert!(output.reason.unwrap().contains("elastos://content"));
    }

    #[tokio::test]
    async fn test_request_capability_allows_content_contract() {
        let output = request_capability(
            State(test_state()),
            Extension(Session::new_capsule("capsule-1".to_string())),
            Json(RequestCapabilityInput {
                resource: "elastos://content/publish".to_string(),
                action: "write".to_string(),
                reason: "publish content".to_string(),
            }),
        )
        .await
        .expect("content contract request should be accepted")
        .0;

        assert_eq!(output.status, "pending");
        assert!(output.request_id.is_some());
        assert!(output.reason.is_none());
    }

    #[tokio::test]
    async fn generic_wallet_capability_requests_fail_before_pending() {
        let state = test_state();
        for (resource, action) in [
            ("elastos://wallet/*", "read"),
            ("elastos://wallet/account/list", "read"),
            ("elastos://wallet/proof/challenge", "read"),
            ("elastos://wallet/approval", "write"),
            ("elastos://wallet/meta/status", "write"),
        ] {
            let output = request_capability(
                State(state.clone()),
                Extension(Session::new_capsule("capsule-1".to_string())),
                Json(RequestCapabilityInput {
                    resource: resource.to_string(),
                    action: action.to_string(),
                    reason: "request generic Wallet authority".to_string(),
                }),
            )
            .await
            .expect("generic Wallet capability request should return a structured denial")
            .0;

            assert_eq!(output.status, "denied", "{resource} {action}");
            assert_eq!(output.request_id, None, "{resource} {action}");
            assert!(
                output
                    .reason
                    .unwrap()
                    .contains("private Runtime Wallet Bus"),
                "{resource} {action}"
            );
        }

        assert!(
            state.pending_store.list_pending().await.is_empty(),
            "rejected Wallet capability requests must not create pending approvals"
        );
    }

    #[tokio::test]
    async fn read_only_wallet_status_capability_remains_requestable() {
        let state = test_state();
        let output = request_capability(
            State(state.clone()),
            Extension(Session::new_capsule("capsule-1".to_string())),
            Json(RequestCapabilityInput {
                resource: crate::provider_resource::WALLET_STATUS_RESOURCE.to_string(),
                action: "read".to_string(),
                reason: "read Wallet provider status".to_string(),
            }),
        )
        .await
        .expect("read-only Wallet status capability should remain requestable")
        .0;

        assert_eq!(output.status, "pending");
        assert!(output.request_id.is_some());
        let pending = state.pending_store.list_pending().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].resource.to_string(),
            crate::provider_resource::WALLET_STATUS_RESOURCE
        );
        assert_eq!(pending[0].action, Action::Read);
    }
}
