use super::*;

pub(super) async fn inbox_summary(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let authority =
        match require_runtime_wallet_authority(&state.data_dir, &headers, &[INBOX_CAPSULE_ID]) {
            Ok(authority) => authority,
            Err(err) => return inbox_error_response(err),
        };
    let context = authority.home_launch_context();

    let home_state = home_state(&state.data_dir);
    let mut notifications = home_state.notifications;
    let contact_authority =
        match super::gateway_home_system::load_configured_contact_authority_for_context(
            &state.data_dir,
            &context,
            state.collaboration_discovery_service.as_ref(),
        ) {
            Ok(authority) => authority,
            Err(err) => return inbox_error_response(err),
        };
    if let Err(err) = super::gateway_home_system::apply_contact_request_notification_projection(
        &state.data_dir,
        contact_authority.as_ref(),
        state.collaboration_chat_product_port.as_ref(),
        &mut notifications,
    ) {
        return inbox_error_response(err);
    }
    let wallet_approvals = system_wallet_approvals_summary(&state, &authority, false).await;
    append_inbox_requests(
        &state,
        &context,
        wallet_approvals.approval_requests,
        &mut notifications,
    )
    .await;
    // Inbox draws hosted decisions and their history from `hosted_routes`.
    #[cfg(unix)]
    let hosted_routes = match owner_hosted_routes(&state.data_dir, &context) {
        Ok(routes) => {
            let pending = routes.iter().filter(|route| route.is_pending()).count();
            notifications.attention_count += pending;
            notifications.unread_count += pending;
            routes
        }
        Err(err) => return inbox_error_response(err),
    };
    Json(InboxSummaryResponse {
        app: HomeCapsuleIdentity {
            id: INBOX_CAPSULE_ID.to_string(),
            route: "/apps/inbox/".to_string(),
        },
        notifications,
        #[cfg(unix)]
        hosted_routes,
    })
    .into_response()
}

/// Adds the person's open Inbox requests kept outside the Home notification
/// store. Inbox, Home's summary and Home events all read this one list, so a
/// request Inbox shows also counts in Home's badge, raises its notification
/// and changes the Inbox events cursor. Owner hosted decisions come from
/// `owner_hosted_routes`.
pub(super) async fn append_inbox_requests(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    wallet_approvals: Vec<SystemWalletApprovalSummary>,
    notifications: &mut HomeNotificationsSummary,
) {
    // Legacy hosted-route prompts in the store are superseded by the owner's
    // private decisions.
    #[cfg(unix)]
    {
        notifications.entries.retain(|entry| {
            !entry.action_ref.as_ref().is_some_and(|action| {
                action
                    .action_id
                    .starts_with(crate::api::model_provider_egress_decision::APPROVE_PREFIX)
            })
        });
        notifications.unread_count = notifications
            .entries
            .iter()
            .filter(|entry| !entry.read)
            .count();
        notifications.attention_count = notifications
            .entries
            .iter()
            .filter(|entry| entry.severity == "attention")
            .count();
    }
    append_home_service_access_notifications(&state.data_dir, context, notifications);
    if let Some(card) =
        super::gateway_collaboration_presence::community_presence_request_notification(
            state, context,
        )
    {
        notifications.unread_count += 1;
        notifications.attention_count += 1;
        notifications.entries.push(card);
    }
    if let Some(card) = gateway_browser_internet::notification(state, context) {
        notifications.unread_count += usize::from(!card.read);
        notifications.attention_count += usize::from(card.severity == "attention");
        notifications.entries.push(card);
    }
    append_wallet_approval_notifications(notifications, wallet_approvals);
    let (home_asks, agent_asks) = live_pending(&state.data_dir).await;
    if ensure_admin_context(&state.data_dir, context).is_ok() {
        append_runtime_capability_notifications(notifications, home_asks);
    }
    // A Guest, including an admin who was just demoted, sees no agent ask.
    if crate::agents::owner_is_admin_now(&state.data_dir, context.principal_id()).ok() == Some(true)
    {
        append_agent_asks(
            notifications,
            context.principal_id(),
            &owned_agents(&state.data_dir),
            &agent_asks,
        );
    }
    if let Ok(inspect_requests) =
        pending_inspect_action_requests(&state.data_dir, context.principal_id())
    {
        append_inspect_action_notifications(notifications, inspect_requests);
    }
}

/// Test-only: the entries `append_inbox_requests` gives `principal_id` on a
/// Home with no ports, as (id, kind, body).
#[cfg(test)]
pub(crate) async fn inbox_request_entries_for_test(
    data_dir: &std::path::Path,
    principal_id: &str,
    proof_binding_id: Option<&str>,
    kind: crate::auth::PrincipalKind,
) -> Vec<(String, String, String)> {
    let state = GatewayState {
        provider_registry: None,
        collaboration_chat_product_port: None,
        collaboration_presence_product_port: None,
        carrier_endpoint: None,
        collaboration_discovery_service: None,
        browser_internet: Default::default(),
        identity_manager: Arc::new(std::sync::OnceLock::new()),
        cache_dir: data_dir.to_path_buf(),
        data_dir: data_dir.to_path_buf(),
    };
    let context = HomeLaunchTokenContext::for_test(
        principal_id,
        "session:inbox-test",
        proof_binding_id.map(str::to_string),
        "grant:inbox-test",
        kind,
    );
    let mut notifications = HomeNotificationsSummary::default();
    append_inbox_requests(&state, &context, Vec::new(), &mut notifications).await;
    notifications
        .entries
        .into_iter()
        .map(|entry| (entry.id, entry.kind, entry.body))
        .collect()
}

/// Hosted access decisions and their history. They are the owner's alone, so
/// anyone else gets none.
#[cfg(unix)]
pub(super) fn owner_hosted_routes(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
) -> anyhow::Result<Vec<crate::api::model_provider_egress_decision::HostedRouteSummary>> {
    if ensure_admin_context(data_dir, context).is_err() {
        return Ok(Vec::new());
    }
    crate::api::model_provider_egress_decision::inbox_history(data_dir)
}

/// Each pending hosted decision as the owner's Home notification; Inbox
/// answers it with the same approve action.
#[cfg(unix)]
pub(super) fn append_hosted_route_notifications(
    notifications: &mut HomeNotificationsSummary,
    routes: &[crate::api::model_provider_egress_decision::HostedRouteSummary],
) {
    for route in routes.iter().filter(|route| route.is_pending()) {
        let provider = if route.provider.trim().is_empty() {
            "Hosted model"
        } else {
            route.provider.as_str()
        };
        notifications.unread_count += 1;
        notifications.attention_count += 1;
        notifications.entries.push(HomeNotificationEntrySummary {
            id: format!("external-http-request:{}", route.id),
            source_app: INBOX_CAPSULE_ID.to_string(),
            kind: "hosted_route_decision".to_string(),
            title: format!("{provider} access request"),
            body: format!(
                "This Home asks to reach {provider} at {}. Approve or deny it in Inbox.",
                route.origin
            ),
            action_ref: Some(HomeNotificationActionSummary {
                app: INBOX_CAPSULE_ID.to_string(),
                action_id: format!(
                    "{}{}",
                    crate::api::model_provider_egress_decision::APPROVE_PREFIX,
                    route.id
                ),
            }),
            severity: "attention".to_string(),
            read: false,
            created_at: route.requested_at,
            ..Default::default()
        });
    }
}

pub(super) fn append_wallet_approval_notifications(
    notifications: &mut HomeNotificationsSummary,
    approval_requests: Vec<SystemWalletApprovalSummary>,
) {
    for request in approval_requests {
        notifications.unread_count += 1;
        notifications.attention_count += 1;
        let capsule = if request.capsule_id.trim().is_empty() {
            "A capsule".to_string()
        } else {
            request.capsule_id.clone()
        };
        notifications.entries.push(HomeNotificationEntrySummary {
            id: format!("wallet-approval-request:{}", request.request_id),
            source_app: request.capsule_id.clone(),
            kind: "wallet_approval_request".to_string(),
            title: wallet_approval_title(&request.intent),
            body: format!(
                "{} requests wallet approval for {}.",
                capsule, request.reason
            ),
            action_ref: Some(HomeNotificationActionSummary {
                app: WALLET_CAPSULE_ID.to_string(),
                action_id: format!(
                    "{}:{}",
                    if request.intent == "browser_account_access" {
                        "wallet-review-request"
                    } else {
                        "wallet-approve-request"
                    },
                    request.request_id
                ),
            }),
            severity: "attention".to_string(),
            read: false,
            created_at: request.created_at,
            ..Default::default()
        });
    }
}

#[derive(Deserialize)]
struct PendingBody {
    #[serde(default)]
    requests: Vec<RuntimeCapabilityPendingRequest>,
}

struct OwnedAgent {
    id: String,
    name: String,
    root: String,
    owner: String,
}

fn rows_from(
    read: Option<anyhow::Result<Vec<RuntimeCapabilityPendingRequest>>>,
) -> Vec<RuntimeCapabilityPendingRequest> {
    match read {
        Some(Ok(rows)) => rows,
        Some(Err(_)) | None => Vec::new(),
    }
}

pub(super) fn forget_shell_url(api_url: &str) {
    if let Ok(mut map) = shell_cache().lock() {
        map.remove(api_url);
    }
}

fn retain_shell_urls(keep: &[String]) {
    if let Ok(mut map) = shell_cache().lock() {
        map.retain(|url, _| keep.iter().any(|kept| kept == url));
    }
}

fn shell_cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

#[cfg(test)]
pub(in crate::api) static ATTACH_SHELL_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

async fn cached_shell(
    client: &reqwest::Client,
    coords: &crate::runtime_control::RuntimeCoords,
) -> anyhow::Result<String> {
    if let Some(token) = shell_cache()
        .lock()
        .ok()
        .and_then(|map| map.get(&coords.api_url).cloned())
    {
        return Ok(token);
    }
    #[cfg(test)]
    ATTACH_SHELL_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let token = home_attach_shell(client, &coords.api_url, &coords.attach_secret).await?;
    if let Ok(mut map) = shell_cache().lock() {
        map.insert(coords.api_url.clone(), token.clone());
    }
    Ok(token)
}

async fn read_pending(
    coords: &crate::runtime_control::RuntimeCoords,
) -> anyhow::Result<Vec<RuntimeCapabilityPendingRequest>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let mut shell = cached_shell(&client, coords).await?;
    let mut response = client
        .get(format!("{}/api/capability/pending", coords.api_url))
        .header(AUTHORIZATION, format!("Bearer {shell}"))
        .send()
        .await?;
    if response.status() == StatusCode::UNAUTHORIZED {
        if let Ok(mut map) = shell_cache().lock() {
            map.remove(&coords.api_url);
        }
        #[cfg(test)]
        ATTACH_SHELL_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        shell = home_attach_shell(&client, &coords.api_url, &coords.attach_secret).await?;
        if let Ok(mut map) = shell_cache().lock() {
            map.insert(coords.api_url.clone(), shell.clone());
        }
        response = client
            .get(format!("{}/api/capability/pending", coords.api_url))
            .header(AUTHORIZATION, format!("Bearer {shell}"))
            .send()
            .await?;
    }
    Ok(response
        .error_for_status()?
        .json::<PendingBody>()
        .await?
        .requests)
}

async fn live_pending(
    data_dir: &std::path::Path,
) -> (
    Vec<RuntimeCapabilityPendingRequest>,
    Vec<RuntimeCapabilityPendingRequest>,
) {
    let home_coords = load_live_runtime_coords(data_dir).await;
    let agent_coords = crate::api::agent_plane::live_coords(data_dir).await;
    let mut keep = Vec::new();
    if let Some(coords) = &home_coords {
        keep.push(coords.api_url.clone());
    }
    if let Some(coords) = &agent_coords {
        keep.push(coords.api_url.clone());
    }
    retain_shell_urls(&keep);
    let home = rows_from(match home_coords {
        Some(coords) => Some(read_pending(&coords).await),
        None => None,
    });
    let agent = rows_from(match agent_coords {
        Some(coords) => Some(read_pending(&coords).await),
        None => None,
    });
    (home, agent)
}

fn owned_agents(data_dir: &std::path::Path) -> Vec<OwnedAgent> {
    let Ok(state) = crate::auth::load_auth_state(data_dir) else {
        return Vec::new();
    };
    state
        .principals
        .into_iter()
        .filter_map(|record| {
            if record.retired_at.is_some() || record.localhost_root.is_empty() {
                return None;
            }
            let owner = record.owner?;
            let name = if record.display_name.is_empty() {
                record.principal_id.clone()
            } else {
                record.display_name
            };
            Some(OwnedAgent {
                id: record.principal_id,
                name,
                root: record.localhost_root,
                owner,
            })
        })
        .filter(|agent| {
            // An agent that is off is still this owner's. `stored_agent`
            // refuses it; the stop lookup does not, so Inbox does not call
            // the agent someone else's.
            crate::agents::stored_agent_for_stop(data_dir, &agent.owner, &agent.id).is_ok()
        })
        .collect()
}

fn own_rest<'a>(resource: &'a str, root: &str) -> Option<&'a str> {
    let root = root.trim_end_matches('/');
    if resource == root {
        return Some("");
    }
    let rest = resource.strip_prefix(root)?.strip_prefix('/')?;
    if rest.is_empty()
        || rest
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    Some(rest)
}

fn ask_sentence(agent: &OwnedAgent, ask: &RuntimeCapabilityPendingRequest) -> Option<String> {
    let word = match ask.action.as_str() {
        "read" | "write" => ask.action.as_str(),
        _ => "use",
    };
    let place = if ask.resource.starts_with("localhost://") {
        match own_rest(&ask.resource, &agent.root)?.rsplit_once('/') {
            Some((dir, _)) if !dir.is_empty() => format!("{dir} in its own folder"),
            _ => "its own folder".to_string(),
        }
    } else {
        ask.resource.clone()
    };
    let who = if ask.resource.starts_with("elastos://") {
        format!("{} ({})", agent.name, agent.id)
    } else {
        agent.name.clone()
    };
    Some(format!(
        "{who} asks to {word} {place}. It requests {} access to {}.",
        ask.action, ask.resource
    ))
}

fn push_capability_card(
    notifications: &mut HomeNotificationsSummary,
    id: String,
    action: &str,
    body: String,
    action_id: String,
    created_at: u64,
) {
    notifications.unread_count += 1;
    notifications.attention_count += 1;
    notifications.entries.push(HomeNotificationEntrySummary {
        id,
        source_app: SYSTEM_CAPSULE_ID.to_string(),
        kind: "capability_request".to_string(),
        title: capability_request_title(action),
        body,
        action_ref: Some(HomeNotificationActionSummary {
            app: SYSTEM_CAPSULE_ID.to_string(),
            action_id,
        }),
        severity: "attention".to_string(),
        read: false,
        created_at,
        ..Default::default()
    });
}

fn append_agent_asks(
    notifications: &mut HomeNotificationsSummary,
    caller: &str,
    agents: &[OwnedAgent],
    asks: &[RuntimeCapabilityPendingRequest],
) {
    for ask in asks {
        let Some(agent) = agents
            .iter()
            .find(|agent| agent.id == ask.agent_id && agent.owner == caller)
        else {
            continue;
        };
        let Some(body) = ask_sentence(agent, ask) else {
            continue;
        };
        push_capability_card(
            notifications,
            format!("capability-request:agent:{}", ask.request_id),
            &ask.action,
            body,
            format!("capability-approve-request:agent:{}", ask.request_id),
            ask.requested_at,
        );
    }
}

fn not_owner(caller: &str, name: &str) -> String {
    format!("{caller} belongs to a different principal and does not own {name}")
}

fn capability_decision(action_id: &str) -> Option<(&str, bool)> {
    if let Some(id) = action_id.strip_prefix("capability-approve-request:") {
        return Some((id, true));
    }
    action_id
        .strip_prefix("capability-deny-request:")
        .map(|id| (id, false))
}

pub(super) fn append_runtime_capability_notifications(
    notifications: &mut HomeNotificationsSummary,
    capability_requests: Vec<RuntimeCapabilityPendingRequest>,
) {
    for request in capability_requests {
        push_capability_card(
            notifications,
            format!("capability-request:{}", request.request_id),
            &request.action,
            format!(
                "A capsule requests {} access to {}.",
                request.action, request.resource
            ),
            format!("capability-approve-request:{}", request.request_id),
            request.requested_at,
        );
    }
}

fn capability_request_title(action: &str) -> String {
    match action {
        "read" => "Read access request".to_string(),
        "write" => "Write access request".to_string(),
        "execute" => "Execute access request".to_string(),
        "delete" => "Delete access request".to_string(),
        "message" => "Message access request".to_string(),
        "admin" => "Admin access request".to_string(),
        _ => "Capability request".to_string(),
    }
}

fn wallet_approval_title(intent: &str) -> String {
    match intent {
        "auth_challenge" => "Wallet sign-in request".to_string(),
        "capability_grant" => "Wallet access request".to_string(),
        "credential" => "Credential signing request".to_string(),
        "publish_envelope" => "Publish approval request".to_string(),
        "transaction_intent" => "Transaction approval request".to_string(),
        "browser_account_access" => "Browser account access request".to_string(),
        "browser_personal_sign" => "Browser signature request".to_string(),
        "browser_typed_data_sign" => "Browser typed data signature request".to_string(),
        "bitcoin_bip322_proof" => "Bitcoin proof request".to_string(),
        "revocation" => "Revocation approval request".to_string(),
        _ => "Wallet approval request".to_string(),
    }
}

pub(super) async fn inbox_action(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let launch =
        match require_home_launch_token_binding(&state.data_dir, &headers, &[INBOX_CAPSULE_ID]) {
            Ok(launch) => launch,
            Err(err) => return inbox_error_response(err),
        };
    let authority = match runtime_wallet_authority(&state.data_dir, &launch) {
        Ok(authority) => authority,
        Err(err) => return inbox_error_response(err),
    };
    let context = launch.context.clone();

    let action = match parse_inbox_action_request(&headers, &body).map_err(anyhow::Error::msg) {
        Ok(req) => req,
        Err(err) => return inbox_error_response(err),
    };
    if action.action_id.starts_with("room-approve-request:")
        || action.action_id.starts_with("room-deny-request:")
    {
        if state.collaboration_chat_product_port.is_some() {
            return super::gateway_room::configured_legacy_room_control_unsupported_response();
        }
        if let Err(error) = ensure_admin_context(&state.data_dir, &context) {
            return inbox_error_response(error);
        }
    }
    if capability_decision(&action.action_id).is_some_and(|(id, _)| {
        id.strip_prefix("agent:")
            .filter(|rest| !rest.is_empty())
            .is_none()
    }) {
        if let Err(error) = ensure_admin_context(&state.data_dir, &context) {
            return inbox_error_response(error);
        }
    }
    match dispatch_inbox_action(&state, &launch, &context, &authority, &action).await {
        Ok(message) => {
            let result = inspect_action_request_id_from_action(&action.action_id)
                .map(|id| inspect_action_result_receipt(&state.data_dir, id))
                .transpose();
            match result {
                Ok(result) => Json(InboxActionResponse { message, result }).into_response(),
                Err(err) => inbox_error_response(err),
            }
        }
        Err(err) => inbox_error_response(err),
    }
}

fn inspect_action_request_id_from_action(action_id: &str) -> Option<&str> {
    action_id
        .strip_prefix("inspect-approve-request:")
        .or_else(|| action_id.strip_prefix("inspect-deny-request:"))
}

fn parse_inbox_action_request(
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<InboxActionRequest, String> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if content_type.starts_with("application/json") {
        serde_json::from_slice(body).map_err(|err| format!("invalid inbox action body: {err}"))
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        let action_id = form_urlencoded::parse(body.as_ref())
            .find_map(|(key, value)| (key == "action_id").then(|| value.into_owned()))
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "missing action_id".to_string())?;
        Ok(InboxActionRequest {
            action_id,
            step_up_token: None,
            request_binding: None,
        })
    } else {
        Err("unsupported inbox action content type".to_string())
    }
}

async fn dispatch_inbox_action(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    context: &HomeLaunchTokenContext,
    authority: &RuntimeWalletAuthority,
    action: &InboxActionRequest,
) -> anyhow::Result<String> {
    let action_id = action.action_id.as_str();
    if action_id.starts_with("browser-internet-") {
        return gateway_browser_internet::answer(
            state,
            launch,
            action_id,
            action.step_up_token.as_deref(),
        )
        .await;
    }
    let data_dir = &state.data_dir;
    // Entries one account owns, such as its direct messages, change only for
    // that account.
    let viewer = super::gateway_home_system::load_profile_authority_for_context(data_dir, context)?
        .map(|profile| profile.document().profile_did.clone());
    if let Some(notification_id) = action_id.strip_prefix("notification-read:") {
        return Ok(
            match crate::notifications::mark_read(data_dir, viewer.as_deref(), notification_id)? {
                true => "Marked inbox entry read.".to_string(),
                false => "That inbox entry was already read or is no longer present.".to_string(),
            },
        );
    }
    if let Some(notification_id) = action_id.strip_prefix("notification-dismiss:") {
        return Ok(
            match crate::notifications::dismiss(data_dir, viewer.as_deref(), notification_id)? {
                true => "Dismissed inbox entry.".to_string(),
                false => "That inbox entry is already gone.".to_string(),
            },
        );
    }
    if let Some(answer) = super::gateway_collaboration_presence::answer_community_presence_request(
        state, context, action_id,
    )
    .await
    {
        return answer;
    }
    if let Some(request_hash) = action_id.strip_prefix("contact-accept-request:") {
        return decide_contact_request(
            state,
            context,
            request_hash,
            crate::collaboration_discovery::CollaborationContactDecision::Accepted,
        )
        .await;
    }
    if let Some(request_hash) = action_id.strip_prefix("contact-decline-request:") {
        return decide_contact_request(
            state,
            context,
            request_hash,
            crate::collaboration_discovery::CollaborationContactDecision::Declined,
        )
        .await;
    }
    if let Some(request_id) = action_id.strip_prefix("room-approve-request:") {
        let message = match crate::room_service::approve_request(data_dir, request_id)? {
            Some(outcome) => format!(
                "Approved Chat web guest request for {} on {}.",
                outcome.display_name, outcome.device_label
            ),
            None => "That web guest request is no longer pending.".to_string(),
        };
        let summary = crate::room_service::load_summary(data_dir)?;
        let _ = crate::notifications::sync_room_notifications(data_dir, &summary);
        let _ = crate::notifications::mark_acted_for_action(data_dir, None, action_id);
        return Ok(message);
    }
    if let Some(request_id) = action_id.strip_prefix("room-deny-request:") {
        let message =
            match crate::room_service::deny_request(data_dir, request_id, "Denied from Inbox.")? {
                Some(outcome) => format!(
                    "Denied Chat web guest request for {} on {}.",
                    outcome.display_name, outcome.device_label
                ),
                None => "That web guest request is no longer pending.".to_string(),
            };
        let summary = crate::room_service::load_summary(data_dir)?;
        let _ = crate::notifications::sync_room_notifications(data_dir, &summary);
        let _ = crate::notifications::mark_acted_for_action(data_dir, None, action_id);
        return Ok(message);
    }
    if let Some(request_id) = action_id.strip_prefix("wallet-approve-request:") {
        let pending = pending_wallet_approval_request(state, authority, request_id).await?;
        if pending.intent == "browser_account_access" {
            anyhow::bail!("Review Browser account access in Wallet before allowing it");
        }
        let Some(step_up_token) = action.step_up_token.as_deref() else {
            anyhow::bail!("fresh passkey verification is required to sign with a built-in wallet");
        };
        consume_passkey_step_up_token(
            data_dir,
            step_up_token,
            launch,
            180,
            "wallet.approve",
            &serde_json::json!({
                "request_id": request_id,
                "reason": "Approved in Inbox",
            }),
        )?;
        let outcome = approve_pending_managed_wallet_request(
            state,
            data_dir,
            context,
            authority,
            pending,
            "Approved in Inbox",
            INBOX_CAPSULE_ID,
        )
        .await?;
        let _ = crate::notifications::mark_acted_for_action(data_dir, None, action_id);
        return Ok(outcome.message);
    }
    if let Some(request_id) = action_id.strip_prefix("wallet-reject-request:") {
        runtime_wallet_data(
            state,
            authority,
            elastos_wallet_contract::WalletProviderOperationV2::RejectApproval {
                request_id: request_id.to_string(),
                reason: "Rejected in Inbox".to_string(),
            },
        )
        .await?;
        append_wallet_approval_audit(
            data_dir,
            WalletApprovalAuditInput {
                capsule_id: INBOX_CAPSULE_ID,
                event_type: "wallet.approval.rejected",
                principal_id: context.principal_id(),
                session_id: context.session_id(),
                request_id,
                result: "rejected",
                reason: "Wallet approval rejected through Runtime authority",
            },
        )?;
        return Ok("Rejected wallet request.".to_string());
    }
    if let Some((request_id, approve)) = capability_decision(action_id) {
        if let Some(id) = request_id
            .strip_prefix("agent:")
            .filter(|id| !id.is_empty())
        {
            return answer_agent_ask(data_dir, context.principal_id(), id, approve).await;
        }
        return match approve {
            true => approve_runtime_capability_request(data_dir, request_id).await,
            false => deny_runtime_capability_request(data_dir, request_id).await,
        };
    }
    if let Some(request_id) = action_id.strip_prefix("service-approve-request:") {
        let discovery_service = state.collaboration_discovery_service.clone();
        let provider_registry = state.provider_registry.clone();
        let data_dir = data_dir.clone();
        let context = context.clone();
        let request_id = request_id.to_string();
        return tokio::task::spawn_blocking(move || {
            approve_home_service_access_request(
                &data_dir,
                &context,
                provider_registry.as_deref(),
                discovery_service.as_ref(),
                &request_id,
            )
        })
        .await
        .map_err(|err| anyhow::anyhow!(err))?;
    }
    if let Some(request_id) = action_id.strip_prefix("service-deny-request:") {
        return super::deny_model_grant_and_settle(
            state.provider_registry.clone(),
            data_dir,
            context,
            state.collaboration_discovery_service.as_ref(),
            request_id,
        )
        .await;
    }
    if let Some(request_id) = action_id.strip_prefix("agent-plan-deny-request:") {
        return super::gateway_inspect_actions::deny_agent_plan_request(
            data_dir,
            context.principal_id(),
            request_id,
        );
    }
    if let Some(request_id) = action_id.strip_prefix("agent-plan-approve-request:") {
        if state.provider_registry.is_none() {
            anyhow::bail!("agent plan provider registry unavailable");
        }
        let card = action
            .request_binding
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("agent plan approval requires the card binding"))?;
        super::gateway_inspect_actions::approve_agent_plan_request(
            state,
            launch,
            context,
            request_id,
            card,
            action.step_up_token.as_deref(),
        )?;
        return super::gateway_inspect_actions::dispatch_approved_agent_plan(
            state, context, request_id,
        )
        .await;
    }
    if let Some(request_id) = action_id.strip_prefix("inspect-approve-request:") {
        let Some(step_up_token) = action.step_up_token.as_deref() else {
            anyhow::bail!("fresh passkey verification is required to approve an Inspector action");
        };
        return approve_inspect_action_request(state, launch, context, request_id, step_up_token)
            .await;
    }
    if let Some(request_id) = action_id.strip_prefix("inspect-deny-request:") {
        return deny_inspect_action_request(state, context, request_id);
    }
    if action_id == WALLET_PRICE_HTTP_APPROVE_ACTION_ID {
        ensure_admin_context(data_dir, context)?;
        let approved_at = now_ts();
        store_wallet_price_http_policy(data_dir, context.principal_id(), approved_at)?;
        let _ = crate::notifications::mark_acted_for_action(data_dir, None, action_id);
        append_wallet_price_policy_audit(
            data_dir,
            context.principal_id(),
            context.session_id(),
            "approved",
            "Approved Wallet market-price HTTP source through Inbox",
        )?;
        return Ok("Approved Wallet market-price source.".to_string());
    }
    if action_id.strip_prefix(WALLET_PRICE_HTTP_DENY_ACTION_PREFIX) == Some("coingecko") {
        let _ = crate::notifications::dismiss_external_http_request(
            data_dir,
            WALLET_PRICE_HTTP_REQUEST_ID,
        );
        append_wallet_price_policy_audit(
            data_dir,
            context.principal_id(),
            context.session_id(),
            "rejected",
            "Rejected Wallet market-price HTTP source through Inbox",
        )?;
        return Ok("Rejected Wallet market-price source.".to_string());
    }
    #[cfg(unix)]
    if let Some(request_id) =
        action_id.strip_prefix(crate::api::model_provider_egress_decision::END_PREFIX)
    {
        ensure_admin_context(data_dir, context)?;
        let proof = context
            .proof_binding_id()
            .ok_or_else(|| anyhow::anyhow!("admin passkey required"))?;
        let _decision = crate::api::model_provider_egress_decision::transition_gate(data_dir)
            .lock_owned()
            .await;
        let _offer_id = crate::api::model_provider_egress_decision::endable_decision_offer_id(
            data_dir, request_id, proof,
        )?;
        crate::api::model_provider_egress_decision::end_decision(data_dir, request_id, proof)?;
        #[cfg(unix)]
        let _end =
            crate::api::hosted_egress_admission::begin_hosted_end(data_dir, &_offer_id).await;
        let _ = crate::notifications::dismiss_external_http_request(data_dir, request_id);
        return Ok(
            "Ended this hosted access. A later request needs a new Inbox decision.".to_string(),
        );
    }
    #[cfg(unix)]
    if let Some(request_id) =
        action_id.strip_prefix(crate::api::model_provider_egress_decision::APPROVE_PREFIX)
    {
        ensure_admin_context(data_dir, context)?;
        let proof = context
            .proof_binding_id()
            .ok_or_else(|| anyhow::anyhow!("admin passkey required"))?;
        let _decision = crate::api::model_provider_egress_decision::transition_gate(data_dir)
            .lock_owned()
            .await;
        crate::api::model_provider_egress_decision::approve(data_dir, request_id, proof)?;
        let _ = crate::notifications::mark_acted_for_action(data_dir, None, action_id);
        return Ok(
            "Approved this hosted access. End it in Inbox when it is no longer needed.".to_string(),
        );
    }
    #[cfg(unix)]
    if let Some(request_id) =
        action_id.strip_prefix(crate::api::model_provider_egress_decision::DENY_PREFIX)
    {
        ensure_admin_context(data_dir, context)?;
        let proof = context
            .proof_binding_id()
            .ok_or_else(|| anyhow::anyhow!("admin passkey required"))?;
        let _decision = crate::api::model_provider_egress_decision::transition_gate(data_dir)
            .lock_owned()
            .await;
        crate::api::model_provider_egress_decision::deny(data_dir, request_id, proof)?;
        let _ = crate::notifications::dismiss_external_http_request(data_dir, request_id);
        return Ok("Denied this hosted access.".to_string());
    }
    if let Some(request_id) =
        action_id.strip_prefix(crate::jev_approval_lens::HOSTED_HTTP_APPROVE_PREFIX)
    {
        ensure_admin_context(data_dir, context)?;
        crate::jev_approval_lens::record_human_decision(data_dir, request_id, "approve")?;
        let _ = crate::notifications::mark_acted_for_action(data_dir, None, action_id);
        return Ok(
            "Recorded your approval. Runtime still asks in Inbox before anything is sent."
                .to_string(),
        );
    }
    if let Some(request_id) =
        action_id.strip_prefix(crate::jev_approval_lens::HOSTED_HTTP_DENY_PREFIX)
    {
        ensure_admin_context(data_dir, context)?;
        crate::jev_approval_lens::record_human_decision(data_dir, request_id, "deny")?;
        let _ = crate::notifications::dismiss_external_http_request(data_dir, request_id);
        return Ok("Denied this hosted connection.".to_string());
    }
    anyhow::bail!("unknown inbox action");
}

async fn decide_contact_request(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    request_hash: &str,
    decision: crate::collaboration_discovery::CollaborationContactDecision,
) -> anyhow::Result<String> {
    let request_hash = request_hash.trim();
    if request_hash.is_empty() {
        anyhow::bail!("contact request is missing");
    }
    let service = state
        .collaboration_discovery_service
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("contact decisions are not available on this Home"))?;
    let authority = super::gateway_home_system::load_configured_contact_authority_for_context(
        &state.data_dir,
        context,
        Some(service),
    )?
    .ok_or_else(|| anyhow::anyhow!("save your Profile before deciding contact requests"))?;
    super::gateway_home_system::register_configured_contact_sync_for_context(
        service,
        context,
        &authority,
        now_ts(),
    )?;
    service
        .submit_contact_decision(
            authority.store.as_ref(),
            &authority.profile,
            request_hash,
            decision,
            now_ts(),
        )
        .await?;
    service.wake_registered_sync(authority.store.as_ref(), &authority.profile, now_ts())?;
    Ok(match decision {
        crate::collaboration_discovery::CollaborationContactDecision::Accepted => {
            "Contact added.".to_string()
        }
        crate::collaboration_discovery::CollaborationContactDecision::Declined => {
            "Request declined.".to_string()
        }
    })
}

#[derive(Debug)]
struct PlaneStatus {
    code: u16,
    message: String,
}

impl std::fmt::Display for PlaneStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = self.code;
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PlaneStatus {}

async fn decide_capability(
    coords: &crate::runtime_control::RuntimeCoords,
    request_id: &str,
    approve: bool,
) -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;
    let shell = home_attach_shell(&client, &coords.api_url, &coords.attach_secret).await?;
    let (path, body, done) = if approve {
        (
            "grant",
            serde_json::json!({
                "request_id": request_id,
                "duration": "session",
                "rationale": "Approved in Inbox",
            }),
            "Approved.",
        )
    } else {
        (
            "deny",
            serde_json::json!({"request_id": request_id, "reason": "Denied in Inbox"}),
            "Denied.",
        )
    };
    let response = client
        .post(format!("{}/api/capability/{path}", coords.api_url))
        .header(AUTHORIZATION, format!("Bearer {shell}"))
        .json(&body)
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let message = if text.trim().is_empty() {
            status.to_string()
        } else {
            text
        };
        return Err(anyhow::Error::new(PlaneStatus {
            code: status.as_u16(),
            message,
        }));
    }
    Ok(done.to_string())
}

pub(super) async fn approve_runtime_capability_request(
    data_dir: &std::path::Path,
    request_id: &str,
) -> anyhow::Result<String> {
    let coords = load_live_runtime_coords(data_dir)
        .await
        .ok_or_else(|| anyhow::anyhow!("local runtime is not running"))?;
    decide_capability(&coords, request_id, true).await
}

pub(super) async fn deny_runtime_capability_request(
    data_dir: &std::path::Path,
    request_id: &str,
) -> anyhow::Result<String> {
    let coords = load_live_runtime_coords(data_dir)
        .await
        .ok_or_else(|| anyhow::anyhow!("local runtime is not running"))?;
    decide_capability(&coords, request_id, false).await
}

async fn answer_agent_ask(
    data_dir: &std::path::Path,
    caller: &str,
    request_id: &str,
    approve: bool,
) -> anyhow::Result<String> {
    let coords = crate::api::agent_plane::live_coords(data_dir)
        .await
        .ok_or_else(|| anyhow::anyhow!("agent runtime is not running"))?;
    let pending = read_pending(&coords).await?;
    let Some(ask) = pending.iter().find(|row| row.request_id == request_id) else {
        let person = crate::auth::stored_principal_record(data_dir, caller)
            .ok()
            .flatten()
            .is_some_and(|record| record.kind == crate::auth::PrincipalKind::Human);
        if person && !crate::agents::owner_is_admin_now(data_dir, caller)? {
            anyhow::bail!(crate::agents::OWNER_NOT_ADMIN);
        }
        anyhow::bail!("that request is no longer pending");
    };
    if ask.agent_id.is_empty() {
        anyhow::bail!("the asking session has ended");
    }
    let agents = owned_agents(data_dir);
    let Some(agent) = agents.iter().find(|agent| agent.id == ask.agent_id) else {
        anyhow::bail!("{}", not_owner(caller, "this agent"));
    };
    if agent.owner != caller {
        anyhow::bail!("{}", not_owner(caller, &agent.name));
    }
    if !crate::agents::owner_is_admin_now(data_dir, caller)? {
        anyhow::bail!(crate::agents::OWNER_NOT_ADMIN);
    }
    if let Err(error) = crate::agents::stored_agent(data_dir, caller, &ask.agent_id) {
        let _ = sign_agent_grant(data_dir, caller, ask, request_id, "denied", "denied");
        let _ = decide_capability(&coords, request_id, false).await;
        return Err(error);
    }
    if ask.resource.starts_with("localhost://") && own_rest(&ask.resource, &agent.root).is_none() {
        sign_agent_grant(data_dir, caller, ask, request_id, "denied", "denied")
            .map_err(|error| super::inbox_audit_refusal(error, "Deny this ask again."))?;
        decide_capability(&coords, request_id, false).await?;
        anyhow::bail!("a path outside the agent's own folder is not pending");
    }
    // One answer at a time, so two approvals of one ask mint one grant.
    #[cfg(test)]
    super::gateway_tests::seams::pause_before_answer_gate(data_dir).await;
    let _gate = grant_answer_gate().lock().await;
    // A demotion commits under this gate, so the role read here holds until the grant.
    if !crate::agents::owner_is_admin_now(data_dir, caller)? {
        anyhow::bail!(crate::agents::OWNER_NOT_ADMIN);
    }
    if !approve {
        sign_agent_grant(data_dir, caller, ask, request_id, "denied", "denied")
            .map_err(|error| super::inbox_audit_refusal(error, "Deny this ask again."))?;
        return decide_capability(&coords, request_id, false).await;
    }
    let again = read_pending(&coords).await?;
    let Some(row) = again.iter().find(|item| item.request_id == request_id) else {
        anyhow::bail!("not_granted: the grant was already given");
    };
    // The signed approval exists before the mint. A crash before the send
    // leaves that row and no grant. `sent` is the marker that the request
    // left this process. After that marker, a crash, a timeout, or a failed
    // minted row is unresolved. `not_granted` is only a refusal the plane
    // answered before any mint.
    sign_agent_grant(data_dir, caller, row, request_id, "approved", "approved")
        .map_err(|error| super::inbox_audit_refusal(error, "Approve this ask again."))?;
    #[cfg(test)]
    if super::gateway_tests::seams::take_grant_kind(data_dir, "before-send") {
        anyhow::bail!("crash before the send");
    }
    sign_agent_grant(data_dir, caller, row, request_id, "sent", "sent").map_err(|error| {
        super::inbox_audit_refusal(error, "This approval is settled the next time Home starts.")
    })?;
    #[cfg(test)]
    if super::gateway_tests::seams::grant_kind_is(data_dir, "timeout") {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()?;
        let shell = cached_shell(&client, &coords).await?;
        let hurried = reqwest::Client::builder()
            .timeout(Duration::from_millis(40))
            .build()?;
        let _ = hurried
            .post(format!("{}/api/capability/grant", coords.api_url))
            .header(AUTHORIZATION, format!("Bearer {shell}"))
            .json(&serde_json::json!({
                "request_id": request_id,
                "duration": "session",
                "rationale": "Approved in Inbox",
            }))
            .send()
            .await;
        let _ = sign_agent_grant(
            data_dir,
            caller,
            row,
            request_id,
            "unresolved",
            "the plane timed out",
        );
        anyhow::bail!("the plane timed out");
    }
    match decide_capability(&coords, request_id, true).await {
        Err(error) if plane_refused(&error) => {
            revoke_capability(&coords, request_id).await;
            let _ = sign_agent_grant(
                data_dir,
                caller,
                row,
                request_id,
                "not_granted",
                "not_granted",
            );
            Err(error)
        }
        Ok(answered) => {
            #[cfg(test)]
            if super::gateway_tests::seams::take_grant_kind(data_dir, "after-mint") {
                anyhow::bail!("crash after the mint");
            }
            match sign_agent_grant(data_dir, caller, row, request_id, "minted", "minted") {
                Ok(()) => Ok(answered),
                Err(error) => {
                    let _ = sign_agent_grant(
                        data_dir,
                        caller,
                        row,
                        request_id,
                        "unresolved",
                        "the minted row failed",
                    );
                    Err(error)
                }
            }
        }
        Err(error) => {
            let _ = sign_agent_grant(
                data_dir,
                caller,
                row,
                request_id,
                "unresolved",
                "the request was sent and the mint was not recorded",
            );
            Err(error)
        }
    }
}

pub(in crate::api) fn grant_answer_gate() -> &'static tokio::sync::Mutex<()> {
    static GATE: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(test)]
fn plane_conflict(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<PlaneStatus>()
        .is_some_and(|status| status.code == 409)
}

fn plane_refused(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<PlaneStatus>()
        .is_some_and(|status| (400..500).contains(&status.code))
}

fn grant_reason(caller: &str, ask: &RuntimeCapabilityPendingRequest, cause: &str) -> String {
    serde_json::json!({
        "cause": cause,
        "principal": caller,
        "session": ask.session_id,
        "agent": ask.agent_id,
        "capsule": ask.agent_id,
        "resource": ask.resource,
    })
    .to_string()
}

fn sign_agent_grant(
    data_dir: &std::path::Path,
    caller: &str,
    ask: &RuntimeCapabilityPendingRequest,
    request_id: &str,
    kind: &str,
    cause: &str,
) -> anyhow::Result<()> {
    #[cfg(test)]
    if kind == "minted" && super::gateway_tests::seams::take_grant_kind(data_dir, "minted-row") {
        anyhow::bail!("the minted row failed");
    }
    #[cfg(test)]
    if kind == "sent" && super::gateway_tests::seams::take_grant_kind(data_dir, "sent") {
        anyhow::bail!("injected agent grant audit failure");
    }
    #[cfg(test)]
    if super::gateway_tests::seams::take_grant_fault(data_dir, false) {
        anyhow::bail!("injected agent grant audit failure");
    }
    crate::auth::append_audit_event(
        data_dir,
        elastos_runtime::auth::RuntimeAuditEventV1 {
            schema: elastos_runtime::auth::RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: format!("audit:{}", super::gateway_home_token::uuid_like_token()),
            event_type: format!("agent.grant.{kind}"),
            principal_id: Some(caller.to_string()),
            proof_binding_id: None,
            session_id: Some(ask.session_id.clone()),
            challenge_id: Some(request_id.to_string()),
            capsule_id: Some(ask.agent_id.clone()),
            result: kind.to_string(),
            reason: grant_reason(caller, ask, cause),
            occurred_at: now_ts(),
            signer_did: None,
            signature: None,
        },
    )
}

async fn revoke_capability(coords: &crate::runtime_control::RuntimeCoords, request_id: &str) {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    else {
        return;
    };
    let Ok(shell) = home_attach_shell(&client, &coords.api_url, &coords.attach_secret).await else {
        return;
    };
    let url = format!("{}/api/capability/{request_id}", coords.api_url);
    let _ = client
        .delete(url)
        .header(AUTHORIZATION, format!("Bearer {shell}"))
        .send()
        .await;
}

fn copied_grant(
    event: &elastos_runtime::auth::RuntimeAuditEventV1,
) -> (String, RuntimeCapabilityPendingRequest) {
    let mut principal = event.principal_id.clone().unwrap_or_default();
    let mut ask = RuntimeCapabilityPendingRequest {
        request_id: event.challenge_id.clone().unwrap_or_default(),
        agent_id: event.capsule_id.clone().unwrap_or_default(),
        session_id: event.session_id.clone().unwrap_or_default(),
        resource: String::new(),
        ..Default::default()
    };
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&event.reason) {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        if !text("principal").is_empty() {
            principal = text("principal");
        }
        if !text("session").is_empty() {
            ask.session_id = text("session");
        }
        if !text("agent").is_empty() {
            ask.agent_id = text("agent");
        }
        if ask.agent_id.is_empty() && !text("capsule").is_empty() {
            ask.agent_id = text("capsule");
        }
        if !text("resource").is_empty() {
            ask.resource = text("resource");
        }
    }
    if ask.resource.is_empty() {
        ask.resource = event.reason.clone();
    }
    (principal, ask)
}

async fn grant_was_minted(data_dir: &std::path::Path, request_id: &str) -> bool {
    let Some(runtime) = crate::api::agent_plane::plane_runtime(data_dir) else {
        return false;
    };
    let Some((store, _, _)) = runtime.instance_authority_plane() else {
        return false;
    };
    store
        .get_request(request_id)
        .await
        .is_some_and(|request| request.is_granted())
}

/// An approved row with no later close is settled once. No `sent` marker means
/// the request never left, so the close is `not_sent`. A `sent` marker means
/// the request left: `crash after the mint` when the grant is still live, and
/// otherwise that the mint was not recorded. The close copies the approved
/// row's principal, session, agent, capsule, and resource.
pub(crate) async fn settle_unminted_agent_grants(data_dir: &std::path::Path) -> anyhow::Result<()> {
    let state = crate::auth::load_auth_state(data_dir)?;
    let mut open = Vec::new();
    let mut sent = std::collections::HashSet::new();
    for event in &state.audit {
        let Some(id) = event.challenge_id.clone() else {
            continue;
        };
        match event.event_type.as_str() {
            "agent.grant.not_granted"
            | "agent.grant.minted"
            | "agent.grant.unresolved"
            | "agent.grant.not_sent" => {
                open.retain(|row: &elastos_runtime::auth::RuntimeAuditEventV1| {
                    row.challenge_id.as_deref() != Some(id.as_str())
                });
                sent.remove(&id);
            }
            "agent.grant.sent" => {
                sent.insert(id);
            }
            "agent.grant.approved"
                if open
                    .iter()
                    .all(|row| row.challenge_id.as_deref() != Some(id.as_str())) =>
            {
                open.push(event.clone());
            }
            _ => {}
        }
    }
    for event in &open {
        let id = event.challenge_id.clone().unwrap_or_default();
        let (principal, ask) = copied_grant(event);
        let (kind, cause) = if sent.contains(&id) {
            if grant_was_minted(data_dir, &id).await {
                ("unresolved", "crash after the mint")
            } else {
                (
                    "unresolved",
                    "the request was sent and the mint was not recorded",
                )
            }
        } else {
            ("not_sent", "crash before the send")
        };
        if let Err(error) = sign_agent_grant(data_dir, &principal, &ask, &id, kind, cause) {
            eprintln!("[gateway] grant settle skipped for {id}: {error:#}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(owner: &str) -> OwnedAgent {
        OwnedAgent {
            id: "agent-1".into(),
            name: "Notes".into(),
            root: "localhost://UsersAI/notes".into(),
            owner: owner.into(),
        }
    }

    fn ask(resource: &str, action: &str) -> RuntimeCapabilityPendingRequest {
        RuntimeCapabilityPendingRequest {
            request_id: "req-1".into(),
            agent_id: "agent-1".into(),
            session_id: "session-1".into(),
            resource: resource.into(),
            action: action.into(),
            requested_at: 1,
        }
    }

    #[tokio::test]
    async fn a_second_inbox_poll_does_not_attach_again() {
        let url = "http://127.0.0.1:9/planted-inbox-poll";
        let coords = crate::runtime_control::RuntimeCoords {
            api_url: url.to_string(),
            attach_secret: "secret".to_string(),
            pid: 1,
            runtime_kind: "agent".to_string(),
            binary_sha256: String::new(),
            policy_sha256: String::new(),
            dependency_sha256: String::new(),
            generation: String::new(),
            process_start: String::new(),
            home_url: String::new(),
        };
        shell_cache()
            .lock()
            .unwrap()
            .insert(url.to_string(), "bearer-once".to_string());
        let before = ATTACH_SHELL_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        let client = reqwest::Client::new();
        let first = cached_shell(&client, &coords).await.unwrap();
        let second = cached_shell(&client, &coords).await.unwrap();
        assert_eq!(first, "bearer-once");
        assert_eq!(second, "bearer-once");
        assert_eq!(
            ATTACH_SHELL_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            before,
            "a cached shell is not another attach"
        );
        shell_cache().lock().unwrap().remove(url);
    }

    #[test]
    fn forgetting_a_plane_url_drops_only_that_shell() {
        let kept = "http://127.0.0.1:9/kept-shell";
        let gone = "http://127.0.0.1:9/gone-shell";
        shell_cache()
            .lock()
            .unwrap()
            .insert(kept.to_string(), "keep".to_string());
        shell_cache()
            .lock()
            .unwrap()
            .insert(gone.to_string(), "drop".to_string());
        forget_shell_url(gone);
        let map = shell_cache().lock().unwrap();
        assert_eq!(map.get(kept).map(String::as_str), Some("keep"));
        assert!(map.get(gone).is_none());
        drop(map);
        shell_cache().lock().unwrap().remove(kept);
    }

    #[test]
    fn a_restarted_home_url_drops_the_old_shell() {
        let old_home = "http://127.0.0.1:9/old-home";
        let plane = "http://127.0.0.1:9/plane";
        shell_cache()
            .lock()
            .unwrap()
            .insert(old_home.to_string(), "stale".to_string());
        shell_cache()
            .lock()
            .unwrap()
            .insert(plane.to_string(), "keep".to_string());
        retain_shell_urls(&["http://127.0.0.1:9/new-home".into(), plane.to_string()]);
        let map = shell_cache().lock().unwrap();
        assert!(map.get(old_home).is_none(), "{map:?}");
        assert_eq!(map.get(plane).map(String::as_str), Some("keep"));
        drop(map);
        shell_cache().lock().unwrap().remove(plane);
    }

    #[test]
    fn the_card_names_the_agent_its_folder_and_the_runtime() {
        let body = ask_sentence(
            &agent("owner-a"),
            &ask("localhost://UsersAI/notes/.AppData/journal", "write"),
        )
        .unwrap();
        assert!(body.starts_with("Notes asks to write "), "{body}");
        assert!(body.contains(".AppData in its own folder"), "{body}");
        assert!(
            body.contains("access to localhost://UsersAI/notes/.AppData/journal."),
            "{body}"
        );
        let mut notes = HomeNotificationsSummary::default();
        append_agent_asks(
            &mut notes,
            "owner-a",
            &[agent("owner-a")],
            &[ask("localhost://UsersAI/notes/.AppData/journal", "read")],
        );
        let entry = &notes.entries[0];
        assert!(entry.id.contains(":agent:"), "{}", entry.id);
        assert_eq!(
            entry.action_ref.as_ref().unwrap().action_id,
            "capability-approve-request:agent:req-1"
        );
    }

    #[test]
    fn another_owner_sees_nothing_and_is_refused_by_name() {
        let mut notes = HomeNotificationsSummary::default();
        append_agent_asks(
            &mut notes,
            "owner-b",
            &[agent("owner-a")],
            &[ask("localhost://UsersAI/notes/.AppData/journal", "read")],
        );
        assert!(notes.entries.is_empty());
        let text = not_owner("owner-b", "Notes");
        assert!(text.contains("owner-b"), "{text}");
        assert!(text.contains("Notes"), "{text}");
        assert!(text.contains("belongs to a different principal"), "{text}");
    }

    #[test]
    fn a_path_outside_the_agents_root_is_not_approvable() {
        let outside = ask("localhost://UsersAI/other/secret", "read");
        assert!(ask_sentence(&agent("owner-a"), &outside).is_none());
        let mut notes = HomeNotificationsSummary::default();
        append_agent_asks(&mut notes, "owner-a", &[agent("owner-a")], &[outside]);
        assert!(notes.entries.is_empty());
        assert!(ask_sentence(
            &agent("owner-a"),
            &ask("localhost://UsersAI/notes-evil/file", "read")
        )
        .is_none());
        assert!(ask_sentence(
            &agent("owner-a"),
            &ask("localhost://UsersAI/notes/../other/file", "write")
        )
        .is_none());
    }

    #[test]
    fn an_elastos_ask_stays_approvable_for_its_owner() {
        let body = ask_sentence(
            &agent("owner-a"),
            &ask("elastos://inspect/submit_agent_plan", "write"),
        )
        .unwrap();
        assert!(body.contains("Notes (agent-1) asks to write "), "{body}");
        assert!(
            body.contains("access to elastos://inspect/submit_agent_plan."),
            "{body}"
        );
    }

    #[test]
    fn one_runtime_down_keeps_the_other() {
        let kept = rows_from(Some(Ok(vec![ask(
            "elastos://inspect/submit_agent_plan",
            "read",
        )])));
        assert_eq!(kept.len(), 1);
        assert!(rows_from(Some(Err(anyhow::anyhow!("down")))).is_empty());
        assert!(rows_from(None).is_empty());
    }

    #[test]
    fn a_home_card_keeps_its_sentence_and_id() {
        let mut notes = HomeNotificationsSummary::default();
        append_runtime_capability_notifications(
            &mut notes,
            vec![RuntimeCapabilityPendingRequest {
                request_id: "cap-1".into(),
                agent_id: String::new(),
                session_id: String::new(),
                resource: "elastos://content".into(),
                action: "read".into(),
                requested_at: 1,
            }],
        );
        let entry = &notes.entries[0];
        assert_eq!(
            entry.body,
            "A capsule requests read access to elastos://content."
        );
        assert_eq!(
            entry.action_ref.as_ref().unwrap().action_id,
            "capability-approve-request:cap-1"
        );
        assert_eq!(
            capability_decision("capability-approve-request:cap-1").map(|(id, _)| id),
            Some("cap-1")
        );
        assert_eq!(
            capability_decision("capability-approve-request:agent:req-1").map(|(id, _)| id),
            Some("agent:req-1")
        );
    }

    #[test]
    fn an_injected_grant_audit_failure_writes_no_row() {
        let home = std::path::Path::new("/no/such/home");
        super::gateway_tests::seams::arm_grant_fault(home, false);
        let error = sign_agent_grant(
            home,
            "person:owner",
            &ask("elastos://inspect/submit_agent_plan", "write"),
            "req-1",
            "approved",
            "approved",
        )
        .expect_err("the injected failure refuses the grant row");
        assert_eq!(error.to_string(), "injected agent grant audit failure");
        let again = sign_agent_grant(
            home,
            "person:owner",
            &ask("elastos://inspect/submit_agent_plan", "write"),
            "req-1",
            "approved",
            "approved",
        )
        .expect_err("the failure is used once");
        assert_ne!(again.to_string(), "injected agent grant audit failure");
    }

    #[test]
    fn a_plane_conflict_is_a_refusal_and_another_status_is_not() {
        let conflict = anyhow::Error::new(PlaneStatus {
            code: 409,
            message: "the session has ended".to_string(),
        });
        assert!(plane_conflict(&conflict));
        assert_eq!(conflict.to_string(), "the session has ended");
        let other = anyhow::Error::new(PlaneStatus {
            code: 500,
            message: "runtime failed".to_string(),
        });
        assert!(!plane_conflict(&other));
    }
}
