//! Lab stand-in for the Runtime's live-grant view, not the Runtime.
//!
//! `get_capability_list` is the one answer for `GET /api/capability/list`.
//! `None` is the plain route. `Some("all_sessions_live")` is the query form.
//! One filter keeps a grant whose life is `Live`. An ended session stays.
//!
//! `post_capsules`, `get_capsules` and `delete_capsule` answer the capsule
//! routes for an admitted resident guest. Launch answers `starting` with the
//! Bus session before `finish_start`. A stop stores `stopped` and revokes
//! that session's `Live` grants. One map names the five statuses. One age
//! compare keeps a `failed` or `stopped` entry. One check refuses a client
//! on a shell-only route. `authorise` is a lab seam on that same filter.
//!
//! `get_capability_requests` answers `GET /api/capability/requests?session=`
//! from one request store beside the grants. `seed_request` is the test seam.
//! An accepted stop denies that session's pending requests with the stop
//! cause; a failed start denies them with the failure cause. One writer stores
//! those three fields. `post_capability_deny` answers
//! `POST /api/capability/deny` through that writer with `shell` as settler,
//! and a `starting` instance of that session ends `failed` with the reason.
//! `post_capability_grant` answers `POST /api/capability/grant` through the
//! same writer with `granted` and `shell`, then `seed_grant` stores the one
//! `Live` grant. A grant body carries no token.
//!
//! `set_instant` calls `expire_due`, which passes the one writer `expired`,
//! `Request timed out` and `runtime` for each pending request at least 300
//! seconds old. A granted or denied record and its instance stay.
//!
//! `bridge_envelope` is the one hostcall. A capability line calls
//! `post_capability_request` for the given capsule id. A `resource_invoke`
//! on `localhost://Users/` or `localhost://UsersAI/` calls `protected_read`
//! or `protected_write` for that capsule id. Any other invoke calls
//! `authorise` for that capsule id and returns `data` null. The principal
//! argument does not choose the caller.
//!
//! `bind_verified_principal` stores the principal the launch verified.
//! `post_capsules` copies that principal onto the new instance.
//! `protected_write` and `protected_read` resolve `Users/self` and
//! `UsersAI/self` from it, then call `authorise`. One map holds the bytes.
//!
//! `bind_verified_component` stores the component hash the launch verified.
//! `post_capsules` copies that hash onto the new instance. `component_hash`
//! reads it. The launch body still rejects `component_hash`. A later bind
//! does not change an instance already created.
//!
//! `get_capability_pending` answers `GET /api/capability/pending` from that
//! same request store. A client is refused before the store is read. The list
//! is every session's pending records, sorted by `session_id` then
//! `request_id`. `expires_at` is `requested_at` plus `REQUEST_TIMEOUT_SECS`.
//! The list does not grant and does not settle.
//!
//! `get_audit` answers `GET /api/audit` from one list. A client is refused
//! before that list is read. `record_use` appends one `capability_use` after
//! `protected_write` or `protected_read` succeeds. The list is newest first.
//! A refusal appends nothing. The lab event has no token, and the body has
//! no epoch. A shell grant, deny or revoke appends one event through that
//! same `record_use` after the decision succeeds. `get_audit_types` answers
//! `GET /api/audit/types` with the four type names and reads no store.
//! `revoke_live` appends one `capability_revoke` for each `Live` grant a stop
//! or a failed start drops. A pending settlement appends nothing.
//!
//! `start_provider` is a lab test seam, not a route. The caller passes the
//! confinement profile it already wrote. Started means `init` answered `ok`.
//! Refused leaves no child. The storage root stays under the borrowed home:
//! an outside base, a `..` component, or a symlink is refused before a
//! directory is created and before a child starts.

use crate::harness::{ChildInput, RunningChild, ThrowawayHome};
use crate::identity;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const LIVE_SCOPE: &str = "all_sessions_live";
const RESIDENT_WORLD: &str = "resident-capsule";
const FAILED_KEEP_SECS: u64 = 60;
const REQUEST_TIMEOUT_SECS: u64 = 300;
const MAX_PENDING_REQUESTS: usize = 1024;
const MAX_PENDING_PER_SESSION: usize = 32;
const AUDIT_DEFAULT_LIMIT: usize = 100;
const AUDIT_MAX_LIMIT: usize = 1000;

/// Authenticated caller. A method argument, not a JSON field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caller<'a> {
    Shell,
    Client { session_id: &'a str },
}

/// Life of one seeded grant. The filter keeps `Live`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Life {
    Live,
    Exhausted,
    Revoked,
    Expired,
}

/// Outcome of one `resident.start` call, supplied by the test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Start {
    Ok,
    Error(String),
    Trap(String),
}

/// Five list statuses. This slice stores `Starting`, `Running`, `Stopped` and `Failed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResidentStatus {
    Starting,
    Running,
    #[allow(dead_code)]
    Stopping,
    Stopped,
    Failed,
}

struct Grant {
    request_id: String,
    session_id: String,
    resource: String,
    action: String,
    duration: String,
    granted_at: u64,
    life: Life,
    session_ended: bool,
}

struct Admitted {
    path: String,
    name: String,
    start: Start,
    world: &'static str,
    principal: Option<String>,
    component_hash: Option<String>,
}

struct Instance {
    id: String,
    name: String,
    start: Start,
    phase: ResidentStatus,
    cause: String,
    ended_at: Option<u64>,
    principal: Option<String>,
    component_hash: Option<String>,
}

/// Four request statuses this slice stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestStatus {
    Pending,
    Granted,
    Denied,
    Expired,
}

struct Request {
    request_id: String,
    session_id: String,
    resource: String,
    action: String,
    reason: String,
    requested_at: u64,
    status: RequestStatus,
    decision_reason: String,
    settled_by: Option<&'static str>,
}

struct AuditUse {
    event_type: &'static str,
    at: u64,
    request_id: String,
    session_id: String,
    resource: String,
    action: String,
    success: bool,
}

pub struct StandIn {
    grants: Vec<Grant>,
    requests: Vec<Request>,
    admitted: Vec<Admitted>,
    instances: Vec<Instance>,
    protected_objects: BTreeMap<String, Vec<u8>>,
    audit: Vec<AuditUse>,
    next_id: u64,
    next_request: u64,
    instant: u64,
}

impl StandIn {
    pub fn new() -> Self {
        Self {
            grants: Vec::new(),
            requests: Vec::new(),
            admitted: Vec::new(),
            instances: Vec::new(),
            protected_objects: BTreeMap::new(),
            audit: Vec::new(),
            next_id: 1,
            next_request: 1,
            instant: 0,
        }
    }

    /// Lab test seam, not a route.
    ///
    /// The `run` launcher's storage directory follows the selected Home: it is
    /// `harness::data_dir(home)` joined with `storage`. The fixed shared temp
    /// path is refused before that rule runs on it. This call creates nothing.
    pub fn storage_for_home(home: &Path) -> Result<PathBuf, (u16, String)> {
        const SHARED_TEMP: &str = "/tmp/elastos/storage";
        const NEEDS_HOME: &str = "storage needs a selected Home";
        const SHARED_REASON: &str = "shared temp directory is not agent storage";

        let refused = |reason: &str| Err((400, reason.to_owned()));
        if home.as_os_str().is_empty()
            || !home.is_absolute()
            || home
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return refused(NEEDS_HOME);
        }
        if home == Path::new(SHARED_TEMP) {
            return refused(SHARED_REASON);
        }
        let data = crate::harness::data_dir(home).map_err(|reason| (400, reason.to_owned()))?;
        let storage = data.join("storage");
        if storage == Path::new(SHARED_TEMP) {
            return refused(SHARED_REASON);
        }
        Ok(storage)
    }

    /// Lab test seam, not a route.
    ///
    /// The two named storage cases are refused here. A symbolic link at the
    /// storage directory is refused and not followed. A regular file under it
    /// whose link count is above 1 is refused and not read. This call creates
    /// nothing.
    pub fn confirm_storage(home: &Path, entry: &str) -> Result<PathBuf, (u16, String)> {
        const LINK_REASON: &str = "storage directory is a symbolic link";
        const ENTRY_REASON: &str = "storage entry stays under the selected Home";

        let storage = Self::storage_for_home(home)?;
        if !crate::harness::directories_only(&storage, home) {
            return Err((400, LINK_REASON.to_owned()));
        }
        if entry.is_empty() {
            return Ok(storage);
        }
        let mut parts = Path::new(entry).components();
        match (parts.next(), parts.next()) {
            (Some(Component::Normal(_)), None) => {}
            _ => return Err((400, ENTRY_REASON.to_owned())),
        }
        let file = storage.join(entry);
        Self::one_link(&file)?;
        Ok(file)
    }

    /// One link-count check. It reads no file bytes and follows no link.
    fn one_link(path: &Path) -> Result<(), (u16, String)> {
        use std::os::unix::fs::MetadataExt;

        const MANY_REASON: &str = "storage file has more than one link";
        const REGULAR_REASON: &str = "storage file is not a single regular file";

        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                    return Err((400, REGULAR_REASON.to_owned()));
                }
                if meta.nlink() > 1 {
                    return Err((400, MANY_REASON.to_owned()));
                }
                Ok(())
            }
            Err(_) => Err((400, REGULAR_REASON.to_owned())),
        }
    }

    /// Lab test seam, not a route.
    ///
    /// `granted_at` is the seeded value. This method reads no clock.
    #[allow(clippy::too_many_arguments)]
    pub fn seed_grant(
        &mut self,
        request_id: &str,
        session_id: &str,
        resource: &str,
        action: &str,
        duration: &str,
        granted_at: u64,
        life: Life,
        session_ended: bool,
    ) {
        self.grants.push(Grant {
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            resource: resource.to_owned(),
            action: action.to_owned(),
            duration: duration.to_owned(),
            granted_at,
            life,
            session_ended,
        });
    }

    /// Lab test seam, not a route.
    ///
    /// Stores one pending request at the current instant unless the store
    /// already holds 1024 pending records, or that session already holds 32.
    /// The store check keeps settled records and removes nothing. This method
    /// reads no clock and no disk.
    pub fn seed_request(
        &mut self,
        request_id: &str,
        session_id: &str,
        resource: &str,
        action: &str,
        reason: &str,
    ) -> Result<(), (u16, String)> {
        if request_id.is_empty()
            || session_id.is_empty()
            || resource.is_empty()
            || action.is_empty()
        {
            return Err((
                400,
                "request needs an id, a session, a resource and an action".to_owned(),
            ));
        }
        if self
            .requests
            .iter()
            .any(|request| request.request_id == request_id)
        {
            return Err((400, format!("request already stored: {request_id}")));
        }
        let pending_in_store = self
            .requests
            .iter()
            .filter(|request| request.status == RequestStatus::Pending)
            .count();
        if pending_in_store >= MAX_PENDING_REQUESTS {
            return Err((400, "Too many pending requests".to_owned()));
        }
        let pending = self
            .requests
            .iter()
            .filter(|request| {
                request.session_id == session_id && request.status == RequestStatus::Pending
            })
            .count();
        if pending >= MAX_PENDING_PER_SESSION {
            return Err((400, "Too many pending requests for this session".to_owned()));
        }
        self.requests.push(Request {
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            resource: resource.to_owned(),
            action: action.to_owned(),
            reason: reason.to_owned(),
            requested_at: self.instant,
            status: RequestStatus::Pending,
            decision_reason: String::new(),
            settled_by: None,
        });
        Ok(())
    }

    /// `GET /api/capability/requests?session=`.
    ///
    /// `session` is the query, a method argument. Ok means status 200.
    pub fn get_capability_requests(
        &self,
        caller: Caller<'_>,
        session: Option<&str>,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let Some(session) = session.filter(|session| !session.is_empty()) else {
            return Err((400, "requests need a session".to_owned()));
        };
        let mut listed: Vec<&Request> = self
            .requests
            .iter()
            .filter(|request| request.session_id == session)
            .collect();
        listed.sort_by(|left, right| left.request_id.cmp(&right.request_id));
        let requests = listed.into_iter().map(request_entry).collect::<Vec<_>>();
        Ok(json!({ "requests": requests }))
    }

    /// `GET /api/capability/pending`.
    ///
    /// The shell receives every session's still-pending requests from the one
    /// request store. A client is status 403 with `This endpoint requires
    /// shell privileges`, and that check runs before the store is read. The
    /// body's only key is `requests`. A record whose status is not pending is
    /// omitted. Entries are sorted by `session_id`, then `request_id`. This
    /// method does not grant, does not settle and does not call `expire_due`.
    pub fn get_capability_pending(&self, caller: Caller<'_>) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let mut listed: Vec<&Request> = self
            .requests
            .iter()
            .filter(|request| request.status == RequestStatus::Pending)
            .collect();
        listed.sort_by(|left, right| {
            left.session_id
                .cmp(&right.session_id)
                .then(left.request_id.cmp(&right.request_id))
        });
        let requests = listed.into_iter().map(pending_entry).collect::<Vec<_>>();
        Ok(json!({ "requests": requests }))
    }

    /// `POST /api/capability/request`.
    ///
    /// A client instance that is `starting` or `running` stores one pending
    /// request through `seed_request`. A shell is refused before the body is
    /// read. A `stopped` or `failed` instance is not live and stores nothing.
    /// A system backend or a generic wallet resource is denied by
    /// `prestore_denial` before the store. Ok is
    /// `{"status": "pending", "request_id": ...}` and carries no token.
    pub fn post_capability_request(
        &mut self,
        caller: Caller<'_>,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        let Caller::Client { session_id } = caller else {
            return Err((
                403,
                "capability request needs an instance session".to_owned(),
            ));
        };
        let (resource, given_action, reason) = request_body(body)?;
        if !resource.starts_with("elastos://") && !resource.starts_with("localhost://") {
            return Err((
                400,
                "Unsupported resource scheme. Allowed: elastos://, localhost://".to_owned(),
            ));
        }
        let action = given_action.to_lowercase();
        if !matches!(
            action.as_str(),
            "read" | "write" | "execute" | "delete" | "message" | "admin"
        ) {
            return Err((
                400,
                format!(
                    "Invalid action: {given_action}. Expected: read, write, execute, delete, message, admin"
                ),
            ));
        }
        let phase = self
            .instances
            .iter()
            .find(|instance| instance.id == session_id)
            .map(|instance| instance.phase)
            .ok_or_else(|| unknown_instance(session_id))?;
        if !matches!(phase, ResidentStatus::Starting | ResidentStatus::Running) {
            return Err(not_live(phase));
        }
        if let Some(reason) = prestore_denial(resource, &action) {
            return Ok(json!({ "status": "denied", "reason": reason }));
        }
        let request_id = format!("request-{}", self.next_request);
        self.seed_request(&request_id, session_id, resource, &action, reason)?;
        self.next_request += 1;
        Ok(json!({ "status": "pending", "request_id": request_id }))
    }

    /// Lab test seam, not a route.
    ///
    /// The one hostcall. A `request_capability` line calls
    /// `post_capability_request` for `capsule_id`. A `resource_invoke` whose
    /// uri starts with `localhost://Users/` or `localhost://UsersAI/` calls
    /// `protected_read` or `protected_write` for `capsule_id`. Any other
    /// invoke calls `authorise` for `capsule_id` and returns `data` null.
    /// `principal` does not choose the caller. This method reads no clock
    /// and no disk.
    pub fn bridge_envelope(
        &mut self,
        line: &str,
        capsule_id: &str,
        principal: Option<&str>,
    ) -> Result<String, String> {
        let _ = principal;
        let envelope: Value =
            serde_json::from_str(line).map_err(|err| format!("Invalid JSON: {err}"))?;
        let id = bridge_id(&envelope)?;
        let request = bridge_request(&envelope)?;
        let request_type = request.get("type").and_then(Value::as_str).unwrap_or("");
        let response = match request_type {
            "request_capability" => {
                let body = capability_fields(request);
                let capability_caller = Caller::Client {
                    session_id: capsule_id,
                };
                match self.post_capability_request(capability_caller, &body) {
                    Ok(data) => bridge_ok(data),
                    Err((_status, message)) => bridge_error(&message),
                }
            }
            "resource_invoke" => {
                let token = invoke_token(request)?;
                let uri = invoke_uri(request);
                if protected_invoke(uri) {
                    self.bridge_protected_invoke(request, capsule_id, token, uri)
                } else {
                    let invoke_caller = Caller::Client {
                        session_id: capsule_id,
                    };
                    match self.authorise(invoke_caller, token) {
                        Ok(()) => bridge_ok(Value::Null),
                        Err((_status, message)) => bridge_error(&message),
                    }
                }
            }
            _ => bridge_error("unsupported bridge request"),
        };
        serde_json::to_string(&json!({
            "id": id,
            "response": response,
        }))
        .map_err(|err| format!("Invalid JSON: {err}"))
    }

    /// One protected invoke on the hostcall.
    ///
    /// `read` calls `protected_read` and ignores `body`. `write` calls
    /// `protected_write` only when `body` is a JSON string. The instance id
    /// is `capsule_id`. A method error keeps `code` `denied` and drops the
    /// numeric status. A resolved root in that reason is rewritten to the
    /// guest form. The stored text is returned unchanged.
    fn bridge_protected_invoke(
        &mut self,
        request: &Value,
        capsule_id: &str,
        token: &str,
        uri: &str,
    ) -> Value {
        let operation = request
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("");
        match operation {
            "read" => match self.protected_read(capsule_id, token, uri) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(text) => bridge_ok(Value::String(text)),
                    Err(_bytes) => bridge_error("protected read is not utf-8"),
                },
                Err((_status, message)) => bridge_error(&Self::redact_protected_reason(&message)),
            },
            "write" => {
                let Some(text) = request.get("body").and_then(Value::as_str) else {
                    return bridge_error("protected write body must be a string");
                };
                match self.protected_write(capsule_id, token, uri, text.as_bytes()) {
                    Ok(_resolved) => bridge_ok(json!({ "stored": true })),
                    Err((_status, message)) => {
                        bridge_error(&Self::redact_protected_reason(&message))
                    }
                }
            }
            _ => bridge_error("protected operation is read or write"),
        }
    }

    /// Rewrites every `Users` or `UsersAI` root in a reason to the guest form.
    ///
    /// A stored grant can name another principal's root in `wrong resource`,
    /// so redaction is independent of the caller. Stored text stays separate.
    fn redact_protected_reason(message: &str) -> String {
        let mut redacted = message.to_owned();
        for prefix in ["localhost://Users/", "localhost://UsersAI/"] {
            let mut remaining = redacted.as_str();
            let mut output = String::new();
            while let Some((before, after)) = remaining.split_once(prefix) {
                output.push_str(before);
                output.push_str(prefix);
                let root_end = after
                    .find(|c: char| c == '/' || c == ',' || c.is_whitespace())
                    .unwrap_or(after.len());
                if root_end > 0 {
                    output.push_str("self");
                }
                remaining = &after[root_end..];
            }
            output.push_str(remaining);
            redacted = output;
        }
        redacted
    }

    /// Lab observation, not a route.
    ///
    /// Reads the shell capsule list and that session's shell request records
    /// through the existing reads. A `stopped` or `failed` instance at the
    /// test instant stays listed with that status and one request record that
    /// is not pending. This method reads no clock and no disk.
    pub fn watch_ended(&self, session_id: &str, ended: &str) -> Result<(), (u16, String)> {
        if ended != "stopped" && ended != "failed" {
            return Err((400, "watch status must be stopped or failed".to_owned()));
        }
        let listed = self.get_capsules(Caller::Shell)?;
        let Some(entry) = listed["capsules"]
            .as_array()
            .and_then(|capsules| capsules.iter().find(|entry| entry["id"] == session_id))
        else {
            return Err((400, format!("left the instance list: {session_id}")));
        };
        let status = entry["status"].as_str().unwrap_or("");
        if status != ended {
            return Err((
                400,
                format!("changed from {ended} to {status}: {session_id}"),
            ));
        }
        let records = self.get_capability_requests(Caller::Shell, Some(session_id))?;
        let requests = records["requests"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if requests
            .iter()
            .any(|request| request["status"] == "pending")
        {
            return Err((400, format!("made a request after it ended: {session_id}")));
        }
        if requests.len() != 1 {
            return Err((
                400,
                format!(
                    "{session_id} has {} request records after it ended",
                    requests.len()
                ),
            ));
        }
        Ok(())
    }

    /// `POST /api/capability/deny`.
    ///
    /// A shell denies one pending request through the one writer, which stores
    /// `shell` as settler. A `starting` instance with that session ends
    /// `failed` with the deny reason as its cause, revokes its live grants and
    /// settles its remaining pending requests through the session cleanup.
    /// Any other phase stays. Ok is `{"success": true}`. After that writer
    /// and that life change, `record_use` appends one `capability_denied`.
    /// When the instance is `starting`, `revoke_live` appends one
    /// `capability_revoke` for each `Live` grant it drops before that
    /// `capability_denied`. A pending settlement appends nothing. A refusal
    /// appends nothing.
    pub fn post_capability_deny(
        &mut self,
        caller: Caller<'_>,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let (request_id, reason) = deny_body(body)?;
        let Some(request) = self
            .requests
            .iter()
            .find(|request| request.request_id == request_id)
        else {
            return Err((400, format!("unknown request: {request_id}")));
        };
        if request.status != RequestStatus::Pending {
            return Err((400, format!("request is not pending: {request_id}")));
        }
        let session_id = request.session_id.clone();
        let resource = request.resource.clone();
        let action = request.action.clone();
        self.settle_record(request_id, RequestStatus::Denied, reason, "shell");
        let instant = self.instant;
        if let Some(instance) = self
            .instances
            .iter_mut()
            .find(|instance| instance.id == session_id.as_str())
        {
            if instance.phase == ResidentStatus::Starting {
                instance.phase = ResidentStatus::Failed;
                instance.cause = reason.to_owned();
                instance.ended_at = Some(instant);
                self.revoke_live(&session_id);
                self.settle_pending(&session_id, reason);
            }
        }
        self.record_use(
            "capability_denied",
            false,
            request_id,
            &session_id,
            &resource,
            &action,
        );
        Ok(json!({ "success": true }))
    }

    /// `POST /api/capability/grant`.
    ///
    /// A shell grants one pending request through the one writer, which stores
    /// `granted`, the rationale and `shell` as settler. `seed_grant` then
    /// stores the one `Live` grant for that request. Ok is
    /// `{"success": true}` and carries no token. After that writer and that
    /// live grant, `record_use` appends one `capability_grant`. A refusal
    /// appends nothing.
    pub fn post_capability_grant(
        &mut self,
        caller: Caller<'_>,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let (request_id, duration, rationale) = grant_body(body)?;
        let Some(request) = self
            .requests
            .iter()
            .find(|request| request.request_id == request_id)
        else {
            return Err((400, format!("unknown request: {request_id}")));
        };
        if request.status != RequestStatus::Pending {
            return Err((400, format!("request is not pending: {request_id}")));
        }
        let request_id = request.request_id.clone();
        let session_id = request.session_id.clone();
        let resource = request.resource.clone();
        let action = request.action.clone();
        self.settle_record(&request_id, RequestStatus::Granted, rationale, "shell");
        let instant = self.instant;
        self.seed_grant(
            &request_id,
            &session_id,
            &resource,
            &action,
            duration,
            instant,
            Life::Live,
            false,
        );
        self.record_use(
            "capability_grant",
            true,
            &request_id,
            &session_id,
            &resource,
            &action,
        );
        Ok(json!({ "success": true }))
    }

    /// `GET /api/capability/request/:id`.
    ///
    /// `request_id` is the path, a method argument, not a JSON field. The
    /// lookup runs before the caller check. A record that is missing is status
    /// 404 with `Request not found: ` plus that id. A shell, or a client whose
    /// session is not the record's, is status 403 with `Cannot access another
    /// session's request`. Ok carries the stored status word, and a denied or
    /// expired record also carries its decision reason. It carries no token
    /// and stores nothing.
    pub fn get_capability_request(
        &self,
        caller: Caller<'_>,
        request_id: &str,
    ) -> Result<Value, (u16, String)> {
        let Some(request) = self
            .requests
            .iter()
            .find(|request| request.request_id == request_id)
        else {
            return Err((404, format!("Request not found: {request_id}")));
        };
        let owns = matches!(
            caller,
            Caller::Client { session_id } if session_id == request.session_id
        );
        if !owns {
            return Err((403, "Cannot access another session's request".to_owned()));
        }
        let status = request_status_text(request.status);
        match request.status {
            RequestStatus::Pending | RequestStatus::Granted => Ok(json!({ "status": status })),
            RequestStatus::Denied | RequestStatus::Expired => Ok(json!({
                "status": status,
                "reason": request.decision_reason,
            })),
        }
    }

    /// `DELETE /api/capability/:id`.
    ///
    /// `request_id` is the path, a method argument, not a JSON field. The shell
    /// check runs before the request store is read. A missing record is status
    /// 404 with `Capability request not found: ` plus that id. A record that is
    /// not granted is status 400 with `Capability ` plus that id plus
    /// ` was not granted`. On success the one writer stores `denied`,
    /// `Revoked by user` and `shell`, and the one life function drops that
    /// id's live grant. Ok is `{"success": true, "revoked_request_id": ...}`
    /// and carries no token. After that writer and that life change,
    /// `record_use` appends one `capability_revoke` from that grant. A
    /// refusal appends nothing.
    pub fn delete_capability(
        &mut self,
        caller: Caller<'_>,
        request_id: &str,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let (session_id, resource, action) = {
            let Some(request) = self
                .requests
                .iter()
                .find(|request| request.request_id == request_id)
            else {
                return Err((404, format!("Capability request not found: {request_id}")));
            };
            if request.status != RequestStatus::Granted {
                return Err((400, format!("Capability {request_id} was not granted")));
            }
            match self
                .grants
                .iter()
                .find(|grant| grant.request_id == request_id)
            {
                Some(grant) => (
                    grant.session_id.clone(),
                    grant.resource.clone(),
                    grant.action.clone(),
                ),
                None => (
                    request.session_id.clone(),
                    request.resource.clone(),
                    request.action.clone(),
                ),
            }
        };
        self.settle_record(
            request_id,
            RequestStatus::Denied,
            "Revoked by user",
            "shell",
        );
        self.revoke_grant(request_id);
        self.record_use(
            "capability_revoke",
            true,
            request_id,
            &session_id,
            &resource,
            &action,
        );
        Ok(json!({
            "success": true,
            "revoked_request_id": request_id,
        }))
    }

    /// `POST /api/capability/revoke-all`.
    ///
    /// A shell revoke stores `denied`, the shell reason and `shell` on every
    /// `Granted` record through the one writer, and the one life function then
    /// drops every `Live` grant. An instance stays. The body's only key is a
    /// string `reason`; a missing one is `Revoked all by user`. Another key is
    /// refused before a non-string `reason` is checked. Ok is
    /// `{"success": true, "reason": ...}` and carries no epoch or token.
    /// The call snapshots the `Live` grants, revokes through this path, then
    /// `record_use` appends one `capability_revoke` per snapshot entry,
    /// sorted by `session_id` then `request_id`. An `Exhausted` grant and a
    /// pending request append nothing. A refusal appends nothing.
    pub fn post_capability_revoke_all(
        &mut self,
        caller: Caller<'_>,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        const DEFAULT_REASON: &str = "Revoked all by user";

        require_shell(caller)?;
        let reason = match body {
            Value::Null => DEFAULT_REASON,
            Value::Object(object) => {
                let mut reason = None;
                let mut reason_not_string = false;
                for (key, value) in object {
                    if key != "reason" {
                        return Err((400, format!("revoke body rejects {key}")));
                    }
                    match value {
                        Value::String(text) => reason = Some(text.as_str()),
                        _ => reason_not_string = true,
                    }
                }
                if reason_not_string {
                    return Err((400, "revoke reason must be a string".to_owned()));
                }
                reason.unwrap_or(DEFAULT_REASON)
            }
            _ => return Err((400, "revoke body needs an object".to_owned())),
        };
        let mut snapshot = self
            .grants
            .iter()
            .filter(|grant| is_live(grant.life))
            .map(|grant| {
                (
                    grant.session_id.clone(),
                    grant.request_id.clone(),
                    grant.resource.clone(),
                    grant.action.clone(),
                )
            })
            .collect::<Vec<_>>();
        snapshot.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        let granted = self
            .requests
            .iter()
            .filter(|request| request.status == RequestStatus::Granted)
            .map(|request| request.request_id.clone())
            .collect::<Vec<_>>();
        for request_id in granted {
            self.settle_record(&request_id, RequestStatus::Denied, reason, "shell");
        }
        let live = self
            .grants
            .iter()
            .filter(|grant| is_live(grant.life))
            .map(|grant| grant.request_id.clone())
            .collect::<Vec<_>>();
        for request_id in live {
            self.revoke_grant(&request_id);
        }
        for (session_id, request_id, resource, action) in &snapshot {
            self.record_use(
                "capability_revoke",
                true,
                request_id,
                session_id,
                resource,
                action,
            );
        }
        Ok(json!({ "success": true, "reason": reason }))
    }

    /// `GET /api/capability/list` for the plain route or `?scope=`.
    pub fn get_capability_list(
        &self,
        caller: Caller<'_>,
        scope: Option<&str>,
    ) -> Result<Value, (u16, String)> {
        if let Some(scope) = scope {
            if scope != LIVE_SCOPE {
                return Err((400, format!("unknown capability list scope: {scope}")));
            }
            require_shell(caller)?;
        }
        Ok(self.render(caller))
    }

    /// Lab test seam, not a route.
    ///
    /// `Ok(())` means the grant authorises that caller, and a `once` grant
    /// stores `Exhausted`. This method reads no clock, no disk and no WIT file.
    /// Storage presents its uri and action through the same check.
    pub fn authorise(&mut self, caller: Caller<'_>, request_id: &str) -> Result<(), (u16, String)> {
        self.authorise_presented(caller, request_id, None)
    }

    /// One authorise check. `presented` is the storage uri and `write` or `read`.
    ///
    /// Unknown, not-live and wrong-caller refusals come first. A different
    /// action is `wrong action`. A different object is `wrong resource`. Either
    /// spends nothing. A missing presentation is the grant's own caller check.
    fn authorise_presented(
        &mut self,
        caller: Caller<'_>,
        request_id: &str,
        presented: Option<(&str, &str)>,
    ) -> Result<(), (u16, String)> {
        let Some(index) = self
            .grants
            .iter()
            .position(|grant| grant.request_id == request_id)
        else {
            return Err(unknown_grant(request_id));
        };
        let life = self.grants[index].life;
        if !is_live(life) {
            return Err(grant_not_live(life));
        }
        if !session_authorises(&self.grants[index], caller) {
            return Err(wrong_capsule(&self.grants[index], caller));
        }
        if let Some((requested, action)) = presented {
            let grant_action = self.grants[index].action.clone();
            let grant_resource = self.grants[index].resource.clone();
            if grant_action != action {
                return Err(wrong_action(&grant_action, action));
            }
            let session_id = self.grants[index].session_id.clone();
            let wanted = self.resolve_protected_uri(&session_id, requested)?;
            let granted = match self.resolve_protected_uri(&session_id, &grant_resource) {
                Ok(uri) => uri,
                Err(_) => return Err(wrong_resource(&grant_resource, requested)),
            };
            if wanted != granted {
                return Err(wrong_resource(&grant_resource, requested));
            }
        }
        if self.grants[index].duration == "once" {
            self.grants[index].life = Life::Exhausted;
        }
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Resolves the uri from the principal copied at launch, then the one
    /// authorise check for that uri and `write`. On `Ok` the bytes replace any
    /// previous value at that exact uri, then `record_use` appends one event.
    pub fn protected_write(
        &mut self,
        instance_id: &str,
        request_id: &str,
        uri: &str,
        bytes: &[u8],
    ) -> Result<String, (u16, String)> {
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
        self.authorise_presented(
            Caller::Client {
                session_id: instance_id,
            },
            request_id,
            Some((uri, "write")),
        )?;
        self.protected_objects
            .insert(resolved.clone(), bytes.to_vec());
        self.record_use(
            "capability_use",
            true,
            request_id,
            instance_id,
            &resolved,
            "write",
        );
        Ok(resolved)
    }

    /// Lab test seam, not a route.
    ///
    /// Resolves the uri from the principal copied at launch, then the one
    /// authorise check for that uri and `read`, then returns the stored bytes.
    /// `record_use` appends one event after those bytes are found.
    pub fn protected_read(
        &mut self,
        instance_id: &str,
        request_id: &str,
        uri: &str,
    ) -> Result<Vec<u8>, (u16, String)> {
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
        self.authorise_presented(
            Caller::Client {
                session_id: instance_id,
            },
            request_id,
            Some((uri, "read")),
        )?;
        let stored = self
            .protected_objects
            .get(&resolved)
            .cloned()
            .ok_or_else(|| (404, "protected object is absent".to_owned()))?;
        self.record_use(
            "capability_use",
            true,
            request_id,
            instance_id,
            &resolved,
            "read",
        );
        Ok(stored)
    }

    /// Appends one audit event and returns nothing.
    ///
    /// This is the only append. `event_type` and `success` name the decision.
    /// `protected_write` and `protected_read` pass `capability_use` and `true`
    /// after the bytes are stored or found. A shell grant, deny or revoke
    /// calls this once after that decision succeeds. `revoke_live` calls this
    /// once per `Live` grant it drops, with `capability_revoke` and `true`.
    /// `settle_pending` and `expire_due` do not call this. A refusal returns
    /// before this call. `at` is the test instant. The event has no token and
    /// no reason.
    fn record_use(
        &mut self,
        event_type: &'static str,
        success: bool,
        request_id: &str,
        session_id: &str,
        resource: &str,
        action: &str,
    ) {
        self.audit.push(AuditUse {
            event_type,
            at: self.instant,
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            resource: resource.to_owned(),
            action: action.to_owned(),
            success,
        });
    }

    /// `GET /api/audit`.
    ///
    /// The shell receives the one audit list, newest first. A client is status
    /// 403 with `This endpoint requires shell privileges`, and that check runs
    /// before the store is read. The body's only keys are `events` and
    /// `total_in_memory`. `total_in_memory` counts every stored event before
    /// the type filter and before the limit. `limit: None` keeps at most 100
    /// events. A limit above 1000 keeps at most 1000. `limit: Some(0)` keeps
    /// none. An event's keys are `type`, `at`, `request_id`, `session_id`,
    /// `resource`, `action` and `success`. There is no token and the body has
    /// no epoch. This method does not change the store.
    pub fn get_audit(
        &self,
        caller: Caller<'_>,
        limit: Option<usize>,
        event_type: Option<&str>,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let total_in_memory = self.audit.len();
        let cap = match limit {
            None => AUDIT_DEFAULT_LIMIT,
            Some(n) => n.min(AUDIT_MAX_LIMIT),
        };
        let events = self
            .audit
            .iter()
            .rev()
            .filter(|event| match event_type {
                Some(wanted) => event.event_type == wanted,
                None => true,
            })
            .take(cap)
            .map(audit_entry)
            .collect::<Vec<_>>();
        Ok(json!({
            "events": events,
            "total_in_memory": total_in_memory,
        }))
    }

    /// `GET /api/audit/types`.
    ///
    /// A client is status 403 with `This endpoint requires shell privileges`,
    /// and that check runs before any other work. The Ok object's only key is
    /// `event_types`. The value is `capability_denied`, `capability_grant`,
    /// `capability_revoke` and `capability_use`, in that order, including when
    /// the store is empty. This method reads no event store and appends nothing.
    pub fn get_audit_types(&self, caller: Caller<'_>) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        Ok(json!({
            "event_types": [
                "capability_denied",
                "capability_grant",
                "capability_revoke",
                "capability_use",
            ],
        }))
    }

    /// The one resolver for `Users/self` and `UsersAI/self`.
    ///
    /// The root is the first 24 characters of `identity::sha256` of the
    /// instance principal. The principal text is not part of the root.
    fn resolve_protected_uri(&self, instance_id: &str, uri: &str) -> Result<String, (u16, String)> {
        let Some(instance) = self
            .instances
            .iter()
            .find(|instance| instance.id == instance_id)
        else {
            return Err(unknown_instance(instance_id));
        };
        if !matches!(
            instance.phase,
            ResidentStatus::Starting | ResidentStatus::Running
        ) {
            return Err(not_live(instance.phase));
        }
        if uri.split('/').any(|segment| segment == "..") {
            return Err((400, "protected path rejects ..".to_owned()));
        }
        let Some(principal) = instance
            .principal
            .as_deref()
            .filter(|principal| !principal.is_empty())
        else {
            return Err((
                400,
                "requires the principal from the verified launch".to_owned(),
            ));
        };
        let digest = &crate::identity::sha256(principal.as_bytes())[..24];
        if let Some(suffix) = uri.strip_prefix("localhost://Users/self") {
            if suffix.is_empty() || suffix.starts_with('/') {
                return Ok(format!("localhost://Users/{digest}{suffix}"));
            }
        }
        if let Some(suffix) = uri.strip_prefix("localhost://UsersAI/self") {
            if suffix.is_empty() || suffix.starts_with('/') {
                return Ok(format!("localhost://UsersAI/{digest}{suffix}"));
            }
        }
        let users_root = format!("localhost://Users/{digest}");
        let users_child = format!("{users_root}/");
        if uri == users_root || uri.starts_with(&users_child) {
            return Ok(uri.to_owned());
        }
        if uri.starts_with("localhost://UsersAI/") {
            return Err((400, "UsersAI roots must use UsersAI/self".to_owned()));
        }
        if uri.starts_with("localhost://Users/") {
            return Err((
                400,
                "localhost://Users roots must use Users/self or the active principal root"
                    .to_owned(),
            ));
        }
        Err((
            400,
            "protected storage needs a Users/self or UsersAI/self resource".to_owned(),
        ))
    }

    /// Lab test seam, not a route.
    ///
    /// Stores one resident guest for `path`. This method reads no directory.
    pub fn admit_resident(
        &mut self,
        path: &str,
        name: &str,
        start: Start,
    ) -> Result<(), (u16, String)> {
        if path.is_empty() || name.is_empty() {
            return Err((400, "resident admit needs a path and a name".to_owned()));
        }
        if self.admitted.iter().any(|row| row.path == path) {
            return Err((400, format!("resident path already admitted: {path}")));
        }
        self.admitted.push(Admitted {
            path: path.to_owned(),
            name: name.to_owned(),
            start,
            world: RESIDENT_WORLD,
            principal: None,
            component_hash: None,
        });
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Stores the principal the launch verified on one admitted path. It mints
    /// no instance id, and a later call does not change an instance already
    /// created.
    pub fn bind_verified_principal(
        &mut self,
        path: &str,
        principal: &str,
    ) -> Result<(), (u16, String)> {
        if principal.is_empty() {
            return Err((400, "verified launch needs a principal".to_owned()));
        }
        let Some(row) = self.admitted.iter_mut().find(|row| row.path == path) else {
            return Err((400, format!("unknown resident path: {path}")));
        };
        if row.principal.is_some() {
            return Err((400, "verified principal already bound".to_owned()));
        }
        row.principal = Some(principal.to_owned());
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Stores the component hash the verified launch supplied on one admitted
    /// path. It mints no instance id, and a later call does not change an
    /// instance already created.
    pub fn bind_verified_component(&mut self, path: &str, hash: &str) -> Result<(), (u16, String)> {
        if hash.is_empty() {
            return Err((400, "verified launch needs a component hash".to_owned()));
        }
        if !crate::report::hex(hash, 64) {
            return Err((
                400,
                "component hash must be 64 lowercase hex characters".to_owned(),
            ));
        }
        let Some(row) = self.admitted.iter_mut().find(|row| row.path == path) else {
            return Err((400, format!("unknown resident path: {path}")));
        };
        if row.component_hash.is_some() {
            return Err((400, "verified component hash already bound".to_owned()));
        }
        row.component_hash = Some(hash.to_owned());
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Returns the component hash `post_capsules` copied onto this instance.
    /// It does not read the admit name, the path, or the launch body.
    pub fn component_hash(&self, instance_id: &str) -> Result<String, (u16, String)> {
        let Some(instance) = self
            .instances
            .iter()
            .find(|instance| instance.id == instance_id)
        else {
            return Err(unknown_instance(instance_id));
        };
        instance
            .component_hash
            .clone()
            .ok_or_else(|| (400, "instance has no verified component hash".to_owned()))
    }

    /// Lab test seam, not a route.
    ///
    /// Applies the admitted `Start` once. This is the stand-in's `resident.start`.
    pub fn finish_start(&mut self, id: &str) -> Result<(), (u16, String)> {
        let instant = self.instant;
        let Some(instance) = self.instances.iter_mut().find(|instance| instance.id == id) else {
            return Err(unknown_instance(id));
        };
        if matches!(
            instance.phase,
            ResidentStatus::Stopped | ResidentStatus::Stopping
        ) {
            return Err(not_live(instance.phase));
        }
        if instance.phase != ResidentStatus::Starting {
            return Err((400, "start already returned".to_owned()));
        }
        let (phase, cause, ended_at) = apply_start(&instance.start, instant);
        instance.phase = phase;
        instance.cause = cause;
        instance.ended_at = ended_at;
        if phase != ResidentStatus::Failed {
            return Ok(());
        }
        let session_id = instance.id.clone();
        let cause = instance.cause.clone();
        self.revoke_live(&session_id);
        self.settle_pending(&session_id, &cause);
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Replaces the instant used for ended-entry age and request age. It then
    /// expires the due pending requests through `expire_due`. This method reads
    /// no clock.
    pub fn set_instant(&mut self, secs: u64) {
        self.instant = secs;
        self.expire_due();
    }

    /// `POST /api/capsules`.
    pub fn post_capsules(
        &mut self,
        caller: Caller<'_>,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let path = launch_path(body)?;
        let (name, start, principal, component_hash) = self.admitted_start(path)?;
        let id = self.mint_id();
        let phase = ResidentStatus::Starting;
        self.instances.push(Instance {
            id: id.clone(),
            name: name.clone(),
            start,
            phase,
            cause: String::new(),
            ended_at: None,
            principal,
            component_hash,
        });
        Ok(launch_body(&id, &name, phase))
    }

    /// `GET /api/capsules`.
    pub fn get_capsules(&self, caller: Caller<'_>) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let mut listed: Vec<&Instance> = self
            .instances
            .iter()
            .filter(|instance| keeps_instance(instance, self.instant))
            .collect();
        listed.sort_by(|left, right| left.id.cmp(&right.id));
        let capsules = listed.into_iter().map(capsule_entry).collect::<Vec<_>>();
        Ok(json!({ "capsules": capsules }))
    }

    /// `DELETE /api/capsules/:id`.
    ///
    /// `id` is the path segment. The shell body carries `reason`. Ok is null.
    pub fn delete_capsule(
        &mut self,
        caller: Caller<'_>,
        id: &str,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let reason = stop_reason(body)?;
        self.stop_one(id, reason)?;
        Ok(Value::Null)
    }

    fn stop_one(&mut self, id: &str, reason: &str) -> Result<(), (u16, String)> {
        let instant = self.instant;
        let Some(index) = self.instances.iter().position(|instance| instance.id == id) else {
            return Err(unknown_instance(id));
        };
        let phase = self.instances[index].phase;
        if !matches!(phase, ResidentStatus::Starting | ResidentStatus::Running) {
            return Err(not_live(phase));
        }
        let session_id = self.instances[index].id.clone();
        self.instances[index].phase = ResidentStatus::Stopped;
        let cause = format!("stopped: {reason}");
        self.instances[index].cause = cause.clone();
        self.instances[index].ended_at = Some(instant);
        self.revoke_live(&session_id);
        self.settle_pending(&session_id, &cause);
        Ok(())
    }

    /// Writes `Revoked` on `Live` grants of one session, then appends one
    /// `capability_revoke` for each grant just dropped.
    ///
    /// The append order is `request_id`. An `Exhausted`, `Revoked` or
    /// `Expired` grant adds none. A grant of another session adds none.
    /// `revoke_grant` is the one `Revoked` assignment and does not append.
    /// A shell deny of a `starting` instance uses this same append, and that
    /// route still appends its own `capability_denied`. `settle_pending` and
    /// `expire_due` do not append.
    fn revoke_live(&mut self, session_id: &str) {
        let mut dropped = self
            .grants
            .iter()
            .filter(|grant| grant.session_id == session_id && is_live(grant.life))
            .map(|grant| {
                (
                    grant.request_id.clone(),
                    grant.resource.clone(),
                    grant.action.clone(),
                )
            })
            .collect::<Vec<_>>();
        dropped.sort_by(|left, right| left.0.cmp(&right.0));
        for (request_id, _, _) in &dropped {
            self.revoke_grant(request_id);
        }
        for (request_id, resource, action) in &dropped {
            self.record_use(
                "capability_revoke",
                true,
                request_id,
                session_id,
                resource,
                action,
            );
        }
    }

    /// The one `Revoked` assignment. A missing grant and another life stay.
    fn revoke_grant(&mut self, request_id: &str) {
        if let Some(grant) = self
            .grants
            .iter_mut()
            .find(|grant| grant.request_id == request_id && is_live(grant.life))
        {
            grant.life = Life::Revoked;
        }
    }

    /// The one request writer. It stores the status, the reason and the
    /// settler on one request.
    ///
    /// The stop and failed-start settlement passes `denied` and `runtime`; the
    /// shell deny route passes `denied` and `shell`; the grant route passes
    /// `granted` and `shell`.
    fn settle_record(
        &mut self,
        request_id: &str,
        status: RequestStatus,
        reason: &str,
        settled_by: &'static str,
    ) {
        if let Some(request) = self
            .requests
            .iter_mut()
            .find(|request| request.request_id == request_id)
        {
            request.status = status;
            request.decision_reason = reason.to_owned();
            request.settled_by = Some(settled_by);
        }
    }

    /// Denies the pending requests of one session with that instance's cause.
    ///
    /// Only `Pending` records change; a record of another session stays. The
    /// one writer stores `runtime` as settler.
    fn settle_pending(&mut self, session_id: &str, cause: &str) {
        let pending = self
            .requests
            .iter()
            .filter(|request| {
                request.session_id == session_id && request.status == RequestStatus::Pending
            })
            .map(|request| request.request_id.clone())
            .collect::<Vec<_>>();
        for request_id in pending {
            self.settle_record(&request_id, RequestStatus::Denied, cause, "runtime");
        }
    }

    /// Not a route. Expires the pending requests whose age is at least
    /// `REQUEST_TIMEOUT_SECS`.
    ///
    /// Age is the stored instant minus that request's `requested_at`. Only
    /// `Pending` records change. The one writer stores `expired`,
    /// `Request timed out` and `runtime` as settler. This method reads no clock.
    fn expire_due(&mut self) {
        let instant = self.instant;
        let due = self
            .requests
            .iter()
            .filter(|request| {
                request.status == RequestStatus::Pending
                    && instant.saturating_sub(request.requested_at) >= REQUEST_TIMEOUT_SECS
            })
            .map(|request| request.request_id.clone())
            .collect::<Vec<_>>();
        for request_id in due {
            self.settle_record(
                &request_id,
                RequestStatus::Expired,
                "Request timed out",
                "runtime",
            );
        }
    }

    fn mint_id(&mut self) -> String {
        let id = format!("component-{}", self.next_id);
        self.next_id += 1;
        id
    }

    fn admitted_start(
        &self,
        path: &str,
    ) -> Result<(String, Start, Option<String>, Option<String>), (u16, String)> {
        if let Some(row) = self.admitted.iter().find(|row| row.path == path) {
            return Ok((
                row.name.clone(),
                row.start.clone(),
                row.principal.clone(),
                row.component_hash.clone(),
            ));
        }
        Err(self.not_resident(path))
    }

    fn not_resident(&self, path: &str) -> (u16, String) {
        (
            400,
            format!(
                "not a resident component: {path} world {}",
                self.resident_world()
            ),
        )
    }

    fn resident_world(&self) -> &'static str {
        self.admitted
            .first()
            .map(|row| row.world)
            .unwrap_or(RESIDENT_WORLD)
    }

    fn render(&self, caller: Caller<'_>) -> Value {
        let mut grants = self.kept(caller);
        let shell = matches!(caller, Caller::Shell);
        if shell {
            grants.sort_by(|left, right| {
                left.session_id
                    .cmp(&right.session_id)
                    .then(left.request_id.cmp(&right.request_id))
            });
        } else {
            grants.sort_by(|left, right| left.request_id.cmp(&right.request_id));
        }
        let capabilities = grants
            .iter()
            .map(|grant| entry(grant, shell))
            .collect::<Vec<_>>();
        body(shell, capabilities)
    }

    /// One filter. A grant stays when its life is `Live`. An ended session stays.
    fn kept(&self, caller: Caller<'_>) -> Vec<&Grant> {
        self.grants
            .iter()
            .filter(|grant| keep(grant, caller))
            .collect()
    }
}

fn keep(grant: &Grant, caller: Caller<'_>) -> bool {
    // Ending a session leaves a live grant in this view.
    let _ended = grant.session_ended;
    is_live(grant.life) && visible(grant, caller)
}

/// One life test. `keep`, `revoke_live`, `revoke_grant`, `authorise` and the
/// revoke-all audit snapshot use it.
fn is_live(life: Life) -> bool {
    life == Life::Live
}

fn visible(grant: &Grant, caller: Caller<'_>) -> bool {
    match caller {
        Caller::Shell => true,
        Caller::Client { session_id } => grant.session_id == session_id,
    }
}

/// Session decision for `authorise`. A shell sees every grant and still does
/// not hold it. The session compare stays in `visible`.
fn session_authorises(grant: &Grant, caller: Caller<'_>) -> bool {
    !matches!(caller, Caller::Shell) && visible(grant, caller)
}

fn entry(grant: &Grant, include_session: bool) -> Value {
    let mut fields = Map::new();
    fields.insert("request_id".to_owned(), json!(grant.request_id));
    if include_session {
        fields.insert("session_id".to_owned(), json!(grant.session_id));
    }
    fields.insert("resource".to_owned(), json!(grant.resource));
    fields.insert("action".to_owned(), json!(grant.action));
    fields.insert("duration".to_owned(), json!(grant.duration));
    fields.insert("granted_at".to_owned(), json!(grant.granted_at));
    Value::Object(fields)
}

fn body(shell: bool, capabilities: Vec<Value>) -> Value {
    if shell {
        json!({
            "scope": LIVE_SCOPE,
            "capabilities": capabilities,
        })
    } else {
        json!({ "capabilities": capabilities })
    }
}

fn request_entry(request: &Request) -> Value {
    json!({
        "request_id": request.request_id,
        "session_id": request.session_id,
        "resource": request.resource,
        "action": request.action,
        "reason": request.reason,
        "status": request_status_text(request.status),
        "decision_reason": request.decision_reason,
        "settled_by": request.settled_by,
    })
}

/// One expiry. `expires_at` is the stored instant plus `REQUEST_TIMEOUT_SECS`.
fn request_expires_at(requested_at: u64) -> u64 {
    requested_at.saturating_add(REQUEST_TIMEOUT_SECS)
}

fn audit_entry(event: &AuditUse) -> Value {
    json!({
        "type": event.event_type,
        "at": event.at,
        "request_id": event.request_id,
        "session_id": event.session_id,
        "resource": event.resource,
        "action": event.action,
        "success": event.success,
    })
}

fn pending_entry(request: &Request) -> Value {
    json!({
        "request_id": request.request_id,
        "session_id": request.session_id,
        "resource": request.resource,
        "action": request.action,
        "reason": request.reason,
        "requested_at": request.requested_at,
        "expires_at": request_expires_at(request.requested_at),
    })
}

/// The four request status strings this slice stores.
fn request_status_text(status: RequestStatus) -> &'static str {
    match status {
        RequestStatus::Pending => "pending",
        RequestStatus::Granted => "granted",
        RequestStatus::Denied => "denied",
        RequestStatus::Expired => "expired",
    }
}

/// One refusal. A client on a shell-only route is status 403.
fn require_shell(caller: Caller<'_>) -> Result<(), (u16, String)> {
    match caller {
        Caller::Shell => Ok(()),
        Caller::Client { .. } => Err((403, "This endpoint requires shell privileges".to_owned())),
    }
}

/// The five status strings from the resident-instance list.
fn status_text(status: ResidentStatus) -> &'static str {
    match status {
        ResidentStatus::Starting => "starting",
        ResidentStatus::Running => "running",
        ResidentStatus::Stopping => "stopping",
        ResidentStatus::Stopped => "stopped",
        ResidentStatus::Failed => "failed",
    }
}

fn launch_path(body: &Value) -> Result<&str, (u16, String)> {
    let Some(object) = body.as_object() else {
        return Err((400, "resident launch body needs path".to_owned()));
    };
    let mut path = None;
    let mut path_not_string = false;
    for (key, value) in object {
        if key == "path" {
            match value {
                Value::String(text) => path = Some(text.as_str()),
                _ => path_not_string = true,
            }
        } else {
            return Err((400, format!("resident launch body rejects {key}")));
        }
    }
    if path_not_string {
        return Err((400, "resident launch path must be a string".to_owned()));
    }
    path.ok_or_else(|| (400, "resident launch body needs path".to_owned()))
}

fn launch_body(id: &str, name: &str, phase: ResidentStatus) -> Value {
    json!({
        "id": id,
        "name": name,
        "status": status_text(phase),
        "session_id": id,
    })
}

fn capsule_entry(instance: &Instance) -> Value {
    json!({
        "id": instance.id,
        "name": instance.name,
        "status": status_text(instance.phase),
        "session_id": instance.id,
        "cause": instance.cause,
    })
}

/// Applies `Error` and `Trap` on one arm, and `Ok` on the other.
fn apply_start(start: &Start, instant: u64) -> (ResidentStatus, String, Option<u64>) {
    match start {
        Start::Ok => (ResidentStatus::Running, String::new(), None),
        Start::Error(text) | Start::Trap(text) => {
            (ResidentStatus::Failed, text.clone(), Some(instant))
        }
    }
}

/// One age compare. `failed` and `stopped` stay while age is under 60 seconds.
fn keeps_instance(instance: &Instance, instant: u64) -> bool {
    match instance.phase {
        ResidentStatus::Starting | ResidentStatus::Running => true,
        ResidentStatus::Failed | ResidentStatus::Stopped => match instance.ended_at {
            Some(at) => instant.saturating_sub(at) < FAILED_KEEP_SECS,
            None => false,
        },
        ResidentStatus::Stopping => false,
    }
}

/// One unknown-instance reason. `delete_capsule` and `finish_start` both use it.
fn unknown_instance(id: &str) -> (u16, String) {
    (400, format!("unknown instance: {id}"))
}

fn unknown_grant(request_id: &str) -> (u16, String) {
    (400, format!("unknown grant: {request_id}"))
}

fn life_text(life: Life) -> &'static str {
    match life {
        Life::Live => "Live",
        Life::Exhausted => "Exhausted",
        Life::Revoked => "Revoked",
        Life::Expired => "Expired",
    }
}

fn grant_not_live(life: Life) -> (u16, String) {
    (400, format!("grant is not live: {}", life_text(life)))
}

fn wrong_capsule(grant: &Grant, caller: Caller<'_>) -> (u16, String) {
    let mut reason = format!("wrong capsule: expected {}", grant.session_id);
    if let Caller::Client { session_id } = caller {
        reason.push_str(&format!(", got {session_id}"));
    }
    (403, reason)
}

fn wrong_action(expected: &str, got: &str) -> (u16, String) {
    (403, format!("wrong action: expected {expected}, got {got}"))
}

fn wrong_resource(expected: &str, got: &str) -> (u16, String) {
    (
        403,
        format!("wrong resource: expected {expected}, got {got}"),
    )
}

/// One not-live reason. `delete_capsule` and `finish_start` both use it.
fn not_live(status: ResidentStatus) -> (u16, String) {
    (
        400,
        format!("instance is not live: {}", status_text(status)),
    )
}

/// The deny body's only keys are `request_id` and an optional string `reason`.
///
/// A missing reason is `Denied by user`.
fn deny_body(body: &Value) -> Result<(&str, &str), (u16, String)> {
    const NEEDS_ID: &str = "deny body needs request_id";
    const DEFAULT_REASON: &str = "Denied by user";

    let Some(object) = body.as_object() else {
        return Err((400, NEEDS_ID.to_owned()));
    };
    let mut request_id = None;
    let mut reason = None;
    let mut request_id_not_string = false;
    let mut reason_not_string = false;
    for (key, value) in object {
        match key.as_str() {
            "request_id" => match value {
                Value::String(text) => request_id = Some(text.as_str()),
                _ => request_id_not_string = true,
            },
            "reason" => match value {
                Value::String(text) => reason = Some(text.as_str()),
                _ => reason_not_string = true,
            },
            other => return Err((400, format!("deny body rejects {other}"))),
        }
    }
    if request_id_not_string {
        return Err((400, "deny request_id must be a string".to_owned()));
    }
    if reason_not_string {
        return Err((400, "deny reason must be a string".to_owned()));
    }
    let request_id = request_id.ok_or_else(|| (400, NEEDS_ID.to_owned()))?;
    Ok((request_id, reason.unwrap_or(DEFAULT_REASON)))
}

/// The grant body's only keys are `request_id`, `duration` and `rationale`.
///
/// A missing duration is `session`; a present duration is stored as its
/// lowercase form. A missing rationale is `Shell auto-grant`.
fn grant_body(body: &Value) -> Result<(&str, &str, &str), (u16, String)> {
    const NEEDS_ID: &str = "grant body needs request_id";
    const DEFAULT_DURATION: &str = "session";
    const DEFAULT_RATIONALE: &str = "Shell auto-grant";

    let Some(object) = body.as_object() else {
        return Err((400, NEEDS_ID.to_owned()));
    };
    let mut request_id = None;
    let mut duration = None;
    let mut rationale = None;
    let mut request_id_not_string = false;
    let mut duration_not_string = false;
    let mut rationale_not_string = false;
    for (key, value) in object {
        match key.as_str() {
            "request_id" => match value {
                Value::String(text) => request_id = Some(text.as_str()),
                _ => request_id_not_string = true,
            },
            "duration" => match value {
                Value::String(text) => duration = Some(text.as_str()),
                _ => duration_not_string = true,
            },
            "rationale" => match value {
                Value::String(text) => rationale = Some(text.as_str()),
                _ => rationale_not_string = true,
            },
            other => return Err((400, format!("grant body rejects {other}"))),
        }
    }
    if request_id_not_string {
        return Err((400, "grant request_id must be a string".to_owned()));
    }
    if duration_not_string {
        return Err((400, "grant duration must be a string".to_owned()));
    }
    if rationale_not_string {
        return Err((400, "grant rationale must be a string".to_owned()));
    }
    let request_id = request_id.ok_or_else(|| (400, NEEDS_ID.to_owned()))?;
    let duration = match duration {
        None => DEFAULT_DURATION,
        Some(text) => match text.to_lowercase().as_str() {
            "once" => "once",
            "session" => "session",
            _ => {
                return Err((
                    400,
                    format!("Invalid duration: {text}. Expected 'once' or 'session'"),
                ))
            }
        },
    };
    Ok((request_id, duration, rationale.unwrap_or(DEFAULT_RATIONALE)))
}

/// The request body's only keys are `resource`, `action` and a `reason`.
///
/// The returned action is the given text; its lowercase form is checked by the
/// caller. A missing reason is `""`.
fn request_body(body: &Value) -> Result<(&str, &str, &str), (u16, String)> {
    const NEEDS_RESOURCE: &str = "request body needs resource";
    const NEEDS_ACTION: &str = "request body needs action";

    let Some(object) = body.as_object() else {
        return Err((400, NEEDS_RESOURCE.to_owned()));
    };
    let mut resource = None;
    let mut action = None;
    let mut reason = "";
    let mut resource_not_string = false;
    let mut action_not_string = false;
    let mut reason_not_string = false;
    for (key, value) in object {
        match key.as_str() {
            "resource" => match value {
                Value::String(text) => resource = Some(text.as_str()),
                _ => resource_not_string = true,
            },
            "action" => match value {
                Value::String(text) => action = Some(text.as_str()),
                _ => action_not_string = true,
            },
            "reason" => match value {
                Value::String(text) => reason = text.as_str(),
                _ => reason_not_string = true,
            },
            other => {
                return Err((400, format!("request body rejects {other}")));
            }
        }
    }
    if resource_not_string {
        return Err((400, "request resource must be a string".to_owned()));
    }
    let Some(resource) = resource else {
        return Err((400, NEEDS_RESOURCE.to_owned()));
    };
    if action_not_string {
        return Err((400, "request action must be a string".to_owned()));
    }
    let Some(action) = action else {
        return Err((400, NEEDS_ACTION.to_owned()));
    };
    if reason_not_string {
        return Err((400, "request reason must be a string".to_owned()));
    }
    Ok((resource, action, reason))
}

/// The one pre-store denial for a system backend or a generic wallet resource.
///
/// The first segment after `elastos://` is the text before the first `/`, `?`
/// or `#`, compared case-sensitively. `action` is the lowercased action the
/// route already validated. `None` lets the route store one pending request.
fn prestore_denial(resource: &str, action: &str) -> Option<&'static str> {
    const SYSTEM_REASON: &str = "system backends are not app capabilities; use elastos://content";
    const WALLET_REASON: &str = "generic Wallet access is limited to read-only elastos://wallet/meta/status; use the private Runtime Wallet Bus for authority-bound operations";

    let segment = resource
        .strip_prefix("elastos://")?
        .split(['/', '?', '#'])
        .next()?;
    if matches!(
        segment,
        "elacity" | "elacity-sdk" | "gateway" | "ipfs" | "ipfs-cluster" | "ipfs-provider" | "kubo"
    ) {
        return Some(SYSTEM_REASON);
    }
    if segment == "wallet" && !(resource == "elastos://wallet/meta/status" && action == "read") {
        return Some(WALLET_REASON);
    }
    None
}

/// The stop body is an object whose only key is a non-empty string `reason`.
fn stop_reason(body: &Value) -> Result<&str, (u16, String)> {
    let Some(object) = body.as_object() else {
        return Err((400, "stop body needs reason".to_owned()));
    };
    let mut reason = None;
    let mut reason_not_string = false;
    for (key, value) in object {
        if key != "reason" {
            return Err((400, format!("stop body rejects {key}")));
        }
        match value {
            Value::String(text) if text.is_empty() => {
                return Err((400, "stop needs a reason".to_owned()));
            }
            Value::String(text) => reason = Some(text.as_str()),
            _ => reason_not_string = true,
        }
    }
    if reason_not_string {
        return Err((400, "stop reason must be a string".to_owned()));
    }
    reason.ok_or_else(|| (400, "stop body misses reason".to_owned()))
}

/// The line's numeric `id`, or `0` when that field is absent.
///
/// A present value that is not a non-negative integer is refused. This reads
/// no grant and stores nothing.
fn bridge_id(envelope: &Value) -> Result<u64, String> {
    match envelope.get("id") {
        None => Ok(0),
        Some(id) => id
            .as_u64()
            .ok_or_else(|| "Invalid JSON: id must be a number".to_owned()),
    }
}

/// The envelope's `request` object.
///
/// A missing `request`, or a `request` that is not an object, is refused.
/// This reads no grant and stores nothing.
fn bridge_request(envelope: &Value) -> Result<&Value, String> {
    match envelope.get("request") {
        Some(request) if request.is_object() => Ok(request),
        _ => Err("Invalid JSON: request must be an object".to_owned()),
    }
}

/// The capability body `post_capability_request` already validates.
///
/// `resource` and `action` are copied as stored, including a missing key or a
/// non-string value. A missing `reason` is `""`. A present `reason` is copied
/// as stored. This function does not accept or refuse a field.
fn capability_fields(request: &Value) -> Value {
    let mut body = Map::new();
    if let Some(resource) = request.get("resource") {
        body.insert("resource".to_owned(), resource.clone());
    }
    if let Some(action) = request.get("action") {
        body.insert("action".to_owned(), action.clone());
    }
    let reason = match request.get("reason") {
        None => Value::String(String::new()),
        Some(reason) => reason.clone(),
    };
    body.insert("reason".to_owned(), reason);
    Value::Object(body)
}

/// The invoke `token` string, or `""` when `token` is absent.
///
/// A present value that is not a string is refused. This does not call
/// `authorise`.
fn invoke_token(request: &Value) -> Result<&str, String> {
    match request.get("token") {
        None => Ok(""),
        Some(Value::String(token)) => Ok(token),
        Some(_) => Err("Invalid JSON: token must be a string".to_owned()),
    }
}

/// The invoke `uri` string, or `""` when `uri` is absent or not a string.
fn invoke_uri(request: &Value) -> &str {
    request.get("uri").and_then(Value::as_str).unwrap_or("")
}

/// A protected invoke. Any other uri stays on the `authorise` arm.
fn protected_invoke(uri: &str) -> bool {
    uri.starts_with("localhost://Users/") || uri.starts_with("localhost://UsersAI/")
}

fn bridge_ok(data: Value) -> Value {
    json!({
        "type": "ok",
        "data": data,
    })
}

fn bridge_error(message: &str) -> Value {
    json!({
        "type": "error",
        "code": "denied",
        "message": message,
    })
}

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const DID_PROVIDER: &str = "did-provider";
const WALLET_PROVIDER: &str = "wallet-provider";
const DECLARED_CONFINED_OS: [&str; 1] = ["macos"];

/// Bytes one provider dialogue may write. A later write that would pass this
/// limit is refused and is not sent.
pub const STDIN_BYTE_LIMIT: usize = 4096;

/// How long one provider response may take. A silent child is a different
/// refusal from a child that has already exited.
pub const RESPONSE_DEADLINE: Duration = Duration::from_secs(5);

/// How long the provider may take to exit after `shutdown`.
pub const EXIT_DEADLINE: Duration = Duration::from_secs(10);

/// A simulated host report. `unavailable` is test input: a missing primitive
/// is refused on every OS, before the confinement-tool check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPrimitive {
    Landlock,
    UserNamespaces,
    SeccompFilter,
}

impl HostPrimitive {
    fn design_refusal(self) -> &'static str {
        match self {
            Self::Landlock => "linux confinement refused: the kernel has no Landlock",
            Self::UserNamespaces => "linux confinement refused: user namespaces are turned off",
            Self::SeccompFilter => {
                "linux confinement refused: the seccomp filter cannot be installed"
            }
        }
    }
}

/// The host the caller reports. This seam does not read a kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostReport {
    pub os: &'static str,
    pub unavailable: Option<HostPrimitive>,
}

/// The live child after `init` answered `status` `ok`.
pub struct StartedProvider<'a> {
    child: RunningChild<'a>,
    pub init: Value,
    pub binary_sha256: String,
    pub profile_sha256: String,
}

impl StartedProvider<'_> {
    /// One later request on the same child. The stdin limit and the response
    /// deadline are the refusals from the one spawn site.
    pub fn request(&mut self, body: &Value) -> Result<Value, String> {
        exchange(&mut self.child, body)
    }

    /// `shutdown` answered `ok` and the child exited 0.
    pub fn shutdown(mut self) -> Result<(), String> {
        let answer = match exchange(&mut self.child, &json!({ "op": "shutdown" })) {
            Ok(answer) => answer,
            Err(reason) => {
                let _ = self.child.stop();
                return Err(reason);
            }
        };
        if answer.get("status").and_then(Value::as_str) != Some("ok") {
            let _ = self.child.stop();
            return Err(format!("shutdown answered {answer}"));
        }
        let status = match self.child.wait_for_exit_within(EXIT_DEADLINE) {
            Ok(status) => status,
            Err(reason) => return Err(reason.to_string()),
        };
        if status.code() != Some(0) {
            return Err(format!("provider exit status {status}"));
        }
        Ok(())
    }
}

/// Lab test seam, not a route.
///
/// "Runtime verifies the principal and session, enforces capabilities, owns
/// lifecycle and audit, and routes the operation." Effect providers "do not
/// decide that an unverified caller is authorized." The caller passes the
/// profile path it already wrote. Started means that binary answered `init`
/// with `status` `ok`, and this value owns the live child. Refused carries a
/// nonempty reason and leaves no child. The storage root stays under the
/// borrowed home. An outside base, a `..` component, or a symlink is refused
/// before a directory is created and before a child starts. This seam stores
/// no key and no credential, and it does not mint a grant.
pub fn start_provider<'a>(
    home: &'a ThrowawayHome,
    binary_path: &Path,
    base_path: &Path,
    name: &str,
    host: HostReport,
    tool_path: &Path,
    profile_path: &Path,
) -> Result<StartedProvider<'a>, String> {
    host_refusal(name, host)?;
    let os = host.os;
    if !tool_path.is_file() {
        return Err(format!(
            "{name} start on {os} is refused: the confinement tool {} is absent",
            tool_path.display()
        ));
    }
    if tool_path != Path::new(SANDBOX_EXEC) {
        return Err(format!(
            "{name} start on {os} is refused: the confinement tool {} is not {SANDBOX_EXEC}, \
             which is the one the stand-in runs",
            tool_path.display()
        ));
    }
    let binary = launch_file(binary_path, name, "provider binary")?;
    let profile = launch_file(profile_path, name, "confinement profile")?;
    let root = storage_layout(name, base_path)?;
    // One check for the base, the parent `create_dir_all` would make, and the
    // `STORAGE_ROOT` binding. The layout path contains that base, and the
    // parent is its prefix. Refuse before creating a directory or binding it.
    if !crate::harness::directories_only(&root, home.root()) {
        return Err(format!(
            "{name} start is refused: the storage root {} stays under this home",
            root.display()
        ));
    }
    let parent = root.parent().ok_or_else(|| {
        format!(
            "{name} start is refused: the storage root {} has no parent",
            root.display()
        )
    })?;
    let binary_text = path_text(&binary, name, "provider binary")?;
    let profile_text = path_text(&profile, name, "confinement profile")?;
    let root_text = path_text(&root, name, "storage root")?;
    let parent_text = path_text(parent, name, "storage parent")?;
    let binary_sha256 = hash_file(&binary, name, "provider binary")?;
    let profile_sha256 = hash_file(&profile, name, "confinement profile")?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "{name} start is refused: the storage parent {} could not be created: {err}",
            parent.display()
        )
    })?;
    let mut arguments = Vec::new();
    arguments.push("-f".to_string());
    arguments.push(profile_text.to_string());
    arguments.push("-D".to_string());
    arguments.push(format!("STORAGE_ROOT={root_text}"));
    arguments.push("-D".to_string());
    arguments.push(format!("STORAGE_PARENT={parent_text}"));
    arguments.push("-D".to_string());
    arguments.push(format!("PROVIDER_EXECUTABLE={binary_text}"));
    arguments.push(binary_text.to_string());
    let program = tool_path;
    let arg_refs: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let mut child = match home.start_with_input(
        program,
        &arg_refs,
        ChildInput::Bounded {
            limit: STDIN_BYTE_LIMIT,
        },
    ) {
        Ok(child) => child,
        Err(reason) => return Err(format!("{name} start is refused: {reason}")),
    };
    let init_request = json!({
        "op": "init",
        "config": { "base_path": base_path.display().to_string() },
    });
    let init = match exchange(&mut child, &init_request) {
        Ok(init) => init,
        Err(reason) => {
            let _ = child.stop();
            return Err(format!("{name} start is refused: {reason}"));
        }
    };
    if init.get("status").and_then(Value::as_str) != Some("ok") {
        let _ = child.stop();
        return Err(format!("{name} start is refused: init answered {init}"));
    }
    Ok(StartedProvider {
        child,
        init,
        binary_sha256,
        profile_sha256,
    })
}

fn host_refusal(name: &str, host: HostReport) -> Result<(), String> {
    let confined_os = DECLARED_CONFINED_OS.join(", ");
    if let Some(primitive) = host.unavailable {
        let reason = primitive.design_refusal();
        return Err(format!("{name} start on {} is refused: {reason}", host.os));
    }
    if DECLARED_CONFINED_OS.contains(&host.os) {
        return Ok(());
    }
    let reason = if host.os == "linux" {
        format!(
            "linux is designed, not enforced, in this lab, so linux is not in \
             DECLARED_CONFINED_OS ({confined_os})"
        )
    } else {
        format!(
            "{} has no confinement design, and the lab stand-in applies confinement only on \
             {confined_os}",
            host.os
        )
    };
    Err(format!("{name} start on {} is refused: {reason}", host.os))
}

fn storage_layout(name: &str, base: &Path) -> Result<PathBuf, String> {
    match name {
        DID_PROVIDER => Ok(base.join("did")),
        WALLET_PROVIDER => Ok(base.join("ElastOS").join("SystemServices").join("Wallet")),
        other => Err(format!(
            "the stand-in serves only {DID_PROVIDER} and {WALLET_PROVIDER}, so {other} has no \
             storage root layout"
        )),
    }
}

// Resolve both launch files once in the caller's working directory. Hashing
// and execution then use the same absolute paths after spawn changes directory.
fn launch_file(path: &Path, name: &str, label: &str) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .ok()
        .filter(|resolved| resolved.is_file())
        .ok_or_else(|| {
            format!(
                "{name} start is refused: the {label} {} is not a file",
                path.display()
            )
        })
}

fn path_text<'a>(path: &'a Path, name: &str, label: &str) -> Result<&'a str, String> {
    path.to_str().ok_or_else(|| {
        format!(
            "{name} start is refused: the {label} {} is not UTF-8",
            path.display()
        )
    })
}

fn hash_file(path: &Path, name: &str, label: &str) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|err| {
        format!(
            "{name} start is refused: the {label} {} could not be read: {err}",
            path.display()
        )
    })?;
    Ok(identity::sha256(&bytes))
}

fn exchange(child: &mut RunningChild<'_>, body: &Value) -> Result<Value, String> {
    let mut line =
        serde_json::to_string(body).map_err(|_| "provider request is not JSON".to_string())?;
    line.push('\n');
    child
        .write_bounded(line.as_bytes())
        .map_err(str::to_owned)?;
    let response = child
        .read_line_within(RESPONSE_DEADLINE)
        .map_err(str::to_owned)?;
    serde_json::from_str(&response)
        .map_err(|_| format!("provider answered with invalid JSON: {response}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn keys(value: &Value) -> BTreeSet<String> {
        value
            .as_object()
            .expect("the stand-in returns an object")
            .keys()
            .cloned()
            .collect()
    }

    fn assert_keys(value: &Value, expected: &[&str], message: &str) {
        let expected: BTreeSet<String> = expected.iter().copied().map(str::to_owned).collect();
        assert_eq!(keys(value), expected, "{message}");
    }

    fn request_ids(body: &Value) -> BTreeSet<String> {
        body["capabilities"]
            .as_array()
            .expect("the stand-in returns a capability list")
            .iter()
            .map(|entry| {
                entry["request_id"]
                    .as_str()
                    .expect("the stand-in entry names request_id")
                    .to_owned()
            })
            .collect()
    }

    fn request_order(body: &Value) -> Vec<String> {
        body["capabilities"]
            .as_array()
            .expect("the stand-in returns a capability list")
            .iter()
            .map(|entry| entry["request_id"].as_str().unwrap().to_owned())
            .collect()
    }

    fn shell_pair(standin: &StandIn) -> (Value, Value) {
        let plain = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell plain view");
        let query = standin
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("the stand-in shell query view");
        (plain, query)
    }

    const SHELL_ENTRY: &[&str] = &[
        "action",
        "duration",
        "granted_at",
        "request_id",
        "resource",
        "session_id",
    ];

    const CLIENT_ENTRY: &[&str] = &["action", "duration", "granted_at", "request_id", "resource"];

    fn assert_entry_keys(body: &Value, expected: &[&str], message: &str) {
        for entry in body["capabilities"].as_array().unwrap() {
            assert_keys(entry, expected, message);
        }
    }

    #[test]
    fn standin_shell_sees_every_live_grant() {
        let mut standin = StandIn::new();
        standin.seed_grant(
            "req-b",
            "s-b",
            "res-b",
            "read",
            "once",
            30,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-z",
            "s-a",
            "res-z",
            "read",
            "session",
            20,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-a",
            "s-a",
            "res-a",
            "write",
            "once",
            10,
            Life::Live,
            true,
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-a".to_owned(), "req-b".to_owned(), "req-z".to_owned()]),
            "the stand-in lists every live grant"
        );
        assert_eq!(
            request_order(&plain),
            ["req-a", "req-z", "req-b"],
            "the stand-in sorts live grants by session then request"
        );
        assert_keys(
            &plain,
            &["capabilities", "scope"],
            "the stand-in shell view carries the scope marker",
        );
        assert_eq!(
            plain["scope"], "all_sessions_live",
            "the stand-in marks the shell view all_sessions_live"
        );
        assert_entry_keys(
            &plain,
            SHELL_ENTRY,
            "the stand-in shell entry carries the live-grant fields",
        );
        assert_eq!(
            plain,
            json!({
                "scope": "all_sessions_live",
                "capabilities": [
                    {
                        "request_id": "req-a",
                        "session_id": "s-a",
                        "resource": "res-a",
                        "action": "write",
                        "duration": "once",
                        "granted_at": 10,
                    },
                    {
                        "request_id": "req-z",
                        "session_id": "s-a",
                        "resource": "res-z",
                        "action": "read",
                        "duration": "session",
                        "granted_at": 20,
                    },
                    {
                        "request_id": "req-b",
                        "session_id": "s-b",
                        "resource": "res-b",
                        "action": "read",
                        "duration": "once",
                        "granted_at": 30,
                    },
                ],
            }),
            "the stand-in shell body is the seeded live grants"
        );
    }

    #[test]
    fn standin_empty_shell_view_has_the_scope_marker() {
        let standin = StandIn::new();
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one empty shell body for both route forms"
        );
        assert_keys(
            &plain,
            &["capabilities", "scope"],
            "the stand-in empty shell view has the scope marker",
        );
        assert_eq!(
            plain["scope"], "all_sessions_live",
            "the stand-in marks an empty shell view all_sessions_live"
        );
        assert_eq!(
            plain["capabilities"],
            json!([]),
            "the stand-in returns an empty capability list when nothing is live"
        );
    }

    #[test]
    fn standin_client_sees_only_its_own_grant() {
        let mut standin = StandIn::new();
        standin.seed_grant(
            "req-b",
            "s-own",
            "res-b",
            "read",
            "once",
            200,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-a",
            "s-own",
            "res-a",
            "read",
            "once",
            100,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-s",
            "s-sib",
            "res-s",
            "read",
            "once",
            300,
            Life::Live,
            false,
        );
        let own = standin
            .get_capability_list(
                Caller::Client {
                    session_id: "s-own",
                },
                None,
            )
            .expect("the stand-in client view");
        assert_eq!(
            request_ids(&own),
            BTreeSet::from(["req-a".to_owned(), "req-b".to_owned()]),
            "the stand-in lists the caller's live grants and leaves the sibling out"
        );
        assert_eq!(
            request_order(&own),
            ["req-a", "req-b"],
            "the stand-in sorts the caller's grants by request"
        );
        assert_keys(
            &own,
            &["capabilities"],
            "the stand-in client view is the capability list",
        );
        assert_entry_keys(
            &own,
            CLIENT_ENTRY,
            "the stand-in client entry leaves session_id out",
        );
        assert_eq!(
            own,
            json!({
                "capabilities": [
                    {
                        "request_id": "req-a",
                        "resource": "res-a",
                        "action": "read",
                        "duration": "once",
                        "granted_at": 100,
                    },
                    {
                        "request_id": "req-b",
                        "resource": "res-b",
                        "action": "read",
                        "duration": "once",
                        "granted_at": 200,
                    },
                ],
            }),
            "the stand-in client body is that session's live grants"
        );
        let empty = standin
            .get_capability_list(
                Caller::Client {
                    session_id: "s-none",
                },
                None,
            )
            .expect("the stand-in empty client view");
        assert_eq!(
            request_ids(&empty),
            BTreeSet::new(),
            "the stand-in returns an empty capability list for a client with no grant"
        );
        assert_eq!(
            empty,
            json!({ "capabilities": [] }),
            "the stand-in empty client view has no scope marker"
        );
    }

    #[test]
    fn standin_client_global_view_is_refused() {
        let mut standin = StandIn::new();
        standin.seed_grant(
            "req-a",
            "s-a",
            "res-a",
            "read",
            "once",
            1,
            Life::Live,
            false,
        );
        let client = standin.get_capability_list(
            Caller::Client { session_id: "s-a" },
            Some("all_sessions_live"),
        );
        assert!(
            matches!(
                &client,
                Err((403, reason)) if reason == "This endpoint requires shell privileges"
            ),
            "the stand-in refuses a client global view: {client:?}"
        );
        assert!(
            standin
                .get_capability_list(Caller::Shell, Some("all_sessions_live"))
                .is_ok(),
            "the stand-in shell view is available to the shell"
        );
    }

    #[test]
    fn standin_unknown_scope_is_refused() {
        let standin = StandIn::new();
        let callers = [Caller::Shell, Caller::Client { session_id: "s-a" }];
        for caller in callers {
            for scope in ["session", ""] {
                let result = standin.get_capability_list(caller, Some(scope));
                assert!(
                    matches!(
                        &result,
                        Err((400, reason))
                            if reason.starts_with("unknown capability list scope:")
                                && reason.contains(scope)
                                && reason == &format!("unknown capability list scope: {scope}")
                    ),
                    "the stand-in refuses unknown scope {scope:?}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn standin_dead_grants_stay_out() {
        let mut standin = StandIn::new();
        standin.seed_grant(
            "req-exhausted",
            "s-a",
            "res-e",
            "read",
            "once",
            1,
            Life::Exhausted,
            false,
        );
        standin.seed_grant(
            "req-revoked",
            "s-b",
            "res-r",
            "read",
            "once",
            2,
            Life::Revoked,
            false,
        );
        standin.seed_grant(
            "req-expired",
            "s-c",
            "res-x",
            "read",
            "once",
            3,
            Life::Expired,
            false,
        );
        standin.seed_grant(
            "req-live",
            "s-d",
            "res-l",
            "read",
            "once",
            4,
            Life::Live,
            false,
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-live".to_owned()]),
            "the stand-in leaves exhausted, revoked and expired grants out"
        );
    }

    const SHARED_PATH: &str = "/capsules/read-shared";
    const SHARED_NAME: &str = "read-shared";
    const AGENT_A_PATH: &str = "/capsules/agent-a";
    const AGENT_A_NAME: &str = "agent-a";
    const AGENT_B_PATH: &str = "/capsules/agent-b";
    const AGENT_B_NAME: &str = "agent-b";

    fn shared_body() -> Value {
        json!({ "path": SHARED_PATH })
    }

    fn agent_body(path: &str) -> Value {
        json!({ "path": path })
    }

    fn shell_list(standin: &StandIn) -> Value {
        standin
            .get_capsules(Caller::Shell)
            .expect("the stand-in shell capsule list")
    }

    fn assert_launch_400(result: &Result<Value, (u16, String)>, token: &str, message: &str) {
        assert!(
            matches!(result, Err((400, reason)) if reason.contains(token)),
            "{message}: {result:?}"
        );
    }

    fn assert_delete(
        result: &Result<Value, (u16, String)>,
        status: u16,
        reason: &str,
        message: &str,
    ) {
        assert!(
            matches!(
                result,
                Err((got_status, got_reason)) if *got_status == status && got_reason == reason
            ),
            "{message}: {result:?}"
        );
    }

    fn admit_shared(standin: &mut StandIn, start: Start) {
        standin
            .admit_resident(SHARED_PATH, SHARED_NAME, start)
            .expect("the stand-in admits the resident path");
    }

    fn launch_starting(standin: &mut StandIn) -> String {
        let launched = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches");
        launched["id"]
            .as_str()
            .expect("the stand-in names the launch")
            .to_owned()
    }

    fn launch_finished(standin: &mut StandIn) -> String {
        let id = launch_starting(standin);
        standin
            .finish_start(&id)
            .expect("the stand-in finishes start");
        id
    }

    fn stop_body() -> Value {
        json!({ "reason": "stop one" })
    }

    fn seed_at(standin: &mut StandIn, request_id: &str, session_id: &str, life: Life) {
        standin.seed_grant(
            request_id, session_id, "res", "read", "once", 1, life, false,
        );
    }

    fn grant_record(standin: &StandIn, request_id: &str) -> (Life, bool) {
        let grant = standin
            .grants
            .iter()
            .find(|grant| grant.request_id == request_id)
            .expect("the stand-in stores the seeded grant");
        (grant.life, grant.session_ended)
    }

    fn assert_capsule(standin: &StandIn, id: &str, status: &str, cause: &str, message: &str) {
        let listed = shell_list(standin);
        let entry = listed["capsules"]
            .as_array()
            .expect("the stand-in returns capsules")
            .iter()
            .find(|entry| entry["id"] == id);
        let expected = json!({
            "id": id,
            "name": SHARED_NAME,
            "status": status,
            "session_id": id,
            "cause": cause,
        });
        assert_eq!(entry, Some(&expected), "{message}");
    }

    fn assert_next_launch(standin: &mut StandIn, id: &str) {
        let launched = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches after a refused stop");
        assert_eq!(
            launched["id"], id,
            "the stand-in does not spend an id on a refused stop"
        );
    }

    const SHARED_RESOURCE: &str = "localhost://Public/resident-instances/shared.txt";

    const REQUEST_ENTRY: &[&str] = &[
        "action",
        "decision_reason",
        "reason",
        "request_id",
        "resource",
        "session_id",
        "settled_by",
        "status",
    ];

    fn seed_shared_request(standin: &mut StandIn, request_id: &str, session_id: &str) {
        standin
            .seed_request(
                request_id,
                session_id,
                SHARED_RESOURCE,
                "read",
                "read shared",
            )
            .expect("the stand-in seeds one pending request");
    }

    fn shell_requests(standin: &StandIn, session: &str) -> Value {
        standin
            .get_capability_requests(Caller::Shell, Some(session))
            .expect("the stand-in shell request record")
    }

    fn request_entries(standin: &StandIn, session: &str) -> Vec<Value> {
        shell_requests(standin, session)["requests"]
            .as_array()
            .expect("the stand-in returns a request list")
            .clone()
    }

    fn pending_count(standin: &StandIn) -> usize {
        standin
            .requests
            .iter()
            .filter(|request| request.status == RequestStatus::Pending)
            .count()
    }

    fn pending_request(request_id: &str, session_id: &str) -> Value {
        json!({
            "request_id": request_id,
            "session_id": session_id,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "pending",
            "decision_reason": "",
            "settled_by": Value::Null,
        })
    }

    fn denied_request(request_id: &str, session_id: &str, cause: &str) -> Value {
        json!({
            "request_id": request_id,
            "session_id": session_id,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "denied",
            "decision_reason": cause,
            "settled_by": "runtime",
        })
    }

    fn expired_request(request_id: &str, session_id: &str) -> Value {
        json!({
            "request_id": request_id,
            "session_id": session_id,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "expired",
            "decision_reason": "Request timed out",
            "settled_by": "runtime",
        })
    }

    fn shell_denied_request(request_id: &str, session_id: &str, cause: &str) -> Value {
        json!({
            "request_id": request_id,
            "session_id": session_id,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "denied",
            "decision_reason": cause,
            "settled_by": "shell",
        })
    }

    fn granted_request(request_id: &str, session_id: &str, rationale: &str) -> Value {
        json!({
            "request_id": request_id,
            "session_id": session_id,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "granted",
            "decision_reason": rationale,
            "settled_by": "shell",
        })
    }

    fn assert_request_refused(result: &Result<(), (u16, String)>, reason: &str, message: &str) {
        assert!(
            matches!(
                result,
                Err((400, got)) if got == reason
            ),
            "{message}: {result:?}"
        );
    }

    #[test]
    fn standin_one_admit_per_path() {
        let mut standin = StandIn::new();
        let empty_path = standin.admit_resident("", SHARED_NAME, Start::Ok);
        assert!(
            matches!(
                &empty_path,
                Err((400, reason)) if reason == "resident admit needs a path and a name"
            ),
            "the stand-in refuses an empty resident path: {empty_path:?}"
        );
        let empty_name = standin.admit_resident(SHARED_PATH, "", Start::Ok);
        assert!(
            matches!(
                &empty_name,
                Err((400, reason)) if reason == "resident admit needs a path and a name"
            ),
            "the stand-in refuses an empty resident name: {empty_name:?}"
        );
        standin
            .admit_resident(SHARED_PATH, SHARED_NAME, Start::Ok)
            .expect("the stand-in admits one resident path");
        let second = standin.admit_resident(
            SHARED_PATH,
            SHARED_NAME,
            Start::Error("replaced".to_owned()),
        );
        assert!(
            matches!(
                &second,
                Err((400, reason))
                    if reason.starts_with("resident path already admitted:")
                        && reason.contains(SHARED_PATH)
            ),
            "the stand-in keeps the first admit: {second:?}"
        );
        let launched = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches the first admit");
        let id = launched["id"]
            .as_str()
            .expect("the stand-in names the launch");
        standin
            .finish_start(id)
            .expect("the stand-in follows the first Start");
        assert_eq!(
            shell_list(&standin)["capsules"][0]["status"],
            "running",
            "the stand-in finish_start follows the first Start::Ok"
        );
    }

    #[test]
    fn standin_unadmitted_path_is_refused() {
        let mut standin = StandIn::new();
        let result = standin.post_capsules(Caller::Shell, &shared_body());
        assert!(
            matches!(
                &result,
                Err((400, reason))
                    if reason.starts_with("not a resident component:")
                        && reason.contains(SHARED_PATH)
                        && reason.contains("resident-capsule")
            ),
            "the stand-in refuses an unadmitted path: {result:?}"
        );
        standin
            .admit_resident(SHARED_PATH, SHARED_NAME, Start::Ok)
            .expect("the stand-in admits the path after the refusal");
        let launched = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches once the path is admitted");
        assert_eq!(
            launched["id"], "component-1",
            "the stand-in does not spend an id on an unadmitted path"
        );
    }

    #[test]
    fn standin_launch_body_is_path_only() {
        let mut standin = StandIn::new();
        standin
            .admit_resident(SHARED_PATH, SHARED_NAME, Start::Ok)
            .expect("the stand-in admits the resident path");
        let missing = standin.post_capsules(Caller::Shell, &json!({}));
        assert_launch_400(
            &missing,
            "path",
            "the stand-in refuses a launch body with no path",
        );
        let numeric = standin.post_capsules(Caller::Shell, &json!({"path": 1}));
        assert_launch_400(
            &numeric,
            "path",
            "the stand-in refuses a launch path that is not a string",
        );
        let extra =
            standin.post_capsules(Caller::Shell, &json!({"path": SHARED_PATH, "cid": "bafy"}));
        assert_launch_400(
            &extra,
            "cid",
            "the stand-in refuses a launch body with an extra key",
        );
        let not_object = standin.post_capsules(Caller::Shell, &Value::Null);
        assert_launch_400(
            &not_object,
            "path",
            "the stand-in refuses a launch body that is not an object",
        );
        let principal = standin.post_capsules(
            Caller::Shell,
            &json!({"path": SHARED_PATH, "principal_id": "person"}),
        );
        assert_launch_400(
            &principal,
            "principal_id",
            "the stand-in refuses principal_id on the launch body",
        );
        let grant = standin.post_capsules(
            Caller::Shell,
            &json!({"path": SHARED_PATH, "launch_grant": "token"}),
        );
        assert_launch_400(
            &grant,
            "launch_grant",
            "the stand-in refuses launch_grant on the launch body",
        );
        let launched = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches after the refused bodies");
        assert_eq!(
            launched["id"], "component-1",
            "the stand-in does not spend an id on a refused launch body"
        );
    }

    #[test]
    fn standin_launch_returns_before_start() {
        let mut standin = StandIn::new();
        standin
            .admit_resident(SHARED_PATH, SHARED_NAME, Start::Ok)
            .expect("the stand-in admits the resident path");
        assert_eq!(
            shell_list(&standin),
            json!({ "capsules": [] }),
            "the stand-in lists no instance before launch"
        );
        let launched = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches before start returns");
        assert_eq!(
            launched,
            json!({
                "id": "component-1",
                "name": SHARED_NAME,
                "status": "starting",
                "session_id": "component-1",
            }),
            "the stand-in returns starting and the Bus session before start finishes"
        );
        assert_keys(
            &launched,
            &["id", "name", "session_id", "status"],
            "the stand-in launch value carries id, name, status and session_id",
        );
        let listed = shell_list(&standin);
        assert_eq!(
            listed["capsules"][0],
            json!({
                "id": "component-1",
                "name": SHARED_NAME,
                "status": "starting",
                "session_id": "component-1",
                "cause": "",
            }),
            "the stand-in lists the instance as starting with an empty cause"
        );
        assert_keys(
            &listed["capsules"][0],
            &["cause", "id", "name", "session_id", "status"],
            "the stand-in list entry carries id, name, status, session_id and cause",
        );
    }

    #[test]
    fn standin_two_launches_are_two_instances() {
        let mut standin = StandIn::new();
        standin
            .admit_resident(SHARED_PATH, SHARED_NAME, Start::Ok)
            .expect("the stand-in admits the resident path");
        let first = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in first launch");
        let second = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in second launch");
        assert_eq!(
            first["id"], "component-1",
            "the stand-in numbers the first launch component-1"
        );
        assert_eq!(
            second["id"], "component-2",
            "the stand-in numbers the second launch component-2"
        );
        assert_eq!(
            first["session_id"], first["id"],
            "the stand-in uses the first launch id as its Bus session"
        );
        assert_eq!(
            second["session_id"], second["id"],
            "the stand-in uses the second launch id as its Bus session"
        );
        let listed = shell_list(&standin);
        assert_keys(
            &listed,
            &["capsules"],
            "the stand-in capsule list has one key",
        );
        assert_eq!(
            listed,
            json!({
                "capsules": [
                    {
                        "id": "component-1",
                        "name": SHARED_NAME,
                        "status": "starting",
                        "session_id": "component-1",
                        "cause": "",
                    },
                    {
                        "id": "component-2",
                        "name": SHARED_NAME,
                        "status": "starting",
                        "session_id": "component-2",
                        "cause": "",
                    },
                ]
            }),
            "the stand-in lists both instances sorted by id"
        );
    }

    #[test]
    fn standin_two_agent_components_stay_resident() {
        let mut standin = StandIn::new();
        standin
            .admit_resident(AGENT_A_PATH, AGENT_A_NAME, Start::Ok)
            .expect("the stand-in admits agent-a");
        standin
            .admit_resident(AGENT_B_PATH, AGENT_B_NAME, Start::Ok)
            .expect("the stand-in admits agent-b");
        let first = standin
            .post_capsules(Caller::Shell, &agent_body(AGENT_A_PATH))
            .expect("the stand-in launches agent-a");
        let second = standin
            .post_capsules(Caller::Shell, &agent_body(AGENT_B_PATH))
            .expect("the stand-in launches agent-b");
        assert_eq!(
            first["id"], "component-1",
            "the stand-in numbers the agent-a launch component-1"
        );
        assert_eq!(
            second["id"], "component-2",
            "the stand-in numbers the agent-b launch component-2"
        );
        assert_eq!(
            first["session_id"], first["id"],
            "the stand-in uses the agent-a launch id as its Bus session"
        );
        assert_eq!(
            second["session_id"], second["id"],
            "the stand-in uses the agent-b launch id as its Bus session"
        );
        assert_eq!(
            first["name"], AGENT_A_NAME,
            "the stand-in names the agent-a launch from its admitted path"
        );
        assert_eq!(
            second["name"], AGENT_B_NAME,
            "the stand-in names the agent-b launch from its admitted path"
        );
        assert_eq!(
            shell_list(&standin),
            json!({
                "capsules": [
                    {
                        "id": "component-1",
                        "name": AGENT_A_NAME,
                        "status": "starting",
                        "session_id": "component-1",
                        "cause": "",
                    },
                    {
                        "id": "component-2",
                        "name": AGENT_B_NAME,
                        "status": "starting",
                        "session_id": "component-2",
                        "cause": "",
                    },
                ]
            }),
            "the stand-in lists both agent components starting after both launches"
        );
        standin
            .finish_start("component-1")
            .expect("the stand-in applies agent-a Start::Ok");
        standin
            .finish_start("component-2")
            .expect("the stand-in applies agent-b Start::Ok");
        let running = shell_list(&standin);
        assert_eq!(
            running,
            json!({
                "capsules": [
                    {
                        "id": "component-1",
                        "name": AGENT_A_NAME,
                        "status": "running",
                        "session_id": "component-1",
                        "cause": "",
                    },
                    {
                        "id": "component-2",
                        "name": AGENT_B_NAME,
                        "status": "running",
                        "session_id": "component-2",
                        "cause": "",
                    },
                ]
            }),
            "the stand-in lists both agent components running with distinct ids after start returned"
        );
        standin.set_instant(60);
        assert_eq!(
            shell_list(&standin),
            running,
            "the stand-in still lists both running agent components at test instant 60"
        );
        assert_eq!(
            standin.delete_capsule(Caller::Shell, "component-1", &stop_body()),
            Ok(Value::Null),
            "the stand-in stops component-1 and answers null"
        );
        let after_stop = shell_list(&standin);
        assert_eq!(
            after_stop["capsules"][0],
            json!({
                "id": "component-1",
                "name": AGENT_A_NAME,
                "status": "stopped",
                "session_id": "component-1",
                "cause": "stopped: stop one",
            }),
            "the stand-in lists component-1 stopped with the stop cause"
        );
        assert_eq!(
            after_stop["capsules"][1],
            json!({
                "id": "component-2",
                "name": AGENT_B_NAME,
                "status": "running",
                "session_id": "component-2",
                "cause": "",
            }),
            "the stand-in keeps component-2 running as agent-b after the sibling stop"
        );
        assert_eq!(
            after_stop["capsules"]
                .as_array()
                .expect("the stand-in returns capsules")
                .len(),
            2,
            "the stand-in lists exactly the two agent components after one stop"
        );
    }

    #[test]
    fn standin_start_ok_is_running() {
        let mut standin = StandIn::new();
        standin
            .admit_resident(SHARED_PATH, SHARED_NAME, Start::Ok)
            .expect("the stand-in admits the resident path");
        let launched = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launch");
        let id = launched["id"]
            .as_str()
            .expect("the stand-in names the launch")
            .to_owned();
        standin
            .finish_start(&id)
            .expect("the stand-in applies Start::Ok");
        assert_eq!(
            shell_list(&standin)["capsules"][0],
            json!({
                "id": "component-1",
                "name": SHARED_NAME,
                "status": "running",
                "session_id": "component-1",
                "cause": "",
            }),
            "the stand-in stores running with an empty cause when start returns ok"
        );
        standin.set_instant(60);
        assert_eq!(
            shell_list(&standin)["capsules"][0]["status"],
            "running",
            "the stand-in keeps a running instance at instant 60"
        );
    }

    #[test]
    fn standin_bad_start_is_failed() {
        for (start, cause) in [
            (Start::Error("start refused".to_owned()), "start refused"),
            (Start::Trap("trap: fuel".to_owned()), "trap: fuel"),
        ] {
            let mut standin = StandIn::new();
            standin
                .admit_resident(SHARED_PATH, SHARED_NAME, start)
                .expect("the stand-in admits the resident path");
            let launched = standin
                .post_capsules(Caller::Shell, &shared_body())
                .expect("the stand-in launch");
            let id = launched["id"]
                .as_str()
                .expect("the stand-in names the launch")
                .to_owned();
            standin
                .finish_start(&id)
                .expect("the stand-in applies the bad start");
            assert_eq!(
                shell_list(&standin)["capsules"][0],
                json!({
                    "id": "component-1",
                    "name": SHARED_NAME,
                    "status": "failed",
                    "session_id": "component-1",
                    "cause": cause,
                }),
                "the stand-in lists a failed start with its cause"
            );
        }
    }

    #[test]
    fn standin_failed_stays_for_sixty_seconds() {
        let mut standin = StandIn::new();
        standin.set_instant(0);
        standin
            .admit_resident(
                SHARED_PATH,
                SHARED_NAME,
                Start::Error("start refused".to_owned()),
            )
            .expect("the stand-in admits the resident path");
        let launched = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launch");
        let id = launched["id"]
            .as_str()
            .expect("the stand-in names the launch")
            .to_owned();
        standin
            .finish_start(&id)
            .expect("the stand-in applies the failed start");
        let at_zero = shell_list(&standin);
        assert_eq!(
            at_zero["capsules"][0]["status"], "failed",
            "the stand-in lists a failed instance at instant 0"
        );
        assert_eq!(
            at_zero["capsules"][0]["cause"], "start refused",
            "the stand-in keeps the failed cause at instant 0"
        );
        standin.set_instant(59);
        assert_eq!(
            shell_list(&standin)["capsules"][0]["status"],
            "failed",
            "the stand-in lists a failed instance at instant 59"
        );
        standin.set_instant(60);
        assert_eq!(
            shell_list(&standin),
            json!({ "capsules": [] }),
            "the stand-in omits a failed instance at instant 60"
        );
    }

    #[test]
    fn standin_start_returns_once() {
        let mut standin = StandIn::new();
        standin
            .admit_resident(SHARED_PATH, SHARED_NAME, Start::Ok)
            .expect("the stand-in admits the resident path");
        let launched = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launch");
        let id = launched["id"]
            .as_str()
            .expect("the stand-in names the launch")
            .to_owned();
        standin
            .finish_start(&id)
            .expect("the stand-in applies the first start");
        let second = standin.finish_start(&id);
        assert!(
            matches!(
                &second,
                Err((400, reason)) if reason == "start already returned"
            ),
            "the stand-in accepts start once: {second:?}"
        );
        assert_eq!(
            shell_list(&standin)["capsules"][0]["status"],
            "running",
            "the stand-in keeps running after a second start"
        );
        let unknown = standin.finish_start("component-9");
        assert!(
            matches!(
                &unknown,
                Err((400, reason)) if reason == "unknown instance: component-9"
            ),
            "the stand-in refuses an unknown instance: {unknown:?}"
        );
        assert_eq!(
            shell_list(&standin)["capsules"][0]["status"],
            "running",
            "the stand-in leaves the running instance in place"
        );

        let mut failed = StandIn::new();
        admit_shared(&mut failed, Start::Error("start refused".to_owned()));
        let failed_id = launch_finished(&mut failed);
        let second_failed = failed.finish_start(&failed_id);
        assert!(
            matches!(
                &second_failed,
                Err((400, reason)) if reason == "start already returned"
            ),
            "the stand-in accepts start once on a failed instance: {second_failed:?}"
        );
        assert_capsule(
            &failed,
            &failed_id,
            "failed",
            "start refused",
            "the stand-in keeps the failed cause after a second start",
        );
    }

    #[test]
    fn standin_client_cannot_launch_or_list() {
        let mut standin = StandIn::new();
        standin
            .admit_resident(SHARED_PATH, SHARED_NAME, Start::Ok)
            .expect("the stand-in admits the resident path");
        let client = Caller::Client {
            session_id: "s-client",
        };
        let launch = standin.post_capsules(client, &shared_body());
        let list = standin.get_capsules(client);
        assert!(
            matches!(
                &launch,
                Err((403, reason)) if reason == "This endpoint requires shell privileges"
            ) && matches!(
                &list,
                Err((403, reason)) if reason == "This endpoint requires shell privileges"
            ),
            "the stand-in refuses a client launch and list: {launch:?} {list:?}"
        );
        let listed = shell_list(&standin);
        assert_eq!(
            listed,
            json!({ "capsules": [] }),
            "the stand-in shell list stays available"
        );
        let launched = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in shell launch");
        assert_eq!(
            launched["id"], "component-1",
            "the stand-in does not spend an id on a refused client launch"
        );
    }

    #[test]
    fn standin_stop_sets_stopped() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let id = launch_finished(&mut standin);
        assert_eq!(
            id, "component-1",
            "the stand-in names the first launch component-1"
        );
        let stopped = standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops one running instance");
        assert!(
            stopped.is_null(),
            "the stand-in answers null when it stops one instance"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in stores stopped with the stop reason",
        );
        let later = standin.finish_start("component-1");
        assert!(
            matches!(
                &later,
                Err((400, reason)) if reason == "instance is not live: stopped"
            ),
            "the stand-in refuses finish_start after a stop: {later:?}"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in keeps stopped after finish_start",
        );
    }

    #[test]
    fn standin_stop_body_is_reason_only() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        let cases = [
            (Value::Null, "stop body needs reason"),
            (json!({}), "stop body misses reason"),
            (json!({ "reason": 1 }), "stop reason must be a string"),
            (json!({ "reason": "" }), "stop needs a reason"),
            (
                json!({ "reason": "stop one", "cid": "bafy" }),
                "stop body rejects cid",
            ),
        ];
        for (body, reason) in cases {
            let result = standin.delete_capsule(Caller::Shell, "component-1", &body);
            let message = format!("the stand-in refuses this stop body: {reason}");
            assert_delete(&result, 400, reason, &message);
            assert_capsule(
                &standin,
                "component-1",
                "running",
                "",
                "the stand-in leaves the running instance unchanged",
            );
            assert_eq!(
                grant_record(&standin, "req-1"),
                (Life::Live, false),
                "the stand-in leaves the live grant unchanged"
            );
        }
        assert_next_launch(&mut standin, "component-2");
    }

    #[test]
    fn standin_unknown_stop_is_refused() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        let unknown = standin.delete_capsule(Caller::Shell, "component-9", &stop_body());
        assert_delete(
            &unknown,
            400,
            "unknown instance: component-9",
            "the stand-in refuses an unknown stop",
        );
        let empty = standin.delete_capsule(Caller::Shell, "", &stop_body());
        assert_delete(
            &empty,
            400,
            "unknown instance: ",
            "the stand-in refuses a stop of an empty id",
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in leaves the known instance unchanged",
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Live, false),
            "the stand-in leaves the seeded grant live"
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in still lists the seeded live grant"
        );
        assert_next_launch(&mut standin, "component-2");
    }

    #[test]
    fn standin_stop_refuses_a_failed_instance() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Error("start refused".to_owned()));
        launch_finished(&mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        let result = standin.delete_capsule(Caller::Shell, "component-1", &stop_body());
        assert_delete(
            &result,
            400,
            "instance is not live: failed",
            "the stand-in refuses to stop a failed instance",
        );
        assert_capsule(
            &standin,
            "component-1",
            "failed",
            "start refused",
            "the stand-in keeps the failed cause",
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Live, false),
            "the stand-in leaves a live grant on a refused stop"
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in still lists the live grant"
        );
        assert_next_launch(&mut standin, "component-2");
    }

    #[test]
    fn standin_stop_revokes_that_sessions_grants() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        launch_finished(&mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        seed_at(&mut standin, "req-1b", "component-1", Life::Live);
        seed_at(&mut standin, "req-e", "component-1", Life::Exhausted);
        seed_at(&mut standin, "req-r", "component-1", Life::Revoked);
        seed_at(&mut standin, "req-x", "component-1", Life::Expired);
        seed_at(&mut standin, "req-2", "component-2", Life::Live);
        let stopped = standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        assert!(
            stopped.is_null(),
            "the stand-in answers null when it revokes that session"
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Revoked, false),
            "the stand-in revokes that session's live grant"
        );
        assert_eq!(
            grant_record(&standin, "req-1b"),
            (Life::Revoked, false),
            "the stand-in revokes every live grant of that session"
        );
        assert_eq!(
            grant_record(&standin, "req-e"),
            (Life::Exhausted, false),
            "the stand-in leaves an exhausted grant exhausted"
        );
        assert_eq!(
            grant_record(&standin, "req-r"),
            (Life::Revoked, false),
            "the stand-in leaves a revoked grant revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-x"),
            (Life::Expired, false),
            "the stand-in leaves an expired grant expired"
        );
        assert_eq!(
            grant_record(&standin, "req-2"),
            (Life::Live, false),
            "the stand-in leaves the sibling session's grant live"
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-2".to_owned()]),
            "the stand-in lists the sibling grant and leaves the revoked grants out"
        );
        let client = standin
            .get_capability_list(
                Caller::Client {
                    session_id: "component-1",
                },
                None,
            )
            .expect("the stand-in client view");
        assert_eq!(
            request_ids(&client),
            BTreeSet::new(),
            "the stand-in client view is empty after the stop"
        );
    }

    #[test]
    fn standin_stop_leaves_the_sibling() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        launch_finished(&mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        seed_at(&mut standin, "req-2", "component-2", Life::Live);
        let stopped = standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        assert!(
            stopped.is_null(),
            "the stand-in answers null when it stops one sibling"
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves the sibling running",
        );
        assert_eq!(
            grant_record(&standin, "req-2"),
            (Life::Live, false),
            "the stand-in leaves the sibling grant live"
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-2".to_owned()]),
            "the stand-in still lists the sibling grant"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in stops only the named instance",
        );
    }

    #[test]
    fn standin_stop_denies_that_sessions_pending() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        launch_finished(&mut standin);
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        seed_at(&mut standin, "req-g", "component-1", Life::Live);
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        assert_eq!(
            shell_requests(&standin, "component-1"),
            json!({
                "requests": [denied_request(
                    "req-1",
                    "component-1",
                    "stopped: stop one",
                )],
            }),
            "the stand-in denies the stopped instance's pending request and names the stop"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::new(),
            "the stand-in shell live-grant list is empty after the stop"
        );
        assert_eq!(
            request_entries(&standin, "component-1")
                .iter()
                .filter(|entry| entry["request_id"] == "req-g")
                .count(),
            0,
            "the stand-in request record does not list the revoked grant"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling's pending request"
        );
        standin.set_instant(60);
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![denied_request("req-1", "component-1", "stopped: stop one")],
            "the stand-in returns the denied request at instant 60"
        );

        let mut multi = StandIn::new();
        admit_shared(&mut multi, Start::Ok);
        launch_finished(&mut multi);
        seed_shared_request(&mut multi, "req-b", "component-1");
        seed_shared_request(&mut multi, "req-a", "component-1");
        multi
            .delete_capsule(
                Caller::Shell,
                "component-1",
                &json!({ "reason": "cancel the run" }),
            )
            .expect("the stand-in stops component-1 with another reason");
        assert_eq!(
            request_entries(&multi, "component-1"),
            vec![
                denied_request("req-a", "component-1", "stopped: cancel the run"),
                denied_request("req-b", "component-1", "stopped: cancel the run"),
            ],
            "the stand-in denies every pending request of that session, sorted, with that stop reason"
        );
    }

    #[test]
    fn standin_stop_leaves_the_siblings_request() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        launch_finished(&mut standin);
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        let sibling = request_entries(&standin, "component-2");
        assert_eq!(
            sibling,
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling's request pending"
        );
        assert!(
            sibling[0]["settled_by"].is_null(),
            "the stand-in leaves the sibling request with no settler"
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves the sibling running",
        );
    }

    #[test]
    fn standin_failed_start_denies_that_sessions_pending() {
        let cases = [
            (Start::Error("start refused".to_owned()), "start refused"),
            (Start::Trap("start trapped".to_owned()), "start trapped"),
        ];
        for (start, cause) in cases {
            let mut standin = StandIn::new();
            admit_shared(&mut standin, start);
            launch_starting(&mut standin);
            seed_shared_request(&mut standin, "req-1", "component-1");
            standin
                .finish_start("component-1")
                .expect("the stand-in finishes a failed start");
            assert_eq!(
                request_entries(&standin, "component-1"),
                vec![denied_request("req-1", "component-1", cause)],
                "the stand-in denies the failed start's pending request with {cause}"
            );
            assert_capsule(
                &standin,
                "component-1",
                "failed",
                cause,
                "the stand-in stores the failed start cause",
            );
        }
    }

    #[test]
    fn standin_failed_start_leaves_the_siblings_request() {
        const FAILING_PATH: &str = "/capsules/fail-after-submit";
        const FAILING_NAME: &str = "fail-after-submit";

        let mut standin = StandIn::new();
        standin
            .admit_resident(
                FAILING_PATH,
                FAILING_NAME,
                Start::Error("start refused".to_owned()),
            )
            .expect("the stand-in admits the failing path");
        admit_shared(&mut standin, Start::Ok);
        let failing = standin
            .post_capsules(Caller::Shell, &agent_body(FAILING_PATH))
            .expect("the stand-in launches the failing path");
        let sibling = standin
            .post_capsules(Caller::Shell, &agent_body(SHARED_PATH))
            .expect("the stand-in launches the shared path");
        assert_eq!(
            failing["id"], "component-1",
            "the stand-in numbers the failing launch component-1"
        );
        assert_eq!(
            sibling["id"], "component-2",
            "the stand-in numbers the sibling launch component-2"
        );
        assert_eq!(
            failing["status"], "starting",
            "the stand-in answers starting for the failing launch"
        );
        assert_eq!(
            sibling["status"], "starting",
            "the stand-in answers starting for the sibling launch"
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes the failing start");
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![denied_request("req-1", "component-1", "start refused")],
            "the stand-in denies the failed instance's request with the failure cause"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling's request pending after the failed start"
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in leaves the sibling starting",
        );
        standin
            .finish_start("component-2")
            .expect("the stand-in finishes the sibling start");
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling's request pending after an Ok start"
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves the sibling running after an Ok start",
        );
        assert!(
            standin.grants.is_empty(),
            "the stand-in mints no grant from a pending request"
        );
    }

    #[test]
    fn standin_refused_finish_start_preserves_requests() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        seed_shared_request(&mut standin, "req-1", "component-1");

        let second = standin.finish_start("component-1");
        assert!(
            matches!(&second, Err((400, reason)) if reason == "start already returned"),
            "the stand-in refuses a second start: {second:?}"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in leaves the request pending after a second start"
        );

        let unknown = standin.finish_start("component-9");
        assert!(
            matches!(&unknown, Err((400, reason)) if reason == "unknown instance: component-9"),
            "the stand-in refuses an unknown instance: {unknown:?}"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in leaves the request pending after an unknown instance"
        );

        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        seed_shared_request(&mut standin, "req-2", "component-1");
        let stopped = standin.finish_start("component-1");
        assert!(
            matches!(&stopped, Err((400, reason)) if reason == "instance is not live: stopped"),
            "the stand-in refuses a start after a stop: {stopped:?}"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                denied_request("req-1", "component-1", "stopped: stop one"),
                pending_request("req-2", "component-1"),
            ],
            "the stand-in keeps the stop settlement and leaves the later request pending"
        );

        let mut failed = StandIn::new();
        admit_shared(&mut failed, Start::Error("start refused".to_owned()));
        launch_starting(&mut failed);
        seed_shared_request(&mut failed, "req-3", "component-1");
        failed
            .finish_start("component-1")
            .expect("the stand-in finishes the failing start");
        let second_failed = failed.finish_start("component-1");
        assert!(
            matches!(&second_failed, Err((400, reason)) if reason == "start already returned"),
            "the stand-in refuses a second failed start: {second_failed:?}"
        );
        assert_eq!(
            request_entries(&failed, "component-1"),
            vec![denied_request("req-3", "component-1", "start refused")],
            "the stand-in keeps the failure settlement after a refused second start"
        );
    }

    #[test]
    fn standin_requests_are_shell_only() {
        let mut standin = StandIn::new();
        seed_shared_request(&mut standin, "req-1", "component-1");
        for session in [Some("component-1"), None, Some("")] {
            let client = standin.get_capability_requests(
                Caller::Client {
                    session_id: "component-1",
                },
                session,
            );
            assert!(
                matches!(
                    &client,
                    Err((403, reason)) if reason == "This endpoint requires shell privileges"
                ),
                "the stand-in refuses a client request record for session {session:?}: {client:?}"
            );
        }
        for session in [None, Some("")] {
            let shell = standin.get_capability_requests(Caller::Shell, session);
            assert!(
                matches!(&shell, Err((400, reason)) if reason == "requests need a session"),
                "the stand-in refuses a shell request record without a session: {shell:?}"
            );
        }
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in returns a shell request record for a valid session"
        );
    }

    #[test]
    fn standin_shell_deny_fails_the_waiting_sibling() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let first = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches the first read-shared instance");
        let second = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches the second read-shared instance");
        assert_eq!(
            first["id"], "component-1",
            "the stand-in numbers the first launch component-1"
        );
        assert_eq!(
            second["id"], "component-2",
            "the stand-in numbers the second launch component-2"
        );
        assert_eq!(
            first["status"], "starting",
            "the stand-in answers starting for the first launch"
        );
        assert_eq!(
            second["status"], "starting",
            "the stand-in answers starting for the second launch"
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        seed_shared_request(&mut standin, "req-extra", "component-2");
        standin.seed_grant(
            "req-g",
            "component-1",
            SHARED_RESOURCE,
            "read",
            "session",
            0,
            Life::Live,
            false,
        );
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes the granted instance start");

        let denied = standin
            .post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": "req-2", "reason": "sibling read denied" }),
            )
            .expect("the stand-in denies the waiting sibling request");
        assert_keys(&denied, &["success"], "the stand-in deny body has one key");
        assert_eq!(
            denied,
            json!({ "success": true }),
            "the stand-in answers success true for the shell deny"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![
                shell_denied_request("req-2", "component-2", "sibling read denied"),
                denied_request("req-extra", "component-2", "sibling read denied"),
            ],
            "the stand-in denies the named request as shell and settles req-extra as runtime"
        );
        assert_eq!(
            request_entries(&standin, "component-2")[1]["settled_by"],
            json!("runtime"),
            "the stand-in settles the other pending request as runtime when the session fails"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in leaves the first instance's request pending"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in keeps the first instance running with its grant",
        );
        assert_capsule(
            &standin,
            "component-2",
            "failed",
            "sibling read denied",
            "the stand-in ends the waiting instance failed with the deny reason",
        );
        let live = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live view");
        assert_eq!(
            request_ids(&live),
            BTreeSet::from(["req-g".to_owned()]),
            "the stand-in still shows exactly the first instance's live grant"
        );
        standin
            .authorise(
                Caller::Client {
                    session_id: "component-1",
                },
                "req-g",
            )
            .expect("the stand-in authorises the first instance with its grant");
        let sibling = standin.authorise(
            Caller::Client {
                session_id: "component-2",
            },
            "req-g",
        );
        assert!(
            matches!(&sibling, Err((403, reason)) if reason.contains("wrong capsule")),
            "the stand-in refuses the sibling presentation of the first instance's grant: {sibling:?}"
        );

        let refused_start = standin.finish_start("component-2");
        assert!(
            matches!(&refused_start, Err((400, reason)) if reason == "start already returned"),
            "the stand-in refuses finish_start for the denied instance: {refused_start:?}"
        );
        assert_capsule(
            &standin,
            "component-2",
            "failed",
            "sibling read denied",
            "the stand-in keeps the deny reason after the refused start",
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![
                shell_denied_request("req-2", "component-2", "sibling read denied"),
                denied_request("req-extra", "component-2", "sibling read denied"),
            ],
            "the stand-in keeps the shell deny after the refused start"
        );

        assert_eq!(
            standin.post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": "req-extra", "reason": "still denied" }),
            ),
            Err((400, "request is not pending: req-extra".to_owned())),
            "the stand-in keeps the failure settlement when the shell denies that request again"
        );
        seed_shared_request(&mut standin, "req-late", "component-2");
        standin
            .post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": "req-late", "reason": "still denied" }),
            )
            .expect("the stand-in denies a seeded request of the failed instance");
        assert_capsule(
            &standin,
            "component-2",
            "failed",
            "sibling read denied",
            "the stand-in keeps a failed instance's phase and cause after a later shell deny",
        );
    }

    #[test]
    fn standin_shell_deny_refuses_a_bad_request() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let id = launch_finished(&mut standin);
        seed_shared_request(&mut standin, "req-1", &id);

        let client = standin.post_capability_deny(
            Caller::Client {
                session_id: "component-1",
            },
            &json!({ "request_id": "req-1" }),
        );
        assert!(
            matches!(&client, Err((403, reason)) if reason == "This endpoint requires shell privileges"),
            "the stand-in refuses a client deny before reading the body: {client:?}"
        );

        for body in [json!({}), json!("req-1")] {
            let refused = standin.post_capability_deny(Caller::Shell, &body);
            assert!(
                matches!(&refused, Err((400, reason)) if reason == "deny body needs request_id"),
                "the stand-in refuses a deny body without request_id: {refused:?}"
            );
        }
        for (body, reason) in [
            (
                json!({ "request_id": 4 }),
                "deny request_id must be a string",
            ),
            (
                json!({ "request_id": "req-1", "reason": 4 }),
                "deny reason must be a string",
            ),
        ] {
            let refused = standin.post_capability_deny(Caller::Shell, &body);
            assert!(
                matches!(&refused, Err((400, got)) if got == reason),
                "the stand-in refuses a non-string deny field: {refused:?}"
            );
        }
        let unknown =
            standin.post_capability_deny(Caller::Shell, &json!({ "request_id": "missing" }));
        assert!(
            matches!(
                &unknown,
                Err((400, reason)) if reason.starts_with("unknown request:") && reason.contains("missing")
            ),
            "the stand-in refuses an unknown deny request id: {unknown:?}"
        );
        assert_eq!(
            request_entries(&standin, &id),
            vec![pending_request("req-1", "component-1")],
            "the stand-in leaves the pending record after a refused deny"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in leaves the running instance after a refused deny",
        );

        let denied = standin
            .post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": "req-1", "reason": "shell said no" }),
            )
            .expect("the stand-in accepts the shell deny");
        assert_eq!(
            denied,
            json!({ "success": true }),
            "the stand-in answers success true for the accepted deny"
        );
        let settled = vec![shell_denied_request(
            "req-1",
            "component-1",
            "shell said no",
        )];
        assert_eq!(
            request_entries(&standin, &id),
            settled,
            "the stand-in stores the shell deny on the named record"
        );

        let again = standin.post_capability_deny(
            Caller::Shell,
            &json!({ "request_id": "req-1", "reason": "again" }),
        );
        assert!(
            matches!(
                &again,
                Err((400, reason)) if reason.starts_with("request is not pending:") && reason.contains("req-1")
            ),
            "the stand-in refuses a second deny of the settled request: {again:?}"
        );
        assert_eq!(
            request_entries(&standin, &id),
            settled,
            "the stand-in keeps the first shell deny after a refused second deny"
        );

        seed_shared_request(&mut standin, "req-2", &id);
        let extra = standin.post_capability_deny(
            Caller::Shell,
            &json!({ "request_id": "req-2", "token": "secret" }),
        );
        assert!(
            matches!(
                &extra,
                Err((400, reason)) if reason.starts_with("deny body rejects ") && reason.contains("token")
            ),
            "the stand-in refuses a deny body with an extra key: {extra:?}"
        );
        assert_eq!(
            request_entries(&standin, &id),
            vec![
                shell_denied_request("req-1", "component-1", "shell said no"),
                pending_request("req-2", "component-1"),
            ],
            "the stand-in changes nothing for a denied body with an extra key"
        );

        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops the first instance");
        seed_shared_request(&mut standin, "req-s", "component-1");
        standin
            .post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": "req-s", "reason": "late deny" }),
            )
            .expect("the stand-in denies a request of the stopped instance");
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in keeps a stopped instance's phase and cause after a shell deny",
        );

        let waiting = launch_starting(&mut standin);
        seed_shared_request(&mut standin, "req-d", &waiting);
        standin
            .post_capability_deny(Caller::Shell, &json!({ "request_id": "req-d" }))
            .expect("the stand-in accepts a deny without a reason");
        assert_eq!(
            request_entries(&standin, &waiting),
            vec![shell_denied_request(
                "req-d",
                "component-2",
                "Denied by user"
            )],
            "the stand-in stores the default deny reason with the shell as settler"
        );
        assert_capsule(
            &standin,
            "component-2",
            "failed",
            "Denied by user",
            "the stand-in ends the starting instance failed with the default reason",
        );
    }

    #[test]
    fn standin_failure_ends_session_authority() {
        for (start, cause) in [
            (Start::Ok, "shell denied start"),
            (Start::Error("start refused".to_owned()), "start refused"),
            (Start::Trap("start trapped".to_owned()), "start trapped"),
        ] {
            let shell_denies = start == Start::Ok;
            let mut standin = StandIn::new();
            admit_shared(&mut standin, start);
            let failed = launch_starting(&mut standin);
            let sibling = launch_starting(&mut standin);
            let client = Caller::Client {
                session_id: &failed,
            };
            let sibling_client = Caller::Client {
                session_id: &sibling,
            };
            let mut requests = Vec::new();
            for caller in [
                client,
                client,
                client,
                client,
                sibling_client,
                sibling_client,
            ] {
                let response = standin
                    .post_capability_request(caller, &request_client_body())
                    .expect("the stand-in accepts a starting instance's request");
                requests.push(response["request_id"].as_str().unwrap().to_owned());
            }
            for (index, duration) in [(0, "session"), (3, "once"), (4, "session")] {
                assert_eq!(
                    standin.post_capability_grant(
                        Caller::Shell,
                        &json!({
                            "request_id": requests[index],
                            "duration": duration,
                            "rationale": "grant shared read",
                        }),
                    ),
                    Ok(json!({ "success": true })),
                    "the stand-in did the work: it grants the starting instance's request"
                );
                assert_eq!(
                    grant_record(&standin, &requests[index]),
                    (Life::Live, false),
                    "the stand-in did the work: the grant is live before failure"
                );
            }
            if shell_denies {
                assert_eq!(
                    standin.post_capability_deny(
                        Caller::Shell,
                        &json!({ "request_id": requests[1], "reason": cause }),
                    ),
                    Ok(json!({ "success": true })),
                    "the stand-in did the work: the shell denies the second request"
                );
            } else {
                standin
                    .finish_start(&failed)
                    .expect("the stand-in finishes the error or trap");
            }
            assert_capsule(
                &standin,
                &failed,
                "failed",
                cause,
                "the stand-in did the work: the failure ends the requesting instance",
            );
            for index in [0, 3] {
                assert_eq!(
                    standin.authorise(client, &requests[index]),
                    Err((400, "grant is not live: Revoked".to_owned())),
                    "the stand-in did the work: {cause} revokes the session and once grants"
                );
                assert_eq!(
                    grant_record(&standin, &requests[index]),
                    (Life::Revoked, false),
                    "the stand-in did the work: failure uses the shared grant cleanup"
                );
            }
            assert_eq!(
                standin.post_capability_grant(
                    Caller::Shell,
                    &json!({ "request_id": requests[2], "duration": "session" }),
                ),
                Err((400, format!("request is not pending: {}", requests[2]))),
                "the stand-in did the work: failure settles the third request before a later grant"
            );
            let second_record = if shell_denies {
                shell_denied_request(&requests[1], &failed, cause)
            } else {
                denied_request(&requests[1], &failed, cause)
            };
            assert_eq!(
                request_entries(&standin, &failed),
                vec![
                    granted_request(&requests[0], &failed, "grant shared read"),
                    second_record,
                    denied_request(&requests[2], &failed, cause),
                    granted_request(&requests[3], &failed, "grant shared read"),
                ],
                "the stand-in did the work: failure settles pending requests and preserves settled records"
            );
            assert_eq!(
                standin.authorise(sibling_client, &requests[4]),
                Ok(()),
                "the stand-in did the work: the sibling's session grant still authorises"
            );
            assert_eq!(
                request_entries(&standin, &sibling),
                vec![
                    granted_request(&requests[4], &sibling, "grant shared read"),
                    pending_request(&requests[5], &sibling),
                ],
                "the stand-in did the work: failure preserves the sibling's records"
            );
            assert_eq!(
                request_ids(&standin.get_capability_list(Caller::Shell, None).unwrap()),
                BTreeSet::from([requests[4].clone()]),
                "the stand-in did the work: only the sibling's grant remains live"
            );
            assert_capsule(
                &standin,
                &sibling,
                "starting",
                "",
                "the stand-in did the work: failure leaves the sibling starting",
            );
        }
    }

    #[test]
    fn standin_shell_grant_makes_one_live_grant() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let first = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches the first read-shared instance");
        let second = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches the second read-shared instance");
        assert_eq!(
            first["id"], "component-1",
            "the stand-in numbers the first launch component-1"
        );
        assert_eq!(
            second["id"], "component-2",
            "the stand-in numbers the second launch component-2"
        );
        assert_eq!(
            (first["status"].as_str(), second["status"].as_str()),
            (Some("starting"), Some("starting")),
            "the stand-in answers starting for both launches"
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        standin.set_instant(4);

        let granted = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-1",
                    "duration": "Session",
                    "rationale": "grant shared read",
                }),
            )
            .expect("the stand-in grants the first instance's request");
        assert_keys(
            &granted,
            &["success"],
            "the stand-in grant body has one key",
        );
        assert_eq!(
            granted,
            json!({ "success": true }),
            "the stand-in answers success true for the shell grant and stores no token"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![granted_request("req-1", "component-1", "grant shared read")],
            "the stand-in grants req-1 with the shell as settler and the rationale as decision"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling request pending with no settler"
        );
        assert!(
            request_entries(&standin, "component-2")[0]["settled_by"].is_null(),
            "the stand-in leaves the sibling settler null"
        );
        let live = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live view");
        assert_eq!(
            request_ids(&live),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in shows exactly the granted request as live"
        );
        assert_eq!(
            live["capabilities"][0],
            json!({
                "request_id": "req-1",
                "session_id": "component-1",
                "resource": SHARED_RESOURCE,
                "action": "read",
                "duration": "session",
                "granted_at": 4,
            }),
            "the stand-in stores the one live grant at the test instant with the lowercase duration"
        );
        let client = standin
            .get_capability_list(
                Caller::Client {
                    session_id: "component-2",
                },
                None,
            )
            .expect("the stand-in client list");
        assert_eq!(
            client["capabilities"].as_array().map(Vec::len),
            Some(0),
            "the stand-in shows the sibling client no grant"
        );
        standin
            .authorise(
                Caller::Client {
                    session_id: "component-1",
                },
                "req-1",
            )
            .expect("the stand-in authorises the granted instance");
        let sibling = standin.authorise(
            Caller::Client {
                session_id: "component-2",
            },
            "req-1",
        );
        assert!(
            matches!(&sibling, Err((403, reason)) if reason.contains("wrong capsule")),
            "the stand-in refuses the sibling presentation of the new grant: {sibling:?}"
        );
        assert_capsule(
            &standin,
            "component-1",
            "starting",
            "",
            "the stand-in keeps the granted instance starting before its start returns",
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in keeps the sibling starting",
        );

        standin
            .finish_start("component-1")
            .expect("the stand-in finishes the granted instance start");
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in runs the granted instance after its start returns",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![granted_request("req-1", "component-1", "grant shared read")],
            "the stand-in keeps the granted record after the start returns"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live view")
            ),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in keeps exactly the one live grant after the start returns"
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in keeps the sibling starting after the other start returns",
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in keeps the sibling request pending after the other start returns"
        );
    }

    #[test]
    fn standin_shell_grant_refuses_a_bad_request() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let id = launch_starting(&mut standin);
        seed_shared_request(&mut standin, "req-d", &id);

        let client = standin.post_capability_grant(
            Caller::Client {
                session_id: "component-1",
            },
            &json!({ "request_id": "req-d" }),
        );
        assert!(
            matches!(&client, Err((403, reason)) if reason == "This endpoint requires shell privileges"),
            "the stand-in refuses a client grant before reading the body: {client:?}"
        );

        for body in [json!({}), json!("req-d")] {
            let refused = standin.post_capability_grant(Caller::Shell, &body);
            assert!(
                matches!(&refused, Err((400, reason)) if reason == "grant body needs request_id"),
                "the stand-in refuses a grant body without request_id: {refused:?}"
            );
        }
        for (body, reason) in [
            (
                json!({ "request_id": 4 }),
                "grant request_id must be a string",
            ),
            (
                json!({ "request_id": "req-d", "duration": 4 }),
                "grant duration must be a string",
            ),
            (
                json!({ "request_id": "req-d", "rationale": 4 }),
                "grant rationale must be a string",
            ),
        ] {
            let refused = standin.post_capability_grant(Caller::Shell, &body);
            assert!(
                matches!(&refused, Err((400, got)) if got == reason),
                "the stand-in refuses a non-string grant field: {refused:?}"
            );
        }

        let unknown =
            standin.post_capability_grant(Caller::Shell, &json!({ "request_id": "missing" }));
        assert!(
            matches!(
                &unknown,
                Err((400, reason)) if reason.starts_with("unknown request:") && reason.contains("missing")
            ),
            "the stand-in refuses an unknown grant request id: {unknown:?}"
        );
        let extra = standin.post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": "req-d", "token": "secret" }),
        );
        assert!(
            matches!(
                &extra,
                Err((400, reason)) if reason.starts_with("grant body rejects ") && reason.contains("token")
            ),
            "the stand-in refuses a grant body with an extra key: {extra:?}"
        );
        let bad_duration = standin.post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": "req-d", "duration": "minutes" }),
        );
        assert!(
            matches!(
                &bad_duration,
                Err((400, reason)) if reason == "Invalid duration: minutes. Expected 'once' or 'session'"
            ),
            "the stand-in refuses an unknown grant duration: {bad_duration:?}"
        );
        assert_eq!(
            request_entries(&standin, &id),
            vec![pending_request("req-d", &id)],
            "the stand-in leaves the request pending after every refused grant"
        );
        assert!(
            standin.grants.is_empty(),
            "the stand-in stores no grant for a refused request"
        );
        assert_capsule(
            &standin,
            &id,
            "starting",
            "",
            "the stand-in leaves the instance starting after a refused grant",
        );

        let granted = standin
            .post_capability_grant(Caller::Shell, &json!({ "request_id": "req-d" }))
            .expect("the stand-in grants the request without duration or rationale");
        assert_eq!(
            granted,
            json!({ "success": true }),
            "the stand-in answers success true for the defaulted grant"
        );
        assert_eq!(
            request_entries(&standin, &id),
            vec![granted_request("req-d", &id, "Shell auto-grant")],
            "the stand-in stores the default rationale with the shell as settler"
        );
        let live = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live view");
        assert_eq!(
            live["capabilities"][0]["duration"], "session",
            "the stand-in stores the default duration as session"
        );

        let again = standin.post_capability_grant(Caller::Shell, &json!({ "request_id": "req-d" }));
        assert!(
            matches!(
                &again,
                Err((400, reason)) if reason.starts_with("request is not pending:") && reason.contains("req-d")
            ),
            "the stand-in refuses a second grant of the settled request: {again:?}"
        );
        assert_eq!(
            request_entries(&standin, &id),
            vec![granted_request("req-d", &id, "Shell auto-grant")],
            "the stand-in keeps the first granted record after a refused second grant"
        );

        let stopped = launch_starting(&mut standin);
        seed_shared_request(&mut standin, "req-s", &stopped);
        standin
            .delete_capsule(Caller::Shell, &stopped, &stop_body())
            .expect("the stand-in stops the second instance");
        let late = standin.post_capability_grant(Caller::Shell, &json!({ "request_id": "req-s" }));
        assert!(
            matches!(
                &late,
                Err((400, reason)) if reason.starts_with("request is not pending:") && reason.contains("req-s")
            ),
            "the stand-in refuses a grant of the stopped instance's request: {late:?}"
        );
        assert_eq!(
            request_entries(&standin, &stopped),
            vec![denied_request("req-s", &stopped, "stopped: stop one")],
            "the stand-in keeps the runtime settlement of the stopped instance's request"
        );
        let live = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live view");
        assert!(
            !request_ids(&live).contains("req-s"),
            "the stand-in shows no live grant for the stopped instance's request"
        );
    }

    #[test]
    fn standin_duplicate_request_is_refused() {
        let mut standin = StandIn::new();
        seed_shared_request(&mut standin, "req-1", "component-1");
        let second = standin.seed_request(
            "req-1",
            "component-2",
            "localhost://Public/other.txt",
            "write",
            "replace it",
        );
        assert!(
            matches!(
                &second,
                Err((400, reason))
                    if reason.starts_with("request already stored:") && reason.contains("req-1")
            ),
            "the stand-in refuses a duplicate request id: {second:?}"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in keeps the first pending record"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            Vec::<Value>::new(),
            "the stand-in stores no replacement record"
        );
    }

    #[test]
    fn standin_request_seed_validation() {
        let mut standin = StandIn::new();
        let empty = [
            ("", "component-1", SHARED_RESOURCE, "read"),
            ("req-1", "", SHARED_RESOURCE, "read"),
            ("req-1", "component-1", "", "read"),
            ("req-1", "component-1", SHARED_RESOURCE, ""),
        ];
        for (request_id, session_id, resource, action) in empty {
            let seeded =
                standin.seed_request(request_id, session_id, resource, action, "read shared");
            assert_request_refused(
                &seeded,
                "request needs an id, a session, a resource and an action",
                "the stand-in refuses a request missing a required field",
            );
            assert_eq!(
                request_entries(&standin, "component-1"),
                Vec::<Value>::new(),
                "the stand-in stores no record for a refused seed"
            );
        }
        standin
            .seed_request("req-1", "component-1", SHARED_RESOURCE, "read", "")
            .expect("the stand-in accepts an empty request reason");
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![json!({
                "request_id": "req-1",
                "session_id": "component-1",
                "resource": SHARED_RESOURCE,
                "action": "read",
                "reason": "",
                "status": "pending",
                "decision_reason": "",
                "settled_by": Value::Null,
            })],
            "the stand-in stores the accepted record pending with the given reason"
        );
    }

    #[test]
    fn standin_request_record_contract() {
        let mut standin = StandIn::new();
        standin
            .seed_request("req-z", "component-1", "res-z", "write", "later")
            .expect("the stand-in seeds req-z");
        standin
            .seed_request("req-a", "component-1", "res-a", "read", "first")
            .expect("the stand-in seeds req-a");
        standin
            .seed_request("req-b", "component-2", "res-b", "read", "other")
            .expect("the stand-in seeds req-b");
        let body = shell_requests(&standin, "component-1");
        assert_keys(
            &body,
            &["requests"],
            "the stand-in request body has one key",
        );
        for entry in body["requests"].as_array().unwrap() {
            assert_keys(
                entry,
                REQUEST_ENTRY,
                "the stand-in request entry carries the record fields",
            );
        }
        assert_eq!(
            body,
            json!({
                "requests": [
                    {
                        "request_id": "req-a",
                        "session_id": "component-1",
                        "resource": "res-a",
                        "action": "read",
                        "reason": "first",
                        "status": "pending",
                        "decision_reason": "",
                        "settled_by": Value::Null,
                    },
                    {
                        "request_id": "req-z",
                        "session_id": "component-1",
                        "resource": "res-z",
                        "action": "write",
                        "reason": "later",
                        "status": "pending",
                        "decision_reason": "",
                        "settled_by": Value::Null,
                    },
                ],
            }),
            "the stand-in returns that session's pending records sorted by request id"
        );
        assert_eq!(
            shell_requests(&standin, "component-3"),
            json!({ "requests": [] }),
            "the stand-in returns an empty list for an unknown session"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![json!({
                "request_id": "req-b",
                "session_id": "component-2",
                "resource": "res-b",
                "action": "read",
                "reason": "other",
                "status": "pending",
                "decision_reason": "",
                "settled_by": Value::Null,
            })],
            "the stand-in keeps another session's records out"
        );
    }

    #[test]
    fn standin_refused_stop_preserves_requests() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        seed_shared_request(&mut standin, "req-1", "component-1");
        let client = Caller::Client {
            session_id: "component-1",
        };
        let refused = [
            (
                client,
                "component-1",
                Value::Null,
                403u16,
                "This endpoint requires shell privileges",
            ),
            (
                Caller::Shell,
                "component-1",
                Value::Null,
                400,
                "stop body needs reason",
            ),
            (
                Caller::Shell,
                "component-9",
                stop_body(),
                400,
                "unknown instance: component-9",
            ),
            (Caller::Shell, "", stop_body(), 400, "unknown instance: "),
        ];
        for (caller, id, body, status, reason) in refused {
            let result = standin.delete_capsule(caller, id, &body);
            assert_delete(
                &result,
                status,
                reason,
                "the stand-in refuses this stop before any settlement",
            );
            assert_eq!(
                request_entries(&standin, "component-1"),
                vec![pending_request("req-1", "component-1")],
                "the stand-in leaves the pending request after a refused stop"
            );
        }
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        seed_shared_request(&mut standin, "req-2", "component-1");
        let ended = standin.delete_capsule(Caller::Shell, "component-1", &stop_body());
        assert_delete(
            &ended,
            400,
            "instance is not live: stopped",
            "the stand-in refuses a stop of the ended instance",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                denied_request("req-1", "component-1", "stopped: stop one"),
                pending_request("req-2", "component-1"),
            ],
            "the stand-in leaves the ended instance's new request pending after the refused stop"
        );
    }

    #[test]
    fn standin_stop_preserves_settled_requests() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        standin.requests.push(Request {
            request_id: "req-old".to_owned(),
            session_id: "component-1".to_owned(),
            resource: SHARED_RESOURCE.to_owned(),
            action: "read".to_owned(),
            reason: "earlier".to_owned(),
            requested_at: 0,
            status: RequestStatus::Denied,
            decision_reason: "denied earlier".to_owned(),
            settled_by: Some("shell"),
        });
        seed_shared_request(&mut standin, "req-1", "component-1");
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                denied_request("req-1", "component-1", "stopped: stop one"),
                json!({
                    "request_id": "req-old",
                    "session_id": "component-1",
                    "resource": SHARED_RESOURCE,
                    "action": "read",
                    "reason": "earlier",
                    "status": "denied",
                    "decision_reason": "denied earlier",
                    "settled_by": "shell",
                }),
            ],
            "the stand-in denies only pending requests and leaves the settled record"
        );
    }

    #[test]
    fn standin_unanswered_request_expires() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let first = launch_finished(&mut standin);
        let second = launch_finished(&mut standin);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("component-1", "component-2"),
            "the stand-in numbers the two finished launches component-1 and component-2"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in runs the first instance",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in runs the second instance",
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        let granted = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-2",
                    "duration": "session",
                    "rationale": "grant shared read",
                }),
            )
            .expect("the stand-in grants the second instance's request");
        assert_eq!(
            granted,
            json!({ "success": true }),
            "the stand-in answers success true for the shell grant"
        );
        standin.set_instant(299);
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in keeps the unanswered request pending below 300 seconds"
        );
        assert!(
            request_entries(&standin, "component-1")[0]["settled_by"].is_null(),
            "the stand-in leaves the unanswered settler null below 300 seconds"
        );
        standin.set_instant(300);
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![expired_request("req-1", "component-1")],
            "the stand-in expires the unanswered request at 300 seconds with the runtime as settler"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in leaves the instance running when its request expires",
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![granted_request("req-2", "component-2", "grant shared read")],
            "the stand-in leaves the granted record from the shell"
        );
        let live = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live view after the expiry");
        assert_eq!(
            request_ids(&live),
            BTreeSet::from(["req-2".to_owned()]),
            "the stand-in shows exactly the granted request as live after the expiry"
        );
        let denied = standin.post_capability_deny(
            Caller::Shell,
            &json!({ "request_id": "req-1", "reason": "too late" }),
        );
        assert_delete(
            &denied,
            400,
            "request is not pending: req-1",
            "the stand-in refuses a deny of the expired request",
        );
        let late = standin.post_capability_grant(Caller::Shell, &json!({ "request_id": "req-1" }));
        assert_delete(
            &late,
            400,
            "request is not pending: req-1",
            "the stand-in refuses a grant of the expired request",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![expired_request("req-1", "component-1")],
            "the stand-in leaves the expired record after both refusals"
        );
        let live = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live view after both refusals");
        assert_eq!(
            request_ids(&live),
            BTreeSet::from(["req-2".to_owned()]),
            "the stand-in leaves exactly the granted request live after both refusals"
        );
        seed_shared_request(&mut standin, "req-3", "component-1");
        standin.set_instant(599);
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                expired_request("req-1", "component-1"),
                pending_request("req-3", "component-1"),
            ],
            "the stand-in keeps a request seeded at 300 pending below its own 300 seconds"
        );
        assert!(
            request_entries(&standin, "component-1")[1]["settled_by"].is_null(),
            "the stand-in leaves the new request's settler null at 599 seconds"
        );
        standin.set_instant(600);
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                expired_request("req-1", "component-1"),
                expired_request("req-3", "component-1"),
            ],
            "the stand-in expires the second request at 600 seconds and keeps the first expired record"
        );
        standin.requests.push(Request {
            request_id: "req-old".to_owned(),
            session_id: "component-1".to_owned(),
            resource: SHARED_RESOURCE.to_owned(),
            action: "read".to_owned(),
            reason: "earlier".to_owned(),
            requested_at: 0,
            status: RequestStatus::Denied,
            decision_reason: "denied earlier".to_owned(),
            settled_by: Some("shell"),
        });
        standin.set_instant(300);
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                expired_request("req-1", "component-1"),
                expired_request("req-3", "component-1"),
                json!({
                    "request_id": "req-old",
                    "session_id": "component-1",
                    "resource": SHARED_RESOURCE,
                    "action": "read",
                    "reason": "earlier",
                    "status": "denied",
                    "decision_reason": "denied earlier",
                    "settled_by": "shell",
                }),
            ],
            "the stand-in leaves the settled denied record as its own test stores it"
        );
    }

    #[test]
    fn standin_starting_stop_denies_that_sessions_pending() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_starting(&mut standin);
        seed_shared_request(&mut standin, "req-1", "component-1");
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops a starting instance");
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![denied_request("req-1", "component-1", "stopped: stop one")],
            "the stand-in denies a starting instance's pending request"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in stores stopped with the stop cause",
        );
    }

    #[test]
    fn standin_stopped_stays_for_sixty_seconds() {
        let mut standin = StandIn::new();
        standin.set_instant(0);
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        launch_finished(&mut standin);
        let stopped = standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 at instant 0");
        assert!(
            stopped.is_null(),
            "the stand-in answers null when it stops one instance"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in lists a stopped instance at instant 0",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in lists the running sibling at instant 0",
        );
        standin.set_instant(59);
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in lists a stopped instance at instant 59",
        );
        standin.set_instant(60);
        assert_eq!(
            shell_list(&standin),
            json!({
                "capsules": [{
                    "id": "component-2",
                    "name": SHARED_NAME,
                    "status": "running",
                    "session_id": "component-2",
                    "cause": "",
                }]
            }),
            "the stand-in omits a stopped instance at instant 60 and keeps the running sibling"
        );

        let mut later = StandIn::new();
        later.set_instant(1_000);
        admit_shared(&mut later, Start::Ok);
        launch_finished(&mut later);
        launch_finished(&mut later);
        later.set_instant(1_070);
        later
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 at instant 1070");
        assert_capsule(
            &later,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in lists a stopped instance at the stop instant",
        );
        later.set_instant(1_129);
        assert_capsule(
            &later,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in lists a stopped instance 59 seconds after the stop",
        );
        later.set_instant(1_130);
        assert_eq!(
            shell_list(&later),
            json!({
                "capsules": [{
                    "id": "component-2",
                    "name": SHARED_NAME,
                    "status": "running",
                    "session_id": "component-2",
                    "cause": "",
                }]
            }),
            "the stand-in omits a stopped instance 60 seconds after the stop and keeps the running sibling"
        );
    }

    #[test]
    fn standin_stopped_instance_makes_no_request() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let first = launch_finished(&mut standin);
        let second = launch_finished(&mut standin);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("component-1", "component-2"),
            "the stand-in numbers the two running launches component-1 and component-2"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in lists component-1 running before the stop",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in lists component-2 running before the stop",
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 at instant 0");
        standin.set_instant(2);
        let watched = standin.watch_ended("component-1", "stopped");
        assert!(
            watched.is_ok(),
            "the stand-in watch reports the stopped instance two seconds after the stop: {watched:?}"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in lists the stopped instance two seconds after the stop",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves the running sibling listed after the watch",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![denied_request("req-1", "component-1", "stopped: stop one",)],
            "the stand-in request record for the stopped instance is not pending"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling's request pending after the watch"
        );
        standin
            .seed_request(
                "req-retry",
                "component-1",
                SHARED_RESOURCE,
                "read",
                "read shared",
            )
            .expect("the stand-in seeds a pending request after the instance ended");
        let retried = standin.watch_ended("component-1", "stopped");
        assert_request_refused(
            &retried,
            "made a request after it ended: component-1",
            "the stand-in watch reports the pending request that appeared after the end",
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in leaves the stopped instance listed after the refusal",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                denied_request("req-1", "component-1", "stopped: stop one"),
                pending_request("req-retry", "component-1"),
            ],
            "the stand-in leaves req-1 denied and req-retry pending after the refusal"
        );
        let unchanged = request_entries(&standin, "component-1");
        let wrong_status = standin.watch_ended("component-1", "running");
        assert_request_refused(
            &wrong_status,
            "watch status must be stopped or failed",
            "the stand-in watch refuses a status other than stopped or failed",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            unchanged,
            "the refused watch status changes no request record"
        );
        let missing = standin.watch_ended("component-9", "stopped");
        assert_request_refused(
            &missing,
            "left the instance list: component-9",
            "the stand-in watch reports an instance that is not listed",
        );

        let mut later = StandIn::new();
        admit_shared(&mut later, Start::Ok);
        launch_finished(&mut later);
        launch_finished(&mut later);
        seed_shared_request(&mut later, "req-1", "component-1");
        later
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 at instant 0");
        later.set_instant(2);
        assert!(
            later.watch_ended("component-1", "stopped").is_ok(),
            "the stand-in watch reports the stopped instance two seconds after the stop"
        );
        later.set_instant(60);
        let left = later.watch_ended("component-1", "stopped");
        assert_request_refused(
            &left,
            "left the instance list: component-1",
            "the stand-in watch reports the stopped instance that left the list at 60 seconds",
        );
        assert_eq!(
            request_entries(&later, "component-1"),
            vec![denied_request("req-1", "component-1", "stopped: stop one",)],
            "the stand-in leaves the one denied request after the 60-second refusal"
        );
    }

    #[test]
    fn standin_failed_instance_makes_no_request() {
        const FAILING_PATH: &str = "/capsules/fail-after-submit";
        const FAILING_NAME: &str = "fail-after-submit";

        let mut standin = StandIn::new();
        standin
            .admit_resident(
                FAILING_PATH,
                FAILING_NAME,
                Start::Error("start refused".to_owned()),
            )
            .expect("the stand-in admits the failing path");
        admit_shared(&mut standin, Start::Ok);
        let failing = standin
            .post_capsules(Caller::Shell, &agent_body(FAILING_PATH))
            .expect("the stand-in launches the failing path");
        let sibling = standin
            .post_capsules(Caller::Shell, &agent_body(SHARED_PATH))
            .expect("the stand-in launches the shared path");
        assert_eq!(
            (failing["id"].as_str(), failing["status"].as_str()),
            (Some("component-1"), Some("starting")),
            "the stand-in answers starting for the failing launch component-1"
        );
        assert_eq!(
            (sibling["id"].as_str(), sibling["status"].as_str()),
            (Some("component-2"), Some("starting")),
            "the stand-in answers starting for the sibling launch component-2"
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes the failing start at instant 0");
        standin.set_instant(2);
        let watched = standin.watch_ended("component-1", "failed");
        assert!(
            watched.is_ok(),
            "the stand-in watch reports the failed instance two seconds after the failure: {watched:?}"
        );
        let listed = shell_list(&standin);
        let ended = listed["capsules"]
            .as_array()
            .expect("the stand-in returns capsules")
            .iter()
            .find(|entry| entry["id"] == "component-1");
        assert_eq!(
            ended,
            Some(&json!({
                "id": "component-1",
                "name": FAILING_NAME,
                "status": "failed",
                "session_id": "component-1",
                "cause": "start refused",
            })),
            "the stand-in lists the failed instance two seconds after the failure"
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in leaves the sibling starting after the watch",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![denied_request("req-1", "component-1", "start refused",)],
            "the stand-in request record for the failed instance is not pending"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling's request pending after the watch"
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in stops no sibling of the failed instance",
        );

        let mut empty = StandIn::new();
        empty
            .admit_resident(
                FAILING_PATH,
                FAILING_NAME,
                Start::Error("start refused".to_owned()),
            )
            .expect("the stand-in admits the failing path");
        let only = empty
            .post_capsules(Caller::Shell, &agent_body(FAILING_PATH))
            .expect("the stand-in launches the failing path once");
        assert_eq!(
            only["id"], "component-1",
            "the stand-in numbers the only failing launch component-1"
        );
        empty
            .finish_start("component-1")
            .expect("the stand-in finishes the failing start with no seeded request");
        empty.set_instant(2);
        let no_records = empty.watch_ended("component-1", "failed");
        assert_request_refused(
            &no_records,
            "component-1 has 0 request records after it ended",
            "the stand-in watch counts the failed instance's request records",
        );
        assert_eq!(
            shell_list(&empty),
            json!({
                "capsules": [{
                    "id": "component-1",
                    "name": FAILING_NAME,
                    "status": "failed",
                    "session_id": "component-1",
                    "cause": "start refused",
                }]
            }),
            "the stand-in leaves the failed entry listed after the count refusal"
        );
        assert!(
            empty.grants.is_empty(),
            "the stand-in mints no grant from the watch"
        );
    }

    #[test]
    fn standin_stop_during_start_blocks_finish() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let first = launch_starting(&mut standin);
        let second = launch_starting(&mut standin);
        assert_eq!(
            (first, second),
            ("component-1".to_owned(), "component-2".to_owned()),
            "the stand-in launches two starting instances"
        );
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        seed_at(&mut standin, "req-2", "component-2", Life::Live);
        let stopped = standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops an instance during start");
        assert!(
            stopped.is_null(),
            "the stand-in answers null when it stops during start"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in stores stopped before start returns",
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Revoked, false),
            "the stand-in revokes the starting instance's live grant"
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-2".to_owned()]),
            "the stand-in drops the revoked grant and keeps the sibling grant"
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in leaves the starting sibling",
        );
        let finished = standin.finish_start("component-1");
        assert!(
            matches!(
                &finished,
                Err((400, reason)) if reason == "instance is not live: stopped"
            ),
            "the stand-in refuses finish_start after a stop during start: {finished:?}"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in keeps stopped when finish_start follows the stop",
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in leaves the starting sibling after the refused finish",
        );
        assert_eq!(
            grant_record(&standin, "req-2"),
            (Life::Live, false),
            "the stand-in leaves the sibling grant live"
        );
    }

    #[test]
    fn standin_second_stop_is_refused() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        launch_finished(&mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        seed_at(&mut standin, "req-e", "component-1", Life::Exhausted);
        seed_at(&mut standin, "req-2", "component-2", Life::Live);
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 once");
        let second = standin.delete_capsule(Caller::Shell, "component-1", &stop_body());
        assert_delete(
            &second,
            400,
            "instance is not live: stopped",
            "the stand-in refuses a second stop",
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in keeps the first stop reason",
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Revoked, false),
            "the stand-in leaves the revoked grant revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-e"),
            (Life::Exhausted, false),
            "the stand-in leaves an exhausted grant exhausted"
        );
        assert_eq!(
            grant_record(&standin, "req-2"),
            (Life::Live, false),
            "the stand-in leaves the sibling grant live"
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves the sibling running",
        );
        assert_next_launch(&mut standin, "component-3");
    }

    #[test]
    fn standin_client_cannot_stop() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        let client = Caller::Client {
            session_id: "component-1",
        };
        let valid = stop_body();
        let attempts = [
            (
                "component-1",
                valid.clone(),
                "the stand-in refuses a client stop",
            ),
            (
                "component-1",
                Value::Null,
                "the stand-in refuses a client stop when the body is not an object",
            ),
            (
                "component-1",
                json!({}),
                "the stand-in refuses a client stop when reason is missing",
            ),
            (
                "component-1",
                json!({ "reason": 1 }),
                "the stand-in refuses a client stop when reason is not a string",
            ),
            (
                "component-1",
                json!({ "reason": "" }),
                "the stand-in refuses a client stop when reason is empty",
            ),
            (
                "component-9",
                valid.clone(),
                "the stand-in refuses a client stop of an unknown id",
            ),
            (
                "",
                valid,
                "the stand-in refuses a client stop of an empty id",
            ),
        ];
        for (id, body, message) in attempts {
            let result = standin.delete_capsule(client, id, &body);
            assert_delete(
                &result,
                403,
                "This endpoint requires shell privileges",
                message,
            );
            assert_capsule(
                &standin,
                "component-1",
                "running",
                "",
                "the stand-in leaves the running instance after a client stop",
            );
            assert_eq!(
                grant_record(&standin, "req-1"),
                (Life::Live, false),
                "the stand-in leaves the live grant after a client stop"
            );
        }
        let shell_body = standin.delete_capsule(Caller::Shell, "component-1", &Value::Null);
        assert_delete(
            &shell_body,
            400,
            "stop body needs reason",
            "the stand-in shell is refused for the body, not for shell privileges",
        );
        let shell_unknown = standin.delete_capsule(Caller::Shell, "component-9", &stop_body());
        assert_delete(
            &shell_unknown,
            400,
            "unknown instance: component-9",
            "the stand-in shell is refused for the unknown id, not for shell privileges",
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in leaves the running instance after the shell refusals",
        );
        assert_next_launch(&mut standin, "component-2");
    }

    fn launch_two_running(standin: &mut StandIn) {
        admit_shared(standin, Start::Ok);
        launch_finished(standin);
        launch_finished(standin);
    }

    fn assert_unknown(result: &Result<(), (u16, String)>, request_id: &str, who: &str) {
        let expected = format!("unknown grant: {request_id}");
        assert!(
            matches!(
                result,
                Err((400, reason)) if reason.starts_with("unknown grant:") && reason == &expected
            ),
            "the stand-in refuses unknown grant {request_id:?} for {who}: {result:?}"
        );
    }

    fn assert_not_live(result: &Result<(), (u16, String)>, life_name: &str, message: &str) {
        let expected = format!("grant is not live: {life_name}");
        assert!(
            matches!(
                result,
                Err((400, reason))
                    if reason.starts_with("grant is not live:")
                        && reason.contains(life_name)
                        && reason == &expected
            ),
            "{message}: {result:?}"
        );
    }

    fn assert_wrong_capsule(
        result: &Result<(), (u16, String)>,
        grant_session: &str,
        caller_session: Option<&str>,
        message: &str,
    ) {
        assert!(
            matches!(
                result,
                Err((403, reason))
                    if reason.contains("wrong capsule")
                        && reason.contains(grant_session)
                        && caller_session.is_none_or(|session_id| reason.contains(session_id))
            ),
            "{message}: {result:?}"
        );
    }

    #[test]
    fn standin_sibling_cannot_use_the_grant() {
        let mut standin = StandIn::new();
        launch_two_running(&mut standin);
        standin.seed_grant(
            "req-1",
            "component-1",
            "res",
            "read",
            "once",
            1,
            Life::Live,
            true,
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in lists exactly the one live grant"
        );
        assert_eq!(
            plain["capabilities"][0]["session_id"], "component-1",
            "the stand-in binds that grant to component-1"
        );
        let sibling_list = standin
            .get_capability_list(
                Caller::Client {
                    session_id: "component-2",
                },
                None,
            )
            .expect("the stand-in client view");
        assert_eq!(
            request_ids(&sibling_list),
            BTreeSet::new(),
            "the stand-in client list for component-2 is empty"
        );
        let refused = standin.authorise(
            Caller::Client {
                session_id: "component-2",
            },
            "req-1",
        );
        assert_wrong_capsule(
            &refused,
            "component-1",
            Some("component-2"),
            "the stand-in refuses instance 1's grant for instance 2",
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Live, true),
            "the stand-in did the work: the sibling refusal spends nothing"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in did the work: the refused sibling leaves the grant in the live view"
        );
        let owner = standin.authorise(
            Caller::Client {
                session_id: "component-1",
            },
            "req-1",
        );
        assert!(
            owner.is_ok(),
            "the stand-in authorises the owning client: {owner:?}"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in leaves instance 1 running",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves instance 2 running",
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Exhausted, true),
            "the stand-in did the work: the owner's one use stores Exhausted"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::new(),
            "the stand-in did the work: the live view omits the spent grant"
        );
    }

    #[test]
    fn standin_once_grant_is_spent_by_one_use() {
        let mut standin = StandIn::new();
        launch_two_running(&mut standin);
        standin.seed_grant(
            "req-once",
            "component-1",
            "res",
            "read",
            "once",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-session",
            "component-2",
            "res",
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::from(["req-once".to_owned(), "req-session".to_owned()]),
            "the stand-in did the work: the live view lists both seeded grants"
        );
        let sibling = standin.authorise(
            Caller::Client {
                session_id: "component-2",
            },
            "req-once",
        );
        assert_wrong_capsule(
            &sibling,
            "component-1",
            Some("component-2"),
            "the stand-in did the work: it refuses the sibling of the once grant",
        );
        let shell = standin.authorise(Caller::Shell, "req-once");
        assert_wrong_capsule(
            &shell,
            "component-1",
            None,
            "the stand-in did the work: it refuses the shell presentation of the once grant",
        );
        assert_eq!(
            grant_record(&standin, "req-once"),
            (Life::Live, false),
            "the stand-in did the work: both refusals spend nothing"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::from(["req-once".to_owned(), "req-session".to_owned()]),
            "the stand-in did the work: both refusals leave the live view unchanged"
        );
        let owner = standin.authorise(
            Caller::Client {
                session_id: "component-1",
            },
            "req-once",
        );
        assert!(
            owner.is_ok(),
            "the stand-in did the work: it authorises the owner's one use: {owner:?}"
        );
        assert_eq!(
            grant_record(&standin, "req-once"),
            (Life::Exhausted, false),
            "the stand-in did the work: the owner's one use stores Exhausted"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::from(["req-session".to_owned()]),
            "the stand-in did the work: the live view omits the spent once grant"
        );
        let again = standin.authorise(
            Caller::Client {
                session_id: "component-1",
            },
            "req-once",
        );
        assert_not_live(
            &again,
            "Exhausted",
            "the stand-in did the work: the spent grant is not live for a second use",
        );
        for attempt in 1..=2 {
            let session = standin.authorise(
                Caller::Client {
                    session_id: "component-2",
                },
                "req-session",
            );
            assert!(
                session.is_ok(),
                "the stand-in did the work: session grant use {attempt} succeeds: {session:?}"
            );
        }
        assert_eq!(
            grant_record(&standin, "req-session"),
            (Life::Live, false),
            "the stand-in did the work: the session grant stays Live after two uses"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::from(["req-session".to_owned()]),
            "the stand-in did the work: the live view still lists the session grant"
        );
        for id in ["component-1", "component-2"] {
            assert_capsule(
                &standin,
                id,
                "running",
                "",
                "the stand-in did the work: it leaves both instances running",
            );
        }
    }

    #[test]
    fn standin_stop_clears_that_sessions_grant() {
        let mut standin = StandIn::new();
        launch_two_running(&mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        seed_at(&mut standin, "req-2", "component-2", Life::Live);
        let stopped = standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        assert!(
            stopped.is_null(),
            "the stand-in answers null when it stops one instance"
        );
        let owner = standin.authorise(
            Caller::Client {
                session_id: "component-1",
            },
            "req-1",
        );
        assert_not_live(
            &owner,
            "Revoked",
            "the stand-in refuses the stopped session's grant",
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-2".to_owned()]),
            "the stand-in lists exactly the sibling grant"
        );
        let sibling_own = standin.authorise(
            Caller::Client {
                session_id: "component-2",
            },
            "req-2",
        );
        assert!(
            sibling_own.is_ok(),
            "the stand-in authorises instance 2's own grant: {sibling_own:?}"
        );
        let sibling_other = standin.authorise(
            Caller::Client {
                session_id: "component-2",
            },
            "req-1",
        );
        assert_not_live(
            &sibling_other,
            "Revoked",
            "the stand-in refuses the stopped grant before the caller check",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves instance 2 running",
        );
    }

    #[test]
    fn standin_authorise_unknown_grant() {
        let mut standin = StandIn::new();
        standin.seed_grant(
            "req-1",
            "component-1",
            "res",
            "read",
            "once",
            1,
            Life::Live,
            false,
        );
        let callers = [
            ("shell", Caller::Shell),
            (
                "owner",
                Caller::Client {
                    session_id: "component-1",
                },
            ),
            (
                "sibling",
                Caller::Client {
                    session_id: "component-2",
                },
            ),
        ];
        for (who, caller) in callers {
            for request_id in ["", "req-missing"] {
                let result = standin.authorise(caller, request_id);
                assert_unknown(&result, request_id, who);
            }
        }
        let owner = standin.authorise(
            Caller::Client {
                session_id: "component-1",
            },
            "req-1",
        );
        assert!(
            owner.is_ok(),
            "the stand-in authorises the owning client of a known live grant: {owner:?}"
        );
    }

    #[test]
    fn standin_authorise_dead_grants() {
        let mut standin = StandIn::new();
        let rows = [
            ("req-exhausted", Life::Exhausted, "Exhausted"),
            ("req-revoked", Life::Revoked, "Revoked"),
            ("req-expired", Life::Expired, "Expired"),
        ];
        for (request_id, life, _) in rows {
            standin.seed_grant(
                request_id,
                "component-1",
                "res",
                "read",
                "once",
                1,
                life,
                false,
            );
        }
        let callers = [
            Caller::Client {
                session_id: "component-1",
            },
            Caller::Client {
                session_id: "component-2",
            },
            Caller::Shell,
        ];
        for (request_id, life, life_name) in rows {
            for caller in callers {
                let result = standin.authorise(caller, request_id);
                assert_not_live(
                    &result,
                    life_name,
                    "the stand-in refuses a grant that is not live before the caller check",
                );
            }
            assert_eq!(
                grant_record(&standin, request_id),
                (life, false),
                "the stand-in leaves a {life_name} grant unchanged"
            );
        }
    }

    #[test]
    fn standin_storage_follows_the_selected_home() {
        use crate::harness::ThrowawayHome;

        let first = ThrowawayHome::new().expect("a throwaway Home for the first storage row");
        let second = ThrowawayHome::new().expect("a throwaway Home for the second storage row");
        let mut paths = Vec::new();
        for home in [&first, &second] {
            let storage = StandIn::storage_for_home(home.home())
                .expect("the stand-in follows the selected Home's data directory");
            assert_eq!(
                storage,
                home.data().join("storage"),
                "the stand-in returns the selected Home's data directory plus storage"
            );
            assert!(
                !storage.exists(),
                "the stand-in returns that path and creates no storage directory"
            );
            paths.push(storage);
        }
        assert_ne!(
            paths[0], paths[1],
            "the stand-in gives two selected Homes two storage directories"
        );
        let again = StandIn::storage_for_home(first.home())
            .expect("the stand-in follows a selected Home on a second call");
        assert_eq!(
            again, paths[0],
            "the stand-in returns one directory for one selected Home"
        );
        first.finish().expect("the first throwaway Home finishes");
        second.finish().expect("the second throwaway Home finishes");

        for (home, text) in [
            ("", "an empty Home"),
            ("standin-a9", "a relative Home"),
            ("/var/standin-a9/../other", "a Home with a parent component"),
        ] {
            let refused = StandIn::storage_for_home(Path::new(home));
            assert!(
                matches!(&refused, Err((400, reason)) if reason == "storage needs a selected Home"),
                "the stand-in refuses {text} and names the missing selected Home: {refused:?}"
            );
        }
    }

    #[test]
    fn standin_shared_temp_storage_is_refused() {
        let shared = Path::new("/tmp/elastos/storage");
        let existed = shared.exists();
        let refused = StandIn::storage_for_home(shared);
        assert!(
            matches!(&refused, Err((400, reason)) if reason == "shared temp directory is not agent storage"),
            "the stand-in refuses the fixed shared temp path before the Home rule: {refused:?}"
        );
        assert_eq!(
            shared.exists(),
            existed,
            "the stand-in creates nothing at the shared temp path"
        );
    }

    #[test]
    fn standin_shell_cannot_authorise() {
        let mut standin = StandIn::new();
        standin.seed_grant(
            "req-1",
            "component-1",
            "res",
            "read",
            "once",
            1,
            Life::Live,
            false,
        );
        let shell = standin.authorise(Caller::Shell, "req-1");
        assert_wrong_capsule(
            &shell,
            "component-1",
            None,
            "the stand-in refuses a shell presentation of a live grant",
        );
        let owner = standin.authorise(
            Caller::Client {
                session_id: "component-1",
            },
            "req-1",
        );
        assert!(
            owner.is_ok(),
            "the stand-in authorises the owning client of that live grant: {owner:?}"
        );
    }

    #[test]
    fn standin_storage_refuses_root_symlink_swap() {
        use crate::harness::ThrowawayHome;
        use std::os::unix::fs::symlink;

        let home = ThrowawayHome::new().expect("a throwaway Home for the root symlink row");
        let storage = StandIn::storage_for_home(home.home())
            .expect("the stand-in returns the selected Home's storage path");
        let accepted = StandIn::confirm_storage(home.home(), "");
        assert_eq!(
            accepted,
            Ok(storage.clone()),
            "the stand-in did the work: it returns the absent storage directory before a link"
        );
        assert!(
            !storage.exists(),
            "the stand-in did the work: it creates no storage directory"
        );

        symlink(home.root().join("swapped-root"), &storage)
            .expect("the test makes the storage path a symbolic link");
        let refused = StandIn::confirm_storage(home.home(), "");
        assert!(
            matches!(&refused, Err((400, reason)) if reason == "storage directory is a symbolic link"),
            "the stand-in did the work: it refuses a storage directory that is a symbolic link: {refused:?}"
        );
        let meta =
            std::fs::symlink_metadata(&storage).expect("the storage path is still a symbolic link");
        assert!(
            meta.file_type().is_symlink(),
            "the stand-in did the work: it does not follow the storage link"
        );
        home.finish().expect("the throwaway Home finishes");
    }

    #[test]
    fn standin_storage_refuses_host_hardlink() {
        use crate::harness::ThrowawayHome;

        let home = ThrowawayHome::new().expect("a throwaway Home for the hard link row");
        let storage = StandIn::storage_for_home(home.home())
            .expect("the stand-in returns the selected Home's storage path");
        std::fs::create_dir(&storage).expect("the test creates the storage directory");
        let absent = StandIn::confirm_storage(home.home(), "absent.txt");
        assert_eq!(
            absent,
            Ok(storage.join("absent.txt")),
            "the stand-in did the work: it returns a joined path that is absent"
        );
        let entry = storage.join("entry.txt");
        std::fs::write(&entry, b"stand-in storage file").expect("the test writes one regular file");
        let accepted = StandIn::confirm_storage(home.home(), "entry.txt");
        assert_eq!(
            accepted,
            Ok(entry.clone()),
            "the stand-in did the work: it returns one regular file whose link count is 1"
        );

        let second = storage.join("second.txt");
        std::fs::hard_link(&entry, &second).expect("the test adds a second name for the same file");
        for name in ["entry.txt", "second.txt"] {
            let refused = StandIn::confirm_storage(home.home(), name);
            assert!(
                matches!(&refused, Err((400, reason)) if reason == "storage file has more than one link"),
                "the stand-in did the work: it refuses the hard-linked file under name {name:?}: {refused:?}"
            );
        }
        for name in ["..", "a/b"] {
            let refused = StandIn::confirm_storage(home.home(), name);
            assert!(
                matches!(&refused, Err((400, reason)) if reason == "storage entry stays under the selected Home"),
                "the stand-in did the work: it refuses entry {name:?} outside one normal component: {refused:?}"
            );
        }
        home.finish().expect("the throwaway Home finishes");
    }

    fn request_client_body() -> Value {
        json!({
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
        })
    }

    fn assert_live_request_ids_empty(standin: &StandIn, message: &str) {
        let listed = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live-grant view");
        assert!(
            request_ids(&listed).is_empty(),
            "the stand-in did the work: {message}"
        );
    }

    #[test]
    fn standin_ended_instance_request_is_refused() {
        const FAILING_PATH: &str = "/capsules/fail-after-submit";
        const FAILING_NAME: &str = "fail-after-submit";

        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let first = launch_finished(&mut standin);
        let second = launch_finished(&mut standin);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("component-1", "component-2"),
            "the stand-in did the work: it numbers the two launches component-1 and component-2"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: it lists component-1 running before the stop",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: it lists component-2 running before the stop",
        );
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 with the stop reason");
        let stopped = standin.post_capability_request(
            Caller::Client {
                session_id: "component-1",
            },
            &request_client_body(),
        );
        assert_eq!(
            stopped,
            Err((400, "instance is not live: stopped".to_owned())),
            "the stand-in did the work: it refuses a new request from the stopped instance"
        );
        assert_eq!(
            shell_requests(&standin, "component-1"),
            json!({ "requests": [] }),
            "the stand-in did the work: the stopped instance stores no request"
        );
        standin.set_instant(60);
        let after_instant = standin.post_capability_request(
            Caller::Client {
                session_id: "component-1",
            },
            &request_client_body(),
        );
        assert_eq!(
            after_instant,
            Err((400, "instance is not live: stopped".to_owned())),
            "the stand-in did the work: it refuses the stopped instance that left the list at instant 60"
        );
        assert_eq!(
            shell_requests(&standin, "component-1"),
            json!({ "requests": [] }),
            "the stand-in did the work: the stopped instance stores no request at instant 60"
        );

        let sibling = standin.post_capability_request(
            Caller::Client {
                session_id: "component-2",
            },
            &request_client_body(),
        );
        assert_eq!(
            sibling,
            Ok(json!({ "status": "pending", "request_id": "request-1" })),
            "the stand-in did the work: it answers pending and request-1 for the running sibling"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-1", "component-2")],
            "the stand-in did the work: it stores one pending request for component-2"
        );
        assert_live_request_ids_empty(
            &standin,
            "the request route stores no live grant for component-2",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: it leaves component-2 running after the request",
        );

        let unknown = standin.post_capability_request(
            Caller::Client {
                session_id: "component-9",
            },
            &request_client_body(),
        );
        assert_eq!(
            unknown,
            Err((400, "unknown instance: component-9".to_owned())),
            "the stand-in did the work: it refuses a client whose instance is unknown"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-1", "component-2")],
            "the stand-in did the work: the unknown client leaves the sibling's request as it was"
        );

        let mut failed = StandIn::new();
        failed
            .admit_resident(
                FAILING_PATH,
                FAILING_NAME,
                Start::Error("start refused".to_owned()),
            )
            .expect("the stand-in admits the failing path");
        let only = failed
            .post_capsules(Caller::Shell, &agent_body(FAILING_PATH))
            .expect("the stand-in launches the failing path once");
        assert_eq!(
            only["id"], "component-1",
            "the stand-in did the work: it numbers the only failing launch component-1"
        );
        failed
            .finish_start("component-1")
            .expect("the stand-in finishes the failing start");
        let refused = failed.post_capability_request(
            Caller::Client {
                session_id: "component-1",
            },
            &request_client_body(),
        );
        assert_eq!(
            refused,
            Err((400, "instance is not live: failed".to_owned())),
            "the stand-in did the work: it refuses a new request from the failed instance"
        );
        assert_eq!(
            shell_requests(&failed, "component-1"),
            json!({ "requests": [] }),
            "the stand-in did the work: the failed instance stores no request"
        );
        assert_eq!(
            shell_list(&failed),
            json!({
                "capsules": [{
                    "id": "component-1",
                    "name": FAILING_NAME,
                    "status": "failed",
                    "session_id": "component-1",
                    "cause": "start refused",
                }]
            }),
            "the stand-in did the work: it leaves the failed entry listed with its cause"
        );
    }

    #[test]
    fn standin_live_instance_request_stays_pending() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let launched = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches once");
        assert_eq!(
            (launched["id"].as_str(), launched["status"].as_str()),
            (Some("component-1"), Some("starting")),
            "the stand-in did the work: it launches component-1 starting"
        );
        let shell = standin.post_capability_request(Caller::Shell, &Value::Null);
        assert_eq!(
            shell,
            Err((
                403,
                "capability request needs an instance session".to_owned()
            )),
            "the stand-in did the work: it refuses a shell before the body is read"
        );
        assert_eq!(
            shell_requests(&standin, "component-1"),
            json!({ "requests": [] }),
            "the stand-in did the work: the shell request stores nothing"
        );

        let first = standin.post_capability_request(
            Caller::Client {
                session_id: "component-1",
            },
            &request_client_body(),
        );
        assert_eq!(
            first,
            Ok(json!({ "status": "pending", "request_id": "request-1" })),
            "the stand-in did the work: it answers pending and request-1 for component-1"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("request-1", "component-1")],
            "the stand-in did the work: it stores one pending request for component-1"
        );
        assert_capsule(
            &standin,
            "component-1",
            "starting",
            "",
            "the stand-in did the work: the starting instance stays starting after the request",
        );
        assert_live_request_ids_empty(
            &standin,
            "the request route stores no live grant for the starting instance",
        );

        standin
            .finish_start("component-1")
            .expect("the stand-in finishes the start");
        let second = standin.post_capability_request(
            Caller::Client {
                session_id: "component-1",
            },
            &json!({
                "resource": SHARED_RESOURCE,
                "action": "Write",
                "reason": "read shared",
            }),
        );
        assert_eq!(
            second,
            Ok(json!({ "status": "pending", "request_id": "request-2" })),
            "the stand-in did the work: it mints request-2 for the running instance"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                pending_request("request-1", "component-1"),
                json!({
                    "request_id": "request-2",
                    "session_id": "component-1",
                    "resource": SHARED_RESOURCE,
                    "action": "write",
                    "reason": "read shared",
                    "status": "pending",
                    "decision_reason": "",
                    "settled_by": Value::Null,
                }),
            ],
            "the stand-in did the work: it stores both pending requests and lowercases the second action"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: the running instance stays running after the second request",
        );
    }

    #[test]
    fn standin_capability_request_refuses_a_bad_body() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let launched = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches once");
        assert_eq!(
            (launched["id"].as_str(), launched["status"].as_str()),
            (Some("component-1"), Some("starting")),
            "the stand-in did the work: it launches component-1 starting"
        );
        let caller = Caller::Client {
            session_id: "component-1",
        };
        for (body, reason, message) in [
            (
                json!({}),
                "request body needs resource",
                "a body with no resource",
            ),
            (
                json!({ "resource": "https://example", "action": "read" }),
                "Unsupported resource scheme. Allowed: elastos://, localhost://",
                "a resource without an allowed scheme",
            ),
            (
                json!({ "resource": SHARED_RESOURCE, "action": "mint" }),
                "Invalid action: mint. Expected: read, write, execute, delete, message, admin",
                "an action outside the six names",
            ),
            (
                json!({ "resource": SHARED_RESOURCE, "action": "read", "token": "x" }),
                "request body rejects token",
                "an extra body key",
            ),
        ] {
            let refused = standin.post_capability_request(caller, &body);
            assert_eq!(
                refused,
                Err((400, reason.to_owned())),
                "the stand-in did the work: it refuses {message} and stores nothing"
            );
        }
        assert_eq!(
            shell_requests(&standin, "component-1"),
            json!({ "requests": [] }),
            "the stand-in did the work: every refused body stores no request"
        );
        let accepted = standin.post_capability_request(caller, &request_client_body());
        assert_eq!(
            accepted,
            Ok(json!({ "status": "pending", "request_id": "request-1" })),
            "the stand-in did the work: the refused bodies do not advance the request id"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("request-1", "component-1")],
            "the stand-in did the work: the valid body stores request-1"
        );
    }

    #[test]
    fn standin_session_pending_cap() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let first = launch_finished(&mut standin);
        let second = launch_finished(&mut standin);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("component-1", "component-2"),
            "the stand-in did the work: it numbers the two launches component-1 and component-2"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: it lists component-1 running after start",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: it lists component-2 running after start",
        );
        let owner = Caller::Client {
            session_id: "component-1",
        };
        let sibling = Caller::Client {
            session_id: "component-2",
        };

        let pending_ids = (1..=32)
            .map(|number| format!("request-{number}"))
            .collect::<Vec<_>>();
        for (index, request_id) in pending_ids.iter().enumerate() {
            assert_eq!(
                standin.post_capability_request(owner, &request_client_body()),
                Ok(json!({ "status": "pending", "request_id": request_id })),
                "the stand-in did the work: call {} of 32 answers pending and {request_id}",
                index + 1
            );
        }
        let mut text_order = pending_ids.clone();
        text_order.sort();
        let expected = text_order
            .iter()
            .map(|request_id| pending_request(request_id, "component-1"))
            .collect::<Vec<_>>();
        let listed = request_entries(&standin, "component-1");
        assert_eq!(
            listed, expected,
            "the stand-in did the work: the shell record for component-1 holds request-1 through request-32 in text order"
        );
        for entry in &listed {
            assert_eq!(
                entry["status"].as_str(),
                Some("pending"),
                "the stand-in did the work: every stored record of component-1 is pending"
            );
            assert_eq!(
                entry["settled_by"],
                Value::Null,
                "the stand-in did the work: every pending record has no settler"
            );
        }

        let refused = standin.post_capability_request(owner, &request_client_body());
        assert_eq!(
            refused,
            Err((400, "Too many pending requests for this session".to_owned(),)),
            "the stand-in did the work: the 33rd pending record of component-1 is refused"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            expected,
            "the stand-in did the work: the refused 33rd record changes no stored record"
        );

        let other = standin.post_capability_request(sibling, &request_client_body());
        assert_eq!(
            other,
            Ok(json!({ "status": "pending", "request_id": "request-33" })),
            "the stand-in did the work: the sibling session stores the next request"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-33", "component-2")],
            "the stand-in did the work: the sibling record is one pending request-33"
        );
        assert_live_request_ids_empty(
            &standin,
            "the request route stores no live grant for component-2",
        );

        let granted = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "request-1",
                    "duration": "session",
                    "rationale": "grant shared read",
                }),
            )
            .expect("the stand-in grants request-1");
        assert_eq!(
            granted,
            json!({ "success": true }),
            "the stand-in did the work: the shell grant answers success true"
        );
        let mut after_grant = expected;
        after_grant[0] = granted_request("request-1", "component-1", "grant shared read");
        assert_eq!(
            request_entries(&standin, "component-1"),
            after_grant,
            "the stand-in did the work: request-1 is granted and the other 31 stay pending"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live-grant view")
            ),
            BTreeSet::from(["request-1".to_owned()]),
            "the stand-in did the work: the live-grant set is exactly request-1"
        );

        let next = standin.post_capability_request(owner, &request_client_body());
        assert_eq!(
            next,
            Ok(json!({ "status": "pending", "request_id": "request-34" })),
            "the stand-in did the work: the granted record frees one slot for request-34"
        );
        let mut pending_after = (2..=32)
            .map(|number| format!("request-{number}"))
            .chain(std::iter::once("request-34".to_owned()))
            .collect::<Vec<_>>();
        pending_after.sort();
        let pending_set = pending_after.into_iter().collect::<BTreeSet<String>>();
        let stored = request_entries(&standin, "component-1");
        assert_eq!(
            stored
                .iter()
                .filter(|entry| entry["status"] == "pending")
                .map(|entry| entry["request_id"].as_str().unwrap().to_owned())
                .collect::<BTreeSet<String>>(),
            pending_set,
            "the stand-in did the work: the pending set is request-2 through request-32 plus request-34"
        );
        assert_eq!(
            stored.len(),
            33,
            "the stand-in did the work: the store holds request-1 granted and 32 pending records"
        );

        let capped = standin.post_capability_request(owner, &request_client_body());
        assert_eq!(
            capped,
            Err((
                400,
                "Too many pending requests for this session".to_owned(),
            )),
            "the stand-in did the work: the next component-1 call is refused with the same cap reason"
        );
        let after_cap = request_entries(&standin, "component-1");
        assert_eq!(
            after_cap.len(),
            33,
            "the stand-in did the work: the refused call stores no request-35"
        );
        assert!(
            after_cap
                .iter()
                .all(|entry| entry["request_id"] != "request-35"),
            "the stand-in did the work: no request-35 is stored"
        );
        assert_eq!(
            after_cap
                .iter()
                .find(|entry| entry["request_id"] == "request-34")
                .map(|entry| entry["status"].as_str()),
            Some(Some("pending")),
            "the stand-in did the work: request-34 stays pending after the refusal"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-33", "component-2")],
            "the stand-in did the work: the sibling record stays one pending request-33"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: it leaves component-1 running after the cap",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: it leaves component-2 running after the cap",
        );
    }

    #[test]
    fn standin_store_holds_at_most_1024_pending() {
        let mut standin = StandIn::new();
        launch_two_running(&mut standin);
        standin
            .seed_request("old", "s-old", SHARED_RESOURCE, "read", "read shared")
            .expect("the stand-in stores old at instant 0");
        standin.set_instant(300);
        assert_eq!(
            request_entries(&standin, "s-old"),
            vec![expired_request("old", "s-old")],
            "the stand-in did the work: old is expired at instant 300"
        );

        for number in 1..=32 {
            standin
                .seed_request(&format!("pack-{number}"), "packed", "res", "read", "bulk")
                .expect("the stand-in stores the 32 pending records of packed");
        }
        assert_eq!(
            standin.seed_request("pack-33", "packed", "res", "read", "bulk"),
            Err((
                400,
                "Too many pending requests for this session".to_owned(),
            )),
            "the stand-in did the work: packed gets the session reason while the store is under 1024"
        );
        assert!(
            standin
                .requests
                .iter()
                .all(|request| request.request_id != "pack-33"),
            "the stand-in did the work: no pack-33 is stored"
        );

        for number in 1..=992 {
            standin
                .seed_request(
                    &format!("fill-{number}"),
                    &format!("f-{number}"),
                    "res",
                    "read",
                    "bulk",
                )
                .expect("the stand-in stores the fill pending record");
        }
        assert_eq!(
            pending_count(&standin),
            1024,
            "the stand-in did the work: the store holds 1024 pending records"
        );
        assert_eq!(
            request_entries(&standin, "s-old"),
            vec![expired_request("old", "s-old")],
            "the stand-in did the work: old stays expired and outside the pending count"
        );

        assert_eq!(
            standin.seed_request("over", "s-over", "res", "read", "bulk"),
            Err((400, "Too many pending requests".to_owned())),
            "the stand-in did the work: over is refused while the store holds 1024 pending records"
        );
        assert!(
            standin
                .requests
                .iter()
                .all(|request| request.request_id != "over"),
            "the stand-in did the work: no over is stored"
        );
        assert_eq!(
            standin.seed_request("pack-34", "packed", "res", "read", "bulk"),
            Err((400, "Too many pending requests".to_owned())),
            "the stand-in did the work: the store reason wins over the session reason at 1024"
        );
        assert!(
            standin
                .requests
                .iter()
                .all(|request| request.request_id != "pack-34"),
            "the stand-in did the work: no pack-34 is stored"
        );

        let granted = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "fill-1",
                    "duration": "session",
                    "rationale": "grant one",
                }),
            )
            .expect("the stand-in grants fill-1");
        assert_eq!(
            granted,
            json!({ "success": true }),
            "the stand-in did the work: the shell grant of fill-1 answers success true"
        );
        assert_eq!(
            request_entries(&standin, "f-1"),
            vec![json!({
                "request_id": "fill-1",
                "session_id": "f-1",
                "resource": "res",
                "action": "read",
                "reason": "bulk",
                "status": "granted",
                "decision_reason": "grant one",
                "settled_by": "shell",
            })],
            "the stand-in did the work: the shell record for fill-1 is granted"
        );

        standin
            .seed_request("room", "s-room", "res", "read", "bulk")
            .expect("the stand-in stores room after the grant frees one slot");
        assert_eq!(
            pending_count(&standin),
            1024,
            "the stand-in did the work: the store holds 1024 pending records again"
        );

        let client = Caller::Client {
            session_id: "component-2",
        };
        let body = request_client_body();
        assert_eq!(
            standin.post_capability_request(client, &body),
            Err((400, "Too many pending requests".to_owned())),
            "the stand-in did the work: the request route returns the store reason and stores nothing"
        );
        assert!(
            standin
                .requests
                .iter()
                .all(|request| request.request_id != "request-1"),
            "the stand-in did the work: no request-1 is stored"
        );

        let denied = standin
            .post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": "room", "reason": "deny room" }),
            )
            .expect("the stand-in denies room");
        assert_eq!(
            denied,
            json!({ "success": true }),
            "the stand-in did the work: the shell deny of room answers success true"
        );

        assert_eq!(
            standin.post_capability_request(client, &body),
            Ok(json!({ "status": "pending", "request_id": "request-1" })),
            "the stand-in did the work: the client stores request-1 after the deny frees one slot"
        );
        assert_eq!(
            pending_count(&standin),
            1024,
            "the stand-in did the work: the store holds 1024 pending records after request-1"
        );

        assert_eq!(
            standin.post_capability_request(client, &body),
            Err((400, "Too many pending requests".to_owned())),
            "the stand-in did the work: the next client call is refused with the store reason"
        );
        assert!(
            standin
                .requests
                .iter()
                .all(|request| request.request_id != "request-2"),
            "the stand-in did the work: no request-2 is stored"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-1", "component-2")],
            "the stand-in did the work: request-1 stays pending after the refusal"
        );

        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: it leaves component-1 running after the store cap",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: it leaves component-2 running after the store cap",
        );
    }

    fn assert_other_session_refused(
        result: &Result<Value, (u16, String)>,
        caller: &str,
        message: &str,
    ) {
        assert_eq!(
            result,
            &Err((403, "Cannot access another session's request".to_owned())),
            "the stand-in did the work: it refuses {caller} on another session's request ({message})"
        );
    }

    #[test]
    fn standin_guest_reads_its_request_later() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let first = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches the first read-shared instance");
        let second = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches the second read-shared instance");
        assert_eq!(
            (first["id"].as_str(), second["id"].as_str()),
            (Some("component-1"), Some("component-2")),
            "the stand-in did the work: it numbers the launches component-1 and component-2"
        );
        assert_eq!(
            (first["status"].as_str(), second["status"].as_str()),
            (Some("starting"), Some("starting")),
            "the stand-in did the work: it answers starting for both launches"
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        let owner = Caller::Client {
            session_id: "component-1",
        };
        let sibling = Caller::Client {
            session_id: "component-2",
        };

        assert_eq!(
            standin.get_capability_request(owner, "req-1"),
            Ok(json!({ "status": "pending" })),
            "the stand-in did the work: the owning client reads req-1 pending before any decision"
        );
        assert_other_session_refused(
            &standin.get_capability_request(Caller::Shell, "req-1"),
            "the shell caller",
            "req-1 is the client's record",
        );
        assert_other_session_refused(
            &standin.get_capability_request(sibling, "req-1"),
            "the component-2 client",
            "req-1 belongs to component-1",
        );
        assert_eq!(
            standin.get_capability_request(sibling, "missing"),
            Err((404, "Request not found: missing".to_owned())),
            "the stand-in did the work: it answers 404 for an id that matches no record"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in did the work: the refused reads leave req-1 pending"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in did the work: the refused reads leave the sibling request pending"
        );

        standin.set_instant(4);
        let granted = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-1",
                    "duration": "session",
                    "rationale": "grant shared read",
                }),
            )
            .expect("the stand-in grants the first instance's request");
        assert_eq!(
            granted,
            json!({ "success": true }),
            "the stand-in did the work: the shell grant answers success true"
        );
        assert_eq!(
            standin.get_capability_request(owner, "req-1"),
            Ok(json!({ "status": "granted" })),
            "the stand-in did the work: the owning client reads req-1 granted on a later call"
        );
        assert_eq!(
            standin.get_capability_request(owner, "req-1"),
            Ok(json!({ "status": "granted" })),
            "the stand-in did the work: a second read of req-1 is the same body"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![granted_request("req-1", "component-1", "grant shared read")],
            "the stand-in did the work: the shell record for req-1 is granted with the rationale"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live-grant view")
            ),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in did the work: the live-grant set is exactly req-1 after the grant"
        );

        let denied = standin
            .post_capability_deny(
                Caller::Shell,
                &json!({
                    "request_id": "req-2",
                    "reason": "sibling read denied",
                }),
            )
            .expect("the stand-in denies the sibling's request");
        assert_eq!(
            denied,
            json!({ "success": true }),
            "the stand-in did the work: the shell deny answers success true"
        );
        assert_eq!(
            standin.get_capability_request(sibling, "req-2"),
            Ok(json!({ "status": "denied", "reason": "sibling read denied" })),
            "the stand-in did the work: the sibling client reads its denial reason on a later call"
        );
        assert_other_session_refused(
            &standin.get_capability_request(owner, "req-2"),
            "the component-1 client",
            "req-2 belongs to component-2",
        );
        let sibling_read = standin
            .get_capability_request(sibling, "req-2")
            .expect("the stand-in sibling denial read");
        assert_keys(
            &sibling_read,
            &["status", "reason"],
            "the stand-in did the work: a denied body has status and reason only",
        );
        assert_capsule(
            &standin,
            "component-1",
            "starting",
            "",
            "the stand-in did the work: the deny leaves the granted instance starting",
        );
        assert_capsule(
            &standin,
            "component-2",
            "failed",
            "sibling read denied",
            "the stand-in did the work: the deny fails the starting sibling with its reason",
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live-grant view")
            ),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in did the work: the reads leave the live-grant set exactly req-1"
        );
    }

    #[test]
    fn standin_guest_reads_a_runtime_denial() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let first = launch_finished(&mut standin);
        let second = launch_finished(&mut standin);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("component-1", "component-2"),
            "the stand-in did the work: it numbers the two launches component-1 and component-2"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: it lists component-1 running before the stop",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: it lists component-2 running before the stop",
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 with the stop reason");
        let owner = Caller::Client {
            session_id: "component-1",
        };
        let sibling = Caller::Client {
            session_id: "component-2",
        };
        let denial = json!({ "status": "denied", "reason": "stopped: stop one" });
        assert_eq!(
            standin.get_capability_request(owner, "req-1"),
            Ok(denial.clone()),
            "the stand-in did the work: the stopped owner reads its request denied by the runtime"
        );
        standin.set_instant(60);
        assert_eq!(
            standin.get_capability_request(owner, "req-1"),
            Ok(denial),
            "the stand-in did the work: the same read stays that denial at instant 60"
        );
        assert_other_session_refused(
            &standin.get_capability_request(sibling, "req-1"),
            "the component-2 client",
            "req-1 belongs to component-1",
        );
        assert_other_session_refused(
            &standin.get_capability_request(Caller::Shell, "req-1"),
            "the shell caller",
            "req-1 is the client's record",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![denied_request("req-1", "component-1", "stopped: stop one")],
            "the stand-in did the work: the reads leave the runtime denial record as it was"
        );
        assert_live_request_ids_empty(&standin, "the denial read leaves no live grant");
    }

    #[test]
    fn standin_shell_revoke_drops_one_live_grant() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let first = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches the first read-shared instance");
        let second = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches the second read-shared instance");
        assert_eq!(
            (first["id"].as_str(), second["id"].as_str()),
            (Some("component-1"), Some("component-2")),
            "the stand-in did the work: it numbers the two launches component-1 and component-2"
        );
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes the component-1 start");
        standin
            .finish_start("component-2")
            .expect("the stand-in finishes the component-2 start");
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: it lists component-1 running after its start",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: it lists component-2 running after its start",
        );

        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-3", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        standin.set_instant(4);

        let first_grant = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-1",
                    "duration": "session",
                    "rationale": "grant shared read",
                }),
            )
            .expect("the stand-in grants req-1 for the session");
        assert_eq!(
            first_grant,
            json!({ "success": true }),
            "the stand-in did the work: the req-1 grant answers success true and stores no token"
        );
        let once_grant = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-3",
                    "duration": "once",
                    "rationale": "grant once",
                }),
            )
            .expect("the stand-in grants req-3 once");
        assert_eq!(
            once_grant,
            json!({ "success": true }),
            "the stand-in did the work: the req-3 once grant answers success true"
        );
        let sibling_grant = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-2",
                    "duration": "session",
                    "rationale": "grant sibling",
                }),
            )
            .expect("the stand-in grants req-2 for its session");
        assert_eq!(
            sibling_grant,
            json!({ "success": true }),
            "the stand-in did the work: the req-2 grant answers success true"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live-grant view")
            ),
            BTreeSet::from(["req-1".to_owned(), "req-2".to_owned(), "req-3".to_owned(),]),
            "the stand-in did the work: it lists exactly the three shell grants"
        );
        standin
            .authorise(
                Caller::Client {
                    session_id: "component-1",
                },
                "req-1",
            )
            .expect("the stand-in authorises req-1 before the revoke");
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Live, false),
            "the stand-in did the work: the req-1 grant is live before the revoke"
        );

        let revoked = standin
            .delete_capability(Caller::Shell, "req-3")
            .expect("the stand-in revokes req-3");
        assert_keys(
            &revoked,
            &["revoked_request_id", "success"],
            "the stand-in did the work: the revoke body has two keys",
        );
        assert_eq!(
            revoked,
            json!({ "success": true, "revoked_request_id": "req-3" }),
            "the stand-in did the work: it answers the revoked id and stores no token"
        );
        let mut revoked_record = denied_request("req-3", "component-1", "Revoked by user");
        revoked_record["settled_by"] = json!("shell");
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                granted_request("req-1", "component-1", "grant shared read"),
                revoked_record.clone(),
            ],
            "the stand-in did the work: the revoke denies req-3 and keeps req-1 granted"
        );
        assert_eq!(
            request_entries(&standin, "component-1")[1]["settled_by"],
            json!("shell"),
            "the stand-in did the work: the shell is the settler of the revoked record"
        );
        assert_eq!(
            grant_record(&standin, "req-3"),
            (Life::Revoked, false),
            "the stand-in did the work: the revoke drops the req-3 live grant"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live-grant view")
            ),
            BTreeSet::from(["req-1".to_owned(), "req-2".to_owned()]),
            "the stand-in did the work: it lists req-1 and req-2 after the revoke"
        );
        assert!(
            matches!(
                standin.authorise(
                    Caller::Client {
                        session_id: "component-1",
                    },
                    "req-3",
                ),
                Err((400, reason)) if reason == "grant is not live: Revoked"
            ),
            "the stand-in did the work: it refuses the revoked grant on the next use"
        );
        standin
            .authorise(
                Caller::Client {
                    session_id: "component-1",
                },
                "req-1",
            )
            .expect("the stand-in keeps authorising req-1 after the revoke");
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Live, false),
            "the stand-in did the work: the revoke leaves req-1 live"
        );
        standin
            .authorise(
                Caller::Client {
                    session_id: "component-2",
                },
                "req-2",
            )
            .expect("the stand-in authorises the sibling grant after the revoke");
        assert_eq!(
            grant_record(&standin, "req-2"),
            (Life::Live, false),
            "the stand-in did the work: the revoke leaves the sibling grant live"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                granted_request("req-1", "component-1", "grant shared read"),
                revoked_record.clone(),
            ],
            "the stand-in did the work: the reads leave the two component-1 records as they were"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![granted_request("req-2", "component-2", "grant sibling")],
            "the stand-in did the work: the revoke leaves the sibling record granted"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: the revoke leaves component-1 running with no cause",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: the revoke leaves component-2 running with no cause",
        );

        let second = standin.delete_capability(Caller::Shell, "req-3");
        assert_delete(
            &second,
            400,
            "Capability req-3 was not granted",
            "the stand-in did the work: a second revoke of req-3 is not granted",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                granted_request("req-1", "component-1", "grant shared read"),
                revoked_record,
            ],
            "the stand-in did the work: the second revoke leaves the denied record as it was"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live-grant view")
            ),
            BTreeSet::from(["req-1".to_owned(), "req-2".to_owned()]),
            "the stand-in did the work: the second revoke leaves req-1 and req-2 live"
        );
    }

    #[test]
    fn standin_shell_revoke_refuses_without_a_grant() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        launch_finished(&mut standin);
        seed_shared_request(&mut standin, "req-1", "component-1");
        standin.set_instant(4);
        standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-1",
                    "duration": "session",
                    "rationale": "grant shared read",
                }),
            )
            .expect("the stand-in grants req-1 for the session");
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Live, false),
            "the stand-in did the work: the req-1 grant starts live"
        );

        let client = standin.delete_capability(
            Caller::Client {
                session_id: "component-1",
            },
            "req-1",
        );
        assert_delete(
            &client,
            403,
            "This endpoint requires shell privileges",
            "the stand-in did the work: a client revoke is refused before the store is read",
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Live, false),
            "the stand-in did the work: the client refusal leaves the grant live"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![granted_request("req-1", "component-1", "grant shared read")],
            "the stand-in did the work: the client refusal leaves the record granted"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: the client refusal leaves component-1 running",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: the client refusal leaves component-2 running",
        );

        let missing = standin.delete_capability(Caller::Shell, "missing");
        assert_delete(
            &missing,
            404,
            "Capability request not found: missing",
            "the stand-in did the work: a revoke of a missing record is not found",
        );

        seed_shared_request(&mut standin, "req-p", "component-1");
        let pending = standin.delete_capability(Caller::Shell, "req-p");
        assert_delete(
            &pending,
            400,
            "Capability req-p was not granted",
            "the stand-in did the work: a revoke of a pending record is not granted",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                granted_request("req-1", "component-1", "grant shared read"),
                pending_request("req-p", "component-1"),
            ],
            "the stand-in did the work: the refusals leave the two records as they were"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live-grant view")
            ),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in did the work: the live set still holds req-1"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: the pending refusal leaves component-1 running",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: the pending refusal leaves component-2 running",
        );
    }

    #[test]
    fn standin_shell_revoke_all_drops_every_live_grant() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        let first = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches the first read-shared instance");
        let second = standin
            .post_capsules(Caller::Shell, &shared_body())
            .expect("the stand-in launches the second read-shared instance");
        assert_eq!(
            (first["id"].as_str(), second["id"].as_str()),
            (Some("component-1"), Some("component-2")),
            "the stand-in did the work: it numbers the two launches component-1 and component-2"
        );
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes the component-1 start");
        standin
            .finish_start("component-2")
            .expect("the stand-in finishes the component-2 start");
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: it lists component-1 running after its start",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: it lists component-2 running after its start",
        );

        seed_shared_request(&mut standin, "req-expired", "component-2");
        standin.set_instant(300);
        standin.set_instant(4);
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-3", "component-1");
        seed_shared_request(&mut standin, "req-denied", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        seed_shared_request(&mut standin, "req-p", "component-2");
        let denied = standin
            .post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": "req-denied", "reason": "deny shared read" }),
            )
            .expect("the stand-in denies req-denied before the revoke-all");
        assert_eq!(
            denied,
            json!({ "success": true }),
            "the stand-in did the work: the req-denied record starts denied"
        );
        assert!(
            request_entries(&standin, "component-2")
                .iter()
                .any(|record| record == &expired_request("req-expired", "component-2")),
            "the stand-in did the work: the req-expired record starts expired"
        );

        let first_grant = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-1",
                    "duration": "session",
                    "rationale": "grant shared read",
                }),
            )
            .expect("the stand-in grants req-1 for the session");
        assert_eq!(
            first_grant,
            json!({ "success": true }),
            "the stand-in did the work: the req-1 grant answers success true"
        );
        let once_grant = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-3",
                    "duration": "once",
                    "rationale": "grant once",
                }),
            )
            .expect("the stand-in grants req-3 once");
        assert_eq!(
            once_grant,
            json!({ "success": true }),
            "the stand-in did the work: the req-3 once grant answers success true"
        );
        let sibling_grant = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-2",
                    "duration": "session",
                    "rationale": "grant sibling",
                }),
            )
            .expect("the stand-in grants req-2 for its session");
        assert_eq!(
            sibling_grant,
            json!({ "success": true }),
            "the stand-in did the work: the req-2 grant answers success true"
        );
        standin.seed_grant(
            "req-orphan",
            "component-2",
            "res",
            "read",
            "session",
            4,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-ended",
            "component-2",
            "res-ended",
            "read",
            "session",
            4,
            Life::Live,
            true,
        );
        standin.seed_grant(
            "req-old",
            "component-1",
            "res-old",
            "read",
            "session",
            4,
            Life::Expired,
            false,
        );
        standin
            .authorise(
                Caller::Client {
                    session_id: "component-1",
                },
                "req-3",
            )
            .expect("the stand-in spends the req-3 once grant");
        assert_eq!(
            grant_record(&standin, "req-3"),
            (Life::Exhausted, false),
            "the stand-in did the work: one use exhausts the req-3 grant"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live-grant view")
            ),
            BTreeSet::from([
                "req-1".to_owned(),
                "req-2".to_owned(),
                "req-ended".to_owned(),
                "req-orphan".to_owned(),
            ]),
            "the stand-in did the work: it lists exactly req-1, req-2, req-ended and req-orphan"
        );

        let revoked = standin
            .post_capability_revoke_all(Caller::Shell, &json!({ "reason": "stop every grant" }))
            .expect("the stand-in revokes every live grant");
        assert_eq!(
            revoked,
            json!({ "success": true, "reason": "stop every grant" }),
            "the stand-in did the work: the revoke-all answers success true and the shell reason"
        );
        let mut revoked_req1 = denied_request("req-1", "component-1", "stop every grant");
        revoked_req1["settled_by"] = json!("shell");
        let mut revoked_req3 = denied_request("req-3", "component-1", "stop every grant");
        revoked_req3["settled_by"] = json!("shell");
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                revoked_req1.clone(),
                revoked_req3.clone(),
                shell_denied_request("req-denied", "component-1", "deny shared read"),
            ],
            "the stand-in did the work: the revoke-all denies both granted component-1 records and keeps req-denied"
        );
        assert_eq!(
            request_entries(&standin, "component-1")[0]["settled_by"],
            json!("shell"),
            "the stand-in did the work: the shell is the settler of the req-1 record"
        );
        let mut revoked_req2 = denied_request("req-2", "component-2", "stop every grant");
        revoked_req2["settled_by"] = json!("shell");
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![
                revoked_req2.clone(),
                expired_request("req-expired", "component-2"),
                pending_request("req-p", "component-2"),
            ],
            "the stand-in did the work: the revoke-all denies req-2, keeps req-expired and leaves req-p pending"
        );
        assert_eq!(
            request_entries(&standin, "component-2")[0]["settled_by"],
            json!("shell"),
            "the stand-in did the work: the shell is the settler of the req-2 record"
        );
        assert!(
            !request_entries(&standin, "component-2")
                .iter()
                .any(|record| record["request_id"] == "req-orphan"),
            "the stand-in did the work: the component-2 record list has no req-orphan"
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Revoked, false),
            "the stand-in did the work: the revoke-all drops the req-1 live grant"
        );
        assert_eq!(
            grant_record(&standin, "req-2"),
            (Life::Revoked, false),
            "the stand-in did the work: the revoke-all drops the req-2 live grant"
        );
        assert_eq!(
            grant_record(&standin, "req-orphan"),
            (Life::Revoked, false),
            "the stand-in did the work: the revoke-all drops the live grant with no record"
        );
        assert_eq!(
            grant_record(&standin, "req-3"),
            (Life::Exhausted, false),
            "the stand-in did the work: the revoke-all leaves the exhausted req-3 grant"
        );
        assert_eq!(
            grant_record(&standin, "req-ended"),
            (Life::Revoked, true),
            "the stand-in did the work: the revoke-all drops the live grant and keeps its ended session flag"
        );
        assert_eq!(
            grant_record(&standin, "req-old"),
            (Life::Expired, false),
            "the stand-in did the work: the revoke-all leaves the expired req-old grant"
        );
        let assert_preserved_grants = |standin: &StandIn| {
            for (request_id, expected) in [
                (
                    "req-1",
                    json!({
                        "request_id": "req-1",
                        "session_id": "component-1",
                        "resource": SHARED_RESOURCE,
                        "action": "read",
                        "duration": "session",
                        "granted_at": 4,
                    }),
                ),
                (
                    "req-2",
                    json!({
                        "request_id": "req-2",
                        "session_id": "component-2",
                        "resource": SHARED_RESOURCE,
                        "action": "read",
                        "duration": "session",
                        "granted_at": 4,
                    }),
                ),
                (
                    "req-orphan",
                    json!({
                        "request_id": "req-orphan",
                        "session_id": "component-2",
                        "resource": "res",
                        "action": "read",
                        "duration": "session",
                        "granted_at": 4,
                    }),
                ),
                (
                    "req-3",
                    json!({
                        "request_id": "req-3",
                        "session_id": "component-1",
                        "resource": SHARED_RESOURCE,
                        "action": "read",
                        "duration": "once",
                        "granted_at": 4,
                    }),
                ),
                (
                    "req-old",
                    json!({
                        "request_id": "req-old",
                        "session_id": "component-1",
                        "resource": "res-old",
                        "action": "read",
                        "duration": "session",
                        "granted_at": 4,
                    }),
                ),
                (
                    "req-ended",
                    json!({
                        "request_id": "req-ended",
                        "session_id": "component-2",
                        "resource": "res-ended",
                        "action": "read",
                        "duration": "session",
                        "granted_at": 4,
                    }),
                ),
            ] {
                let grant = standin
                    .grants
                    .iter()
                    .find(|grant| grant.request_id == request_id)
                    .expect("the stand-in keeps the seeded grant");
                assert_eq!(
                    entry(grant, true),
                    expected,
                    "the stand-in did the work: the revoke-all keeps every field of {request_id}"
                );
            }
        };
        assert_preserved_grants(&standin);
        assert_live_request_ids_empty(&standin, "the revoke-all leaves no live grant");
        assert!(
            matches!(
                standin.authorise(
                    Caller::Client {
                        session_id: "component-1",
                    },
                    "req-1",
                ),
                Err((400, reason)) if reason == "grant is not live: Revoked"
            ),
            "the stand-in did the work: the component-1 client cannot use the revoked req-1"
        );
        assert!(
            matches!(
                standin.authorise(
                    Caller::Client {
                        session_id: "component-2",
                    },
                    "req-2",
                ),
                Err((400, reason)) if reason == "grant is not live: Revoked"
            ),
            "the stand-in did the work: the component-2 client cannot use the revoked req-2"
        );
        assert!(
            matches!(
                standin.authorise(
                    Caller::Client {
                        session_id: "component-1",
                    },
                    "req-3",
                ),
                Err((400, reason)) if reason == "grant is not live: Exhausted"
            ),
            "the stand-in did the work: the component-1 client cannot use the exhausted req-3"
        );
        assert!(
            matches!(
                standin.authorise(
                    Caller::Client {
                        session_id: "component-2",
                    },
                    "req-ended",
                ),
                Err((400, reason)) if reason == "grant is not live: Revoked"
            ),
            "the stand-in did the work: the component-2 client cannot use the revoked req-ended"
        );
        assert!(
            matches!(
                standin.authorise(
                    Caller::Client {
                        session_id: "component-1",
                    },
                    "req-old",
                ),
                Err((400, reason)) if reason == "grant is not live: Expired"
            ),
            "the stand-in did the work: the component-1 client cannot use the expired req-old"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: the revoke-all leaves component-1 running with no cause",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: the revoke-all leaves component-2 running with no cause",
        );

        let second = standin
            .post_capability_revoke_all(Caller::Shell, &json!({ "reason": "stop every grant" }))
            .expect("the stand-in answers a second revoke-all");
        assert_eq!(
            second,
            json!({ "success": true, "reason": "stop every grant" }),
            "the stand-in did the work: the second revoke-all is the same Ok value"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                revoked_req1,
                revoked_req3,
                shell_denied_request("req-denied", "component-1", "deny shared read"),
            ],
            "the stand-in did the work: the second revoke-all leaves the component-1 records"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![
                revoked_req2,
                expired_request("req-expired", "component-2"),
                pending_request("req-p", "component-2"),
            ],
            "the stand-in did the work: the second revoke-all leaves the component-2 records"
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Revoked, false),
            "the stand-in did the work: the second revoke-all leaves req-1 revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-2"),
            (Life::Revoked, false),
            "the stand-in did the work: the second revoke-all leaves req-2 revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-orphan"),
            (Life::Revoked, false),
            "the stand-in did the work: the second revoke-all leaves req-orphan revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-3"),
            (Life::Exhausted, false),
            "the stand-in did the work: the second revoke-all leaves req-3 exhausted"
        );
        assert_eq!(
            grant_record(&standin, "req-ended"),
            (Life::Revoked, true),
            "the stand-in did the work: the second revoke-all leaves req-ended revoked with its ended session flag"
        );
        assert_eq!(
            grant_record(&standin, "req-old"),
            (Life::Expired, false),
            "the stand-in did the work: the second revoke-all leaves req-old expired"
        );
        assert_live_request_ids_empty(&standin, "the second revoke-all leaves no live grant");
        assert_preserved_grants(&standin);
    }

    #[test]
    fn standin_shell_revoke_all_refuses_without_shell() {
        let mut standin = StandIn::new();
        admit_shared(&mut standin, Start::Ok);
        launch_finished(&mut standin);
        launch_finished(&mut standin);
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        standin.set_instant(4);
        standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-1",
                    "duration": "session",
                    "rationale": "grant shared read",
                }),
            )
            .expect("the stand-in grants req-1 for the session");
        standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-2",
                    "duration": "session",
                    "rationale": "grant sibling",
                }),
            )
            .expect("the stand-in grants req-2 for its session");
        assert_eq!(
            (
                grant_record(&standin, "req-1"),
                grant_record(&standin, "req-2"),
            ),
            ((Life::Live, false), (Life::Live, false)),
            "the stand-in did the work: both grants start live"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![granted_request("req-1", "component-1", "grant shared read")],
            "the stand-in did the work: the req-1 record starts granted"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![granted_request("req-2", "component-2", "grant sibling")],
            "the stand-in did the work: the req-2 record starts granted"
        );

        let client = standin.post_capability_revoke_all(
            Caller::Client {
                session_id: "component-1",
            },
            &json!({}),
        );
        assert_delete(
            &client,
            403,
            "This endpoint requires shell privileges",
            "the stand-in did the work: a client revoke-all is refused before the body is read",
        );
        let string_body = standin.post_capability_revoke_all(Caller::Shell, &json!("stop"));
        assert_delete(
            &string_body,
            400,
            "revoke body needs an object",
            "the stand-in did the work: a string body is refused",
        );
        let extra_key = standin.post_capability_revoke_all(
            Caller::Shell,
            &json!({ "reason": "stop every grant", "token": "req-1" }),
        );
        assert_delete(
            &extra_key,
            400,
            "revoke body rejects token",
            "the stand-in did the work: another body key is refused",
        );
        let number_reason =
            standin.post_capability_revoke_all(Caller::Shell, &json!({ "reason": 1 }));
        assert_delete(
            &number_reason,
            400,
            "revoke reason must be a string",
            "the stand-in did the work: a non-string reason is refused",
        );
        let client_string_body = standin.post_capability_revoke_all(
            Caller::Client {
                session_id: "component-1",
            },
            &json!("stop"),
        );
        assert_delete(
            &client_string_body,
            403,
            "This endpoint requires shell privileges",
            "the stand-in did the work: a client with a malformed body is refused before the body is read",
        );
        let client_extra_key = standin.post_capability_revoke_all(
            Caller::Client {
                session_id: "component-2",
            },
            &json!({ "reason": 1, "token": "req-1" }),
        );
        assert_delete(
            &client_extra_key,
            403,
            "This endpoint requires shell privileges",
            "the stand-in did the work: a client with two body faults is still refused as a client",
        );
        let mixed = standin
            .post_capability_revoke_all(Caller::Shell, &json!({ "reason": 1, "token": "req-1" }));
        assert_delete(
            &mixed,
            400,
            "revoke body rejects token",
            "the stand-in did the work: an unknown body key wins over a non-string reason",
        );
        assert_eq!(
            (
                grant_record(&standin, "req-1"),
                grant_record(&standin, "req-2"),
            ),
            ((Life::Live, false), (Life::Live, false)),
            "the stand-in did the work: the refusals leave both grants live"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![granted_request("req-1", "component-1", "grant shared read")],
            "the stand-in did the work: the refusals leave the req-1 record granted"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![granted_request("req-2", "component-2", "grant sibling")],
            "the stand-in did the work: the refusals leave the req-2 record granted"
        );

        let revoked = standin
            .post_capability_revoke_all(Caller::Shell, &json!({}))
            .expect("the stand-in revokes every live grant with the default reason");
        assert_eq!(
            revoked,
            json!({ "success": true, "reason": "Revoked all by user" }),
            "the stand-in did the work: a missing reason is Revoked all by user"
        );
        let mut revoked_req1 = denied_request("req-1", "component-1", "Revoked all by user");
        revoked_req1["settled_by"] = json!("shell");
        let mut revoked_req2 = denied_request("req-2", "component-2", "Revoked all by user");
        revoked_req2["settled_by"] = json!("shell");
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![revoked_req1],
            "the stand-in did the work: the default reason denies the req-1 record"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![revoked_req2],
            "the stand-in did the work: the default reason denies the req-2 record"
        );
        assert_eq!(
            request_entries(&standin, "component-1")[0]["settled_by"],
            json!("shell"),
            "the stand-in did the work: the shell is the settler of the default-reason record"
        );
        assert_eq!(
            (
                grant_record(&standin, "req-1"),
                grant_record(&standin, "req-2"),
            ),
            ((Life::Revoked, false), (Life::Revoked, false)),
            "the stand-in did the work: the revoke-all drops both live grants"
        );
        assert_live_request_ids_empty(&standin, "the revoke-all leaves no live grant");
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: the revoke-all leaves component-1 running with no cause",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: the revoke-all leaves component-2 running with no cause",
        );

        let fresh_grants = || {
            let mut standin = StandIn::new();
            admit_shared(&mut standin, Start::Ok);
            launch_finished(&mut standin);
            launch_finished(&mut standin);
            seed_shared_request(&mut standin, "req-1", "component-1");
            seed_shared_request(&mut standin, "req-2", "component-2");
            standin.set_instant(4);
            standin
                .post_capability_grant(
                    Caller::Shell,
                    &json!({
                        "request_id": "req-1",
                        "duration": "session",
                        "rationale": "grant shared read",
                    }),
                )
                .expect("the stand-in grants req-1 for the session");
            standin
                .post_capability_grant(
                    Caller::Shell,
                    &json!({
                        "request_id": "req-2",
                        "duration": "session",
                        "rationale": "grant sibling",
                    }),
                )
                .expect("the stand-in grants req-2 for its session");
            standin
        };

        let mut null_standin = fresh_grants();
        let null_body = null_standin
            .post_capability_revoke_all(Caller::Shell, &Value::Null)
            .expect("the stand-in accepts a null body as the default reason");
        assert_eq!(
            null_body,
            json!({ "success": true, "reason": "Revoked all by user" }),
            "the stand-in did the work: a null body uses the default reason"
        );
        assert_eq!(
            request_entries(&null_standin, "component-1"),
            vec![shell_denied_request(
                "req-1",
                "component-1",
                "Revoked all by user"
            )],
            "the stand-in did the work: the null body denies the req-1 record"
        );
        assert_eq!(
            request_entries(&null_standin, "component-2"),
            vec![shell_denied_request(
                "req-2",
                "component-2",
                "Revoked all by user"
            )],
            "the stand-in did the work: the null body denies the req-2 record"
        );
        assert_eq!(
            (
                grant_record(&null_standin, "req-1"),
                grant_record(&null_standin, "req-2"),
            ),
            ((Life::Revoked, false), (Life::Revoked, false)),
            "the stand-in did the work: the null body drops both live grants"
        );
        assert_live_request_ids_empty(&null_standin, "the null body leaves no live grant");
        assert_capsule(
            &null_standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: the null body leaves component-1 running",
        );
        assert_capsule(
            &null_standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: the null body leaves component-2 running",
        );

        let mut empty_standin = fresh_grants();
        let empty_reason = empty_standin
            .post_capability_revoke_all(Caller::Shell, &json!({ "reason": "" }))
            .expect("the stand-in keeps an empty reason");
        assert_eq!(
            empty_reason,
            json!({ "success": true, "reason": "" }),
            "the stand-in did the work: an empty reason is stored as given"
        );
        assert_eq!(
            request_entries(&empty_standin, "component-1"),
            vec![shell_denied_request("req-1", "component-1", "")],
            "the stand-in did the work: the empty reason denies the req-1 record"
        );
        assert_eq!(
            request_entries(&empty_standin, "component-2"),
            vec![shell_denied_request("req-2", "component-2", "")],
            "the stand-in did the work: the empty reason denies the req-2 record"
        );
        assert_eq!(
            (
                grant_record(&empty_standin, "req-1"),
                grant_record(&empty_standin, "req-2"),
            ),
            ((Life::Revoked, false), (Life::Revoked, false)),
            "the stand-in did the work: the empty reason drops both live grants"
        );
        assert_live_request_ids_empty(&empty_standin, "the empty reason leaves no live grant");
        assert_capsule(
            &empty_standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: the empty reason leaves component-1 running",
        );
        assert_capsule(
            &empty_standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: the empty reason leaves component-2 running",
        );
    }

    #[test]
    fn standin_system_and_wallet_requests_never_become_pending() {
        const SYSTEM_REASON: &str =
            "system backends are not app capabilities; use elastos://content";
        const WALLET_REASON: &str = "generic Wallet access is limited to read-only elastos://wallet/meta/status; use the private Runtime Wallet Bus for authority-bound operations";

        let mut standin = StandIn::new();
        launch_two_running(&mut standin);
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: it lists component-1 running before the requests",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: it lists component-2 running before the requests",
        );
        let owner = Caller::Client {
            session_id: "component-1",
        };

        for resource in [
            "elastos://elacity/x",
            "elastos://elacity-sdk/x",
            "elastos://gateway/x",
            "elastos://ipfs/x",
            "elastos://ipfs-cluster/x",
            "elastos://ipfs-provider/x",
            "elastos://kubo/x",
            "elastos://ipfs?hash",
            "elastos://ipfs",
            "elastos://kubo#x",
        ] {
            let denied = standin.post_capability_request(
                owner,
                &json!({
                    "resource": resource,
                    "action": "read",
                    "reason": "read shared",
                }),
            );
            assert_eq!(
                denied,
                Ok(json!({ "status": "denied", "reason": SYSTEM_REASON })),
                "the stand-in did the work: it denies {resource} before the store"
            );
        }

        for (resource, action) in [
            ("elastos://wallet/open", "read"),
            ("elastos://wallet/meta/status", "write"),
            ("elastos://wallet/meta/status/extra", "read"),
            ("elastos://wallet", "read"),
            ("elastos://wallet?open", "read"),
            ("elastos://wallet#open", "read"),
        ] {
            let denied = standin.post_capability_request(
                owner,
                &json!({
                    "resource": resource,
                    "action": action,
                    "reason": "read shared",
                }),
            );
            assert_eq!(
                denied,
                Ok(json!({ "status": "denied", "reason": WALLET_REASON })),
                "the stand-in did the work: it denies {resource} with action {action} before the store"
            );
        }

        assert!(
            request_entries(&standin, "component-1").is_empty(),
            "the stand-in did the work: the denied requests store nothing for component-1"
        );
        assert!(
            request_entries(&standin, "component-2").is_empty(),
            "the stand-in did the work: the denied requests store nothing for component-2"
        );

        let upper_case = standin.post_capability_request(
            owner,
            &json!({
                "resource": "elastos://IPFS/x",
                "action": "read",
                "reason": "read shared",
            }),
        );
        assert_eq!(
            upper_case,
            Ok(json!({ "status": "pending", "request_id": "request-1" })),
            "the stand-in did the work: the segment compare keeps its case, so IPFS stores request-1"
        );
        let status_read = standin.post_capability_request(
            owner,
            &json!({
                "resource": "elastos://wallet/meta/status",
                "action": "read",
                "reason": "read shared",
            }),
        );
        assert_eq!(
            status_read,
            Ok(json!({ "status": "pending", "request_id": "request-2" })),
            "the stand-in did the work: the read-only status resource stores request-2"
        );
        let content = standin.post_capability_request(
            owner,
            &json!({
                "resource": "elastos://content/demo",
                "action": "read",
                "reason": "read shared",
            }),
        );
        assert_eq!(
            content,
            Ok(json!({ "status": "pending", "request_id": "request-3" })),
            "the stand-in did the work: elastos://content stores request-3"
        );

        let stored: Vec<Value> = [
            ("request-1", "elastos://IPFS/x"),
            ("request-2", "elastos://wallet/meta/status"),
            ("request-3", "elastos://content/demo"),
        ]
        .into_iter()
        .map(|(request_id, resource)| {
            let mut entry = pending_request(request_id, "component-1");
            entry["resource"] = json!(resource);
            entry
        })
        .collect();
        assert_eq!(
            request_entries(&standin, "component-1"),
            stored,
            "the stand-in did the work: component-1 holds exactly the three pending read requests"
        );

        let further = standin.post_capability_request(
            owner,
            &json!({
                "resource": "elastos://gateway/meta",
                "action": "read",
                "reason": "read shared",
            }),
        );
        assert_eq!(
            further,
            Ok(json!({ "status": "denied", "reason": SYSTEM_REASON })),
            "the stand-in did the work: a further system body is denied before the store"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            stored,
            "the stand-in did the work: the further system body stores nothing"
        );
        assert_eq!(
            standin.next_request, 4,
            "the stand-in did the work: the denied bodies mint no request-4"
        );

        standin
            .delete_capsule(Caller::Shell, "component-2", &stop_body())
            .expect("the stand-in stops component-2 with the stop reason");
        let stopped = standin.post_capability_request(
            Caller::Client {
                session_id: "component-2",
            },
            &json!({
                "resource": "elastos://ipfs/x",
                "action": "read",
                "reason": "read shared",
            }),
        );
        assert_eq!(
            stopped,
            Err((400, "instance is not live: stopped".to_owned())),
            "the stand-in did the work: the not-live refusal still answers a stopped instance"
        );
        assert!(
            request_entries(&standin, "component-2").is_empty(),
            "the stand-in did the work: the stopped instance stores nothing"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: it leaves component-1 running after the stop",
        );
        assert_live_request_ids_empty(
            &standin,
            "the denial route stores no live grant for component-1",
        );

        let third = launch_starting(&mut standin);
        assert_eq!(
            third, "component-3",
            "the stand-in did the work: it numbers the third launch component-3"
        );
        let starting = Caller::Client {
            session_id: "component-3",
        };
        for (resource, reason) in [
            ("elastos://ipfs/x", SYSTEM_REASON),
            ("elastos://wallet/open", WALLET_REASON),
        ] {
            let denied = standin.post_capability_request(
                starting,
                &json!({
                    "resource": resource,
                    "action": "read",
                    "reason": "read shared",
                }),
            );
            assert_eq!(
                denied,
                Ok(json!({ "status": "denied", "reason": reason })),
                "the stand-in did the work: it denies {resource} from a starting instance"
            );
        }
        assert!(
            request_entries(&standin, "component-3").is_empty(),
            "the stand-in did the work: the starting instance stores nothing"
        );
        assert_capsule(
            &standin,
            "component-3",
            "starting",
            "",
            "the stand-in did the work: it leaves component-3 starting after the denials",
        );
        assert_eq!(
            standin.next_request, 4,
            "the stand-in did the work: the starting-instance denials mint no request-4"
        );

        let mut similar = StandIn::new();
        launch_two_running(&mut similar);
        let similar_owner = Caller::Client {
            session_id: "component-1",
        };
        for (resource, action, request_id, message) in [
            (
                "elastos://ipfs-extra/x",
                "read",
                "request-1",
                "ipfs-extra is not the ipfs segment",
            ),
            (
                "elastos://elacity-sdk-extra/x",
                "read",
                "request-2",
                "elacity-sdk-extra is not the elacity-sdk segment",
            ),
            (
                "elastos://wallet/meta/status",
                "Read",
                "request-3",
                "the status exception reads the lowercased action",
            ),
            (
                "elastos://Wallet/open",
                "read",
                "request-4",
                "Wallet is not the wallet segment",
            ),
        ] {
            let accepted = similar.post_capability_request(
                similar_owner,
                &json!({
                    "resource": resource,
                    "action": action,
                    "reason": "read shared",
                }),
            );
            assert_eq!(
                accepted,
                Ok(json!({ "status": "pending", "request_id": request_id })),
                "the stand-in did the work: {message} and stores {request_id}"
            );
        }
    }

    fn host_line(
        standin: &mut StandIn,
        line: &str,
        capsule_id: &str,
        principal: Option<&str>,
    ) -> Result<Value, String> {
        let raw = standin.bridge_envelope(line, capsule_id, principal)?;
        assert_eq!(
            raw.trim(),
            raw,
            "the stand-in did the work: the hostcall returns one JSON object with no trailing text"
        );
        let parsed: Value = serde_json::from_str(&raw).unwrap_or_else(|err| {
            panic!(
                "the stand-in did the work: the hostcall returns one JSON object: {err}; raw {raw:?}"
            )
        });
        assert!(
            parsed.as_object().is_some(),
            "the stand-in did the work: the hostcall returns one JSON object"
        );
        Ok(parsed)
    }

    fn assert_no_token(parsed: &Value, message: &str) {
        assert!(
            parsed.get("token").is_none(),
            "the stand-in did the work: {message} has no token key"
        );
        assert!(
            parsed["response"].get("token").is_none(),
            "the stand-in did the work: {message} response has no token key"
        );
        if let Some(data) = parsed["response"]
            .get("data")
            .filter(|data| data.is_object())
        {
            assert!(
                data.get("token").is_none(),
                "the stand-in did the work: {message} data has no token key"
            );
        }
    }

    fn assert_host_ok(parsed: &Value, id: u64, data: Value, message: &str) {
        assert_eq!(
            parsed,
            &json!({
                "id": id,
                "response": {
                    "type": "ok",
                    "data": data,
                }
            }),
            "the stand-in did the work: {message}"
        );
        assert_no_token(parsed, message);
        assert!(
            parsed["response"]
                .as_object()
                .expect("the stand-in did the work: the response is an object")
                .contains_key("data"),
            "the stand-in did the work: {message} keeps data"
        );
    }

    fn assert_host_error(parsed: &Value, id: u64, message_text: &str, message: &str) {
        assert_eq!(
            parsed,
            &json!({
                "id": id,
                "response": {
                    "type": "error",
                    "code": "denied",
                    "message": message_text,
                }
            }),
            "the stand-in did the work: {message}"
        );
        assert_no_token(parsed, message);
        assert!(
            !parsed["response"]
                .as_object()
                .expect("the stand-in did the work: the response is an object")
                .contains_key("data"),
            "the stand-in did the work: {message} error has no data"
        );
    }

    fn assert_bridge_kept(standin: &StandIn, next_request: u64, message: &str) {
        assert_eq!(
            standin.next_request, next_request,
            "the stand-in did the work: {message} stores nothing"
        );
        assert_eq!(
            grant_record(standin, "req-once"),
            (Life::Live, false),
            "the stand-in did the work: {message} leaves the grant live"
        );
    }

    fn pending_reason(request_id: &str, session_id: &str, reason: &str) -> Value {
        let mut entry = pending_request(request_id, session_id);
        entry["reason"] = json!(reason);
        entry
    }

    #[test]
    fn standin_bridge_envelope_records_the_capsule_request() {
        let mut standin = StandIn::new();
        launch_two_running(&mut standin);
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: component-1 is running",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 is running",
        );
        standin.seed_grant(
            "req-once",
            "component-1",
            SHARED_RESOURCE,
            "read",
            "once",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            grant_record(&standin, "req-once"),
            (Life::Live, false),
            "the stand-in did the work: req-once starts live"
        );

        for line in [
            r#"{"id":7}"#,
            r#"{"id":7,"request":"ping"}"#,
            r#"{"id":7,"request":null}"#,
            r#"{"id":7,"request":[]}"#,
            r#"{"id":7,"request":1}"#,
            "1",
            "null",
            "[]",
        ] {
            let refused = standin.bridge_envelope(line, "component-1", None);
            assert!(
                matches!(refused.as_ref(), Err(reason) if reason == "Invalid JSON: request must be an object"),
                "the stand-in did the work: a request that is not an object is refused: {line} {refused:?}"
            );
        }
        assert!(
            request_entries(&standin, "component-1").is_empty(),
            "the stand-in did the work: a request that is not an object stores nothing for component-1"
        );
        assert!(
            request_entries(&standin, "component-2").is_empty(),
            "the stand-in did the work: a request that is not an object stores nothing for component-2"
        );
        assert_bridge_kept(&standin, 1, "a request that is not an object");

        for id_json in [r#""7""#, "true", "7.5", "null", "-1"] {
            let line = format!(
                r#"{{"id":{id_json},"request":{{"type":"request_capability","resource":"{SHARED_RESOURCE}","action":"read","reason":"read shared"}}}}"#
            );
            let refused = standin.bridge_envelope(&line, "component-1", Some("person-a"));
            assert!(
                matches!(refused.as_ref(), Err(reason) if reason == "Invalid JSON: id must be a number"),
                "the stand-in did the work: a nonnumeric id is refused: {id_json} {refused:?}"
            );
        }
        assert_bridge_kept(&standin, 1, "a nonnumeric id");

        let capability = format!(
            r#"{{"id":7,"request":{{"type":"request_capability","resource":"{SHARED_RESOURCE}","action":"read","reason":"read shared"}}}}"#
        );
        let first = host_line(&mut standin, &capability, "component-1", Some("person-a"))
            .expect("the stand-in did the work: component-1's capability line is one response");
        assert_host_ok(
            &first,
            7,
            json!({ "status": "pending", "request_id": "request-1" }),
            "component-1's capability line stores request-1",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("request-1", "component-1")],
            "the stand-in did the work: component-1 has that one pending request"
        );
        assert!(
            request_entries(&standin, "component-2").is_empty(),
            "the stand-in did the work: component-2 has no request yet"
        );

        let second = host_line(&mut standin, &capability, "component-2", None)
            .expect("the stand-in did the work: component-2's capability line is one response");
        assert_host_ok(
            &second,
            7,
            json!({ "status": "pending", "request_id": "request-2" }),
            "component-2's capability line stores request-2",
        );
        assert_eq!(
            second["response"]["data"]["request_id"], "request-2",
            "the stand-in did the work: component-2's response names request-2"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-2", "component-2")],
            "the stand-in did the work: component-2 has that one pending request"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("request-1", "component-1")],
            "the stand-in did the work: component-1 still has only request-1"
        );

        let scheme = format!(
            r#"{{"id":7,"request":{{"type":"request_capability","resource":"https://example","action":"read","reason":"read shared"}}}}"#
        );
        let scheme_body = host_line(&mut standin, &scheme, "component-1", None)
            .expect("the stand-in did the work: the scheme refusal is one response");
        assert_host_error(
            &scheme_body,
            7,
            "Unsupported resource scheme. Allowed: elastos://, localhost://",
            "an unsupported scheme is refused",
        );
        assert!(
            standin
                .requests
                .iter()
                .all(|request| request.request_id != "request-3"),
            "the stand-in did the work: the refused scheme stores no request-3"
        );
        assert_bridge_kept(&standin, 3, "an unsupported scheme");

        let refused = standin.bridge_envelope("not json", "component-1", None);
        let reason = match refused {
            Err(reason) => reason,
            Ok(body) => panic!("the stand-in did the work: invalid JSON is refused: {body}"),
        };
        assert!(
            reason.contains("Invalid JSON"),
            "the stand-in did the work: the refusal names Invalid JSON: {reason}"
        );
        assert!(
            !reason.contains("request must be an object"),
            "the stand-in did the work: a parse failure is not the request-object refusal: {reason}"
        );
        assert!(
            !reason.contains("id must be a number"),
            "the stand-in did the work: a parse failure is not the id refusal: {reason}"
        );
        assert_bridge_kept(&standin, 3, "invalid JSON");

        let ping = host_line(
            &mut standin,
            r#"{"id":7,"request":{"type":"ping"}}"#,
            "component-1",
            None,
        )
        .expect("the stand-in did the work: ping is one response");
        assert_host_error(
            &ping,
            7,
            "unsupported bridge request",
            "ping is an unsupported bridge request",
        );
        for line in [
            r#"{"id":6,"request":{}}"#,
            r#"{"id":6,"request":{"type":1}}"#,
        ] {
            let other = host_line(&mut standin, line, "component-1", None)
                .expect("the stand-in did the work: another request type is one response");
            assert_host_error(
                &other,
                6,
                "unsupported bridge request",
                "any other request type is unsupported",
            );
        }
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("request-1", "component-1")],
            "the stand-in did the work: an unsupported request stores nothing further for component-1"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-2", "component-2")],
            "the stand-in did the work: an unsupported request stores nothing further for component-2"
        );
        assert_bridge_kept(&standin, 3, "an unsupported bridge request");

        let omitted_id = format!(
            r#"{{"request":{{"type":"request_capability","resource":"{SHARED_RESOURCE}","action":"read","reason":"read shared"}}}}"#
        );
        let omitted_id_body = host_line(&mut standin, &omitted_id, "component-1", None)
            .expect("the stand-in did the work: an omitted id is one response");
        assert_host_ok(
            &omitted_id_body,
            0,
            json!({ "status": "pending", "request_id": "request-3" }),
            "an omitted id is 0 and stores request-3",
        );

        let omitted_reason = format!(
            r#"{{"id":4,"request":{{"type":"request_capability","resource":"{SHARED_RESOURCE}","action":"read"}}}}"#
        );
        let omitted_reason_body = host_line(&mut standin, &omitted_reason, "component-1", None)
            .expect("the stand-in did the work: an omitted reason is one response");
        assert_host_ok(
            &omitted_reason_body,
            4,
            json!({ "status": "pending", "request_id": "request-4" }),
            "an omitted reason stores request-4",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                pending_request("request-1", "component-1"),
                pending_request("request-3", "component-1"),
                pending_reason("request-4", "component-1", ""),
            ],
            "the stand-in did the work: an omitted reason is stored as an empty string"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-2", "component-2")],
            "the stand-in did the work: the omitted fields stay on component-1"
        );
        assert_eq!(
            standin.next_request, 5,
            "the stand-in did the work: the omitted fields store request-3 and request-4"
        );
        assert_eq!(
            grant_record(&standin, "req-once"),
            (Life::Live, false),
            "the stand-in did the work: the omitted fields leave the grant live"
        );

        let missing_resource = r#"{"id":5,"request":{"type":"request_capability","action":"read","reason":"read shared"}}"#;
        let missing_action = format!(
            r#"{{"id":5,"request":{{"type":"request_capability","resource":"{SHARED_RESOURCE}","reason":"read shared"}}}}"#
        );
        let bad_resource = format!(
            r#"{{"id":5,"request":{{"type":"request_capability","resource":1,"action":"read","reason":"read shared"}}}}"#
        );
        let bad_action = format!(
            r#"{{"id":5,"request":{{"type":"request_capability","resource":"{SHARED_RESOURCE}","action":1,"reason":"read shared"}}}}"#
        );
        let bad_reason = format!(
            r#"{{"id":5,"request":{{"type":"request_capability","resource":"{SHARED_RESOURCE}","action":"read","reason":1}}}}"#
        );
        let bad_word = format!(
            r#"{{"id":5,"request":{{"type":"request_capability","resource":"{SHARED_RESOURCE}","action":"jump","reason":"read shared"}}}}"#
        );
        for (line, message_text, message) in [
            (
                missing_resource,
                "request body needs resource",
                "a missing resource reaches post_capability_request",
            ),
            (
                missing_action.as_str(),
                "request body needs action",
                "a missing action reaches post_capability_request",
            ),
            (
                bad_resource.as_str(),
                "request resource must be a string",
                "a non-string resource reaches post_capability_request",
            ),
            (
                bad_action.as_str(),
                "request action must be a string",
                "a non-string action reaches post_capability_request",
            ),
            (
                bad_reason.as_str(),
                "request reason must be a string",
                "a non-string reason reaches post_capability_request",
            ),
            (
                bad_word.as_str(),
                "Invalid action: jump. Expected: read, write, execute, delete, message, admin",
                "an unknown action reaches post_capability_request",
            ),
        ] {
            let parsed = host_line(&mut standin, line, "component-1", None)
                .expect("the stand-in did the work: a capability field refusal is one response");
            assert_host_error(&parsed, 5, message_text, message);
            assert_bridge_kept(&standin, 5, message);
        }

        for token_json in ["1", "null", "true", "[]"] {
            let line = format!(
                r#"{{"id":8,"request":{{"type":"resource_invoke","uri":"{SHARED_RESOURCE}","operation":"read","body":{{}},"token":{token_json}}}}}"#
            );
            let refused = standin.bridge_envelope(&line, "component-1", Some("person-a"));
            assert!(
                matches!(refused.as_ref(), Err(reason) if reason == "Invalid JSON: token must be a string"),
                "the stand-in did the work: a non-string token is refused: {token_json} {refused:?}"
            );
        }
        assert_bridge_kept(&standin, 5, "a non-string token");

        let omitted_token = format!(
            r#"{{"id":9,"request":{{"type":"resource_invoke","uri":"{SHARED_RESOURCE}","operation":"read","body":{{}}}}}}"#
        );
        let omitted_token_body = host_line(
            &mut standin,
            &omitted_token,
            "component-1",
            Some("person-a"),
        )
        .expect("the stand-in did the work: an omitted token is one response");
        assert_host_error(
            &omitted_token_body,
            9,
            "unknown grant: ",
            "an omitted token is an unknown grant",
        );
        assert_bridge_kept(&standin, 5, "an omitted token");

        let invoke = format!(
            r#"{{"id":8,"request":{{"type":"resource_invoke","uri":"{SHARED_RESOURCE}","operation":"read","body":{{}},"token":"req-once"}}}}"#
        );
        let sibling = host_line(&mut standin, &invoke, "component-2", Some("component-1"))
            .expect("the stand-in did the work: the sibling invoke is one response");
        assert_host_error(
            &sibling,
            8,
            "wrong capsule: expected component-1, got component-2",
            "a grant for the other capsule is refused",
        );
        assert_eq!(
            grant_record(&standin, "req-once"),
            (Life::Live, false),
            "the stand-in did the work: the sibling refusal leaves req-once live"
        );

        let owner = host_line(&mut standin, &invoke, "component-1", Some("person-a"))
            .expect("the stand-in did the work: the owner invoke is one response");
        assert_host_ok(
            &owner,
            8,
            Value::Null,
            "the owner invoke authorises component-1",
        );
        assert!(
            owner["response"]
                .as_object()
                .expect("the stand-in did the work: the response is an object")
                .get("data")
                .is_some_and(Value::is_null),
            "the stand-in did the work: the owner invoke data is null"
        );
        assert_eq!(
            grant_record(&standin, "req-once"),
            (Life::Exhausted, false),
            "the stand-in did the work: the owner's one use stores Exhausted"
        );

        let again = host_line(&mut standin, &invoke, "component-1", Some("person-a"))
            .expect("the stand-in did the work: the second owner invoke is one response");
        assert_host_error(
            &again,
            8,
            "grant is not live: Exhausted",
            "a second owner invoke finds the grant exhausted",
        );
        assert_eq!(
            grant_record(&standin, "req-once"),
            (Life::Exhausted, false),
            "the stand-in did the work: the second invoke leaves the grant exhausted"
        );
        assert_eq!(
            standin.next_request, 5,
            "the stand-in did the work: an invoke stores no request"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: component-1 stays running",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 stays running",
        );
        assert_live_request_ids_empty(&standin, "the shell live-grant request_id set is empty");
    }

    fn assert_named_capsule(
        standin: &StandIn,
        id: &str,
        name: &str,
        status: &str,
        cause: &str,
        message: &str,
    ) {
        let listed = shell_list(standin);
        let entry = listed["capsules"]
            .as_array()
            .expect("the stand-in returns capsules")
            .iter()
            .find(|entry| entry["id"] == id);
        let expected = json!({
            "id": id,
            "name": name,
            "status": status,
            "session_id": id,
            "cause": cause,
        });
        assert_eq!(
            entry,
            Some(&expected),
            "the stand-in did the work: {message}"
        );
    }

    fn shape_refused(standin: &mut StandIn, uri: &str, bytes: &[u8], reason: &str, message: &str) {
        assert_eq!(
            standin.protected_write("component-1", "req-shape", uri, bytes),
            Err((400, reason.to_owned())),
            "the stand-in did the work: {message}"
        );
        assert_eq!(
            grant_record(standin, "req-shape"),
            (Life::Live, false),
            "the stand-in did the work: {message} spends nothing"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: {message} leaves the stored journal"
        );
    }

    #[test]
    fn standin_protected_storage_uses_the_launch_principal() {
        let digest_a_hex = crate::identity::sha256(b"agent-ada");
        let digest_b_hex = crate::identity::sha256(b"agent-bob");
        let digest_a = &digest_a_hex[..24];
        let digest_b = &digest_b_hex[..24];
        assert_ne!(
            digest_a, digest_b,
            "the stand-in did the work: the two principals differ"
        );
        for digest in [digest_a, digest_b] {
            assert!(
                !digest.contains("agent-ada") && !digest.contains("agent-bob"),
                "the stand-in did the work: the digest is not the principal text: {digest}"
            );
        }
        let users_a = format!("localhost://Users/{digest_a}");
        let usersai_a = format!("localhost://UsersAI/{digest_a}");
        let journal_a = format!("localhost://UsersAI/{digest_a}/journal");
        let journal_b = format!("localhost://UsersAI/{digest_b}/journal");
        let person_a = format!("localhost://Users/{digest_a}/journal");
        let once_a = format!("localhost://UsersAI/{digest_a}/once");
        let users_reason =
            "localhost://Users roots must use Users/self or the active principal root";
        let usersai_reason = "UsersAI roots must use UsersAI/self";
        let needs_reason = "protected storage needs a Users/self or UsersAI/self resource";

        let mut open = StandIn::new();
        open.admit_resident("/capsules/journal-open", "journal-open", Start::Ok)
            .expect("the stand-in admits journal-open");
        let launched = open
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-open"}))
            .expect("the stand-in launches journal-open");
        assert_eq!(
            launched,
            json!({
                "id": "component-1",
                "name": "journal-open",
                "status": "starting",
                "session_id": "component-1",
            }),
            "the stand-in did the work: the launch session_id equals its id"
        );
        open.finish_start("component-1")
            .expect("the stand-in finishes journal-open");
        assert_eq!(
            open.protected_write(
                "component-1",
                "req-none",
                "localhost://UsersAI/self/journal",
                b"journal-v1",
            ),
            Err((
                400,
                "requires the principal from the verified launch".to_owned(),
            )),
            "the stand-in did the work: an unbound launch requires the verified principal"
        );
        assert_eq!(
            open.protected_write(
                "component-1",
                "req-none",
                "localhost://UsersAI/self/../journal",
                b"dot-v1",
            ),
            Err((400, "protected path rejects ..".to_owned())),
            "the stand-in did the work: .. is refused before the principal check"
        );
        assert!(
            open.protected_objects.is_empty(),
            "the stand-in did the work: a resolver error stores nothing"
        );
        assert_eq!(
            open.bind_verified_principal("/capsules/journal-open", ""),
            Err((400, "verified launch needs a principal".to_owned())),
            "the stand-in did the work: an empty principal is refused"
        );
        assert_eq!(
            open.bind_verified_principal("/capsules/missing", "agent-ada"),
            Err((400, "unknown resident path: /capsules/missing".to_owned())),
            "the stand-in did the work: an unknown path is refused"
        );
        assert_eq!(
            shell_list(&open)["capsules"].as_array().map(Vec::len),
            Some(1),
            "the stand-in did the work: a refused bind mints no instance"
        );
        open.bind_verified_principal("/capsules/journal-open", "agent-ada")
            .expect("the stand-in binds agent-ada after launch");
        open.seed_grant(
            "req-old",
            "component-1",
            "localhost://UsersAI/self/journal",
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            open.protected_write(
                "component-1",
                "req-old",
                "localhost://UsersAI/self/journal",
                b"retro-v1",
            ),
            Err((
                400,
                "requires the principal from the verified launch".to_owned(),
            )),
            "the stand-in did the work: a later bind leaves the instance already created"
        );
        assert!(
            open.protected_objects.is_empty(),
            "the stand-in did the work: the later bind stores nothing on that instance"
        );
        assert_eq!(
            grant_record(&open, "req-old"),
            (Life::Live, false),
            "the stand-in did the work: the later bind spends nothing"
        );
        let started = open
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-open"}))
            .expect("the stand-in launches the bound path");
        assert_eq!(
            started,
            json!({
                "id": "component-2",
                "name": "journal-open",
                "status": "starting",
                "session_id": "component-2",
            }),
            "the stand-in did the work: the bound launch session_id equals its id"
        );
        open.seed_grant(
            "req-start",
            "component-2",
            "localhost://UsersAI/self/journal",
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        open.seed_grant(
            "req-start-read",
            "component-2",
            "localhost://UsersAI/self/journal",
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            open.protected_write(
                "component-2",
                "req-start",
                "localhost://UsersAI/self/journal",
                b"start-v1",
            ),
            Ok(journal_a.clone()),
            "the stand-in did the work: a Starting instance stores the approved write"
        );
        assert_eq!(
            open.protected_read(
                "component-2",
                "req-start",
                "localhost://UsersAI/self/journal"
            ),
            Err((403, "wrong action: expected write, got read".to_owned())),
            "the stand-in did the work: a Starting write grant cannot read"
        );
        assert_eq!(
            grant_record(&open, "req-start"),
            (Life::Live, false),
            "the stand-in did the work: the refused Starting read spends nothing"
        );
        assert_eq!(
            open.protected_read(
                "component-2",
                "req-start-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"start-v1".to_vec()),
            "the stand-in did the work: a Starting instance reads the approved write"
        );
        assert_named_capsule(
            &open,
            "component-2",
            "journal-open",
            "starting",
            "",
            "component-2 is still starting",
        );

        let mut standin = StandIn::new();
        standin
            .admit_resident("/capsules/journal-a", "journal-a", Start::Ok)
            .expect("the stand-in admits journal-a");
        standin
            .admit_resident("/capsules/journal-b", "journal-b", Start::Ok)
            .expect("the stand-in admits journal-b");
        standin
            .bind_verified_principal("/capsules/journal-a", "agent-ada")
            .expect("the stand-in binds agent-ada");
        assert_eq!(
            standin.bind_verified_principal("/capsules/journal-a", "agent-other"),
            Err((400, "verified principal already bound".to_owned())),
            "the stand-in did the work: a second principal is refused"
        );
        assert_eq!(
            standin.bind_verified_principal("/capsules/journal-a", ""),
            Err((400, "verified launch needs a principal".to_owned())),
            "the stand-in did the work: an empty principal stays refused after a bind"
        );
        standin
            .bind_verified_principal("/capsules/journal-b", "agent-bob")
            .expect("the stand-in binds agent-bob");
        assert_eq!(
            shell_list(&standin)["capsules"].as_array().map(Vec::len),
            Some(0),
            "the stand-in did the work: bind mints no instance"
        );
        let launch_a = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-a"}))
            .expect("the stand-in launches journal-a");
        assert_eq!(
            launch_a,
            json!({
                "id": "component-1",
                "name": "journal-a",
                "status": "starting",
                "session_id": "component-1",
            }),
            "the stand-in did the work: component-1 session_id equals its id"
        );
        let launch_b = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-b"}))
            .expect("the stand-in launches journal-b");
        assert_eq!(
            launch_b,
            json!({
                "id": "component-2",
                "name": "journal-b",
                "status": "starting",
                "session_id": "component-2",
            }),
            "the stand-in did the work: component-2 session_id equals its id"
        );
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes component-1");
        standin
            .finish_start("component-2")
            .expect("the stand-in finishes component-2");
        assert_named_capsule(
            &standin,
            "component-1",
            "journal-a",
            "running",
            "",
            "component-1 is running",
        );
        assert_named_capsule(
            &standin,
            "component-2",
            "journal-b",
            "running",
            "",
            "component-2 is running",
        );
        let named = standin.post_capsules(
            Caller::Shell,
            &json!({"path": "/capsules/journal-a", "principal_id": "agent-ada"}),
        );
        match &named {
            Err((400, reason)) if reason.contains("principal_id") => {}
            other => {
                panic!("the stand-in did the work: the launch body rejects principal_id: {other:?}")
            }
        }
        assert_eq!(
            shell_list(&standin)["capsules"].as_array().map(Vec::len),
            Some(2),
            "the stand-in did the work: a rejected principal_id stores no instance"
        );
        standin.seed_grant(
            "req-a",
            "component-1",
            "localhost://UsersAI/self/journal",
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-b",
            "component-2",
            "localhost://UsersAI/self/journal",
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-a-read",
            "component-1",
            "localhost://UsersAI/self/journal",
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-b-read",
            "component-2",
            "localhost://UsersAI/self/journal",
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-a",
                "localhost://UsersAI/self/journal",
                b"journal-v1",
            ),
            Ok(journal_a.clone()),
            "the stand-in did the work: the approved write is stored under the launch principal"
        );
        assert_eq!(
            grant_record(&standin, "req-a"),
            (Life::Live, false),
            "the stand-in did the work: a session grant stays live"
        );
        assert_eq!(
            standin.protected_read("component-1", "req-a", "localhost://UsersAI/self/journal"),
            Err((403, "wrong action: expected write, got read".to_owned())),
            "the stand-in did the work: a write grant cannot read the journal"
        );
        assert_eq!(
            grant_record(&standin, "req-a"),
            (Life::Live, false),
            "the stand-in did the work: the refused read spends nothing"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/other",
                b"other-v1",
            ),
            Err((403, "wrong action: expected read, got write".to_owned())),
            "the stand-in did the work: a read-only journal grant cannot write another path"
        );
        assert_eq!(
            grant_record(&standin, "req-a-read"),
            (Life::Live, false),
            "the stand-in did the work: the read-only refusal spends nothing"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-a",
                "localhost://UsersAI/self/other",
                b"other-v1",
            ),
            Err((
                403,
                "wrong resource: expected localhost://UsersAI/self/journal, got localhost://UsersAI/self/other"
                    .to_owned(),
            )),
            "the stand-in did the work: a journal grant cannot write another path"
        );
        assert_eq!(
            grant_record(&standin, "req-a"),
            (Life::Live, false),
            "the stand-in did the work: the other-path refusal spends nothing"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: the owner reads the stored journal"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-missing",
                "localhost://UsersAI/self/journal"
            ),
            Err((400, "unknown grant: req-missing".to_owned())),
            "the stand-in did the work: an unknown grant cannot read"
        );
        assert_eq!(
            standin.protected_read("component-2", "req-b", "localhost://UsersAI/self/journal"),
            Err((403, "wrong action: expected write, got read".to_owned())),
            "the stand-in did the work: component-2's write grant cannot read"
        );
        assert_eq!(
            grant_record(&standin, "req-b"),
            (Life::Live, false),
            "the stand-in did the work: component-2's refused read spends nothing"
        );
        assert_eq!(
            standin.protected_read(
                "component-2",
                "req-b-read",
                "localhost://UsersAI/self/journal"
            ),
            Err((404, "protected object is absent".to_owned())),
            "the stand-in did the work: the sibling root has no journal"
        );
        let sibling_read =
            standin.protected_read("component-2", "req-a", "localhost://UsersAI/self/journal");
        match &sibling_read {
            Err((403, reason)) if reason.contains("wrong capsule") => {}
            other => {
                panic!("the stand-in did the work: a sibling read is wrong capsule: {other:?}")
            }
        }
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: a refused sibling read leaves the journal"
        );
        let sibling_write = standin.protected_write(
            "component-2",
            "req-a",
            "localhost://UsersAI/self/journal",
            b"other",
        );
        match &sibling_write {
            Err((403, reason)) if reason.contains("wrong capsule") => {}
            other => {
                panic!("the stand-in did the work: a sibling write is wrong capsule: {other:?}")
            }
        }
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: a sibling write leaves the journal"
        );
        assert_eq!(
            standin.protected_write(
                "component-2",
                "req-b",
                "localhost://UsersAI/self/journal",
                b"bob-v1",
            ),
            Ok(journal_b.clone()),
            "the stand-in did the work: component-2 stores under its own principal"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: component-1 keeps its own journal"
        );
        assert_eq!(
            standin.protected_write("component-1", "req-a", &journal_a, b"other",),
            Err((400, usersai_reason.to_owned())),
            "the stand-in did the work: an explicit UsersAI root is refused"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-a",
                "localhost://Users/self/journal",
                b"person-v1",
            ),
            Err((
                403,
                "wrong resource: expected localhost://UsersAI/self/journal, got localhost://Users/self/journal"
                    .to_owned(),
            )),
            "the stand-in did the work: a UsersAI grant cannot write Users"
        );
        assert_eq!(
            grant_record(&standin, "req-a"),
            (Life::Live, false),
            "the stand-in did the work: the Users refusal spends nothing"
        );
        standin.seed_grant(
            "req-person",
            "component-1",
            "localhost://Users/self/journal",
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-person-read",
            "component-1",
            "localhost://Users/self/journal",
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-b-person-read",
            "component-2",
            "localhost://Users/self/journal",
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-person",
                "localhost://Users/self/journal",
                b"person-v1",
            ),
            Ok(person_a.clone()),
            "the stand-in did the work: Users/self stores under the same principal"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-person-read",
                "localhost://Users/self/journal"
            ),
            Ok(b"person-v1".to_vec()),
            "the stand-in did the work: the owner reads the Users journal"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: the Users write leaves the UsersAI journal"
        );
        assert_eq!(
            standin.protected_read(
                "component-2",
                "req-b-person-read",
                "localhost://Users/self/journal"
            ),
            Err((404, "protected object is absent".to_owned())),
            "the stand-in did the work: component-2 does not see the Users journal"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-a",
                "localhost://Users/someone/journal",
                b"other",
            ),
            Err((400, users_reason.to_owned())),
            "the stand-in did the work: another Users root is refused"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-a",
                "localhost://UsersAI/self/../journal",
                b"other",
            ),
            Err((400, "protected path rejects ..".to_owned())),
            "the stand-in did the work: a parent segment is refused"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-missing",
                "localhost://UsersAI/self/journal",
                b"missing-v1",
            ),
            Err((400, "unknown grant: req-missing".to_owned())),
            "the stand-in did the work: an unknown grant cannot write"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: a missing grant stores nothing"
        );
        standin.seed_grant(
            "req-shape",
            "component-1",
            "localhost://UsersAI/self/journal",
            "write",
            "once",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-shape",
                "localhost://UsersAI/self/journal"
            ),
            Err((403, "wrong action: expected write, got read".to_owned())),
            "the stand-in did the work: a once write grant cannot read"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-shape",
                "localhost://UsersAI/self/other",
                b"shape-other",
            ),
            Err((
                403,
                "wrong resource: expected localhost://UsersAI/self/journal, got localhost://UsersAI/self/other"
                    .to_owned(),
            )),
            "the stand-in did the work: a once journal grant cannot write another path"
        );
        assert_eq!(
            grant_record(&standin, "req-shape"),
            (Life::Live, false),
            "the stand-in did the work: a mismatched once grant stays live"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: a mismatched once grant stores nothing"
        );
        shape_refused(
            &mut standin,
            "localhost://UsersAI/self/../secret",
            b"shape-dot",
            "protected path rejects ..",
            "a once grant does not pass ..",
        );
        shape_refused(
            &mut standin,
            &journal_a,
            b"shape-ai",
            usersai_reason,
            "a once grant does not pass another UsersAI root",
        );
        shape_refused(
            &mut standin,
            &usersai_a,
            b"shape-ai-root",
            usersai_reason,
            "a once grant does not pass a bare UsersAI root",
        );
        shape_refused(
            &mut standin,
            "localhost://Users/someone/journal",
            b"shape-someone",
            users_reason,
            "a once grant does not pass another Users root",
        );
        shape_refused(
            &mut standin,
            "localhost://Users/selfish/journal",
            b"shape-selfish",
            users_reason,
            "a Users/self prefix lookalike is refused",
        );
        shape_refused(
            &mut standin,
            "localhost://UsersAI/selfish/journal",
            b"shape-ai-selfish",
            usersai_reason,
            "a UsersAI/self prefix lookalike is refused",
        );
        shape_refused(
            &mut standin,
            &format!("localhost://Users/{digest_a}x"),
            b"shape-prefix",
            users_reason,
            "a Users root prefix lookalike is refused",
        );
        shape_refused(
            &mut standin,
            &format!("localhost://Users/{digest_b}/journal"),
            b"shape-bob",
            users_reason,
            "the other principal's Users root is refused",
        );
        shape_refused(
            &mut standin,
            "elastos://content/journal",
            b"shape-scheme",
            needs_reason,
            "an elastos uri is refused",
        );
        shape_refused(
            &mut standin,
            "localhost://Public/self",
            b"shape-public",
            needs_reason,
            "another localhost root is refused",
        );
        shape_refused(
            &mut standin,
            "localhost://Users",
            b"shape-users",
            needs_reason,
            "a Users uri without a slash is refused",
        );
        shape_refused(
            &mut standin,
            "localhost://UsersAI",
            b"shape-usersai",
            needs_reason,
            "a UsersAI uri without a slash is refused",
        );
        standin.seed_grant(
            "req-bare-ai",
            "component-1",
            "localhost://UsersAI/self",
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-bare-ai-read",
            "component-1",
            "localhost://UsersAI/self",
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-bare-users",
            "component-1",
            "localhost://Users/self",
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-bare-users-read",
            "component-1",
            "localhost://Users/self",
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-notes",
            "component-1",
            "localhost://Users/self/notes",
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-notes-read",
            "component-1",
            "localhost://Users/self/notes",
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-a",
                "localhost://UsersAI/self",
                b"bare-ai"
            ),
            Err((
                403,
                "wrong resource: expected localhost://UsersAI/self/journal, got localhost://UsersAI/self"
                    .to_owned(),
            )),
            "the stand-in did the work: a journal grant cannot write the bare UsersAI root"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-bare-ai",
                "localhost://UsersAI/self",
                b"bare-ai"
            ),
            Ok(usersai_a.clone()),
            "the stand-in did the work: bare UsersAI/self resolves to the principal root"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-bare-ai-read",
                "localhost://UsersAI/self"
            ),
            Ok(b"bare-ai".to_vec()),
            "the stand-in did the work: the owner reads the bare UsersAI root"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-bare-ai",
                "localhost://UsersAI/self/journal",
                b"wide-ai",
            ),
            Err((
                403,
                "wrong resource: expected localhost://UsersAI/self, got localhost://UsersAI/self/journal"
                    .to_owned(),
            )),
            "the stand-in did the work: a bare UsersAI grant cannot write the journal"
        );
        assert_eq!(
            grant_record(&standin, "req-bare-ai"),
            (Life::Live, false),
            "the stand-in did the work: the bare UsersAI refusal spends nothing"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-bare-users",
                "localhost://Users/self",
                b"bare-users"
            ),
            Ok(users_a.clone()),
            "the stand-in did the work: bare Users/self resolves to the principal root"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-bare-users-read",
                "localhost://Users/self"
            ),
            Ok(b"bare-users".to_vec()),
            "the stand-in did the work: the owner reads the bare Users root"
        );
        assert_eq!(
            standin.protected_write("component-1", "req-bare-users", &users_a, b"root-v2"),
            Ok(users_a.clone()),
            "the stand-in did the work: the active Users root replaces the stored bytes"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-bare-users-read",
                "localhost://Users/self"
            ),
            Ok(b"root-v2".to_vec()),
            "the stand-in did the work: the bare Users read sees the replacement"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-bare-users",
                "localhost://Users/self/journal",
                b"wide-users",
            ),
            Err((
                403,
                "wrong resource: expected localhost://Users/self, got localhost://Users/self/journal"
                    .to_owned(),
            )),
            "the stand-in did the work: a bare Users grant cannot write the journal"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-person-read",
                "localhost://Users/self/journal"
            ),
            Ok(b"person-v1".to_vec()),
            "the stand-in did the work: the bare Users refusal leaves the journal"
        );
        let notes_a = format!("localhost://Users/{digest_a}/notes");
        assert_eq!(
            standin.protected_write("component-1", "req-person", &notes_a, b"notes-v1"),
            Err((
                403,
                format!("wrong resource: expected localhost://Users/self/journal, got {notes_a}"),
            )),
            "the stand-in did the work: a journal grant cannot write notes"
        );
        assert_eq!(
            standin.protected_write("component-1", "req-notes", &notes_a, b"notes-v1"),
            Ok(notes_a.clone()),
            "the stand-in did the work: a path under the active Users root stays itself"
        );
        assert_eq!(
            standin.protected_read("component-1", "req-notes-read", &notes_a),
            Ok(b"notes-v1".to_vec()),
            "the stand-in did the work: the owner reads the active Users path"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: the Users root writes leave the journal"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-a",
                "localhost://UsersAI/self/journal",
                b"journal-v2",
            ),
            Ok(journal_a.clone()),
            "the stand-in did the work: a second write replaces the stored journal"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"journal-v2".to_vec()),
            "the stand-in did the work: the owner reads the replacement"
        );
        assert_eq!(
            standin.protected_read(
                "component-2",
                "req-b-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"bob-v1".to_vec()),
            "the stand-in did the work: the replacement leaves the sibling journal"
        );
        standin.seed_grant(
            "req-once",
            "component-1",
            "localhost://UsersAI/self/once",
            "write",
            "once",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-once-read",
            "component-1",
            "localhost://UsersAI/self/once",
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-once",
                "localhost://UsersAI/self/once",
                b"once-v1",
            ),
            Ok(once_a.clone()),
            "the stand-in did the work: one once write stores the bytes"
        );
        assert_eq!(
            grant_record(&standin, "req-once"),
            (Life::Exhausted, false),
            "the stand-in did the work: the once grant is exhausted"
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-once",
                "localhost://UsersAI/self/once",
                b"once-v2",
            ),
            Err((400, "grant is not live: Exhausted".to_owned())),
            "the stand-in did the work: a second once write is refused"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-once-read",
                "localhost://UsersAI/self/once"
            ),
            Ok(b"once-v1".to_vec()),
            "the stand-in did the work: the exhausted write leaves the stored bytes"
        );
        assert_eq!(
            standin.protected_read("component-1", "req-once", "localhost://UsersAI/self/once"),
            Err((400, "grant is not live: Exhausted".to_owned())),
            "the stand-in did the work: an exhausted grant cannot read"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-once-read",
                "localhost://UsersAI/self/once"
            ),
            Ok(b"once-v1".to_vec()),
            "the stand-in did the work: the refused read leaves the stored bytes"
        );
        assert_eq!(
            standin.protected_write(
                "component-missing",
                "req-a",
                "localhost://UsersAI/self/journal",
                b"missing-instance",
            ),
            Err((400, "unknown instance: component-missing".to_owned())),
            "the stand-in did the work: an unknown instance cannot write"
        );
        assert_eq!(
            standin.protected_read(
                "component-missing",
                "req-a",
                "localhost://UsersAI/self/../journal",
            ),
            Err((400, "unknown instance: component-missing".to_owned())),
            "the stand-in did the work: an unknown instance cannot read"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"journal-v2".to_vec()),
            "the stand-in did the work: an unknown instance stores nothing"
        );

        standin
            .admit_resident("/capsules/journal-stop", "journal-stop", Start::Ok)
            .expect("the stand-in admits journal-stop");
        standin
            .bind_verified_principal("/capsules/journal-stop", "agent-stop")
            .expect("the stand-in binds agent-stop");
        let stopped = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-stop"}))
            .expect("the stand-in launches journal-stop");
        assert_eq!(
            stopped["id"], "component-3",
            "the stand-in did the work: journal-stop is component-3"
        );
        standin
            .finish_start("component-3")
            .expect("the stand-in finishes journal-stop");
        standin.seed_grant(
            "req-stop",
            "component-3",
            "localhost://UsersAI/self/journal",
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin
            .delete_capsule(Caller::Shell, "component-3", &json!({"reason": "end"}))
            .expect("the stand-in stops journal-stop");
        assert_eq!(
            standin.protected_write(
                "component-3",
                "req-stop",
                "localhost://UsersAI/self/journal",
                b"stop-v1",
            ),
            Err((400, "instance is not live: stopped".to_owned())),
            "the stand-in did the work: a stopped instance cannot write"
        );
        assert_eq!(
            standin.protected_read(
                "component-3",
                "req-stop",
                "localhost://UsersAI/self/journal"
            ),
            Err((400, "instance is not live: stopped".to_owned())),
            "the stand-in did the work: a stopped instance cannot read"
        );

        standin
            .admit_resident(
                "/capsules/journal-fail",
                "journal-fail",
                Start::Error("boom".to_owned()),
            )
            .expect("the stand-in admits journal-fail");
        standin
            .bind_verified_principal("/capsules/journal-fail", "agent-fail")
            .expect("the stand-in binds agent-fail");
        let failed = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-fail"}))
            .expect("the stand-in launches journal-fail");
        assert_eq!(
            failed["id"], "component-4",
            "the stand-in did the work: journal-fail is component-4"
        );
        standin.seed_grant(
            "req-fail",
            "component-4",
            "localhost://UsersAI/self/journal",
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin
            .finish_start("component-4")
            .expect("the stand-in finishes journal-fail");
        assert_eq!(
            standin.protected_write(
                "component-4",
                "req-fail",
                "localhost://UsersAI/self/journal",
                b"fail-v1",
            ),
            Err((400, "instance is not live: failed".to_owned())),
            "the stand-in did the work: a failed instance cannot write"
        );
        assert_eq!(
            standin.protected_read(
                "component-4",
                "req-fail",
                "localhost://UsersAI/self/journal"
            ),
            Err((400, "instance is not live: failed".to_owned())),
            "the stand-in did the work: a failed instance cannot read"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-a-read",
                "localhost://UsersAI/self/journal"
            ),
            Ok(b"journal-v2".to_vec()),
            "the stand-in did the work: an ended instance leaves the stored journal"
        );
        assert_named_capsule(
            &standin,
            "component-1",
            "journal-a",
            "running",
            "",
            "component-1 stays running",
        );
        assert_named_capsule(
            &standin,
            "component-2",
            "journal-b",
            "running",
            "",
            "component-2 stays running",
        );
    }

    #[test]
    fn standin_instance_stores_the_verified_component_hash() {
        let mut standin = StandIn::new();
        standin
            .admit_resident("/capsules/agent-a", "agent-a", Start::Ok)
            .expect("the stand-in did the work: it admits agent-a");
        standin
            .admit_resident("/capsules/agent-b", "agent-b", Start::Ok)
            .expect("the stand-in did the work: it admits agent-b");
        standin
            .admit_resident("/capsules/agent-a-again", "agent-a-again", Start::Ok)
            .expect("the stand-in did the work: it admits agent-a-again");
        standin
            .admit_resident("/capsules/late", "late", Start::Ok)
            .expect("the stand-in did the work: it admits late");

        let hash_a = "a".repeat(64);
        let hash_b = "b".repeat(64);
        let hash_63 = "a".repeat(63);
        let hash_65 = "a".repeat(65);
        let hash_a_upper = format!("A{}", &hash_a[1..]);
        let needs_hash = "verified launch needs a component hash";
        let hex_hash = "component hash must be 64 lowercase hex characters";
        let already_bound = "verified component hash already bound";

        assert_eq!(
            standin.bind_verified_component("/capsules/agent-a", ""),
            Err((400, needs_hash.to_owned())),
            "the stand-in did the work: an empty hash is refused"
        );
        assert_eq!(
            standin.bind_verified_component("/capsules/missing", ""),
            Err((400, needs_hash.to_owned())),
            "the stand-in did the work: an empty hash is refused before the path"
        );
        assert_eq!(
            standin.bind_verified_component("/capsules/agent-a", "agent-a"),
            Err((400, hex_hash.to_owned())),
            "the stand-in did the work: a name is not a component hash"
        );
        assert_eq!(
            standin.bind_verified_component("/capsules/agent-a", &hash_a_upper),
            Err((400, hex_hash.to_owned())),
            "the stand-in did the work: an uppercase hash is refused"
        );
        assert_eq!(
            standin.bind_verified_component("/capsules/agent-a", &hash_63),
            Err((400, hex_hash.to_owned())),
            "the stand-in did the work: a 63-character hash is refused"
        );
        assert_eq!(
            standin.bind_verified_component("/capsules/agent-a", &hash_65),
            Err((400, hex_hash.to_owned())),
            "the stand-in did the work: a 65-character hash is refused"
        );
        assert_eq!(
            standin.bind_verified_component("/capsules/missing", "agent-a"),
            Err((400, hex_hash.to_owned())),
            "the stand-in did the work: a malformed hash is refused before the path"
        );
        assert_eq!(
            standin.bind_verified_component("/capsules/missing", &hash_63),
            Err((400, hex_hash.to_owned())),
            "the stand-in did the work: a short hash is refused before the path"
        );
        assert_eq!(
            standin.bind_verified_component("/capsules/missing", &hash_a),
            Err((400, "unknown resident path: /capsules/missing".to_owned())),
            "the stand-in did the work: an unknown path is refused"
        );
        standin
            .bind_verified_component("/capsules/agent-a", &hash_a)
            .expect("the stand-in did the work: it binds agent-a");
        assert_eq!(
            standin.bind_verified_component("/capsules/agent-a", ""),
            Err((400, needs_hash.to_owned())),
            "the stand-in did the work: an empty hash is refused before a rebind"
        );
        assert_eq!(
            standin.bind_verified_component("/capsules/agent-a", "agent-a"),
            Err((400, hex_hash.to_owned())),
            "the stand-in did the work: a malformed hash is refused before a rebind"
        );
        assert_eq!(
            standin.bind_verified_component("/capsules/agent-a", &hash_63),
            Err((400, hex_hash.to_owned())),
            "the stand-in did the work: a short hash is refused before a rebind"
        );
        assert_eq!(
            standin.bind_verified_component("/capsules/agent-a", &hash_b),
            Err((400, already_bound.to_owned())),
            "the stand-in did the work: a second hash is refused"
        );
        standin
            .bind_verified_component("/capsules/agent-b", &hash_b)
            .expect("the stand-in did the work: it binds agent-b");
        standin
            .bind_verified_component("/capsules/agent-a-again", &hash_a)
            .expect("the stand-in did the work: it binds agent-a-again");
        assert_eq!(
            shell_list(&standin)["capsules"],
            json!([]),
            "the stand-in did the work: a bind mints no instance"
        );

        let first = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/agent-a"}))
            .expect("the stand-in did the work: it launches agent-a");
        let second = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/agent-b"}))
            .expect("the stand-in did the work: it launches agent-b");
        let third = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/agent-a-again"}))
            .expect("the stand-in did the work: it launches agent-a-again");
        assert_eq!(
            first["id"], "component-1",
            "the stand-in did the work: the first launch is component-1"
        );
        assert_eq!(
            second["id"], "component-2",
            "the stand-in did the work: the second launch is component-2"
        );
        assert_eq!(
            third["id"], "component-3",
            "the stand-in did the work: the third launch is component-3"
        );
        for launch in [&first, &second, &third] {
            assert_eq!(
                launch["session_id"], launch["id"],
                "the stand-in did the work: session_id equals the instance id"
            );
            assert_keys(
                launch,
                &["id", "name", "session_id", "status"],
                "the stand-in did the work: the launch object has no component_hash key",
            );
        }
        assert_eq!(
            standin.component_hash("component-1"),
            Ok(hash_a.clone()),
            "the stand-in did the work: component-1 stores hash_a"
        );
        assert_eq!(
            standin.component_hash("component-2"),
            Ok(hash_b.clone()),
            "the stand-in did the work: component-2 stores hash_b"
        );
        assert_eq!(
            standin.component_hash("component-3"),
            Ok(hash_a.clone()),
            "the stand-in did the work: component-3 stores hash_a"
        );
        assert_ne!(
            hash_a, hash_b,
            "the stand-in did the work: the two component hashes differ"
        );
        for label in [
            "agent-a",
            "agent-b",
            "/capsules/agent-a",
            "/capsules/agent-b",
        ] {
            assert_ne!(
                hash_a, label,
                "the stand-in did the work: a component hash is not a name or a path"
            );
            assert_ne!(
                hash_b, label,
                "the stand-in did the work: a component hash is not a name or a path"
            );
        }
        assert_eq!(
            standin.post_capsules(
                Caller::Shell,
                &json!({"path": "/capsules/agent-a", "component_hash": hash_a}),
            ),
            Err((
                400,
                "resident launch body rejects component_hash".to_owned(),
            )),
            "the stand-in did the work: the launch body rejects component_hash"
        );
        assert_eq!(
            standin.component_hash("component-9"),
            Err((400, "unknown instance: component-9".to_owned())),
            "the stand-in did the work: an unknown instance is refused"
        );

        let late = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/late"}))
            .expect("the stand-in did the work: it launches late");
        assert_eq!(
            late["id"], "component-4",
            "the stand-in did the work: the unbound launch is component-4"
        );
        assert_eq!(
            standin.component_hash("component-4"),
            Err((400, "instance has no verified component hash".to_owned())),
            "the stand-in did the work: an unbound launch stores no hash"
        );
        standin
            .bind_verified_component("/capsules/late", &hash_b)
            .expect("the stand-in did the work: it binds late");
        assert_eq!(
            standin.component_hash("component-4"),
            Err((400, "instance has no verified component hash".to_owned())),
            "the stand-in did the work: a later bind leaves the instance already created"
        );
        let late_again = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/late"}))
            .expect("the stand-in did the work: it launches late again");
        assert_eq!(
            late_again["id"], "component-5",
            "the stand-in did the work: the later launch is component-5"
        );
        assert_eq!(
            standin.component_hash("component-5"),
            Ok(hash_b.clone()),
            "the stand-in did the work: component-5 stores hash_b"
        );
        assert_eq!(
            standin.finish_start("component-1"),
            Ok(()),
            "the stand-in did the work: component-1 finishes start"
        );
        assert_eq!(
            standin.delete_capsule(Caller::Shell, "component-2", &json!({"reason": "stop one"}),),
            Ok(Value::Null),
            "the stand-in did the work: stopping component-2 answers null"
        );
        assert_eq!(
            standin.component_hash("component-1"),
            Ok(hash_a.clone()),
            "the stand-in did the work: component-1 still stores hash_a"
        );
        assert_eq!(
            standin.component_hash("component-2"),
            Ok(hash_b),
            "the stand-in did the work: component-2 still stores hash_b"
        );
        let listed = shell_list(&standin);
        let capsules = listed["capsules"]
            .as_array()
            .expect("the stand-in returns capsules");
        let entry = |id: &str| {
            capsules
                .iter()
                .find(|entry| entry["id"] == id)
                .unwrap_or_else(|| panic!("the stand-in lists {id}"))
        };
        let running = entry("component-1");
        assert_keys(
            running,
            &["cause", "id", "name", "session_id", "status"],
            "the stand-in did the work: the list entry has no component_hash key",
        );
        assert_eq!(
            running["status"], "running",
            "the stand-in did the work: component-1 is running"
        );
        assert_eq!(
            running["cause"], "",
            "the stand-in did the work: component-1 has an empty cause"
        );
        let starting = entry("component-3");
        assert_eq!(
            starting["status"], "starting",
            "the stand-in did the work: component-3 stays starting"
        );
        assert_eq!(
            starting["cause"], "",
            "the stand-in did the work: component-3 has an empty cause"
        );
    }

    fn shell_pending(standin: &StandIn) -> Value {
        standin
            .get_capability_pending(Caller::Shell)
            .expect("the stand-in did the work: the shell reads the pending list")
    }

    fn pending_ids(body: &Value) -> Vec<String> {
        body["requests"]
            .as_array()
            .expect("the stand-in did the work: the shell pending list is requests")
            .iter()
            .map(|entry| {
                entry["request_id"]
                    .as_str()
                    .expect("the stand-in did the work: a pending entry names request_id")
                    .to_owned()
            })
            .collect()
    }

    fn assert_pending_entry(
        entry: &Value,
        request_id: &str,
        session_id: &str,
        resource: &str,
        action: &str,
        reason: &str,
        requested_at: u64,
        expires_at: u64,
    ) {
        assert_keys(
            entry,
            &[
                "action",
                "expires_at",
                "reason",
                "request_id",
                "requested_at",
                "resource",
                "session_id",
            ],
            "the stand-in did the work: a pending entry's keys are request_id, session_id, resource, action, reason, requested_at and expires_at",
        );
        assert_eq!(
            entry["request_id"], request_id,
            "the stand-in did the work: the pending entry names {request_id}"
        );
        assert_eq!(
            entry["session_id"], session_id,
            "the stand-in did the work: {request_id} belongs to {session_id}"
        );
        assert_eq!(
            entry["resource"], resource,
            "the stand-in did the work: {request_id} keeps its resource"
        );
        assert_eq!(
            entry["action"], action,
            "the stand-in did the work: {request_id} keeps its action"
        );
        assert_eq!(
            entry["reason"], reason,
            "the stand-in did the work: {request_id} keeps its reason"
        );
        assert_eq!(
            entry["requested_at"].as_u64(),
            Some(requested_at),
            "the stand-in did the work: {request_id} keeps the instant seed_request stored"
        );
        assert_eq!(
            entry["expires_at"].as_u64(),
            Some(expires_at),
            "the stand-in did the work: {request_id} expires at requested_at plus REQUEST_TIMEOUT_SECS"
        );
    }

    fn record_status(standin: &StandIn, session_id: &str, request_id: &str) -> String {
        let records = standin
            .get_capability_requests(Caller::Shell, Some(session_id))
            .expect("the stand-in did the work: the per-session record still needs a session");
        records["requests"]
            .as_array()
            .expect("the stand-in did the work: the per-session record is requests")
            .iter()
            .find(|entry| entry["request_id"] == request_id)
            .unwrap_or_else(|| {
                panic!("the stand-in did the work: the per-session record holds {request_id}")
            })["status"]
            .as_str()
            .expect("the stand-in did the work: the per-session record names status")
            .to_owned()
    }

    #[test]
    fn standin_shell_lists_every_pending_request() {
        let mut standin = StandIn::new();
        launch_two_running(&mut standin);
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: component-1 is running",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 is running",
        );
        let empty = shell_pending(&standin);
        assert_keys(
            &empty,
            &["requests"],
            "the stand-in did the work: the shell pending list's only key is requests",
        );
        assert_eq!(
            empty,
            json!({ "requests": [] }),
            "the stand-in did the work: the shell pending list starts empty"
        );
        assert_eq!(
            standin.get_capability_pending(Caller::Client {
                session_id: "component-1",
            }),
            Err((403, "This endpoint requires shell privileges".to_owned(),)),
            "the stand-in did the work: a client is refused before the store is read"
        );
        assert_eq!(
            standin.get_capability_requests(Caller::Shell, None),
            Err((400, "requests need a session".to_owned())),
            "the stand-in did the work: the per-session record still needs a session"
        );

        let resource_a = "localhost://Public/resident-instances/a.txt";
        let resource_c = "localhost://Public/resident-instances/c.txt";
        let resource_b = "localhost://Public/resident-instances/b.txt";
        let resource_d = "localhost://Public/resident-instances/d.txt";
        let resource_late = "localhost://Public/resident-instances/late.txt";
        let resource_sat = "localhost://Public/resident-instances/sat.txt";
        // req-c is stored before req-a so a sort by session_id alone is not request_id order.
        standin
            .seed_request("req-b", "component-2", resource_b, "execute", "execute b")
            .expect("the stand-in did the work: it stores req-b");
        standin
            .seed_request("req-c", "component-1", resource_c, "write", "write c")
            .expect("the stand-in did the work: it stores req-c");
        standin
            .seed_request("req-a", "component-1", resource_a, "read", "read a")
            .expect("the stand-in did the work: it stores req-a");
        assert_eq!(
            standin.get_capability_pending(Caller::Client {
                session_id: "component-1",
            }),
            Err((403, "This endpoint requires shell privileges".to_owned(),)),
            "the stand-in did the work: a client is refused while requests are pending"
        );

        let listed = shell_pending(&standin);
        assert_keys(
            &listed,
            &["requests"],
            "the stand-in did the work: the shell pending list's only key is requests",
        );
        assert_eq!(
            pending_ids(&listed),
            vec!["req-a".to_owned(), "req-c".to_owned(), "req-b".to_owned()],
            "the stand-in did the work: the shell pending list is req-a, req-c, req-b"
        );
        let requests = listed["requests"]
            .as_array()
            .expect("the stand-in did the work: the shell pending list is requests");
        assert_pending_entry(
            &requests[0],
            "req-a",
            "component-1",
            resource_a,
            "read",
            "read a",
            0,
            300,
        );
        assert_pending_entry(
            &requests[1],
            "req-c",
            "component-1",
            resource_c,
            "write",
            "write c",
            0,
            300,
        );
        assert_pending_entry(
            &requests[2],
            "req-b",
            "component-2",
            resource_b,
            "execute",
            "execute b",
            0,
            300,
        );
        assert_eq!(
            record_status(&standin, "component-1", "req-a"),
            "pending",
            "the stand-in did the work: the shell pending list leaves req-a pending"
        );
        assert_eq!(
            record_status(&standin, "component-1", "req-c"),
            "pending",
            "the stand-in did the work: the shell pending list leaves req-c pending"
        );
        assert_eq!(
            record_status(&standin, "component-2", "req-b"),
            "pending",
            "the stand-in did the work: the shell pending list leaves req-b pending"
        );

        let granted = standin.post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": "req-c", "duration": "once" }),
        );
        assert!(
            granted.is_ok(),
            "the stand-in did the work: the shell grant of req-c is Ok: {granted:?}"
        );
        let after_grant = shell_pending(&standin);
        assert_eq!(
            pending_ids(&after_grant),
            vec!["req-a".to_owned(), "req-b".to_owned()],
            "the stand-in did the work: a granted request leaves the shell pending list"
        );
        assert_eq!(
            record_status(&standin, "component-1", "req-c"),
            "granted",
            "the stand-in did the work: the per-session record keeps req-c granted"
        );

        standin
            .seed_request("req-d", "component-1", resource_d, "delete", "delete d")
            .expect("the stand-in did the work: it stores req-d");
        let denied = standin.post_capability_deny(
            Caller::Shell,
            &json!({ "request_id": "req-d", "reason": "deny d" }),
        );
        assert!(
            denied.is_ok(),
            "the stand-in did the work: the shell deny of req-d is Ok: {denied:?}"
        );
        let after_deny = shell_pending(&standin);
        assert_eq!(
            pending_ids(&after_deny),
            vec!["req-a".to_owned(), "req-b".to_owned()],
            "the stand-in did the work: a denied request leaves the shell pending list"
        );
        assert_eq!(
            record_status(&standin, "component-1", "req-d"),
            "denied",
            "the stand-in did the work: the per-session record keeps req-d denied"
        );

        standin.set_instant(299);
        let at_299 = shell_pending(&standin);
        assert_eq!(
            pending_ids(&at_299),
            vec!["req-a".to_owned(), "req-b".to_owned()],
            "the stand-in did the work: instant 299 leaves req-a then req-b"
        );
        assert_eq!(
            at_299["requests"][0]["expires_at"].as_u64(),
            Some(300),
            "the stand-in did the work: req-a's expiry stays 300 at instant 299"
        );
        standin.set_instant(300);
        assert_eq!(
            shell_pending(&standin),
            json!({ "requests": [] }),
            "the stand-in did the work: instant 300 leaves the shell pending list empty"
        );
        assert_eq!(
            record_status(&standin, "component-1", "req-a"),
            "expired",
            "the stand-in did the work: the per-session record keeps req-a expired"
        );

        standin
            .seed_request(
                "req-late",
                "component-2",
                resource_late,
                "message",
                "message late",
            )
            .expect("the stand-in did the work: it stores req-late");
        let late = shell_pending(&standin);
        assert_eq!(
            pending_ids(&late),
            vec!["req-late".to_owned()],
            "the stand-in did the work: req-a and req-b stay absent after req-late"
        );
        assert_pending_entry(
            &late["requests"][0],
            "req-late",
            "component-2",
            resource_late,
            "message",
            "message late",
            300,
            600,
        );

        let near = u64::MAX - 10;
        standin.set_instant(near);
        standin
            .seed_request("req-sat", "component-1", resource_sat, "admin", "admin sat")
            .expect("the stand-in did the work: it stores req-sat");
        let saturated = shell_pending(&standin);
        assert_eq!(
            pending_ids(&saturated),
            vec!["req-sat".to_owned()],
            "the stand-in did the work: the shell pending list is the request seeded near u64::MAX"
        );
        assert_pending_entry(
            &saturated["requests"][0],
            "req-sat",
            "component-1",
            resource_sat,
            "admin",
            "admin sat",
            near,
            u64::MAX,
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: component-1 stays running",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 stays running",
        );
    }

    fn shell_audit(standin: &StandIn, limit: Option<usize>, event_type: Option<&str>) -> Value {
        let body = standin
            .get_audit(Caller::Shell, limit, event_type)
            .expect("the stand-in did the work: the shell reads the audit list");
        assert_keys(
            &body,
            &["events", "total_in_memory"],
            "the stand-in did the work: the audit body's only keys are events and total_in_memory",
        );
        body
    }

    fn audit_total(standin: &StandIn) -> u64 {
        shell_audit(standin, None, None)["total_in_memory"]
            .as_u64()
            .expect("the stand-in did the work: total_in_memory is a count")
    }

    fn assert_capability_use(
        event: &Value,
        at: u64,
        request_id: &str,
        session_id: &str,
        resource: &str,
        action: &str,
        message: &str,
    ) {
        assert_keys(
            event,
            &[
                "action",
                "at",
                "request_id",
                "resource",
                "session_id",
                "success",
                "type",
            ],
            &format!(
                "the stand-in did the work: {message} has type, at, request_id, session_id, resource, action and success"
            ),
        );
        assert_eq!(
            event,
            &json!({
                "type": "capability_use",
                "at": at,
                "request_id": request_id,
                "session_id": session_id,
                "resource": resource,
                "action": action,
                "success": true,
            }),
            "the stand-in did the work: {message}"
        );
    }

    fn expected_types() -> Value {
        json!({
            "event_types": [
                "capability_denied",
                "capability_grant",
                "capability_revoke",
                "capability_use",
            ],
        })
    }

    fn shell_types(standin: &StandIn) -> Value {
        let body = standin
            .get_audit_types(Caller::Shell)
            .expect("the stand-in did the work: the shell reads the audit types");
        assert_keys(
            &body,
            &["event_types"],
            "the stand-in did the work: the audit type body's only key is event_types",
        );
        body
    }

    macro_rules! refused_audit {
        ($standin:ident, $call:expr, $status:expr, $reason:expr, $total:expr, $message:expr $(,)?) => {{
            let result = $call;
            assert_eq!(
                result,
                Err(($status, $reason.to_owned())),
                "the stand-in did the work: {}",
                $message
            );
            assert_eq!(
                audit_total(&$standin),
                $total,
                "the stand-in did the work: {} appends nothing",
                $message
            );
        }};
    }

    fn assert_decision(
        event: &Value,
        event_type: &str,
        at: u64,
        request_id: &str,
        session_id: &str,
        resource: &str,
        action: &str,
        success: bool,
        message: &str,
    ) {
        assert_keys(
            event,
            &[
                "action",
                "at",
                "request_id",
                "resource",
                "session_id",
                "success",
                "type",
            ],
            &format!(
                "the stand-in did the work: {message} has type, at, request_id, session_id, resource, action and success"
            ),
        );
        assert_eq!(
            event,
            &json!({
                "type": event_type,
                "at": at,
                "request_id": request_id,
                "session_id": session_id,
                "resource": resource,
                "action": action,
                "success": success,
            }),
            "the stand-in did the work: {message}"
        );
    }

    fn audit_events(standin: &StandIn) -> Vec<Value> {
        shell_audit(standin, None, None)["events"]
            .as_array()
            .expect("the stand-in did the work: events is a list")
            .clone()
    }

    fn assert_audit_list(events: &[Value], expected: &[(&str, u64, &str, &str, &str, &str, bool)]) {
        assert_eq!(
            events.len(),
            expected.len(),
            "the stand-in did the work: the audit list has one event per decision"
        );
        for (event, (event_type, at, request_id, session_id, resource, action, success)) in
            events.iter().zip(expected)
        {
            assert_decision(
                event,
                event_type,
                *at,
                request_id,
                session_id,
                resource,
                action,
                *success,
                &format!("{event_type} {request_id}"),
            );
        }
    }

    fn decision_reason(standin: &StandIn, session_id: &str, request_id: &str) -> String {
        request_entries(standin, session_id)
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the stand-in did the work: the request record stays")["decision_reason"]
            .as_str()
            .expect("the stand-in did the work: the request record holds a decision reason")
            .to_owned()
    }

    fn request_status(standin: &StandIn, session_id: &str, request_id: &str) -> String {
        request_entries(standin, session_id)
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the stand-in did the work: the request record stays")["status"]
            .as_str()
            .expect("the stand-in did the work: the request record holds a status")
            .to_owned()
    }

    fn assert_absent(events: &[Value], request_id: &str) {
        assert!(
            events.iter().all(|event| event["request_id"] != request_id),
            "the stand-in did the work: {request_id} adds no audit event"
        );
    }

    fn refusal<T>(result: Result<T, (u16, String)>) -> Result<(), (u16, String)> {
        result.map(|_| ())
    }

    fn kept_refusal(
        standin: &StandIn,
        kept: &BTreeMap<String, Vec<u8>>,
        total: u64,
        result: Result<(), (u16, String)>,
        status: u16,
        reason: &str,
        message: &str,
    ) {
        assert_eq!(
            result,
            Err((status, reason.to_owned())),
            "the stand-in did the work: {message}"
        );
        assert_eq!(
            &standin.protected_objects, kept,
            "the stand-in did the work: {message} leaves the stored bytes"
        );
        assert_eq!(
            audit_total(standin),
            total,
            "the stand-in did the work: {message} appends nothing"
        );
    }

    macro_rules! refuse {
        ($standin:ident, $kept:ident, $total:expr, $call:expr, $status:expr, $reason:expr, $message:expr) => {{
            let result = refusal($call);
            kept_refusal(
                &$standin, &$kept, $total, result, $status, $reason, $message,
            );
        }};
    }

    #[test]
    fn standin_approved_use_is_on_the_audit_list() {
        let digest_a_hex = crate::identity::sha256(b"agent-ada");
        let digest_b_hex = crate::identity::sha256(b"agent-bob");
        let digest_a = &digest_a_hex[..24];
        let digest_b = &digest_b_hex[..24];
        let resolved = format!("localhost://UsersAI/{digest_a}/journal");
        let resolved_b = format!("localhost://UsersAI/{digest_b}/journal");
        let once_resolved = format!("localhost://UsersAI/{digest_a}/once");
        let guest = "localhost://UsersAI/self/journal";
        let once_guest = "localhost://UsersAI/self/once";
        let dot_guest = "localhost://UsersAI/self/../journal";
        let other_guest = "localhost://UsersAI/self/other";
        let users_guest = "localhost://Users/someone/journal";
        let public_guest = "localhost://Public/note";
        let missing_guest = "localhost://UsersAI/self/missing";
        let usersai_reason = "UsersAI roots must use UsersAI/self";
        let users_reason =
            "localhost://Users roots must use Users/self or the active principal root";
        let needs_reason = "protected storage needs a Users/self or UsersAI/self resource";
        let principal_reason = "requires the principal from the verified launch";
        let dot_reason = "protected path rejects ..";
        let wrong_action_read = "wrong action: expected write, got read";
        let wrong_action_write = "wrong action: expected read, got write";
        let wrong_resource = "wrong resource: expected localhost://UsersAI/self/journal, got localhost://UsersAI/self/other";
        let wrong_capsule = "wrong capsule: expected component-1, got component-2";

        let mut standin = StandIn::new();
        standin
            .admit_resident("/capsules/journal-a", "journal-a", Start::Ok)
            .expect("the stand-in admits journal-a");
        standin
            .admit_resident("/capsules/journal-b", "journal-b", Start::Ok)
            .expect("the stand-in admits journal-b");
        assert_eq!(
            standin.bind_verified_principal("/capsules/journal-a", "agent-ada"),
            Ok(()),
            "the stand-in did the work: journal-a binds agent-ada"
        );
        assert_eq!(
            standin.bind_verified_principal("/capsules/journal-b", "agent-bob"),
            Ok(()),
            "the stand-in did the work: journal-b binds agent-bob"
        );
        let launch_a = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-a"}))
            .expect("the stand-in launches journal-a");
        assert_eq!(
            launch_a,
            json!({
                "id": "component-1",
                "name": "journal-a",
                "status": "starting",
                "session_id": "component-1",
            }),
            "the stand-in did the work: component-1 session_id equals its id"
        );
        let launch_b = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-b"}))
            .expect("the stand-in launches journal-b");
        assert_eq!(
            launch_b,
            json!({
                "id": "component-2",
                "name": "journal-b",
                "status": "starting",
                "session_id": "component-2",
            }),
            "the stand-in did the work: component-2 session_id equals its id"
        );
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes component-1");
        standin
            .finish_start("component-2")
            .expect("the stand-in finishes component-2");
        assert_named_capsule(
            &standin,
            "component-1",
            "journal-a",
            "running",
            "",
            "component-1 is running",
        );
        assert_named_capsule(
            &standin,
            "component-2",
            "journal-b",
            "running",
            "",
            "component-2 is running",
        );

        let empty = json!({ "events": [], "total_in_memory": 0 });
        assert_eq!(
            shell_audit(&standin, None, None),
            empty,
            "the stand-in did the work: the shell audit list starts empty"
        );
        assert_eq!(
            standin.get_audit(
                Caller::Client {
                    session_id: "component-1",
                },
                None,
                None,
            ),
            Err((403, "This endpoint requires shell privileges".to_owned())),
            "the stand-in did the work: a client is refused before the store is read"
        );
        assert_eq!(
            shell_audit(&standin, None, None),
            empty,
            "the stand-in did the work: a client refusal leaves the shell list empty"
        );
        assert_eq!(
            standin.protected_write("component-1", "req-missing", guest, b"nope"),
            Err((400, "unknown grant: req-missing".to_owned())),
            "the stand-in did the work: an unknown grant cannot write"
        );
        assert!(
            standin.protected_objects.is_empty(),
            "the stand-in did the work: an unknown grant stores nothing"
        );
        assert_eq!(
            shell_audit(&standin, None, None),
            empty,
            "the stand-in did the work: an unknown grant appends nothing"
        );

        standin.seed_grant(
            "req-a",
            "component-1",
            guest,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-read",
            "component-1",
            guest,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-b",
            "component-2",
            guest,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            standin.authorise(
                Caller::Client {
                    session_id: "component-1",
                },
                "req-a",
            ),
            Ok(()),
            "the stand-in did the work: the owning client is authorised"
        );
        assert_eq!(
            shell_audit(&standin, None, None),
            empty,
            "the stand-in did the work: authorise appends nothing"
        );
        assert_eq!(
            grant_record(&standin, "req-a"),
            (Life::Live, false),
            "the stand-in did the work: authorise leaves a session grant live"
        );

        let wrote = standin
            .protected_write("component-1", "req-a", guest, b"journal-v1")
            .expect("the stand-in did the work: the approved write is stored");
        assert_eq!(
            wrote, resolved,
            "the stand-in did the work: the approved write returns the resolved uri"
        );
        assert!(
            !wrote.contains("agent-ada") && !wrote.contains("/self"),
            "the stand-in did the work: the resolved uri hides the principal and /self"
        );
        let listed = shell_audit(&standin, None, None);
        assert_eq!(
            listed["total_in_memory"],
            json!(1),
            "the stand-in did the work: one approved write is one stored event"
        );
        assert_eq!(
            listed["events"].as_array().map(Vec::len),
            Some(1),
            "the stand-in did the work: the shell list has one event"
        );
        assert_capability_use(
            &listed["events"][0],
            0,
            "req-a",
            "component-1",
            &resolved,
            "write",
            "the approved write records the resolved uri",
        );

        assert_eq!(
            standin.protected_read("component-2", "req-b", guest),
            Err((404, "protected object is absent".to_owned())),
            "the stand-in did the work: the sibling root has no journal"
        );
        assert_eq!(
            standin.protected_objects.get(&resolved),
            Some(&b"journal-v1".to_vec()),
            "the stand-in did the work: an absent read leaves the stored bytes"
        );
        assert_eq!(
            audit_total(&standin),
            1,
            "the stand-in did the work: an absent read appends nothing"
        );
        assert_eq!(
            standin.protected_read("component-1", "req-read", guest),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: the owner reads the stored journal"
        );
        let two = shell_audit(&standin, None, None);
        assert_eq!(
            two["total_in_memory"],
            json!(2),
            "the stand-in did the work: the approved read is the second stored event"
        );
        assert_capability_use(
            &two["events"][0],
            0,
            "req-read",
            "component-1",
            &resolved,
            "read",
            "the later read is ahead of the earlier write",
        );
        assert_capability_use(
            &two["events"][1],
            0,
            "req-a",
            "component-1",
            &resolved,
            "write",
            "the earlier write follows the later read",
        );
        assert_eq!(
            shell_audit(&standin, None, None),
            two,
            "the stand-in did the work: a second shell read returns the same body"
        );

        standin.set_instant(4);
        assert_eq!(
            standin.protected_write("component-1", "req-a", guest, b"journal-v2"),
            Ok(resolved.clone()),
            "the stand-in did the work: the later write returns the same resolved uri"
        );
        let three = shell_audit(&standin, None, None);
        assert_eq!(
            three["total_in_memory"],
            json!(3),
            "the stand-in did the work: the later write is the third stored event"
        );
        assert_eq!(
            three["events"][0]["at"],
            json!(4),
            "the stand-in did the work: the later write records the test instant"
        );
        assert_eq!(
            three["events"][0]["action"],
            json!("write"),
            "the stand-in did the work: the later event is a write"
        );
        assert_eq!(
            three["events"][0]["request_id"],
            json!("req-a"),
            "the stand-in did the work: the later write keeps its request id"
        );
        assert_eq!(
            standin.protected_read("component-1", "req-read", guest),
            Ok(b"journal-v2".to_vec()),
            "the stand-in did the work: the owner reads the later journal"
        );
        let one = shell_audit(&standin, Some(1), None);
        assert_eq!(
            one["total_in_memory"],
            json!(4),
            "the stand-in did the work: limit 1 leaves the stored count"
        );
        assert_eq!(
            one["events"].as_array().map(Vec::len),
            Some(1),
            "the stand-in did the work: limit 1 keeps one event"
        );
        assert_capability_use(
            &one["events"][0],
            4,
            "req-read",
            "component-1",
            &resolved,
            "read",
            "limit 1 keeps the newest read",
        );
        let none = shell_audit(&standin, Some(0), None);
        assert_eq!(
            none["events"],
            json!([]),
            "the stand-in did the work: limit 0 keeps no event"
        );
        assert_eq!(
            none["total_in_memory"],
            json!(4),
            "the stand-in did the work: limit 0 leaves the stored count"
        );
        let typed = shell_audit(&standin, Some(1001), Some("capability_use"));
        assert_eq!(
            typed["events"].as_array().map(Vec::len),
            Some(4),
            "the stand-in did the work: a high limit keeps every capability_use event"
        );
        assert_eq!(
            typed["total_in_memory"],
            json!(4),
            "the stand-in did the work: a type filter leaves the stored count"
        );
        let other_type = shell_audit(&standin, None, Some("capsule_launch"));
        assert_eq!(
            other_type["events"],
            json!([]),
            "the stand-in did the work: a capsule_launch filter keeps no capability_use event"
        );
        assert_eq!(
            other_type["total_in_memory"],
            json!(4),
            "the stand-in did the work: an empty type filter leaves the stored count"
        );

        assert_eq!(
            standin.protected_write("component-9", "req-a", guest, b"other"),
            Err((400, "unknown instance: component-9".to_owned())),
            "the stand-in did the work: an unknown instance cannot write"
        );
        assert_eq!(
            standin.protected_objects.get(&resolved),
            Some(&b"journal-v2".to_vec()),
            "the stand-in did the work: an unknown instance leaves the stored bytes"
        );
        assert_eq!(
            audit_total(&standin),
            4,
            "the stand-in did the work: an unknown instance appends nothing"
        );

        standin.seed_grant(
            "req-once",
            "component-1",
            once_guest,
            "write",
            "once",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            standin.protected_write("component-1", "req-once", once_guest, b"once-v1"),
            Ok(once_resolved.clone()),
            "the stand-in did the work: the once write returns its resolved uri"
        );
        assert_eq!(
            grant_record(&standin, "req-once"),
            (Life::Exhausted, false),
            "the stand-in did the work: the once grant is exhausted"
        );
        assert_eq!(
            audit_total(&standin),
            5,
            "the stand-in did the work: the once write is the fifth stored event"
        );
        assert_eq!(
            standin.protected_write("component-1", "req-once", once_guest, b"once-v2"),
            Err((400, "grant is not live: Exhausted".to_owned())),
            "the stand-in did the work: an exhausted grant cannot write"
        );
        assert_eq!(
            standin.protected_objects.get(&once_resolved),
            Some(&b"once-v1".to_vec()),
            "the stand-in did the work: an exhausted grant leaves the stored bytes"
        );
        assert_eq!(
            audit_total(&standin),
            5,
            "the stand-in did the work: an exhausted grant appends nothing"
        );
        assert_named_capsule(
            &standin,
            "component-1",
            "journal-a",
            "running",
            "",
            "component-1 stays running",
        );
        assert_named_capsule(
            &standin,
            "component-2",
            "journal-b",
            "running",
            "",
            "component-2 stays running",
        );

        let five = shell_audit(&standin, None, None);
        assert_capability_use(
            &five["events"][0],
            4,
            "req-once",
            "component-1",
            &once_resolved,
            "write",
            "the once use records its own resource",
        );
        standin.seed_grant(
            "req-b-write",
            "component-2",
            guest,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            standin.protected_write("component-2", "req-b-write", guest, b"bob-v1"),
            Ok(resolved_b.clone()),
            "the stand-in did the work: component-2 stores under its own principal"
        );
        assert!(
            !resolved_b.contains("agent-bob") && !resolved_b.contains("/self"),
            "the stand-in did the work: component-2's resolved uri hides the principal and /self"
        );
        let six = shell_audit(&standin, None, None);
        assert_eq!(
            six["total_in_memory"],
            json!(6),
            "the stand-in did the work: component-2's write is the sixth stored event"
        );
        assert_capability_use(
            &six["events"][0],
            4,
            "req-b-write",
            "component-2",
            &resolved_b,
            "write",
            "component-2 records its own session and resource",
        );
        assert_capability_use(
            &six["events"][1],
            4,
            "req-once",
            "component-1",
            &once_resolved,
            "write",
            "the once resource stays on its event",
        );

        standin
            .admit_resident("/capsules/journal-stop", "journal-stop", Start::Ok)
            .expect("the stand-in admits journal-stop");
        standin
            .bind_verified_principal("/capsules/journal-stop", "agent-stop")
            .expect("the stand-in binds agent-stop");
        let launch_stop = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-stop"}))
            .expect("the stand-in launches journal-stop");
        assert_eq!(
            launch_stop["id"], "component-3",
            "the stand-in did the work: the stopped instance is component-3"
        );
        standin
            .finish_start("component-3")
            .expect("the stand-in finishes component-3");
        standin
            .delete_capsule(Caller::Shell, "component-3", &stop_body())
            .expect("the stand-in stops component-3");
        standin.seed_grant(
            "req-stop",
            "component-3",
            guest,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin
            .admit_resident(
                "/capsules/journal-fail",
                "journal-fail",
                Start::Error("start refused".to_owned()),
            )
            .expect("the stand-in admits journal-fail");
        standin
            .bind_verified_principal("/capsules/journal-fail", "agent-fail")
            .expect("the stand-in binds agent-fail");
        let launch_fail = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-fail"}))
            .expect("the stand-in launches journal-fail");
        assert_eq!(
            launch_fail["id"], "component-4",
            "the stand-in did the work: the failed instance is component-4"
        );
        standin
            .finish_start("component-4")
            .expect("the stand-in finishes component-4");
        standin.seed_grant(
            "req-fail",
            "component-4",
            guest,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin
            .admit_resident("/capsules/journal-plain", "journal-plain", Start::Ok)
            .expect("the stand-in admits journal-plain");
        let launch_plain = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-plain"}))
            .expect("the stand-in launches journal-plain");
        assert_eq!(
            launch_plain["id"], "component-5",
            "the stand-in did the work: the unbound instance is component-5"
        );
        standin
            .finish_start("component-5")
            .expect("the stand-in finishes component-5");
        standin.seed_grant(
            "req-plain",
            "component-5",
            guest,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-revoked",
            "component-1",
            guest,
            "write",
            "session",
            1,
            Life::Revoked,
            false,
        );
        standin.seed_grant(
            "req-expired",
            "component-1",
            guest,
            "write",
            "session",
            1,
            Life::Expired,
            false,
        );
        standin.seed_grant(
            "req-absent",
            "component-1",
            missing_guest,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        assert_named_capsule(
            &standin,
            "component-3",
            "journal-stop",
            "stopped",
            "stopped: stop one",
            "component-3 is stopped",
        );
        assert_named_capsule(
            &standin,
            "component-4",
            "journal-fail",
            "failed",
            "start refused",
            "component-4 is failed",
        );
        assert_named_capsule(
            &standin,
            "component-1",
            "journal-a",
            "running",
            "",
            "component-1 stays running after the other instances",
        );
        assert_named_capsule(
            &standin,
            "component-2",
            "journal-b",
            "running",
            "",
            "component-2 stays running after the other instances",
        );

        let total = audit_total(&standin);
        assert_eq!(
            total, 6,
            "the stand-in did the work: preparing a refusal appends nothing"
        );
        let kept = standin.protected_objects.clone();
        refuse!(
            standin,
            kept,
            total,
            standin.protected_write("component-3", "req-stop", guest, b"stop"),
            400,
            "instance is not live: stopped",
            "a stopped instance cannot write"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-3", "req-stop", guest),
            400,
            "instance is not live: stopped",
            "a stopped instance cannot read"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_write("component-4", "req-fail", guest, b"fail"),
            400,
            "instance is not live: failed",
            "a failed instance cannot write"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-4", "req-fail", guest),
            400,
            "instance is not live: failed",
            "a failed instance cannot read"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_write("component-1", "req-a", dot_guest, b"dot"),
            400,
            dot_reason,
            "a .. write is refused"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-1", "req-read", dot_guest),
            400,
            dot_reason,
            "a .. read is refused"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_write("component-1", "req-a", &resolved, b"root"),
            400,
            usersai_reason,
            "an explicit UsersAI root cannot write"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-1", "req-read", &resolved),
            400,
            usersai_reason,
            "an explicit UsersAI root cannot read"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_write("component-1", "req-a", users_guest, b"root"),
            400,
            users_reason,
            "another Users root cannot write"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-1", "req-read", users_guest),
            400,
            users_reason,
            "another Users root cannot read"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_write("component-1", "req-a", public_guest, b"root"),
            400,
            needs_reason,
            "a resource outside Users cannot write"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-1", "req-read", public_guest),
            400,
            needs_reason,
            "a resource outside Users cannot read"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_write("component-5", "req-plain", guest, b"plain"),
            400,
            principal_reason,
            "an unbound instance cannot write"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-5", "req-plain", guest),
            400,
            principal_reason,
            "an unbound instance cannot read"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-9", "req-read", guest),
            400,
            "unknown instance: component-9",
            "an unknown instance cannot read"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-1", "req-missing", guest),
            400,
            "unknown grant: req-missing",
            "an unknown grant cannot read"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_write("component-1", "req-revoked", guest, b"revoked"),
            400,
            "grant is not live: Revoked",
            "a revoked grant cannot write"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-1", "req-revoked", guest),
            400,
            "grant is not live: Revoked",
            "a revoked grant cannot read"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_write("component-1", "req-expired", guest, b"expired"),
            400,
            "grant is not live: Expired",
            "an expired grant cannot write"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-1", "req-expired", guest),
            400,
            "grant is not live: Expired",
            "an expired grant cannot read"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_write("component-2", "req-a", guest, b"stolen"),
            403,
            wrong_capsule,
            "a sibling cannot write with component-1's grant"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-2", "req-read", guest),
            403,
            wrong_capsule,
            "a sibling cannot read with component-1's grant"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-1", "req-a", guest),
            403,
            wrong_action_read,
            "a write grant cannot read"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_write("component-1", "req-read", guest, b"nope"),
            403,
            wrong_action_write,
            "a read grant cannot write"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_write("component-1", "req-a", other_guest, b"other"),
            403,
            wrong_resource,
            "a journal grant cannot write another path"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-1", "req-read", other_guest),
            403,
            wrong_resource,
            "a journal grant cannot read another path"
        );
        refuse!(
            standin,
            kept,
            total,
            standin.protected_read("component-1", "req-absent", missing_guest),
            404,
            "protected object is absent",
            "an absent object cannot be read"
        );
        assert_eq!(
            grant_record(&standin, "req-a"),
            (Life::Live, false),
            "the stand-in did the work: a refusal spends nothing"
        );
        assert_eq!(
            grant_record(&standin, "req-read"),
            (Life::Live, false),
            "the stand-in did the work: a refused read spends nothing"
        );
        assert_eq!(
            grant_record(&standin, "req-stop"),
            (Life::Live, false),
            "the stand-in did the work: a stopped instance spends nothing"
        );
        assert_eq!(
            grant_record(&standin, "req-fail"),
            (Life::Live, false),
            "the stand-in did the work: a failed instance spends nothing"
        );
        assert_eq!(
            grant_record(&standin, "req-once"),
            (Life::Exhausted, false),
            "the stand-in did the work: the exhausted once grant stays exhausted"
        );
        assert_eq!(
            grant_record(&standin, "req-b-write"),
            (Life::Live, false),
            "the stand-in did the work: component-2's session grant stays live"
        );

        standin.seed_grant(
            "req-read-once",
            "component-1",
            guest,
            "read",
            "once",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            standin.protected_read("component-1", "req-read-once", guest),
            Ok(b"journal-v2".to_vec()),
            "the stand-in did the work: the first read of a once grant returns the journal"
        );
        assert_eq!(
            grant_record(&standin, "req-read-once"),
            (Life::Exhausted, false),
            "the stand-in did the work: the once read is spent"
        );
        let once_read = shell_audit(&standin, Some(1), None);
        assert_eq!(
            once_read["total_in_memory"],
            json!(total + 1),
            "the stand-in did the work: the once read is recorded"
        );
        assert_capability_use(
            &once_read["events"][0],
            4,
            "req-read-once",
            "component-1",
            &resolved,
            "read",
            "the once read records the resolved uri",
        );
        assert_eq!(
            standin.protected_read("component-1", "req-read-once", guest),
            Err((400, "grant is not live: Exhausted".to_owned())),
            "the stand-in did the work: a second once read is refused"
        );
        assert_eq!(
            shell_audit(&standin, Some(1), None),
            once_read,
            "the stand-in did the work: an exhausted read appends nothing"
        );
        assert_eq!(
            &standin.protected_objects, &kept,
            "the stand-in did the work: an exhausted read leaves the stored bytes"
        );

        while standin.audit.len() < 1000 {
            standin
                .protected_write("component-1", "req-a", guest, b"fill")
                .expect("the stand-in did the work: a session grant fills the audit list");
        }
        standin.seed_grant(
            "req-tail",
            "component-1",
            guest,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            standin.protected_write("component-1", "req-tail", guest, b"tail"),
            Ok(resolved.clone()),
            "the stand-in did the work: the newest use returns the resolved uri"
        );
        assert_eq!(
            standin.audit.len(),
            1001,
            "the stand-in did the work: the audit list holds 1001 events"
        );
        let default_list = shell_audit(&standin, None, None);
        assert_eq!(
            default_list["total_in_memory"],
            json!(1001),
            "the stand-in did the work: the default read counts every stored event"
        );
        assert_eq!(
            default_list["events"].as_array().map(Vec::len),
            Some(100),
            "the stand-in did the work: the default limit keeps 100 events"
        );
        assert_eq!(
            default_list["events"][0]["request_id"],
            json!("req-tail"),
            "the stand-in did the work: the default window starts with the newest use"
        );
        let max_list = shell_audit(&standin, Some(1001), None);
        assert_eq!(
            max_list["total_in_memory"],
            json!(1001),
            "the stand-in did the work: a limit above 1000 counts every stored event"
        );
        assert_eq!(
            max_list["events"].as_array().map(Vec::len),
            Some(1000),
            "the stand-in did the work: a limit above 1000 keeps 1000 events"
        );
        assert_eq!(
            max_list["events"][0]["request_id"],
            json!("req-tail"),
            "the stand-in did the work: the maximum window starts with the newest use"
        );
        let max_typed = shell_audit(&standin, Some(1001), Some("capability_use"));
        assert_eq!(
            max_typed["events"].as_array().map(Vec::len),
            Some(1000),
            "the stand-in did the work: the capability_use filter keeps the maximum window"
        );
        assert_eq!(
            max_typed["total_in_memory"],
            json!(1001),
            "the stand-in did the work: the capability_use filter leaves the stored count"
        );
        let missed = shell_audit(&standin, None, Some("capsule_launch"));
        assert_eq!(
            missed["events"],
            json!([]),
            "the stand-in did the work: a capsule_launch filter keeps no event from a long list"
        );
        assert_eq!(
            missed["total_in_memory"],
            json!(1001),
            "the stand-in did the work: a capsule_launch filter leaves the long stored count"
        );
        let zero = shell_audit(&standin, Some(0), None);
        assert_eq!(
            zero["events"],
            json!([]),
            "the stand-in did the work: limit 0 keeps no event when the list is long"
        );
        assert_eq!(
            zero["total_in_memory"],
            json!(1001),
            "the stand-in did the work: limit 0 leaves the long stored count"
        );
        assert_named_capsule(
            &standin,
            "component-1",
            "journal-a",
            "running",
            "",
            "component-1 stays running after the audit fill",
        );
        assert_named_capsule(
            &standin,
            "component-2",
            "journal-b",
            "running",
            "",
            "component-2 stays running after the audit fill",
        );
    }

    fn host_pair(
        standin: &mut StandIn,
        line: &str,
        capsule_id: &str,
        principal: Option<&str>,
    ) -> Result<(String, Value), String> {
        let raw = standin.bridge_envelope(line, capsule_id, principal)?;
        assert_eq!(
            raw.trim(),
            raw,
            "the stand-in did the work: the hostcall returns one JSON object with no trailing text"
        );
        let parsed: Value = serde_json::from_str(&raw).unwrap_or_else(|err| {
            panic!(
                "the stand-in did the work: the hostcall returns one JSON object: {err}; raw {raw:?}"
            )
        });
        Ok((raw, parsed))
    }

    fn assert_no_protected_leak(raw: &str, digest: &str, principal: &str, message: &str) {
        assert!(
            !raw.contains(principal),
            "the stand-in did the work: {message} names no principal"
        );
        assert!(
            !raw.contains(digest),
            "the stand-in did the work: {message} names no resolved root"
        );
        assert!(
            !raw.contains("token"),
            "the stand-in did the work: {message} has no token"
        );
        assert!(
            !raw.contains("audit"),
            "the stand-in did the work: {message} has no audit"
        );
    }

    fn running_ada() -> StandIn {
        let mut standin = StandIn::new();
        standin
            .admit_resident("/capsules/journal-a", "journal-a", Start::Ok)
            .expect("the stand-in admits journal-a");
        assert_eq!(
            standin.bind_verified_principal("/capsules/journal-a", "agent-ada"),
            Ok(()),
            "the stand-in did the work: journal-a binds agent-ada"
        );
        let launched = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-a"}))
            .expect("the stand-in launches journal-a");
        assert_eq!(
            launched["id"], "component-1",
            "the stand-in did the work: the launch id is component-1"
        );
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes component-1");
        standin
    }

    #[test]
    fn standin_hostcall_returns_the_protected_result() {
        let digest_a_hex = crate::identity::sha256(b"agent-ada");
        let digest_a = &digest_a_hex[..24];
        let guest = "localhost://UsersAI/self/journal";
        let once_guest = "localhost://UsersAI/self/once";
        let users_guest = "localhost://Users/self/note";
        let object_line = r#"{"id":3,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/journal","operation":"write","body":{"bytes":"journal-v1"},"token":"req-w"}}"#;
        let write_line = r#"{"id":4,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/journal","operation":"write","body":"journal-v1","token":"req-w"}}"#;
        let read_line = r#"{"id":5,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/journal","operation":"read","body":{},"token":"req-r"}}"#;
        let sibling_line = r#"{"id":5,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/journal","operation":"read","body":{},"token":"req-b"}}"#;
        let wrong_line = r#"{"id":4,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/journal","operation":"write","body":"other","token":"req-w"}}"#;
        let once_line = r#"{"id":6,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/once","operation":"write","body":"once-v1","token":"req-once"}}"#;
        let once_read = r#"{"id":7,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/journal","operation":"read","body":{},"token":"req-once-read"}}"#;
        let list_line = r#"{"id":9,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/journal","operation":"list","body":"journal-v1","token":"req-w"}}"#;
        let public_line = r#"{"id":8,"request":{"type":"resource_invoke","uri":"localhost://Public/resident-instances/shared.txt","operation":"read","body":{},"token":"req-pub"}}"#;
        let users_write = r#"{"id":15,"request":{"type":"resource_invoke","uri":"localhost://Users/self/note","operation":"write","body":"note-v1","token":"req-users-w"}}"#;
        let users_read = r#"{"id":16,"request":{"type":"resource_invoke","uri":"localhost://Users/self/note","operation":"read","body":{},"token":"req-users-r"}}"#;

        let mut standin = StandIn::new();
        standin
            .admit_resident("/capsules/journal-a", "journal-a", Start::Ok)
            .expect("the stand-in admits journal-a");
        standin
            .admit_resident("/capsules/journal-b", "journal-b", Start::Ok)
            .expect("the stand-in admits journal-b");
        assert_eq!(
            standin.bind_verified_principal("/capsules/journal-a", "agent-ada"),
            Ok(()),
            "the stand-in did the work: journal-a binds agent-ada"
        );
        assert_eq!(
            standin.bind_verified_principal("/capsules/journal-b", "agent-bob"),
            Ok(()),
            "the stand-in did the work: journal-b binds agent-bob"
        );
        let launch_a = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-a"}))
            .expect("the stand-in launches journal-a");
        let launch_b = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/journal-b"}))
            .expect("the stand-in launches journal-b");
        assert_eq!(
            launch_a["id"], "component-1",
            "the stand-in did the work: journal-a is component-1"
        );
        assert_eq!(
            launch_b["id"], "component-2",
            "the stand-in did the work: journal-b is component-2"
        );
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes component-1");
        standin
            .finish_start("component-2")
            .expect("the stand-in finishes component-2");
        assert_named_capsule(
            &standin,
            "component-1",
            "journal-a",
            "running",
            "",
            "component-1 is running",
        );
        assert_named_capsule(
            &standin,
            "component-2",
            "journal-b",
            "running",
            "",
            "component-2 is running",
        );
        standin.seed_grant(
            "req-w",
            "component-1",
            guest,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-r",
            "component-1",
            guest,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-b",
            "component-2",
            guest,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-once",
            "component-1",
            once_guest,
            "write",
            "once",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-once-read",
            "component-1",
            guest,
            "read",
            "once",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-pub",
            "component-1",
            SHARED_RESOURCE,
            "read",
            "once",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-users-w",
            "component-1",
            users_guest,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-users-r",
            "component-1",
            users_guest,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );

        let (raw, parsed) = host_pair(&mut standin, object_line, "component-1", Some("agent-ada"))
            .expect("the stand-in did the work: an object write body is one response");
        assert_host_error(
            &parsed,
            3,
            "protected write body must be a string",
            "an object write body is refused",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "an object write body");
        assert_eq!(
            standin.protected_read("component-1", "req-r", guest),
            Err((404, "protected object is absent".to_owned())),
            "the stand-in did the work: an object write body stores nothing"
        );
        assert_eq!(
            grant_record(&standin, "req-w"),
            (Life::Live, false),
            "the stand-in did the work: an object write body leaves the grant live"
        );

        let (raw, parsed) = host_pair(&mut standin, write_line, "component-1", Some("agent-ada"))
            .expect("the stand-in did the work: the approved write is one response");
        assert_host_ok(
            &parsed,
            4,
            json!({ "stored": true }),
            "the approved write returns stored",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the approved write");
        assert_eq!(
            standin.protected_read("component-1", "req-r", guest),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: the approved write stores journal-v1"
        );

        let (raw, parsed) = host_pair(&mut standin, read_line, "component-1", None)
            .expect("the stand-in did the work: the approved read is one response");
        assert_host_ok(
            &parsed,
            5,
            json!("journal-v1"),
            "the approved read returns the stored text",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the approved read");

        for (line, message) in [
            (
                r#"{"id":5,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/journal","operation":"read","token":"req-r"}}"#,
                "a missing read body is ignored",
            ),
            (
                r#"{"id":5,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/journal","operation":"read","body":null,"token":"req-r"}}"#,
                "a null read body is ignored",
            ),
            (
                r#"{"id":5,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/journal","operation":"read","body":1,"token":"req-r"}}"#,
                "a numeric read body is ignored",
            ),
        ] {
            let (raw, parsed) = host_pair(&mut standin, line, "component-1", None)
                .expect("the stand-in did the work: a read body is one response");
            assert_host_ok(&parsed, 5, json!("journal-v1"), message);
            assert_no_protected_leak(&raw, digest_a, "agent-ada", message);
        }

        let (raw, sibling) = host_pair(
            &mut standin,
            sibling_line,
            "component-2",
            Some("component-1"),
        )
        .expect("the stand-in did the work: the other capsule's read is one response");
        assert_host_error(
            &sibling,
            5,
            "protected object is absent",
            "the other capsule reads its own absent object",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the other capsule's read");
        assert_eq!(
            standin.protected_read("component-1", "req-r", guest),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: the other capsule's read leaves journal-v1"
        );

        let (raw, wrong) = host_pair(&mut standin, wrong_line, "component-2", Some("component-1"))
            .expect("the stand-in did the work: the other capsule's write is one response");
        assert_host_error(
            &wrong,
            4,
            "wrong capsule: expected component-1, got component-2",
            "the other capsule's write is refused",
        );
        assert!(
            wrong["response"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("wrong capsule"),
            "the stand-in did the work: the other capsule's write names wrong capsule"
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the other capsule's write");
        assert_eq!(
            standin.protected_read("component-1", "req-r", guest),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: the other capsule's write leaves journal-v1"
        );

        for (line, message) in [
            (
                r#"{"id":10,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/once","operation":"write","token":"req-once"}}"#,
                "a missing write body is refused",
            ),
            (
                r#"{"id":11,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/once","operation":"write","body":null,"token":"req-once"}}"#,
                "a null write body is refused",
            ),
            (
                r#"{"id":12,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/once","operation":"write","body":1,"token":"req-once"}}"#,
                "a numeric write body is refused",
            ),
            (
                r#"{"id":13,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/once","operation":"write","body":true,"token":"req-once"}}"#,
                "a boolean write body is refused",
            ),
            (
                r#"{"id":14,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/once","operation":"write","body":[],"token":"req-once"}}"#,
                "an array write body is refused",
            ),
        ] {
            let (raw, parsed) = host_pair(&mut standin, line, "component-1", None)
                .expect("the stand-in did the work: a non-string write body is one response");
            assert_host_error(
                &parsed,
                parsed["id"].as_u64().unwrap(),
                "protected write body must be a string",
                message,
            );
            assert_no_protected_leak(&raw, digest_a, "agent-ada", message);
            assert_eq!(
                standin.protected_read("component-1", "req-r", guest),
                Ok(b"journal-v1".to_vec()),
                "the stand-in did the work: {message} leaves the stored bytes"
            );
            assert_eq!(
                grant_record(&standin, "req-once"),
                (Life::Live, false),
                "the stand-in did the work: {message} leaves the once grant live"
            );
            assert!(
                standin
                    .protected_objects
                    .keys()
                    .all(|key| !key.ends_with("/once")),
                "the stand-in did the work: {message} stores nothing"
            );
        }

        let (raw, once_read_body) = host_pair(&mut standin, once_read, "component-1", None)
            .expect("the stand-in did the work: the once read is one response");
        assert_host_ok(
            &once_read_body,
            7,
            json!("journal-v1"),
            "the once read returns the stored text",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the once read");
        assert_eq!(
            grant_record(&standin, "req-once-read"),
            (Life::Exhausted, false),
            "the stand-in did the work: the once read stores Exhausted"
        );
        let (raw, once_read_again) = host_pair(&mut standin, once_read, "component-1", None)
            .expect("the stand-in did the work: the second once read is one response");
        assert_host_error(
            &once_read_again,
            7,
            "grant is not live: Exhausted",
            "a second once read finds the grant exhausted",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the second once read");
        assert_eq!(
            standin.protected_read("component-1", "req-r", guest),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: the once read leaves journal-v1"
        );

        let (raw, once_body) = host_pair(&mut standin, once_line, "component-1", None)
            .expect("the stand-in did the work: the once write is one response");
        assert_host_ok(
            &once_body,
            6,
            json!({ "stored": true }),
            "the once write returns stored",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the once write");
        assert_eq!(
            grant_record(&standin, "req-once"),
            (Life::Exhausted, false),
            "the stand-in did the work: the once write stores Exhausted"
        );
        let (raw, once_again) = host_pair(&mut standin, once_line, "component-1", None)
            .expect("the stand-in did the work: the second once write is one response");
        assert_host_error(
            &once_again,
            6,
            "grant is not live: Exhausted",
            "a second once write finds the grant exhausted",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the second once write");

        let (raw, listed) = host_pair(&mut standin, list_line, "component-1", None)
            .expect("the stand-in did the work: a list invoke is one response");
        assert_host_error(
            &listed,
            9,
            "protected operation is read or write",
            "list is not a protected operation",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "a list invoke");
        assert_eq!(
            grant_record(&standin, "req-w"),
            (Life::Live, false),
            "the stand-in did the work: list leaves the write grant live"
        );
        assert_eq!(
            standin.protected_read("component-1", "req-r", guest),
            Ok(b"journal-v1".to_vec()),
            "the stand-in did the work: list stores nothing"
        );

        let (raw, users_written) = host_pair(&mut standin, users_write, "component-1", None)
            .expect("the stand-in did the work: the Users write is one response");
        assert_host_ok(
            &users_written,
            15,
            json!({ "stored": true }),
            "the Users write returns stored",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the Users write");
        let (raw, users_body) = host_pair(&mut standin, users_read, "component-1", None)
            .expect("the stand-in did the work: the Users read is one response");
        assert_host_ok(
            &users_body,
            16,
            json!("note-v1"),
            "the Users read returns the stored text",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the Users read");

        let (raw, public) = host_pair(&mut standin, public_line, "component-1", Some("agent-ada"))
            .expect("the stand-in did the work: the public invoke is one response");
        assert_host_ok(
            &public,
            8,
            Value::Null,
            "the public invoke returns data null",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the public invoke");
        assert_eq!(
            grant_record(&standin, "req-pub"),
            (Life::Exhausted, false),
            "the stand-in did the work: the public invoke stores Exhausted"
        );
        assert_named_capsule(
            &standin,
            "component-1",
            "journal-a",
            "running",
            "",
            "component-1 stays running",
        );
        assert_named_capsule(
            &standin,
            "component-2",
            "journal-b",
            "running",
            "",
            "component-2 stays running",
        );
    }

    #[test]
    fn standin_hostcall_redacts_protected_errors() {
        let digest_a_hex = crate::identity::sha256(b"agent-ada");
        let digest_a = &digest_a_hex[..24];
        let users_grant = format!("localhost://Users/{digest_a}/journal");
        let usersai_grant = format!("localhost://UsersAI/{digest_a}/journal");
        let users_leaked =
            format!("wrong resource: expected {users_grant}, got localhost://Users/self/other");
        let usersai_leaked =
            format!("wrong resource: expected {usersai_grant}, got localhost://UsersAI/self/other");
        let users_redacted =
            "wrong resource: expected localhost://Users/self/journal, got localhost://Users/self/other";
        let usersai_redacted = "wrong resource: expected localhost://UsersAI/self/journal, got localhost://UsersAI/self/other";
        let mut standin = running_ada();
        standin.seed_grant(
            "req-users-root",
            "component-1",
            &users_grant,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-usersai-root",
            "component-1",
            &usersai_grant,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-users-root",
                "localhost://Users/self/other",
                b"nope",
            ),
            Err((403, users_leaked)),
            "the stand-in did the work: the protected method names the resolved Users root"
        );
        let users_line = r#"{"id":1,"request":{"type":"resource_invoke","uri":"localhost://Users/self/other","operation":"write","body":"nope","token":"req-users-root"}}"#;
        let (raw, parsed) = host_pair(&mut standin, users_line, "component-1", Some("agent-ada"))
            .expect("the stand-in did the work: the Users refusal is one response");
        assert_host_error(
            &parsed,
            1,
            users_redacted,
            "the hostcall redacts the resolved Users root",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the redacted Users error");
        assert_eq!(
            grant_record(&standin, "req-users-root"),
            (Life::Live, false),
            "the stand-in did the work: the redacted Users error leaves the grant live"
        );

        assert_eq!(
            standin.protected_write(
                "component-1",
                "req-usersai-root",
                "localhost://UsersAI/self/other",
                b"nope",
            ),
            Err((403, usersai_leaked)),
            "the stand-in did the work: the protected method names the resolved UsersAI root"
        );
        let usersai_line = r#"{"id":2,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/other","operation":"write","body":"nope","token":"req-usersai-root"}}"#;
        let (raw, parsed) = host_pair(&mut standin, usersai_line, "component-1", Some("agent-ada"))
            .expect("the stand-in did the work: the UsersAI refusal is one response");
        assert_host_error(
            &parsed,
            2,
            usersai_redacted,
            "the hostcall redacts the resolved UsersAI root",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the redacted UsersAI error");
        assert_eq!(
            grant_record(&standin, "req-usersai-root"),
            (Life::Live, false),
            "the stand-in did the work: the redacted UsersAI error leaves the grant live"
        );

        let digest_b_hex = crate::identity::sha256(b"agent-bob");
        let digest_b = &digest_b_hex[..24];
        for digest in [digest_a, digest_b] {
            for namespace in ["Users", "UsersAI"] {
                for operation in ["read", "write"] {
                    for suffix in ["", "/journal"] {
                        let request_id = format!("req-{digest}-{namespace}-{operation}-{suffix}");
                        let resource = format!("localhost://{namespace}/{digest}{suffix}");
                        let uri = format!("localhost://{namespace}/self/other");
                        standin.seed_grant(
                            &request_id,
                            "component-1",
                            &resource,
                            operation,
                            "once",
                            1,
                            Life::Live,
                            false,
                        );
                        let line = json!({
                            "id": 3,
                            "request": {
                                "type": "resource_invoke",
                                "uri": uri,
                                "operation": operation,
                                "body": "nope",
                                "token": request_id,
                            },
                        })
                        .to_string();
                        let (raw, parsed) = host_pair(&mut standin, &line, "component-1", None)
                            .expect("the stand-in did the work: a root mismatch is one response");
                        assert_host_error(
                            &parsed,
                            3,
                            &format!(
                                "wrong resource: expected localhost://{namespace}/self{suffix}, got {uri}"
                            ),
                            &format!("the hostcall redacts any owner's {namespace} root on {operation}"),
                        );
                        assert_no_protected_leak(&raw, digest_a, "agent-ada", "a root mismatch");
                        assert_no_protected_leak(&raw, digest_b, "agent-bob", "a root mismatch");
                        assert_eq!(
                            grant_record(&standin, &request_id),
                            (Life::Live, false),
                            "the stand-in did the work: a root mismatch leaves the once grant live"
                        );
                    }
                }
            }
        }
        assert!(
            standin.protected_objects.is_empty(),
            "the stand-in did the work: a redacted refusal stores nothing"
        );
    }

    #[test]
    fn standin_hostcall_preserves_payload_text() {
        let digest_a_hex = crate::identity::sha256(b"agent-ada");
        let digest_a = &digest_a_hex[..24];
        let digest_b_hex = crate::identity::sha256(b"agent-bob");
        let digest_b = &digest_b_hex[..24];
        let payload = format!(
            "agent-ada {digest_a} agent-bob {digest_b} localhost://Users/{digest_a}/journal localhost://UsersAI/{digest_a}/journal localhost://Users/{digest_b}/journal localhost://UsersAI/{digest_b}/journal"
        );
        let mut standin = running_ada();
        standin.seed_grant(
            "req-w",
            "component-1",
            "localhost://UsersAI/self/journal",
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-r",
            "component-1",
            "localhost://UsersAI/self/journal",
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        let write_line = format!(
            r#"{{"id":1,"request":{{"type":"resource_invoke","uri":"localhost://UsersAI/self/journal","operation":"write","body":"{payload}","token":"req-w"}}}}"#
        );
        let (raw, parsed) = host_pair(&mut standin, &write_line, "component-1", Some("agent-ada"))
            .expect("the stand-in did the work: the payload write is one response");
        assert_host_ok(
            &parsed,
            1,
            json!({ "stored": true }),
            "the payload write returns stored",
        );
        assert_no_protected_leak(&raw, digest_a, "agent-ada", "the payload write");
        let read_line = r#"{"id":2,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/journal","operation":"read","body":{},"token":"req-r"}}"#;
        let (raw, parsed) = host_pair(&mut standin, read_line, "component-1", None)
            .expect("the stand-in did the work: the payload read is one response");
        assert_host_ok(
            &parsed,
            2,
            json!(payload),
            "the payload read returns the stored text",
        );
        assert!(
            raw.contains("agent-ada"),
            "the stand-in did the work: the stored text keeps the principal name"
        );
        assert!(
            raw.contains(digest_a),
            "the stand-in did the work: the stored text keeps the digest the grant approved"
        );
        assert!(
            !raw.contains("token"),
            "the stand-in did the work: the payload read has no token"
        );
        assert!(
            !raw.contains("audit"),
            "the stand-in did the work: the payload read has no audit"
        );
        assert_eq!(
            standin.protected_read("component-1", "req-r", "localhost://UsersAI/self/journal"),
            Ok(payload.into_bytes()),
            "the stand-in did the work: the stored bytes keep the payload"
        );
    }

    #[test]
    fn standin_hostcall_refuses_invalid_utf8() {
        let bytes = vec![0xFF, 0xFE];
        let mut standin = running_ada();
        standin.seed_grant(
            "req-utf8-w",
            "component-1",
            "localhost://UsersAI/self/bytes",
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-utf8-r",
            "component-1",
            "localhost://UsersAI/self/bytes",
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        assert!(
            standin
                .protected_write(
                    "component-1",
                    "req-utf8-w",
                    "localhost://UsersAI/self/bytes",
                    &bytes
                )
                .is_ok(),
            "the stand-in did the work: the invalid bytes are stored"
        );
        let line = r#"{"id":2,"request":{"type":"resource_invoke","uri":"localhost://UsersAI/self/bytes","operation":"read","body":{},"token":"req-utf8-r"}}"#;
        let (raw, parsed) = host_pair(&mut standin, line, "component-1", None)
            .expect("the stand-in did the work: the utf-8 refusal is one response");
        assert_host_error(
            &parsed,
            2,
            "protected read is not utf-8",
            "invalid utf-8 is refused",
        );
        assert!(
            !raw.contains('\u{FFFD}'),
            "the stand-in did the work: the refusal is not lossy text"
        );
        assert_eq!(
            grant_record(&standin, "req-utf8-r"),
            (Life::Live, false),
            "the stand-in did the work: the utf-8 refusal leaves the session grant live"
        );
        assert_eq!(
            standin.protected_read(
                "component-1",
                "req-utf8-r",
                "localhost://UsersAI/self/bytes"
            ),
            Ok(bytes),
            "the stand-in did the work: the refusal leaves the stored bytes"
        );
    }

    #[test]
    fn standin_shell_decisions_join_the_audit_list() {
        let mut standin = StandIn::new();
        launch_two_running(&mut standin);
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: component-1 is running",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 is running",
        );

        let client = Caller::Client {
            session_id: "component-1",
        };
        const SHELL: &str = "This endpoint requires shell privileges";
        let shared = SHARED_RESOURCE;
        let orphan = "localhost://Public/resident-instances/orphan.txt";
        let spent = "localhost://Public/resident-instances/spent.txt";
        let old = "localhost://Public/resident-instances/old.txt";
        let wait = "localhost://Public/resident-instances/wait.txt";
        let guest = "localhost://UsersAI/self/journal";
        let digest = &crate::identity::sha256(b"agent-ada")[..24];
        let resolved = format!("localhost://UsersAI/{digest}/journal");

        assert_eq!(
            shell_audit(&standin, None, None),
            json!({"events": [], "total_in_memory": 0}),
            "the stand-in did the work: the shell audit list starts empty"
        );
        assert_eq!(
            shell_types(&standin),
            expected_types(),
            "the stand-in did the work: the shell type list names the four audit types"
        );
        refused_audit!(
            standin,
            standin.get_audit_types(client),
            403,
            SHELL,
            0,
            "a client is refused before the type list is built",
        );
        assert_eq!(
            shell_types(&standin),
            expected_types(),
            "the stand-in did the work: the shell type list stays the four audit types"
        );
        assert_eq!(
            audit_total(&standin),
            0,
            "the stand-in did the work: reading the type list appends nothing"
        );
        refused_audit!(
            standin,
            standin.get_audit(client, None, None),
            403,
            SHELL,
            0,
            "a client is refused before the audit list is read",
        );
        refused_audit!(
            standin,
            standin.post_capability_grant(client, &json!([])),
            403,
            SHELL,
            0,
            "a client grant is refused before the body is read",
        );
        refused_audit!(
            standin,
            standin.post_capability_deny(client, &json!({})),
            403,
            SHELL,
            0,
            "a client deny is refused before the body is read",
        );
        refused_audit!(
            standin,
            standin.delete_capability(client, "missing"),
            403,
            SHELL,
            0,
            "a client revoke is refused before the request is read",
        );
        refused_audit!(
            standin,
            standin.post_capability_revoke_all(client, &json!({})),
            403,
            SHELL,
            0,
            "a client revoke-all is refused before the body is read",
        );
        refused_audit!(
            standin,
            standin.post_capability_grant(Caller::Shell, &json!([])),
            400,
            "grant body needs request_id",
            0,
            "a grant body that is not an object is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_grant(Caller::Shell, &json!({"request_id": 1})),
            400,
            "grant request_id must be a string",
            0,
            "a non-string grant request_id is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_grant(
                Caller::Shell,
                &json!({"request_id": "missing", "token": "x"}),
            ),
            400,
            "grant body rejects token",
            0,
            "a grant body with token is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_grant(
                Caller::Shell,
                &json!({"request_id": "missing", "duration": "week"}),
            ),
            400,
            "Invalid duration: week. Expected 'once' or 'session'",
            0,
            "a grant duration other than once or session is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_deny(Caller::Shell, &json!([])),
            400,
            "deny body needs request_id",
            0,
            "a deny body that is not an object is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_deny(Caller::Shell, &json!({"reason": "x"})),
            400,
            "deny body needs request_id",
            0,
            "a deny body without request_id is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_deny(
                Caller::Shell,
                &json!({"request_id": "missing", "token": "x"}),
            ),
            400,
            "deny body rejects token",
            0,
            "a deny body with token is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_deny(Caller::Shell, &json!({"request_id": 1})),
            400,
            "deny request_id must be a string",
            0,
            "a non-string deny request_id is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_deny(Caller::Shell, &json!({"request_id": "missing"})),
            400,
            "unknown request: missing",
            0,
            "an unknown deny is refused",
        );
        refused_audit!(
            standin,
            standin.delete_capability(Caller::Shell, "missing"),
            404,
            "Capability request not found: missing",
            0,
            "an unknown revoke is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_revoke_all(Caller::Shell, &json!([])),
            400,
            "revoke body needs an object",
            0,
            "a revoke-all body that is not an object is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_revoke_all(Caller::Shell, &json!({"token": "x"})),
            400,
            "revoke body rejects token",
            0,
            "a revoke-all body with token is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_revoke_all(Caller::Shell, &json!({"reason": 1})),
            400,
            "revoke reason must be a string",
            0,
            "a non-string revoke-all reason is refused",
        );
        let empty_revoke = standin
            .post_capability_revoke_all(Caller::Shell, &json!({}))
            .expect("the stand-in did the work: an empty revoke-all succeeds");
        assert_eq!(
            empty_revoke,
            json!({"success": true, "reason": "Revoked all by user"}),
            "the stand-in did the work: an empty revoke-all keeps its Ok keys"
        );
        assert_eq!(
            audit_total(&standin),
            0,
            "the stand-in did the work: a revoke-all with no Live grant appends nothing"
        );

        for (request_id, session_id) in [
            ("req-a", "component-1"),
            ("req-c", "component-1"),
            ("req-b", "component-2"),
            ("req-x", "component-2"),
        ] {
            standin
                .seed_request(request_id, session_id, shared, "read", "read shared")
                .expect("the stand-in did the work: it stores the pending request");
        }
        assert_eq!(
            audit_total(&standin),
            0,
            "the stand-in did the work: seeding a request appends nothing"
        );
        let unknown = standin.post_capability_grant(
            Caller::Shell,
            &json!({"request_id": "missing", "duration": "session"}),
        );
        assert!(
            matches!(&unknown, Err((400, reason)) if reason.starts_with("unknown request:")),
            "the stand-in did the work: an unknown grant is refused: {unknown:?}"
        );
        assert_eq!(
            unknown,
            Err((400, "unknown request: missing".to_owned())),
            "the stand-in did the work: an unknown grant names the id"
        );
        assert_eq!(
            shell_audit(&standin, None, None),
            json!({"events": [], "total_in_memory": 0}),
            "the stand-in did the work: an unknown grant appends nothing"
        );

        standin.set_instant(4);
        let grant_a = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-a",
                    "duration": "session",
                    "rationale": "grant shared read",
                }),
            )
            .expect("the stand-in did the work: it grants req-a");
        assert_eq!(
            grant_a,
            json!({"success": true}),
            "the stand-in did the work: the req-a grant answers success true"
        );
        let grant_b = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-b",
                    "duration": "session",
                    "rationale": "grant sibling",
                }),
            )
            .expect("the stand-in did the work: it grants req-b");
        assert_eq!(
            grant_b,
            json!({"success": true}),
            "the stand-in did the work: the req-b grant answers success true"
        );
        let grant_c = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-c",
                    "duration": "once",
                    "rationale": "grant once",
                }),
            )
            .expect("the stand-in did the work: it grants req-c");
        assert_eq!(
            grant_c,
            json!({"success": true}),
            "the stand-in did the work: the req-c grant answers success true"
        );
        assert_eq!(
            audit_total(&standin),
            3,
            "the stand-in did the work: three grants append three events"
        );
        assert_eq!(
            shell_types(&standin),
            expected_types(),
            "the stand-in did the work: the type list stays the four names when the store holds grants"
        );
        assert_eq!(
            audit_total(&standin),
            3,
            "the stand-in did the work: reading the type list still appends nothing"
        );
        assert_eq!(
            decision_reason(&standin, "component-1", "req-a"),
            "grant shared read",
            "the stand-in did the work: the request record holds the grant rationale"
        );
        refused_audit!(
            standin,
            standin.post_capability_revoke_all(client, &json!({})),
            403,
            SHELL,
            3,
            "a client revoke-all leaves the three grant events",
        );
        assert_eq!(
            grant_record(&standin, "req-a"),
            (Life::Live, false),
            "the stand-in did the work: req-a stays live after the client revoke-all"
        );
        refused_audit!(
            standin,
            standin.post_capability_grant(
                Caller::Shell,
                &json!({"request_id": "req-a", "duration": "session"}),
            ),
            400,
            "request is not pending: req-a",
            3,
            "a second grant of req-a is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_deny(
                Caller::Shell,
                &json!({"request_id": "req-a", "reason": "too late"}),
            ),
            400,
            "request is not pending: req-a",
            3,
            "a deny of a granted request is refused",
        );
        assert_eq!(
            decision_reason(&standin, "component-1", "req-a"),
            "grant shared read",
            "the stand-in did the work: the refused deny leaves the grant rationale"
        );
        assert_audit_list(
            &audit_events(&standin),
            &[
                (
                    "capability_grant",
                    4,
                    "req-c",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_grant",
                    4,
                    "req-b",
                    "component-2",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_grant",
                    4,
                    "req-a",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
            ],
        );
        let listed = shell_audit(&standin, None, None);
        assert!(
            !listed.to_string().contains("token"),
            "the stand-in did the work: the audit response has no token"
        );
        assert!(
            !listed.to_string().contains("current_epoch"),
            "the stand-in did the work: the audit response has no current_epoch"
        );
        assert!(
            !listed.to_string().contains("grant shared read"),
            "the stand-in did the work: the audit event does not copy the rationale"
        );

        let denied = standin
            .post_capability_deny(
                Caller::Shell,
                &json!({"request_id": "req-x", "reason": "sibling read denied"}),
            )
            .expect("the stand-in did the work: it denies req-x");
        assert_eq!(
            denied,
            json!({"success": true}),
            "the stand-in did the work: the req-x deny answers success true"
        );
        assert_eq!(
            audit_total(&standin),
            4,
            "the stand-in did the work: the deny appends one event"
        );
        assert_eq!(
            decision_reason(&standin, "component-2", "req-x"),
            "sibling read denied",
            "the stand-in did the work: the request record holds the deny reason"
        );
        assert_audit_list(
            &audit_events(&standin),
            &[
                (
                    "capability_denied",
                    4,
                    "req-x",
                    "component-2",
                    shared,
                    "read",
                    false,
                ),
                (
                    "capability_grant",
                    4,
                    "req-c",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_grant",
                    4,
                    "req-b",
                    "component-2",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_grant",
                    4,
                    "req-a",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
            ],
        );
        assert!(
            !shell_audit(&standin, None, None)
                .to_string()
                .contains("sibling read denied"),
            "the stand-in did the work: the deny event does not copy the reason"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: component-1 stays running after the deny",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 stays running after the deny",
        );
        let grants = shell_audit(&standin, None, Some("capability_grant"));
        assert_eq!(
            grants["total_in_memory"], 4,
            "the stand-in did the work: the grant filter leaves the stored count"
        );
        assert_audit_list(
            grants["events"]
                .as_array()
                .expect("the stand-in did the work: events is a list"),
            &[
                (
                    "capability_grant",
                    4,
                    "req-c",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_grant",
                    4,
                    "req-b",
                    "component-2",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_grant",
                    4,
                    "req-a",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
            ],
        );
        assert_eq!(
            shell_audit(&standin, None, Some("capability_use")),
            json!({"events": [], "total_in_memory": 4}),
            "the stand-in did the work: a capability_use filter keeps no shell decision"
        );
        refused_audit!(
            standin,
            standin.post_capability_deny(Caller::Shell, &json!({"request_id": "req-x"})),
            400,
            "request is not pending: req-x",
            4,
            "a second deny of req-x is refused",
        );
        refused_audit!(
            standin,
            standin.post_capability_grant(
                Caller::Shell,
                &json!({"request_id": "req-x", "duration": "session"}),
            ),
            400,
            "request is not pending: req-x",
            4,
            "a grant of a denied request is refused",
        );

        standin.set_instant(5);
        let revoked = standin
            .delete_capability(Caller::Shell, "req-a")
            .expect("the stand-in did the work: it revokes req-a");
        assert_eq!(
            revoked,
            json!({"success": true, "revoked_request_id": "req-a"}),
            "the stand-in did the work: the revoke keeps its Ok keys"
        );
        assert_eq!(
            audit_total(&standin),
            5,
            "the stand-in did the work: the revoke appends one event"
        );
        assert_eq!(
            grant_record(&standin, "req-a"),
            (Life::Revoked, false),
            "the stand-in did the work: req-a is revoked"
        );
        assert_eq!(
            decision_reason(&standin, "component-1", "req-a"),
            "Revoked by user",
            "the stand-in did the work: the request record holds the revoke reason"
        );
        assert_decision(
            &audit_events(&standin)[0],
            "capability_revoke",
            5,
            "req-a",
            "component-1",
            shared,
            "read",
            true,
            "the revoke of req-a",
        );
        assert!(
            !shell_audit(&standin, None, None)
                .to_string()
                .contains("Revoked by user"),
            "the stand-in did the work: the revoke event does not copy the reason"
        );
        refused_audit!(
            standin,
            standin.delete_capability(Caller::Shell, "req-a"),
            400,
            "Capability req-a was not granted",
            5,
            "a second revoke of req-a is refused",
        );

        standin.seed_grant(
            "req-orphan",
            "component-2",
            orphan,
            "read",
            "session",
            4,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-spent",
            "component-2",
            spent,
            "spend",
            "once",
            4,
            Life::Exhausted,
            false,
        );
        standin.seed_grant(
            "req-old",
            "component-1",
            old,
            "expire",
            "session",
            4,
            Life::Expired,
            false,
        );
        standin
            .seed_request("req-wait", "component-1", wait, "wait", "still waiting")
            .expect("the stand-in did the work: it stores the pending request");
        assert_eq!(
            audit_total(&standin),
            5,
            "the stand-in did the work: a seeded grant and a pending request append nothing"
        );
        refused_audit!(
            standin,
            standin.delete_capability(Caller::Shell, "req-wait"),
            400,
            "Capability req-wait was not granted",
            5,
            "a pending request is not a revoke",
        );
        assert_eq!(
            request_status(&standin, "component-1", "req-wait"),
            "pending",
            "the stand-in did the work: the refused revoke leaves the pending request"
        );

        let revoke_all = standin
            .post_capability_revoke_all(Caller::Shell, &json!({"reason": "stop every grant"}))
            .expect("the stand-in did the work: it revokes every live grant");
        assert_eq!(
            revoke_all,
            json!({"success": true, "reason": "stop every grant"}),
            "the stand-in did the work: revoke-all keeps its Ok keys"
        );
        let revoked_events = audit_events(&standin);
        for request_id in ["req-spent", "req-old", "req-wait"] {
            assert_absent(&revoked_events, request_id);
        }
        assert_audit_list(
            &revoked_events[..3],
            &[
                (
                    "capability_revoke",
                    5,
                    "req-orphan",
                    "component-2",
                    orphan,
                    "read",
                    true,
                ),
                (
                    "capability_revoke",
                    5,
                    "req-b",
                    "component-2",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_revoke",
                    5,
                    "req-c",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
            ],
        );
        assert_eq!(
            audit_total(&standin),
            8,
            "the stand-in did the work: revoke-all appends one event per Live grant"
        );
        assert_audit_list(
            &revoked_events,
            &[
                (
                    "capability_revoke",
                    5,
                    "req-orphan",
                    "component-2",
                    orphan,
                    "read",
                    true,
                ),
                (
                    "capability_revoke",
                    5,
                    "req-b",
                    "component-2",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_revoke",
                    5,
                    "req-c",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_revoke",
                    5,
                    "req-a",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_denied",
                    4,
                    "req-x",
                    "component-2",
                    shared,
                    "read",
                    false,
                ),
                (
                    "capability_grant",
                    4,
                    "req-c",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_grant",
                    4,
                    "req-b",
                    "component-2",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_grant",
                    4,
                    "req-a",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
            ],
        );
        assert!(
            !shell_audit(&standin, None, None)
                .to_string()
                .contains("stop every grant"),
            "the stand-in did the work: the revoke-all events do not copy the reason"
        );
        assert_eq!(
            grant_record(&standin, "req-b"),
            (Life::Revoked, false),
            "the stand-in did the work: req-b is revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-c"),
            (Life::Revoked, false),
            "the stand-in did the work: req-c is revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-orphan"),
            (Life::Revoked, false),
            "the stand-in did the work: req-orphan is revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-spent"),
            (Life::Exhausted, false),
            "the stand-in did the work: the exhausted grant stays exhausted"
        );
        assert_eq!(
            grant_record(&standin, "req-old"),
            (Life::Expired, false),
            "the stand-in did the work: the expired grant stays expired"
        );
        assert_eq!(
            request_status(&standin, "component-1", "req-wait"),
            "pending",
            "the stand-in did the work: the pending request stays pending"
        );
        assert_eq!(
            decision_reason(&standin, "component-2", "req-b"),
            "stop every grant",
            "the stand-in did the work: req-b's request record holds the revoke-all reason"
        );
        assert_eq!(
            decision_reason(&standin, "component-1", "req-c"),
            "stop every grant",
            "the stand-in did the work: req-c's request record holds the revoke-all reason"
        );
        assert_eq!(
            decision_reason(&standin, "component-1", "req-a"),
            "Revoked by user",
            "the stand-in did the work: the earlier revoke reason stays"
        );
        let limited = shell_audit(&standin, Some(1), None);
        assert_eq!(
            limited["total_in_memory"], 8,
            "the stand-in did the work: limit 1 leaves the stored count"
        );
        assert_decision(
            &limited["events"][0],
            "capability_revoke",
            5,
            "req-orphan",
            "component-2",
            orphan,
            "read",
            true,
            "limit 1 keeps the newest revoke",
        );
        assert_eq!(
            limited["events"]
                .as_array()
                .expect("the stand-in did the work: events is a list")
                .len(),
            1,
            "the stand-in did the work: limit 1 keeps one event"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: component-1 stays running after revoke-all",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 stays running after revoke-all",
        );

        let again = standin
            .post_capability_revoke_all(Caller::Shell, &json!({}))
            .expect("the stand-in did the work: a second revoke-all succeeds");
        assert_eq!(
            again,
            json!({"success": true, "reason": "Revoked all by user"}),
            "the stand-in did the work: the empty revoke-all keeps its Ok keys"
        );
        assert_eq!(
            audit_total(&standin),
            8,
            "the stand-in did the work: a revoke-all with no Live grant appends nothing"
        );
        for request_id in ["req-spent", "req-old", "req-wait"] {
            assert_absent(&audit_events(&standin), request_id);
        }
        assert_eq!(
            grant_record(&standin, "req-spent"),
            (Life::Exhausted, false),
            "the stand-in did the work: the second revoke-all leaves the exhausted grant"
        );
        assert_eq!(
            grant_record(&standin, "req-old"),
            (Life::Expired, false),
            "the stand-in did the work: the second revoke-all leaves the expired grant"
        );
        assert_eq!(
            request_status(&standin, "component-1", "req-wait"),
            "pending",
            "the stand-in did the work: the second revoke-all leaves the pending request"
        );
        assert_eq!(
            shell_types(&standin),
            expected_types(),
            "the stand-in did the work: the type list does not shrink to the stored types"
        );

        standin
            .bind_verified_principal(SHARED_PATH, "agent-ada")
            .expect("the stand-in did the work: the launch principal binds");
        let third = launch_finished(&mut standin);
        assert_eq!(
            third, "component-3",
            "the stand-in did the work: the protected use has its own instance"
        );
        standin.set_instant(6);
        standin
            .seed_request("req-use", "component-3", guest, "write", "write journal")
            .expect("the stand-in did the work: it stores the protected request");
        let grant_use = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-use",
                    "duration": "session",
                    "rationale": "grant journal",
                }),
            )
            .expect("the stand-in did the work: it grants the protected write");
        assert_eq!(
            grant_use,
            json!({"success": true}),
            "the stand-in did the work: the protected grant answers success true"
        );
        assert_eq!(
            audit_total(&standin),
            9,
            "the stand-in did the work: the protected grant joins the same audit list"
        );
        let missed = standin.protected_write("component-3", "req-missing", guest, b"no");
        assert_eq!(
            missed,
            Err((400, "unknown grant: req-missing".to_owned())),
            "the stand-in did the work: an unknown protected use is refused"
        );
        assert_eq!(
            audit_total(&standin),
            9,
            "the stand-in did the work: a refused protected use appends nothing"
        );
        assert_eq!(
            standin.protected_write("component-3", "req-use", guest, b"note"),
            Ok(resolved.clone()),
            "the stand-in did the work: the protected write stores the bytes"
        );
        assert_eq!(
            audit_total(&standin),
            10,
            "the stand-in did the work: the protected use joins the same audit list"
        );
        assert_eq!(
            decision_reason(&standin, "component-3", "req-use"),
            "grant journal",
            "the stand-in did the work: the protected request holds its rationale"
        );
        let combined = audit_events(&standin);
        assert_decision(
            &combined[0],
            "capability_use",
            6,
            "req-use",
            "component-3",
            &resolved,
            "write",
            true,
            "the protected use is newest on the same list",
        );
        assert_decision(
            &combined[1],
            "capability_grant",
            6,
            "req-use",
            "component-3",
            guest,
            "write",
            true,
            "the protected grant stays behind its use",
        );
        assert_decision(
            &combined[2],
            "capability_revoke",
            5,
            "req-orphan",
            "component-2",
            orphan,
            "read",
            true,
            "the earlier revoke stays on the same list",
        );
        assert!(
            !shell_audit(&standin, None, None)
                .to_string()
                .contains("grant journal"),
            "the stand-in did the work: the protected grant event does not copy the rationale"
        );
        let uses = shell_audit(&standin, None, Some("capability_use"));
        assert_eq!(
            uses["total_in_memory"], 10,
            "the stand-in did the work: the use filter leaves the stored count"
        );
        assert_audit_list(
            uses["events"]
                .as_array()
                .expect("the stand-in did the work: events is a list"),
            &[(
                "capability_use",
                6,
                "req-use",
                "component-3",
                &resolved,
                "write",
                true,
            )],
        );
        let later_grants = shell_audit(&standin, None, Some("capability_grant"));
        assert_eq!(later_grants["total_in_memory"], 10);
        assert_audit_list(
            later_grants["events"]
                .as_array()
                .expect("the stand-in did the work: events is a list"),
            &[
                (
                    "capability_grant",
                    6,
                    "req-use",
                    "component-3",
                    guest,
                    "write",
                    true,
                ),
                (
                    "capability_grant",
                    4,
                    "req-c",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_grant",
                    4,
                    "req-b",
                    "component-2",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_grant",
                    4,
                    "req-a",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
            ],
        );
        let revokes = shell_audit(&standin, None, Some("capability_revoke"));
        assert_eq!(revokes["total_in_memory"], 10);
        assert_audit_list(
            revokes["events"]
                .as_array()
                .expect("the stand-in did the work: events is a list"),
            &[
                (
                    "capability_revoke",
                    5,
                    "req-orphan",
                    "component-2",
                    orphan,
                    "read",
                    true,
                ),
                (
                    "capability_revoke",
                    5,
                    "req-b",
                    "component-2",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_revoke",
                    5,
                    "req-c",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
                (
                    "capability_revoke",
                    5,
                    "req-a",
                    "component-1",
                    shared,
                    "read",
                    true,
                ),
            ],
        );
        let denials = shell_audit(&standin, None, Some("capability_denied"));
        assert_eq!(denials["total_in_memory"], 10);
        assert_audit_list(
            denials["events"]
                .as_array()
                .expect("the stand-in did the work: events is a list"),
            &[(
                "capability_denied",
                4,
                "req-x",
                "component-2",
                shared,
                "read",
                false,
            )],
        );
        assert_eq!(
            shell_audit(&standin, None, Some("capsule_launch")),
            json!({"events": [], "total_in_memory": 10}),
            "the stand-in did the work: another type keeps no event from this list"
        );
        let newest = shell_audit(&standin, Some(1), None);
        assert_eq!(newest["total_in_memory"], 10);
        assert_decision(
            &newest["events"][0],
            "capability_use",
            6,
            "req-use",
            "component-3",
            &resolved,
            "write",
            true,
            "limit 1 keeps the protected use",
        );
        assert_eq!(
            shell_types(&standin),
            expected_types(),
            "the stand-in did the work: the type list stays the four names after every decision"
        );
        assert_eq!(
            audit_total(&standin),
            10,
            "the stand-in did the work: the type list still appends nothing"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: component-1 stays running",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 stays running",
        );
    }

    #[test]
    fn standin_stop_revoke_joins_the_audit_list() {
        let mut standin = StandIn::new();
        launch_two_running(&mut standin);
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: component-1 is running",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 is running",
        );
        let empty = json!({"events": [], "total_in_memory": 0});
        assert_eq!(
            shell_audit(&standin, None, None),
            empty,
            "the stand-in did the work: the shell audit list starts empty"
        );

        let read_b = "localhost://Public/resident-instances/b.txt";
        let write_a = "localhost://Public/resident-instances/a.txt";
        let spent = "localhost://Public/resident-instances/spent.txt";
        let sibling = "localhost://Public/resident-instances/sib.txt";
        let already = "localhost://Public/resident-instances/old.txt";
        let aged = "localhost://Public/resident-instances/age.txt";
        let waiting = "localhost://Public/resident-instances/pend.txt";
        let kept = "localhost://Public/resident-instances/kept.txt";
        let sibling_wait = "localhost://Public/resident-instances/sib-pend.txt";
        standin.seed_grant(
            "req-b",
            "component-1",
            read_b,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-a",
            "component-1",
            write_a,
            "write",
            "once",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-spent",
            "component-1",
            spent,
            "read",
            "once",
            1,
            Life::Exhausted,
            false,
        );
        standin.seed_grant(
            "req-sib",
            "component-2",
            sibling,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-old",
            "component-1",
            already,
            "read",
            "session",
            1,
            Life::Revoked,
            false,
        );
        standin.seed_grant(
            "req-age",
            "component-1",
            aged,
            "read",
            "session",
            1,
            Life::Expired,
            false,
        );
        standin
            .seed_request("req-pend", "component-1", waiting, "read", "still waiting")
            .expect("the stand-in did the work: it stores the pending request");
        standin
            .seed_request("req-kept", "component-1", kept, "read", "already asked")
            .expect("the stand-in did the work: it stores the granted request");
        standin.settle_record(
            "req-kept",
            RequestStatus::Granted,
            "already granted",
            "shell",
        );
        standin
            .seed_request(
                "req-pend-sib",
                "component-2",
                sibling_wait,
                "read",
                "sibling waiting",
            )
            .expect("the stand-in did the work: it stores the sibling pending request");
        let stored = |entries: Vec<Value>, request_id: &str| {
            entries
                .into_iter()
                .find(|entry| entry["request_id"] == request_id)
                .unwrap_or_else(|| panic!("the stand-in did the work: {request_id} stays stored"))
        };
        let kept_before = stored(request_entries(&standin, "component-1"), "req-kept");
        let pend_before = stored(request_entries(&standin, "component-1"), "req-pend");
        let sibling_before = stored(request_entries(&standin, "component-2"), "req-pend-sib");
        assert_eq!(
            kept_before["status"], "granted",
            "the stand-in did the work: the stored request is granted"
        );

        standin.set_instant(6);
        assert_eq!(
            shell_audit(&standin, None, None),
            empty,
            "the stand-in did the work: ageing the instant appends nothing"
        );
        assert_eq!(
            request_status(&standin, "component-1", "req-pend"),
            "pending",
            "the stand-in did the work: the pending request stays pending before the stop"
        );
        let client = Caller::Client {
            session_id: "component-1",
        };
        assert_eq!(
            standin.delete_capsule(client, "component-1", &json!({"reason": "stop one"})),
            Err((403, "This endpoint requires shell privileges".to_owned())),
            "the stand-in did the work: a client stop is refused"
        );
        assert_eq!(
            standin.delete_capsule(Caller::Shell, "component-1", &Value::Null),
            Err((400, "stop body needs reason".to_owned())),
            "the stand-in did the work: a stop without a reason is refused"
        );
        assert_eq!(
            shell_audit(&standin, None, None),
            empty,
            "the stand-in did the work: a refused stop appends nothing"
        );
        assert_eq!(
            grant_record(&standin, "req-a"),
            (Life::Live, false),
            "the stand-in did the work: a refused stop leaves req-a live"
        );

        assert_eq!(
            standin.delete_capsule(Caller::Shell, "component-1", &json!({"reason": "stop one"})),
            Ok(Value::Null),
            "the stand-in did the work: the stop answers null"
        );
        assert_eq!(
            audit_total(&standin),
            2,
            "the stand-in did the work: the stop appends one event per live grant"
        );
        let stopped = shell_audit(&standin, None, None);
        let events = stopped["events"]
            .as_array()
            .expect("the stand-in did the work: events is a list");
        assert_decision(
            &events[0],
            "capability_revoke",
            6,
            "req-b",
            "component-1",
            read_b,
            "read",
            true,
            "the stop revoke of req-b",
        );
        assert_decision(
            &events[1],
            "capability_revoke",
            6,
            "req-a",
            "component-1",
            write_a,
            "write",
            true,
            "the stop revoke of req-a",
        );
        assert!(
            !stopped.to_string().contains("token"),
            "the stand-in did the work: the audit response has no token"
        );
        assert!(
            !stopped.to_string().contains("current_epoch"),
            "the stand-in did the work: the audit response has no current_epoch"
        );
        assert!(
            !stopped.to_string().contains("reason"),
            "the stand-in did the work: the audit response has no reason"
        );
        for request_id in [
            "req-spent",
            "req-sib",
            "req-old",
            "req-age",
            "req-pend",
            "req-kept",
            "req-pend-sib",
        ] {
            assert_absent(events, request_id);
        }
        assert_eq!(
            grant_record(&standin, "req-a"),
            (Life::Revoked, false),
            "the stand-in did the work: req-a is revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-b"),
            (Life::Revoked, false),
            "the stand-in did the work: req-b is revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-spent"),
            (Life::Exhausted, false),
            "the stand-in did the work: req-spent stays exhausted"
        );
        assert_eq!(
            grant_record(&standin, "req-sib"),
            (Life::Live, false),
            "the stand-in did the work: req-sib stays live"
        );
        assert_eq!(
            grant_record(&standin, "req-old"),
            (Life::Revoked, false),
            "the stand-in did the work: req-old stays revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-age"),
            (Life::Expired, false),
            "the stand-in did the work: req-age stays expired"
        );
        let kept_after = stored(request_entries(&standin, "component-1"), "req-kept");
        assert_eq!(
            kept_after, kept_before,
            "the stand-in did the work: the granted request record is unchanged"
        );
        let mut pend_expected = pend_before.clone();
        pend_expected["status"] = json!("denied");
        pend_expected["decision_reason"] = json!("stopped: stop one");
        pend_expected["settled_by"] = json!("runtime");
        assert_eq!(
            stored(request_entries(&standin, "component-1"), "req-pend"),
            pend_expected,
            "the stand-in did the work: the pending request is denied and its other fields stay"
        );
        assert_eq!(
            stored(request_entries(&standin, "component-2"), "req-pend-sib"),
            sibling_before,
            "the stand-in did the work: the sibling pending request stays pending"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in did the work: component-1 is stopped",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 stays running",
        );

        assert_eq!(
            standin.delete_capsule(Caller::Shell, "component-1", &json!({"reason": "stop one"})),
            Err((400, "instance is not live: stopped".to_owned())),
            "the stand-in did the work: a second stop of component-1 is refused"
        );
        assert_eq!(
            shell_audit(&standin, None, None),
            stopped,
            "the stand-in did the work: a second stop leaves the audit list unchanged"
        );
        assert_eq!(
            standin.delete_capsule(Caller::Shell, "component-9", &json!({"reason": "stop one"})),
            Err((400, "unknown instance: component-9".to_owned())),
            "the stand-in did the work: an unknown stop is refused"
        );
        assert_eq!(
            shell_audit(&standin, None, None),
            stopped,
            "the stand-in did the work: an unknown stop leaves the audit list unchanged"
        );
        let sibling_client = Caller::Client {
            session_id: "component-2",
        };
        assert_eq!(
            standin.delete_capsule(
                sibling_client,
                "component-2",
                &json!({"reason": "stop one"}),
            ),
            Err((403, "This endpoint requires shell privileges".to_owned())),
            "the stand-in did the work: a client stop of component-2 is refused"
        );
        assert_eq!(
            standin.delete_capsule(Caller::Shell, "component-2", &Value::Null),
            Err((400, "stop body needs reason".to_owned())),
            "the stand-in did the work: a stop of component-2 without a reason is refused"
        );
        assert_eq!(
            standin.finish_start("component-1"),
            Err((400, "instance is not live: stopped".to_owned())),
            "the stand-in did the work: finish_start of a stopped instance is refused"
        );
        assert_eq!(
            standin.finish_start("component-2"),
            Err((400, "start already returned".to_owned())),
            "the stand-in did the work: finish_start of a running instance is refused"
        );
        assert_eq!(
            standin.finish_start("component-9"),
            Err((400, "unknown instance: component-9".to_owned())),
            "the stand-in did the work: finish_start of an unknown instance is refused"
        );
        assert_eq!(
            shell_audit(&standin, None, None),
            stopped,
            "the stand-in did the work: a refused start leaves the audit list unchanged"
        );
        assert_eq!(
            audit_total(&standin),
            2,
            "the stand-in did the work: a refused start appends nothing"
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 stays running after the refusals",
        );

        standin
            .admit_resident(
                "/capsules/fail-after-submit",
                "fail-after-submit",
                Start::Error("start refused".to_owned()),
            )
            .expect("the stand-in did the work: it admits the failed start");
        let launched = standin
            .post_capsules(
                Caller::Shell,
                &json!({"path": "/capsules/fail-after-submit"}),
            )
            .expect("the stand-in did the work: it launches the failed start");
        assert_eq!(
            launched["id"], "component-3",
            "the stand-in did the work: the failed start is component-3"
        );
        let fail_id = "component-3";
        let fail_res = "localhost://Public/resident-instances/fail.txt";
        let fail_wait = "localhost://Public/resident-instances/fail-pend.txt";
        let fail_kept = "localhost://Public/resident-instances/fail-kept.txt";
        standin.seed_grant(
            "req-fail",
            fail_id,
            fail_res,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        standin
            .seed_request("req-fail-pend", fail_id, fail_wait, "read", "still waiting")
            .expect("the stand-in did the work: it stores the failed start's pending request");
        standin
            .seed_request("req-fail-kept", fail_id, fail_kept, "read", "already asked")
            .expect("the stand-in did the work: it stores the failed start's granted request");
        standin.settle_record(
            "req-fail-kept",
            RequestStatus::Granted,
            "already granted",
            "shell",
        );
        let fail_kept_before = stored(request_entries(&standin, fail_id), "req-fail-kept");
        let fail_pend_before = stored(request_entries(&standin, fail_id), "req-fail-pend");
        standin.set_instant(7);
        assert_eq!(
            shell_audit(&standin, None, None),
            stopped,
            "the stand-in did the work: seeding the failed start appends nothing"
        );
        assert_eq!(
            standin.finish_start(fail_id),
            Ok(()),
            "the stand-in did the work: the failed start returns ok"
        );
        assert_eq!(
            audit_total(&standin),
            3,
            "the stand-in did the work: the failed start appends one event"
        );
        let failed = shell_audit(&standin, None, None);
        let failed_events = failed["events"]
            .as_array()
            .expect("the stand-in did the work: events is a list");
        assert_decision(
            &failed_events[0],
            "capability_revoke",
            7,
            "req-fail",
            fail_id,
            fail_res,
            "read",
            true,
            "the failed start revoke of req-fail",
        );
        assert_eq!(
            &failed_events[1..],
            stopped["events"]
                .as_array()
                .expect("the stand-in did the work: events is a list")
                .as_slice(),
            "the stand-in did the work: the failed start leaves the stop's events unchanged"
        );
        assert_absent(failed_events, "req-sib");
        assert_absent(failed_events, "req-fail-pend");
        assert_absent(failed_events, "req-fail-kept");
        assert!(
            !failed.to_string().contains("token"),
            "the stand-in did the work: the failed start audit response has no token"
        );
        assert_eq!(
            grant_record(&standin, "req-fail"),
            (Life::Revoked, false),
            "the stand-in did the work: req-fail is revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-sib"),
            (Life::Live, false),
            "the stand-in did the work: req-sib stays live after the failed start"
        );
        assert_eq!(
            stored(request_entries(&standin, fail_id), "req-fail-kept"),
            fail_kept_before,
            "the stand-in did the work: the failed start leaves its granted request unchanged"
        );
        let mut fail_pend_expected = fail_pend_before.clone();
        fail_pend_expected["status"] = json!("denied");
        fail_pend_expected["decision_reason"] = json!("start refused");
        fail_pend_expected["settled_by"] = json!("runtime");
        assert_eq!(
            stored(request_entries(&standin, fail_id), "req-fail-pend"),
            fail_pend_expected,
            "the stand-in did the work: the failed start denies its pending request and appends none"
        );
        assert_named_capsule(
            &standin,
            fail_id,
            "fail-after-submit",
            "failed",
            "start refused",
            "the failed start stores its cause",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 stays running after the failed start",
        );
        assert_eq!(
            standin.finish_start(fail_id),
            Err((400, "start already returned".to_owned())),
            "the stand-in did the work: a second start of the failed instance is refused"
        );
        assert_eq!(
            shell_audit(&standin, None, None),
            failed,
            "the stand-in did the work: a second start of the failed instance leaves the audit list unchanged"
        );

        standin
            .admit_resident("/capsules/deny-starting", "deny-starting", Start::Ok)
            .expect("the stand-in did the work: it admits the starting deny");
        let deny_launch = standin
            .post_capsules(Caller::Shell, &json!({"path": "/capsules/deny-starting"}))
            .expect("the stand-in did the work: it launches the starting deny");
        assert_eq!(
            deny_launch["id"], "component-4",
            "the stand-in did the work: the starting deny is component-4"
        );
        let deny_id = "component-4";
        let deny_live = "localhost://Public/resident-instances/deny-live.txt";
        let deny_wait = "localhost://Public/resident-instances/deny-wait.txt";
        let deny_extra = "localhost://Public/resident-instances/deny-extra.txt";
        let deny_spent = "localhost://Public/resident-instances/deny-spent.txt";
        standin.seed_grant(
            "req-deny-live",
            deny_id,
            deny_live,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-deny-spent",
            deny_id,
            deny_spent,
            "read",
            "once",
            1,
            Life::Exhausted,
            false,
        );
        standin
            .seed_request("req-deny-wait", deny_id, deny_wait, "read", "still waiting")
            .expect("the stand-in did the work: it stores the deny request");
        standin
            .seed_request(
                "req-deny-extra",
                deny_id,
                deny_extra,
                "read",
                "also waiting",
            )
            .expect("the stand-in did the work: it stores the other deny request");
        let deny_wait_before = stored(request_entries(&standin, deny_id), "req-deny-wait");
        let deny_extra_before = stored(request_entries(&standin, deny_id), "req-deny-extra");
        standin.set_instant(8);
        assert_eq!(
            shell_audit(&standin, None, None),
            failed,
            "the stand-in did the work: seeding the starting deny appends nothing"
        );
        let denied = standin
            .post_capability_deny(
                Caller::Shell,
                &json!({"request_id": "req-deny-wait", "reason": "start denied"}),
            )
            .expect("the stand-in did the work: it denies the starting instance");
        assert_eq!(
            denied,
            json!({"success": true}),
            "the stand-in did the work: the starting deny answers success true"
        );
        assert_eq!(
            audit_total(&standin),
            5,
            "the stand-in did the work: the starting deny appends the dropped grant and its own denial"
        );
        let denied_audit = shell_audit(&standin, None, None);
        let denied_events = denied_audit["events"]
            .as_array()
            .expect("the stand-in did the work: events is a list");
        assert_decision(
            &denied_events[0],
            "capability_denied",
            8,
            "req-deny-wait",
            deny_id,
            deny_wait,
            "read",
            false,
            "the starting deny of req-deny-wait",
        );
        assert_decision(
            &denied_events[1],
            "capability_revoke",
            8,
            "req-deny-live",
            deny_id,
            deny_live,
            "read",
            true,
            "the starting deny revoke of req-deny-live",
        );
        assert_eq!(
            &denied_events[2..],
            failed["events"]
                .as_array()
                .expect("the stand-in did the work: events is a list")
                .as_slice(),
            "the stand-in did the work: the starting deny leaves the earlier events unchanged"
        );
        for request_id in ["req-deny-spent", "req-deny-extra", "req-sib"] {
            assert_absent(denied_events, request_id);
        }
        assert_eq!(
            grant_record(&standin, "req-deny-live"),
            (Life::Revoked, false),
            "the stand-in did the work: req-deny-live is revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-deny-spent"),
            (Life::Exhausted, false),
            "the stand-in did the work: req-deny-spent stays exhausted"
        );
        assert_eq!(
            grant_record(&standin, "req-sib"),
            (Life::Live, false),
            "the stand-in did the work: req-sib stays live after the starting deny"
        );
        let mut deny_wait_expected = deny_wait_before.clone();
        deny_wait_expected["status"] = json!("denied");
        deny_wait_expected["decision_reason"] = json!("start denied");
        deny_wait_expected["settled_by"] = json!("shell");
        assert_eq!(
            stored(request_entries(&standin, deny_id), "req-deny-wait"),
            deny_wait_expected,
            "the stand-in did the work: the named deny keeps the shell settlement"
        );
        let mut deny_extra_expected = deny_extra_before.clone();
        deny_extra_expected["status"] = json!("denied");
        deny_extra_expected["decision_reason"] = json!("start denied");
        deny_extra_expected["settled_by"] = json!("runtime");
        assert_eq!(
            stored(request_entries(&standin, deny_id), "req-deny-extra"),
            deny_extra_expected,
            "the stand-in did the work: the other pending request is settled and adds no event"
        );
        assert_named_capsule(
            &standin,
            deny_id,
            "deny-starting",
            "failed",
            "start denied",
            "the starting deny stores its cause",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 stays running after the starting deny",
        );
    }
}
